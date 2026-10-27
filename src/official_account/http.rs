// SPDX-License-Identifier: AGPL-3.0-only
// RustDesk contributors: selected HTTP/client/proxy/polling helpers from
// 092a961b629d318fe290eeafac0cd214a1e9deeb. Modified for rd-engine 2026-09-23.
// See UPSTREAM.json for exact selections and fail-closed security adaptations.

use super::{AccountContext, api, state};
use base::config::keys;
use hbb_common::{
    ResultType, Stream, anyhow::anyhow, bail,
    bytes::Bytes,
    config::{self, Config, Socks5Server},
    protobuf::Message as _,
    proxy::{Proxy, ProxyScheme},
    rendezvous_proto::{HeaderEntry, HttpProxyRequest, KeyExchange, RendezvousMessage, rendezvous_message},
    serde_derive::Serialize,
    serde_json,
    sha2::{Digest, Sha256},
    sodiumoxide::crypto::{box_, secretbox, sign},
    tls::{TlsType, get_cached_tls_accept_invalid_cert, get_cached_tls_type},
};
use reqwest::{Client, Method, header::{HeaderMap, HeaderName, HeaderValue}};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, atomic::{AtomicU64, Ordering}},
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::AbortHandle, time::timeout};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const CONSTRUCTION_TIMEOUT: Duration = Duration::from_secs(6);
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const REQUEST_LIFETIME: Duration = Duration::from_secs(24);
const RESULT_RETENTION: Duration = Duration::from_secs(60);
const MAX_REQUESTS: usize = 32;
const MAX_BODY: usize = 16 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;

static CONSTRUCTION_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
static REQUESTS: LazyLock<Mutex<HashMap<[u8; 32], PendingRequest>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

struct PendingRequest {
    id: u64,
    context: AccountContext,
    expires: Instant,
    result: Option<ResultType<Zeroizing<String>>>,
    job: Option<AbortHandle>,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            job.abort();
        }
    }
}

pub(super) struct Request {
    url: Zeroizing<String>,
    method: Method,
    body: Option<Zeroizing<String>>,
    headers: HeaderMap,
}

impl Request {
    pub(super) fn new(url: String, method: &str, body: Option<String>, headers: String) -> ResultType<Self> {
        let url = Zeroizing::new(url);
        let body = body.map(Zeroizing::new);
        let headers = Zeroizing::new(headers);
        api::http_url(&url, false)?;
        let method = match method.to_ascii_lowercase().as_str() {
            "get" => Method::GET,
            "post" => Method::POST,
            "put" => Method::PUT,
            "delete" => Method::DELETE,
            _ => bail!("The HTTP request method is not supported"),
        };
        if body.as_ref().is_some_and(|value| value.len() > MAX_BODY) {
            bail!("Account HTTP request is too large");
        }
        Ok(Self { url, method, body, headers: parse_json_header_entries(&headers)? })
    }
}

// Upstream parse_json_header_entries, with malformed/non-string/invalid header
// values rejected instead of silently replacing them with empty strings.
fn parse_json_header_entries(header: &str) -> ResultType<HeaderMap> {
    if header.len() > MAX_HEADERS {
        bail!("Account HTTP headers are too large");
    }
    let mut entries: HashMap<String, String> = serde_json::from_str(header)
        .map_err(|_| anyhow!("HTTP header information parsing failed"))?;
    let parsed = (|| {
        let mut headers = HeaderMap::with_capacity(entries.len());
        for (name, value) in &entries {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow!("Invalid HTTP header name"))?;
            let mut value = HeaderValue::from_str(value)
                .map_err(|_| anyhow!("Invalid HTTP header value"))?;
            // This also prevents dependent request Debug output exposing headers.
            value.set_sensitive(true);
            if headers.insert(name, value).is_some() {
                bail!("Duplicate HTTP header name");
            }
        }
        Ok(headers)
    })();
    for value in entries.values_mut() {
        value.zeroize();
    }
    parsed
}

#[derive(Serialize)]
pub(super) struct HttpResponse {
    pub(super) status_code: u16,
    headers: HashMap<String, String>,
    pub(super) body: String,
}

impl Drop for HttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
        for value in self.headers.values_mut() {
            value.zeroize();
        }
    }
}

impl HttpResponse {
    fn to_json(&self) -> ResultType<String> {
        serde_json::to_string(self).map_err(|_| anyhow!("Cannot encode HTTP response"))
    }
}

struct ProxyConfig(Option<Socks5Server>);

impl Drop for ProxyConfig {
    fn drop(&mut self) {
        if let Some(conf) = self.0.as_mut() {
            conf.proxy.zeroize();
            conf.username.zeroize();
            conf.password.zeroize();
        }
    }
}

struct TcpRoute {
    api: Url,
    address: String,
    key: sign::PublicKey,
    proxy: Option<Proxy>,
    proxy_tls: Option<Arc<rustls::ClientConfig>>,
}

enum Route {
    Https(Client),
    Tcp(TcpRoute),
}

/// A task-local official transport, reused by the OIDC query loop. No cookies,
/// default credentials, insecure TLS cache, environment-proxy bypass or logging.
pub(super) struct Transport {
    route: Route,
}

fn same_api_target(target: &Url, api: &Url) -> bool {
    let base_path = api.path().trim_end_matches('/');
    target.origin() == api.origin()
        && (base_path.is_empty() || target.path() == base_path
            || target.path().strip_prefix(base_path).is_some_and(|rest| rest.starts_with('/')))
}

impl Transport {
    pub(super) async fn new(context: &AccountContext, target: &str) -> ResultType<Self> {
        ensure_current(context)?;
        let target = api::http_url(target, false)?;
        let api_url = api::http_url(&context.api_server, true)?;
        // Source's explicit raw-TCP mode, tightened from host-only matching to
        // origin + base path. Never selected as a fallback after any TLS failure.
        let raw_tcp = api::builtin(keys::OPTION_USE_RAW_TCP_FOR_API) == "Y"
            && !config::use_ws()
            && !api::is_public(&context.api_server)
            && same_api_target(&target, &api_url);
        if !raw_tcp && target.scheme() != "https" {
            bail!("Account HTTP transport requires HTTPS");
        }
        let address = if raw_tcp { api::rendezvous_server() } else { String::new() };
        let key = if raw_tcp { Some(api::public_key()?) } else { None };
        if raw_tcp && (address.contains("://") || address.contains(['/', '?', '#', '@'])) {
            bail!("Invalid account TCP proxy endpoint");
        }
        let proxy_conf = ProxyConfig(Config::get_socks());
        let tls_type = if get_cached_tls_accept_invalid_cert(target.as_str()) == Some(false) {
            match get_cached_tls_type(target.as_str()) {
                Some(TlsType::NativeTls) => TlsType::NativeTls,
                _ => TlsType::Rustls,
            }
        } else {
            TlsType::Rustls
        };
        ensure_current(context)?;

        // Proxy::from_conf may perform OS DNS and root-store construction is
        // blocking. Bound admission and caller wait; a timed-out OS operation
        // retains its slot until it really finishes, not an unbounded worker pool.
        let transport = timeout(CONSTRUCTION_TIMEOUT, async move {
            let permit = CONSTRUCTION_SLOTS.clone().acquire_owned().await
                .map_err(|_| anyhow!("HTTP client construction unavailable"))?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let proxy = proxy_conf.0.as_ref()
                    .map(|conf| Proxy::from_conf(conf, Some(REQUEST_TIMEOUT.as_millis() as u64)))
                    .transpose().map_err(|_| anyhow!("Invalid account proxy configuration"))?;
                let route = if let Some(key) = key {
                    let proxy_tls = if proxy.as_ref().is_some_and(|p| matches!(p.intercept, ProxyScheme::Https { .. })) {
                        Some(Arc::new(hbb_common::verifier::client_config(false)
                            .map_err(|_| anyhow!("Cannot construct strict proxy TLS client"))?))
                    } else {
                        None
                    };
                    Route::Tcp(TcpRoute { api: api_url, address, key, proxy, proxy_tls })
                } else {
                    Route::Https(create_http_client_strict(tls_type, proxy.as_ref())?)
                };
                Ok::<_, hbb_common::anyhow::Error>(Self { route })
            }).await.map_err(|_| anyhow!("HTTP client construction failed"))?
        }).await.map_err(|_| anyhow!("HTTP client construction timed out"))??;
        ensure_current(context)?;
        Ok(transport)
    }

    /// Official /api/login-options HEAD warmup, now bounded and fallible.
    pub(super) async fn probe(&self, url: &str) -> ResultType<()> {
        let parsed = api::http_url(url, false)?;
        timeout(REQUEST_TIMEOUT, async {
            match &self.route {
                Route::Https(client) => {
                    if parsed.scheme() != "https" {
                        bail!("Account HTTP transport requires HTTPS");
                    }
                    let response = client.head(parsed).send().await.map_err(http_error)?;
                    reject_redirect(response.status().as_u16())?;
                }
                Route::Tcp(route) => {
                    let request = Request {
                        url: Zeroizing::new(url.to_owned()), method: Method::HEAD,
                        body: None, headers: HeaderMap::new(),
                    };
                    tcp_proxy_request(route, request).await?;
                }
            }
            Ok(())
        }).await.map_err(|_| anyhow!("HTTP probe timed out"))?
    }

    pub(super) async fn request(&self, request: Request) -> ResultType<HttpResponse> {
        timeout(REQUEST_TIMEOUT, async {
            match &self.route {
                Route::Https(client) => http_request_http(client, request).await,
                Route::Tcp(route) => tcp_proxy_request(route, request).await,
            }
        }).await.map_err(|_| anyhow!("HTTP request timed out"))?
    }
}

// Adapted configure_http_client/create_http_client_async_with_url_strict.
// No Client::new fallback, no danger flag and no TLS-error retry.
fn create_http_client_strict(tls_type: TlsType, proxy: Option<&Proxy>) -> ResultType<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .connect_timeout(REQUEST_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    match tls_type {
        TlsType::NativeTls => builder = builder.use_native_tls(),
        _ => {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                let config = hbb_common::verifier::client_config(false)
                    .map_err(|_| anyhow!("Cannot construct strict HTTP TLS client"))?;
                builder = builder.use_preconfigured_tls(config);
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                builder = builder.use_rustls_tls();
            }
        }
    }
    if let Some(proxy) = proxy {
        let mut configured = match &proxy.intercept {
            ProxyScheme::Http { host, .. } => reqwest::Proxy::all(format!("http://{host}")),
            ProxyScheme::Https { host, .. } => reqwest::Proxy::all(format!("https://{host}")),
            ProxyScheme::Socks5 { addr, .. } => reqwest::Proxy::all(format!("socks5://{addr}")),
        }.map_err(|_| anyhow!("Invalid account proxy configuration"))?;
        if let Some(auth) = proxy.intercept.maybe_auth() {
            if !auth.username().is_empty() && !auth.password().is_empty() {
                configured = configured.basic_auth(auth.username(), auth.password());
            }
        }
        builder = builder.proxy(configured);
    }
    builder.build().map_err(|_| anyhow!("Cannot construct strict HTTP client"))
}

fn http_error(error: reqwest::Error) -> hbb_common::anyhow::Error {
    // Do not retain the original error as a source: its URL/query, headers or
    // response details can contain codes, passwords and bearer credentials.
    if error.is_timeout() {
        anyhow!("HTTP request timed out")
    } else if error.is_connect() {
        anyhow!("HTTP connection or TLS authentication failed")
    } else if error.is_builder() {
        anyhow!("Invalid HTTP request")
    } else if error.is_body() || error.is_decode() {
        anyhow!("Cannot read HTTP response")
    } else {
        anyhow!("HTTP transport failed")
    }
}

fn reject_redirect(status: u16) -> ResultType<()> {
    if (300..400).contains(&status) {
        bail!("Account HTTP redirects are not permitted");
    }
    Ok(())
}

async fn http_request_http(client: &Client, mut request: Request) -> ResultType<HttpResponse> {
    let parsed = api::http_url(&request.url, false)?;
    if parsed.scheme() != "https" {
        bail!("Account HTTP transport requires HTTPS");
    }
    let mut builder = client.request(request.method, parsed).headers(request.headers);
    if let Some(body) = request.body.as_mut() {
        builder = builder.body(std::mem::take(&mut **body));
    }
    let mut response = builder.send().await.map_err(http_error)?;
    let status_code = response.status().as_u16();
    reject_redirect(status_code)?;
    if response.content_length().is_some_and(|length| length > MAX_BODY as u64) {
        bail!("Account HTTP response is too large");
    }
    let mut result = HttpResponse { status_code, headers: HashMap::new(), body: String::new() };
    let mut header_bytes = 0usize;
    for (name, value) in response.headers() {
        header_bytes = header_bytes.saturating_add(name.as_str().len() + value.as_bytes().len());
        if header_bytes > MAX_HEADERS {
            bail!("Account HTTP response headers are too large");
        }
        result.headers.insert(name.to_string(), value.to_str().unwrap_or("").to_owned());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(http_error)? {
        if chunk.len() > MAX_BODY.saturating_sub(bytes.len()) {
            bail!("Account HTTP response is too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    result.body = String::from_utf8_lossy(&bytes).into_owned();
    Ok(result)
}

// The same pinned signed key-exchange and libsodium box/secretbox construction.
// Unlike secure_tcp_impl's peer compatibility path, every non-KeyExchange,
// malformed message, read failure and EOF is a hard failure before credentials.
async fn secure_tcp_silent(conn: &mut Stream, rs_pk: &sign::PublicKey) -> ResultType<()> {
    let bytes = conn.next().await
        .ok_or_else(|| anyhow!("Account proxy closed before authentication"))?
        .map_err(|_| anyhow!("Account proxy authentication read failed"))?;
    let msg = RendezvousMessage::parse_from_bytes(&bytes)
        .map_err(|_| anyhow!("Invalid account proxy key exchange"))?;
    let Some(rendezvous_message::Union::KeyExchange(exchange)) = msg.union else {
        bail!("Account proxy did not authenticate");
    };
    if exchange.keys.len() != 1 {
        bail!("Invalid account proxy key exchange");
    }
    let their_pk = sign::verify(&exchange.keys[0], rs_pk)
        .map_err(|_| anyhow!("Account proxy signature verification failed"))?;
    let their_pk: [u8; 32] = their_pk.as_slice().try_into()
        .map_err(|_| anyhow!("Invalid account proxy public key"))?;
    let (asymmetric_value, symmetric_value, key) = create_symmetric_key_msg(their_pk);
    let mut out = RendezvousMessage::new();
    out.set_key_exchange(KeyExchange {
        keys: vec![asymmetric_value, symmetric_value], ..Default::default()
    });
    conn.send(&out).await.map_err(|_| anyhow!("Account proxy key exchange failed"))?;
    conn.set_key(key);
    Ok(())
}

fn create_symmetric_key_msg(their_pk_b: [u8; 32]) -> (Bytes, Bytes, secretbox::Key) {
    let their_pk_b = box_::PublicKey(their_pk_b);
    let (our_pk_b, our_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &our_sk_b);
    (Vec::from(our_pk_b.0).into(), sealed_key.into(), key)
}

// Reuse the selected common library's actual CONNECT/SOCKS implementations,
// but never its https_connect_*_wrap_danger compatibility/fallback wrappers.
async fn connect_proxy(route: &TcpRoute) -> ResultType<Stream> {
    let Some(proxy) = &route.proxy else {
        let stream = hbb_common::tcp::FramedStream::new(
            &route.address, None, REQUEST_TIMEOUT.as_millis() as u64,
        ).await.map_err(|_| anyhow!("Cannot connect to account proxy"))?;
        return Ok(Stream::Tcp(stream));
    };
    let (host, port, tls_host) = match &proxy.intercept {
        ProxyScheme::Http { host, .. } | ProxyScheme::Https { host, .. } => {
            let scheme = if matches!(&proxy.intercept, ProxyScheme::Https { .. }) { "https" } else { "http" };
            let endpoint = Url::parse(&format!("{scheme}://{host}"))
                .map_err(|_| anyhow!("Invalid account proxy configuration"))?;
            let host = endpoint.host_str().ok_or_else(|| anyhow!("Invalid account proxy configuration"))?
                .trim_matches(['[', ']']).to_owned();
            let port = endpoint.port_or_known_default()
                .ok_or_else(|| anyhow!("Invalid account proxy configuration"))?;
            (host.clone(), port, Some(host))
        }
        ProxyScheme::Socks5 { addr, .. } => (addr.ip().to_string(), addr.port(), None),
    };
    let socket = tokio::net::TcpStream::connect((host.as_str(), port)).await
        .map_err(|_| anyhow!("Cannot connect to configured account proxy"))?;
    let local = socket.local_addr().map_err(|_| anyhow!("Cannot inspect account proxy connection"))?;
    use hbb_common::IntoTargetAddr as _;
    let target = route.address.as_str().into_target_addr()
        .map_err(|_| anyhow!("Invalid account TCP proxy endpoint"))?;
    let framed = match &proxy.intercept {
        ProxyScheme::Http { .. } => {
            let stream = proxy.http_connect(socket, &target).await
                .map_err(|_| anyhow!("Account proxy CONNECT failed"))?;
            hbb_common::tcp::FramedStream::from(stream, local)
        }
        ProxyScheme::Https { .. } => {
            let config = route.proxy_tls.as_ref()
                .ok_or_else(|| anyhow!("Strict account proxy TLS unavailable"))?;
            let name = rustls::pki_types::ServerName::try_from(tls_host.unwrap_or_default())
                .map_err(|_| anyhow!("Invalid account proxy TLS name"))?;
            let stream = tokio_rustls::TlsConnector::from(config.clone()).connect(name, socket).await
                .map_err(|_| anyhow!("Account proxy TLS authentication failed"))?;
            let stream = proxy.http_connect(stream, &target).await
                .map_err(|_| anyhow!("Account proxy CONNECT failed"))?;
            hbb_common::tcp::FramedStream::from(stream, local)
        }
        ProxyScheme::Socks5 { .. } => {
            let stream = if let Some(auth) = proxy.intercept.maybe_auth() {
                hbb_common::tokio_socks::tcp::Socks5Stream::connect_with_password_and_socket(
                    socket, target, auth.username(), auth.password(),
                ).await
            } else {
                hbb_common::tokio_socks::tcp::Socks5Stream::connect_with_socket(socket, target).await
            }.map_err(|_| anyhow!("Account SOCKS proxy connection failed"))?;
            hbb_common::tcp::FramedStream::from(stream, local)
        }
    };
    Ok(Stream::Tcp(framed))
}

async fn tcp_proxy_request(route: &TcpRoute, mut request: Request) -> ResultType<HttpResponse> {
    let parsed = api::http_url(&request.url, false)?;
    if !same_api_target(&parsed, &route.api) {
        bail!("Account proxy target does not match its authenticated context");
    }
    hbb_common::sodiumoxide::init().map_err(|_| anyhow!("Account proxy cryptography unavailable"))?;
    let mut conn = connect_proxy(route).await?;
    if let Stream::Tcp(stream) = &mut conn {
        stream.0.codec_mut().set_max_packet_length(MAX_HEADERS);
    } else {
        bail!("Account proxy requires an authenticated TCP transport");
    }
    secure_tcp_silent(&mut conn, &route.key).await?;
    if let Stream::Tcp(stream) = &mut conn {
        stream.0.codec_mut().set_max_packet_length(MAX_BODY + MAX_HEADERS + 4096);
    }
    let path = if let Some(query) = parsed.query() {
        format!("{}?{}", parsed.path(), query)
    } else {
        parsed.path().to_owned()
    };
    let headers = request.headers.iter().map(|(name, value)| {
        Ok(HeaderEntry {
            name: name.as_str().to_owned(),
            value: value.to_str().map_err(|_| anyhow!("Invalid HTTP header value"))?.to_owned(),
            ..Default::default()
        })
    }).collect::<ResultType<Vec<_>>>()?;
    let body = request.body.as_mut().map(|body| std::mem::take(&mut **body)).unwrap_or_default();
    let mut out = RendezvousMessage::new();
    out.set_http_proxy_request(HttpProxyRequest {
        method: request.method.as_str().to_owned(), path,
        headers, body: Bytes::from(body.into_bytes()), ..Default::default()
    });
    conn.send(&out).await.map_err(|_| anyhow!("Account proxy request failed"))?;
    drop(out);
    let bytes = conn.next().await.ok_or_else(|| anyhow!("Account proxy closed without a response"))?
        .map_err(|_| anyhow!("Account proxy response read failed"))?;
    let msg = RendezvousMessage::parse_from_bytes(&bytes)
        .map_err(|_| anyhow!("Invalid account proxy response"))?;
    let Some(rendezvous_message::Union::HttpProxyResponse(response)) = msg.union else {
        bail!("Unexpected account proxy response");
    };
    if !response.error.is_empty() {
        bail!("Account proxy reported a transport failure");
    }
    let status_code = u16::try_from(response.status)
        .ok().filter(|status| (100..600).contains(status))
        .ok_or_else(|| anyhow!("Invalid account proxy HTTP status"))?;
    reject_redirect(status_code)?;
    if response.body.len() > MAX_BODY {
        bail!("Account HTTP response is too large");
    }
    let mut result = HttpResponse { status_code, headers: HashMap::new(), body: String::new() };
    let mut header_bytes = 0usize;
    for entry in response.headers {
        header_bytes = header_bytes.saturating_add(entry.name.len() + entry.value.len());
        if header_bytes > MAX_HEADERS {
            bail!("Account HTTP response headers are too large");
        }
        HeaderName::from_bytes(entry.name.as_bytes()).map_err(|_| anyhow!("Invalid proxy response header"))?;
        HeaderValue::from_str(&entry.value).map_err(|_| anyhow!("Invalid proxy response header"))?;
        result.headers.insert(entry.name.to_lowercase(), entry.value);
    }
    result.body = String::from_utf8_lossy(&response.body).into_owned();
    Ok(result)
}

fn ensure_current(context: &AccountContext) -> ResultType<()> {
    if !state::context_is_current(context)? {
        bail!("Account context changed");
    }
    Ok(())
}

fn request_key(url: &str) -> [u8; 32] {
    Sha256::digest(url.as_bytes()).into()
}

fn remove_request(key: &[u8; 32], id: u64) {
    let mut requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if requests.get(key).is_some_and(|entry| entry.id == id) {
        requests.remove(key);
    }
}

struct RequestLifetime {
    key: [u8; 32],
    id: u64,
}

impl Drop for RequestLifetime {
    fn drop(&mut self) {
        remove_request(&self.key, self.id);
    }
}

/// The official URL-keyed asynchronous HttpService entry point. A URL owns one
/// unconsumed request, including its terminal result; another start must fail.
pub fn start(url: String, method: String, body: Option<String>, headers: String) -> ResultType<()> {
    let request = Request::new(url, &method, body, headers)?;
    let context = state::current_context()?;
    let runtime = crate::executor::runtime().map_err(|_| anyhow!("Account HTTP executor unavailable"))?;
    let key = request_key(&request.url);
    let id = NEXT_REQUEST.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| anyhow!("Account HTTP request sequence exhausted"))?;
    let now = Instant::now();
    {
        let mut requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        requests.retain(|_, entry| entry.expires > now
            && (entry.context == context || entry.context.generation > context.generation));
        if requests.contains_key(&key) {
            bail!("An account HTTP request for this URL is already pending or unconsumed");
        }
        if requests.len() >= MAX_REQUESTS {
            bail!("Too many account HTTP requests");
        }
        requests.insert(key, PendingRequest {
            id, context: context.clone(), expires: now + REQUEST_LIFETIME, result: None, job: None,
        });
    }
    if let Err(error) = ensure_current(&context) {
        remove_request(&key, id);
        return Err(error);
    }
    let job = runtime.spawn(async move {
        let _lifetime = RequestLifetime { key, id };
        {
            let outcome = timeout(REQUEST_LIFETIME, async {
                let transport = Transport::new(&context, &request.url).await?;
                ensure_current(&context)?;
                let response = transport.request(request).await?;
                ensure_current(&context)?;
                response.to_json().map(Zeroizing::new)
            }).await.unwrap_or_else(|_| Err(anyhow!("HTTP request timed out")));
            let current = state::context_is_current(&context);
            let mut requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(entry) = requests.get_mut(&key).filter(|entry| entry.id == id) {
                match current {
                    Ok(true) => {
                        entry.result = Some(outcome);
                        entry.expires = Instant::now() + RESULT_RETENTION;
                    }
                    Ok(false) => { requests.remove(&key); }
                    Err(_) => {
                        entry.result = Some(Err(anyhow!("Account context unavailable")));
                        entry.expires = Instant::now() + RESULT_RETENTION;
                    }
                }
            }
        }
        let deadline = Instant::now() + RESULT_RETENTION;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if Instant::now() >= deadline
                || matches!(state::context_is_current(&context), Ok(false))
            {
                remove_request(&key, id);
                break;
            }
            let current = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&key).is_some_and(|entry| entry.id == id);
            if !current { break; }
        }
    });
    {
        let mut requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = requests.get_mut(&key).filter(|entry| entry.id == id) {
            entry.job = Some(job.abort_handle());
        } else {
            job.abort();
        }
    }
    Ok(())
}

/// Pending => one space; terminal => consume once; genuinely absent => None.
/// B is consulted outside the registry lock, including a final read-side check.
pub fn poll(url: &str) -> ResultType<Option<String>> {
    let key = request_key(url);
    let snapshot = {
        let requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        requests.get(&key).map(|entry| (entry.id, entry.context.clone()))
    };
    let Some((id, context)) = snapshot else { return Ok(None) };
    if !state::context_is_current(&context)? {
        remove_request(&key, id);
        bail!("Account context changed");
    }
    let outcome = {
        let mut requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = requests.get_mut(&key).filter(|entry| entry.id == id) else {
            return Ok(None);
        };
        // Completion may have installed a fresh retention deadline during B's
        // check. Expire only this matching entry's currently published state.
        if entry.expires <= Instant::now() {
            requests.remove(&key);
            bail!("Account HTTP result expired");
        }
        if entry.result.is_none() {
            None
        } else {
            let outcome = entry.result.take();
            requests.remove(&key);
            outcome
        }
    };
    ensure_current(&context)?;
    match outcome {
        None => Ok(Some(" ".to_owned())),
        Some(Ok(mut response)) => Ok(Some(std::mem::take(&mut *response))),
        Some(Err(error)) => Err(error),
    }
}
