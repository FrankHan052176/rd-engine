// SPDX-License-Identifier: AGPL-3.0-only
// RustDesk contributors: hbbs_http/account.rs and HbbHttpResponse at
// 092a961b629d318fe290eeafac0cd214a1e9deeb. Modified for rd-engine 2026-09-23.
// Exact provenance/security adaptations: UPSTREAM.json. Dart owns login business.

use super::{AuthAttempt, api, http::{Request, Transport}, state};
use hbb_common::{
    ResultType, anyhow::anyhow, bail,
    base64::{Engine as _, engine::general_purpose::STANDARD},
    config::Config,
    serde_derive::{Deserialize, Serialize},
    serde_json::{self, Map, Value},
};
use serde::de::DeserializeOwned;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{collections::HashMap, sync::{LazyLock, Mutex}, time::{Duration, Instant}};
use tokio::task::AbortHandle;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const QUERY_INTERVAL: Duration = Duration::from_secs(1);
const QUERY_TIMEOUT: Duration = Duration::from_secs(60 * 3);
const AUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(36);
const RESULT_RETENTION: Duration = Duration::from_secs(60);
const REQUESTING_ACCOUNT_AUTH: &str = "Requesting account auth";
const WAITING_ACCOUNT_AUTH: &str = "Waiting account auth";
const LOGIN_ACCOUNT_AUTH: &str = "Login account auth";

static OIDC_SESSION: LazyLock<Mutex<OidcSession>> = LazyLock::new(|| Mutex::new(OidcSession::new()));

// The four-way official envelope is distinct from HTTP status. Never turn a
// parsing error into absent/success, or include the original response in errors.
enum HbbHttpResponse<T> {
    ErrorFormat,
    Error(Zeroizing<String>),
    DataTypeFormat,
    Data(T),
}

impl<T: DeserializeOwned> HbbHttpResponse<T> {
    fn parse(body: &str) -> ResultType<Self> {
        let map = serde_json::from_str::<Map<String, Value>>(body)
            .map_err(|_| anyhow!("Invalid account response"))?;
        if let Some(error) = map.get("error") {
            if let Some(error) = error.as_str() {
                Ok(Self::Error(Zeroizing::new(error.to_owned())))
            } else {
                Ok(Self::ErrorFormat)
            }
        } else {
            match serde_json::from_value(Value::Object(map)) {
                Ok(value) => Ok(Self::Data(value)),
                Err(_) => Ok(Self::DataTypeFormat),
            }
        }
    }
}

#[derive(Deserialize)]
struct OidcAuthUrl {
    code: String,
    // Same URL wire string; validate with Url before publishing. String ownership
    // permits clearing our retained code-bearing buffer, unlike cloning Url.
    url: String,
}

impl Drop for OidcAuthUrl {
    fn drop(&mut self) {
        self.code.zeroize();
        self.url.zeroize();
    }
}

#[derive(Deserialize, Serialize, Default)]
struct DeviceInfo {
    #[serde(default)]
    os: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    name: String,
}

#[derive(Serialize, Deserialize, Default)]
struct WhitelistItem {
    data: String,
    info: DeviceInfo,
    exp: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct UserInfo {
    #[serde(default, flatten)]
    settings: UserSettings,
    #[serde(default)]
    login_device_whitelist: Vec<WhitelistItem>,
    #[serde(default)]
    other: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Default)]
struct UserSettings {
    #[serde(default)]
    email_verification: bool,
    #[serde(default)]
    email_alarm_notification: bool,
}

#[derive(Clone, Copy, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
enum UserStatus {
    Disabled = 0,
    Normal = 1,
    Unverified = -1,
}

impl Default for UserStatus {
    fn default() -> Self { Self::Normal }
}

#[derive(Serialize, Deserialize)]
struct UserPayload {
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    avatar: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    status: UserStatus,
    info: UserInfo,
    #[serde(default)]
    is_admin: bool,
    #[serde(default)]
    third_auth_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AuthBody {
    access_token: String,
    r#type: String,
    #[serde(default)]
    tfa_type: String,
    #[serde(default)]
    secret: String,
    user: UserPayload,
}

impl Drop for AuthBody {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.secret.zeroize();
    }
}

// A borrowed serialization view avoids the upstream repeated token/secret Clone.
// Necessary returned FRB/Dart and HTTP-library/serde copies remain outside this
// owner's erasure guarantees.
#[derive(Serialize)]
struct AuthResult<'a> {
    state_msg: &'a str,
    failed_msg: &'a str,
    url: Option<&'a str>,
    auth_body: Option<&'a AuthBody>,
    account_scope: Option<&'a str>,
}

struct OidcSession {
    state_msg: &'static str,
    failed_msg: &'static str,
    url: Option<Zeroizing<String>>,
    auth_body: Option<AuthBody>,
    attempt: Option<AuthAttempt>,
    attempt_receipt: Option<String>,
    account_scope: Option<String>,
    terminal_consumed: bool,
    running: bool,
    expires: Option<Instant>,
    job: Option<AbortHandle>,
}

impl OidcSession {
    fn new() -> Self {
        Self {
            state_msg: REQUESTING_ACCOUNT_AUTH, failed_msg: "", url: None,
            auth_body: None, attempt: None, running: false, expires: None, job: None,
            attempt_receipt: None, account_scope: None, terminal_consumed: false,
        }
    }

    fn is_current(&self, attempt: &AuthAttempt) -> bool {
        self.attempt.as_ref().is_some_and(|active| {
            active.generation == attempt.generation && active.context == attempt.context
        })
    }

    fn reset(&mut self) {
        if let Some(job) = self.job.take() {
            job.abort();
        }
        self.state_msg = REQUESTING_ACCOUNT_AUTH;
        self.failed_msg = "";
        self.url = None;
        self.auth_body = None;
        self.attempt = None;
        self.attempt_receipt = None;
        self.account_scope = None;
        self.terminal_consumed = false;
        self.running = false;
        self.expires = None;
    }

    fn encode_result(&self) -> ResultType<String> {
        serde_json::to_string(&AuthResult {
            state_msg: self.state_msg,
            failed_msg: self.failed_msg,
            url: self.url.as_ref().map(|url| url.as_str()),
            auth_body: self.auth_body.as_ref(),
            account_scope: self.account_scope.as_deref(),
        }).map_err(|_| anyhow!("Cannot encode account authentication result"))
    }
}

fn discard(attempt: &AuthAttempt) -> ResultType<()> {
    // Aborting the async task cannot cancel an already queued blocking commit.
    // Retire its exact B witness before losing A's cancellation mapping. A
    // missing/replaced witness or poisoned owner already refuses this commit;
    // cancellation never logs out an account whose commit won the owner lock.
    let retired = state::cancel_auth(attempt);
    let mut session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if session.is_current(attempt) {
        session.reset();
    }
    retired
}

// Erase retained payloads if the async task is canceled or unwinds, not just
// when its normal retention timer finishes. The actual attempt remains B-owned.
struct AttemptLifetime<'a>(&'a AuthAttempt);

impl Drop for AttemptLifetime<'_> {
    fn drop(&mut self) {
        let _ = discard(self.0);
    }
}

fn ensure_current(attempt: &AuthAttempt) -> ResultType<()> {
    if !state::auth_is_current(attempt)? {
        bail!("Account authentication was canceled or replaced");
    }
    Ok(())
}

fn publish_url(attempt: &AuthAttempt, url: String) -> ResultType<()> {
    let url = Zeroizing::new(url);
    ensure_current(attempt)?;
    let mut session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if !session.is_current(attempt) {
        bail!("Account authentication was replaced");
    }
    session.state_msg = WAITING_ACCOUNT_AUTH;
    session.failed_msg = "";
    session.url = Some(url);
    Ok(())
}

fn publish_auth_body(attempt: &AuthAttempt, body: AuthBody, account_scope: Option<String>) -> ResultType<()> {
    // B's committed-attempt witness keeps this original attempt authorized after
    // commit advances account generation. Never use its old context alone here.
    ensure_current(attempt)?;
    let mut session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if !session.is_current(attempt) {
        bail!("Account authentication was replaced");
    }
    session.state_msg = LOGIN_ACCOUNT_AUTH;
    session.failed_msg = "";
    session.url = None;
    session.auth_body = Some(body);
    session.account_scope = account_scope;
    session.running = false;
    session.expires = Some(Instant::now() + RESULT_RETENTION);
    Ok(())
}

fn finish(attempt: &AuthAttempt, failure: Option<&'static str>) {
    let failure = match state::auth_is_current(attempt) {
        Ok(true) => failure,
        Ok(false) => {
            let _ = discard(attempt);
            return;
        }
        Err(_) => Some("Account context unavailable"),
    };
    let mut session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if session.is_current(attempt) {
        session.running = false;
        session.expires = Some(Instant::now() + RESULT_RETENTION);
        if let Some(failure) = failure {
            session.failed_msg = failure;
            session.url = None;
            session.auth_body = None;
        }
    }
}

async fn auth(
    transport: &Transport, api_server: &str, op: &str, id: &str, uuid: &str,
) -> ResultType<HbbHttpResponse<OidcAuthUrl>> {
    let device_info: Value = serde_json::from_str(&api::device_info()?)
        .map_err(|_| anyhow!("Invalid login device information"))?;
    let body = serde_json::json!({
        "op": op, "id": id, "uuid": uuid,
        "deviceInfo": device_info, "apiDomain": api_server,
    }).to_string();
    let response = transport.request(Request::new(
        format!("{api_server}/api/oidc/auth"), "post", Some(body),
        r#"{"Content-Type":"application/json"}"#.to_owned(),
    )?).await?;
    HbbHttpResponse::parse(&response.body)
}

async fn query(
    transport: &Transport, api_server: &str, code: &str, id: &str, uuid: &str,
) -> ResultType<HbbHttpResponse<AuthBody>> {
    let url = Url::parse_with_params(
        &format!("{api_server}/api/oidc/auth-query"),
        &[("code", code), ("id", id), ("uuid", uuid)],
    ).map_err(|_| anyhow!("Invalid account query endpoint"))?;
    // The same official HTTP body envelope, without serializing it only to parse
    // it again inside Rust. The public HttpService still receives the full JSON.
    let response = transport.request(Request::new(
        url.into(), "get", None, "{}".to_owned(),
    )?).await?;
    HbbHttpResponse::parse(&response.body)
}

async fn auth_task(attempt: &AuthAttempt, op: &str, remember_me: bool) -> Option<&'static str> {
    let api_server = &attempt.context.api_server;
    let id = Config::get_id();
    let uuid = STANDARD.encode(hbb_common::get_uuid());
    let warmup = format!("{api_server}/api/login-options");
    let requested = tokio::time::timeout(AUTH_REQUEST_TIMEOUT, async {
        ensure_current(attempt)?;
        let transport = Transport::new(&attempt.context, &warmup).await?;
        transport.probe(&warmup).await?;
        ensure_current(attempt)?;
        let response = auth(&transport, api_server, op, &id, &uuid).await?;
        Ok::<_, hbb_common::anyhow::Error>((transport, response))
    }).await;
    if ensure_current(attempt).is_err() {
        return None;
    }
    let (transport, mut code_url) = match requested {
        Ok(Ok((transport, HbbHttpResponse::Data(code_url)))) => (transport, code_url),
        Ok(Ok((_, HbbHttpResponse::Error(_)))) => return Some("Account authentication rejected by server"),
        Ok(Ok(_)) => return Some("Invalid auth response"),
        Ok(Err(_)) => return Some("Account authentication request failed"),
        Err(_) => return Some("Account authentication request timed out"),
    };
    // The external provider URL is an authorized business result, not a log or
    // error context. Do not open an insecure or credential-userinfo URL.
    let valid_url = api::http_url(&code_url.url, false)
        .is_ok_and(|url| url.scheme() == "https");
    if !valid_url || code_url.code.is_empty() || code_url.code.len() > 16 * 1024 {
        return Some("Invalid auth response");
    }
    if publish_url(attempt, std::mem::take(&mut code_url.url)).is_err() {
        return None;
    }

    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    while tokio::time::Instant::now() < deadline && ensure_current(attempt).is_ok() {
        let queried = tokio::time::timeout_at(
            deadline, query(&transport, api_server, &code_url.code, &id, &uuid),
        ).await;
        if ensure_current(attempt).is_err() {
            return None;
        }
        match queried {
            Ok(Ok(HbbHttpResponse::Data(body))) => {
                let account_scope = if body.r#type == "access_token" {
                    let user_info = serde_json::json!({
                        "name": body.user.name,
                        "display_name": body.user.display_name,
                        "avatar": body.user.avatar,
                        "status": body.user.status,
                    }).to_string();
                    // This one token copy is required: B owns the committed
                    // credential, while the official cbLogin must receive it.
                    let token = body.access_token.clone();
                    let commit_attempt = attempt.clone();
                    let committed = tokio::task::spawn_blocking(move || {
                        state::commit_oidc(&commit_attempt, token, user_info, remember_me)
                    }).await;
                    match committed {
                        Ok(Ok(receipt)) => Some(receipt),
                        _ => return Some("Account credential commit failed"),
                    }
                } else {
                    None
                };
                // Verification/email_check bodies remain Dart business. They do
                // not prematurely commit an account credential.
                if publish_auth_body(attempt, body, account_scope).is_err() {
                    return None;
                }
                return None;
            }
            Ok(Ok(HbbHttpResponse::Error(error))) => {
                if !error.contains("No authed oidc is found") {
                    return Some("Account authentication rejected by server");
                }
            }
            Ok(Ok(_)) | Ok(Err(_)) => {
                // Exact upstream query behavior: transient transport/format
                // errors keep polling to the absolute three-minute deadline.
            }
            Err(_) => break,
        }
        tokio::time::sleep_until((tokio::time::Instant::now() + QUERY_INTERVAL).min(deadline)).await;
    }
    if ensure_current(attempt).is_ok() { Some("timeout") } else { None }
}

/// Start or replace the official OIDC attempt, without a runtime/block_on or
/// waiting under a lock for the previous network operation to finish.
pub fn start(receipt: String, op: String, remember_me: bool) -> ResultType<String> {
    if op.len() > 16 * 1024 {
        bail!("Account authentication provider is too large");
    }
    let runtime = crate::executor::runtime().map_err(|_| anyhow!("Account authentication executor unavailable"))?;
    let attempt = state::begin_auth(&receipt)?;
    ensure_current(&attempt)?;
    let attempt_receipt = hbb_common::uuid::Uuid::new_v4().to_string();
    {
        let mut session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // begin_auth generations are monotonic across server/account changes.
        // A delayed older start must not abort the already-installed newer job.
        if session.attempt.as_ref().is_some_and(|active| active.generation > attempt.generation) {
            bail!("Account authentication was replaced");
        }
        session.reset();
        session.attempt = Some(attempt.clone());
        session.attempt_receipt = Some(attempt_receipt.clone());
        session.running = true;
        session.expires = Some(Instant::now() + AUTH_REQUEST_TIMEOUT + QUERY_TIMEOUT);
    }
    let worker_attempt = attempt.clone();
    let job = runtime.spawn(async move {
        let _lifetime = AttemptLifetime(&worker_attempt);
        let failure = auth_task(&worker_attempt, &op, remember_me).await;
        finish(&worker_attempt, failure);
        // Bound secret retention even if Dart stops polling. Also retire promptly
        // after logout/server change rather than waiting for the full TTL.
        let deadline = Instant::now() + RESULT_RETENTION;
        loop {
            tokio::time::sleep(QUERY_INTERVAL).await;
            if Instant::now() >= deadline || matches!(state::auth_is_current(&worker_attempt), Ok(false)) {
                let _ = discard(&worker_attempt);
                break;
            }
            let current = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_current(&worker_attempt);
            if !current { break; }
        }
    });
    {
        let mut session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if session.is_current(&attempt) {
            session.job = Some(job.abort_handle());
        } else {
            job.abort();
        }
    }
    Ok(attempt_receipt)
}

/// Dialog cancellation invalidates the attempt, never the already committed
/// account. A newer begin_auth that races after cancellation must survive.
pub fn cancel(attempt_receipt: &str) -> ResultType<()> {
    let attempt = {
        let session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if session.attempt_receipt.as_deref() != Some(attempt_receipt) {
            bail!("Unknown or retired account authentication attempt");
        }
        session.attempt.clone().ok_or_else(|| anyhow!("No account authentication attempt"))?
    };
    // B matches this exact attempt atomically; a delayed old dialog cannot
    // cancel a new dialog which starts between this snapshot and the call.
    discard(&attempt)
}

/// Return official URL/wait/auth-body/error shapes. Terminal bodies are delivered
/// once, and a final B check rejects results canceled while being serialized.
pub fn result(attempt_receipt: &str) -> ResultType<String> {
    let attempt = {
        let session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if session.attempt_receipt.as_deref() != Some(attempt_receipt) {
            bail!("Unknown or retired account authentication attempt");
        }
        session.attempt.clone().ok_or_else(|| anyhow!("No account authentication attempt"))?
    };
    if !state::auth_is_current(&attempt)? {
        let _ = discard(&attempt);
        bail!("Account authentication was canceled or replaced");
    }
    let mut response = {
        let mut session = OIDC_SESSION.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !session.is_current(&attempt) || session.attempt_receipt.as_deref() != Some(attempt_receipt) {
            bail!("Account authentication was replaced");
        }
        // Publication can replace the running deadline while B is checked.
        // Decide expiry against the current attempt under the session lock.
        if session.expires.is_some_and(|expires| expires <= Instant::now()) {
            drop(session);
            discard(&attempt)?;
            bail!("Account authentication result expired");
        }
        if session.terminal_consumed {
            bail!("Account authentication result was already consumed");
        }
        let encoded = Zeroizing::new(session.encode_result()?);
        if !session.running {
            // Keep only non-secret cancellation ownership so closing the
            // successful dialog can retire its witness without logging out.
            session.url = None;
            session.auth_body = None;
            session.account_scope = None;
            session.terminal_consumed = true;
        }
        encoded
    };
    ensure_current(&attempt)?;
    Ok(std::mem::take(&mut *response))
}
