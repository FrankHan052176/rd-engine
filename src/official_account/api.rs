// SPDX-License-Identifier: AGPL-3.0-only
// RustDesk contributors: selected helpers from rustdesk/rustdesk
// 092a961b629d318fe290eeafac0cd214a1e9deeb. Modified for rd-engine 2026-09-23.
// Exact source selections, hashes and security adaptations: UPSTREAM.json.

use base::config::keys;
use hbb_common::{
    ResultType, anyhow::anyhow, bail,
    base64::{Engine as _, engine::general_purpose::STANDARD},
    config::{self, Config, RENDEZVOUS_PORT},
    serde_derive::Serialize,
    serde_json,
    sha2::{Digest, Sha256},
    socket_client::{check_port, increase_port},
    sodiumoxide::crypto::sign,
};
use std::sync::Mutex;
use url::Url;

#[cfg(target_os = "windows")]
#[path = "upstream/custom_server.rs"]
mod custom_server;

static DEVICE_NAME: Mutex<String> = Mutex::new(String::new());

/// The existing official `main_device_name` bridge supplies the mobile name.
/// This is not another public bridge method or a persisted account option.
pub fn set_device_name(name: String) {
    *DEVICE_NAME.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
}

#[cfg(target_os = "windows")]
fn get_license_from_exe_name() -> ResultType<custom_server::CustomServer> {
    let mut exe = std::env::current_exe()?.to_str().unwrap_or("").to_owned();
    // The portable launcher supplies the original executable's licensed name.
    if let Ok(portable_exe) = std::env::var("RUSTDESK_APPNAME") {
        exe = portable_exe;
    }
    custom_server::get_custom_server_from_string(&exe)
}

pub(super) fn builtin(key: &str) -> String {
    config::BUILTIN_SETTINGS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(key)
        .cloned()
        .unwrap_or_default()
}

fn get_custom_rendezvous_server(custom: String) -> String {
    #[cfg(target_os = "windows")]
    if let Ok(lic) = get_license_from_exe_name() {
        if !lic.host.is_empty() {
            return lic.host;
        }
    }
    if !custom.is_empty() {
        return custom;
    }
    config::PROD_RENDEZVOUS_SERVER
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn get_api_server_(api: String, custom: String) -> String {
    #[cfg(target_os = "windows")]
    if let Ok(lic) = get_license_from_exe_name() {
        if !lic.api.is_empty() {
            return lic.api;
        }
    }
    if !api.is_empty() {
        return api;
    }
    let s0 = get_custom_rendezvous_server(custom);
    if !s0.is_empty() {
        let s = increase_port(&s0, -2);
        if s == s0 {
            return format!("http://{}:{}", s, RENDEZVOUS_PORT - 2);
        }
        return format!("http://{}", s);
    }
    "https://admin.rustdesk.com".to_owned()
}

/// Official display/resolution semantics, including Windows filename licenses.
/// Deliberately does not silently turn an official `http` result into `https`.
/// The transport separately enforces authenticated delivery.
pub fn server() -> String {
    if Config::no_register_device() {
        return String::new();
    }
    let mut res = get_api_server_(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
    );
    if res.ends_with('/') {
        res.pop();
    }
    if res.starts_with("https")
        && res.ends_with(":21114")
        && builtin(keys::OPTION_ALLOW_HTTPS_21114) != "Y"
    {
        return res.replace(":21114", "");
    }
    res
}

pub(super) fn is_public(url: &str) -> bool {
    let parsed = Url::parse(url)
        .ok()
        .filter(|parsed| parsed.has_host())
        .or_else(|| Url::parse(&format!("http://{url}")).ok());
    let Some(host) = parsed.as_ref().and_then(Url::host_str) else {
        return false;
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    host == "rustdesk.com" || host.ends_with(".rustdesk.com")
}

/// The pinned synchronous `get_key(true)` branch; no application IPC dependency.
fn key() -> String {
    #[cfg(target_os = "windows")]
    if let Ok(lic) = get_license_from_exe_name() {
        if !lic.key.is_empty() {
            return lic.key;
        }
    }
    let key = Config::get_option("key");
    if key.is_empty() {
        config::RS_PUB_KEY.to_owned()
    } else {
        key
    }
}

pub(super) fn public_key() -> ResultType<sign::PublicKey> {
    let bytes = STANDARD.decode(key()).map_err(|_| anyhow!("Invalid account server public key"))?;
    sign::PublicKey::from_slice(&bytes)
        .ok_or_else(|| anyhow!("Invalid account server public key"))
}

pub(super) fn rendezvous_server() -> String {
    #[cfg(target_os = "windows")]
    if let Ok(lic) = get_license_from_exe_name() {
        if !lic.host.is_empty() {
            return check_port(lic.host, RENDEZVOUS_PORT);
        }
    }
    check_port(Config::get_rendezvous_server(), RENDEZVOUS_PORT)
}

fn parse_endpoint(value: &str) -> ResultType<Url> {
    // Url::parse intentionally repairs some input; do not admit that ambiguity
    // at the credential boundary, or allow userinfo to become part of a scope.
    if value.is_empty() || value.len() > 16 * 1024
        || value.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        bail!("Invalid account endpoint");
    }
    let parsed = Url::parse(value).map_err(|_| anyhow!("Invalid account endpoint"))?;
    let authority = value.split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .ok_or_else(|| anyhow!("Invalid account endpoint"))?;
    if !parsed.has_host() || parsed.cannot_be_a_base()
        || !parsed.username().is_empty() || parsed.password().is_some()
        || authority.contains('@') || parsed.port() == Some(0)
    {
        bail!("Invalid account endpoint");
    }
    let bytes = value.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'%' && (i + 2 >= bytes.len()
            || !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit())
        {
            bail!("Invalid account endpoint");
        }
    }
    Ok(parsed)
}

pub(super) fn http_url(value: &str, base: bool) -> ResultType<Url> {
    let parsed = parse_endpoint(value)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.fragment().is_some()
        || (base && parsed.query().is_some())
    {
        bail!("Invalid account HTTP endpoint");
    }
    Ok(parsed)
}

fn canonical_endpoint(url: &Url, default_port: u16) -> ResultType<String> {
    let host = url.host_str().ok_or_else(|| anyhow!("Invalid account endpoint"))?;
    // Tuple serialization separates IPv6, path and port without ambiguous joins.
    serde_json::to_string(&(
        url.scheme(), host, url.port_or_known_default().unwrap_or(default_port), url.path(),
    )).map_err(|_| anyhow!("Cannot encode account scope"))
}

/// Non-secret identity for the effective API plus its rendezvous/key trust.
/// B serializes configuration changes while capturing this value.
pub fn scope() -> ResultType<String> {
    let api = http_url(&server(), true)?;
    let rendezvous = rendezvous_server();
    let rendezvous = if rendezvous.contains("://") {
        parse_endpoint(&rendezvous)?
    } else {
        parse_endpoint(&format!("tcp://{rendezvous}"))?
    };
    if !matches!(rendezvous.scheme(), "tcp" | "ws" | "wss")
        || rendezvous.query().is_some() || rendezvous.fragment().is_some()
        || (rendezvous.scheme() == "tcp" && !matches!(rendezvous.path(), "" | "/"))
    {
        bail!("Invalid account rendezvous endpoint");
    }
    let trust_key = public_key()?;
    let value = serde_json::to_vec(&(
        "rd-engine/official-account/scope/v1",
        canonical_endpoint(&api, 443)?,
        canonical_endpoint(&rendezvous, RENDEZVOUS_PORT as u16)?,
        trust_key.as_ref(),
        builtin(keys::OPTION_USE_RAW_TCP_FOR_API) == "Y",
        config::use_ws(),
    )).map_err(|_| anyhow!("Cannot encode account scope"))?;
    let digest = Sha256::digest(&value);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(encoded)
}

#[derive(Serialize)]
struct LoginDeviceInfo {
    os: &'static str,
    r#type: &'static str,
    name: String,
}

fn hostname() -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let mut name = hbb_common::whoami::fallible::hostname()
            .unwrap_or_else(|_| "localhost".to_owned());
        name.make_ascii_lowercase();
        #[cfg(target_os = "macos")]
        if name.ends_with(".local") {
            name = name.trim_end_matches(".local").to_owned();
        }
        name
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        DEVICE_NAME.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }
}

pub fn device_info() -> ResultType<String> {
    serde_json::to_string(&LoginDeviceInfo {
        os: std::env::consts::OS,
        r#type: "client",
        name: hostname(),
    }).map_err(|_| anyhow!("Cannot encode login device information"))
}
