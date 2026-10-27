use super::{ControlError, ServiceSnapshot};
use crate::{authentication::{Passwords, PrimaryPolicy, salted_password}, host::{HostCredentials, HostOptions}, publisher::{CodecSelection, PublisherBackend}};
use hbb_common::{config::{self, CheckedHostConfig, Config}, sodiumoxide::crypto::sign};
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};

pub(super) struct Secret(pub String);
impl Drop for Secret { fn drop(&mut self) { wipe(&mut self.0); } }
pub(super) fn wipe(value: &mut String) {
    // NUL bytes preserve UTF-8, and sodium's memzero cannot be optimized away.
    unsafe { hbb_common::sodiumoxide::utils::memzero(value.as_bytes_mut()); }
}

pub(super) fn option<'a>(options: &'a HashMap<String, String>, key: &str) -> &'a str {
    options.get(key).map(String::as_str).unwrap_or("")
}
pub(super) fn enabled(options: &HashMap<String, String>, key: &str) -> bool {
    config::option2bool(key, option(options, key))
}
pub(super) fn validate(options: &HashMap<String, String>) -> Result<(), ControlError> {
    if options.len() > 256 || options.iter().any(|(key, value)| key.len() > 128 || value.len() > 4096) {
        return Err(ControlError("Host configuration exceeds its bounds"));
    }
    for key in ["2fa", "totp", "bot", "os-login", "os-login-password", "whitelist", "ip-whitelist", "id-whitelist"] {
        if !option(options, key).is_empty() { return Err(ControlError("Configured authentication requirement is unsupported by this host")); }
    }
    for key in ["enable-trusted-devices", "enable-os-login", "allow-logon-screen-password", "allow-only-conn-window-open", "allow-remote-config-modification"] {
        if options.contains_key(key) && enabled(options, key) { return Err(ControlError("Configured authorization requirement is unsupported by this host")); }
    }
    for key in ["enable-clipboard", "enable-file-transfer", "enable-audio", "enable-remote-printer", "enable-terminal", "enable-tunnel", "enable-camera", "enable-record-session", "enable-privacy-mode", "enable-remote-restart", "enable-block-input"] {
        if option(options, key) == "Y" { return Err(ControlError("Requested host capability has no implemented adapter")); }
    }
    if !matches!(option(options, "approve-mode"), "" | "password" | "click" | "both")
        || !matches!(option(options, "verification-method"), "" | "use-temporary-password" | "use-permanent-password" | "use-both-passwords")
        || !matches!(option(options, "temporary-password-length"), "" | "6" | "8" | "10")
        || !matches!(option(options, "access-mode"), "" | "full" | "view" | "custom") {
        return Err(ControlError("Unsupported host authentication or access policy"));
    }
    if enabled(options, "allow-websocket") || !option(options, "proxy-url").is_empty() {
        return Err(ControlError("Configured host transport is unsupported"));
    }
    if enabled(options, "direct-server") { direct_address(options)?; }
    Ok(())
}

pub(super) fn is_secret_option(key: &str, value: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    // `key` is public only when it is an actual Ed25519 rendezvous key. Older
    // installations may carry an opaque relay licence credential in this slot.
    lower == "key" && !value.is_empty() && !hbb_common::sodiumoxide::base64::decode(value,
        hbb_common::sodiumoxide::base64::Variant::Original).is_ok_and(|key| key.len() == 32)
        || lower == "2fa" || lower == "bot" || lower.contains("token") || lower.contains("secret")
        || lower.contains("password") && !matches!(lower.as_str(), "temporary-password-length" | "allow-numeric-one-time-password" | "allow-logon-screen-password")
}
pub(super) fn sanitized(options: &HashMap<String, String>) -> HashMap<String, String> {
    options.iter().filter(|(key, value)| !is_secret_option(key, value)).map(|(k, v)| (k.clone(), v.clone())).collect()
}

pub(super) fn temporary(options: &HashMap<String, String>) -> Secret {
    let length = match option(options, "temporary-password-length") { "8" => 8, "10" => 10, _ => 6 };
    Secret(if enabled(options, "allow-numeric-one-time-password") { Config::get_auto_numeric_password(length) } else { Config::get_auto_password(length) })
}

pub(super) fn credentials(config: &CheckedHostConfig, temporary: &Secret, revision: u64, previous: Option<&HostCredentials>) -> Arc<HostCredentials> {
    let method = option(&config.options, "verification-method");
    let temporary = (method != "use-permanent-password" && !temporary.0.is_empty())
        .then(|| salted_password(temporary.0.as_bytes(), &config.salt));
    let permanent = if method != "use-temporary-password" { config.permanent_h1 } else { None };
    let passwords = Passwords::from_host(temporary, permanent);
    let policy = match option(&config.options, "approve-mode") {
        "password" => PrimaryPolicy::PasswordOnly,
        "click" => PrimaryPolicy::ClickOnly,
        _ => PrimaryPolicy::PasswordOrClick,
    };
    Arc::new(match previous {
        Some(previous) => HostCredentials::revised(revision, config.salt.clone(), passwords, policy, previous),
        None => HostCredentials::managed(revision, config.salt.clone(), passwords, policy),
    })
}

pub(super) fn apply_metadata(snapshot: &mut ServiceSnapshot, config: &CheckedHostConfig) {
    snapshot.id = config.id.clone();
    // Pinned common::pk_to_fingerprint: hexadecimal pairs, space every two bytes.
    snapshot.fingerprint = config.public_key.0.chunks(2).map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()).collect::<Vec<_>>().join(" ");
    snapshot.permanent_password_set = config.permanent_h1.is_some();
    snapshot.local_permanent_password_set = config.local_password_set;
    snapshot.preset_password = config.preset_password;
    snapshot.options = sanitized(&config.options);
}

fn direct_address(options: &HashMap<String, String>) -> Result<SocketAddr, ControlError> {
    let port = match option(options, "direct-access-port") {
        "" => 21118,
        value => value.parse::<u16>().ok().filter(|port| *port != 0).ok_or(ControlError("Invalid direct listener port"))?,
    };
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
}

pub(super) fn host_options(id: String, signing_key: sign::SecretKey,
    credentials: Arc<HostCredentials>, options: HashMap<String, String>) -> Result<HostOptions, ControlError> {
    validate(&options)?;
    let outputs = crate::windows_native::enumerate_outputs().map_err(|_| ControlError("Unable to enumerate desktop outputs"))?;
    let requested = option(&options, "host-output-key");
    let candidates: Vec<_> = outputs.iter().filter(|output| {
        if requested.is_empty() {
            // Windows places the actual primary desktop's upper-left at (0,0).
            output.desktop_rect[0] == 0 && output.desktop_rect[1] == 0
        } else { crate::windows_input::output_key(output.id) == requested }
    }).collect();
    if candidates.len() != 1 { return Err(ControlError("Selected or primary desktop output is unavailable or ambiguous")); }
    let key = crate::windows_input::output_key(candidates[0].id);
    let binding = crate::windows_input::bind_output_key(&key).map_err(|_| ControlError("Selected desktop output cannot be bound"))?;
    let name = std::env::var("COMPUTERNAME").ok().filter(|name| !name.is_empty() && !name.chars().any(char::is_control)).unwrap_or_else(|| id.clone());
    let allow_input = match option(&options, "access-mode") {
        "view" => false, "full" => true, _ => enabled(&options, "enable-keyboard"),
    };
    Ok(HostOptions {
        listen: if enabled(&options, "direct-server") { Some(direct_address(&options)?) } else { None },
        allow_legacy_plain: enabled(&options, "allow-legacy-direct"), id, display_name: name,
        signing_key, width: binding.width(), height: binding.height(), bitrate: 20_000_000,
        platform: "Windows".into(), credentials, publisher_backend: PublisherBackend::Auto,
        output_key: key, allow_input, codec_selection: CodecSelection::Auto,
    })
}

pub(super) fn server_changed(before: &HashMap<String, String>, after: &HashMap<String, String>) -> bool {
    ["api-server", "custom-rendezvous-server", "relay-server", "key", "allow-websocket"].iter()
        .any(|key| option(before, key) != option(after, key))
}
pub(super) fn run_changed(before: &HashMap<String, String>, after: &HashMap<String, String>) -> bool {
    server_changed(before, after) || ["access-mode", "enable-keyboard", "host-output-key", "direct-server", "direct-access-port", "allow-legacy-direct"].iter()
        .any(|key| option(before, key) != option(after, key))
}
