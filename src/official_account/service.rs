//! Blocking, token-free account/cloud-address-book seam for native bridges (the
//! OHOS NAPI worker threads). Every function returns the frozen JSON text:
//! `{"ok":true,...}` or `{"ok":false,"code":...,"error":...,"sent"?:bool}`.
//! Credentials, the OIDC `auth_body` and peer secrets never appear in a result.
//!
//! Admission: the bridge captures [`Admission::capture`] under its application
//! lock when it admits a call, and may raise [`revoke_pending`] under that same
//! lock on a privacy withdrawal (a lock-free atomic bump: no fsync, network or
//! owner lock). Work admitted before the bump fails closed with `revoked`.

use super::{api, cloud, mutation, oidc, state};
use super::state::AccountError;
use super::http::{Request, Transport};
use hbb_common::{
    anyhow::Error,
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{self, Config},
    serde_json::{self, json, Map, Value},
    sodiumoxide::crypto::sign,
};
use std::{sync::Mutex, time::Duration};
use base::config::keys;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Unbound,
    Revoked,
    StaleReceipt,
    Unauthorized,
    Forbidden,
    ServerUnsupported,
    Busy,
    Network,
    Server,
    Invalid,
    Conflict,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::Revoked => "revoked",
            Self::StaleReceipt => "stale_receipt",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::ServerUnsupported => "server_unsupported",
            Self::Busy => "busy",
            Self::Network => "network",
            Self::Server => "server",
            Self::Invalid => "invalid",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    pub code: Code,
    pub message: String,
    /// Set for mutating cloud calls: whether a state-changing request may have
    /// left this process. `true` is never rolled back by this core.
    pub sent: Option<bool>,
}

impl Failure {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), sent: None }
    }

    pub(super) fn from_error(error: &Error) -> Self {
        match error.downcast_ref::<AccountError>() {
            Some(AccountError::StaleReceipt) => Self::new(Code::StaleReceipt, "The account receipt is stale"),
            Some(AccountError::Revoked) => Self::new(Code::Revoked, "The account work was revoked"),
            Some(AccountError::ScopeMismatch) =>
                Self::new(Code::Unbound, "The account storage belongs to a different server; bind the server again"),
            Some(AccountError::IncompleteRevocation) =>
                Self::new(Code::Revoked, "A previous account revocation is incomplete; retry the logout"),
            Some(AccountError::NotLoggedIn) => Self::new(Code::Unauthorized, "The account is not logged in"),
            None => Self::new(Code::Server, cloud::sanitize(&error.to_string())),
        }
    }
}

/// The bridge-held proof that a call was admitted at a given fence value.
#[derive(Clone, Copy, Debug)]
pub struct Admission(u64);

impl Admission {
    pub fn capture() -> Self {
        Self(state::revocation())
    }

    pub fn is_current(self) -> bool {
        self.0 == state::revocation()
    }
}

/// Raise the privacy fence (see module docs). Returns the new value.
pub fn revoke_pending() -> u64 {
    state::revoke_pending()
}

pub fn revocation() -> u64 {
    state::revocation()
}

fn render(reply: Result<Value, Failure>) -> String {
    let value = match reply {
        Ok(Value::Object(mut map)) => {
            map.insert("ok".to_owned(), Value::Bool(true));
            Value::Object(map)
        }
        Ok(_) => json!({ "ok": true }),
        Err(failure) => {
            let mut map = Map::new();
            map.insert("ok".to_owned(), Value::Bool(false));
            map.insert("code".to_owned(), json!(failure.code.as_str()));
            map.insert("error".to_owned(), json!(failure.message));
            if let Some(sent) = failure.sent { map.insert("sent".to_owned(), json!(sent)); }
            Value::Object(map)
        }
    };
    value.to_string()
}

fn admitted(admission: Admission) -> Result<(), Failure> {
    state::check_admitted(admission.0).map_err(|error| Failure::from_error(&error))
}

// ------------------------------------------------------------------ binding

#[derive(Clone, Copy)]
enum Binding {
    Unbound,
    Bound { custom: bool, revision: u64 },
    Unsupported { revision: u64, reason: &'static str },
}

static BINDING: Mutex<Binding> = Mutex::new(Binding::Unbound);
/// Serializes binds; account calls only read BINDING briefly and never wait for it.
static BIND_LOCK: Mutex<()> = Mutex::new(());

fn set_binding(value: Binding) {
    *BINDING.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

fn require_bound() -> Result<Value, Failure> {
    let binding = *BINDING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match binding {
        Binding::Unbound => Err(Failure::new(Code::Unbound, "No server profile is bound to the account")),
        Binding::Unsupported { reason, .. } => Err(Failure::new(Code::ServerUnsupported, reason)),
        Binding::Bound { custom, revision } => Ok(json!({
            "mode": if custom { "custom" } else { "official" }, "profileRevision": revision,
        })),
    }
}

struct Profile {
    custom: bool,
    revision: u64,
    api: String,
    id: String,
    key: String,
    key_kind: String,
}

fn parse_profile(text: &str) -> Result<Profile, Failure> {
    let official = |revision| Profile {
        custom: false, revision,
        api: "https://admin.rustdesk.com".to_owned(),
        id: hbb_common::config::RENDEZVOUS_SERVERS[0].to_owned(),
        key: hbb_common::config::RS_PUB_KEY.to_owned(),
        key_kind: "official".to_owned(),
    };
    if text.trim().is_empty() { return Ok(official(0)); }
    if text.len() > 16 * 1024 { return Err(Failure::new(Code::Invalid, "Server profile is too large")); }
    let value: Value = serde_json::from_str(text)
        .map_err(|_| Failure::new(Code::Invalid, "Server profile is not valid JSON"))?;
    let object = value.as_object().ok_or_else(|| Failure::new(Code::Invalid, "Server profile must be an object"))?;
    let revision = object.get("profileRevision").and_then(Value::as_u64).unwrap_or(0);
    let field = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().trim().to_owned();
    match object.get("mode").and_then(Value::as_str) {
        Some("official") => Ok(official(revision)),
        Some("custom") => {
            let key = field("key");
            let key_kind = object.get("keyKind").and_then(Value::as_str)
                .unwrap_or(if key.is_empty() { "default" } else { "public" }).to_owned();
            Ok(Profile { custom: true, revision, api: field("apiServer"), id: field("idServer"), key, key_kind })
        }
        _ => Err(Failure::new(Code::Invalid, "Unknown server profile mode")),
    }
}

/// Normalize a native profile's optional API base without selecting a transport
/// policy. Empty means unset. HTTP and HTTPS syntax are accepted here; account
/// binding and `Transport` separately enforce credential delivery over HTTPS.
/// Query, fragment, userinfo, whitespace/control characters and non-HTTP schemes
/// are refused by the same parser the account transport uses.
pub fn validate_api_base(value: &str) -> Result<String, Failure> {
    let value = value.trim();
    if value.is_empty() { return Ok(String::new()); }
    let parsed = api::http_url(value, true)
        .map_err(|_| Failure::new(Code::Invalid, "The API server address is invalid"))?;
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn validate_custom(profile: &Profile) -> Result<(), Failure> {
    let bad = |message: &str| Failure::new(Code::Invalid, message);
    if profile.id.len() > 1024 || profile.id.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad("The custom ID server is invalid"));
    }
    if !matches!(profile.key_kind.as_str(), "default" | "public" | "shared" | "conflict") {
        return Err(bad("The custom account Key kind is invalid"));
    }
    if profile.key_kind == "shared" && !profile.key.is_empty() {
        return Err(bad("A shared Key must not occupy the account public-key field"));
    }
    if !profile.key.is_empty() {
        let key = STANDARD.decode(&profile.key).map_err(|_| bad("The custom server key is not base64"))?;
        sign::PublicKey::from_slice(&key).ok_or_else(|| bad("The custom server key is not a public key"))?;
    }
    Ok(())
}

/// Bind the account owner to the native-saved server profile (see CONTRACT.md).
/// An empty text means the official default at revision 0.
pub fn bind_server(admission: Admission, profile_json: &str) -> String {
    render(bind(admission, profile_json))
}

fn bind(admission: Admission, profile_json: &str) -> Result<Value, Failure> {
    admitted(admission)?;
    let mut profile = parse_profile(profile_json)?;
    if profile.custom {
        validate_custom(&profile)?;
        profile.api = validate_api_base(&profile.api)?;
        if profile.id.is_empty() { profile.id = hbb_common::config::RENDEZVOUS_SERVERS[0].to_owned(); }
        if profile.key.is_empty() && profile.key_kind != "shared" {
            profile.key = hbb_common::config::RS_PUB_KEY.to_owned();
        }
    }
    let _serial = BIND_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    admitted(admission)?;
    if profile.custom {
        let https = api::http_url(&profile.api, true).is_ok_and(|url| url.scheme() == "https");
        let shared_raw_tcp = profile.key_kind == "shared"
            && api::builtin(keys::OPTION_USE_RAW_TCP_FOR_API) == "Y"
            && !config::use_ws() && !api::is_public(&profile.api);
        let unsupported = if profile.key_kind == "conflict" {
            Some("The saved server contains two Keys; resolve the conflict in server settings")
        } else if shared_raw_tcp {
            Some("The configured raw-TCP account transport requires a public Key; shared Key accounts require HTTPS")
        } else if !https {
            Some("The custom server has no usable HTTPS API server for accounts")
        } else { None };
        if let Some(reason) = unsupported {
            // Fail closed: nothing is applied to Config (no silent official
            // fallback) and the account stays unusable until a valid bind.
            // Moving to an unsupported custom profile still retires the old
            // account, not just its UI. Never let a later switch back resurrect
            // credentials/caches which belonged to the earlier server profile.
            state::change_server_configuration_admitted(admission.0, || {
                set_binding(Binding::Unsupported { revision: profile.revision, reason });
            }).map_err(|error| Failure::from_error(&error))?;
            return Err(Failure::new(Code::ServerUnsupported, reason));
        }
    }
    let retained = state::bind_server_configuration(|| {
        // This check owns the bind's linearization point: it runs under the
        // existing account owner/OS lock, before Config or credentials change.
        state::check_admitted(admission.0)?;
        set_binding(Binding::Unbound);
        // The native-saved profile is authoritative. Config is its runtime
        // mirror; its legacy writer does not return persistence errors. Set one
        // complete option map, preserve all unrelated options, and read back
        // the effective values so deployment defaults/overrides cannot silently
        // send account traffic to a different server.
        let wanted = [
            ("api-server", profile.api.clone()),
            ("custom-rendezvous-server", profile.id.clone()),
            ("key", profile.key.clone()),
            (api::ACCOUNT_KEY_KIND, if profile.key_kind == "shared" { "shared".to_owned() } else { String::new() }),
        ];
        let mut options = Config::get_options();
        for (key, value) in &wanted {
            if value.is_empty() { options.remove(*key); } else { options.insert((*key).to_owned(), value.clone()); }
        }
        Config::set_options(options);
        for (key, value) in &wanted {
            if Config::get_option(key) != *value {
                return Err(hbb_common::anyhow::anyhow!("Effective account server configuration does not match the saved profile"));
            }
        }
        let intended = if profile.custom { profile.api.as_str() } else { "https://admin.rustdesk.com" };
        if api::server() != intended {
            return Err(hbb_common::anyhow::anyhow!("Effective account API server does not match the saved profile"));
        }
        let intended_id = hbb_common::socket_client::check_port(profile.id.clone(), hbb_common::config::RENDEZVOUS_PORT);
        if api::rendezvous_server() != intended_id {
            return Err(hbb_common::anyhow::anyhow!("Effective account ID server does not match the saved profile"));
        }
        Ok(())
    }).map_err(|error| Failure::from_error(&error))?;
    set_binding(Binding::Bound { custom: profile.custom, revision: profile.revision });
    Ok(json!({
        "mode": if profile.custom { "custom" } else { "official" },
        "profileRevision": profile.revision,
        "sessionRetained": retained,
    }))
}

// ----------------------------------------------------------------- snapshot

fn user_json(user: &state::PublicUser) -> Value {
    let mut map = Map::new();
    map.insert("name".into(), json!(user.name));
    map.insert("displayName".into(), json!(user.display_name));
    if let Some(avatar) = &user.avatar { map.insert("avatar".into(), json!(avatar)); }
    if let Some(status) = user.status { map.insert("status".into(), json!(status)); }
    Value::Object(map)
}

fn snapshot_value(admission: Admission) -> Result<Value, Failure> {
    admitted(admission)?;
    let binding = require_bound()?;
    let snapshot = state::public_snapshot(admission.0).map_err(|error| Failure::from_error(&error))?;
    admitted(admission)?;
    if binding != require_bound()? {
        return Err(Failure::new(Code::StaleReceipt, "The bound server changed while reading the account"));
    }
    let mut map = Map::new();
    map.insert("receipt".into(), json!(snapshot.receipt));
    map.insert("loggedIn".into(), json!(snapshot.logged_in));
    map.insert("serverBinding".into(), binding);
    if let Some(user) = &snapshot.user { map.insert("user".into(), user_json(user)); }
    Ok(Value::Object(map))
}

pub fn snapshot(admission: Admission) -> String {
    render(snapshot_value(admission))
}

// ---------------------------------------------------------------- providers

fn provider_list(body: &str) -> Result<Vec<String>, Failure> {
    let bad = || Failure::new(Code::Server, "Invalid login options response");
    let items: Vec<Value> = serde_json::from_str(body).map_err(|_| bad())?;
    let strings: Vec<&str> = items.iter().map(|item| item.as_str().ok_or_else(bad)).collect::<Result<_, _>>()?;
    let mut names: Vec<String> = Vec::new();
    let mut push = |name: &str| {
        if !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
            && !names.iter().any(|existing| existing == name)
        {
            names.push(name.to_owned());
        }
    };
    // Official `queryOidcLoginOptions`: a common-oidc entry carries the list.
    if let Some(common) = strings.iter().find_map(|item| item.strip_prefix("common-oidc/")) {
        let entries: Vec<Value> = serde_json::from_str(common).map_err(|_| bad())?;
        for entry in &entries {
            if let Some(name) = entry.get("name").and_then(Value::as_str) { push(name); }
        }
    } else {
        for item in &strings {
            if let Some(name) = item.strip_prefix("oidc/") { push(name); }
        }
    }
    Ok(names)
}

fn providers_value(admission: Admission) -> Result<Value, Failure> {
    require_bound()?;
    admitted(admission)?;
    let context = state::current_context().map_err(|error| Failure::from_error(&error))?;
    let url = format!("{}/api/login-options", context.api_server);
    let runtime = crate::executor::runtime().map_err(|_| Failure::new(Code::Server, "Account executor is unavailable"))?;
    let response = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let transport = Transport::new(&context, &url).await?;
            transport.request(Request::new(url.clone(), "get", None, "{}".to_owned())?).await
        }).await
    });
    state::request_still_valid(&context, admission.0).map_err(|error| Failure::from_error(&error))?;
    let response = match response {
        Ok(Ok(response)) => response,
        _ => return Err(Failure::new(Code::Network, "Cannot reach the account server")),
    };
    if !(200..300).contains(&response.status_code) {
        return Err(Failure::new(Code::Server, format!("HTTP {}", response.status_code)));
    }
    let providers: Vec<Value> = provider_list(&response.body)?.into_iter()
        .map(|name| json!({ "id": name, "label": name })).collect();
    Ok(json!({ "providers": providers }))
}

pub fn providers(admission: Admission) -> String {
    render(providers_value(admission))
}

// --------------------------------------------------------------------- oidc

static CANCELLED_ATTEMPT: Mutex<Option<String>> = Mutex::new(None);

fn oidc_start_value(admission: Admission, receipt: &str, provider_id: &str, remember_me: bool)
    -> Result<Value, Failure>
{
    require_bound()?;
    if provider_id.is_empty() || provider_id.len() > 1024 || provider_id.chars().any(char::is_control) {
        return Err(Failure::new(Code::Invalid, "The sign-in provider is invalid"));
    }
    let started = state::start_admitted(admission.0, ||
        oidc::start(receipt.to_owned(), provider_id.to_owned(), remember_me));
    match started {
        Ok(attempt_receipt) => Ok(json!({ "attemptReceipt": attempt_receipt, "state": "pending" })),
        Err(error) => {
            admitted(admission)?;
            Err(Failure::from_error(&error))
        }
    }
}

pub fn oidc_start(admission: Admission, receipt: &str, provider_id: &str, remember_me: bool) -> String {
    render(oidc_start_value(admission, receipt, provider_id, remember_me))
}

fn oidc_result_value(admission: Admission, attempt_receipt: &str) -> Result<Value, Failure> {
    require_bound()?;
    admitted(admission)?;
    let cancelled = CANCELLED_ATTEMPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_deref() == Some(attempt_receipt);
    if cancelled { return Ok(json!({ "state": "cancelled" })); }
    let result = match oidc::result_public(attempt_receipt) {
        Ok(result) => result,
        Err(error) => {
            admitted(admission)?;
            return Err(match error.downcast_ref::<AccountError>() {
                Some(_) => Failure::from_error(&error),
                None => Failure::new(Code::StaleReceipt, "The sign-in attempt is no longer active"),
            });
        }
    };
    match result.state {
        oidc::PublicState::Pending => Ok(json!({ "state": "pending" })),
        oidc::PublicState::UrlReady => {
            let url = result.url.unwrap_or_default();
            let http = api::http_url(&url, false).is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https"));
            if http {
                Ok(json!({ "state": "url-ready", "url": url }))
            } else {
                Ok(json!({ "state": "failed", "message": "Invalid sign-in URL" }))
            }
        }
        oidc::PublicState::Complete => {
            // The committed credential stays in the owner; only the public view is read.
            let mut complete = snapshot_value(admission)?;
            complete["state"] = json!("complete");
            Ok(complete)
        }
        oidc::PublicState::Failed => Ok(json!({ "state": "failed", "message": result.message })),
        oidc::PublicState::NeedsBusiness => Ok(json!({ "state": "needs-business" })),
    }
}

pub fn oidc_result(admission: Admission, attempt_receipt: &str) -> String {
    render(oidc_result_value(admission, attempt_receipt))
}

/// Cancels exactly this attempt; a newer attempt, or an account already
/// committed, is untouched. Allowed after a privacy withdrawal.
pub fn oidc_cancel(attempt_receipt: &str) -> String {
    let cancelled = oidc::cancel(attempt_receipt).is_ok();
    if cancelled {
        *CANCELLED_ATTEMPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(attempt_receipt.to_owned());
    }
    render(Ok(json!({ "cancelled": cancelled, "attemptReceipt": attempt_receipt })))
}

// ------------------------------------------------------------------- logout

fn logout_value(admission: Admission, receipt: &str) -> Result<Value, Failure> {
    require_bound()?;
    // Official client best-effort `/api/logout` (2 s) while the token still exists.
    // It is skipped when the admission was withdrawn; the local revocation never is.
    let body = json!({ "id": Config::get_id(), "uuid": STANDARD.encode(hbb_common::get_uuid()) }).to_string();
    match cloud::drive(admission.0, receipt, false, async |client| {
        let _ = tokio::time::timeout(Duration::from_secs(2),
            client.call("post", "/api/logout", &[], Some(body.clone()), false)).await;
        Ok::<(), Failure>(())
    }) {
        Err(failure) if failure.code == Code::StaleReceipt => return Err(failure),
        _ => {}
    }
    let receipt = state::set_local_option_scoped(receipt, "access_token", String::new())
        .map_err(|error| Failure::from_error(&error))?;
    Ok(json!({ "receipt": receipt }))
}

pub fn logout(admission: Admission, receipt: &str) -> String {
    render(logout_value(admission, receipt))
}

// ------------------------------------------------------------------- cloud

pub fn cloud_list(admission: Admission, receipt: &str) -> String {
    render(require_bound().and_then(|_|
        cloud::drive(admission.0, receipt, false, async |client| cloud::list(client).await)
            .map(|(value, _)| value)))
}

pub fn cloud_load(admission: Admission, receipt: &str, book_id: &str) -> String {
    render(validate_book_id(book_id).and_then(|_| require_bound()).and_then(|_|
        cloud::drive(admission.0, receipt, false, async |client| cloud::load(client, book_id).await)
            .map(|(value, _)| value)))
}

pub fn cloud_mutate(admission: Admission, receipt: &str, book_id: &str, mutation_json: &str) -> String {
    render(validate_book_id(book_id).and_then(|_| require_bound()).and_then(|_| {
        let change = mutation::parse_mutation(mutation_json)?;
        cloud::drive(admission.0, receipt, true, async |client|
            mutation::mutate(client, book_id, change).await)
            .map(|(_, sent)| json!({ "sent": sent }))
    }).map_err(|mut failure| {
        // Validation, binding, admission and drive's early failures have not
        // dispatched a mutation. Preserve drive's true/false once it ran.
        if failure.sent.is_none() { failure.sent = Some(false); }
        failure
    }))
}

fn validate_book_id(book_id: &str) -> Result<(), Failure> {
    if book_id.is_empty() || book_id.len() > 64
        || !book_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Failure::new(Code::Invalid, "The address-book id is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdrawn_admission_is_refused_before_any_work_starts() {
        let admission = Admission::capture();
        revoke_pending();
        let mut ran = false;
        let started = state::start_admitted(admission.0, || { ran = true; Ok(()) });
        assert!(!ran);
        let failure = Failure::from_error(&started.expect_err("withdrawn admission"));
        assert_eq!(failure.code, Code::Revoked);
        assert!(admitted(admission).is_err());
    }

    #[test]
    fn custom_profile_without_https_api_is_never_official() {
        let profile = parse_profile(r#"{"mode":"custom","profileRevision":7,"apiServer":"http://plain.example","idServer":"id.example"}"#)
            .expect("profile");
        assert!(profile.custom && profile.revision == 7);
        let reply = bind(Admission::capture(), r#"{"mode":"custom","profileRevision":7,"apiServer":"http://plain.example"}"#);
        assert_eq!(reply.expect_err("plain http").code, Code::ServerUnsupported);
        assert_eq!(require_bound().expect_err("unsupported").code, Code::ServerUnsupported);
        let empty = parse_profile("").expect("official");
        assert!(!empty.custom && empty.revision == 0);
    }

    #[test]
    fn login_options_follow_the_official_parsing() {
        let names = provider_list(r#"["oidc/github","oidc/google","other"]"#).expect("plain");
        assert_eq!(names, ["github", "google"]);
        let common = provider_list(r#"["oidc/ignored","common-oidc/[{\"name\":\"corp\"},{\"name\":\"alt\"}]"]"#).expect("common");
        assert_eq!(common, ["corp", "alt"]);
        assert!(provider_list("{}").is_err());
    }

    #[test]
    fn invalid_book_path_is_not_sent() {
        let reply: Value = serde_json::from_str(&cloud_mutate(
            Admission::capture(), "unused", "../../users", r#"{"action":"deletePeer","id":"1"}"#,
        )).expect("JSON reply");
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["code"], "invalid");
        assert_eq!(reply["sent"], false);
    }
}
