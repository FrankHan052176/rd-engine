//! App-scoped, manual-edit server profile storage for this HAR.
//!
//! The profile is admitted with the same rules as `validateServerProfile` and
//! persisted only under the fixed private root. A saved profile is a validated
//! configuration, never a reachability or identity result: the endpoint probe
//! below reports only what a TCP connection attempt did, and saving never
//! claims the server is reachable.
use super::{
    app_context::{app_scope, AppScope},
    app_storage::{read_private, store_dir, write_private},
    server_credentials,
    server_profile::{accepted_approval, KeyInput, KeyUpdate, ServerProfile, APPROVAL, MAX_SAFE_REVISION},
};
use hbb_common::sodiumoxide::utils::memzero;
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task},
    Env,
};
use serde_json::{json, Value};
use std::{
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::Duration,
};

#[path = "server_draft.rs"]
mod draft;

const PROFILE_FILE: &str = "server-profile.json";
static PROFILE_WRITES: std::sync::Mutex<()> = std::sync::Mutex::new(());
static LATEST_PROFILE_WRITE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const MAX_PROFILE_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_PROBE_ADDRESSES: usize = 2;

struct SavedProfile {
    revision: u64,
    profile: ServerProfile,
}

/// Account scope fields from the native-committed document. No shared-Key
/// pointer or secret is needed to bind accounts, and loading this projection
/// must never query the system credential store.
pub(super) struct SavedBinding {
    pub(super) revision: u64,
    pub(super) mode: &'static str,
    pub(super) id_server: String,
    pub(super) api_server: String,
    pub(super) key: String,
    pub(super) key_kind: &'static str,
}

pub(super) fn load_saved_binding(dir: &Path) -> Result<Option<SavedBinding>, String> {
    Ok(load_saved(dir)?.map(|saved| SavedBinding {
        revision: saved.revision,
        mode: saved.profile.mode(),
        id_server: saved.profile.id_server().to_owned(),
        api_server: saved.profile.api_server().to_owned(),
        key: saved.profile.public_key().to_owned(),
        key_kind: saved.profile.key_kind(),
    }))
}

pub(super) fn require_profile_revision(scope: &AppScope, revision: u64) -> Result<(), String> {
    scope.check()?;
    let current = load_saved(&store_dir(scope)?)?
        .ok_or_else(|| "the host profile is no longer saved".to_string())?;
    if current.revision != revision { return Err("the host server profile changed".to_string()); }
    Ok(())
}

enum ProfileOp {
    Get,
    Set(Box<ServerProfile>, KeyUpdate, u64),
    Draft(Box<draft::Candidate>, u64),
    Test(Box<ServerProfile>, KeyUpdate),
}

impl ProfileOp {
    fn action(&self) -> &'static str {
        match self {
            Self::Get => "get_server_config",
            Self::Set(_, _, _) => "set_server_config",
            Self::Draft(_, _) => "set_server_draft",
            Self::Test(_, _) => "test_server_config",
        }
    }
}

/// One admitted profile operation. The scope is the app generation and reserved
/// root it was admitted under; a fence revokes it before and after the worker.
pub struct ProfileWork {
    scope: Option<AppScope>,
    op: Option<ProfileOp>,
    error: Option<String>,
}

pub struct ProfileOutput {
    document: String,
    committed: bool,
    action: &'static str,
}

fn failure(action: &str, error: &str, committed: bool) -> Value {
    json!({
        "ok": false,
        "action": action,
        "approved": false,
        "config": Value::Null,
        "approvedProfile": Value::Null,
        "committed": committed,
        "error": error,
    })
}

fn load_saved(dir: &Path) -> Result<Option<SavedProfile>, String> {
    let Some(bytes) = read_private(&dir.join(PROFILE_FILE), MAX_PROFILE_BYTES)? else {
        return Ok(None);
    };
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "the saved server profile is not valid JSON".to_string())?;
    // v1 predates apiServer and the shared Key: its documents have neither field,
    // which `ServerProfile::parse` reads as "empty" and "no key".
    if !matches!(value.get("schemaVersion").and_then(Value::as_u64), Some(1 | 2))
        || !accepted_approval(&value)
    {
        return Err("the saved server profile has no manual-edit provenance".to_string());
    }
    let revision = value
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| (1..=MAX_SAFE_REVISION).contains(revision))
        .ok_or_else(|| "the saved server profile has an invalid revision".to_string())?;
    let stored = value
        .get("profile")
        .ok_or_else(|| "the saved server profile has no profile document".to_string())?;
    Ok(Some(SavedProfile {
        revision,
        profile: ServerProfile::parse(stored)?,
    }))
}

fn save_profile(dir: &Path, profile: &ServerProfile, revision: u64) -> Result<(), String> {
    // The document holds the public pointer to the protected shared Key, never
    // the key itself.
    let document = json!({
        "schemaVersion": 2,
        "approval": APPROVAL,
        "revision": revision,
        "profile": profile.normalized(),
    });
    let bytes = serde_json::to_vec(&document)
        .map_err(|_| "cannot serialize the server profile".to_string())?;
    if bytes.len() as u64 > MAX_PROFILE_BYTES {
        return Err("the server profile is larger than this layer accepts".to_string());
    }
    write_private(&dir.join(PROFILE_FILE), &bytes)
}

/// The value-owned approved route this store hands to `sessionAdd` and
/// `peerQueryOnline`: a flat envelope over the saved fields. It is derived from
/// the persisted approval, so no caller may mint one without a real save.
fn approved_profile(profile: &ServerProfile, revision: u64) -> Value {
    let mut value = profile.normalized();
    if let Value::Object(fields) = &mut value {
        fields.insert("schemaVersion".to_string(), json!(2));
        fields.insert("approval".to_string(), json!(APPROVAL));
        fields.insert("revision".to_string(), json!(revision));
    }
    value
}

/// One bounded transport probe. A successful connect means the endpoint accepted
/// TCP; it does not identify the server and does not prove the RustDesk wire.
fn probe(name: &str) -> Result<(), String> {
    let addresses = name
        .to_socket_addrs()
        .map_err(|error| format!("address resolution failed: {error}"))?;
    let mut last = None;
    for address in addresses.take(MAX_PROBE_ADDRESSES) {
        match TcpStream::connect_timeout(&address, PROBE_TIMEOUT) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(());
            }
            Err(error) => last = Some(error),
        }
    }
    match last {
        Some(error) => Err(format!("TCP connect failed: {error}")),
        None => Err("address resolution returned no address".to_string()),
    }
}

fn test_profile(profile: &ServerProfile, update: &KeyUpdate) -> Value {
    let (id_error, id_reachable) = match probe(profile.id_server()) {
        Ok(()) => (String::new(), true),
        Err(error) => (error, false),
    };
    let relay = profile
        .relay_server()
        .map(|endpoint| match probe(endpoint) {
            Ok(()) => (String::new(), true),
            Err(error) => (error, false),
        });
    let relay_reachable = relay.as_ref().is_none_or(|(_, accepted)| *accepted);
    let ok = id_reachable && relay_reachable;
    let mut errors = json!({ "idServer": id_error });
    let mut reachable = json!({ "idServer": id_reachable });
    if let Some((error, accepted)) = &relay {
        errors["relayServer"] = json!(error);
        reachable["relayServer"] = json!(accepted);
    }
    let message = if ok {
        "a TCP connection was accepted by every configured endpoint; this does not authenticate the server or prove RustDesk protocol compatibility"
    } else {
        "at least one configured endpoint did not accept a TCP connection"
    };
    json!({
        "ok": ok,
        "action": "test_server_config",
        "approved": false,
        "config": profile.candidate_document(update),
        "approvedProfile": Value::Null,
        "committed": false,
        "reachable": reachable,
        "errors": errors,
        "message": message,
    })
}

impl ProfileWork {
    fn refused(error: String) -> Self {
        Self {
            scope: None,
            op: None,
            error: Some(error),
        }
    }

    fn run(&mut self) -> Value {
        let action = self
            .op
            .as_ref()
            .map_or("get_server_config", ProfileOp::action);
        let Some(scope) = self.scope.as_ref() else {
            return failure(
                action,
                self.error
                    .as_deref()
                    .unwrap_or("server profile storage was not admitted"),
                false,
            );
        };
        if let Err(error) = scope.check() {
            return failure(action, &error, false);
        }
        let Some(op) = self.op.take() else {
            return failure(action, "server profile operation is missing", false);
        };
        let dir = match store_dir(scope) {
            Ok(dir) => dir,
            Err(error) => return failure(action, &error, false),
        };
        match op {
            ProfileOp::Get => {
                let mut document = match load_saved(&dir) {
                Ok(Some(saved)) => {
                    let mut document = json!({
                        "ok": true,
                        "action": "get_server_config",
                        "approved": true,
                        "revision": saved.revision.to_string(),
                        "config": saved.profile.normalized(),
                        "approvedProfile": approved_profile(&saved.profile, saved.revision),
                        "committed": false,
                        "message": "the saved profile is present; it was validated when it was saved and is not probed here",
                    });
                    // Only whether the protected secret is usable is reported;
                    // the secret itself never leaves the store.
                    if saved.profile.key_version() > 0 {
                        if let Err(error) = server_credentials::get(
                            &server_credentials::system(),
                            saved.profile.key_version(),
                            &saved.profile.key_binding(),
                        ) {
                            document["keyError"] = json!(error);
                        }
                    }
                    document
                }
                Ok(None) => json!({
                    "ok": true,
                    "action": "get_server_config",
                    "approved": false,
                    "revision": "0",
                    "config": Value::Null,
                    "approvedProfile": Value::Null,
                    "committed": false,
                    "message": "no server profile has been saved, so no server route is approved",
                }),
                Err(error) => failure("get_server_config", &error, false),
                };
                match draft::public(&dir, &server_credentials::system()) {
                    Ok(value) => document["draft"] = json!(value),
                    Err(error) => document["draftError"] = json!(error),
                }
                document
            },
            ProfileOp::Set(profile, update, sequence) => {
                let _serial = PROFILE_WRITES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                // NAPI workers may begin out of submission order. Once a newer
                // edit is admitted, an older call must not publish a stale route,
                // even when its JS waiter has timed out.
                let current = || check_write(scope, sequence);
                match commit_profile(&dir, *profile, update, &server_credentials::system(), current) {
                    Ok(committed) => {
                        let mut document = json!({
                            "ok": true,
                            "action": "set_server_config",
                            "approved": true,
                            "revision": committed.revision.to_string(),
                            "config": committed.profile.normalized(),
                            "approvedProfile": approved_profile(&committed.profile, committed.revision),
                            "committed": true,
                            "message": "saved after validation; this is neither a reachability nor an identity result",
                        });
                        if let Some(warning) = committed.cleanup_warning {
                            document["cleanupWarning"] = json!(warning);
                        }
                        document
                    }
                    Err(error) => json!({
                        "ok": false,
                        "action": "set_server_config",
                        "approved": false,
                        "config": Value::Null,
                        "approvedProfile": Value::Null,
                        "committed": false,
                        "error": error,
                    }),
                }
            }
            ProfileOp::Draft(candidate, sequence) => {
                let _serial = PROFILE_WRITES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                draft::commit(&dir, *candidate, &server_credentials::system(), || check_write(scope, sequence))
                    .unwrap_or_else(|error| failure("set_server_draft", &error, false))
            }
            ProfileOp::Test(profile, update) => test_profile(&profile, &update),
        }
    }
}

impl Task for ProfileWork {
    type Output = ProfileOutput;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        let action = self
            .op
            .as_ref()
            .map_or("get_server_config", ProfileOp::action);
        let value = self.run();
        Ok(ProfileOutput {
            committed: value
                .get("committed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            document: value.to_string(),
            action,
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi_ohos::Result<Self::JsValue> {
        if let Some(error) = self.scope.as_ref().and_then(|scope| scope.check().err()) {
            return Ok(failure(output.action, &error, output.committed).to_string());
        }
        Ok(output.document)
    }
}

fn check_write(scope: &AppScope, sequence: u64) -> Result<(), String> {
    scope.check()?;
    if LATEST_PROFILE_WRITE.load(std::sync::atomic::Ordering::Acquire) != sequence {
        return Err("a newer server edit superseded this write".to_string());
    }
    Ok(())
}

fn admit(op: ProfileOp) -> ProfileWork {
    match app_scope() {
        Ok(scope) => ProfileWork {
            scope: Some(scope),
            op: Some(op),
            error: None,
        },
        Err(error) => ProfileWork::refused(error),
    }
}

fn candidate(request: String) -> Result<(ServerProfile, KeyUpdate), String> {
    let mut request = request;
    let parsed = if request.len() > MAX_REQUEST_BYTES {
        Err("server profile JSON is larger than this layer accepts".to_string())
    } else {
        serde_json::from_str::<Value>(&request)
            .map_err(|_| "server profile must be a JSON object".to_string())
            .and_then(|value| ServerProfile::parse_candidate(&value))
    };
    // The request may carry a shared Key. Wipe this native copy (the JS-side
    // string is outside this owner's control).
    memzero(unsafe { request.as_bytes_mut() });
    parsed
}

fn write_candidate(mut request: String) -> Result<ProfileOp, String> {
    let result = if request.len() > MAX_REQUEST_BYTES {
        Err("server profile JSON is larger than this layer accepts".to_string())
    } else {
        serde_json::from_str::<Value>(&request)
            .map_err(|_| "server profile must be a JSON object".to_string())
            .and_then(|value| {
                if value.get("draftOnly").and_then(Value::as_bool) == Some(true) {
                    draft::Candidate::parse(&value).map(|draft| ProfileOp::Draft(Box::new(draft), 0))
                } else {
                    ServerProfile::parse_candidate(&value)
                        .map(|(profile, update)| ProfileOp::Set(Box::new(profile), update, 0))
                }
            })
    };
    memzero(unsafe { request.as_bytes_mut() });
    result
}

/// Reads the saved, committed server profile.
///
/// `ok` is true whenever the store was read, including `approved: false` with a
/// null `config` when no profile was ever saved. A returned `config` is what was
/// validated and saved; it is not a reachability test.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_get_server_config() -> AsyncTask<ProfileWork> {
    AsyncTask::new(admit(ProfileOp::Get))
}

/// Saves the supplied profile after the same validation `validateServerProfile`
/// applies. This call is the manual-edit commit; the persisted document records
/// that approval and a fresh revision, and no reachability follows from it.
/// `keyUpdate` (keep/set/clear) is applied to protected storage in the same
/// act; a failure leaves the previous approved profile and key untouched.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_set_server_config(profile_json: String) -> AsyncTask<ProfileWork> {
    AsyncTask::new(match write_candidate(profile_json) {
        Ok(mut operation) => match LATEST_PROFILE_WRITE.fetch_update(
            std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire,
            |value| value.checked_add(1),
        ) {
            Ok(previous) => {
                match &mut operation {
                    ProfileOp::Set(_, _, sequence) | ProfileOp::Draft(_, sequence) => *sequence = previous + 1,
                    _ => return AsyncTask::new(ProfileWork::refused("not a server write".to_string())),
                }
                admit(operation)
            },
            Err(_) => ProfileWork::refused("server edit generation is exhausted".to_string()),
        },
        Err(error) => ProfileWork::refused(error),
    })
}

/// Probes every configured endpoint with one bounded TCP connection attempt and
/// saves nothing. `reachable` is a transport observation: it neither
/// authenticates the server nor proves that a RustDesk server answered. A relay
/// Key in the request is validated for shape only and never sent anywhere.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_test_server_config(profile_json: String) -> AsyncTask<ProfileWork> {
    AsyncTask::new(match candidate(profile_json) {
        Ok((profile, update)) => admit(ProfileOp::Test(Box::new(profile), update)),
        Err(error) => ProfileWork::refused(error),
    })
}

struct Committed {
    revision: u64,
    profile: ServerProfile,
    cleanup_warning: Option<String>,
}

/// One manual edit. The order keeps the previous approval valid at every step:
/// add the new credential version, atomically replace the profile file, and only
/// then remove the superseded version. A failure before the file replacement
/// removes the credential this call added and reports nothing committed.
fn commit_profile(
    dir: &Path,
    candidate: ServerProfile,
    update: KeyUpdate,
    store: &impl server_credentials::CredentialStore,
    check: impl Fn() -> Result<(), String>,
) -> Result<Committed, String> {
    check()?;
    let saved = load_saved(dir)?;
    let (current, old_version) = saved.as_ref().map_or((0, 0), |saved| {
        (saved.revision, saved.profile.key_version())
    });
    let revision = current.checked_add(1)
        .filter(|revision| *revision <= MAX_SAFE_REVISION)
        .ok_or_else(|| "saved profile revision is exhausted".to_string())?;
    let update = draft::resolve_update(dir, &candidate, update, store)?;
    let mut added = 0;
    let profile = match update {
        KeyUpdate::Keep => match &saved {
            Some(saved) => {
                let profile = candidate.keep_key(&saved.profile)?;
                if profile.key_version() > 0 {
                    // A route cannot become newly effective while its referenced
                    // Asset is missing or bound to different endpoints.
                    server_credentials::get(store, profile.key_version(), &profile.key_binding())?;
                }
                profile
            }
            None => candidate,
        },
        KeyUpdate::Clear => candidate.with_key(String::new(), 0)?,
        KeyUpdate::Set(KeyInput::Public(key)) => candidate.with_key(key, 0)?,
        KeyUpdate::Set(KeyInput::Shared(key)) => {
            let version = server_credentials::fresh_version();
            let profile = candidate.with_key(String::new(), version)?;
            server_credentials::put(store, version, &profile.key_binding(), &key)?;
            added = version;
            profile
        }
        KeyUpdate::Draft(_) => return Err("the draft Key was not resolved".to_string()),
    };
    let new_version = profile.key_version();
    let rollback = |error: String| {
        if added == 0 { return error; }
        match server_credentials::remove(store, added) {
            Ok(()) => error,
            Err(cleanup) => format!("{error}; the new Key could not be removed from protected storage ({cleanup})"),
        }
    };
    // A background/revocation fence observed after the Asset call must not
    // authorize a new route. Roll back only the unreferenced new Asset version.
    if let Err(error) = check() { return Err(rollback(error)); }
    if let Err(error) = save_profile(dir, &profile, revision) {
        return Err(rollback(error));
    }
    // Retire a shared compatibility epoch as soon as its profile changes.
    // The host's existing close owner joins capture/listener/peers as before.
    super::host_bridge::request_host_close_after_profile_change();
    let cleanup_warning = if old_version > 0 && old_version != new_version {
        server_credentials::remove(store, old_version).err()
            .map(|error| format!("the previous Key could not be removed from protected storage ({error})"))
    } else { None };
    Ok(Committed { revision, profile, cleanup_warning })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_credentials::tests::Memory;
    use std::sync::atomic::{AtomicU32, Ordering};

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    static NEXT: AtomicU32 = AtomicU32::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rd-profile-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn request(relay: &str, update: Value) -> (ServerProfile, KeyUpdate) {
        ServerProfile::parse_candidate(&json!({
            "mode": "custom",
            "idServer": "hbbs.example",
            "relayServer": relay,
            "apiServer": "https://api.example.com",
            "keyUpdate": update,
        }))
        .unwrap()
    }

    fn save(
        dir: &Path,
        store: &Memory,
        relay: &str,
        update: Value,
    ) -> Result<Committed, String> {
        let (profile, update) = request(relay, update);
        commit_profile(dir, profile, update, store, || Ok(()))
    }

    fn stored(store: &Memory, relay: &str, version: u64) -> Option<String> {
        let binding = request(relay, json!({ "action": "keep" })).0.key_binding();
        server_credentials::get(store, version, &binding)
            .ok()
            .map(|key| key.expose().to_owned())
    }

    #[test]
    fn set_keep_replace_and_clear_move_the_protected_version_with_the_profile() {
        let (dir, store) = (temp_dir(), Memory::default());
        let set = save(&dir, &store, "hbbr.example", json!({ "action": "set", "value": "s3cret-one" })).unwrap();
        assert_eq!(set.revision, 1);
        let first = set.profile.key_version();
        let document = set.profile.normalized();
        assert_eq!((document["keyConfigured"].clone(), document["keyVersion"].clone()), (json!(true), json!(first)));
        assert_eq!(document["apiServer"], "https://api.example.com");
        assert!(!approved_profile(&set.profile, 1).to_string().contains("s3cret-one"));
        assert!(!std::fs::read_to_string(dir.join(PROFILE_FILE)).unwrap().contains("s3cret-one"));
        assert_eq!(stored(&store, "hbbr.example", first).as_deref(), Some("s3cret-one"));

        // keep (explicit and by omission) retains the same version on the same route
        let keep = save(&dir, &store, "hbbr.example", json!({ "action": "keep" })).unwrap();
        assert_eq!(keep.profile.key_version(), first);
        assert_eq!(keep.revision, 2);
        let (profile, _) = request("hbbr.example", Value::Null);
        let omitted = commit_profile(&dir, profile, KeyUpdate::Keep, &store, || Ok(())).unwrap();
        assert_eq!(omitted.profile.key_version(), first);
        assert_eq!(stored(&store, "hbbr.example", first).as_deref(), Some("s3cret-one"));

        // replacing writes a new version, then removes the superseded one
        let replaced = save(&dir, &store, "hbbr.example", json!({ "action": "set", "value": "two" })).unwrap();
        let second = replaced.profile.key_version();
        assert_ne!(first, second);
        assert!(replaced.cleanup_warning.is_none());
        assert_eq!(stored(&store, "hbbr.example", second).as_deref(), Some("two"));
        assert!(stored(&store, "hbbr.example", first).is_none());

        let cleared = save(&dir, &store, "hbbr.example", json!({ "action": "clear" })).unwrap();
        assert_eq!(cleared.profile.key_version(), 0);
        assert!(stored(&store, "hbbr.example", second).is_none());
        // after clear, keep means "no key", not an error
        let keep = save(&dir, &store, "hbbr.example", json!({ "action": "keep" })).unwrap();
        assert_eq!(keep.profile.key_version(), 0);
    }

    #[test]
    fn keep_never_carries_a_key_to_another_server_and_changes_nothing() {
        let (dir, store) = (temp_dir(), Memory::default());
        let saved = save(&dir, &store, "hbbr.example", json!({ "action": "set", "value": "s3cret-one" })).unwrap();
        let first = saved.profile.key_version();
        let before = std::fs::read(dir.join(PROFILE_FILE)).unwrap();
        let error = save(&dir, &store, "other.example", json!({ "action": "keep" })).err().unwrap();
        assert!(error.contains("another server"));
        assert_eq!(std::fs::read(dir.join(PROFILE_FILE)).unwrap(), before);
        assert_eq!(stored(&store, "hbbr.example", first).as_deref(), Some("s3cret-one"));
        // an explicit set for the new route is accepted and the old key is dropped
        let moved = save(&dir, &store, "other.example", json!({ "action": "set", "value": "new" })).unwrap();
        assert_eq!(stored(&store, "other.example", moved.profile.key_version()).as_deref(), Some("new"));
        assert!(stored(&store, "hbbr.example", first).is_none());
    }

    #[test]
    fn a_failed_profile_write_removes_the_new_key_and_keeps_the_old_state() {
        let (dir, store) = (temp_dir(), Memory::default());
        let saved = save(&dir, &store, "hbbr.example", json!({ "action": "set", "value": "s3cret-one" })).unwrap();
        let first = saved.profile.key_version();
        let before = std::fs::read(dir.join(PROFILE_FILE)).unwrap();
        // A directory in the place of the temporary file makes the write fail.
        std::fs::create_dir(dir.join(format!("{PROFILE_FILE}.tmp"))).unwrap();
        let error = save(&dir, &store, "hbbr.example", json!({ "action": "set", "value": "two" })).err().unwrap();
        assert!(error.contains("private store"));
        assert_eq!(std::fs::read(dir.join(PROFILE_FILE)).unwrap(), before);
        assert_eq!(stored(&store, "hbbr.example", first).as_deref(), Some("s3cret-one"));
        assert_eq!(store.record_count(), 1);
    }

    #[test]
    fn v1_profiles_load_with_empty_api_and_no_key() {
        let dir = temp_dir();
        let legacy = json!({
            "schemaVersion": 1,
            "approval": "explicit-save",
            "revision": 5,
            "profile": { "mode": "custom", "idServer": "hbbs.example:21116", "relayServer": "", "key": KEY },
        });
        std::fs::write(dir.join(PROFILE_FILE), legacy.to_string()).unwrap();
        let saved = load_saved(&dir).unwrap().unwrap();
        assert_eq!(saved.revision, 5);
        assert_eq!(saved.profile.normalized()["apiServer"], "");
        assert_eq!(saved.profile.key_version(), 0);
    }
}
