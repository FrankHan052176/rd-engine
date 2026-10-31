//! App-scoped, explicit-save server profile storage for this HAR.
//!
//! The profile is admitted with the same rules as `validateServerProfile` and
//! persisted only under the fixed private root. A saved profile is a validated
//! configuration, never a reachability or identity result: the endpoint probe
//! below reports only what a TCP connection attempt did, and saving never
//! claims the server is reachable.
use super::{
    app_context::{app_scope, AppScope},
    app_storage::{read_private, store_dir, write_private},
    server_profile::{ServerProfile, MAX_SAFE_REVISION},
};
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

const PROFILE_FILE: &str = "server-profile.json";
const MAX_PROFILE_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_PROBE_ADDRESSES: usize = 2;

struct SavedProfile {
    revision: u64,
    profile: ServerProfile,
}

enum ProfileOp {
    Get,
    Set(Box<ServerProfile>),
    Test(Box<ServerProfile>),
}

impl ProfileOp {
    fn action(&self) -> &'static str {
        match self {
            Self::Get => "get_server_config",
            Self::Set(_) => "set_server_config",
            Self::Test(_) => "test_server_config",
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
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || value.get("approval").and_then(Value::as_str) != Some("explicit-save")
    {
        return Err("the saved server profile has no explicit-save approval".to_string());
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
    let document = json!({
        "schemaVersion": 1,
        "approval": "explicit-save",
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
        fields.insert("approval".to_string(), json!("explicit-save"));
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

fn test_profile(profile: &ServerProfile) -> Value {
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
        "config": profile.normalized(),
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
            ProfileOp::Get => match load_saved(&dir) {
                Ok(Some(saved)) => json!({
                    "ok": true,
                    "action": "get_server_config",
                    "approved": true,
                    "revision": saved.revision.to_string(),
                    "config": saved.profile.normalized(),
                    "approvedProfile": approved_profile(&saved.profile, saved.revision),
                    "committed": false,
                    "message": "the saved profile is present; it was validated when it was saved and is not probed here",
                }),
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
            },
            ProfileOp::Set(profile) => {
                let current = match load_saved(&dir) {
                    Ok(Some(saved)) => saved.revision,
                    Ok(None) => 0,
                    Err(error) => return failure("set_server_config", &error, false),
                };
                let Some(revision) = current
                    .checked_add(1)
                    .filter(|revision| *revision <= MAX_SAFE_REVISION)
                else {
                    return failure(
                        "set_server_config",
                        "saved profile revision is exhausted",
                        false,
                    );
                };
                match save_profile(&dir, &profile, revision) {
                    Ok(()) => json!({
                        "ok": true,
                        "action": "set_server_config",
                        "approved": true,
                        "revision": revision.to_string(),
                        "config": profile.normalized(),
                        "approvedProfile": approved_profile(&profile, revision),
                        "committed": true,
                        "message": "saved after validation; this is neither a reachability nor an identity result",
                    }),
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
            ProfileOp::Test(profile) => test_profile(&profile),
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

fn parse_candidate(profile_json: &str) -> Result<ServerProfile, String> {
    if profile_json.len() > MAX_REQUEST_BYTES {
        return Err("server profile JSON is larger than this layer accepts".to_string());
    }
    let value = serde_json::from_str::<Value>(profile_json)
        .map_err(|_| "server profile must be a JSON object".to_string())?;
    ServerProfile::parse(&value)
}

/// Reads the saved, explicitly approved server profile.
///
/// `ok` is true whenever the store was read, including `approved: false` with a
/// null `config` when no profile was ever saved. A returned `config` is what was
/// validated and saved; it is not a reachability test.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_get_server_config() -> AsyncTask<ProfileWork> {
    AsyncTask::new(admit(ProfileOp::Get))
}

/// Saves the supplied profile after the same validation `validateServerProfile`
/// applies. This call is the explicit-save act; the persisted document records
/// that approval and a fresh revision, and no reachability follows from it.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_set_server_config(profile_json: String) -> AsyncTask<ProfileWork> {
    AsyncTask::new(match parse_candidate(&profile_json) {
        Ok(profile) => admit(ProfileOp::Set(Box::new(profile))),
        Err(error) => ProfileWork::refused(error),
    })
}

/// Probes every configured endpoint with one bounded TCP connection attempt and
/// saves nothing. `reachable` is a transport observation: it neither
/// authenticates the server nor proves that a RustDesk server answered.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_test_server_config(profile_json: String) -> AsyncTask<ProfileWork> {
    AsyncTask::new(match parse_candidate(&profile_json) {
        Ok(profile) => admit(ProfileOp::Test(Box::new(profile))),
        Err(error) => ProfileWork::refused(error),
    })
}
