//! Raw editor draft. Public route text is private JSON; every entered Key,
//! including incomplete/invalid text, stays in the existing Asset store.
//! This module is called only under app_profile's admitted, serialized writer.
use super::{server_credentials, KeyInput, KeyUpdate, ServerProfile, MAX_SAFE_REVISION};
use crate::app_storage;
use super::server_credentials::{CredentialStore, LicenceKey};
use serde_json::{json, Value};
use std::path::Path;

const FILE: &str = "server-draft.json";
const MAX_BYTES: u64 = 16 * 1024;

pub(super) struct Candidate {
    fields: Value,
    update: KeyUpdate,
}

impl Candidate {
    pub(super) fn parse(value: &Value) -> Result<Self, String> {
        let mode = value.get("mode").and_then(Value::as_str)
            .filter(|mode| matches!(*mode, "official" | "custom"))
            .ok_or_else(|| "draft mode must be official or custom".to_string())?;
        // A nonsecret UI write witness reconciles a newer public-address
        // fallback with an older Asset-backed draft after an interrupted wait.
        // It grants no authority: Key reuse still needs revision + route binding.
        let edit_token = value.get("editToken").and_then(Value::as_str).unwrap_or_default();
        if edit_token.len() > 128 || edit_token.chars().any(char::is_control) {
            return Err("the draft edit token is invalid".to_string());
        }
        let mut fields = json!({ "mode": mode, "editToken": edit_token });
        for name in ["idServer", "relayServer", "apiServer"] {
            fields[name] = json!(value.get(name).and_then(Value::as_str)
                .ok_or_else(|| format!("draft {name} must be a string"))?);
        }
        Ok(Self { fields, update: KeyUpdate::parse(value, mode, true)? })
    }
}

fn load(dir: &Path) -> Result<Option<Value>, String> {
    let Some(bytes) = app_storage::read_private(&dir.join(FILE), MAX_BYTES)? else { return Ok(None); };
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "the saved server draft is not valid JSON".to_string())?;
    revision(&value)?;
    for field in ["mode", "idServer", "relayServer", "apiServer", "keyAction"] {
        if value.get(field).and_then(Value::as_str).is_none() {
            return Err("the saved server draft is incomplete".to_string());
        }
    }
    if !matches!(value["keyAction"].as_str(), Some("keep" | "set" | "clear")) {
        return Err("the saved draft has an invalid Key action".to_string());
    }
    key_version(&value)?;
    Ok(Some(value))
}

fn revision(value: &Value) -> Result<u64, String> {
    value.get("revision").and_then(Value::as_u64)
        .filter(|v| (1..=MAX_SAFE_REVISION).contains(v))
        .ok_or_else(|| "the saved draft revision is invalid".to_string())
}

fn key_version(value: &Value) -> Result<u64, String> {
    value.get("keyVersion").and_then(Value::as_u64).filter(|v| *v <= MAX_SAFE_REVISION)
        .ok_or_else(|| "the saved draft Key reference is invalid".to_string())
}

fn binding(scope: &Value) -> Result<[u8; 32], String> {
    let field = |name| scope.get(name).and_then(Value::as_str)
        .ok_or_else(|| "the draft Key binding is incomplete".to_string());
    // A distinct purpose in the same record format, not another secret store.
    Ok(server_credentials::binding("draft", field("mode")?, field("idServer")?, field("relayServer")?))
}

pub(super) fn public(dir: &Path, store: &impl CredentialStore) -> Result<Option<Value>, String> {
    let Some(value) = load(dir)? else { return Ok(None); };
    let version = key_version(&value)?;
    let mut output = json!({
        "mode": value["mode"], "idServer": value["idServer"],
        "relayServer": value["relayServer"], "apiServer": value["apiServer"],
        "draftRevision": revision(&value)?, "draftKeyConfigured": version > 0,
        "draftEditToken": value.get("editToken").and_then(Value::as_str).unwrap_or_default(),
        "draftKeyAction": value["keyAction"],
    });
    if version > 0 {
        if let Err(error) = binding(&value["keyScope"])
            .and_then(|scope| server_credentials::get_draft(store, version, &scope)) {
            output["keyError"] = json!(error);
        }
    }
    Ok(Some(output))
}

pub(super) fn commit(
    dir: &Path, candidate: Candidate, store: &impl CredentialStore,
    check: impl Fn() -> Result<(), String>,
) -> Result<Value, String> {
    check()?;
    let old = load(dir)?;
    let old_revision = old.as_ref().map(revision).transpose()?.unwrap_or(0);
    let old_version = old.as_ref().map(key_version).transpose()?.unwrap_or(0);
    let next = old_revision.checked_add(1).filter(|v| *v <= MAX_SAFE_REVISION)
        .ok_or_else(|| "the server draft revision is exhausted".to_string())?;
    let mut document = candidate.fields;
    let mut added = 0;
    let (action, version, scope) = match candidate.update {
        KeyUpdate::Keep => ("keep", 0, Value::Null),
        KeyUpdate::Clear => ("clear", 0, Value::Null),
        KeyUpdate::Draft(expected) => {
            let old = old.as_ref().filter(|_| old_revision == expected)
                .ok_or_else(|| "the server draft changed; reload before reusing its Key".to_string())?;
            (old["keyAction"].as_str().unwrap_or("keep"), old_version, old["keyScope"].clone())
        }
        KeyUpdate::Set(key) => {
            let key = match key {
                KeyInput::Public(text) => LicenceKey::draft(text)?,
                KeyInput::Shared(key) => key,
            };
            let scope = json!({ "mode": document["mode"], "idServer": document["idServer"], "relayServer": document["relayServer"] });
            let version = server_credentials::fresh_version();
            server_credentials::put(store, version, &binding(&scope)?, &key)?;
            added = version;
            ("set", version, scope)
        }
    };
    document["revision"] = json!(next);
    document["keyAction"] = json!(action);
    document["keyVersion"] = json!(version);
    document["keyScope"] = scope;
    let result = (|| {
        check()?;
        let bytes = serde_json::to_vec(&document).map_err(|_| "cannot serialize the server draft".to_string())?;
        if bytes.len() as u64 > MAX_BYTES { return Err("the server draft exceeds the storage limit".to_string()); }
        app_storage::write_private(&dir.join(FILE), &bytes)
    })();
    if let Err(error) = result {
        if added > 0 {
            if let Err(cleanup) = server_credentials::remove(store, added) {
                return Err(format!("{error}; the new draft Key could not be removed ({cleanup})"));
            }
        }
        return Err(error);
    }
    let cleanup = if old_version > 0 && old_version != version {
        server_credentials::remove(store, old_version).err()
    } else { None };
    let mut output = json!({ "ok": true, "action": "set_server_draft", "committed": true, "approved": false });
    match public(dir, store) {
        Ok(value) => output["draft"] = json!(value),
        Err(error) => { output["ok"] = json!(false); output["draftError"] = json!(error); }
    }
    if let Some(warning) = cleanup { output["cleanupWarning"] = json!(warning); }
    Ok(output)
}

/// The route a stored draft names, as it compares with an effective profile.
///
/// The draft keeps the operator's text verbatim, while the effective profile the
/// client hands to `runtimeSetServerConfig` is the editor's trimmed value. Only
/// the endpoint fields are normalized for that comparison: the stored text and
/// the Key binding derived from it keep their original bytes, because the
/// binding names exactly what the Key was saved under.
fn route(value: &Value) -> Result<ServerProfile, String> {
    let endpoint_field = |name: &str| value.get(name).and_then(Value::as_str)
        .map(str::trim)
        .ok_or_else(|| format!("the saved server draft is missing {name}"));
    ServerProfile::parse(&json!({
        "mode": value["mode"], "idServer": endpoint_field("idServer")?,
        "relayServer": endpoint_field("relayServer")?,
    }))
}

/// A caller can reference only the current native draft. Never trust a caller's
/// Asset pointer or move stored text to a different canonical hbbs/hbbr route.
pub(super) fn resolve_update(
    dir: &Path, candidate: &ServerProfile, update: KeyUpdate, store: &impl CredentialStore,
) -> Result<KeyUpdate, String> {
    let KeyUpdate::Draft(expected) = update else { return Ok(update); };
    let value = load(dir)?.filter(|v| revision(v).ok() == Some(expected))
        .ok_or_else(|| "the server draft changed; save the current edit again".to_string())?;
    if !candidate.same_route(&route(&value)?) {
        return Err("the current edit no longer matches the saved draft".to_string());
    }
    match value["keyAction"].as_str() {
        Some("keep") => Ok(KeyUpdate::Keep),
        Some("clear") => Ok(KeyUpdate::Clear),
        Some("set") => {
            let scope = &value["keyScope"];
            if !candidate.same_route(&route(scope)?) {
                return Err("draft saved; enter the Key again or clear it before using a different server".to_string());
            }
            let key = server_credentials::get_draft(store, key_version(&value)?, &binding(scope)?)?;
            // Full wire validation/classification happens only now. Invalid raw
            // text remains protected in the draft, never an effective route.
            KeyUpdate::parse(&json!({ "keyUpdate": { "action": "set", "value": key.expose() } }), candidate.mode(), false)
        }
        _ => Err("the saved draft has an invalid Key action".to_string()),
    }
}
