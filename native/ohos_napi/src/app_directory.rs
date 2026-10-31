//! App-scoped device directory: the recent and favorite rows this app stored.
//!
//! This is not discovery. A row exists here only because the client explicitly
//! recorded it after observing a session, or marked it favorite; a LAN scan
//! result stays in the official discovery cache and is never copied here, so a
//! discovered peer can never read as an online or recently used one. Reads
//! distinguish "no store yet" (`exists: false`) from a read failure
//! (`ok: false`) and never answer an empty list for a store they could not read.
use super::{
    app_context::{app_scope, AppScope},
    app_storage::{read_private, store_dir, write_private},
};
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task},
    Env,
};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

const DIRECTORY_FILE: &str = "device-directory.json";
const SOURCE: &str = "engine-directory";
const SCHEMA_VERSION: u64 = 1;
const MAX_STORE_BYTES: u64 = 512 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RECENT: usize = 256;
const MAX_FAVORITES: usize = 256;
const MAX_ID_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 512;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

// One read-modify-write boundary for this store. It is not the app metadata lock
// and is never held across a JS call or a join.
static STORE: Mutex<()> = Mutex::new(());

fn store_lock() -> MutexGuard<'static, ()> {
    STORE.lock().unwrap_or_else(|error| error.into_inner())
}

struct Directory {
    revision: u64,
    recent: Vec<Value>,
    favorites: Vec<String>,
}

impl Default for Directory {
    fn default() -> Self {
        Self {
            revision: 0,
            recent: Vec::new(),
            favorites: Vec::new(),
        }
    }
}

fn identifier(value: &str, name: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(format!(
            "{name} must be a nonempty token without whitespace or control characters"
        ));
    }
    Ok(value.to_string())
}

fn text_field(value: Option<&Value>, name: &str) -> Result<String, String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text))
            if text.len() <= MAX_TEXT_BYTES && !text.chars().any(char::is_control) =>
        {
            Ok(text.clone())
        }
        Some(_) => Err(format!("{name} is not an accepted value")),
    }
}

fn uint_field(value: Option<&Value>, max: u64, name: &str) -> Result<u64, String> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(number) => number
            .as_u64()
            .filter(|number| *number <= max)
            .ok_or_else(|| format!("{name} is not an accepted integer")),
    }
}

fn protocol_field(value: Option<&Value>) -> Result<&'static str, String> {
    match value {
        None | Some(Value::Null) => Ok("rustdesk"),
        Some(Value::String(protocol)) => match protocol.as_str() {
            "" | "rustdesk" => Ok("rustdesk"),
            "vnc" => Ok("vnc"),
            "rdp" => Ok("rdp"),
            _ => Err("protocol is not one this layer stores".to_string()),
        },
        Some(_) => Err("protocol must be a string".to_string()),
    }
}

/// One stored row, normalized to the fields this layer keeps. Values the caller
/// did not supply are stored as empty/zero, never invented.
fn recent_row(entry: &Value) -> Result<Value, String> {
    if !entry.is_object() {
        return Err("a recent row is not an object".to_string());
    }
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "a recent row has no id".to_string())?;
    Ok(json!({
        "id": identifier(id, "recent id")?,
        "protocol": protocol_field(entry.get("protocol"))?,
        "address": text_field(entry.get("address"), "recent address")?,
        "port": uint_field(entry.get("port"), 65_535, "recent port")?,
        "username": text_field(entry.get("username"), "recent username")?,
        "hostname": text_field(entry.get("hostname"), "recent hostname")?,
        "platform": text_field(entry.get("platform"), "recent platform")?,
        "alias": text_field(entry.get("alias"), "recent alias")?,
        "note": text_field(entry.get("note"), "recent note")?,
        "lastSuccessAt": uint_field(
            entry.get("lastSuccessAt"),
            MAX_SAFE_INTEGER,
            "recent lastSuccessAt",
        )?,
    }))
}

fn parse_directory(bytes: &[u8]) -> Result<Directory, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "the device directory store is not valid JSON".to_string())?;
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(SCHEMA_VERSION) {
        return Err("the device directory store has an unknown schema".to_string());
    }
    let revision = value
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision <= MAX_SAFE_INTEGER)
        .ok_or_else(|| "the device directory store has an invalid revision".to_string())?;
    let recent_entries = value
        .get("recent")
        .and_then(Value::as_array)
        .ok_or_else(|| "the device directory store has no recent list".to_string())?;
    if recent_entries.len() > MAX_RECENT {
        return Err("the device directory store exceeds its recent bound".to_string());
    }
    let mut recent = Vec::with_capacity(recent_entries.len());
    for entry in recent_entries {
        recent.push(recent_row(entry)?);
    }
    let favorite_entries = value
        .get("favorites")
        .and_then(Value::as_array)
        .ok_or_else(|| "the device directory store has no favorite list".to_string())?;
    if favorite_entries.len() > MAX_FAVORITES {
        return Err("the device directory store exceeds its favorite bound".to_string());
    }
    let mut favorites = Vec::with_capacity(favorite_entries.len());
    for entry in favorite_entries {
        let Some(id) = entry.as_str() else {
            return Err("the device directory store has a non-string favorite".to_string());
        };
        favorites.push(identifier(id, "favorite")?);
    }
    Ok(Directory {
        revision,
        recent,
        favorites,
    })
}

fn load(dir: &Path) -> Result<Option<Directory>, String> {
    match read_private(&dir.join(DIRECTORY_FILE), MAX_STORE_BYTES)? {
        None => Ok(None),
        Some(bytes) => parse_directory(&bytes).map(Some),
    }
}

fn save(dir: &Path, directory: &Directory) -> Result<(), String> {
    let document = json!({
        "schemaVersion": SCHEMA_VERSION,
        "revision": directory.revision,
        "recent": directory.recent,
        "favorites": directory.favorites,
    });
    let bytes = serde_json::to_vec(&document)
        .map_err(|_| "cannot serialize the device directory".to_string())?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err("the device directory would exceed this layer's store bound".to_string());
    }
    write_private(&dir.join(DIRECTORY_FILE), &bytes)
}

fn next_revision(directory: &Directory) -> Result<u64, String> {
    directory
        .revision
        .checked_add(1)
        .filter(|revision| *revision <= MAX_SAFE_INTEGER)
        .ok_or_else(|| "device directory revision is exhausted".to_string())
}

enum DirectoryOp {
    ListRecent,
    ListFavorites,
    SetFavorite { peer_id: String, favorite: bool },
    RecordRecent { row: Value },
    RemoveRecent { peer_id: String },
}

impl DirectoryOp {
    fn action(&self) -> &'static str {
        match self {
            Self::ListRecent => "list_recent_peers",
            Self::ListFavorites => "list_favorites",
            Self::SetFavorite { .. } => "set_favorite",
            Self::RecordRecent { .. } => "record_recent_peer",
            Self::RemoveRecent { .. } => "remove_recent_peer",
        }
    }
}

pub struct DirectoryWork {
    scope: Option<AppScope>,
    op: Option<DirectoryOp>,
    error: Option<String>,
}

pub struct DirectoryOutput {
    document: String,
    committed: bool,
    action: &'static str,
}

fn failure(action: &str, error: &str, committed: bool) -> Value {
    json!({
        "ok": false,
        "action": action,
        "source": SOURCE,
        "committed": committed,
        "error": error,
    })
}

impl DirectoryWork {
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
            .map_or("list_recent_peers", DirectoryOp::action);
        let Some(scope) = self.scope.as_ref() else {
            return failure(
                action,
                self.error
                    .as_deref()
                    .unwrap_or("device directory storage was not admitted"),
                false,
            );
        };
        if let Err(error) = scope.check() {
            return failure(action, &error, false);
        }
        let Some(op) = self.op.take() else {
            return failure(action, "device directory operation is missing", false);
        };
        let dir = match store_dir(scope) {
            Ok(dir) => dir,
            Err(error) => return failure(action, &error, false),
        };
        // Serializes this store's read-modify-write sequences. It is a store
        // boundary only; the app metadata lock is never held here.
        let _store = store_lock();
        match op {
            DirectoryOp::ListRecent => match load(&dir) {
                Ok(None) => json!({
                    "ok": true,
                    "action": "list_recent_peers",
                    "source": SOURCE,
                    "exists": false,
                    "revision": "0",
                    "peers": [],
                    "message": "no device directory store exists yet",
                }),
                Ok(Some(directory)) => json!({
                    "ok": true,
                    "action": "list_recent_peers",
                    "source": SOURCE,
                    "exists": true,
                    "revision": directory.revision.to_string(),
                    "peers": directory.recent,
                }),
                Err(error) => failure("list_recent_peers", &error, false),
            },
            DirectoryOp::ListFavorites => match load(&dir) {
                Ok(None) => json!({
                    "ok": true,
                    "action": "list_favorites",
                    "source": SOURCE,
                    "exists": false,
                    "revision": "0",
                    "favorites": [],
                    "message": "no device directory store exists yet",
                }),
                Ok(Some(directory)) => json!({
                    "ok": true,
                    "action": "list_favorites",
                    "source": SOURCE,
                    "exists": true,
                    "revision": directory.revision.to_string(),
                    "favorites": directory.favorites,
                }),
                Err(error) => failure("list_favorites", &error, false),
            },
            DirectoryOp::SetFavorite { peer_id, favorite } => {
                let mut directory = match load(&dir) {
                    Ok(Some(directory)) => directory,
                    Ok(None) => Directory::default(),
                    Err(error) => return failure("set_favorite", &error, false),
                };
                let present = directory.favorites.iter().any(|id| id == &peer_id);
                if favorite && !present {
                    if directory.favorites.len() >= MAX_FAVORITES {
                        return failure("set_favorite", "favorite capacity is exhausted", false);
                    }
                    directory.favorites.push(peer_id);
                } else if !favorite && present {
                    directory.favorites.retain(|id| id != &peer_id);
                }
                let changed = present != favorite;
                if changed {
                    directory.revision = match next_revision(&directory) {
                        Ok(revision) => revision,
                        Err(error) => return failure("set_favorite", &error, false),
                    };
                    if let Err(error) = save(&dir, &directory) {
                        return failure("set_favorite", &error, false);
                    }
                }
                json!({
                    "ok": true,
                    "action": "set_favorite",
                    "source": SOURCE,
                    "revision": directory.revision.to_string(),
                    "changed": changed,
                    "favorites": directory.favorites,
                })
            }
            DirectoryOp::RecordRecent { row } => {
                let mut directory = match load(&dir) {
                    Ok(Some(directory)) => directory,
                    Ok(None) => Directory::default(),
                    Err(error) => return failure("record_recent_peer", &error, false),
                };
                let id = row
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                directory
                    .recent
                    .retain(|entry| entry.get("id").and_then(Value::as_str) != Some(id.as_str()));
                directory.recent.insert(0, row);
                directory.recent.truncate(MAX_RECENT);
                directory.revision = match next_revision(&directory) {
                    Ok(revision) => revision,
                    Err(error) => return failure("record_recent_peer", &error, false),
                };
                if let Err(error) = save(&dir, &directory) {
                    return failure("record_recent_peer", &error, false);
                }
                json!({
                    "ok": true,
                    "action": "record_recent_peer",
                    "source": SOURCE,
                    "revision": directory.revision.to_string(),
                    "peers": directory.recent,
                })
            }
            DirectoryOp::RemoveRecent { peer_id } => {
                let mut directory = match load(&dir) {
                    Ok(Some(directory)) => directory,
                    Ok(None) => Directory::default(),
                    Err(error) => return failure("remove_recent_peer", &error, false),
                };
                let before = directory.recent.len();
                directory
                    .recent
                    .retain(|entry| entry.get("id").and_then(Value::as_str) != Some(peer_id.as_str()));
                let removed = directory.recent.len() != before;
                if removed {
                    directory.revision = match next_revision(&directory) {
                        Ok(revision) => revision,
                        Err(error) => return failure("remove_recent_peer", &error, false),
                    };
                    if let Err(error) = save(&dir, &directory) {
                        return failure("remove_recent_peer", &error, false);
                    }
                }
                json!({
                    "ok": true,
                    "action": "remove_recent_peer",
                    "source": SOURCE,
                    "revision": directory.revision.to_string(),
                    "removed": removed,
                    "peers": directory.recent,
                })
            }
        }
    }
}

impl Task for DirectoryWork {
    type Output = DirectoryOutput;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        let action = self
            .op
            .as_ref()
            .map_or("list_recent_peers", DirectoryOp::action);
        let value = self.run();
        Ok(DirectoryOutput {
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

fn admit(op: DirectoryOp) -> DirectoryWork {
    match app_scope() {
        Ok(scope) => DirectoryWork {
            scope: Some(scope),
            op: Some(op),
            error: None,
        },
        Err(error) => DirectoryWork::refused(error),
    }
}

fn parse_row(peer_json: &str) -> Result<Value, String> {
    if peer_json.len() > MAX_REQUEST_BYTES {
        return Err("recent peer JSON is larger than this layer accepts".to_string());
    }
    let value = serde_json::from_str::<Value>(peer_json)
        .map_err(|_| "recent peer must be a JSON object".to_string())?;
    recent_row(&value)
}

/// Lists the rows this app recorded after observed sessions.
///
/// `ok: true` with `exists: false` means no store exists yet; `ok: false` is a
/// read failure and carries no peers. A row's presence here is not a liveness
/// or reachability observation.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_list_recent_peers() -> AsyncTask<DirectoryWork> {
    AsyncTask::new(admit(DirectoryOp::ListRecent))
}

/// Lists the favorite targets this app stored, in insertion order.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_list_favorites() -> AsyncTask<DirectoryWork> {
    AsyncTask::new(admit(DirectoryOp::ListFavorites))
}

/// Adds or removes one favorite target and reports the persisted list.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_set_favorite(peer_id: String, favorite: bool) -> AsyncTask<DirectoryWork> {
    AsyncTask::new(match identifier(&peer_id, "favorite id") {
        Ok(peer_id) => admit(DirectoryOp::SetFavorite { peer_id, favorite }),
        Err(error) => DirectoryWork::refused(error),
    })
}

/// Records one peer row. The caller must have observed the session itself; this
/// layer only persists what it is given and never infers a success time.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_record_recent_peer(peer_json: String) -> AsyncTask<DirectoryWork> {
    AsyncTask::new(match parse_row(&peer_json) {
        Ok(row) => admit(DirectoryOp::RecordRecent { row }),
        Err(error) => DirectoryWork::refused(error),
    })
}

/// Removes one recent row by id and reports whether a row was removed.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_remove_recent_peer(peer_id: String) -> AsyncTask<DirectoryWork> {
    AsyncTask::new(match identifier(&peer_id, "recent id") {
        Ok(peer_id) => admit(DirectoryOp::RemoveRecent { peer_id }),
        Err(error) => DirectoryWork::refused(error),
    })
}
