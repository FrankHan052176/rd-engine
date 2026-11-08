//! Native client for the pinned official cloud address-book REST API, driven by
//! the one account owner. It exists so an OHOS front end never holds a token:
//! the bearer credential is leased from `state` for exactly one operation, only
//! ever written into a request header through the owner's `Transport`
//! (Bearer, HTTPS-only, no redirects, bounded body/time), and never returned.
//!
//! Wire sources (pinned official Flutter client, `.build-deps/official-client/
//! flutter/lib/models/ab_model.dart` unless noted):
//! * mode probe `POST /api/ab/personal` (404 = legacy server; no/null `guid` = legacy) — `_getPersonalAbGuid`
//! * `POST /api/ab/settings` `max_peer_one_ab` — `_getAbSettings`
//! * `POST /api/ab/shared/profiles?current&pageSize` — `_getSharedAbProfiles`;
//!   profile fields `guid,name,owner,note,info,rule` are `common/hbbs/hbbs.dart` `AbProfile`,
//!   `ShareRule` read=1 / readWrite=2 / fullControl=3
//! * `POST /api/ab/peers?current&pageSize&ab=<guid>`, `POST /api/ab/tags/<guid>` — `Ab._fetchPeers/_fetchTags`
//! * legacy `GET /api/ab` / `POST /api/ab` with `{"data": "<json string>"}` — `LegacyAb.pullAbImpl/pushAb`
//!   (`data` = `{tags, peers, tag_colors:"<json string>"}`)
//! Mutations (peer/tag endpoints) live in `mutation.rs`.
//!
//! Known limit, not hidden: the REST API has no revision/CAS, so a legacy
//! read-modify-write can lose a concurrent edit made by another client between
//! its GET and POST. The new API's per-peer/tag calls are server-side
//! field-level updates and do not rewrite other fields.

use super::{
    http::{HttpResponse, Request, Transport},
    service::{Code, Failure},
    state::{self, RequestAccess},
};
use hbb_common::serde_json::{self, json, Map, Value};
use std::{cell::Cell, collections::HashMap, sync::Mutex, time::Duration};
use url::Url;
use zeroize::Zeroizing;

const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const PAGE_SIZE: u64 = 100;
const MAX_PAGES: u64 = 2000;
const LEGACY_ID: &str = "legacy";
const LEGACY_NAME: &str = "Legacy address book";
const PERSONAL_NAME: &str = "My address book";

/// Mutations never overlap in this process (our own legacy read-modify-write
/// would otherwise race itself). Reads are not gated.
static GATE: Mutex<()> = Mutex::new(());

pub(super) fn invalid(message: &str) -> Failure {
    Failure::new(Code::Invalid, message)
}

pub(super) fn server(message: impl Into<String>) -> Failure {
    Failure::new(Code::Server, message)
}

/// One operation's transport + credential lease. `sent` is set before every
/// mutating request leaves, so a failure never claims "not sent" for a request
/// that may have reached the server.
pub(super) struct Client<'a> {
    transport: Transport,
    access: &'a RequestAccess,
    admission: u64,
    sent: &'a Cell<bool>,
}

/// Run one cloud operation on the shared executor from a NAPI worker thread.
/// No owner or application lock is held across the network. `mutating` ops are
/// serialized, report `busy` instead of queueing, and attach `sent` to failures.
/// Must not be called from an executor thread (it blocks).
pub(super) fn drive<T>(
    admission: u64,
    receipt: &str,
    mutating: bool,
    operation: impl AsyncFnOnce(&Client<'_>) -> Result<T, Failure>,
) -> Result<(T, bool), Failure> {
    state::check_admitted(admission).map_err(|error| Failure::from_error(&error))?;
    let gate = if mutating {
        match GATE.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) =>
                return Err(Failure::new(Code::Busy, "Another address-book change is in progress")),
        }
    } else {
        None
    };
    let access = state::begin_request(receipt, admission).map_err(|error| Failure::from_error(&error))?;
    let runtime = crate::executor::runtime()
        .map_err(|_| Failure::new(Code::Server, "Account executor is unavailable"))?;
    let sent = Cell::new(false);
    let outcome = runtime.block_on(async {
        let target = format!("{}/api/ab", access.context.api_server);
        let transport = match Transport::new(&access.context, &target).await {
            Ok(transport) => transport,
            Err(_) => return Err(network_failure(&access, admission)),
        };
        let client = Client { transport, access: &access, admission, sent: &sent };
        match tokio::time::timeout(OPERATION_TIMEOUT, operation(&client)).await {
            Ok(result) => result,
            Err(_) => Err(Failure::new(Code::Network, "Address-book operation timed out")),
        }
    });
    drop(gate);
    let outcome = match state::request_still_valid(&access.context, admission) {
        Ok(()) => outcome,
        Err(error) => Err(Failure::from_error(&error)),
    };
    outcome.map(|value| (value, sent.get())).map_err(|mut failure| {
        if mutating { failure.sent = Some(sent.get()); }
        failure
    })
}

pub(super) fn network_failure(access: &RequestAccess, admission: u64) -> Failure {
    match state::request_still_valid(&access.context, admission) {
        Err(error) => Failure::from_error(&error),
        Ok(()) => Failure::new(Code::Network, "Cannot reach the account server"),
    }
}

// ---------------------------------------------------------------- responses

pub(super) fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

fn status_failure(status: u16) -> Option<Failure> {
    match status {
        401 => Some(Failure::new(Code::Unauthorized, "The server rejected the account credential")),
        403 => Some(Failure::new(Code::Forbidden, "The account is not permitted to do this")),
        _ => None,
    }
}

fn server_error(body: &str) -> bool {
    let value: Value = match serde_json::from_str(body) { Ok(value) => value, Err(_) => return false };
    value.as_object().is_some_and(|map| map.contains_key("error"))
}

// Never echo the server's error text: it may reflect a submitted credential or
// an unedited peer password. Status and a fixed actionable error are enough.
const SERVER_ERROR: &str = "The account server rejected the request";

/// Official `_jsonDecodeRespMap/List` + `json['error']`: an `error` key is a
/// failure whatever the HTTP status; a non-200 without JSON is `HTTP n`.
fn json_value(response: &HttpResponse) -> Result<Value, Failure> {
    if let Some(failure) = status_failure(response.status_code) { return Err(failure); }
    let parsed: Result<Value, _> = serde_json::from_str(&response.body);
    let Ok(value) = parsed else {
        return Err(server(if response.status_code == 200 {
            "Invalid server response".to_owned()
        } else {
            format!("HTTP {}", response.status_code)
        }));
    };
    if value.as_object().is_some_and(|map| map.contains_key("error")) {
        return Err(server(SERVER_ERROR));
    }
    if response.status_code != 200 { return Err(server(format!("HTTP {}", response.status_code))); }
    Ok(value)
}

fn json_object(response: &HttpResponse) -> Result<Map<String, Value>, Failure> {
    match json_value(response)? {
        Value::Object(map) => Ok(map),
        _ => Err(server("Invalid server response")),
    }
}

fn json_list(response: &HttpResponse) -> Result<Vec<Value>, Failure> {
    match json_value(response)? {
        Value::Array(list) => Ok(list),
        _ => Err(server("Invalid server response")),
    }
}

/// Official `_jsonDecodeActionResp`: success is exactly `200` + empty body.
fn action_ok(response: &HttpResponse) -> Result<(), Failure> {
    if let Some(failure) = status_failure(response.status_code) { return Err(failure); }
    if response.status_code == 200 && response.body.is_empty() { return Ok(()); }
    if server_error(&response.body) { return Err(server(SERVER_ERROR)); }
    if response.status_code != 200 { return Err(server(format!("HTTP {}", response.status_code))); }
    Err(server("Unexpected server response"))
}

/// Official `LegacyAb.pushAb`: 200 with empty or `null` body, or any 200 without `error`.
fn legacy_push_ok(response: &HttpResponse) -> Result<(), Failure> {
    if let Some(failure) = status_failure(response.status_code) { return Err(failure); }
    let body = response.body.trim();
    if response.status_code == 200 && (body.is_empty() || body.eq_ignore_ascii_case("null")) { return Ok(()); }
    // Nonempty legacy actions still have to be valid JSON, as in pushAb; do
    // not turn a 200 block page or truncated body into a successful change.
    let value: Value = serde_json::from_str(body).map_err(|_| server("Invalid server response"))?;
    if value.as_object().is_some_and(|map| map.contains_key("error")) { return Err(server(SERVER_ERROR)); }
    if response.status_code == 200 { Ok(()) } else { Err(server(format!("HTTP {}", response.status_code))) }
}

fn guid_ok(guid: &str) -> bool {
    !guid.is_empty() && guid.len() <= 64
        && guid.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(super) enum Mode {
    Legacy,
    Cloud(String),
}

pub(super) struct Book {
    pub(super) id: String,
    name: String,
    kind: &'static str,
    rule: Option<i64>,
    pub(super) writable: bool,
}

impl Book {
    fn summary(&self) -> Value {
        json!({ "id": self.id, "name": self.name, "kind": self.kind, "writable": self.writable })
    }

    fn with_capabilities(&self) -> Value {
        let writable = self.writable;
        let mut summary = self.summary();
        summary["capabilities"] = json!({
            "upsertPeer": writable, "deletePeer": writable,
            "upsertTag": writable, "renameTag": writable, "deleteTag": writable,
        });
        if let Some(rule) = self.rule { summary["capabilities"]["rule"] = json!(rule); }
        summary
    }
}

// ------------------------------------------------------------------- client

impl Client<'_> {
    pub(super) async fn call(&self, method: &str, path: &str, query: &[(&str, &str)],
        body: Option<String>, mutating: bool) -> Result<HttpResponse, Failure>
    {
        state::request_still_valid(&self.access.context, self.admission)
            .map_err(|error| Failure::from_error(&error))?;
        let mut url = Url::parse(&format!("{}{}", self.access.context.api_server, path))
            .map_err(|_| invalid("Invalid address-book endpoint"))?;
        if !query.is_empty() { url.query_pairs_mut().extend_pairs(query); }
        let token = std::str::from_utf8(self.access.token.bytes())
            .map_err(|_| Failure::new(Code::Unauthorized, "The account credential is unusable"))?;
        let bearer = Zeroizing::new(format!("Bearer {token}"));
        let encoded = Zeroizing::new(serde_json::to_string(&*bearer)
            .map_err(|_| Failure::new(Code::Server, "Cannot encode request headers"))?);
        let headers = format!("{{\"Authorization\":{},\"Content-Type\":\"application/json\"}}", &*encoded);
        // The official client sets Content-Length: 0 on body-less POSTs; an empty
        // body gives reqwest the same explicit length.
        let body = if method == "get" { None } else { Some(body.unwrap_or_default()) };
        let request = Request::new(url.into(), method, body, headers)
            .map_err(|_| invalid("Invalid address-book request"))?;
        // Final privacy admission point before dispatch. A request which wins
        // this check may already be on the wire when withdrawal is raised; it
        // reports sent=true rather than pretending it was cancelled/rolled back.
        state::check_admitted(self.admission).map_err(|error| Failure::from_error(&error))?;
        if mutating { self.sent.set(true); }
        let response = match self.transport.request(request).await {
            Ok(response) => response,
            Err(_) => return Err(network_failure(self.access, self.admission)),
        };
        state::request_still_valid(&self.access.context, self.admission)
            .map_err(|error| Failure::from_error(&error))?;
        Ok(response)
    }

    async fn paged(&self, path: &str, extra: &[(&str, &str)], missing_is_empty: bool)
        -> Result<Vec<Value>, Failure>
    {
        let mut out = Vec::new();
        let mut total = 0u64;
        let mut current = 1u64;
        loop {
            let current_text = current.to_string();
            let page_size = PAGE_SIZE.to_string();
            let mut query = vec![("current", current_text.as_str()), ("pageSize", page_size.as_str())];
            query.extend_from_slice(extra);
            let response = self.call("post", path, &query, None, false).await?;
            if missing_is_empty && response.status_code == 404 { return Ok(Vec::new()); }
            let map = json_object(&response)?;
            let count = map.get("total").and_then(Value::as_u64)
                .ok_or_else(|| server("Invalid paged address-book response"))?;
            if total == 0 { total = count; }
            match map.get("data") {
                Some(Value::Array(data)) => out.extend(data.iter().cloned()),
                None | Some(Value::Null) if count == 0 => {},
                _ => return Err(server("Invalid paged address-book response")),
            }
            if current * PAGE_SIZE >= total { break; }
            if current >= MAX_PAGES { return Err(server("The address book has too many pages")); }
            current += 1;
        }
        Ok(out)
    }

    async fn mode(&self) -> Result<Mode, Failure> {
        let response = self.call("post", "/api/ab/personal", &[], None, false).await?;
        if response.status_code == 404 { return Ok(Mode::Legacy); }
        let map = json_object(&response)?;
        match map.get("guid") {
            None | Some(Value::Null) => Ok(Mode::Legacy),
            Some(Value::String(guid)) if guid_ok(guid) => Ok(Mode::Cloud(guid.clone())),
            _ => Err(server("Invalid personal address-book id")),
        }
    }

    async fn books(&self) -> Result<(Mode, Vec<Book>), Failure> {
        let mode = self.mode().await?;
        let personal = match &mode {
            Mode::Legacy => {
                return Ok((mode, vec![Book {
                    id: LEGACY_ID.to_owned(), name: LEGACY_NAME.to_owned(), kind: "legacy",
                    rule: None, writable: true,
                }]));
            }
            Mode::Cloud(guid) => guid.clone(),
        };
        let mut books = vec![Book {
            id: personal.clone(), name: PERSONAL_NAME.to_owned(), kind: "personal", rule: None, writable: true,
        }];
        for profile in self.paged("/api/ab/shared/profiles", &[], true).await? {
            let guid = profile.get("guid").and_then(Value::as_str).unwrap_or_default();
            if !guid_ok(guid) { return Err(server("Invalid shared address-book id")); }
            if guid == personal || books.iter().any(|book| book.id == guid) { continue; }
            let rule = profile.get("rule").and_then(Value::as_i64).unwrap_or(0);
            books.push(Book {
                id: guid.to_owned(),
                name: sanitize(profile.get("name").and_then(Value::as_str).unwrap_or_default()),
                kind: "shared",
                rule: Some(rule),
                // ShareRule readWrite(2) / fullControl(3), as `Ab.canWrite`.
                writable: rule == 2 || rule == 3,
            });
        }
        Ok((mode, books))
    }

    /// Re-resolved on every call from the server, so the permission and the
    /// existence of a book are never taken from the caller.
    pub(super) async fn book(&self, id: &str) -> Result<(Mode, Book), Failure> {
        let (mode, books) = self.books().await?;
        let book = books.into_iter().find(|book| book.id == id)
            .ok_or_else(|| invalid("Unknown address book"))?;
        Ok((mode, book))
    }

    pub(super) async fn cloud_peers(&self, guid: &str) -> Result<Vec<Value>, Failure> {
        let raw = self.paged("/api/ab/peers", &[("ab", guid)], false).await?;
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut peers: Vec<Value> = Vec::new();
        for peer in raw {
            let id = peer.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())
                .ok_or_else(|| server("Invalid address-book peer"))?.to_owned();
            match index.get(&id) {
                Some(&at) => peers[at] = peer,
                None => { index.insert(id, peers.len()); peers.push(peer); }
            }
        }
        Ok(peers)
    }

    pub(super) async fn cloud_tags(&self, guid: &str) -> Result<Vec<String>, Failure> {
        let response = self.call("post", &format!("/api/ab/tags/{guid}"), &[], None, false).await?;
        let mut tags: Vec<String> = Vec::new();
        for item in json_list(&response)? {
            let name = item.get("name").and_then(Value::as_str).filter(|name| !name.is_empty())
                .ok_or_else(|| server("Invalid address-book tag"))?;
            if !tags.iter().any(|tag| tag == name) { tags.push(name.to_owned()); }
        }
        Ok(tags)
    }

    pub(super) async fn legacy_read(&self) -> Result<(Value, u64), Failure> {
        let response = self.call("get", "/api/ab", &[], None, false).await?;
        if let Some(failure) = status_failure(response.status_code) { return Err(failure); }
        if response.status_code == 404 {
            return Err(Failure::new(Code::ServerUnsupported, "The server has no supported address-book API"));
        }
        if response.status_code == 200 && response.body.trim().eq_ignore_ascii_case("null") {
            return Ok((Value::Object(Map::new()), 0));
        }
        let map = json_object(&response)?;
        let licensed = map.get("licensed_devices").and_then(Value::as_u64).unwrap_or(0);
        let data = map.get("data").and_then(Value::as_str).ok_or_else(|| server("Invalid server response"))?;
        match serde_json::from_str::<Value>(data) {
            Ok(inner @ Value::Object(_)) => Ok((inner, licensed)),
            Ok(Value::Null) => Ok((Value::Object(Map::new()), licensed)),
            _ => Err(server("Invalid address-book data")),
        }
    }

    pub(super) async fn legacy_write(&self, inner: &Value) -> Result<(), Failure> {
        let data = serde_json::to_string(inner).map_err(|_| server("Cannot encode address-book data"))?;
        let body = serde_json::to_string(&json!({ "data": data }))
            .map_err(|_| server("Cannot encode address-book data"))?;
        let response = self.call("post", "/api/ab", &[], Some(body), true).await?;
        legacy_push_ok(&response)
    }

    pub(super) async fn max_peers(&self) -> Result<u64, Failure> {
        let response = self.call("post", "/api/ab/settings", &[], None, false).await?;
        if response.status_code == 404 { return Ok(0); }
        Ok(json_object(&response)?.get("max_peer_one_ab").and_then(Value::as_u64).unwrap_or(0))
    }

    pub(super) async fn action(&self, method: &str, path: &str, body: Value) -> Result<(), Failure> {
        let body = serde_json::to_string(&body).map_err(|_| invalid("Cannot encode request"))?;
        let response = self.call(method, path, &[], Some(body), true).await?;
        action_ok(&response)
    }
}

// --------------------------------------------------------------------- reads

fn peer_dto(raw: &Value) -> Result<Value, Failure> {
    let object = raw.as_object().ok_or_else(|| server("Invalid address-book peer"))?;
    let id = object.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())
        .ok_or_else(|| server("Invalid address-book peer"))?;
    let mut peer = Map::new();
    peer.insert("id".into(), json!(id));
    peer.insert("alias".into(), json!(object.get("alias").and_then(Value::as_str).unwrap_or_default()));
    peer.insert("tags".into(), json!(tag_names(object.get("tags"))?));
    for key in ["hostname", "platform"] {
        if let Some(value) = object.get(key).and_then(Value::as_str).filter(|value| !value.is_empty()) {
            peer.insert(key.into(), json!(value));
        }
    }
    // hash / password / note and every other server field stay server-side.
    Ok(Value::Object(peer))
}

fn tag_names(raw: Option<&Value>) -> Result<Vec<String>, Failure> {
    match raw {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(tags)) => tags.iter().map(|tag| tag.as_str().map(str::to_owned)
            .ok_or_else(|| server("Invalid address-book tags"))).collect(),
        _ => Err(server("Invalid address-book tags")),
    }
}

fn project_peers(raw: Option<&Value>) -> Result<Vec<Value>, Failure> {
    match raw {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(peers)) => peers.iter().map(peer_dto).collect(),
        _ => Err(server("Invalid address-book peers")),
    }
}

pub(super) async fn list(client: &Client<'_>) -> Result<Value, Failure> {
    let (mode, books) = client.books().await?;
    // A missing modern endpoint alone is not a book. Establish that this server
    // actually implements the official legacy API before publishing its book.
    // load/mutate already do this GET for the data, and do not duplicate it.
    if matches!(mode, Mode::Legacy) { client.legacy_read().await?; }
    let books: Vec<Value> = books.iter().map(Book::with_capabilities).collect();
    Ok(json!({ "books": books }))
}

pub(super) async fn load(client: &Client<'_>, book_id: &str) -> Result<Value, Failure> {
    let (mode, book) = client.book(book_id).await?;
    let (peers, tags): (Vec<Value>, Vec<String>) = match &mode {
        Mode::Legacy => {
            let (inner, licensed) = client.legacy_read().await?;
            let mut peers = project_peers(inner.get("peers"))?;
            // `LegacyAb._deserialize`: a licensed-device limit truncates the list.
            if licensed > 0 && peers.len() as u64 > licensed { peers.truncate(licensed as usize); }
            (peers, tag_names(inner.get("tags"))?)
        }
        Mode::Cloud(_) => {
            let peers = client.cloud_peers(&book.id).await?.iter().map(peer_dto).collect::<Result<_, _>>()?;
            (peers, client.cloud_tags(&book.id).await?)
        }
    };
    Ok(json!({ "book": book.with_capabilities(), "peers": peers, "tags": tags }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_projection_drops_secrets() {
        let raw = json!({"id": "1", "alias": "a", "tags": ["t"], "hash": "H", "password": "P", "hostname": "h", "note": "n"});
        let dto = peer_dto(&raw).expect("peer");
        assert_eq!(dto, json!({"id": "1", "alias": "a", "tags": ["t"], "hostname": "h"}));
    }
}
