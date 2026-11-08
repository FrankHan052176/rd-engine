//! Closed set of address-book edits over the official endpoints (see cloud.rs):
//! `upsertPeer`, `deletePeer`, `upsertTag` (+`newName` = official tag rename) and
//! `deleteTag`. Nothing here accepts a URL, method, header or raw body from the
//! caller. Peer edits send only `id`, `alias` and `tags`; passwords, hashes and
//! every field the caller did not name are left to the server (new API) or are
//! re-sent byte-for-byte from the server's own document (legacy).
//!
//! * new API (personal + shared): `POST /api/ab/peer/add/<guid>`,
//!   `PUT /api/ab/peer/update/<guid>`, `DELETE /api/ab/peer/<guid>` (body `["id"]`),
//!   `POST /api/ab/tag/add/<guid>`, `PUT /api/ab/tag/rename/<guid>` (`{old,new}`),
//!   `DELETE /api/ab/tag/<guid>` (body `["name"]`) — `Ab.addPeers/changeAlias/
//!   changeTagForPeers/deletePeers/addTags/renameTag/deleteTag` in ab_model.dart.
//! * legacy: read-modify-write of `GET/POST /api/ab` — `LegacyAb` in ab_model.dart.

use super::{
    cloud::{invalid, sanitize, Client, Mode},
    service::{Code, Failure},
};
use hbb_common::{
    serde_json::{self, json, Map, Value},
    sha2::{Digest, Sha256},
};

const UNTAGGED: &str = "Untagged";
/// Official `str2color2` derives a colour from the tag name; this engine picks a
/// stable Material colour from a name hash, only when it creates a tag.
const TAG_COLORS: [u32; 8] = [
    0xFF2196F3, 0xFF4CAF50, 0xFFFF9800, 0xFFF44336, 0xFF9C27B0, 0xFF009688, 0xFF795548, 0xFF607D8B,
];

pub(super) enum Mutation {
    UpsertPeer { id: String, alias: String, tags: Vec<String> },
    DeletePeer { id: String },
    UpsertTag { name: String, new_name: Option<String> },
    DeleteTag { name: String },
}

fn clean_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}

pub(super) fn parse_mutation(json_text: &str) -> Result<Mutation, Failure> {
    if json_text.len() > 256 * 1024 {
        return Err(invalid("Mutation is too large"));
    }
    let value: Value = serde_json::from_str(json_text).map_err(|_| invalid("Mutation is not valid JSON"))?;
    let object = value.as_object().ok_or_else(|| invalid("Mutation must be an object"))?;
    let text = |key: &str, max: usize| -> Result<String, Failure> {
        let value = object.get(key).and_then(Value::as_str).ok_or_else(|| invalid("Mutation field is missing"))?;
        if !clean_text(value, max) {
            return Err(invalid("Mutation field is empty, too long or has control characters"));
        }
        Ok(value.to_owned())
    };
    let tag_name = |key: &str| -> Result<String, Failure> {
        let name = text(key, 128)?;
        if name == UNTAGGED { return Err(invalid("The reserved Untagged name cannot be edited")); }
        Ok(name)
    };
    match object.get("action").and_then(Value::as_str) {
        Some("upsertPeer") => {
            let peer = object.get("peer").and_then(Value::as_object)
                .ok_or_else(|| invalid("Mutation peer is missing"))?;
            let id = peer.get("id").and_then(Value::as_str).unwrap_or_default();
            if !clean_text(id, 128) {
                return Err(invalid("Peer id is empty, too long or has control characters"));
            }
            let alias = peer.get("alias").and_then(Value::as_str).unwrap_or_default();
            if alias.chars().count() > 256 || alias.chars().any(char::is_control) {
                return Err(invalid("Peer alias is too long or has control characters"));
            }
            let mut tags: Vec<String> = Vec::new();
            match peer.get("tags") {
                None | Some(Value::Null) => {}
                Some(Value::Array(items)) if items.len() <= 256 => {
                    for item in items {
                        let tag = item.as_str().filter(|tag| clean_text(tag, 128))
                            .ok_or_else(|| invalid("Peer tag is invalid"))?;
                        if !tags.iter().any(|existing| existing == tag) { tags.push(tag.to_owned()); }
                    }
                }
                _ => return Err(invalid("Peer tags must be an array of strings")),
            }
            Ok(Mutation::UpsertPeer { id: id.to_owned(), alias: alias.to_owned(), tags })
        }
        Some("deletePeer") => Ok(Mutation::DeletePeer { id: text("id", 128)? }),
        Some("upsertTag") => {
            let name = tag_name("name")?;
            let new_name = match object.get("newName") {
                None | Some(Value::Null) => None,
                Some(_) => Some(tag_name("newName")?),
            };
            Ok(Mutation::UpsertTag { name, new_name })
        }
        Some("deleteTag") => Ok(Mutation::DeleteTag { name: tag_name("name")? }),
        _ => Err(invalid("Unsupported address-book mutation action")),
    }
}

fn palette(name: &str) -> u32 {
    TAG_COLORS[Sha256::digest(name.as_bytes())[0] as usize % TAG_COLORS.len()]
}

pub(super) async fn mutate(client: &Client<'_>, book_id: &str, mutation: Mutation) -> Result<(), Failure> {
    let (mode, book) = client.book(book_id).await?;
    if !book.writable {
        return Err(Failure::new(Code::Forbidden, "This address book is read-only for the account"));
    }
    match mode {
        Mode::Legacy => legacy_mutate(client, &mutation).await,
        Mode::Cloud(_) => cloud_mutate(client, &book.id, &mutation).await,
    }
}

async fn cloud_mutate(client: &Client<'_>, guid: &str, mutation: &Mutation) -> Result<(), Failure> {
    match mutation {
        Mutation::UpsertPeer { id, alias, tags } => {
            let known = client.cloud_tags(guid).await?;
            if let Some(unknown) = tags.iter().find(|tag| !known.contains(tag)) {
                return Err(invalid(&format!("Unknown tag: {}", sanitize(unknown))));
            }
            let peers = client.cloud_peers(guid).await?;
            if peers.iter().any(|peer| peer.get("id").and_then(Value::as_str) == Some(id.as_str())) {
                // Field-level server update: only these fields change.
                client.action("put", &format!("/api/ab/peer/update/{guid}"),
                    json!({ "id": id, "alias": alias, "tags": tags })).await
            } else {
                let max = client.max_peers().await?;
                if max > 0 && peers.len() as u64 >= max {
                    return Err(Failure::new(Code::Conflict, "exceed_max_devices"));
                }
                client.action("post", &format!("/api/ab/peer/add/{guid}"),
                    json!({ "id": id, "alias": alias, "tags": tags })).await
            }
        }
        Mutation::DeletePeer { id } =>
            client.action("delete", &format!("/api/ab/peer/{guid}"), json!([id])).await,
        Mutation::UpsertTag { name, new_name } => {
            let known = client.cloud_tags(guid).await?;
            match new_name.as_ref().filter(|new_name| *new_name != name) {
                Some(new_name) => {
                    if !known.contains(name) { return Err(invalid("The tag does not exist")); }
                    if known.contains(new_name) { return Err(Failure::new(Code::Conflict, "Tag already exists")); }
                    client.action("put", &format!("/api/ab/tag/rename/{guid}"),
                        json!({ "old": name, "new": new_name })).await
                }
                None if new_name.is_some() || known.contains(name) => Ok(()),
                None => client.action("post", &format!("/api/ab/tag/add/{guid}"),
                    json!({ "name": name, "color": palette(name) })).await,
            }
        }
        Mutation::DeleteTag { name } =>
            client.action("delete", &format!("/api/ab/tag/{guid}"), json!([name])).await,
    }
}

/// Read-modify-write that touches only the addressed entries and re-sends every
/// other (including unknown) field exactly as the server returned it. There is no
/// server revision: a concurrent edit by another client in the window between
/// the GET and the POST is overwritten (the REST API offers no CAS to prevent it).
async fn legacy_mutate(client: &Client<'_>, mutation: &Mutation) -> Result<(), Failure> {
    let (mut inner, licensed) = client.legacy_read().await?;
    let object = inner.as_object_mut().ok_or_else(|| super::cloud::server("Invalid address-book data"))?;
    if apply_legacy(object, licensed, mutation)? {
        client.legacy_write(&inner).await
    } else {
        Ok(())
    }
}

fn data_error() -> Failure {
    super::cloud::server("Invalid address-book data")
}

fn legacy_array<'a>(object: &'a mut Map<String, Value>, key: &str) -> Result<&'a mut Vec<Value>, Failure> {
    object.entry(key.to_owned()).or_insert_with(|| json!([])).as_array_mut().ok_or_else(data_error)
}

fn legacy_tag_names(object: &mut Map<String, Value>) -> Result<Vec<String>, Failure> {
    Ok(legacy_array(object, "tags")?.iter().filter_map(Value::as_str).map(str::to_owned).collect())
}

fn legacy_colors(object: &Map<String, Value>) -> Result<Map<String, Value>, Failure> {
    match object.get("tag_colors") {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::String(text)) if text.is_empty() => Ok(Map::new()),
        Some(Value::String(text)) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(data_error()),
        },
        Some(Value::Object(map)) => Ok(map.clone()),
        _ => Err(data_error()),
    }
}

fn set_legacy_colors(object: &mut Map<String, Value>, colors: Map<String, Value>) -> Result<(), Failure> {
    // The official wire stores tag_colors as a JSON-encoded string.
    let text = serde_json::to_string(&Value::Object(colors)).map_err(|_| data_error())?;
    object.insert("tag_colors".to_owned(), Value::String(text));
    Ok(())
}

fn replace_tag(tags: &mut Vec<Value>, from: &str, to: &str) {
    for tag in tags.iter_mut() {
        if tag.as_str() == Some(from) { *tag = json!(to); }
    }
}

/// Returns whether the document changed (and so must be written back).
fn apply_legacy(object: &mut Map<String, Value>, licensed: u64, mutation: &Mutation) -> Result<bool, Failure> {
    match mutation {
        Mutation::UpsertPeer { id, alias, tags } => {
            let known = legacy_tag_names(object)?;
            if let Some(unknown) = tags.iter().find(|tag| !known.contains(tag)) {
                return Err(invalid(&format!("Unknown tag: {}", sanitize(unknown))));
            }
            let peers = legacy_array(object, "peers")?;
            if let Some(existing) = peers.iter_mut()
                .find(|peer| peer.get("id").and_then(Value::as_str) == Some(id.as_str()))
            {
                let existing = existing.as_object_mut().ok_or_else(data_error)?;
                existing.insert("alias".into(), json!(alias));
                existing.insert("tags".into(), json!(tags));
            } else {
                if licensed > 0 && peers.len() as u64 >= licensed {
                    return Err(Failure::new(Code::Conflict, "exceed_max_devices"));
                }
                peers.push(json!({ "id": id, "alias": alias, "tags": tags }));
            }
            Ok(true)
        }
        Mutation::DeletePeer { id } => {
            let peers = legacy_array(object, "peers")?;
            let before = peers.len();
            peers.retain(|peer| peer.get("id").and_then(Value::as_str) != Some(id.as_str()));
            Ok(peers.len() != before)
        }
        Mutation::UpsertTag { name, new_name } => {
            let known = legacy_tag_names(object)?;
            match new_name.as_ref().filter(|new_name| *new_name != name) {
                Some(new_name) => {
                    if !known.contains(name) { return Err(invalid("The tag does not exist")); }
                    if known.contains(new_name) { return Err(Failure::new(Code::Conflict, "Tag already exists")); }
                    replace_tag(legacy_array(object, "tags")?, name, new_name);
                    for peer in legacy_array(object, "peers")?.iter_mut() {
                        if let Some(Value::Array(peer_tags)) = peer.get_mut("tags") {
                            replace_tag(peer_tags, name, new_name);
                        }
                    }
                    let mut colors = legacy_colors(object)?;
                    if let Some(color) = colors.remove(name) { colors.insert(new_name.clone(), color); }
                    set_legacy_colors(object, colors)?;
                    Ok(true)
                }
                None if new_name.is_some() || known.contains(name) => Ok(false),
                None => {
                    legacy_array(object, "tags")?.push(json!(name));
                    let mut colors = legacy_colors(object)?;
                    colors.entry(name.clone()).or_insert_with(|| json!(palette(name)));
                    set_legacy_colors(object, colors)?;
                    Ok(true)
                }
            }
        }
        Mutation::DeleteTag { name } => {
            let mut changed = false;
            let tags = legacy_array(object, "tags")?;
            let before = tags.len();
            tags.retain(|tag| tag.as_str() != Some(name.as_str()));
            changed |= tags.len() != before;
            for peer in legacy_array(object, "peers")?.iter_mut() {
                if let Some(Value::Array(peer_tags)) = peer.get_mut("tags") {
                    let before = peer_tags.len();
                    peer_tags.retain(|tag| tag.as_str() != Some(name.as_str()));
                    changed |= peer_tags.len() != before;
                }
            }
            let mut colors = legacy_colors(object)?;
            if colors.remove(name).is_some() {
                set_legacy_colors(object, colors)?;
                changed = true;
            }
            Ok(changed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Map<String, Value> {
        json!({
            "tags": ["work", "home"],
            "peers": [
                {"id": "100", "alias": "a", "tags": ["work"], "hash": "SECRET-HASH", "username": "u", "future": 7},
                {"id": "200", "alias": "b", "tags": [], "hash": "H2"}
            ],
            "tag_colors": "{\"work\":1,\"home\":2}",
            "unknown_top": {"keep": true}
        }).as_object().cloned().expect("document")
    }

    #[test]
    fn legacy_peer_update_preserves_unedited_fields() {
        let mut document = document();
        let mutation = Mutation::UpsertPeer { id: "100".into(), alias: "renamed".into(), tags: vec!["home".into()] };
        assert!(apply_legacy(&mut document, 0, &mutation).expect("apply"));
        let peers = document["peers"].as_array().expect("peers");
        assert_eq!(peers[0]["alias"], "renamed");
        assert_eq!(peers[0]["tags"], json!(["home"]));
        assert_eq!(peers[0]["hash"], "SECRET-HASH");
        assert_eq!(peers[0]["username"], "u");
        assert_eq!(peers[0]["future"], 7);
        assert_eq!(peers[1]["hash"], "H2");
        assert_eq!(document["unknown_top"], json!({"keep": true}));
    }

    #[test]
    fn legacy_tag_rename_moves_peers_and_colour() {
        let mut document = document();
        let mutation = Mutation::UpsertTag { name: "work".into(), new_name: Some("job".into()) };
        assert!(apply_legacy(&mut document, 0, &mutation).expect("apply"));
        assert_eq!(document["tags"], json!(["job", "home"]));
        assert_eq!(document["peers"][0]["tags"], json!(["job"]));
        let colors: Value = serde_json::from_str(document["tag_colors"].as_str().expect("colors")).expect("json");
        assert_eq!(colors, json!({"job": 1, "home": 2}));
        assert_eq!(document["peers"][0]["hash"], "SECRET-HASH");
    }

    #[test]
    fn legacy_licensed_limit_and_unknown_tag_are_refused() {
        let mut document = document();
        let add = Mutation::UpsertPeer { id: "300".into(), alias: String::new(), tags: Vec::new() };
        assert_eq!(apply_legacy(&mut document, 2, &add).expect_err("full").code, Code::Conflict);
        let tagged = Mutation::UpsertPeer { id: "100".into(), alias: String::new(), tags: vec!["nope".into()] };
        assert_eq!(apply_legacy(&mut document, 0, &tagged).expect_err("unknown").code, Code::Invalid);
    }

    #[test]
    fn mutation_surface_is_closed() {
        assert!(parse_mutation(r#"{"action":"upsertPeer","peer":{"id":"1","alias":"x","tags":["t"]}}"#).is_ok());
        assert!(parse_mutation(r#"{"action":"deleteTag","name":"Untagged"}"#).is_err());
        assert!(parse_mutation(r#"{"action":"get","url":"https://x"}"#).is_err());
    }
}
