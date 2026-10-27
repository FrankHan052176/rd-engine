//! Pure, explicit-save server-profile admission for this HAR only.
//!
//! The controlled Resk store supplies approval; JSON syntax cannot prove a
//! Preferences flush. Targets, handoffs, LAN claims and mutable Config options
//! are never server/key sources. No Config, DNS, socket or persistence calls.
use hbb_common::{
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{RELAY_PORT, RENDEZVOUS_PORT, RENDEZVOUS_SERVERS, RS_PUB_KEY},
    sodiumoxide::crypto::sign,
};
use napi_derive_ohos::napi;
use rd_engine::rendezvous::{endpoint, RendezvousConfig};
use serde_json::{json, Value};
use std::time::Duration;

const MAX_SAFE_REVISION: u64 = 9_007_199_254_740_991;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// Deliberately no Debug: preserve the original wire key without logging it.
struct ServerProfile {
    mode: &'static str,
    id_server: String,
    relay_server: Option<String>,
    wire_key: String,
    signer: sign::PublicKey,
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("server profile requires a string {name}"))
}

impl ServerProfile {
    fn parse(value: &Value) -> Result<Self, String> {
        let (mode, id_server, relay_server, wire_key) = match string_field(value, "mode")? {
            "official" => {
                // Same pinned PUBLIC_SERVER branch as official client.rs. Do
                // not call Config::get_rendezvous_server(s): those are mutable.
                let server = RENDEZVOUS_SERVERS
                    .first()
                    .ok_or_else(|| "pinned official server is unavailable".to_string())?;
                (
                    "official",
                    endpoint(server, RENDEZVOUS_PORT as u16).map_err(|error| error.to_string())?,
                    None,
                    RS_PUB_KEY.to_owned(),
                )
            }
            "custom" => {
                let server = endpoint(string_field(value, "idServer")?, RENDEZVOUS_PORT as u16)
                    .map_err(|error| error.to_string())?;
                let relay = match value.get("relayServer") {
                    None => None,
                    Some(Value::String(relay)) if relay.is_empty() => None,
                    Some(Value::String(relay)) => Some(
                        endpoint(relay, RELAY_PORT as u16).map_err(|error| error.to_string())?,
                    ),
                    Some(_) => return Err("relayServer must be a string".to_string()),
                };
                (
                    "custom",
                    server,
                    relay,
                    string_field(value, "key")?.to_owned(),
                )
            }
            _ => return Err("server profile mode must be official or custom".to_string()),
        };
        if wire_key.is_empty()
            || wire_key.len() > 1024
            || wire_key
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err("server profile requires an explicit base64 public key".to_string());
        }
        let decoded = STANDARD
            .decode(wire_key.as_bytes())
            .map_err(|_| "server public key is not STANDARD base64".to_string())?;
        let signer = sign::PublicKey::from_slice(&decoded)
            .ok_or_else(|| "server public key must decode to 32 Ed25519 bytes".to_string())?;
        Ok(Self {
            mode,
            id_server,
            relay_server,
            wire_key,
            signer,
        })
    }

    fn normalized(&self) -> Value {
        json!({
            "mode": self.mode,
            "idServer": self.id_server,
            "relayServer": self.relay_server.as_deref().unwrap_or_default(),
            "key": self.wire_key,
        })
    }
}

/// Owned at session registration; neither start nor a password retry reads an
/// editable profile or a global server setting. No alternate router is added.
pub(super) struct ApprovedRoute {
    id: String,
    profile: ServerProfile,
}

impl ApprovedRoute {
    pub(super) fn parse(id: &str, value: Option<&Value>) -> Result<Self, String> {
        let value = value.ok_or_else(|| {
            "RustDesk ID routing requires an explicitly saved server profile".to_string()
        })?;
        if value.get("schemaVersion").and_then(Value::as_u64) != Some(2)
            || value.get("approval").and_then(Value::as_str) != Some("explicit-save")
            || !value
                .get("revision")
                .and_then(Value::as_u64)
                .is_some_and(|revision| (1..=MAX_SAFE_REVISION).contains(&revision))
        {
            return Err(
                "server profile requires v2 explicit-save approval and a positive safe revision"
                    .to_string(),
            );
        }
        let id = id.trim();
        if id.is_empty() || id.len() > 512 {
            return Err("invalid RustDesk peer ID".to_string());
        }
        Ok(Self {
            id: id.to_owned(),
            profile: ServerProfile::parse(value)?,
        })
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn configuration(&self) -> RendezvousConfig {
        RendezvousConfig {
            id: self.id.clone(),
            rendezvous_server: self.profile.id_server.clone(),
            licence_key: self.profile.wire_key.clone(),
            server_key: self.profile.signer,
            relay_server: self.profile.relay_server.clone(),
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

/// Syntax/key validation only. This does not approve, save or test a server.
#[napi]
pub fn validate_server_profile(profile_json: String) -> String {
    let parsed = serde_json::from_str::<Value>(&profile_json)
        .map_err(|_| "server profile must be a JSON object".to_string())
        .and_then(|value| ServerProfile::parse(&value));
    match parsed {
        Ok(profile) => json!({ "ok": true, "normalizedProfile": profile.normalized() }).to_string(),
        Err(error) => json!({ "ok": false, "error": error }).to_string(),
    }
}
