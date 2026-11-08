//! Single-Key server-profile admission for this HAR.
//!
//! Manual edits become routes only after a successful native commit. Targets,
//! handoffs, LAN claims and mutable Config options are never server/key sources.
//! The original client's Key is either a STANDARD-base64 32-byte Ed25519 public
//! key, or shared licence text. Only public keys are in profile JSON. Shared
//! text is resolved from the existing, route-bound Asset store at admission.
use super::server_credentials::{self, CredentialStore, LicenceKey};
use hbb_common::{
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{RELAY_PORT, RENDEZVOUS_PORT, RENDEZVOUS_SERVERS, RS_PUB_KEY},
    sodiumoxide::{crypto::sign, utils::memzero},
};
use napi_derive_ohos::napi;
use rd_engine::rendezvous::{endpoint, RendezvousConfig};
use serde_json::{json, Value};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_API_SERVER_BYTES: usize = 2048;
pub(super) const MAX_SAFE_REVISION: u64 = 9_007_199_254_740_991;
pub(super) const APPROVAL: &str = "manual-edit";

pub(super) fn accepted_approval(value: &Value) -> bool {
    matches!(value.get("approval").and_then(Value::as_str), Some("manual-edit" | "explicit-save"))
}

// No Debug: a candidate may own a secret.
pub(super) struct ServerProfile {
    mode: &'static str,
    id_server: String,
    relay_server: Option<String>,
    /// Empty means default or shared. Never arbitrary licence text.
    public_key: String,
    api_server: String,
    key_version: u64,
}

pub(super) enum KeyInput {
    Public(String),
    Shared(LicenceKey),
}

pub(super) enum KeyUpdate {
    Keep,
    /// Keep a protected, explicitly edited Key from this native draft revision.
    Draft(u64),
    Set(KeyInput),
    Clear,
}

impl KeyUpdate {
    pub(super) fn parse(value: &Value, mode: &str, draft: bool) -> Result<Self, String> {
        if value.get("relayKeyUpdate").is_some() || value.get("key").is_some() {
            return Err("use keyUpdate keep/set/clear; key is a read-only public projection".to_string());
        }
        let update = match value.get("keyUpdate") {
            None | Some(Value::Null) => KeyUpdate::Keep,
            Some(update) => {
                let action = update.get("action").and_then(Value::as_str)
                    .ok_or_else(|| "keyUpdate.action must be keep, set or clear".to_string())?;
                match (action, update.get("value")) {
                    ("keep", None | Some(Value::Null)) => match update.get("draftRevision") {
                        None | Some(Value::Null) => KeyUpdate::Keep,
                        Some(revision) => KeyUpdate::Draft(revision.as_u64()
                            .filter(|v| (1..=MAX_SAFE_REVISION).contains(v))
                            .ok_or_else(|| "draftRevision must be a positive safe integer".to_string())?),
                    },
                    ("clear", None | Some(Value::Null)) => KeyUpdate::Clear,
                    ("set", Some(Value::String(text))) => {
                        if mode != "custom" {
                            return Err("a Key can be set only for a custom server".to_string());
                        }
                        // Own and scrub the text even when validation fails.
                        let text = if draft { LicenceKey::draft(text.clone())? } else { LicenceKey::new(text.clone())? };
                        if public_signer(text.expose()).is_some() {
                            KeyUpdate::Set(KeyInput::Public(text.expose().to_owned()))
                        } else {
                            KeyUpdate::Set(KeyInput::Shared(text))
                        }
                    }
                    _ => return Err("keyUpdate needs keep/clear without value, or set with a nonempty string value".to_string()),
                }
            }
        };
        Ok(update)
    }

    pub(super) fn action(&self) -> &'static str {
        match self {
            Self::Keep | Self::Draft(_) => "keep",
            Self::Set(_) => "set",
            Self::Clear => "clear",
        }
    }
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value.get(name).and_then(Value::as_str)
        .ok_or_else(|| format!("server profile requires a string {name}"))
}

fn public_signer(text: &str) -> Option<sign::PublicKey> {
    STANDARD.decode(text.as_bytes()).ok()
        .and_then(|bytes| sign::PublicKey::from_slice(&bytes))
}

/// Syntax only. Account binding separately requires HTTPS for credentials.
pub(super) fn validate_api_server(value: &str) -> Result<String, String> {
    if value.len() > MAX_API_SERVER_BYTES {
        return Err("apiServer must be an http(s) URL such as https://api.example.com:21114".to_string());
    }
    rd_engine::official_account::service::validate_api_base(value)
        .map_err(|failure| failure.message)
}

impl ServerProfile {
    /// Saved/approved documents only. Legacy public-key-only profiles load
    /// unchanged. Legacy dual-Key profiles remain a visible conflict; neither
    /// credential is silently selected or removed.
    pub(super) fn parse(value: &Value) -> Result<Self, String> {
        let mut profile = Self::parse_route(value)?;
        if profile.mode == "custom" {
            profile.public_key = value.get("key").and_then(Value::as_str)
                .unwrap_or_default().to_owned();
            if !profile.public_key.is_empty() && public_signer(&profile.public_key).is_none() {
                return Err("a saved profile may contain only a public Key, not licence text".to_string());
            }
        }
        let version = value.get("keyVersion").or_else(|| value.get("relayKeyVersion"));
        profile.key_version = match version {
            None | Some(Value::Null) => 0,
            Some(version) => version.as_u64().filter(|v| *v <= MAX_SAFE_REVISION)
                .ok_or_else(|| "keyVersion must be a non-negative safe integer".to_string())?,
        };
        if profile.mode != "custom" && profile.key_version > 0 {
            return Err("a shared Key belongs only to a custom server profile".to_string());
        }
        if let Some(kind) = value.get("keyKind") {
            if kind.as_str() != Some(profile.key_kind()) {
                return Err("keyKind contradicts the saved Key fields".to_string());
            }
        }
        if let Some(configured) = value.get("keyConfigured") {
            if configured.as_bool() != Some(profile.key_configured()) {
                return Err("keyConfigured contradicts the saved Key fields".to_string());
            }
        }
        Ok(profile)
    }

    /// A single tri-state Key update. No secret ever occupies the public `key`
    /// field, and the old independent relayKeyUpdate grammar is refused.
    pub(super) fn parse_candidate(value: &Value) -> Result<(Self, KeyUpdate), String> {
        let profile = Self::parse_route(value)?;
        let update = KeyUpdate::parse(value, profile.mode, false)?;
        Ok((profile, update))
    }

    fn parse_route(value: &Value) -> Result<Self, String> {
        let (mode, id_server, relay_server) = match string_field(value, "mode")? {
            "official" => {
                let server = RENDEZVOUS_SERVERS.first()
                    .ok_or_else(|| "pinned official server is unavailable".to_string())?;
                ("official", endpoint(server, RENDEZVOUS_PORT as u16)
                    .map_err(|error| error.to_string())?, None)
            }
            "custom" => {
                let server = endpoint(string_field(value, "idServer")?, RENDEZVOUS_PORT as u16)
                    .map_err(|error| error.to_string())?;
                let relay = match value.get("relayServer") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(relay)) if relay.is_empty() => None,
                    Some(Value::String(relay)) => Some(endpoint(relay, RELAY_PORT as u16)
                        .map_err(|error| error.to_string())?),
                    Some(_) => return Err("relayServer must be a string".to_string()),
                };
                ("custom", server, relay)
            }
            _ => return Err("server profile mode must be official or custom".to_string()),
        };
        let api_server = match value.get("apiServer") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(api)) => validate_api_server(api)?,
            Some(_) => return Err("apiServer must be a string".to_string()),
        };
        if mode == "official" && !api_server.is_empty() {
            return Err("the official server profile has no custom apiServer".to_string());
        }
        Ok(Self { mode, id_server, relay_server, public_key: String::new(), api_server, key_version: 0 })
    }

    pub(super) fn key_kind(&self) -> &'static str {
        if self.mode == "official" { "official" }
        else if self.key_version > 0 && !self.public_key.is_empty() { "conflict" }
        else if self.key_version > 0 { "shared" }
        else if !self.public_key.is_empty() { "public" }
        else { "default" }
    }

    fn key_configured(&self) -> bool {
        self.key_version > 0 || !self.public_key.is_empty()
    }

    pub(super) fn normalized(&self) -> Value {
        json!({
            "mode": self.mode,
            "idServer": self.id_server,
            "relayServer": self.relay_server.as_deref().unwrap_or_default(),
            "key": self.public_key(),
            "apiServer": self.api_server,
            "keyKind": self.key_kind(),
            "keyConfigured": self.key_configured(),
            "keyVersion": self.key_version,
        })
    }

    pub(super) fn candidate_document(&self, update: &KeyUpdate) -> Value {
        let mut value = self.normalized();
        value["keyAction"] = json!(update.action());
        value["keyConfigured"] = match update {
            KeyUpdate::Set(_) => json!(true),
            KeyUpdate::Clear => json!(false),
            KeyUpdate::Keep | KeyUpdate::Draft(_) => Value::Null,
        };
        match update {
            KeyUpdate::Set(KeyInput::Public(key)) => {
                value["key"] = json!(key);
                value["keyKind"] = json!("public");
            }
            KeyUpdate::Set(KeyInput::Shared(_)) => value["keyKind"] = json!("shared"),
            _ => {}
        }
        value
    }

    pub(super) fn id_server(&self) -> &str { &self.id_server }
    pub(super) fn mode(&self) -> &'static str { self.mode }
    pub(super) fn api_server(&self) -> &str { &self.api_server }
    /// Account trust root projection; never a shared licence text.
    pub(super) fn public_key(&self) -> &str {
        if self.mode == "official" { RS_PUB_KEY } else { &self.public_key }
    }
    pub(super) fn relay_server(&self) -> Option<&str> { self.relay_server.as_deref() }
    pub(super) fn key_version(&self) -> u64 { self.key_version }

    pub(super) fn with_key(mut self, public: String, version: u64) -> Result<Self, String> {
        if self.mode != "custom" && (version > 0 || !public.is_empty()) {
            return Err("a Key belongs only to a custom server".to_string());
        }
        if version > 0 && !public.is_empty() {
            return Err("a profile cannot hold both a public and shared Key".to_string());
        }
        self.public_key = public;
        self.key_version = version;
        Ok(self)
    }

    /// Keep only the saved credential, never move shared text to another route.
    pub(super) fn keep_key(mut self, saved: &Self) -> Result<Self, String> {
        if saved.key_kind() == "conflict" {
            return Err("the old profile contains two Keys; enter one Key or clear it to resolve the conflict".to_string());
        }
        if self.mode == "official" { return Ok(self); }
        if saved.key_version > 0 && !self.same_route(saved) {
            return Err("the saved Key is bound to another server; enter the Key again or clear it".to_string());
        }
        if saved.mode == "custom" {
            self.public_key = saved.public_key.clone();
            self.key_version = saved.key_version;
        }
        Ok(self)
    }

    pub(super) fn key_binding(&self) -> [u8; 32] {
        // Keep the Asset alias/record format. New single-Key secrets have no
        // simultaneous public key in the binding; legacy dual-Key records are
        // retained but unusable until the operator explicitly resolves them.
        server_credentials::binding(self.mode, &self.id_server,
            self.relay_server.as_deref().unwrap_or_default(), &self.public_key)
    }
    pub(super) fn same_route(&self, other: &Self) -> bool {
        self.mode == other.mode && self.id_server == other.id_server && self.relay_server == other.relay_server
    }
}

/// Owned at registration; start/password retry never reads an editable profile.
pub(super) struct ApprovedRoute {
    id: String,
    revision: u64,
    profile: ServerProfile,
    shared_key: Option<LicenceKey>,
    signer: Option<sign::PublicKey>,
}

impl ApprovedRoute {
    pub(super) fn parse(id: &str, value: Option<&Value>) -> Result<Self, String> {
        Self::parse_with(id, value, &server_credentials::system())
    }

    pub(super) fn parse_with(id: &str, value: Option<&Value>, store: &impl CredentialStore) -> Result<Self, String> {
        let value = value.ok_or_else(|| "RustDesk ID routing requires a committed server profile".to_string())?;
        if value.get("schemaVersion").and_then(Value::as_u64) != Some(2)
            || !accepted_approval(value)
            || !value.get("revision").and_then(Value::as_u64)
                .is_some_and(|revision| (1..=MAX_SAFE_REVISION).contains(&revision))
        {
            return Err("server profile requires v2 manual-edit provenance and a positive safe revision".to_string());
        }
        let id = id.trim();
        if id.is_empty() || id.len() > 512 { return Err("invalid RustDesk peer ID".to_string()); }
        let profile = ServerProfile::parse(value)?;
        if profile.key_kind() == "conflict" {
            return Err("the old profile contains two Keys; enter one Key or clear it in server settings".to_string());
        }
        let shared_key = match profile.key_version {
            0 => None,
            version => Some(server_credentials::get(store, version, &profile.key_binding())?),
        };
        let signer = if shared_key.is_some() { None } else {
            let public = if profile.public_key.is_empty() { RS_PUB_KEY } else { &profile.public_key };
            Some(public_signer(public).ok_or_else(|| "the configured public Key is invalid".to_string())?)
        };
        let revision = value.get("revision").and_then(Value::as_u64)
            .ok_or_else(|| "the approved profile revision is missing".to_string())?;
        Ok(Self { id: id.to_owned(), revision, profile, shared_key, signer })
    }

    pub(super) fn id(&self) -> &str { &self.id }
    pub(super) fn revision(&self) -> u64 { self.revision }
    pub(super) fn is_shared(&self) -> bool { self.shared_key.is_some() }

    fn licence(&self) -> &str {
        match &self.shared_key {
            Some(key) => key.expose(),
            None if self.profile.public_key.is_empty() => RS_PUB_KEY,
            None => &self.profile.public_key,
        }
    }

    pub(super) fn configuration(&self) -> RendezvousConfig {
        RendezvousConfig {
            id: self.id.clone(),
            rendezvous_server: self.profile.id_server.clone(),
            licence_key: self.licence().to_owned(),
            // Only the custom shared-Key kind has no trust root. A public-key
            // or official/default route cannot opt into legacy compatibility.
            server_key: self.signer,
            relay_server: self.profile.relay_server.clone(),
            connect_timeout: CONNECT_TIMEOUT,
        }
    }

}

/// Syntax only; no persistence, network, or secret echo.
#[napi]
pub fn validate_server_profile(mut profile_json: String) -> String {
    let parsed = serde_json::from_str::<Value>(&profile_json)
        .map_err(|_| "server profile must be a JSON object".to_string())
        .and_then(|value| ServerProfile::parse_candidate(&value));
    memzero(unsafe { profile_json.as_bytes_mut() });
    match parsed {
        Ok((profile, update)) => json!({ "ok": true, "normalizedProfile": profile.candidate_document(&update) }).to_string(),
        Err(error) => json!({ "ok": false, "error": error }).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_credentials::tests::Memory;
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const SECRET: &str = "shared-secret";

    fn custom(update: Value) -> Value {
        json!({ "mode": "custom", "idServer": "hbbs.example", "relayServer": "hbbr.example", "keyUpdate": update })
    }
    fn approved(profile: &ServerProfile) -> Value {
        let mut value = profile.normalized();
        value["schemaVersion"] = json!(2);
        value["approval"] = json!(APPROVAL);
        value["revision"] = json!(3);
        value
    }

    #[test]
    fn candidate_key_is_classified_without_echoing_shared_text() {
        assert!(matches!(ServerProfile::parse_candidate(&custom(json!({"action":"set","value":KEY}))).unwrap().1,
            KeyUpdate::Set(KeyInput::Public(_))));
        let value = custom(json!({"action":"set","value":SECRET}));
        let (profile, update) = ServerProfile::parse_candidate(&value).unwrap();
        assert!(matches!(&update, KeyUpdate::Set(KeyInput::Shared(_))));
        assert!(!profile.candidate_document(&update).to_string().contains(SECRET));
        assert!(!validate_server_profile(value.to_string()).contains(SECRET));
    }

    #[test]
    fn approved_shared_key_is_resolved_for_its_route_and_has_no_trust_root() {
        let store = Memory::default();
        let profile = ServerProfile::parse_candidate(&custom(json!({"action":"keep"}))).unwrap().0;
        server_credentials::put(&store, 3, &profile.key_binding(), &LicenceKey::new(SECRET.into()).unwrap()).unwrap();
        let profile = profile.with_key(String::new(), 3).unwrap();
        let document = approved(&profile);
        let route = ApprovedRoute::parse_with("123456789", Some(&document), &store).unwrap();
        assert_eq!(route.configuration().licence_key, SECRET);
        assert!(route.configuration().server_key.is_none());
        assert!(route.is_shared());
        let mut forged = document.clone();
        forged["idServer"] = json!("other.example:21116");
        assert!(ApprovedRoute::parse_with("123456789", Some(&forged), &store).is_err());
        assert!(!document.to_string().contains(SECRET));
    }

    #[test]
    fn legacy_public_profiles_remain_strict_and_dual_keys_are_an_explicit_conflict() {
        let mut value = json!({"mode":"custom", "idServer":"hbbs.example", "key":KEY});
        let profile = ServerProfile::parse(&value).unwrap();
        let route = ApprovedRoute::parse_with("123456789", Some(&approved(&profile)), &Memory::default()).unwrap();
        assert_eq!(route.configuration().licence_key, KEY);
        assert!(route.configuration().server_key.is_some());
        value["relayKeyVersion"] = json!(7);
        let conflict = ServerProfile::parse(&value).unwrap();
        assert_eq!(conflict.key_kind(), "conflict");
        assert!(ApprovedRoute::parse_with("123456789", Some(&approved(&conflict)), &Memory::default()).is_err());
    }
}
