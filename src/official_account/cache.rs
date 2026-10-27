//! Official Ab/Group schema adapters only. Cloud synchronization remains in
//! Dart. Upstream Ab/Group::{store,load,remove} are intentionally never called:
//! they use public identity-derived keys and swallow persistence errors.

use super::{state, CacheKind};
use super::storage::{RecordKind, SecretBytes, MAX_CACHE_BYTES};
use hbb_common::{
    anyhow::{anyhow, ensure},
    config::{Ab, Group},
    serde_json,
    sodiumoxide::utils::memzero,
    ResultType,
};

fn record_kind(kind: CacheKind) -> RecordKind {
    match kind {
        CacheKind::AddressBook => RecordKind::AddressBook,
        CacheKind::Group => RecordKind::Group,
    }
}

/// These guards intentionally do not inherit the upstream models' Debug/Clone.
/// In particular, the personal address book's peer.hash and the bearer token
/// are erased along with the remaining owned model strings when we are done.
struct AddressBook(Ab);
struct DeviceGroup(Group);

enum Model {
    AddressBook(AddressBook),
    Group(DeviceGroup),
}

impl Model {
    fn parse(kind: CacheKind, json: &[u8]) -> ResultType<Self> {
        ensure!(json.len() <= MAX_CACHE_BYTES, "Account cache exceeds its size bound");
        // Keep exact selected hbb_common serde behavior, including the string
        // tag_colors field and upstream default handling for missing fields.
        // Do not expose parser diagnostics containing the source secret JSON.
        match kind {
            CacheKind::AddressBook => serde_json::from_slice::<Ab>(json)
                .map(|value| Self::AddressBook(AddressBook(value)))
                .map_err(|_| anyhow!("Invalid official address-book cache JSON")),
            CacheKind::Group => serde_json::from_slice::<Group>(json)
                .map(|value| Self::Group(DeviceGroup(value)))
                .map_err(|_| anyhow!("Invalid official group cache JSON")),
        }
    }

    fn empty(kind: CacheKind) -> Self {
        match kind {
            CacheKind::AddressBook => Self::AddressBook(AddressBook(Ab::default())),
            CacheKind::Group => Self::Group(DeviceGroup(Group::default())),
        }
    }

    fn token(&self) -> &[u8] {
        match self {
            Self::AddressBook(value) => value.0.access_token.as_bytes(),
            Self::Group(value) => value.0.access_token.as_bytes(),
        }
    }

    fn serialize(&self) -> ResultType<SecretBytes> {
        let result = match self {
            Self::AddressBook(value) => serde_json::to_string(&value.0),
            Self::Group(value) => serde_json::to_string(&value.0),
        }.map_err(|_| anyhow!("Official account cache serialization failed"))?;
        let result = SecretBytes::from_string(result);
        ensure!(result.bytes().len() <= MAX_CACHE_BYTES,
            "Serialized account cache exceeds its size bound");
        Ok(result)
    }
}

pub fn access_scoped(receipt: &str, kind: CacheKind, operation: &str,
    value: Option<String>) -> ResultType<String>
{
    let value = value.map(SecretBytes::from_string);
    match (operation, value) {
        ("save", Some(input)) => {
            ensure!(input.bytes().len() <= MAX_CACHE_BYTES, "Account cache exceeds its size bound");
            state::save_cache(receipt, record_kind(kind), |token| {
                let model = Model::parse(kind, input.bytes())?;
                ensure!(model.token() == token, "Account cache does not belong to the active account");
                model.serialize()
            })
        }
        ("load", None) => {
            let json = state::load_cache(receipt, record_kind(kind), |input, token| {
                let Some(input) = input else {
                    // Authenticated absence/clear or a deliberately absent
                    // session-only cache, never a read/decrypt/parse failure.
                    return Model::empty(kind).serialize();
                };
                let model = Model::parse(kind, input.bytes())?;
                ensure!(!token.is_empty() && model.token() == token,
                    "Stored account cache does not belong to the active account");
                model.serialize()
            })?;
            // State, receipt and lock release succeeded before the business
            // String crosses the native erasure boundary into FRB/Dart.
            Ok(json.into_string()?)
        }
        ("clear", None) => state::clear_cache(receipt, record_kind(kind)),
        _ => Err(anyhow!("Invalid scoped account cache operation or value")),
    }
}

fn wipe(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    memzero(&mut bytes);
}

impl Drop for AddressBook {
    fn drop(&mut self) {
        wipe(&mut self.0.access_token);
        for entry in &mut self.0.ab_entries {
            wipe(&mut entry.guid);
            wipe(&mut entry.name);
            wipe(&mut entry.tag_colors);
            for tag in &mut entry.tags { wipe(tag); }
            for peer in &mut entry.peers {
                wipe(&mut peer.id);
                wipe(&mut peer.hash);
                wipe(&mut peer.username);
                wipe(&mut peer.hostname);
                wipe(&mut peer.platform);
                wipe(&mut peer.alias);
                for tag in &mut peer.tags { wipe(tag); }
            }
        }
    }
}

impl Drop for DeviceGroup {
    fn drop(&mut self) {
        wipe(&mut self.0.access_token);
        for user in &mut self.0.users {
            wipe(&mut user.name);
            wipe(&mut user.display_name);
        }
        for peer in &mut self.0.peers {
            wipe(&mut peer.id);
            wipe(&mut peer.username);
            wipe(&mut peer.hostname);
            wipe(&mut peer.platform);
            wipe(&mut peer.login_name);
        }
        for group in &mut self.0.device_groups { wipe(&mut group.name); }
    }
}
