//! The client's configuration store, read through the credential boundary.
//!
//! Pinned hbb_common owns ordinary client configuration and peer records. The
//! engine's official-account owner alone stores account token/user metadata;
//! only the dedicated local-option branches may access that protected state.
//! The remaining adaptation below follows the pinned official revision
//! (092a961b629d318fe290eeafac0cd214a1e9deeb, AGPL-3.0-only), with credentials
//! removed from generic settings and peer exports.
//!
//! * the peer-list shape: `peer_to_map` (`src/ui_interface.rs:786`);
//! * the recent-peer enumeration and its consumers: `load_recent_peers`,
//!   `main_load_recent_peers`, `main_load_recent_peers_for_ab` and
//!   `main_load_fav_peers` (`src/flutter_ffi.rs:1414-1560`);
//! * which stored peer values are credentials: `PeerConfig::load` /
//!   `PeerConfig::store_` (`hbb_common/src/config.rs:1716,1751`, pin
//!   cd80a9990224bc0f307b0c7da05d67e65f3865d9), which decrypt `rdp_password`,
//!   `os-username` and `os-password` out of `options` and keep the peer
//!   `password` field beside them.
//!
//! The consumer of both shapes is the official Dart: `Peer.fromJson`
//! (`flutter/lib/models/peer_model.dart:33`), `_updatePeers`/`_decodePeers`
//! (`:249-289`, which replaces the peer cards with the `peers` field of the
//! event) and the address-book sync (`flutter/lib/models/ab_model.dart:548`).
//!
//! Two deliberate deviations from upstream, both recorded here because they
//! change what a consumer sees:
//!
//! * Upstream's `PeerConfig::batch_peers` drops every record whose
//!   `info.platform` is empty and deletes that peer's file
//!   (`hbb_common/src/config.rs:1908`). In this bridge the only writer of peer
//!   records is the client's own settings API - nothing here saves peer info
//!   while connecting - so upstream's filter would hide exactly the records the
//!   client created, which is the opposite of the list the audit asked for. A
//!   record's file is the client's record for that id, and a list call must not
//!   delete one, so the enumeration below keeps them.
//! The official favourite-list branch also supplements stored peer records with
//! observed LAN metadata. The bridge supplies that snapshot through the shared
//! LAN owner's serialized query; no discovery value becomes a credential.
//!
//! The list itself is one JSON array, which is the shape the client's
//! `_decodePeers` parses. Upstream's Windows two-round load splits that array
//! and sends the remaining ids in an `ids` field
//! (`src/flutter_ffi.rs:1452-1474`); the event this bridge builds carries no
//! `ids`, which is the same shape upstream sends wherever it loads in one round
//! (`main_load_recent_peers` without `load_two_times`).

use anyhow::{anyhow, Result};
use hbb_common::config::{LocalConfig, PeerConfig, PeerInfoSerde};
use hbb_common::log;
use hbb_common::sodiumoxide::utils;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// The credential keys
// ---------------------------------------------------------------------------

/// The settings whose values are credential material, matched by the exact key
/// the client uses for each of them.
///
/// Peer-record credentials, the set the pinned store states for itself:
/// `PeerConfig::load` and `PeerConfig::store_` decrypt and re-encrypt the
/// `rdp_password`, `os-username` and `os-password` options
/// (hbb_common/src/config.rs:1726,1760), and the peer `password` is a field of
/// the record rather than an option. `password` is also the key the official
/// client writes to forget a memorised peer password
/// (`flutter/lib/web/bridge.dart:1016`) and the key hbb_common reads its own
/// host credential from (`HARD_SETTINGS`, `hbb_common/src/config.rs:1428`), so
/// one name covers the peer store and the shared store both.
///
/// Account token and metadata belong to the dedicated protected account owner.
/// The official Dart local-option accessors are its authorized interface, but
/// these keys remain refused/redacted in ordinary, batch, peer, session and
/// Flutter option APIs. In particular, never remove access_token from this
/// classification merely to enable the authorized account branch.
///
/// Matching is exact and never by substring: the client's own settings include
/// keys that merely mention a password - `allow-deep-link-password`,
/// `remove-preset-password-warning`, `disable-change-permanent-password`,
/// `allow-numeric-one-time-password` (`flutter/lib/consts.dart:133,207,209,215`)
/// - and those are switches the settings page keeps reading and writing.
///
/// `rdp_username` is deliberately absent: the pinned store does not encrypt it,
/// it is not in the set above, and the client's RDP dialog reads it back as the
/// pre-filled user name of a connection it may still configure
/// (`flutter/lib/common/widgets/peer_card.dart:1353`). Refusing it would break a
/// setting that is not a secret. Credentials that are refused by their own entry
/// rather than by a config key - the local unlock pin (`main_set_unlock_pin`),
/// proxy credentials (`main_set_socks`) and the host's permanent password
/// (`main_set_permanent_password_with_result`) - are not keys, so they are not
/// here either.
const CREDENTIAL_KEYS: [&str; 6] = [
    "password",
    "rdp_password",
    "os-password",
    "os-username",
    "access_token",
    "user_info",
];

/// Is `key` one of the settings that carry credential material?
///
/// Generic setting APIs ask this before reading, writing or serializing values.
/// Account local-option branches explicitly route their two keys to the engine
/// owner first; all other credential access remains refused or redacted.
pub fn is_credential_key(key: &str) -> bool {
    CREDENTIAL_KEYS.contains(&key)
}

/// The keys that rule covers, for a caller applying it to a whole map instead
/// of to one key: a batch read is redacted with them and a batch write is
/// refused at them.
pub fn credential_keys() -> &'static [&'static str] {
    &CREDENTIAL_KEYS
}

/// Drop every credential from an option map, wiping each plaintext as it goes.
///
/// The removed value is exactly the one a serializer would hand out, so it is
/// overwritten rather than merely dropped, the same way `strip_credentials`
/// treats the fields the pinned store decrypts while loading a peer.
pub fn strip_credential_options(options: &mut HashMap<String, String>) {
    for key in CREDENTIAL_KEYS {
        if let Some(value) = options.remove(key) {
            wipe(value);
        }
    }
}

/// Overwrite a plaintext secret's own bytes, then let its buffer be freed.
///
/// `utils::memzero` is libsodium's `sodium_memzero`, so the overwrite is not
/// something an optimizer may drop. Removing a credential from a map hands the
/// plaintext to the caller - which is what would otherwise be serialized - so it
/// is wiped here rather than dropped as is.
fn wipe(secret: String) {
    let mut bytes = secret.into_bytes();
    utils::memzero(&mut bytes);
}

/// Remove every credential the store decrypts on load, wiping the plaintext.
///
/// `PeerConfig::load` hands out the decrypted `password`, `rdp_password`,
/// `os-username` and `os-password`. No caller of this module may publish them,
/// so they are wiped as soon as the record is loaded: the plaintext exists only
/// between the load and this call.
///
/// `ui_flutter` is swept with the same keys as `options`: the client writes both
/// maps with the peer's own key names, and neither map has a key this bridge is
/// allowed to hand back once it holds a credential.
fn strip_credentials(config: &mut PeerConfig) {
    let mut password = std::mem::take(&mut config.password);
    utils::memzero(&mut password);
    for key in CREDENTIAL_KEYS {
        if let Some(secret) = config.options.remove(key) {
            wipe(secret);
        }
        if let Some(secret) = config.ui_flutter.remove(key) {
            wipe(secret);
        }
    }
}

// ---------------------------------------------------------------------------
// One peer's stored configuration
// ---------------------------------------------------------------------------

/// A peer's stored configuration as JSON, with every credential removed.
///
/// The client asks for this to render a peer, never to authenticate it:
/// `getDesktopTabLabel` reads `info.hostname` out of it
/// (`flutter/lib/common.dart:3303`) and the port-forward page reads
/// `port_forwards` (`flutter/lib/desktop/pages/port_forward_page.dart:286`).
/// Upstream's entry is `main_get_peer_sync` (`src/flutter_ffi.rs:1110`) over
/// `get_peer` = `PeerConfig::load` (`src/ui_interface.rs:666`): the same JSON
/// of the same type, handed out with the peer password in it. This bridge loads
/// that field only to wipe it, and a record that does not exist or cannot be
/// read answers with the store's defaults, because `PeerConfig::load` is what
/// decides that and the client expects defaults for a peer it has no settings
/// for.
///
/// An error here is a serialization failure only, and it names no value: a peer
/// id identifies a machine, not a secret.
pub fn sanitized_peer_json(id: &str) -> Result<String> {
    let mut config = PeerConfig::load(id);
    strip_credentials(&mut config);
    serde_json::to_string(&config)
        .map_err(|error| anyhow!("peer config {id} could not be serialized: {error}"))
}

// ---------------------------------------------------------------------------
// The lists the client asks for
// ---------------------------------------------------------------------------

/// The stored peers, most recently used first, limited to `id_filter` if given.
///
/// Ordering, id decoding (a `base64_` file name for an id with characters a file
/// name cannot hold) and the id filter are the pinned store's own
/// `PeerConfig::get_vec_id_modified_time_path` (hbb_common/src/config.rs:1800,
/// newest first), which is the enumeration upstream's `load_recent_peers` reads
/// through `PeerConfig::batch_peers`. Loading each record is what that function
/// does too; the difference is only that this one neither deletes a record with
/// no peer info nor drops it from the list (see the module documentation).
fn stored_peers(id_filter: Option<Vec<String>>) -> Vec<(String, PeerConfig)> {
    PeerConfig::get_vec_id_modified_time_path(&id_filter)
        .into_iter()
        .map(|(id, _, _)| {
            let mut config = PeerConfig::load(&id);
            strip_credentials(&mut config);
            (id, config)
        })
        .collect()
}

/// One peer in the shape the client's own core publishes.
///
/// The keys are upstream's `peer_to_map` (`src/ui_interface.rs:786`), one value
/// changed: upstream sends the peer's remembered password as `hash`, and this
/// bridge has no credential to share, so the key is present and empty. An empty
/// `hash` is the value the client already handles for a peer without one -
/// `Peer.fromJson` defaults it to `''`
/// (`flutter/lib/models/peer_model.dart:35`) and the address book skips an empty
/// hash (`flutter/lib/models/peer_card.dart:1182`) - so the shape stays the one
/// the consumer parses while no secret leaves the process.
///
/// Upstream sends no other field, in particular no `password` and no
/// `forceAlwaysRelay`: the client fetches the relay setting separately
/// (`flutter/lib/common/widgets/peer_card.dart:732`).
fn peer_map(id: String, config: &PeerConfig) -> HashMap<&'static str, String> {
    HashMap::from([
        ("id", id),
        ("username", config.info.username.clone()),
        ("hostname", config.info.hostname.clone()),
        ("platform", config.info.platform.clone()),
        (
            "alias",
            config.options.get("alias").cloned().unwrap_or_default(),
        ),
        ("hash", String::new()),
    ])
}

/// The peers of one filtered enumeration, as the JSON array the client parses.
///
/// Both list entries below publish this one array - the peer cards of the recent
/// and favourite views, and the address book's recent sync - so the field
/// mapping and the shape a consumer sees cannot drift apart. An empty
/// enumeration is `[]`, which is what the client's `_decodePeers` turns into an
/// empty list (`flutter/lib/models/peer_model.dart:278`); it is never `""`.
fn peer_list_json(id_filter: Option<Vec<String>>) -> Result<String> {
    let peers: Vec<HashMap<&'static str, String>> = stored_peers(id_filter)
        .into_iter()
        .map(|(id, config)| peer_map(id, &config))
        .collect();
    serde_json::to_string(&peers)
        .map_err(|error| anyhow!("peer list could not be serialized: {error}"))
}

/// Stored recent peers, in the same one-round list shape as the official client.
pub fn recent_peers_json() -> Result<String> {
    peer_list_json(None)
}

/// Pinned `main_load_fav_peers`: supplement favourites missing a stored peer
/// record with the official LAN cache's metadata. Match against the original
/// recent set, not earlier LAN rows: upstream permits id/username variants.
/// LAN-only supplement rows carry a boolean ID-only intent, not authentication.
pub fn favorite_peers_json(mut discovered: Vec<HashMap<&'static str, String>>) -> Result<String> {
    let favorites = LocalConfig::get_fav();
    let recent = stored_peers(Some(favorites.clone()));
    let lan: Vec<_> = discovered
        .drain(..)
        .filter(|peer| {
            peer.get("id").is_some_and(|id| {
                favorites.contains(id) && recent.iter().all(|record| &record.0 != id)
            })
        })
        .map(|mut peer| {
            (
                peer.remove("id").unwrap_or_default(),
                PeerConfig {
                    info: PeerInfoSerde {
                        username: peer.remove("username").unwrap_or_default(),
                        hostname: peer.remove("hostname").unwrap_or_default(),
                        platform: peer.remove("platform").unwrap_or_default(),
                    },
                    ..Default::default()
                },
            )
        })
        .collect();
    let peers: Vec<_> = recent
        .into_iter()
        .map(|(id, config)| serde_json::json!(peer_map(id, &config)))
        .chain(lan.into_iter().map(|(id, config)| {
            let mut peer = serde_json::json!(peer_map(id, &config));
            peer["rustdeskIdOnly"] = serde_json::Value::Bool(true);
            peer
        }))
        .collect();
    serde_json::to_string(&peers)
        .map_err(|error| anyhow!("favourite list could not be serialized: {error}"))
}

/// The stored peers for the address book, limited to the ids the caller asks for.
///
/// Upstream's contract, kept as it is (`src/flutter_ffi.rs:1486`): the filter is
/// a JSON array of peer ids, and an unreadable or empty filter means "no id
/// filter" rather than "no peers" - it is what the client sends when it syncs
/// the whole recent list at once (`flutter/lib/models/ab_model.dart:548-562`).
/// A filter that names ids answers with those records only, most recent first.
pub fn recent_peers_for_ab(filter: &str) -> Result<String> {
    let ids: Vec<String> = match serde_json::from_str(filter) {
        Ok(ids) => ids,
        Err(error) => {
            // Upstream ignores an unreadable filter the same way; it is logged
            // because a client that meant to filter and did not is worth seeing.
            log::debug!(
                "recent_peers_for_ab: filter is not a list of ids ({error}), using all peers"
            );
            Vec::new()
        }
    };
    let id_filter = if ids.is_empty() { None } else { Some(ids) };
    peer_list_json(id_filter)
}
