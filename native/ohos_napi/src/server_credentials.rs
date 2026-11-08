//! Protected storage of a shared licence Key: the single Key of a custom server
//! profile when its text is not a public key (the original client's `key`
//! option used as a licence for hbbs and hbbr alike).
//!
//! The key is a secret. It lives only in the HarmonyOS Asset Store, in its own
//! alias space (`rd-engine.server-credential.v1.<version>`), separate from the
//! engine identity and from the official-account master key, so signing out of
//! an account never touches it. There is deliberately no plaintext file,
//! Preferences, Config option or any other fallback: a locked or unavailable
//! store is a real error, never a reason to keep the secret somewhere weaker.
//!
//! A record is addressed by an opaque safe-integer identifier (legacy records
//! used save revisions) and carries a digest that binds it to the exact server route it was
//! approved for (mode, hbbs endpoint, hbbr endpoint; the public-key part is
//! empty because a shared Key profile has none). A reader
//! checks the binding, so a profile that names another route can never obtain
//! this secret. Versions are only added and removed, never overwritten: the
//! caller adds the new version, commits its profile, then removes the old one.
use hbb_common::sodiumoxide::{crypto::hash::sha256, utils::memzero};

const MAGIC: &[u8; 5] = b"RDRK1";
const BINDING_BYTES: usize = 32;
const MAX_KEY_BYTES: usize = 1024;
const MAX_DRAFT_KEY_BYTES: usize = 8 * 1024;
const DOMAIN: &[u8] = b"rd-engine/server-credential/binding/v1\0";
const ALIAS_PREFIX: &str = "rd-engine.server-credential.v1.";

/// A shared Key held in memory. No Debug/Clone; zeroed on drop. Copies made by
/// the NAPI string transport or by `RendezvousConfig` are outside this owner's
/// erasure control.
pub(super) struct LicenceKey(String);

impl LicenceKey {
    pub(super) fn new(value: String) -> Result<Self, String> {
        let key = Self(value);
        if key.0.is_empty()
            || key.0.len() > MAX_KEY_BYTES
            || key.0.chars().any(char::is_control)
        {
            return Err(
                "the Key must be 1..=1024 bytes without control characters"
                    .to_string(),
            );
        }
        Ok(key)
    }

    /// Incomplete editor text is protected too, but is never wire-admitted here.
    pub(super) fn draft(value: String) -> Result<Self, String> {
        let key = Self(value);
        if key.0.is_empty() || key.0.len() > MAX_DRAFT_KEY_BYTES {
            return Err("the draft Key must be 1..=8192 bytes".to_string());
        }
        Ok(key)
    }

    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for LicenceKey {
    fn drop(&mut self) {
        // Zero bytes are valid UTF-8, so the string stays well formed.
        memzero(unsafe { self.0.as_bytes_mut() });
    }
}

/// The route a stored key is approved for. Built from the normalized profile
/// fields, never from caller-supplied references.
pub(super) fn binding(
    mode: &str,
    id_server: &str,
    relay_server: &str,
    hbbs_key: &str,
) -> [u8; BINDING_BYTES] {
    let mut input = Vec::from(DOMAIN);
    for part in [mode, id_server, relay_server, hbbs_key] {
        input.extend_from_slice(&(part.len() as u32).to_le_bytes());
        input.extend_from_slice(part.as_bytes());
    }
    sha256::hash(&input).0
}

fn alias(version: u64) -> String {
    format!("{ALIAS_PREFIX}{version}")
}

fn encode(binding: &[u8; BINDING_BYTES], key: &LicenceKey) -> Vec<u8> {
    let mut record = Vec::with_capacity(MAGIC.len() + BINDING_BYTES + key.0.len());
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(binding);
    record.extend_from_slice(key.0.as_bytes());
    record
}

/// The system store, as three operations. `add` returns `Ok(false)` when the
/// alias already exists; nothing overwrites.
pub(super) trait CredentialStore {
    fn add(&self, alias: &str, secret: &[u8]) -> Result<bool, String>;
    fn query(&self, alias: &str) -> Result<Option<Vec<u8>>, String>;
    fn remove(&self, alias: &str) -> Result<(), String>;
}

/// Adds a fresh opaque identifier. Never overwrite even on an identifier
/// collision: effective and draft records use the same protected store.
pub(super) fn put(
    store: &impl CredentialStore,
    version: u64,
    binding: &[u8; BINDING_BYTES],
    key: &LicenceKey,
) -> Result<(), String> {
    let name = alias(version);
    let mut record = encode(binding, key);
    let outcome = (|| {
        if store.add(&name, &record)? {
            return Ok(());
        }
        Err("the protected Key identifier already exists; no record was overwritten".to_string())
    })();
    memzero(&mut record);
    outcome
}

/// Reads `version` and returns the key only when the record is well formed and
/// bound to exactly `expected`. A missing or differently bound record is a
/// clear error, never a different key.
pub(super) fn get(
    store: &impl CredentialStore,
    version: u64,
    expected: &[u8; BINDING_BYTES],
) -> Result<LicenceKey, String> {
    get_record(store, version, expected, false)
}

pub(super) fn get_draft(
    store: &impl CredentialStore, version: u64, expected: &[u8; BINDING_BYTES],
) -> Result<LicenceKey, String> {
    get_record(store, version, expected, true)
}

fn get_record(
    store: &impl CredentialStore, version: u64, expected: &[u8; BINDING_BYTES], draft: bool,
) -> Result<LicenceKey, String> {
    let mut record = store.query(&alias(version))?.ok_or_else(|| {
        "the saved Key is missing from protected storage; enter the Key again"
            .to_string()
    })?;
    let result = (|| {
        if record.len() <= MAGIC.len() + BINDING_BYTES
            || record.len() > MAGIC.len() + BINDING_BYTES + if draft { MAX_DRAFT_KEY_BYTES } else { MAX_KEY_BYTES }
            || !record.starts_with(MAGIC)
        {
            return Err("the saved Key record is malformed".to_string());
        }
        let bound = &record[MAGIC.len()..MAGIC.len() + BINDING_BYTES];
        // Not secret: a digest of the public route. Still compared in full.
        if bound != expected {
            return Err(
                "the saved Key belongs to another server; enter the Key again"
                    .to_string(),
            );
        }
        let text = std::str::from_utf8(&record[MAGIC.len() + BINDING_BYTES..])
            .map_err(|_| "the saved Key record is malformed".to_string())?;
        if draft { LicenceKey::draft(text.to_owned()) } else { LicenceKey::new(text.to_owned()) }
    })();
    memzero(&mut record);
    result
}

/// Safe-integer opaque Asset identifier. Add refuses a collision, so a failed
/// allocation cannot delete an existing effective or draft credential.
pub(super) fn fresh_version() -> u64 {
    let mut bytes = [0u8; 8];
    hbb_common::sodiumoxide::randombytes::randombytes_into(&mut bytes);
    u64::from_le_bytes(bytes) % 9_007_199_254_740_991 + 1
}

/// Removes `version`. Removing a version that is already gone is success.
pub(super) fn remove(store: &impl CredentialStore, version: u64) -> Result<(), String> {
    store.remove(&alias(version))
}

/// The platform store: the HarmonyOS Asset Store, or an explicit refusal.
#[cfg(target_env = "ohos")]
pub(super) fn system() -> impl CredentialStore {
    ohos::AssetStore
}

#[cfg(not(target_env = "ohos"))]
pub(super) fn system() -> impl CredentialStore {
    Unavailable
}

#[cfg(not(target_env = "ohos"))]
struct Unavailable;

#[cfg(not(target_env = "ohos"))]
impl CredentialStore for Unavailable {
    fn add(&self, _alias: &str, _secret: &[u8]) -> Result<bool, String> {
        Err("protected credential storage is unavailable on this platform".to_string())
    }
    fn query(&self, _alias: &str) -> Result<Option<Vec<u8>>, String> {
        Err("protected credential storage is unavailable on this platform".to_string())
    }
    fn remove(&self, _alias: &str) -> Result<(), String> {
        Err("protected credential storage is unavailable on this platform".to_string())
    }
}

#[cfg(target_env = "ohos")]
mod ohos {
    use super::{memzero, CredentialStore};
    use std::ptr;

    const SECRET: u32 = 0x3000_0001;
    const ALIAS: u32 = 0x3000_0002;
    const ACCESSIBILITY: u32 = 0x2000_0003;
    const SYNC_TYPE: u32 = 0x2000_0010;
    const RETURN_TYPE: u32 = 0x2000_0040;
    const RETURN_LIMIT: u32 = 0x2000_0041;
    const CONFLICT_RESOLUTION: u32 = 0x2000_0044;
    const NOT_FOUND: i32 = 24_000_002;
    const DUPLICATED: i32 = 24_000_003;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Blob {
        size: u32,
        data: *mut u8,
    }
    #[repr(C)]
    union Value {
        boolean: bool,
        number: u32,
        blob: Blob,
    }
    #[repr(C)]
    struct Attribute {
        tag: u32,
        value: Value,
    }
    #[repr(C)]
    struct AssetResult {
        count: u32,
        attrs: *mut Attribute,
    }
    #[repr(C)]
    struct ResultSet {
        count: u32,
        results: *mut AssetResult,
    }

    #[link(name = "asset_ndk.z")]
    unsafe extern "C" {
        fn OH_Asset_Add(attributes: *const Attribute, count: u32) -> i32;
        fn OH_Asset_Remove(query: *const Attribute, count: u32) -> i32;
        fn OH_Asset_Query(attributes: *const Attribute, count: u32, results: *mut ResultSet)
            -> i32;
        fn OH_Asset_ParseAttr(result: *const AssetResult, tag: u32) -> *mut Attribute;
        fn OH_Asset_FreeResultSet(results: *mut ResultSet);
    }

    fn blob(tag: u32, bytes: &[u8]) -> Attribute {
        Attribute {
            tag,
            value: Value {
                blob: Blob {
                    size: bytes.len() as u32,
                    data: bytes.as_ptr().cast_mut(),
                },
            },
        }
    }
    fn number(tag: u32, value: u32) -> Attribute {
        Attribute {
            tag,
            value: Value { number: value },
        }
    }

    /// Only the numeric status is reported; provider text can carry material.
    fn failure(operation: &str, code: i32) -> String {
        let reason = match code {
            201 | 24_000_004 | 24_000_005 => {
                "the protected store is locked or this app may not use it (unlock the device and retry)"
            }
            24_000_007 => "the protected store rejected the record",
            _ => "the protected store operation failed",
        };
        format!("Key {operation}: {reason} (Asset code {code})")
    }

    /// Owns a query result set; the returned SECRET is system-owned writable
    /// memory, wiped before the set is freed.
    struct Results(ResultSet);
    impl Drop for Results {
        fn drop(&mut self) {
            unsafe {
                if !self.0.results.is_null() && self.0.count <= 2 {
                    for index in 0..self.0.count as usize {
                        let attr = OH_Asset_ParseAttr(self.0.results.add(index), SECRET);
                        if !attr.is_null() {
                            let secret = (*attr).value.blob;
                            if !secret.data.is_null() && secret.size <= 2048 {
                                memzero(std::slice::from_raw_parts_mut(
                                    secret.data,
                                    secret.size as usize,
                                ));
                            }
                        }
                    }
                }
                OH_Asset_FreeResultSet(&mut self.0);
            }
        }
    }

    pub(super) struct AssetStore;

    impl CredentialStore for AssetStore {
        fn add(&self, name: &str, secret: &[u8]) -> Result<bool, String> {
            let attrs = [
                blob(ALIAS, name.as_bytes()),
                blob(SECRET, secret),
                number(ACCESSIBILITY, 2), // Only while the device is unlocked.
                number(SYNC_TYPE, 0),     // Never synced off this installation.
                number(CONFLICT_RESOLUTION, 1), // Never overwrite another creator.
            ];
            // No IS_PERSISTENT, GROUP_ID or plaintext DATA_LABEL attribute.
            match unsafe { OH_Asset_Add(attrs.as_ptr(), attrs.len() as u32) } {
                0 => Ok(true),
                DUPLICATED => Ok(false),
                code => Err(failure("save", code)),
            }
        }

        fn query(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            let query = [
                blob(ALIAS, name.as_bytes()),
                number(RETURN_TYPE, 0),
                number(RETURN_LIMIT, 2),
            ];
            let mut results = Results(ResultSet {
                count: 0,
                results: ptr::null_mut(),
            });
            let code =
                unsafe { OH_Asset_Query(query.as_ptr(), query.len() as u32, &mut results.0) };
            if code == NOT_FOUND {
                return Ok(None);
            }
            if code != 0 {
                return Err(failure("read", code));
            }
            if results.0.count != 1 || results.0.results.is_null() {
                return Err("the protected store holds an ambiguous Key".to_string());
            }
            let attr = unsafe { OH_Asset_ParseAttr(results.0.results, SECRET) };
            if attr.is_null() {
                return Err("the protected Key record carries no secret".to_string());
            }
            let secret = unsafe { (*attr).value.blob };
            if secret.data.is_null() || secret.size == 0 || secret.size > 2048 {
                return Err("the protected Key record is malformed".to_string());
            }
            // The result guard owns this memory until after this bounded copy.
            Ok(Some(
                unsafe { std::slice::from_raw_parts(secret.data, secret.size as usize) }.to_vec(),
            ))
        }

        fn remove(&self, name: &str) -> Result<(), String> {
            let query = [blob(ALIAS, name.as_bytes())];
            match unsafe { OH_Asset_Remove(query.as_ptr(), query.len() as u32) } {
                0 | NOT_FOUND => Ok(()),
                code => Err(failure("remove", code)),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap};

    #[derive(Default)]
    pub(crate) struct Memory(RefCell<HashMap<String, Vec<u8>>>);

    impl Memory {
        pub(crate) fn record_count(&self) -> usize { self.0.borrow().len() }
    }

    impl CredentialStore for Memory {
        fn add(&self, alias: &str, secret: &[u8]) -> Result<bool, String> {
            let mut map = self.0.borrow_mut();
            if map.contains_key(alias) {
                return Ok(false);
            }
            map.insert(alias.to_owned(), secret.to_vec());
            Ok(true)
        }
        fn query(&self, alias: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.borrow().get(alias).cloned())
        }
        fn remove(&self, alias: &str) -> Result<(), String> {
            self.0.borrow_mut().remove(alias);
            Ok(())
        }
    }

    fn key(value: &str) -> LicenceKey {
        LicenceKey::new(value.to_owned()).unwrap()
    }

    #[test]
    fn a_key_is_only_returned_for_the_route_it_was_approved_for() {
        let store = Memory::default();
        let route = binding("custom", "hbbs.example:21116", "hbbr.example:21117", "AAAA");
        put(&store, 3, &route, &key("relay-secret")).unwrap();
        assert_eq!(get(&store, 3, &route).unwrap().expose(), "relay-secret");
        for other in [
            binding("custom", "other.example:21116", "hbbr.example:21117", "AAAA"),
            binding("custom", "hbbs.example:21116", "other.example:21117", "AAAA"),
            binding("custom", "hbbs.example:21116", "hbbr.example:21117", "BBBB"),
            binding("official", "hbbs.example:21116", "hbbr.example:21117", "AAAA"),
        ] {
            assert!(get(&store, 3, &other).is_err());
        }
        // Part boundaries are length-prefixed, so fields cannot be shifted.
        assert_ne!(
            binding("custom", "ab", "c", "k"),
            binding("custom", "a", "bc", "k")
        );
    }

    #[test]
    fn a_missing_version_is_an_error_and_a_collision_preserves_the_record() {
        let store = Memory::default();
        let route = binding("custom", "a:1", "b:2", "k");
        assert!(get(&store, 1, &route).is_err());
        put(&store, 2, &route, &key("old-orphan")).unwrap();
        assert!(put(&store, 2, &route, &key("fresh")).is_err());
        assert_eq!(get(&store, 2, &route).unwrap().expose(), "old-orphan");
        remove(&store, 2).unwrap();
        remove(&store, 2).unwrap();
        assert!(get(&store, 2, &route).is_err());
    }

    #[test]
    fn versions_coexist_until_the_old_one_is_removed() {
        let store = Memory::default();
        let route = binding("custom", "a:1", "b:2", "k");
        put(&store, 1, &route, &key("one")).unwrap();
        put(&store, 2, &route, &key("two")).unwrap();
        assert_eq!(get(&store, 1, &route).unwrap().expose(), "one");
        remove(&store, 1).unwrap();
        assert_eq!(get(&store, 2, &route).unwrap().expose(), "two");
    }

    #[test]
    fn malformed_records_and_keys_are_refused() {
        let store = Memory::default();
        let route = binding("custom", "a:1", "b:2", "k");
        store.add(&alias(9), b"RDRK1short").unwrap();
        assert!(get(&store, 9, &route).is_err());
        for bad in ["", "tab\t", "new\nline"] {
            assert!(LicenceKey::new(bad.to_owned()).is_err());
        }
        assert!(LicenceKey::new("x".repeat(1025)).is_err());
        assert!(LicenceKey::new("x".repeat(1024)).is_ok());
    }
}
