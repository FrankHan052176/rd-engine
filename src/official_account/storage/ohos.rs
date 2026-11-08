//! HarmonyOS Asset Store-backed account master keys.
//!
//! This is missing platform integration, not transplanted RustDesk persistence.
//! The system Asset Store (`asset_ndk.z`, `OH_Asset_*`) is the HarmonyOS
//! equivalent of AndroidKeyStore and the Linux Secret Service: a system-owned,
//! app-scoped secret store that hands the bytes back to this application's own
//! UID and to nothing else. There is no plaintext key file, no software
//! protection fallback and no regeneration of a missing key.
//!
//! The common store holds its cross-process namespace lock throughout these
//! blocking calls; `namespace` already binds the application and profile path,
//! so `root` is not another secret file. A missing item is `Ok(None)` and only a
//! present item may answer; a malformed, duplicated, locked or inaccessible item
//! is an error, never an opportunity to elect a new key or to fall back to
//! software-held key material.
//!
//! The item carries one 32-byte common master key, is readable only while the
//! device is unlocked (a locked device therefore fails closed), is never synced
//! off this installation, and refuses to overwrite another creator. The account
//! records themselves are encrypted with that key and live in the private root.
//!
//! The FFI declarations deliberately mirror `platform::identity_store`'s OHOS
//! module (same System API, same attribute encoding). Only the alias space
//! differs, so the identity key and this key can never meet.

use hbb_common::sodiumoxide::{crypto::secretbox, utils::memzero};
use std::{io, path::Path, ptr};

const SECRET: u32 = 0x3000_0001;
const ALIAS: u32 = 0x3000_0002;
const ACCESSIBILITY: u32 = 0x2000_0003;
const SYNC_TYPE: u32 = 0x2000_0010;
const RETURN_TYPE: u32 = 0x2000_0040;
const RETURN_LIMIT: u32 = 0x2000_0041;
const CONFLICT_RESOLUTION: u32 = 0x2000_0044;
const NOT_FOUND: i32 = 24_000_002;
const DUPLICATED: i32 = 24_000_003;

/// Alias space of this store; separate from `rd-engine.identity.v2.*`.
const ALIAS_PREFIX: &str = "rd-engine.official-account.v1.";

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
    fn OH_Asset_Query(attributes: *const Attribute, count: u32, results: *mut ResultSet) -> i32;
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

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Only the numeric status is reported: provider strings can carry material
/// that is not this layer's to expose.
fn error(code: i32) -> io::Error {
    let kind = match code {
        // The store is locked or this application is not allowed to read it.
        201 | 24_000_004 | 24_000_005 => io::ErrorKind::PermissionDenied,
        24_000_007 => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        format!("HarmonyOS Asset Store account master-key operation failed ({code})"),
    )
}

/// The alias is the account namespace itself, so an item can only ever be
/// addressed by the profile that created it.
fn alias(namespace: &str) -> io::Result<String> {
    if namespace.len() != 64
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "account master-key namespace must be a lowercase SHA-256 digest",
        ));
    }
    Ok(format!("{ALIAS_PREFIX}{namespace}"))
}

/// Owns one query result set until it is parsed. The returned `SECRET` is
/// System-API-owned writable memory, so it is wiped before the set is freed.
struct Results(ResultSet);

impl Drop for Results {
    fn drop(&mut self) {
        // The query requests one record plus one duplicate witness. Anything
        // larger is refused by the caller without touching these buffers.
        unsafe {
            if !self.0.results.is_null() && self.0.count <= 2 {
                for index in 0..self.0.count as usize {
                    let attr = OH_Asset_ParseAttr(self.0.results.add(index), SECRET);
                    if !attr.is_null() {
                        let secret = (*attr).value.blob;
                        if !secret.data.is_null() && secret.size <= 1024 {
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

pub(super) fn load_key(_root: &Path, namespace: &str) -> io::Result<Option<secretbox::Key>> {
    let alias = alias(namespace)?;
    let query = [
        blob(ALIAS, alias.as_bytes()),
        // All attributes and the secret; the alias is the only search key.
        number(RETURN_TYPE, 0),
        number(RETURN_LIMIT, 2),
    ];
    let mut results = Results(ResultSet {
        count: 0,
        results: ptr::null_mut(),
    });
    let code = unsafe { OH_Asset_Query(query.as_ptr(), query.len() as u32, &mut results.0) };
    if code == NOT_FOUND {
        return Ok(None);
    }
    if code != 0 {
        return Err(error(code));
    }
    if results.0.count != 1 || results.0.results.is_null() {
        return Err(invalid(
            "HarmonyOS Asset Store holds an ambiguous account master key",
        ));
    }
    let attr = unsafe { OH_Asset_ParseAttr(results.0.results, SECRET) };
    if attr.is_null() {
        return Err(invalid(
            "HarmonyOS Asset Store account master key carries no secret",
        ));
    }
    let secret = unsafe { (*attr).value.blob };
    if secret.data.is_null() || secret.size as usize != secretbox::KEYBYTES {
        return Err(invalid(
            "HarmonyOS Asset Store account master key must contain exactly 32 bytes",
        ));
    }
    // The result guard owns this memory until after this bounded copy; the key
    // type wipes its own bytes on drop.
    let key = unsafe { std::slice::from_raw_parts(secret.data, secret.size as usize) };
    secretbox::Key::from_slice(key)
        .map(Some)
        .ok_or_else(|| invalid("HarmonyOS Asset Store account master key is unusable"))
}

pub(super) fn create_key(
    _root: &Path,
    namespace: &str,
    key: &secretbox::Key,
) -> io::Result<bool> {
    let alias = alias(namespace)?;
    let attrs = [
        blob(ALIAS, alias.as_bytes()),
        blob(SECRET, key.0.as_slice()),
        number(ACCESSIBILITY, 2), // Only while the device is unlocked.
        number(SYNC_TYPE, 0),     // Never sync this installation's account key.
        number(CONFLICT_RESOLUTION, 1), // Never overwrite another creator.
    ];
    // No IS_PERSISTENT, GROUP_ID, DATA_LABEL or developer-id attribute: an item
    // this application cannot address again is worse than a refused creation.
    let code = unsafe { OH_Asset_Add(attrs.as_ptr(), attrs.len() as u32) };
    match code {
        0 => Ok(true),
        // Another creator won. The caller must load that key and must not use
        // its unpersisted candidate.
        DUPLICATED => Ok(false),
        _ => Err(error(code)),
    }
}
