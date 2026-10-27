use sha2::{Digest, Sha256};
use sodiumoxide::base64;

use crate::{
    log,
    password_security::{decrypt_str_or_original, symmetric_crypt},
};

pub(super) const PASSWORD_ENC_VERSION: &str = "00";
pub(super) const PERMANENT_PASSWORD_ENC_VERSION: &str = "01";
pub(super) const PERMANENT_PASSWORD_HASH_PREFIX: &str = "00";
const HBBS_PRESET_PASSWORD_HASH_PREFIX: &str = "00";
pub(super) const PERMANENT_PASSWORD_H1_LEN: usize = 32;
pub(super) const DEFAULT_SALT_LEN: usize = 32;
pub const ENCRYPT_MAX_LEN: usize = 128; // used for password, pin, etc, not for all
const VERSION_LEN: usize = 2;

#[cfg(test)]
pub(super) fn is_permanent_password_hashed_storage(v: &str) -> bool {
    decode_permanent_password_h1_from_hashed_storage(v).is_some()
}

pub fn compute_permanent_password_h1(
    password: &str,
    salt: &str,
) -> [u8; PERMANENT_PASSWORD_H1_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());
    let out = hasher.finalize();
    let mut h1 = [0u8; PERMANENT_PASSWORD_H1_LEN];
    h1.copy_from_slice(&out[..PERMANENT_PASSWORD_H1_LEN]);
    h1
}

pub(super) fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    sodiumoxide::utils::memcmp(a, b)
}

pub(super) fn encode_permanent_password_storage_from_h1(
    h1: &[u8; PERMANENT_PASSWORD_H1_LEN],
) -> String {
    PERMANENT_PASSWORD_HASH_PREFIX.to_owned() + &base64::encode(h1, base64::Variant::Original)
}

pub(super) fn encode_permanent_password_encrypted_storage_from_h1(
    h1: &[u8; PERMANENT_PASSWORD_H1_LEN],
) -> Option<String> {
    let hashed_storage = encode_permanent_password_storage_from_h1(h1);
    encrypt_permanent_password_storage(&hashed_storage)
}

pub(super) fn decode_permanent_password_h1_from_hashed_storage(
    storage: &str,
) -> Option<[u8; PERMANENT_PASSWORD_H1_LEN]> {
    decode_password_h1_after_prefix(storage, PERMANENT_PASSWORD_HASH_PREFIX)
}

fn decode_password_h1_after_prefix(
    storage: &str,
    prefix: &str,
) -> Option<[u8; PERMANENT_PASSWORD_H1_LEN]> {
    let encoded = storage.strip_prefix(prefix)?;

    let v = base64::decode(encoded.as_bytes(), base64::Variant::Original).ok()?;
    if v.len() != PERMANENT_PASSWORD_H1_LEN {
        return None;
    }
    let mut h1 = [0u8; PERMANENT_PASSWORD_H1_LEN];
    h1.copy_from_slice(&v[..PERMANENT_PASSWORD_H1_LEN]);
    Some(h1)
}

fn encrypt_permanent_password_storage(storage: &str) -> Option<String> {
    if storage.chars().count() > ENCRYPT_MAX_LEN {
        return None;
    }
    let encrypted = symmetric_crypt(storage.as_bytes(), true).ok()?;
    Some(
        PERMANENT_PASSWORD_ENC_VERSION.to_owned()
            + &base64::encode(encrypted, base64::Variant::Original),
    )
}

pub(super) fn decrypt_permanent_password_str_or_original(storage: &str) -> (String, bool, bool) {
    if storage.len() > VERSION_LEN && storage.starts_with(PERMANENT_PASSWORD_ENC_VERSION) {
        if let Ok(decoded) = base64::decode(
            &storage.as_bytes()[VERSION_LEN..],
            base64::Variant::Original,
        ) {
            if let Ok(v) = symmetric_crypt(&decoded, false) {
                return (String::from_utf8_lossy(&v).to_string(), true, false);
            }
        }
    }
    (storage.to_owned(), false, !storage.is_empty())
}

pub fn local_permanent_password_storage_is_usable_for_auth(storage: &str, salt: &str) -> bool {
    if storage.is_empty() {
        return false;
    }

    if decode_permanent_password_h1_from_storage(storage).is_some() {
        return !salt.is_empty();
    }
    if storage.starts_with(PERMANENT_PASSWORD_ENC_VERSION) {
        let (_, decrypted, _) = decrypt_permanent_password_str_or_original(storage);
        if decrypted {
            log::error!("Permanent password storage looks current but cannot be decoded as a hash");
            return false;
        }
    }

    let (_, decrypted, looks_like_plaintext) =
        decrypt_str_or_original(storage, PASSWORD_ENC_VERSION);
    if storage.starts_with(PASSWORD_ENC_VERSION) && !decrypted && !looks_like_plaintext {
        log::error!("Permanent password storage looks encrypted but cannot be decrypted");
        return false;
    }
    true
}

pub fn preset_permanent_password_storage_is_usable_for_auth(storage: &str, salt: &str) -> bool {
    if storage.is_empty() {
        return false;
    }
    if salt.is_empty() {
        return true;
    }
    decode_preset_password_h1_from_storage(storage).is_some()
}

pub fn decode_preset_password_h1_from_storage(
    storage: &str,
) -> Option<[u8; PERMANENT_PASSWORD_H1_LEN]> {
    decode_password_h1_after_prefix(storage, HBBS_PRESET_PASSWORD_HASH_PREFIX)
}

#[cfg(test)]
fn local_permanent_password_storage_matches_plain(storage: &str, salt: &str, input: &str) -> bool {
    if storage.is_empty() || input.is_empty() {
        return false;
    }
    if !local_permanent_password_storage_is_usable_for_auth(storage, salt) {
        return false;
    }
    if let Some(stored_h1) = decode_permanent_password_h1_from_storage(storage) {
        if salt.is_empty() {
            log::error!("Salt is empty but permanent password storage is hashed");
            return false;
        }
        let h1 = compute_permanent_password_h1(input, salt);
        return constant_time_eq_32(&h1, &stored_h1);
    }
    storage == input
}

pub(super) fn preset_permanent_password_storage_matches_plain(
    storage: &str,
    salt: &str,
    input: &str,
) -> bool {
    if storage.is_empty() || input.is_empty() {
        return false;
    }
    if salt.is_empty() {
        return storage == input;
    }
    let Some(stored_h1) = decode_preset_password_h1_from_storage(storage) else {
        return false;
    };
    let h1 = compute_permanent_password_h1(input, salt);
    constant_time_eq_32(&h1, &stored_h1)
}

pub fn decode_permanent_password_h1_from_storage(
    storage: &str,
) -> Option<[u8; PERMANENT_PASSWORD_H1_LEN]> {
    if storage.starts_with(PERMANENT_PASSWORD_ENC_VERSION) {
        let (hashed_storage, decrypted, _) = decrypt_permanent_password_str_or_original(storage);
        if !decrypted {
            return None;
        }
        return decode_permanent_password_h1_from_hashed_storage(&hashed_storage);
    }
    None
}

/// Checked native host adapter. Current/potential encrypted storage never falls
/// back to an authentication password when decoding fails. Legacy unprefixed
/// plaintext remains compatible and is hashed exactly once with the stable salt.
pub(super) fn checked_local_h1(storage: &str, salt: &str, uuid: &[u8], pk: &[u8]) -> anyhow::Result<Option<[u8; 32]>> {
    if storage.is_empty() { return Ok(None); }
    if salt.is_empty() { return Err(anyhow::anyhow!("Permanent password salt unavailable")); }
    if storage.starts_with(PERMANENT_PASSWORD_ENC_VERSION) {
        let mut hashed = checked_decrypt(storage, PERMANENT_PASSWORD_ENC_VERSION, uuid, pk)?;
        let result = decode_permanent_password_h1_from_hashed_storage(&hashed).map(Some)
            .ok_or_else(|| anyhow::anyhow!("Invalid stored permanent password verifier"));
        unsafe { sodiumoxide::utils::memzero(hashed.as_bytes_mut()); }
        return result;
    }
    if storage.starts_with(PASSWORD_ENC_VERSION) {
        let mut plain = checked_decrypt(storage, PASSWORD_ENC_VERSION, uuid, pk)?;
        let h1 = compute_permanent_password_h1(&plain, salt);
        unsafe { sodiumoxide::utils::memzero(plain.as_bytes_mut()); }
        return Ok(Some(h1));
    }
    Ok(Some(compute_permanent_password_h1(storage, salt)))
}

/// Explicit-material adapter of password_security::symmetric_crypt and
/// open_secretbox_payload at the recorded common pin. The original helpers call
/// get_uuid -> get_key_pair and may generate/write identity during decryption.
/// Checked startup supplies its frozen UUID/EXISTING fallback key instead.
pub(super) fn checked_decrypt(storage: &str, prefix: &str, uuid: &[u8], pk: &[u8]) -> anyhow::Result<String> {
    use sodiumoxide::crypto::secretbox;
    let encoded = storage.strip_prefix(prefix).ok_or_else(|| anyhow::anyhow!("Invalid encrypted storage prefix"))?;
    let bytes = base64::decode(encoded, base64::Variant::Original).map_err(|_| anyhow::anyhow!("Invalid encrypted storage encoding"))?;
    for material in [uuid, pk] {
        if material.is_empty() { continue; }
        let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
        let length = material.len().min(secretbox::KEYBYTES);
        key.0[..length].copy_from_slice(&material[..length]);
        let mut opened = None;
        if bytes.first() == Some(&1) && bytes.len() >= 1 + secretbox::NONCEBYTES + secretbox::MACBYTES {
            let mut nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
            nonce.0.copy_from_slice(&bytes[1..1 + secretbox::NONCEBYTES]);
            opened = secretbox::open(&bytes[1 + secretbox::NONCEBYTES..], &nonce, &key).ok();
        }
        if opened.is_none() {
            opened = secretbox::open(&bytes, &secretbox::Nonce([0; secretbox::NONCEBYTES]), &key).ok();
        }
        if let Some(mut plain) = opened {
            let result = std::str::from_utf8(&plain).map(str::to_owned).map_err(|_| anyhow::anyhow!("Invalid decrypted storage encoding"));
            sodiumoxide::utils::memzero(&mut plain);
            return result;
        }
    }
    Err(anyhow::anyhow!("Stored security value cannot be decrypted with the existing identity"))
}

// Salt can be updated only when the password is empty, plaintext, or decryptable
// legacy storage. Current-prefixed storage is treated as salt-bound.
pub(super) fn password_is_empty_or_not_hashed(permanent_password_storage: &str) -> bool {
    if permanent_password_storage.is_empty() {
        return true;
    }
    if decode_permanent_password_h1_from_storage(permanent_password_storage).is_some() {
        return false;
    }
    if permanent_password_storage.starts_with(PERMANENT_PASSWORD_ENC_VERSION) {
        return false;
    }
    let (_, decrypted, looks_like_plaintext) =
        decrypt_str_or_original(permanent_password_storage, PASSWORD_ENC_VERSION);
    decrypted || looks_like_plaintext
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password_security::encrypt_str_or_original;

    fn encode_hbbs_preset_password_storage_from_h1(h1: &[u8; PERMANENT_PASSWORD_H1_LEN]) -> String {
        HBBS_PRESET_PASSWORD_HASH_PREFIX.to_owned() + &base64::encode(h1, base64::Variant::Original)
    }

    #[test]
    fn test_permanent_password_h1_storage_roundtrip() {
        let salt = "salt123";
        let password = "p@ssw0rd";
        let h1 = compute_permanent_password_h1(password, salt);
        let stored = encode_permanent_password_storage_from_h1(&h1);
        assert!(stored.starts_with(PERMANENT_PASSWORD_HASH_PREFIX));
        assert!(is_permanent_password_hashed_storage(&stored));
        let decoded = decode_permanent_password_h1_from_hashed_storage(&stored).unwrap();
        assert_eq!(&decoded[..], &h1[..]);
    }

    #[test]
    fn test_permanent_password_encrypted_storage_uses_01_outer_and_00_inner() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let storage = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        assert!(storage.starts_with(PERMANENT_PASSWORD_ENC_VERSION));
        assert!(!is_permanent_password_hashed_storage(&storage));

        let (inner, decrypted, should_store) = decrypt_permanent_password_str_or_original(&storage);
        assert!(decrypted);
        assert!(!should_store);
        assert!(inner.starts_with(PERMANENT_PASSWORD_HASH_PREFIX));
        assert_eq!(
            decode_permanent_password_h1_from_storage(&storage),
            Some(h1)
        );
    }

    #[test]
    fn test_encrypted_hashed_password_storage_matches_plain_with_salt() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let storage = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        assert!(local_permanent_password_storage_is_usable_for_auth(
            &storage, salt
        ));
        assert!(local_permanent_password_storage_matches_plain(
            &storage, salt, "p@ssw0rd"
        ));
        assert!(!local_permanent_password_storage_matches_plain(
            &storage, salt, "wrong"
        ));
    }

    #[test]
    fn test_hbbs_00_hashed_preset_password_storage_is_decoded_for_preset_auth() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let storage = encode_hbbs_preset_password_storage_from_h1(&h1);

        assert_eq!(decode_preset_password_h1_from_storage(&storage), Some(h1));
    }

    #[test]
    fn test_hbbs_00_hashed_preset_password_storage_matches_plain_with_salt() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let storage = encode_hbbs_preset_password_storage_from_h1(&h1);

        assert!(preset_permanent_password_storage_is_usable_for_auth(
            &storage, salt
        ));
        assert!(preset_permanent_password_storage_matches_plain(
            &storage, salt, "p@ssw0rd"
        ));
        assert!(!preset_permanent_password_storage_matches_plain(
            &storage, salt, "wrong"
        ));
    }

    #[test]
    fn test_encrypted_hash_storage_is_not_accepted_as_preset_storage() {
        let salt = "salt123";
        let h1 = compute_permanent_password_h1("p@ssw0rd", salt);
        let storage = encode_permanent_password_encrypted_storage_from_h1(&h1).unwrap();

        assert!(!preset_permanent_password_storage_is_usable_for_auth(
            &storage, salt
        ));
        assert!(!preset_permanent_password_storage_matches_plain(
            &storage, salt, "p@ssw0rd"
        ));
    }

    #[test]
    fn test_hbbs_00_shaped_preset_password_without_salt_stays_plaintext() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let storage = encode_hbbs_preset_password_storage_from_h1(&h1);

        assert!(preset_permanent_password_storage_is_usable_for_auth(
            &storage, ""
        ));
        assert!(preset_permanent_password_storage_matches_plain(
            &storage, "", &storage
        ));
        assert!(!preset_permanent_password_storage_matches_plain(
            &storage, "", "p@ssw0rd"
        ));
    }

    #[test]
    fn test_hashed_preset_password_storage_without_salt_is_not_usable() {
        let h1 = compute_permanent_password_h1("p@ssw0rd", "salt123");
        let storage = encode_permanent_password_storage_from_h1(&h1);

        assert!(!local_permanent_password_storage_is_usable_for_auth(
            &storage, ""
        ));
        assert!(!local_permanent_password_storage_matches_plain(
            &storage, "", "p@ssw0rd"
        ));
    }

    #[test]
    fn test_legacy_plain_preset_password_without_salt_keeps_old_behavior() {
        let storage = "01not-a-valid-hash";

        assert!(preset_permanent_password_storage_is_usable_for_auth(
            storage, ""
        ));
        assert!(preset_permanent_password_storage_matches_plain(
            storage,
            "",
            "01not-a-valid-hash"
        ));
    }

    #[test]
    fn test_malformed_preset_password_with_salt_is_not_usable_for_auth() {
        for storage in ["01not-a-valid-hash", "00not-a-valid-hash"] {
            assert!(!preset_permanent_password_storage_is_usable_for_auth(
                storage,
                "preset-salt"
            ));
            assert!(!preset_permanent_password_storage_matches_plain(
                storage,
                "preset-salt",
                storage
            ));
        }
    }

    #[test]
    fn test_invalid_current_version_storage_is_not_usable_for_auth() {
        let encrypted = symmetric_crypt(b"not-a-hash", true).unwrap();
        let encrypted_non_hash = PERMANENT_PASSWORD_ENC_VERSION.to_owned()
            + &base64::encode(encrypted, base64::Variant::Original);

        assert!(!local_permanent_password_storage_is_usable_for_auth(
            &encrypted_non_hash,
            "salt123"
        ));
        assert!(!local_permanent_password_storage_matches_plain(
            &encrypted_non_hash,
            "salt123",
            &encrypted_non_hash
        ));
    }

    #[test]
    fn test_legacy_plain_preset_password_that_decodes_as_hash_requires_salt() {
        let h1 = compute_permanent_password_h1("plain-looking-hash", "salt123");
        let storage = encode_permanent_password_storage_from_h1(&h1);

        assert!(!local_permanent_password_storage_is_usable_for_auth(
            &storage, ""
        ));
        assert!(!local_permanent_password_storage_matches_plain(
            &storage, "", &storage
        ));
    }

    #[test]
    fn test_password_is_empty_or_not_hashed_accepts_plaintext_and_decryptable_legacy_plaintext() {
        let storage =
            encrypt_str_or_original("legacy-secret", PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);

        assert!(password_is_empty_or_not_hashed("00secret"));
        assert!(password_is_empty_or_not_hashed(&storage));
    }

    #[test]
    fn test_password_is_empty_or_not_hashed_treats_locked_00_storage_as_hashed() {
        let invalid_payload = vec![42u8; sodiumoxide::crypto::secretbox::MACBYTES + 1];
        let locked_storage = PASSWORD_ENC_VERSION.to_owned()
            + &base64::encode(invalid_payload, base64::Variant::Original);

        assert!(!password_is_empty_or_not_hashed(&locked_storage));
    }

    #[test]
    fn test_password_is_empty_or_not_hashed_treats_invalid_01_storage_as_hashed() {
        assert!(!password_is_empty_or_not_hashed("01not-a-valid-hash"));
    }
}
