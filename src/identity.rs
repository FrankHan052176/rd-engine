//! Stable local peer identity, kept exclusively in the platform protected store.
//! Creating this identity is NOT hbbs registration or proof of reachability.
use hbb_common::{
    sodiumoxide::{
        self,
        crypto::{hash::sha256, sign},
        randombytes,
        utils::memzero,
    },
    uuid::Uuid,
};
use std::io;

#[path = "platform/identity_store.rs"]
mod store;

const MAGIC: &[u8; 8] = b"RDEID002";
const PAYLOAD_BYTES: usize = 65;
const RECORD_BYTES: usize = PAYLOAD_BYTES + 32;

// No Debug/Clone/serialization: the only public representation is the public
// identity, never the signing seed or the registration UUID in diagnostics.
pub struct PersistentIdentity {
    id: String,
    registration_uuid: [u8; 16],
    public_key: sign::PublicKey,
    signing_key: sign::SecretKey,
}

impl PersistentIdentity {
    /// Blocking OS storage operation. Call from an owning blocking worker, not
    /// the network reader, an async executor thread, or a UI/NAPI callback.
    /// A locked/corrupt/unavailable store fails without replacing its identity.
    pub fn load_or_create(slot: &str) -> io::Result<Self> {
        validate_slot(slot)?;
        sodiumoxide::init().map_err(|_| io::Error::other("Identity cryptography unavailable"))?;
        if let Some(record) = store::load(slot)? {
            return record.decode();
        }
        let candidate = Record::generate();
        if store::create(slot, &candidate)? {
            candidate.decode()
        } else {
            // Another process won creation. Its identity, not our discarded
            // candidate, is authoritative; never overwrite or silently retry.
            store::load(slot)?
                .ok_or_else(|| io::Error::other("Protected identity disappeared during creation"))?
                .decode()
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key(&self) -> sign::PublicKey {
        self.public_key
    }

    /// Native engine ownership transfer only. These secret-bearing parts must
    /// never be serialized into a frontend event, profile, URL, or snapshot.
    /// The receiving owner must erase the UUID when registration no longer
    /// needs it; the signing key already provides zeroizing destruction.
    pub fn into_parts(mut self) -> (String, [u8; 16], sign::PublicKey, sign::SecretKey) {
        (
            std::mem::take(&mut self.id),
            std::mem::take(&mut self.registration_uuid),
            self.public_key,
            std::mem::replace(&mut self.signing_key, sign::SecretKey([0; sign::SECRETKEYBYTES])),
        )
    }
}

impl Drop for PersistentIdentity {
    fn drop(&mut self) {
        memzero(&mut self.registration_uuid);
    }
}

fn validate_slot(slot: &str) -> io::Result<()> {
    if slot.is_empty()
        || slot.len() > 80
        || !slot
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid protected identity slot",
        ));
    }
    Ok(())
}

struct Record([u8; RECORD_BYTES]);

impl Record {
    fn generate() -> Self {
        let mut record = Self([0; RECORD_BYTES]);
        record.0[..8].copy_from_slice(MAGIC);
        let id = (100_000_000 + randombytes::randombytes_uniform(900_000_000)).to_string();
        record.0[8..17].copy_from_slice(id.as_bytes());
        record.0[17..33].copy_from_slice(Uuid::new_v4().as_bytes());
        randombytes::randombytes_into(&mut record.0[33..65]);
        let digest = sha256::hash(&record.0[..PAYLOAD_BYTES]);
        record.0[PAYLOAD_BYTES..].copy_from_slice(&digest.0);
        record
    }

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != RECORD_BYTES {
            return Err(corrupt());
        }
        let mut record = Self([0; RECORD_BYTES]);
        record.0.copy_from_slice(bytes);
        Ok(record)
    }

    fn decode(&self) -> io::Result<PersistentIdentity> {
        // The digest is an additional corruption check INSIDE OS protection,
        // not a substitute for authenticated storage or a peer signature.
        if &self.0[..8] != MAGIC
            || self.0[8] == b'0'
            || !self.0[8..17].iter().all(u8::is_ascii_digit)
            || self.0[23] >> 4 != 4
            || self.0[25] & 0xc0 != 0x80
            || sha256::hash(&self.0[..PAYLOAD_BYTES]).0 != self.0[PAYLOAD_BYTES..]
        {
            return Err(corrupt());
        }
        let id = std::str::from_utf8(&self.0[8..17])
            .map_err(|_| corrupt())?
            .to_owned();
        let mut registration_uuid = [0; 16];
        registration_uuid.copy_from_slice(&self.0[17..33]);
        let seed = sign::Seed::from_slice(&self.0[33..65]).ok_or_else(corrupt)?;
        let (public_key, signing_key) = sign::keypair_from_seed(&seed);
        Ok(PersistentIdentity {
            id,
            registration_uuid,
            public_key,
            signing_key,
        })
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}

fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Protected identity is corrupt or has an unsupported format; it was not replaced",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_record_keeps_peer_signatures_valid() {
        sodiumoxide::init().unwrap();
        let record = Record::generate();
        let first = record.decode().unwrap();
        let restored = Record::from_bytes(&record.0).unwrap().decode().unwrap();
        let (id, mut registration_uuid, public_key, signing_key) = first.into_parts();
        let proof = sign::sign_detached(b"fresh peer handshake", &signing_key);
        assert!(sign::verify_detached(
            &proof,
            b"fresh peer handshake",
            &restored.public_key
        ));
        assert_eq!(id, restored.id);
        assert_eq!(public_key, restored.public_key);
        assert_eq!(registration_uuid, restored.registration_uuid);
        memzero(&mut registration_uuid);
    }

    #[test]
    fn corruption_never_becomes_a_replacement_identity() {
        sodiumoxide::init().unwrap();
        let mut record = Record::generate();
        record.0[40] ^= 1;
        assert_eq!(
            record.decode().err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            Record::from_bytes(&record.0[..64]).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn identity_slots_cannot_escape_their_store() {
        for slot in [
            "",
            "../primary",
            "a/b",
            "a\\b",
            "a:b",
            ".",
            "primary\0suffix",
        ] {
            assert_eq!(
                PersistentIdentity::load_or_create(slot)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
