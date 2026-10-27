//! Account-only persistence. This is a missing platform integration, not an
//! upstream LocalConfig/Ab persistence transplant. Crypto and cache schemas are
//! supplied by the selected hbb_common. No identity material is used as a key.

use hbb_common::{
    config::{Config, APP_NAME},
    sodiumoxide::{self, crypto::{hash::sha256, secretbox}, randombytes, utils::memzero},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
mod linux;
#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::init_account_storage;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use apple as backend;
#[cfg(target_os = "windows")]
use windows as backend;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
use linux as backend;
#[cfg(target_os = "android")]
use android as backend;

pub(super) const MAX_TOKEN_BYTES: usize = 1024 * 1024;
pub(super) const MAX_USER_INFO_BYTES: usize = 4 * 1024 * 1024;
// The owned upstream decompressor accepts 256 MiB. This store does not compress
// and never applies the identity store's 4 KiB limit to an address book.
pub(super) const MAX_CACHE_BYTES: usize = 256 * 1024 * 1024;
const MAX_SCOPE_BYTES: usize = 1024;
const DOMAIN: &[u8] = b"rd-engine/official-account/record/v1\0";
const MAGIC: &[u8; 8] = b"RDACCT01";
const ENVELOPE_ALLOWANCE: usize = DOMAIN.len() + 64 + 1 + 4 + MAX_SCOPE_BYTES + 8 + 32 + 8;
const ACCOUNT_BYTES: usize = MAX_TOKEN_BYTES + MAX_USER_INFO_BYTES + 33;
const FILE_ALLOWANCE: usize = MAGIC.len() + secretbox::NONCEBYTES + secretbox::MACBYTES;
const LOCK_FILE: &str = "owner.lock";

/// Deliberately has neither Debug nor Clone. Native-owned plaintext is erased
/// on replacement and drop; authorized returned String/FRB/Dart copies are not
/// under this owner's erasure control.
#[derive(Default)]
pub(super) struct SecretBytes(Vec<u8>, usize);

impl SecretBytes {
    pub(super) fn from_string(value: String) -> Self {
        Self(value.into_bytes(), 0)
    }

    fn from_vec(value: Vec<u8>) -> Self {
        Self(value, 0)
    }

    pub(super) fn from_slice(value: &[u8]) -> Self {
        Self(value.to_vec(), 0)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.0[self.1..]
    }

    pub(super) fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }


    pub(super) fn into_string(mut self) -> io::Result<String> {
        std::str::from_utf8(self.bytes()).map_err(|_| invalid("Account text is not UTF-8"))?;
        if self.1 != 0 {
            let length = self.0.len() - self.1;
            self.0.copy_within(self.1.., 0);
            memzero(&mut self.0[length..]);
            self.0.truncate(length);
            self.1 = 0;
        }
        // Checked above; transfer the allocation to the authorized consumer.
        Ok(unsafe { String::from_utf8_unchecked(std::mem::take(&mut self.0)) })
    }

    pub(super) fn clear(&mut self) {
        memzero(&mut self.0);
        self.0.clear();
        self.1 = 0;
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy)]
pub(super) enum RecordKind {
    Account,
    AddressBook,
    Group,
}

impl RecordKind {
    fn tag(self) -> u8 {
        match self {
            Self::Account => 1,
            Self::AddressBook => 2,
            Self::Group => 3,
        }
    }

    fn file(self) -> &'static str {
        match self {
            Self::Account => "account.enc",
            Self::AddressBook => "address-book.enc",
            Self::Group => "group.enc",
        }
    }

    fn limit(self) -> usize {
        match self {
            Self::Account => ACCOUNT_BYTES,
            Self::AddressBook | Self::Group => MAX_CACHE_BYTES,
        }
    }
}

/// The credential-free form is a durable revocation tombstone. It is retained
/// after logout: deleting the epoch along with the token would permit ABA and a
/// stale process to republish its old credentials. It is still authenticated and
/// encrypted, and contains no token, user metadata or cached peer hashes.
pub(super) struct AccountRecord {
    pub(super) scope: String,
    pub(super) epoch: u64,
    pub(super) epoch_id: [u8; 32],
    pub(super) metadata_revision: u64,
    pub(super) ab_revision: u64,
    pub(super) group_revision: u64,
    ab_present: bool,
    group_present: bool,
    pub(super) token: SecretBytes,
    pub(super) user_info: SecretBytes,
}

impl AccountRecord {
    pub(super) fn empty(scope: String, epoch: u64) -> Self {
        // Numeric n+1 is not unique after an uncertain pre-publication failure:
        // a different process may also choose n+1, including session-only. This
        // public random ID identifies the exact authenticated transition.
        let mut epoch_id = [0; 32];
        randombytes::randombytes_into(&mut epoch_id);
        Self {
            scope,
            epoch,
            epoch_id,
            metadata_revision: 0,
            ab_revision: 0,
            group_revision: 0,
            ab_present: false,
            group_present: false,
            token: SecretBytes::default(),
            user_info: SecretBytes::default(),
        }
    }

    pub(super) fn revision(&self, kind: RecordKind) -> io::Result<u64> {
        match kind {
            RecordKind::AddressBook => Ok(self.ab_revision),
            RecordKind::Group => Ok(self.group_revision),
            RecordKind::Account => Err(invalid("Account is not a cache kind")),
        }
    }

    pub(super) fn advance_cache(&mut self, kind: RecordKind, present: bool) -> io::Result<()> {
        let (revision, stored) = match kind {
            RecordKind::AddressBook => (&mut self.ab_revision, &mut self.ab_present),
            RecordKind::Group => (&mut self.group_revision, &mut self.group_present),
            RecordKind::Account => return Err(invalid("Account is not a cache kind")),
        };
        *revision = revision.checked_add(1)
            .ok_or_else(|| invalid("Account cache generation exhausted"))?;
        *stored = present;
        Ok(())
    }

    fn cache_present(&self, kind: RecordKind) -> io::Result<bool> {
        match kind {
            RecordKind::AddressBook => Ok(self.ab_present),
            RecordKind::Group => Ok(self.group_present),
            RecordKind::Account => Err(invalid("Account is not a cache kind")),
        }
    }

    fn cache_file(&self, kind: RecordKind) -> io::Result<String> {
        Ok(format!("{}.{}.{:016x}", kind.file(), hex(&self.epoch_id), self.revision(kind)?))
    }
}

struct OpenedRecord {
    scope: String,
    epoch: u64,
    epoch_id: [u8; 32],
    revision: u64,
    payload: SecretBytes,
}

/// The handle's lifetime is the OS exclusive lock lifetime. The in-process
/// owner always acquires its mutex first, then this lock, and never calls into
/// HTTP/OIDC while holding either. std File locking is stable at our MSRV 1.89.
pub(super) struct Store {
    root: PathBuf,
    namespace: String,
    lock: File,
    key: Option<secretbox::Key>,
}

impl Store {
    pub(super) fn open() -> io::Result<Self> {
        if !cfg!(any(
            target_os = "macos", target_os = "ios", target_os = "windows",
            target_os = "android", all(target_os = "linux", not(target_env = "ohos"))
        )) {
            return Err(io::Error::new(io::ErrorKind::Unsupported,
                "Official account protected storage is unsupported on this target"));
        }
        sodiumoxide::init().map_err(|_| io::Error::other("Account cryptography unavailable"))?;
        let (root, namespace) = location()?;
        private_directory(&root)?;
        // std returns an extended-length path on Windows; keep it for the
        // native durable rename as revision-qualified names can exceed MAX_PATH.
        let root = fs::canonicalize(root)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        secure_options(&mut options);
        let lock = options.open(root.join(LOCK_FILE))?;
        check_regular(&lock)?;
        lock.lock()?;
        let key = platform_load_key(&root, &namespace)?;
        let result = Self { root, namespace, lock, key };
        if result.key.is_none() && result.has_records()? {
            return Err(invalid("Protected account key is missing for existing encrypted records"));
        }
        Ok(result)
    }

    pub(super) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(super) fn finish(self) -> io::Result<()> {
        self.lock.unlock()
    }

    fn has_records(&self) -> io::Result<bool> {
        let mut found = false;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            // Includes unpublished ciphertext: a lost protected key must not
            // silently become a new key election, even after a process crash.
            if owned_kind(&entry.file_name()).is_some() {
                let kind = entry.file_type()?;
                if !kind.is_file() || kind.is_symlink() {
                    return Err(invalid("Account record is not a regular file"));
                }
                found = true;
            }
        }
        Ok(found)
    }

    fn ensure_key(&mut self) -> io::Result<()> {
        if self.key.is_some() {
            return Ok(());
        }
        if self.has_records()? {
            return Err(invalid("Protected account key is missing for existing encrypted records"));
        }
        let candidate = secretbox::gen_key();
        self.key = if platform_create_key(&self.root, &self.namespace, &candidate)? {
            Some(candidate)
        } else {
            Some(platform_load_key(&self.root, &self.namespace)?
                .ok_or_else(|| invalid("Protected account key creation did not leave a readable key"))?)
        };
        Ok(())
    }

    pub(super) fn read_account(&self) -> io::Result<Option<AccountRecord>> {
        let Some(record) = self.read_record(RecordKind::Account, RecordKind::Account.file())? else {
            // An unpublished first account staging file is not a committed
            // account. Any cache, however, must already have an account owner.
            for entry in fs::read_dir(&self.root)? {
                if owned_kind(&entry?.file_name()).is_some_and(|kind| !matches!(kind, RecordKind::Account)) {
                    return Err(invalid("Encrypted cache has no account owner record"));
                }
            }
            return Ok(None);
        };
        if record.revision != 0 {
            return Err(invalid("Invalid account record revision"));
        }
        let mut reader = Fields::new(record.payload.bytes());
        let metadata_revision = reader.u64()?;
        let ab_revision = reader.u64()?;
        let group_revision = reader.u64()?;
        let flags = reader.take(1)?[0];
        if flags & !3 != 0 {
            return Err(invalid("Invalid account cache presence flags"));
        }
        let token = reader.bytes(MAX_TOKEN_BYTES)?;
        let user_info = reader.bytes(MAX_USER_INFO_BYTES)?;
        reader.end()?;
        std::str::from_utf8(token).map_err(|_| invalid("Account token is not UTF-8"))?;
        std::str::from_utf8(user_info).map_err(|_| invalid("Account metadata is not UTF-8"))?;
        if token.is_empty() && (!user_info.is_empty() || flags != 0) {
            return Err(invalid("A revoked account record contains metadata or a persisted cache"));
        }
        if (flags & 1 != 0 && ab_revision == 0) || (flags & 2 != 0 && group_revision == 0) {
            return Err(invalid("Invalid committed cache generation"));
        }
        Ok(Some(AccountRecord {
            scope: record.scope,
            epoch: record.epoch,
            epoch_id: record.epoch_id,
            metadata_revision,
            ab_revision,
            group_revision,
            ab_present: flags & 1 != 0,
            group_present: flags & 2 != 0,
            token: SecretBytes::from_slice(token),
            user_info: SecretBytes::from_slice(user_info),
        }))
    }

    pub(super) fn write_account(&mut self, record: &AccountRecord) -> io::Result<()> {
        if record.token.bytes().len() > MAX_TOKEN_BYTES
            || record.user_info.bytes().len() > MAX_USER_INFO_BYTES
            || (record.token.is_empty() && (!record.user_info.is_empty() || record.ab_present || record.group_present))
        {
            return Err(invalid("Account record exceeds its bound or has revoked metadata"));
        }
        let metadata_revision = record.metadata_revision.to_le_bytes();
        let ab_revision = record.ab_revision.to_le_bytes();
        let group_revision = record.group_revision.to_le_bytes();
        let flags = [u8::from(record.ab_present) | (u8::from(record.group_present) << 1)];
        let token_length = (record.token.bytes().len() as u32).to_le_bytes();
        let info_length = (record.user_info.bytes().len() as u32).to_le_bytes();
        self.write_record(RecordKind::Account, RecordKind::Account.file(), &record.scope,
            record.epoch, &record.epoch_id, 0, &[&metadata_revision, &ab_revision,
                &group_revision, &flags, &token_length, record.token.bytes(),
                &info_length, record.user_info.bytes()])
    }

    pub(super) fn read_cache(&self, kind: RecordKind, account: &AccountRecord)
        -> io::Result<Option<SecretBytes>>
    {
        if !account.cache_present(kind)? {
            // Authenticated control explicitly says absent/cleared. Orphaned
            // uncommitted ciphertext is never a fallback or auto-deleted here.
            return Ok(None);
        }
        let record = self.read_record(kind, &account.cache_file(kind)?)?
            .ok_or_else(|| invalid("Committed encrypted account cache is missing"))?;
        if record.scope != account.scope || record.epoch != account.epoch
            || record.epoch_id != account.epoch_id || record.revision != account.revision(kind)?
        {
            return Err(invalid("Encrypted cache belongs to a retired account or cache generation"));
        }
        std::str::from_utf8(record.payload.bytes())
            .map_err(|_| invalid("Encrypted account cache is not UTF-8"))?;
        Ok(Some(record.payload))
    }

    pub(super) fn write_cache(&mut self, kind: RecordKind, account: &AccountRecord, value: &[u8])
        -> io::Result<()>
    {
        if account.token.is_empty() || !account.cache_present(kind)? {
            return Err(invalid("A cache cannot be persisted without a remembered account"));
        }
        // Publish a complete candidate first. The account control's later
        // atomic replacement is the commit point; the old version remains
        // readable if that commit fails before publication.
        self.write_record(kind, &account.cache_file(kind)?, &account.scope,
            account.epoch, &account.epoch_id, account.revision(kind)?, &[value])
    }

    pub(super) fn remove_cache(&self, kind: RecordKind) -> io::Result<()> {
        if matches!(kind, RecordKind::Account) {
            return Err(invalid("The durable account revocation record cannot be removed"));
        }
        self.prune(kind, None)
    }

    pub(super) fn remove_caches(&self) -> io::Result<()> {
        let ab = self.remove_cache(RecordKind::AddressBook);
        let group = self.remove_cache(RecordKind::Group);
        let account_temporaries = self.prune(RecordKind::Account, Some(RecordKind::Account.file()));
        combine(combine(ab, group), account_temporaries)
    }

    pub(super) fn prune_cache(&self, kind: RecordKind, account: &AccountRecord) -> io::Result<()> {
        let keep = if account.cache_present(kind)? { Some(account.cache_file(kind)?) } else { None };
        self.prune(kind, keep.as_deref())
    }

    fn prune(&self, kind: RecordKind, keep: Option<&str>) -> io::Result<()> {
        let mut result = Ok(());
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            if owned_kind(&name).is_some_and(|value| value.tag() == kind.tag())
                && name.to_str() != keep
            {
                result = combine(result, remove_temporary(&entry.path(), &self.root));
            }
        }
        result
    }

    fn read_record(&self, kind: RecordKind, name: &str) -> io::Result<Option<OpenedRecord>> {
        let mut options = OpenOptions::new();
        options.read(true);
        secure_options(&mut options);
        let file = match options.open(self.root.join(name)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        check_regular(&file)?;
        let max = kind.limit() + ENVELOPE_ALLOWANCE + FILE_ALLOWANCE;
        let length = file.metadata()?.len();
        if length > max as u64 {
            return Err(invalid("Encrypted account record exceeds its size bound"));
        }
        let mut ciphertext = Vec::with_capacity(length as usize);
        file.take(max as u64 + 1).read_to_end(&mut ciphertext)?;
        if ciphertext.len() > max || ciphertext.len() < FILE_ALLOWANCE
            || !ciphertext.starts_with(MAGIC)
        {
            return Err(invalid("Invalid encrypted account record envelope"));
        }
        let key = self.key.as_ref()
            .ok_or_else(|| invalid("Protected key is missing for an encrypted account record"))?;
        let nonce_start = MAGIC.len();
        let nonce_end = nonce_start + secretbox::NONCEBYTES;
        let nonce = secretbox::Nonce::from_slice(&ciphertext[nonce_start..nonce_end])
            .ok_or_else(|| invalid("Invalid account record nonce"))?;
        let mut plaintext = SecretBytes::from_vec(secretbox::open(&ciphertext[nonce_end..], &nonce, key)
            .map_err(|_| invalid("Account record authentication failed"))?);
        let mut reader = Fields::new(plaintext.bytes());
        if reader.take(DOMAIN.len())? != DOMAIN
            || reader.take(64)? != self.namespace.as_bytes()
            || reader.take(1)? != [kind.tag()]
        {
            return Err(invalid("Account record domain, profile or kind mismatch"));
        }
        let scope = std::str::from_utf8(reader.bytes(MAX_SCOPE_BYTES)?)
            .map_err(|_| invalid("Invalid account scope encoding"))?.to_owned();
        if scope.is_empty() {
            return Err(invalid("Empty account record scope"));
        }
        let epoch = reader.u64()?;
        let mut epoch_id = [0; 32];
        epoch_id.copy_from_slice(reader.take(32)?);
        let revision = reader.u64()?;
        if epoch == 0 || reader.rest().len() > kind.limit() {
            return Err(invalid("Invalid account record generation or payload bound"));
        }
        // Keep a view into the wiped allocation, not a second 256 MiB payload
        // allocation. The authenticated header is wiped with that allocation.
        plaintext.1 = plaintext.bytes().len() - reader.rest().len();
        Ok(Some(OpenedRecord {
            scope, epoch, epoch_id, revision, payload: plaintext,
        }))
    }

    fn write_record(&mut self, kind: RecordKind, name: &str, scope: &str, epoch: u64,
        epoch_id: &[u8; 32], revision: u64, parts: &[&[u8]]) -> io::Result<()>
    {
        let payload_len = parts.iter().try_fold(0usize, |total, part| total.checked_add(part.len()))
            .ok_or_else(|| invalid("Account record payload size overflow"))?;
        if scope.is_empty() || scope.len() > MAX_SCOPE_BYTES || epoch == 0
            || payload_len > kind.limit()
        {
            return Err(invalid("Invalid account record scope, generation or size"));
        }
        self.ensure_key()?;
        let key = self.key.as_ref()
            .ok_or_else(|| io::Error::other("Protected account key unavailable"))?;
        let capacity = DOMAIN.len() + 64 + 1 + 4 + scope.len() + 16 + 32 + payload_len;
        let mut plaintext = SecretBytes::from_vec(Vec::with_capacity(capacity));
        plaintext.0.extend_from_slice(DOMAIN);
        plaintext.0.extend_from_slice(self.namespace.as_bytes());
        plaintext.0.push(kind.tag());
        append_bytes(&mut plaintext.0, scope.as_bytes())?;
        plaintext.0.extend_from_slice(&epoch.to_le_bytes());
        plaintext.0.extend_from_slice(epoch_id);
        plaintext.0.extend_from_slice(&revision.to_le_bytes());
        for part in parts { plaintext.0.extend_from_slice(part); }
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(plaintext.bytes(), &nonce, key);
        drop(plaintext);
        self.publish(name, &nonce, &ciphertext)
    }

    fn publish(&self, name: &str, nonce: &secretbox::Nonce, ciphertext: &[u8]) -> io::Result<()> {
        let mut suffix = [0u8; 16];
        randombytes::randombytes_into(&mut suffix);
        let temporary = self.root.join(format!("{name}.tmp-{}", hex(&suffix)));
        let destination = self.root.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_options(&mut options);
        let mut file = options.open(&temporary)?;
        let staged = (|| {
            file.write_all(MAGIC)?;
            file.write_all(&nonce.0)?;
            file.write_all(ciphertext)?;
            file.sync_all()
        })();
        drop(file);
        if let Err(error) = staged {
            return combine(Err(error), remove_temporary(&temporary, &self.root));
        }
        if let Err(error) = replace_file(&temporary, &destination) {
            return combine(Err(error), remove_temporary(&temporary, &self.root));
        }
        #[cfg(not(windows))]
        sync_directory(&self.root)?;
        // Windows publication already used native WRITE_THROUGH replacement.
        Ok(())
    }
}

fn platform_load_key(root: &Path, namespace: &str) -> io::Result<Option<secretbox::Key>> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows",
        target_os = "android", all(target_os = "linux", not(target_env = "ohos"))))]
    { backend::load_key(root, namespace) }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows",
        target_os = "android", all(target_os = "linux", not(target_env = "ohos")))))]
    { let _ = (root, namespace); Err(io::Error::new(io::ErrorKind::Unsupported,
        "Official account protected storage is unsupported on this target")) }
}

fn platform_create_key(root: &Path, namespace: &str, key: &secretbox::Key) -> io::Result<bool> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows",
        target_os = "android", all(target_os = "linux", not(target_env = "ohos"))))]
    { backend::create_key(root, namespace, key) }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows",
        target_os = "android", all(target_os = "linux", not(target_env = "ohos")))))]
    { let _ = (root, namespace, key); Err(io::Error::new(io::ErrorKind::Unsupported,
        "Official account protected storage is unsupported on this target")) }
}

fn location() -> io::Result<(PathBuf, String)> {
    let profile = Config::path("");
    if !profile.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::NotFound,
            "Application private account directory has not been initialized"));
    }
    let app_name = APP_NAME.read().map_err(|_| io::Error::other("Application name lock poisoned"))?;
    let mut identity = Vec::from(&b"rd-engine/official-account/profile/v1\0"[..]);
    identity.extend_from_slice(app_name.as_bytes());
    identity.push(0);
    // as_encoded_bytes preserves platform-native path identity without a lossy
    // conversion; this value is neither an engine identity nor encryption key.
    identity.extend_from_slice(profile.as_os_str().as_encoded_bytes());
    let namespace = hex(&sha256::hash(&identity).0);
    #[cfg(target_os = "windows")]
    let base = {
        let directory = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound,
                "Current-user LOCALAPPDATA is unavailable for account storage"))?;
        directory.join("rd-engine").join("official-account")
    };
    #[cfg(not(target_os = "windows"))]
    let base = profile.join("official-account");
    private_directory(&base)?;
    Ok((base.join(&namespace), namespace))
}

fn private_directory(path: &Path) -> io::Result<()> {
    let missing = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("Account storage root is not a private directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { hbb_common::libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "Account storage directory is not private to the current user"));
        }
    }
    #[cfg(not(windows))]
    if missing {
        let parent = path.parent().ok_or_else(|| invalid("Account root has no parent"))?;
        sync_directory(parent)?;
    }
    #[cfg(windows)]
    let _ = missing;
    Ok(())
}

fn secure_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(hbb_common::libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Opening the reparse point itself prevents following a substituted
        // symlink; check_regular rejects it before any data is consumed.
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
}

fn check_regular(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("Account storage entry is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { hbb_common::libc::geteuid() }
            || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "Account storage entry is not private to the current user"));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // The complete ciphertext was flushed first. Request durable replacement;
    // unlike remove-then-rename this never exposes a truncated account record.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}


fn remove_temporary(path: &Path, root: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            #[cfg(not(windows))]
            sync_directory(root)?;
            #[cfg(windows)]
            let _ = root;
            // Windows deletion has no directory-fsync equivalent. Its native
            // error is checked; durable revocation was published with
            // WRITE_THROUGH before any retired live record is removed.
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn owned_kind(name: &std::ffi::OsStr) -> Option<RecordKind> {
    let name = name.to_str()?;
    let base = match name.rsplit_once(".tmp-") {
        Some((base, suffix)) if lower_hex(suffix, 32) => base,
        Some(_) => return None,
        None => name,
    };
    for kind in [RecordKind::Account, RecordKind::AddressBook, RecordKind::Group] {
        if base == kind.file() { return Some(kind); }
        if !matches!(kind, RecordKind::Account) {
            if let Some(suffix) = base.strip_prefix(kind.file()).and_then(|value| value.strip_prefix('.')) {
                if let Some((epoch_id, revision)) = suffix.split_once('.') {
                    if lower_hex(epoch_id, 64) && lower_hex(revision, 16) { return Some(kind); }
                }
            }
        }
    }
    None
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn combine(first: io::Result<()>, second: io::Result<()>) -> io::Result<()> {
    match (first, second) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(first), Err(second)) => Err(io::Error::new(first.kind(),
            format!("{first}; encrypted account cleanup also failed: {second}"))),
    }
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| invalid("Account field is too large"))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Fields<'a> {
    remaining: &'a [u8],
}

impl<'a> Fields<'a> {
    fn new(remaining: &'a [u8]) -> Self { Self { remaining } }
    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        if count > self.remaining.len() {
            return Err(invalid("Truncated authenticated account record"));
        }
        let (field, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        Ok(field)
    }
    fn u64(&mut self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }
    fn bytes(&mut self, max: usize) -> io::Result<&'a [u8]> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4)?);
        let length = u32::from_le_bytes(bytes) as usize;
        if length > max { return Err(invalid("Account field exceeds its size bound")); }
        self.take(length)
    }
    fn rest(&self) -> &'a [u8] { self.remaining }
    fn end(&self) -> io::Result<()> {
        if self.remaining.is_empty() { Ok(()) }
        else { Err(invalid("Unexpected authenticated account record fields")) }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 15) as usize] as char);
    }
    value
}
