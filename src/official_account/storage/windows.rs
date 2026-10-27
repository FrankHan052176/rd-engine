//! Account-only current-user DPAPI master-key storage.
//!
//! The DATA_BLOB/LocalFree ownership and plaintext wiping follow the existing
//! `platform::identity_store::windows` mechanism, not its identity record or
//! path. This is a new platform adapter, not an upstream account-store import.
//! The caller owns the cross-process lock and supplies an existing private,
//! namespace-selected account directory. DPAPI protects the Windows user, not
//! other applications running as that same user; the entropy is domain binding,
//! not another secret.

use hbb_common::{
    sodiumoxide::{crypto::secretbox, utils::memzero},
    uuid::Uuid,
};
use std::{
    ffi::c_void,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::windows::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}},
    path::{Path, PathBuf},
    ptr,
};

const KEY_FILE_NAME: &str = "account-master-key.v1.dpapi";
// This bounds a DPAPI envelope containing only a 32-byte master key, not caches
// or credentials and not the immutable identity store's record-size contract.
const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 1;
const FILE_SHARE_READ: u32 = 1;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const MOVEFILE_WRITE_THROUGH: u32 = 8;
const ERROR_FILE_NOT_FOUND: i32 = 2;

#[repr(C)]
struct Blob {
    size: u32,
    data: *mut u8,
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        input: *mut Blob,
        description: *const u16,
        entropy: *mut Blob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
    fn CryptUnprotectData(
        input: *mut Blob,
        description: *mut *mut u16,
        entropy: *mut Blob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(pointer: *mut c_void) -> *mut c_void;
    fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
}

struct ProtectedBuffer {
    blob: Blob,
    plaintext: bool,
}

impl ProtectedBuffer {
    fn bytes(&self) -> io::Result<&[u8]> {
        let length = self.blob.size as usize;
        if self.blob.data.is_null()
            || length == 0
            || length > MAX_CIPHERTEXT_BYTES
            || (self.plaintext && length != secretbox::KEYBYTES)
        {
            return Err(corrupt());
        }
        // DPAPI owns this allocation until release/Drop. Its documented output
        // length has been checked before constructing the borrowed slice.
        Ok(unsafe { std::slice::from_raw_parts(self.blob.data, length) })
    }

    fn release(&mut self) -> io::Result<()> {
        if self.blob.data.is_null() {
            return Ok(());
        }
        // Both successful and rejected decryptions must wipe all native output,
        // including a correctly allocated output whose length is not 32 bytes.
        unsafe {
            if self.plaintext {
                memzero(std::slice::from_raw_parts_mut(
                    self.blob.data,
                    self.blob.size as usize,
                ));
                self.plaintext = false;
            }
            if !LocalFree(self.blob.data.cast()).is_null() {
                return Err(io::Error::last_os_error());
            }
        }
        self.blob.data = ptr::null_mut();
        self.blob.size = 0;
        Ok(())
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        // Normal/error returns explicitly check release; this also covers unwind
        // and makes a final release attempt after a reported LocalFree failure.
        let _ = self.release();
    }
}

fn corrupt() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid account master-key data")
}

fn with_cleanup<T>(result: io::Result<T>, cleanup: io::Result<()>) -> io::Result<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(io::Error::new(
            error.kind(),
            format!("Account key operation failed ({error}); cleanup failed ({cleanup})"),
        )),
    }
}

fn entropy(namespace: &str) -> io::Result<String> {
    // The common store supplies a lowercase SHA-256 application/profile digest.
    if namespace.len() != 64
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid account storage namespace",
        ));
    }
    Ok(format!("rd-engine.official-account.master-key.v1:{namespace}"))
}

fn crypt(entropy: &str, bytes: &[u8], protect: bool) -> io::Result<ProtectedBuffer> {
    let size = u32::try_from(bytes.len()).map_err(|_| corrupt())?;
    if bytes.is_empty()
        || bytes.len() > MAX_CIPHERTEXT_BYTES
        || (protect && bytes.len() != secretbox::KEYBYTES)
    {
        return Err(corrupt());
    }
    let mut input = Blob {
        size,
        data: bytes.as_ptr().cast_mut(),
    };
    let mut extra = Blob {
        size: entropy.len() as u32,
        data: entropy.as_ptr().cast_mut(),
    };
    let mut output = ProtectedBuffer {
        blob: Blob {
            size: 0,
            data: ptr::null_mut(),
        },
        plaintext: !protect,
    };
    // DATA_BLOB pointers are mutable in the SDK but these inputs are read-only.
    // No machine-wide, audit, prompt, or automatic reprotection flags are used.
    let result = unsafe {
        if protect {
            CryptProtectData(
                &mut input,
                ptr::null(),
                &mut extra,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.blob,
            )
        } else {
            CryptUnprotectData(
                &mut input,
                ptr::null_mut(),
                &mut extra,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.blob,
            )
        }
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        return with_cleanup(Err(error), output.release());
    }
    Ok(output)
}

fn key_path(root: &Path) -> io::Result<PathBuf> {
    // Besides supporting long Windows paths for the later native rename, this
    // keeps an unavailable root distinct from a genuinely absent key file.
    let directory = fs::canonicalize(root)?;
    if !fs::metadata(&directory)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Account storage root is not a directory",
        ));
    }
    Ok(directory.join(KEY_FILE_NAME))
}

fn load_at(path: &Path, entropy: &str) -> io::Result<Option<secretbox::Key>> {
    let file = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        // ERROR_PATH_NOT_FOUND and other unavailable-root errors are not absence.
        Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() == 0
        || metadata.len() > MAX_CIPHERTEXT_BYTES as u64
    {
        return Err(corrupt());
    }
    let mut encrypted = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CIPHERTEXT_BYTES as u64 + 1)
        .read_to_end(&mut encrypted)?;
    if encrypted.len() as u64 != metadata.len() || encrypted.len() > MAX_CIPHERTEXT_BYTES {
        return Err(corrupt());
    }
    let mut clear = crypt(entropy, &encrypted, false)?;
    let key = clear
        .bytes()
        .and_then(|bytes| secretbox::Key::from_slice(bytes).ok_or_else(corrupt));
    with_cleanup(key, clear.release()).map(Some)
}

pub(super) fn load_key(root: &Path, namespace: &str) -> io::Result<Option<secretbox::Key>> {
    let entropy = entropy(namespace)?;
    load_at(&key_path(root)?, &entropy)
}

fn publish_add_only(temporary: &Path, destination: &Path) -> io::Result<()> {
    let temporary: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
    // Both names are in the same canonicalized directory. No REPLACE_EXISTING or
    // COPY_ALLOWED: publication is a rename, cannot clobber an existing entry,
    // and cannot fall back to a partially written copy. WRITE_THROUGH requests
    // completion on disk, after the staging file's checked sync_all below.
    if unsafe { MoveFileExW(temporary.as_ptr(), destination.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn create_key(
    root: &Path,
    namespace: &str,
    key: &secretbox::Key,
) -> io::Result<bool> {
    let entropy = entropy(namespace)?;
    let path = key_path(root)?;
    // A directory, corrupt envelope, wrong user's key, or denied read is an
    // error, not a duplicate. The transient loaded key zeroizes on drop.
    if load_at(&path, &entropy)?.is_some() {
        return Ok(false);
    }
    let mut encrypted = crypt(&entropy, key.as_ref(), true)?;
    let temporary = path.with_file_name(format!(".account-master-key-{}.pending", Uuid::new_v4()));
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&temporary)
    {
        Ok(file) => file,
        // A staging-name collision is not evidence of an existing master key.
        Err(error) => return with_cleanup(Err(error), encrypted.release()),
    };
    let staged = (|| {
        file.write_all(encrypted.bytes()?)?;
        file.sync_all()
    })();
    drop(file);
    let staged = with_cleanup(staged, encrypted.release());
    if let Err(error) = staged {
        return with_cleanup(Err(error), fs::remove_file(&temporary));
    }
    match publish_add_only(&temporary, &path) {
        Ok(()) => Ok(true),
        Err(error) => {
            // Delete only our own create_new ciphertext staging file. A cleanup
            // error must not be reported as either successful election outcome.
            let already_exists = error.kind() == io::ErrorKind::AlreadyExists;
            let result = if already_exists {
                match load_at(&path, &entropy) {
                    Ok(Some(_)) => Ok(false),
                    Ok(None) => Err(error),
                    Err(error) => Err(error),
                }
            } else {
                Err(error)
            };
            with_cleanup(result, fs::remove_file(&temporary))
        }
    }
}
