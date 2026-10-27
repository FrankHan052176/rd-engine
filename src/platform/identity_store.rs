//! Private, create-only storage for an engine identity. There is deliberately no
//! plaintext fallback, overwrite, deletion, or implicit identity migration.
use super::Record;
use std::io;

#[cfg(target_env = "ohos")]
use ohos as platform;
#[cfg(any(target_os = "windows", dsh_windows_typecheck))]
use windows as platform;

pub(super) fn load(slot: &str) -> io::Result<Option<Record>> {
    #[cfg(any(target_env = "ohos", target_os = "windows", dsh_windows_typecheck))]
    return platform::load(slot);
    #[cfg(not(any(target_env = "ohos", target_os = "windows", dsh_windows_typecheck)))]
    {
        let _ = slot;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Protected identity storage is unavailable on this platform",
        ))
    }
}

/// False means an existing record won the create-only race. The caller must
/// load that record and must not use its unpersisted candidate.
pub(super) fn create(slot: &str, record: &Record) -> io::Result<bool> {
    #[cfg(any(target_env = "ohos", target_os = "windows", dsh_windows_typecheck))]
    return platform::create(slot, record);
    #[cfg(not(any(target_env = "ohos", target_os = "windows", dsh_windows_typecheck)))]
    {
        let _ = (slot, record);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Protected identity storage is unavailable on this platform",
        ))
    }
}

#[cfg(any(target_os = "windows", dsh_windows_typecheck))]
mod windows {
    use super::*;
    use hbb_common::{sodiumoxide::utils::memzero, uuid::Uuid};
    use std::{
        ffi::c_void,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        path::PathBuf,
        ptr,
    };

    const MAX_CIPHERTEXT_BYTES: usize = 4096;
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 1;

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
    }

    struct ProtectedBuffer {
        blob: Blob,
        plaintext: bool,
    }
    impl Drop for ProtectedBuffer {
        fn drop(&mut self) {
            if !self.blob.data.is_null() {
                // DPAPI owns this documented LocalAlloc result until LocalFree.
                unsafe {
                    if self.plaintext {
                        memzero(std::slice::from_raw_parts_mut(
                            self.blob.data,
                            self.blob.size as usize,
                        ));
                    }
                    LocalFree(self.blob.data.cast());
                }
            }
        }
    }
    impl ProtectedBuffer {
        fn bytes(&self) -> io::Result<&[u8]> {
            if self.blob.data.is_null()
                || self.blob.size == 0
                || self.blob.size as usize > MAX_CIPHERTEXT_BYTES
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid DPAPI output",
                ));
            }
            // Owned until this guard drops; the result is immutable to callers.
            Ok(unsafe { std::slice::from_raw_parts(self.blob.data, self.blob.size as usize) })
        }
    }

    fn crypt(slot: &str, bytes: &[u8], protect: bool) -> io::Result<ProtectedBuffer> {
        let size = u32::try_from(bytes.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Identity envelope too large")
        })?;
        let entropy = format!("rd-engine.identity.v2:{slot}");
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
        // User-bound DPAPI, not CRYPTPROTECT_LOCAL_MACHINE. Inputs are documented
        // read-only even though DATA_BLOB carries a mutable pointer in the SDK.
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
            return Err(io::Error::last_os_error());
        }
        Ok(output)
    }

    fn path(slot: &str) -> io::Result<PathBuf> {
        let root = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Windows per-user application data directory unavailable",
                )
            })?;
        Ok(root
            .join("rd-engine")
            .join("identities")
            .join(format!("{slot}.dpapi")))
    }

    pub(super) fn load(slot: &str) -> io::Result<Option<Record>> {
        let path = path(slot)?;
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CIPHERTEXT_BYTES as u64
        {
            return Err(super::super::corrupt());
        }
        let mut encrypted = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_CIPHERTEXT_BYTES as u64 + 1)
            .read_to_end(&mut encrypted)?;
        if encrypted.len() > MAX_CIPHERTEXT_BYTES {
            return Err(super::super::corrupt());
        }
        let clear = crypt(slot, &encrypted, false)?;
        Record::from_bytes(clear.bytes()?).map(Some)
    }

    struct TemporaryFile(PathBuf);
    impl Drop for TemporaryFile {
        fn drop(&mut self) {
            // Only our own uniquely created ciphertext staging file, never the
            // identity or a pre-existing file belonging to the caller.
            let _ = fs::remove_file(&self.0);
        }
    }

    pub(super) fn create(slot: &str, record: &Record) -> io::Result<bool> {
        let final_path = path(slot)?;
        let directory = final_path
            .parent()
            .ok_or_else(|| io::Error::other("Invalid identity directory"))?;
        fs::create_dir_all(directory)?;
        let encrypted = crypt(slot, &record.0, true)?;
        let temporary_path = directory.join(format!(".{slot}-{}.pending", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        let temporary = TemporaryFile(temporary_path);
        file.write_all(encrypted.bytes()?)?;
        file.sync_all()?;
        drop(file);
        // A same-directory hard link atomically publishes the fully flushed
        // ciphertext without replacing a concurrent winner. Unsupported file
        // systems fail explicitly; there is no partially written final record.
        match fs::hard_link(&temporary.0, &final_path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_env = "ohos")]
mod ohos {
    use super::*;
    use hbb_common::sodiumoxide::utils::memzero;
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
    fn error(code: i32) -> io::Error {
        let kind = if matches!(code, 201 | 24_000_004 | 24_000_005) {
            io::ErrorKind::PermissionDenied
        } else if code == 24_000_007 {
            io::ErrorKind::InvalidData
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(
            kind,
            format!("Protected identity Asset Store operation failed ({code})"),
        )
    }

    struct Results(ResultSet);
    impl Drop for Results {
        fn drop(&mut self) {
            // The query requests at most two records. These are SDK-owned,
            // writable result buffers; wipe returned SECRET before freeing.
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

    pub(super) fn load(slot: &str) -> io::Result<Option<Record>> {
        let alias = format!("rd-engine.identity.v2.{slot}");
        let query = [
            blob(ALIAS, alias.as_bytes()),
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
            return Err(super::super::corrupt());
        }
        let attr = unsafe { OH_Asset_ParseAttr(results.0.results, SECRET) };
        if attr.is_null() {
            return Err(super::super::corrupt());
        }
        let secret = unsafe { (*attr).value.blob };
        if secret.data.is_null() || secret.size as usize != super::super::RECORD_BYTES {
            return Err(super::super::corrupt());
        }
        // The result guard owns this memory until after the bounded copy.
        Record::from_bytes(unsafe { std::slice::from_raw_parts(secret.data, secret.size as usize) })
            .map(Some)
    }

    pub(super) fn create(slot: &str, record: &Record) -> io::Result<bool> {
        let alias = format!("rd-engine.identity.v2.{slot}");
        let attrs = [
            blob(ALIAS, alias.as_bytes()),
            blob(SECRET, &record.0),
            number(ACCESSIBILITY, 2), // Only while the device is unlocked.
            number(SYNC_TYPE, 0),     // Never sync this installation's identity.
            number(CONFLICT_RESOLUTION, 1), // Never overwrite another creator.
        ];
        // No IS_PERSISTENT, GROUP_ID, or plaintext DATA_LABEL attributes.
        let code = unsafe { OH_Asset_Add(attrs.as_ptr(), attrs.len() as u32) };
        match code {
            0 => Ok(true),
            DUPLICATED => Ok(false),
            _ => Err(error(code)),
        }
    }
}
