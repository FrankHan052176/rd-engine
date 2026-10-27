//! AndroidKeyStore-backed account master keys, via the official Android runner.
//!
//! The companion implementation and its actual Application/FFI callsite are in
//! `native/frb/patches/official-client-account-storage.patch`, pinned to upstream
//! 092a961b629d318fe290eeafac0cd214a1e9deeb. This is missing platform integration,
//! not an upstream account-storage transplant. API 23+ uses AndroidKeyStore
//! AES-GCM. API 22 uses the attributed legacy OS RSA wrapping pattern plus an
//! OS-private-key SHA256withRSA signature, verified before unwrap. No raw OS key
//! is exported and no software/plaintext protection fallback exists.
//!
//! The common store holds its cross-process namespace lock throughout these
//! blocking calls. Java retains only the Application context, never the borrowed
//! direct key buffers. Its non-exportable OS key wraps the independently random
//! common master key. Disk holds authenticated ciphertext and one non-secret
//! immutable generation reservation. A fresh random alias avoids Android's
//! ambiguous absence checks; an existing reservation never permits regeneration.

use hbb_common::sodiumoxide::crypto::secretbox::{self, Key};
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JObject, JValue},
    sys::jint,
};
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::OnceLock,
};

const KEY_CALL_SIGNATURE: &str = "(Ljava/lang/String;Ljava/lang/String;Ljava/nio/ByteBuffer;)I";
const SUCCESS: jint = 1;
const ABSENT_OR_EXISTS: jint = 0;
const UNSUPPORTED: jint = -1;
const LOCKED: jint = -2;
const UNAVAILABLE: jint = -3;
const CORRUPT: jint = -4;
const DENIED: jint = -5;
const IO_FAILURE: jint = -6;
const DUPLICATE: jint = -7;
const INVALID_ARGUMENT: jint = -8;
const SECURE_LOCK_REQUIRED: jint = -9;
const INCOMPLETE_INITIALIZATION: jint = -10;

struct AndroidStorage {
    vm: JavaVM,
    helper: GlobalRef,
}

static STORAGE: OnceLock<AndroidStorage> = OnceLock::new();

/// Called once by the pinned MainApplication, after its unchanged onAppStart.
///
/// Main reexports this through the FRB cdylib so dependency dead stripping cannot
/// make the Kotlin native declaration an unused or unresolved helper. This does
/// not replace JNI_OnLoad, the official application callback, NDK context setup,
/// or the service/media lifecycle. The JavaVM is the one of this existing runner.
/// A repeated initialization is an explicit DUPLICATE, not replacement of a live
/// application context. The Kotlin callsite checks the status before proceeding.
#[unsafe(export_name = "Java_ffi_FFI_initAccountStorage")]
pub extern "system" fn init_account_storage(
    mut env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    helper: JObject<'_>,
) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if helper.is_null() {
            return INVALID_ARGUMENT;
        }
        if STORAGE.get().is_some() {
            return DUPLICATE;
        }
        let setup = (|| -> jni::errors::Result<AndroidStorage> {
            // Resolve through the actual application object, not FindClass on a
            // native worker (whose class loader cannot see application classes).
            let class = env.get_object_class(&helper)?;
            env.get_method_id(&class, "loadKey", KEY_CALL_SIGNATURE)?;
            env.get_method_id(&class, "createKey", KEY_CALL_SIGNATURE)?;
            Ok(AndroidStorage {
                vm: env.get_java_vm()?,
                helper: env.new_global_ref(&helper)?,
            })
        })();
        match setup {
            Ok(storage) => match STORAGE.set(storage) {
                Ok(()) => SUCCESS,
                Err(_) => DUPLICATE,
            },
            Err(_) => {
                // The JNI status, not a raw Java exception/log, crosses back.
                // If clearing itself fails, JNI still propagates that exception.
                if env.exception_clear().is_err() {
                    return UNAVAILABLE;
                }
                UNAVAILABLE
            }
        }
    }));
    match result {
        Ok(status) => status,
        Err(_) => UNAVAILABLE,
    }
}

pub(super) fn load_key(root: &Path, namespace: &str) -> io::Result<Option<Key>> {
    // Key's Drop wipes even a partially written result on every failure path.
    let mut key = Key([0; secretbox::KEYBYTES]);
    match call_key_method("loadKey", root, namespace, &mut key)? {
        SUCCESS => Ok(Some(key)),
        ABSENT_OR_EXISTS => Ok(None),
        status => Err(status_error(status)),
    }
}

pub(super) fn create_key(root: &Path, namespace: &str, key: &Key) -> io::Result<bool> {
    // JNI DirectByteBuffer requires writable memory. A private 32-byte copy
    // avoids exposing the caller's shared &Key as mutable; Key wipes it on Drop.
    let mut candidate = key.clone();
    match call_key_method("createKey", root, namespace, &mut candidate)? {
        SUCCESS => Ok(true),
        // Only a valid existing ciphertext wins. The caller must load its key,
        // never use this losing candidate. Corrupt existing data is an error.
        ABSENT_OR_EXISTS => Ok(false),
        status => Err(status_error(status)),
    }
}

fn call_key_method(
    method: &str,
    root: &Path,
    namespace: &str,
    key: &mut Key,
) -> io::Result<jint> {
    let root = root.to_str().ok_or_else(|| status_error(INVALID_ARGUMENT))?;
    if root.is_empty()
        || root.len() > 4096
        || root.contains('\0')
        || namespace.len() != 64
        || !namespace.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(status_error(INVALID_ARGUMENT));
    }
    let storage = STORAGE.get().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "Android account storage is unavailable: runner initialization is missing",
        )
    })?;
    let mut env = storage.vm.attach_current_thread().map_err(|_| status_error(UNAVAILABLE))?;
    let result = env.with_local_frame(8, |env| -> jni::errors::Result<jint> {
        let root = env.new_string(root)?;
        let namespace = env.new_string(namespace)?;
        // SAFETY: this unique Key borrow outlives the synchronous Java call and
        // its local frame. The recorded helper never retains, returns, queues or
        // shares the buffer, and copies only KEYBYTES. No Java reference to the
        // native allocation survives the local frame or the Key's lifetime.
        let buffer = unsafe {
            env.new_direct_byte_buffer(key.0.as_mut_ptr(), secretbox::KEYBYTES)?
        };
        env.call_method(
            storage.helper.as_obj(),
            method,
            KEY_CALL_SIGNATURE,
            &[
                JValue::Object(root.as_ref()),
                JValue::Object(namespace.as_ref()),
                JValue::Object(buffer.as_ref()),
            ],
        )?
        .i()
    });
    match result {
        Ok(status) => Ok(status),
        Err(_) => {
            // No Throwable.toString(), messages, paths or crypto input are
            // copied into diagnostics. Also leave attached FRB workers clean.
            env.exception_clear().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Android account storage is unavailable: JNI exception cleanup failed",
                )
            })?;
            Err(status_error(UNAVAILABLE))
        }
    }
}

fn status_error(status: jint) -> io::Error {
    let (kind, message) = match status {
        UNSUPPORTED => (
            io::ErrorKind::Unsupported,
            "Android account storage requires API 22+ and the reserved OS key algorithm",
        ),
        LOCKED => (
            io::ErrorKind::PermissionDenied,
            "Android account storage is locked; no authentication prompt was requested",
        ),
        UNAVAILABLE => (
            io::ErrorKind::NotConnected,
            "Android account storage or AndroidKeyStore is unavailable",
        ),
        CORRUPT => (
            io::ErrorKind::InvalidData,
            "Android account master key is corrupt, invalidated or missing its wrapping key",
        ),
        DENIED => (
            io::ErrorKind::PermissionDenied,
            "Android account storage access or its private application boundary was denied",
        ),
        IO_FAILURE => (
            io::ErrorKind::Other,
            "Android account master key I/O or durable publication failed",
        ),
        DUPLICATE => (
            io::ErrorKind::AlreadyExists,
            "Android account storage initialization, OS alias or staging name is duplicated",
        ),
        INVALID_ARGUMENT => (
            io::ErrorKind::InvalidInput,
            "Android account storage received an invalid path, namespace or key buffer",
        ),
        SECURE_LOCK_REQUIRED => (
            io::ErrorKind::PermissionDenied,
            "Android legacy account protection requires an existing secure screen lock; none was requested",
        ),
        INCOMPLETE_INITIALIZATION => (
            io::ErrorKind::NotConnected,
            "Android account key initialization is incomplete or its reserved OS key is unavailable; automatic regeneration is forbidden",
        ),
        _ => (
            io::ErrorKind::InvalidData,
            "Android account storage returned an unknown provider status",
        ),
    };
    io::Error::new(kind, message)
}
