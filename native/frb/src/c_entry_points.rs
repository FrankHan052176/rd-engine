//! The C entry points the official client's runners load, and the frame pointer
//! its Dart reads.
//!
//! These mirror the pinned pure upstream `src/flutter.rs` exports and live
//! outside `client_compat.rs` on
//! purpose: that file is the flutter_rust_bridge input, whose parser would try to
//! turn raw pointers and `wchar_t` buffers into wire functions.
//!
//! Where each one is asked for:
//!
//! * `flutter/windows/runner/main.cpp` loads `rustdesk_core_main_args`,
//!   `free_c_args`, `rustdesk_is_disable_installation` and
//!   `get_rustdesk_app_name` before it starts the window. A missing symbol is
//!   `EXIT_FAILURE`, and a null answer from the first one exits without a UI.
//! * `flutter/macos/Runner/MainFlutterWindow.swift` calls `rustdesk_core_main`.
//! * `flutter/lib/models/native_model.dart` looks `session_get_rgba` up on the
//!   loaded library and reads the frame it points at, so its absence would leave
//!   the client without a picture.

use crate::client_compat;
use std::ffi::{c_char, c_int, CStr, CString};

/// The Windows runner's `FUNC_RUSTDESK_CORE_MAIN`: the core's own main answers
/// with the arguments the Flutter side should also see. This engine has no core
/// main that parses a command line, so the list is empty - and an empty list is
/// the runner's "carry on and start the UI", which is what the engine wants.
#[no_mangle]
pub extern "C" fn rustdesk_core_main_args(args_len: *mut c_int) -> *mut *mut c_char {
    rust_args_to_c_args(Vec::new(), args_len)
}

/// The argv array the runner takes, in the layout it frees through
/// `free_c_args`: null-terminated strings as raw pointers, and the count written
/// back through `outlen`. Mirrors `rust_args_to_c_args` in the client's core.
fn rust_args_to_c_args(args: Vec<String>, outlen: *mut c_int) -> *mut *mut c_char {
    let mut pointers = Vec::with_capacity(args.len());
    for arg in args {
        match CString::new(arg) {
            Ok(arg) => pointers.push(arg.into_raw()),
            Err(_) => {
                // An argument with a NUL in it cannot travel; the core refuses
                // the whole list, and so does this.
                for pointer in pointers {
                    drop(unsafe { CString::from_raw(pointer) });
                }
                if !outlen.is_null() {
                    unsafe { std::ptr::write(outlen, 0) };
                }
                return std::ptr::null_mut();
            }
        }
    }
    pointers.shrink_to_fit();
    let len = pointers.len();
    let pointer = pointers.as_mut_ptr();
    std::mem::forget(pointers);
    if !outlen.is_null() {
        unsafe { std::ptr::write(outlen, len as c_int) };
    }
    pointer
}

/// Frees what `rustdesk_core_main_args` handed over. The runner calls this with
/// the length it was given, so the pointer comes back as the vector it was.
#[no_mangle]
pub unsafe extern "C" fn free_c_args(pointer: *mut *mut c_char, len: c_int) {
    if pointer.is_null() || len <= 0 {
        // The empty answer has no allocation behind it, which is what the
        // runner's zero length means.
        return;
    }
    let len = len as usize;
    let pointers = Vec::from_raw_parts(pointer, len, len);
    for arg in pointers {
        if !arg.is_null() {
            drop(CString::from_raw(arg));
        }
    }
}

/// The Windows runner removes its injected `--install` when this is non-zero.
/// Share the FRB viewer-only capability: this artifact has no installer even
/// when the upstream store's independent hard option is unset.
#[no_mangle]
pub extern "C" fn rustdesk_is_disable_installation() -> c_int {
    c_int::from(client_compat::is_disable_installation().0)
}

/// The Windows runner's `FUNC_RUSTDESK_GET_APP_NAME`: writes the application
/// name into the caller's buffer as UTF-16 with a terminator. `0` means the name
/// fitted; anything else means the buffer was too short, which is how the
/// client's own core answers too.
#[no_mangle]
pub unsafe extern "C" fn get_rustdesk_app_name(buffer: *mut u16, length: c_int) -> c_int {
    if buffer.is_null() {
        return -1;
    }
    let name: Vec<u16> = client_compat::APP_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    if length > name.len() as c_int {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buffer, name.len());
        return 0;
    }
    -1
}

/// The macOS runner's entry point. The client's core answers whether the app
/// keeps running - its own main exits the process for a service-only invocation.
/// The engine has no such branch, so the UI always starts.
#[cfg(not(windows))]
#[no_mangle]
pub extern "C" fn rustdesk_core_main() -> bool {
    true
}

/// The frame the client's Dart reads. `native_model.dart` looks this symbol up
/// as `Pointer<Uint8> Function(Pointer<Utf8>, Int32)` and calls it after an
/// `Rgba` event, then reads `session_get_rgba_size` bytes from the answer.
///
/// The second argument is an `Int32` in that typedef, so it is read as one: a
/// `usize` here would read undefined upper bits. The engine publishes display 0
/// and answers null for any other display, or for a session it does not know.
#[no_mangle]
pub unsafe extern "C" fn session_get_rgba(
    session_uuid_str: *const c_char,
    display: c_int,
) -> *const u8 {
    if session_uuid_str.is_null() || display != 0 {
        return std::ptr::null();
    }
    let Ok(session_id) = CStr::from_ptr(session_uuid_str).to_str() else {
        return std::ptr::null();
    };
    client_compat::rgba_pointer(session_id, 0)
}
