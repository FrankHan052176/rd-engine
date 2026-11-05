//! Terminal-failure provenance for the RFB wire.
//!
//! `RfbError::Transport` is deliberately one value, so the viewer's terminal
//! state cannot say whether the peer closed, a read timed out, a syscall failed
//! or a local step failed. Every line emitted here is one fixed-vocabulary
//! record of the *first* failing operation: a stage name, an errno or
//! `io::ErrorKind`, and counts/durations. It never contains peer text,
//! credentials, authentication responses, frame bytes or clipboard content.
//!
//! On OHOS the line goes to hilog (a release `hbb_common::init_log` writes only
//! to a file and C `stderr` is not captured), under the same domain and tag the
//! ArkTS side logs with, so one capture shows both. Elsewhere it uses the normal
//! `log` facade. There is no global logger state: each call is a single
//! thread-safe write.

use std::fmt;

pub(super) fn emit(args: fmt::Arguments<'_>) {
    let line = format!("rfb-origin {args}");
    hbb_common::log::warn!("{line}");
    #[cfg(target_env = "ohos")]
    hilog(&line);
}

/// A local (Rust-side) failure that `RfbError::Transport` would otherwise hide.
pub(super) fn io(stage: &'static str, error: &std::io::Error) {
    emit(format_args!(
        "layer=rust stage={stage} io_kind={:?} errno={}",
        error.kind(),
        error.raw_os_error().unwrap_or(0)
    ));
}

#[cfg(target_env = "ohos")]
fn hilog(line: &str) {
    use std::ffi::{CString, c_char, c_int, c_uint};
    // OH_LOG_Print(LOG_APP, LOG_WARN, domain, tag, "%{public}s", text).
    // `%{public}` is required: hilog masks string arguments as <private> otherwise.
    const LOG_APP: c_int = 0;
    const LOG_WARN: c_int = 5;
    const DOMAIN: c_uint = 0xFF01;
    #[link(name = "hilog_ndk.z")]
    unsafe extern "C" {
        fn OH_LOG_Print(
            kind: c_int,
            level: c_int,
            domain: c_uint,
            tag: *const c_char,
            format: *const c_char,
            ...
        ) -> c_int;
    }
    // Only fixed ASCII vocabulary and numbers are formatted, so this cannot hold
    // an interior NUL; if it ever did, the line is dropped rather than altered.
    let (Ok(text), Ok(tag)) = (CString::new(line), CString::new("RustDeskIndex")) else {
        return;
    };
    unsafe {
        OH_LOG_Print(
            LOG_APP,
            LOG_WARN,
            DOMAIN,
            tag.as_ptr(),
            c"%{public}s".as_ptr(),
            text.as_ptr(),
        );
    }
}
