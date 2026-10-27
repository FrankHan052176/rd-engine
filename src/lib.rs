//! Replacement RustDesk runtime. Wire definitions and cryptography retain the
//! upstream contract; legacy Connection/VideoService/VideoHandler are not linked.
pub mod authentication;
mod executor;
pub mod handshake;
#[cfg(any(
    not(target_os = "windows"),
    feature = "windows-modern-producer",
    dsh_windows_typecheck
))]
pub mod host;
pub mod identity;
pub mod lan;
pub mod media_capability;
pub mod media_color;
#[cfg(all(feature = "official-account", not(target_env = "ohos")))]
pub mod official_account;
#[cfg(not(any(target_os = "windows", dsh_windows_typecheck)))]
#[path = "platform/ohos_publisher.rs"]
pub mod publisher;
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
#[path = "platform/windows_host_publisher.rs"]
pub mod publisher;
pub mod rendezvous;
pub mod session;
// Rectangle protocols present through a CPU-writable surface buffer; the
// in-memory sink in this module is what the host build and tests exercise.
#[path = "platform/ohos_surface.rs"]
pub mod surface;
pub mod transport;
// The RustDesk-wire encoded video pipeline, shared by every session that owns one.
pub mod video;
pub mod viewer;
pub mod wake_on_lan;
// The per-frame decode budget every presentation path records against.
pub mod latency;
pub mod net;
pub mod protocol;
#[path = "platform/windows_decoder.rs"]
pub mod windows_decoder;
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
#[path = "platform/windows_input.rs"]
pub(crate) mod windows_input;
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
#[path = "platform/windows_native.rs"]
pub mod windows_native;
#[path = "platform/windows_presentation.rs"]
pub mod windows_presentation;
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
pub use windows_native::NATIVE_BACKEND_IMPLEMENTED;
#[cfg(feature = "windows-modern-producer")]
#[path = "platform/windows_publisher.rs"]
pub mod windows_publisher;
