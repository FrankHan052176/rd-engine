//! Non-HarmonyOS FRB artifact for the pinned official RustDesk Flutter client.
//!
//! `client_compat` is the single flutter_rust_bridge input. Generated bindings,
//! the official runner exports, and the Windows-only engine texture ABI are
//! linked into this artifact; this crate is not a Flutter application.

#[cfg(target_env = "ohos")]
compile_error!("native/frb is a non-HarmonyOS artifact; use native/ohos_napi for HarmonyOS");

mod bridge_generated;
mod c_entry_points;
pub mod client_compat;
mod configuration;
mod frames;
mod keyboard;
mod localization;
mod platform;

#[cfg(target_os = "windows")]
mod host_bridge;

// JNI exports belong to the Java VM, not the generated Dart/C call surface.
/// cbindgen:ignore
#[cfg(target_os = "android")]
mod android;

// Keep the account Keystore lifecycle entry point in the final Android library.
#[cfg(target_os = "android")]
pub use rd_engine::official_account::init_account_storage;

#[cfg(target_os = "windows")]
mod windows_texture;
