//! Native backing for the pinned official Dart account implementation and for
//! the HarmonyOS NAPI bridge.
//!
//! Password/verification login and cloud address-book business remain in Dart
//! for the FRB consumer. The OHOS NAPI bridge reaches the same single account
//! owner through [`service`] (token-free JSON seam: server binding, snapshot,
//! OIDC, logout, official cloud address-book list/load/edit). Its private account
//! state never uses the engine's persistent identity or media services.

pub mod api;
pub mod http;
pub mod oidc;
pub mod service;
mod cache;
mod cloud;
mod mutation;
mod state;
mod storage;

pub use cache::access_scoped as access_cache_scoped;
pub use state::{
    change_server_configuration, get_local_option, set_local_option_scoped, snapshot,
};

#[cfg(target_os = "android")]
pub use storage::init_account_storage;

/// A native operation belongs to the API and account generation it started in.
/// Deliberately not Debug: even the API URL is not suitable diagnostic context.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountContext {
    pub api_server: String,
    pub scope: String,
    pub generation: u64,
}

/// OIDC cancellation does not implicitly log out an already committed account.
#[derive(Clone)]
pub struct AuthAttempt {
    pub context: AccountContext,
    pub generation: u64,
}

#[derive(Clone, Copy)]
pub enum CacheKind {
    AddressBook,
    Group,
}
