//! Authentication outcome reported by the native client, not a local handshake.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authentication {
    None,
    VncAuth,
}
