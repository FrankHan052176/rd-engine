//! VNC sessions backed by pinned LibVNCClient 0.9.15.
//!
//! Upstream owns protocol negotiation, authentication, decoding and update
//! requests. One blocking worker owns each native client. Completed damage is
//! borrowed until the next pump and copied into the current `PixelTarget`.
//! NativeSurface buffers are never retained by the native decoder.

pub mod auth;
pub mod session;
mod native;
mod worker;

use crate::protocol::rect::PixelError;
use std::fmt;

pub const DEFAULT_PORT: u16 = 5900;
pub const MAX_CUT_TEXT: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub enum RfbError {
    Transport,
    BadServerVersion,
    NoUsableSecurityType,
    SecurityRefused(String),
    /// Actual upstream SecurityResult failure, with the peer's reason if sent.
    AuthenticationFailed(String),
    PasswordTooLong,
    /// The baseline upstream password callback cannot represent this credential.
    CredentialUnavailable,
    Protocol(&'static str),
    Geometry,
    Sink,
    Allocation,
    Cancelled,
    Closed,
}

impl fmt::Display for RfbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport => f.write_str("RFB transport failed"),
            Self::BadServerVersion => f.write_str("RFB server sent an unsupported version"),
            Self::NoUsableSecurityType => f.write_str("RFB server offered no supported security type (this build supports None/VNC authentication, not TLS)"),
            Self::SecurityRefused(reason) => write!(f, "RFB server refused the session: {reason}"),
            Self::AuthenticationFailed(reason) => write!(f, "RFB authentication failed: {reason}"),
            Self::PasswordTooLong => f.write_str("RFB password is too long"),
            Self::CredentialUnavailable => f.write_str("LibVNCClient requires a nonempty, NUL-free password for VNC authentication"),
            Self::Protocol(reason) => write!(f, "RFB protocol error: {reason}"),
            Self::Geometry => f.write_str("RFB framebuffer geometry is invalid"),
            Self::Sink => f.write_str("RFB presentation sink rejected the framebuffer"),
            Self::Allocation => f.write_str("LibVNCClient could not allocate session data"),
            Self::Cancelled => f.write_str("RFB session was cancelled"),
            Self::Closed => f.write_str("RFB session is closed"),
        }
    }
}
impl std::error::Error for RfbError {}
impl From<std::io::Error> for RfbError {
    fn from(_: std::io::Error) -> Self { Self::Transport }
}
impl From<PixelError> for RfbError {
    fn from(_: PixelError) -> Self { Self::Geometry }
}
