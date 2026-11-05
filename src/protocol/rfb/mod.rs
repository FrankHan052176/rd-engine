//! VNC sessions backed by pinned LibVNCClient 0.9.15.
//!
//! Upstream owns protocol negotiation, authentication, decoding and update
//! requests. One blocking worker owns each native client. Completed damage is
//! borrowed until the next pump and copied into the current `PixelTarget`.
//! NativeSurface buffers are never retained by the native decoder.

pub mod auth;
mod diag;
mod native;
pub mod session;
mod worker;

use crate::protocol::rect::PixelError;
use std::fmt;

pub const DEFAULT_PORT: u16 = 5900;
pub const MAX_CUT_TEXT: usize = 1024 * 1024;

/// The name of an RFB encoding the wire can carry, or `None` for an identifier
/// this build does not name.
///
/// The identifiers are the protocol's own; these are the encodings this build
/// advertises plus the ones upstream can decode without extra libraries. A name
/// here is the encoding a rectangle arrived in, never a decoder implementation,
/// a vendor or a claim about hardware.
pub fn encoding_name(encoding: u32) -> Option<&'static str> {
    Some(match encoding {
        0 => "Raw",
        1 => "CopyRect",
        2 => "RRE",
        4 => "CoRRE",
        5 => "Hextile",
        6 => "Zlib",
        7 => "Tight",
        15 => "TRLE",
        16 => "ZRLE",
        17 => "ZYWRLE",
        _ => return None,
    })
}

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
    fn from(_: std::io::Error) -> Self {
        Self::Transport
    }
}
impl From<PixelError> for RfbError {
    fn from(_: PixelError) -> Self {
        Self::Geometry
    }
}

#[cfg(test)]
mod tests {
    use super::encoding_name;

    /// The names this build can publish are the encodings it advertises, and an
    /// identifier it does not know answers nothing rather than a made-up label.
    #[test]
    fn names_only_the_encodings_it_knows() {
        for (identifier, name) in [
            (0, "Raw"),
            (1, "CopyRect"),
            (2, "RRE"),
            (4, "CoRRE"),
            (5, "Hextile"),
            (6, "Zlib"),
            (16, "ZRLE"),
        ] {
            assert_eq!(encoding_name(identifier), Some(name), "{identifier}");
        }
        assert_eq!(encoding_name(3), None, "an unassigned identifier");
        assert_eq!(
            encoding_name(0xFFFF_FF11),
            None,
            "a cursor pseudo-encoding is a shape, not a frame encoding"
        );
    }
}
