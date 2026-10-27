//! Byte-stream plumbing shared by the direct-connect protocols.
//!
//! The RustDesk wire is length-prefixed and encrypted per record
//! (`crate::transport`). RFB and RDP are plain byte streams with their own
//! internal framing, so they share this module instead of growing a second
//! buffering layer each.

pub mod bufsource;
pub mod quic;

pub use bufsource::{BufSource, MAX_WINDOW_BYTES};
