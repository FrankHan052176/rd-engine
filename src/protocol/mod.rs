//! Protocol routing: one session shell, three wire protocols.
//!
//! The ArkTS client selects VNC and RDP with a URL scheme in the session target
//! (`RustDeskIndex.ets::sessionTargetForKind`) and hands the string to
//! `sessionAdd` unchanged. Everything downstream of this module is shared:
//! `Viewer` owns the lifecycle, cancellation, snapshot and teardown for all
//! three protocols, and they differ only in how they speak to the peer.
//!
//! Parsing is deliberately strict. A bare `host:port` stays a RustDesk peer,
//! because the client's own rule is that only an explicit scheme selects
//! another protocol — treating `10.0.0.1:5900` as VNC would break direct
//! RustDesk connections, and guessing a protocol from a port number is exactly
//! that mistake in a different shape.

pub mod rdp;
pub mod rect;
pub mod rfb;

use std::fmt;

pub const VNC_DEFAULT_PORT: u16 = 5900;
pub const RDP_DEFAULT_PORT: u16 = 3389;

/// Longest accepted target. The client's own field limit is far below this; the
/// bound exists so a malformed paste cannot allocate for us.
const MAX_TARGET: usize = 512;
const MAX_HOST: usize = 255;
const MAX_USER: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    RustDesk,
    Vnc,
    Rdp,
}

impl Protocol {
    /// Stable token used in `ViewerSnapshot` and the HAR manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RustDesk => "rustdesk",
            Self::Vnc => "vnc",
            Self::Rdp => "rdp",
        }
    }
}

/// A resolved remote endpoint for a direct-connect protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// RFB has no user field; RDP needs one. `None` means "the client has not
    /// supplied a user yet", never a fabricated default.
    pub user: Option<String>,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The original RustDesk wire contract: a peer id with an optional
    /// rendezvous server, or a direct `host:port`.
    RustDesk(String),
    Vnc(Endpoint),
    Rdp(Endpoint),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    TooLong,
    MissingHost,
    InvalidHost,
    InvalidPort,
    MissingUser,
    UnsupportedScheme(String),
    /// A path/query on a protocol that has no meaning for it.
    UnexpectedPath,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty session target"),
            Self::TooLong => write!(f, "Session target is too long"),
            Self::MissingHost => write!(f, "Session target has no host"),
            Self::InvalidHost => write!(f, "Session target has an invalid host"),
            Self::InvalidPort => write!(f, "Session target has an invalid port"),
            Self::MissingUser => write!(f, "Session target has an empty user"),
            Self::UnsupportedScheme(scheme) => {
                write!(f, "Unsupported session scheme: {scheme}")
            }
            Self::UnexpectedPath => write!(f, "Session target must not carry a path or query"),
        }
    }
}

impl std::error::Error for TargetError {}

impl Target {
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::RustDesk(_) => Protocol::RustDesk,
            Self::Vnc(_) => Protocol::Vnc,
            Self::Rdp(_) => Protocol::Rdp,
        }
    }

    pub fn endpoint(&self) -> Option<&Endpoint> {
        match self {
            Self::RustDesk(_) => None,
            Self::Vnc(endpoint) | Self::Rdp(endpoint) => Some(endpoint),
        }
    }

    /// Splits the target exactly once, on the first `://` the client added.
    pub fn parse(raw: &str) -> Result<Self, TargetError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(TargetError::Empty);
        }
        if trimmed.len() > MAX_TARGET {
            return Err(TargetError::TooLong);
        }
        let Some((scheme, rest)) = trimmed.split_once("://") else {
            return Ok(Self::RustDesk(trimmed.to_owned()));
        };
        // Any path or query is rejected rather than silently dropped: a
        // `vnc://host/path` target would otherwise connect somewhere the user
        // did not ask for and hide the mistake.
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(TargetError::UnexpectedPath);
        }
        match scheme.to_ascii_lowercase().as_str() {
            "vnc" => Ok(Self::Vnc(parse_authority(rest, VNC_DEFAULT_PORT)?)),
            "rdp" => Ok(Self::Rdp(parse_authority(rest, RDP_DEFAULT_PORT)?)),
            other => Err(TargetError::UnsupportedScheme(other.to_owned())),
        }
    }
}

/// `[user@]host[:port]`, with bracketed IPv6 literals.
fn parse_authority(authority: &str, default_port: u16) -> Result<Endpoint, TargetError> {
    let (user, host_port) = match authority.split_once('@') {
        Some((user, host)) => {
            if user.is_empty() || user.len() > MAX_USER || user.contains(':') {
                return Err(TargetError::MissingUser);
            }
            (Some(user.to_owned()), host)
        }
        None => (None, authority),
    };
    let (host, port) = split_host_port(host_port)?;
    if host.is_empty() {
        return Err(TargetError::MissingHost);
    }
    if host.len() > MAX_HOST {
        return Err(TargetError::InvalidHost);
    }
    Ok(Endpoint {
        host: host.to_owned(),
        port: port.unwrap_or(default_port),
        user,
    })
}

fn split_host_port(value: &str) -> Result<(&str, Option<u16>), TargetError> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(TargetError::InvalidHost)?;
        if !host.contains(':') {
            return Err(TargetError::InvalidHost);
        }
        return Ok((host, parse_optional_port(tail)?));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() => {
            let port = port.parse::<u16>().map_err(|_| TargetError::InvalidPort)?;
            if port == 0 {
                return Err(TargetError::InvalidPort);
            }
            Ok((host, Some(port)))
        }
        // A trailing colon without a number is a malformed target, not a
        // hostname that happens to end in one.
        Some(_) => Err(TargetError::InvalidPort),
        None => Ok((value, None)),
    }
}

fn parse_optional_port(tail: &str) -> Result<Option<u16>, TargetError> {
    let tail = tail.strip_prefix(':').unwrap_or(tail);
    if tail.is_empty() {
        return Ok(None);
    }
    let port = tail.parse::<u16>().map_err(|_| TargetError::InvalidPort)?;
    if port == 0 {
        return Err(TargetError::InvalidPort);
    }
    Ok(Some(port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vnc(host: &str, port: u16) -> Target {
        Target::Vnc(Endpoint {
            host: host.into(),
            port,
            user: None,
        })
    }

    #[test]
    fn bare_targets_stay_rustdesk() {
        // The client only adds a scheme when the user picked another protocol,
        // so these must never be reinterpreted.
        for raw in ["10.0.0.1", "10.0.0.1:21118", "100 001", "id@server:21116?key=abc"] {
            let target = Target::parse(raw).unwrap();
            assert_eq!(target.protocol(), Protocol::RustDesk, "{raw}");
        }
        assert_eq!(
            Target::parse("  10.0.0.1:21118 ").unwrap(),
            Target::RustDesk("10.0.0.1:21118".into())
        );
    }

    #[test]
    fn vnc_and_rdp_default_ports_match_the_client_comment() {
        assert_eq!(Target::parse("vnc://1.2.3.4").unwrap(), vnc("1.2.3.4", 5900));
        assert_eq!(
            Target::parse("rdp://1.2.3.4").unwrap(),
            Target::Rdp(Endpoint {
                host: "1.2.3.4".into(),
                port: 3389,
                user: None
            })
        );
        assert_eq!(
            Target::parse("vnc://1.2.3.4:5901").unwrap(),
            vnc("1.2.3.4", 5901)
        );
    }

    #[test]
    fn rdp_userinfo_is_captured_because_the_login_payload_has_no_username() {
        assert_eq!(
            Target::parse("rdp://CORP\\ann@10.0.0.5:3390").unwrap(),
            Target::Rdp(Endpoint {
                host: "10.0.0.5".into(),
                port: 3390,
                user: Some("CORP\\ann".into())
            })
        );
        assert_eq!(
            Target::parse("rdp://@host").unwrap_err(),
            TargetError::MissingUser
        );
    }

    #[test]
    fn ipv6_literals_keep_their_colons() {
        assert_eq!(
            Target::parse("vnc://[fe80::1]:5901").unwrap(),
            vnc("fe80::1", 5901)
        );
        assert_eq!(Target::parse("vnc://[fe80::1]").unwrap(), vnc("fe80::1", 5900));
        assert_eq!(
            Target::parse("vnc://[fe80::1").unwrap_err(),
            TargetError::InvalidHost
        );
        assert_eq!(
            Target::parse("vnc://[fe80::1]:0").unwrap_err(),
            TargetError::InvalidPort
        );
    }

    #[test]
    fn malformed_targets_are_rejected_not_guessed() {
        assert_eq!(Target::parse("").unwrap_err(), TargetError::Empty);
        assert_eq!(Target::parse("vnc://").unwrap_err(), TargetError::MissingHost);
        assert_eq!(
            Target::parse("vnc://host/desktop").unwrap_err(),
            TargetError::UnexpectedPath
        );
        assert_eq!(
            Target::parse("vnc://host?k=v").unwrap_err(),
            TargetError::UnexpectedPath
        );
        assert_eq!(
            Target::parse("vnc://host:").unwrap_err(),
            TargetError::InvalidPort
        );
        assert_eq!(
            Target::parse("vnc://host:66111").unwrap_err(),
            TargetError::InvalidPort
        );
        assert_eq!(
            Target::parse("http://host").unwrap_err(),
            TargetError::UnsupportedScheme("http".into())
        );
        assert_eq!(
            Target::parse(&"v".repeat(MAX_TARGET + 1)).unwrap_err(),
            TargetError::TooLong
        );
    }

    #[test]
    fn scheme_case_is_normalised() {
        assert_eq!(Target::parse("VNC://Host").unwrap(), vnc("Host", 5900));
    }
}
