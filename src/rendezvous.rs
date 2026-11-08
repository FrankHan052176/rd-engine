//! Original TCP rendezvous / relay viewer dialer, without the old app runtime.
//! Source order: client.rs start/connect/request_relay/create_relay and
//! common.rs get_next_nonkeyexchange_msg. No UDP/KCP/WebSocket/proxy or account
//! token route is implied. No password enters this module.
//!
//! The `registration` submodule is the other half of the same rendezvous service:
//! the host's UDP registration/heartbeat, the controller routes hbbs hands it, and
//! the presence query. It reuses these endpoint, framing and address helpers and
//! leaves the dialer below unchanged.
//!
//! hbbs signs IdPk (peer ID + Ed25519 PEER key); that peer then signs its
//! ephemeral box key in SignedId. These two signing keys are not interchangeable.
//! Missing/bad evidence terminates, never a TOFU fallback. The one exception is
//! the original shared-licence compatibility: with no trust root
//! (`server_key: None`, built only for a custom profile whose Key is explicitly
//! not a public key) the hbbs signature cannot be checked, the route is dialled
//! through `ViewerIdentity::LegacyUnverified` and reports
//! `peer_verified == false` / `encrypted == false`.
//!
//! Every hbbs punch and every relay request of one attempt carries the same
//! fixed protocol role (`ConnType`) chosen once from `SessionMode`; the role
//! never changes the target ID, the dialed address or the verified identity.
use crate::handshake::{self, Established, Security, ViewerIdentity};
use crate::session::SessionMode;
use hbb_common::{
    AddrMangle,
    protobuf::Message as _,
    rendezvous_proto::{
        ConnType, IdPk, NatType, PunchHoleRequest, RelayResponse, RendezvousMessage, RequestRelay,
        punch_hole_response::Failure as PunchFailure, rendezvous_message,
    },
    sodiumoxide::{self, crypto::sign},
    tcp::FramedStream,
    uuid::Uuid,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpSocket, TcpStream},
    time::{Instant, timeout, timeout_at},
};

mod registration;
pub use registration::{
    HostRouteKind, IdentityConflict, IncomingHostRoute, PresenceConfig, PresenceState,
    RegistrationConfig, RegistrationFailure, RegistrationState, RouteRequirements, ServerRefusal,
    StopReason, query_presence, run_host_registration,
};

/// No Debug: caller configuration contains identities and a trust anchor.
pub struct RendezvousConfig {
    pub id: String,
    /// Hostname/IP with optional port (default 21116); resolved asynchronously.
    pub rendezvous_server: String,
    /// Exact original client `key` wire value: the compiled `RS_PUB_KEY` string
    /// for the public service, a configured public key, or a shared licence
    /// text. The one value rides both the hbbs `PunchHoleRequest.licence_key`
    /// and the hbbr `RequestRelay.licence_key`, as in the original client. It is
    /// never reconstructed by encoding `server_key` and is never logged (this
    /// struct has no Debug).
    pub licence_key: String,
    /// hbbs trust root that verifies the signed peer IdPk; a failed check ends
    /// the connection. `None` only when the Key is a shared licence text that is
    /// not a public key: nothing can be verified then, and the route is the
    /// original unverified/unencrypted compatibility path.
    pub server_key: Option<sign::PublicKey>,
    /// Explicit relay address override; otherwise use the hbbs-advertised relay.
    pub relay_server: Option<String>,
    /// Total operation deadline, including DNS, punch, relay and peer handshake.
    pub connect_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    TcpHolePunch,
    Relay,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEvidence {
    pub route: RouteKind,
    /// Peer handshake evidence only, NOT user authentication or media readiness.
    pub peer_verified: bool,
    pub encrypted: bool,
}

/// Observed LAN claims only. Neither same-IP UDP nor a MAC/name authenticates
/// a peer. Feed claimed_id into a separate verified hbbs lookup; never make a
/// pin from this response. No Debug to keep identities/MACs out of diagnostics.
pub struct LanPeerEvidence {
    pub claimed_id: String,
    pub claimed_name: String,
    pub claimed_platform: String,
    pub claimed_mac: String,
    pub verified: bool,
}

/// One explicitly targeted probe, not broadcast scanning. The supplied port is
/// ignored: original src/lan.rs listens on UDP21119 and sends raw protobuf (no
/// RustDesk TCP length header). No local identity or device details are sent.
pub async fn discover_peer(mut target: SocketAddr, wait: Duration) -> io::Result<LanPeerEvidence> {
    use hbb_common::rendezvous_proto::PeerDiscovery;
    target.set_port(21119);
    if !valid_address(target) || wait.is_zero() || wait > Duration::from_secs(60) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid LAN discovery target or deadline",
        ));
    }
    timeout(wait, async move {
        let bind: SocketAddr = if target.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let socket = tokio::net::UdpSocket::bind(bind).await?;
        let mut ping = RendezvousMessage::new();
        ping.set_peer_discovery(PeerDiscovery {
            cmd: "ping".into(),
            ..Default::default()
        });
        let bytes = ping
            .write_to_bytes()
            .map_err(|_| invalid("LAN discovery serialization failed"))?;
        socket.send_to(&bytes, target).await?;
        // The extra byte distinguishes oversized/truncated datagrams from the
        // original 2048-byte discovery limit. Invalid packets never become trust.
        let mut bytes = [0; 2049];
        for _ in 0..64 {
            let (length, origin) = socket.recv_from(&mut bytes).await?;
            if origin.ip() != target.ip() || length > 2048 {
                continue;
            }
            let Ok(message) = RendezvousMessage::parse_from_bytes(&bytes[..length]) else {
                continue;
            };
            let Some(rendezvous_message::Union::PeerDiscovery(peer)) = message.union else {
                continue;
            };
            if peer.cmd != "pong"
                || peer.id.is_empty()
                || peer.id.len() > 64
                || !peer
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                || !peer.id.as_bytes()[0].is_ascii_alphanumeric()
                || peer.hostname.len() > 256
                || peer.platform.len() > 64
                || peer.mac.len() > 64
                || [&peer.hostname, &peer.platform, &peer.mac]
                    .iter()
                    .any(|s| s.chars().any(char::is_control))
            {
                continue;
            }
            return Ok(LanPeerEvidence {
                claimed_id: peer.id,
                claimed_name: peer.hostname,
                claimed_platform: peer.platform,
                claimed_mac: peer.mac,
                verified: false,
            });
        }
        Err(invalid("No valid targeted LAN discovery response"))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Targeted LAN discovery timed out"))?
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "Rendezvous connection deadline expired",
    )
}

/// The one wire encoding of the fixed role. Original client passes its
/// `ConnType` straight through to hbbs/hbbr; nothing here derives it from an
/// address, a peer ID, a response or a fallback.
fn conn_type(mode: SessionMode) -> ConnType {
    match mode {
        SessionMode::Desktop => ConnType::DEFAULT_CONN,
        SessionMode::FileTransfer => ConnType::FILE_TRANSFER,
    }
}

/// Desktop-compatible entry point: the fixed role is `SessionMode::Desktop`.
pub async fn connect_viewer(config: RendezvousConfig) -> io::Result<(Established, RouteEvidence)> {
    connect_viewer_for(config, SessionMode::Desktop).await
}

/// Returns the exact unsplit peer stream, retaining its codec buffer and nonce
/// counters, for ViewerSession::from_established. Never claims login succeeded.
///
/// `mode` is this attempt's immutable protocol role. It rides only the
/// `conn_type` field of the hbbs punch, of the hbbs relay request and of the
/// final hbbr join, so a file-transfer dial is never advertised as a desktop
/// one and a relay fallback cannot change it. The target ID, the resolved
/// route, the deadline, cancellation and the peer signature checks are
/// unchanged; the role is never derived from them.
pub async fn connect_viewer_for(
    config: RendezvousConfig,
    mode: SessionMode,
) -> io::Result<(Established, RouteEvidence)> {
    if config.id.is_empty()
        || config.id.len() > 512
        || !valid_wire_key(&config.licence_key)
        || config.connect_timeout.is_zero()
        || config.connect_timeout > Duration::from_secs(180)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid rendezvous configuration",
        ));
    }
    endpoint(&config.rendezvous_server, 21116)?;
    if let Some(relay) = &config.relay_server {
        endpoint(relay, 21117)?;
    }
    sodiumoxide::init().map_err(|_| io::Error::other("Crypto initialization failed"))?;
    let deadline = Instant::now() + config.connect_timeout;
    timeout_at(deadline, connect(config, mode, deadline))
        .await
        .map_err(|_| timed_out())?
}

/// Wire Key text: non-empty, bounded, no control characters. Shared licence
/// text is not normalized (spaces are part of the configured Key).
fn valid_wire_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && !key.chars().any(char::is_control)
}

fn valid_address(address: SocketAddr) -> bool {
    address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast()
}

/// Strict original check_port-style endpoint normalization: no URL, userinfo,
/// whitespace, ambiguous IPv6+port, zero port or malformed DNS labels. Bare
/// IPv6 means the complete address with the default port; an explicit IPv6 port
/// must use brackets. No DNS is performed during validation.
pub fn endpoint(name: &str, default_port: u16) -> io::Result<String> {
    if name.is_empty()
        || name.len() > 1024
        || name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid("Invalid server endpoint"));
    }
    if let Ok(address) = name.parse::<SocketAddr>() {
        return if valid_address(address) {
            Ok(address.to_string())
        } else {
            Err(invalid("Invalid server address"))
        };
    }
    if let Ok(ip) = name.parse::<IpAddr>() {
        let address = SocketAddr::new(ip, default_port);
        return if valid_address(address) {
            Ok(address.to_string())
        } else {
            Err(invalid("Invalid server address"))
        };
    }
    if name.starts_with('[') && name.ends_with(']') {
        let ip = name[1..name.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalid("Invalid bracketed server address"))?;
        let address = SocketAddr::new(IpAddr::V6(ip), default_port);
        return if valid_address(address) {
            Ok(address.to_string())
        } else {
            Err(invalid("Invalid server address"))
        };
    }
    let (host, port) = if let Some((host, port)) = name.rsplit_once(':') {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("Invalid server port"));
        }
        (
            host,
            port.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| invalid("Invalid server port"))?,
        )
    } else {
        (name, default_port)
    };
    let dns = host.strip_suffix('.').unwrap_or(host);
    if dns.is_empty()
        || dns.len() > 253
        || !dns.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid("Invalid server hostname"));
    }
    Ok(format!("{host}:{port}"))
}

async fn server_dial(name: &str, default_port: u16, deadline: Instant) -> io::Result<FramedStream> {
    let endpoint = endpoint(name, default_port)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(timed_out());
    }
    // Original FramedStream::new owns async lookup_host and reuse-enabled TCP
    // sockets; no DNS is pushed onto a synchronous HAR/NAPI callback. Candidate
    // connect waits are bounded while the outer deadline includes DNS itself.
    let milliseconds = (remaining / 2)
        .min(Duration::from_secs(3))
        .as_millis()
        .max(1) as u64;
    let mut wire = FramedStream::new(endpoint, None, milliseconds)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Server resolution or connection failed",
            )
        })?;
    wire.0
        .codec_mut()
        .set_max_packet_length(handshake::AUTH_MAX_RECORD_BYTES);
    Ok(wire)
}

async fn dial(remote: SocketAddr, local: Option<SocketAddr>) -> io::Result<FramedStream> {
    let stream = dial_socket(remote, local).await?;
    let local = stream.local_addr()?;
    let mut wire = FramedStream::from(stream, local);
    wire.0
        .codec_mut()
        .set_max_packet_length(handshake::AUTH_MAX_RECORD_BYTES);
    Ok(wire)
}

async fn dial_socket(remote: SocketAddr, local: Option<SocketAddr>) -> io::Result<TcpStream> {
    if !valid_address(remote) {
        return Err(invalid("Invalid route address"));
    }
    let socket = if remote.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Same original tcp::new_socket(..., reuse=true) semantics; keep the hbbs
    // source port for direct TCP simultaneous-open. Do not read local Config.
    socket.set_reuseaddr(true)?;
    #[cfg(all(unix, not(target_os = "illumos")))]
    socket.set_reuseport(true)?;
    let local = local.unwrap_or_else(|| {
        if remote.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        }
    });
    if local.is_ipv4() != remote.is_ipv4() {
        return Err(invalid("Punch address family mismatch"));
    }
    socket.bind(local)?;
    let stream = socket.connect(remote).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn send(wire: &mut FramedStream, message: &RendezvousMessage) -> io::Result<()> {
    if message.compute_size() > handshake::AUTH_MAX_RECORD_BYTES as u64 {
        return Err(invalid("Oversized rendezvous request"));
    }
    wire.send(message)
        .await
        .map_err(|_| io::Error::other("Rendezvous write failed"))
}

async fn receive(wire: &mut FramedStream) -> io::Result<RendezvousMessage> {
    // With no account token/switch-code, original client does not secure_tcp its
    // hbbs control stream. It skips at most one unsolicited KeyExchange record.
    // That record is NOT peer evidence and never changes the wire's secretbox.
    for _ in 0..2 {
        let bytes = wire
            .next()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Rendezvous closed"))?
            .map_err(|_| invalid("Invalid rendezvous record"))?;
        let message = RendezvousMessage::parse_from_bytes(&bytes)
            .map_err(|_| invalid("Invalid rendezvous message"))?;
        if !matches!(
            message.union,
            Some(rendezvous_message::Union::KeyExchange(_))
        ) {
            return Ok(message);
        }
    }
    Err(invalid("Excess rendezvous key-exchange records"))
}

/// The peer signing key vouched for by the hbbs signature, or `None` when the
/// profile has no trust root (shared licence compatibility). With a trust root a
/// missing or invalid signature is an error, never an unverified fallback.
fn peer_key(signed: &[u8], config: &RendezvousConfig) -> io::Result<Option<sign::PublicKey>> {
    let Some(server_key) = &config.server_key else {
        return Ok(None);
    };
    let plain = sign::verify(signed, server_key)
        .map_err(|_| invalid("Peer certificate signature missing or invalid"))?;
    let identity =
        IdPk::parse_from_bytes(&plain).map_err(|_| invalid("Invalid peer certificate"))?;
    if identity.id != config.id {
        return Err(invalid("Peer certificate identity mismatch"));
    }
    sign::PublicKey::from_slice(&identity.pk)
        .map(Some)
        .ok_or_else(|| invalid("Invalid peer signing key length"))
}

fn peer_address(bytes: &[u8]) -> io::Result<SocketAddr> {
    if bytes.is_empty() || (bytes.len() > 16 && bytes.len() != 18) {
        return Err(invalid("Invalid mangled address"));
    }
    if bytes.len() <= 16 {
        // AddrMangle::decode assumes valid input and uses unchecked subtraction.
        // Validate its original integer representation before calling it; never
        // let an unauthenticated route record cause an underflow panic/wrap.
        let mut padded = [0; 16];
        padded[..bytes.len()].copy_from_slice(bytes);
        let n = u128::from_le_bytes(padded);
        let tm = (n >> 17) & u32::MAX as u128;
        let ip = (n >> 49)
            .checked_sub(tm)
            .ok_or_else(|| invalid("Invalid mangled address"))?;
        // Only low 17 bits encode port+salt; upstream's wider 24-bit mask
        // also includes tm bits, subsequently discarded by its u16 cast.
        let port = (n & 0x1ffff)
            .checked_sub(tm & 0xffff)
            .ok_or_else(|| invalid("Invalid mangled address"))?;
        if ip > u32::MAX as u128 || port == 0 || port > u16::MAX as u128 {
            return Err(invalid("Invalid mangled address"));
        }
    }
    let address = AddrMangle::decode(bytes);
    if !valid_address(address) {
        return Err(invalid("Invalid peer route"));
    }
    Ok(address)
}

fn relay_name(config: &RendezvousConfig, advertised: &str) -> io::Result<String> {
    endpoint(config.relay_server.as_deref().unwrap_or(advertised), 21117)
}

async fn finish(
    wire: FramedStream,
    config: &RendezvousConfig,
    key: Option<sign::PublicKey>,
    route: RouteKind,
    deadline: Instant,
) -> io::Result<(Established, RouteEvidence)> {
    let Some(key) = key else {
        // Shared-licence compatibility (no trust root): the original viewer's
        // empty-reply branch. The evidence is read from what the handshake
        // really established, so it reports an unencrypted, unverified peer.
        let established = handshake::viewer(
            wire,
            ViewerIdentity::LegacyUnverified,
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
        let encrypted = matches!(established.security(), Security::Encrypted { .. });
        let peer_verified =
            matches!(established.security(), Security::Encrypted { peer_id: Some(_) });
        return Ok((
            established,
            RouteEvidence {
                route,
                encrypted,
                peer_verified,
            },
        ));
    };
    let established = handshake::viewer(
        wire,
        ViewerIdentity::PinnedHost {
            expected_id: config.id.clone(),
            peer_signing_key: key,
        },
        deadline.saturating_duration_since(Instant::now()),
    )
    .await?;
    if !matches!(established.security(), Security::Encrypted { peer_id: Some(id) } if id == &config.id)
    {
        return Err(invalid("Verified encrypted peer required"));
    }
    Ok((
        established,
        RouteEvidence {
            route,
            encrypted: true,
            peer_verified: true,
        },
    ))
}

/// Original hbbs punch request: the role is fixed before any route is chosen,
/// so neither the TCP punch nor the relay fallback can change it.
fn punch_hole_request(config: &RendezvousConfig, mode: SessionMode) -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_punch_hole_request(PunchHoleRequest {
        id: config.id.clone(),
        licence_key: config.licence_key.clone(),
        nat_type: NatType::UNKNOWN_NAT.into(),
        conn_type: conn_type(mode).into(),
        version: "1.4.9".into(),
        ..Default::default()
    });
    message
}

/// hbbs relay negotiation on a fresh control socket, carrying the same fixed
/// role as the hbbr join that follows it.
fn relay_request(
    config: &RendezvousConfig,
    name: &str,
    uuid: &str,
    mode: SessionMode,
) -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_request_relay(RequestRelay {
        id: config.id.clone(),
        uuid: uuid.to_owned(),
        relay_server: name.to_owned(),
        secure: config.server_key.is_some(),
        conn_type: conn_type(mode).into(),
        ..Default::default()
    });
    message
}

/// hbbr join record: licence_key/id/uuid/conn_type, NOT the hbbs secure flag.
/// The licence is the profile's one Key, exactly what hbbs received.
/// There is no relay ACK to consume: the next record is the PEER SignedId.
fn relay_join_request(
    config: &RendezvousConfig,
    uuid: String,
    mode: SessionMode,
) -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_request_relay(RequestRelay {
        id: config.id.clone(),
        uuid,
        licence_key: config.licence_key.clone(),
        conn_type: conn_type(mode).into(),
        ..Default::default()
    });
    message
}

async fn join_relay(
    config: &RendezvousConfig,
    name: &str,
    uuid: String,
    key: Option<sign::PublicKey>,
    mode: SessionMode,
    deadline: Instant,
) -> io::Result<(Established, RouteEvidence)> {
    if uuid.len() > 64 || Uuid::parse_str(&uuid).is_err() {
        return Err(invalid("Invalid relay pairing UUID"));
    }
    if config.server_key.is_none() {
        // The one Key is a secret in this mode. The configured hbbs may receive
        // it, but an unsigned hbbs relay hint does not authorize sending it to
        // another endpoint. Preserve the existing local-relay-only policy.
        let configured = config.relay_server.as_deref()
            .map(|relay| endpoint(relay, 21117)).transpose()?;
        if configured.as_deref() != Some(endpoint(name, 21117)?.as_str()) {
            return Err(invalid("Shared Key requires the explicitly configured relay"));
        }
    }
    let mut wire = server_dial(name, 21117, deadline).await?;
    let message = relay_join_request(config, uuid, mode);
    send(&mut wire, &message).await?;
    finish(wire, config, key, RouteKind::Relay, deadline).await
}

fn relay_response(message: RendezvousMessage) -> io::Result<RelayResponse> {
    match message.union {
        Some(rendezvous_message::Union::RelayResponse(response))
            if response.refuse_reason.is_empty() =>
        {
            Ok(response)
        }
        _ => Err(invalid("Relay request refused or invalid response")),
    }
}

async fn request_relay(
    config: &RendezvousConfig,
    name: &str,
    key: Option<sign::PublicKey>,
    mode: SessionMode,
    deadline: Instant,
) -> io::Result<(Established, RouteEvidence)> {
    // Original hbbs requires a NEW control socket / NAT tuple for relay requests.
    let mut wire = server_dial(&config.rendezvous_server, 21116, deadline).await?;
    let uuid = Uuid::new_v4().to_string();
    let message = relay_request(config, name, &uuid, mode);
    send(&mut wire, &message).await?;
    let response = relay_response(receive(&mut wire).await?)?;
    // Original success ACK may omit uuid/pk. Nonempty contradictory evidence
    // cannot silently change the signed peer or pair us into another session.
    if !response.uuid.is_empty() && response.uuid != uuid {
        return Err(invalid("Relay UUID mismatch"));
    }
    if !response.pk().is_empty() && peer_key(response.pk(), config)? != key {
        return Err(invalid("Relay peer key changed"));
    }
    drop(wire);
    join_relay(config, name, uuid, key, mode, deadline).await
}

async fn connect(
    config: RendezvousConfig,
    mode: SessionMode,
    deadline: Instant,
) -> io::Result<(Established, RouteEvidence)> {
    let mut wire = server_dial(&config.rendezvous_server, 21116, deadline).await?;
    let local = wire.local_addr();
    let request = punch_hole_request(&config, mode);
    let mut response = None;
    for attempt in 1..=3 {
        send(&mut wire, &request).await?;
        match timeout(Duration::from_secs(attempt * 3), receive(&mut wire)).await {
            Ok(result) => {
                response = Some(result?);
                break;
            }
            Err(_) => continue,
        }
    }
    let response = response.ok_or_else(timed_out)?;
    match response.union {
        Some(rendezvous_message::Union::PunchHoleResponse(response)) => {
            if !response.other_failure.is_empty() || response.socket_addr.is_empty() {
                // Same failure branch as the original client. Only the hbbs
                // licence verdicts are named; an empty failure (default
                // ID_NOT_EXIST) and every relay close/timeout stay generic, so
                // an hbbr problem is never reported as a wrong key.
                if response.other_failure.is_empty() {
                    match response.failure.enum_value() {
                        Ok(PunchFailure::LICENSE_MISMATCH) => {
                            return Err(invalid("Key mismatch"));
                        }
                        Ok(PunchFailure::LICENSE_OVERUSE) => {
                            return Err(invalid("Key overuse"));
                        }
                        _ => {}
                    }
                }
                return Err(invalid("Peer unavailable or rendezvous request refused"));
            }
            if response.is_udp {
                return Err(invalid("Unexpected UDP route for TCP punch request"));
            }
            let key = peer_key(&response.pk, &config)?;
            let address = peer_address(&response.socket_addr)?;
            let relay = relay_name(&config, &response.relay_server).ok();
            drop(wire);
            let remaining = deadline.saturating_duration_since(Instant::now());
            let budget = if relay.is_some() {
                (remaining / 2).min(Duration::from_secs(3))
            } else {
                remaining
            };
            match timeout(budget, dial(address, Some(local))).await {
                Ok(Ok(peer)) => finish(peer, &config, key, RouteKind::TcpHolePunch, deadline).await,
                _ => {
                    let relay = relay.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "TCP hole punch failed; no relay available",
                        )
                    })?;
                    request_relay(&config, &relay, key, mode, deadline).await
                }
            }
        }
        Some(rendezvous_message::Union::RelayResponse(response)) => {
            if !response.refuse_reason.is_empty() {
                return Err(invalid("Relay request refused"));
            }
            let key = peer_key(response.pk(), &config)?;
            // This UUID was paired with the advertised relay, not a configured override.
            let relay = endpoint(&response.relay_server, 21117)?;
            drop(wire);
            join_relay(&config, &relay, response.uuid, key, mode, deadline).await
        }
        _ => Err(invalid("Unexpected rendezvous response")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RendezvousConfig {
        RendezvousConfig {
            id: "123456789".into(),
            rendezvous_server: "127.0.0.1".into(),
            licence_key: "test-key".into(),
            server_key: Some(sign::PublicKey([0; 32])),
            relay_server: None,
            connect_timeout: Duration::from_secs(5),
        }
    }

    fn punch_role(config: &RendezvousConfig, mode: SessionMode) -> ConnType {
        match punch_hole_request(config, mode).union {
            Some(rendezvous_message::Union::PunchHoleRequest(request)) => {
                request.conn_type.enum_value().expect("a known punch role")
            }
            _ => panic!("punch request builder produced another message"),
        }
    }

    fn hbbs_relay_role(config: &RendezvousConfig, mode: SessionMode) -> ConnType {
        match relay_request(config, "127.0.0.1:21117", "uuid", mode).union {
            Some(rendezvous_message::Union::RequestRelay(request)) => {
                request.conn_type.enum_value().expect("a known hbbs relay role")
            }
            _ => panic!("hbbs relay request builder produced another message"),
        }
    }

    fn hbbr_join_role(config: &RendezvousConfig, mode: SessionMode) -> ConnType {
        match relay_join_request(config, "uuid".to_owned(), mode).union {
            Some(rendezvous_message::Union::RequestRelay(request)) => {
                request.conn_type.enum_value().expect("a known hbbr join role")
            }
            _ => panic!("hbbr join builder produced another message"),
        }
    }

    fn join_licence(config: &RendezvousConfig) -> String {
        match relay_join_request(config, "uuid".to_owned(), SessionMode::Desktop).union {
            Some(rendezvous_message::Union::RequestRelay(request)) => request.licence_key,
            _ => panic!("hbbr join builder produced another message"),
        }
    }

    /// One Key: the same text reaches the hbbs punch and the hbbr join, and the
    /// hbbs-side relay negotiation never carries a licence.
    #[test]
    fn the_single_key_reaches_both_hbbs_and_hbbr() {
        let mut config = config();
        config.licence_key = "shared-licence".into();
        config.server_key = None;
        let punch = match punch_hole_request(&config, SessionMode::Desktop).union {
            Some(rendezvous_message::Union::PunchHoleRequest(request)) => request.licence_key,
            _ => panic!("punch request builder produced another message"),
        };
        assert_eq!(punch, "shared-licence");
        assert_eq!(join_licence(&config), "shared-licence");
        let hbbs_relay = match relay_request(&config, "relay.example:21117", "uuid", SessionMode::Desktop)
            .union
        {
            Some(rendezvous_message::Union::RequestRelay(request)) => request.licence_key,
            _ => panic!("hbbs relay request builder produced another message"),
        };
        assert!(hbbs_relay.is_empty());
    }

    /// Without a trust root nothing is verified, whatever the hbbs record says;
    /// with one, a bad signature is an error instead of an unverified fallback.
    #[test]
    fn no_trust_root_means_no_peer_key_and_a_trust_root_still_refuses_bad_signatures() {
        let mut config = config();
        assert!(peer_key(b"not signed", &config).is_err());
        config.server_key = None;
        assert_eq!(peer_key(b"not signed", &config).unwrap(), None);
    }

    /// The role belongs to the attempt, not to the route taken: every request
    /// hbbs/hbbr receives carries the same value, and `Desktop` keeps the
    /// original default that a relay-only peer already sees today.
    #[test]
    fn fixed_role_reaches_punch_hbbs_relay_and_hbbr_join() {
        let config = config();
        for (mode, role) in [
            (SessionMode::Desktop, ConnType::DEFAULT_CONN),
            (SessionMode::FileTransfer, ConnType::FILE_TRANSFER),
        ] {
            assert_eq!(punch_role(&config, mode), role, "{mode:?} punch");
            assert_eq!(hbbs_relay_role(&config, mode), role, "{mode:?} hbbs relay");
            assert_eq!(hbbr_join_role(&config, mode), role, "{mode:?} hbbr join");
        }
    }
}
