//! Host-side rendezvous service: UDP registration/heartbeat, the controller routes
//! hbbs hands this host (TCP punch, intranet local address, hbbr relay pairing), and
//! the TCP presence query.
//!
//! Wire behavior follows the pinned OSS `rendezvous_server.rs` and `relay_server.rs`
//! at commit `a7736be5e40f85bfc141120dce587e836e5d4b80`. The engine's shared
//! protobuf source is pinned separately by `vendor/rustdesk/UPSTREAM.json`.
//! Local socket reuse, prepare-before-announce ordering, crossing dial, and handoff
//! policies are local algorithms requiring platform-specific proof and are never
//! claimed to be upstream contracts.
//!
//! A server answer is an unauthenticated observation, not authentication:
//! * `RegisterPeer`, `RegisterPk`, their responses and `ConfigUpdate` travel
//!   unsigned over UDP. Pinning the configured endpoint plus length/message-type
//!   checks on the current run still does not authenticate the server, so the only
//!   registration state published here is an `Observed` *observation*.
//! * UDP has no nonces, cryptographic signatures, or transaction authentication.
//!   An attacker capable of forging UDP source addresses or replaying packets
//!   cannot be cryptographically distinguished by this service. Therefore, this
//!   service never claims authenticated registration.
//! * `Observed` indicates only that a server answered OK to this run's own `RegisterPk`
//!   submission for the supplied id/uuid/pk; it does not indicate that a controller
//!   can reach this host, that hbbs signed our key, that any caller is authorized,
//!   or that any media path is ready.
//! * `AddressObserved` indicates only that the server answered a heartbeat and
//!   refreshed its view of our registered UDP address; it does NOT confirm that the
//!   server accepted the supplied uuid or public key.
//! * `ConfigUpdate.rendezvous_servers` is never applied: an unsigned datagram
//!   cannot replace the configured trust root. Only its serial is echoed for this
//!   run so the server stops pushing the same update. Nothing is persisted.
//! * A route's `ControlPermissions.permissions` arrives unauthenticated from the
//!   network and may only restrict local grants; the caller intersects it with its
//!   own authority. `Some(0)` is strictly restrictive (denying all permissions).
//! * `RegisterPk.keep_alive` has no defined unit in the pinned protobuf, so it is
//!   reported raw (`Observed.keep_alive_raw`) and never used to schedule anything.
//!   The heartbeat interval is this module's own pinned `REG_INTERVAL`.
//! * `old_id`/`no_register_device` are left unset: this engine never migrates or
//!   replaces an identity silently. Pinned server rejects ids shorter than 6 bytes
//!   with `UUID_MISMATCH` (S:377-378); such ids are rejected at preflight.
//!
//! Route semantics:
//! * hbbs pushes `PunchHole`/`FetchLocalAddr`/`RequestRelay` to the host's
//!   registered UDP address, while the host answers on a fresh TCP connection to
//!   hbbs (`PunchHoleSent`, `LocalAddr`, `RelayResponse`). The punch/local reply
//!   must never be sent on the UDP socket.
//! * Local route (`FetchLocalAddr`): prepares an independently bound ready listener
//!   on the local network interface BEFORE announcing the address via `LocalAddr` to
//!   hbbs. The server does not require the control source port to be used (M10).
//! * TCP punch (`PunchHole`): prepares the accepting listener on the punch port
//!   before sending `PunchHoleSent` from that exact same port (using socket reuse)
//!   so that the server-observed TCP source mapping (S:637-668) is preserved and the
//!   listener is already waiting when the controller connects.
//! * Relay trust (`RequestRelay`): controller-forwarded `RequestRelay.relay_server`
//!   is NOT server authorization (S:522-535). Only the independently configured
//!   trusted relay (`RegistrationConfig.relay_server`) may receive the local
//!   `licence_key`. If a controller proposes a different relay instance, the request
//!   is refused. Server-selected `PunchHole.relay_server` is an unauthenticated hint
//!   and is never joined without independent configuration.
//! * Relay readiness before positive announcement: the host resolves, connects to,
//!   and submits `RequestRelay` join to hbbr BEFORE sending a positive `RelayResponse`
//!   to hbbs. If hbbr connection/join fails, a refusal is announced to hbbs and no
//!   route is published. hbbr sends no pairing ACK (R:461-498); the stream is handed
//!   off unread and intact so the peer's first record is preserved.
//! * Relay pairing ownership: one bounded reservation per UUID and fixed approved
//!   relay in this registration run. Its lease is carried by the actual transport,
//!   surviving task completion and route handoff. Repeated envelopes cannot replace
//!   its first metadata. Live entries are never evicted; retired entries remain for
//!   65s, covering both pinned hbbr 30s windows plus margin. This is local duplicate
//!   ownership prevention, not cryptographic UDP replay protection across epochs.
//! * Unmet security and context requirements (`secure`, `controlled_context`, `token`,
//!   `switch_code`) are immutably preserved in `RouteRequirements` for the downstream
//!   Host owner; they are never claimed to be satisfied by this module.
//! * Lifecycle: startup DNS resolution, socket binding, and every await/send is
//!   enclosed in the same cancel / deadline / `routes.closed()` boundary. An idle or
//!   preclosed receiver causes immediate termination. Owned route tasks are aborted
//!   and awaited before terminal state publication.
//!   Each admitted route additionally has one absolute CONNECT_WINDOW deadline
//!   covering all acquisition phases and sends; no route is published after expiry.
//! * Scrubbing: owned registration UUID buffers and serialized registration datagrams
//!   are scrubbed using sodiumoxide `memzero` on normal and cancelled drops.

use super::{dial, dial_socket, endpoint, invalid, peer_address, send, timed_out, valid_address};
use crate::handshake::AUTH_MAX_RECORD_BYTES;
use hbb_common::{
    AddrMangle,
    bytes::Bytes,
    protobuf::Message as _,
    rendezvous_proto::{
        ConnType, FetchLocalAddr, LocalAddr, NatType, OnlineRequest, PunchHole, PunchHoleSent,
        RegisterPeer, RegisterPk, RelayResponse, RendezvousMessage, RequestRelay,
        register_pk_response, rendezvous_message,
    },
    sodiumoxide::{crypto::sign, utils::memzero},
    tcp::FramedStream,
    uuid::Uuid,
};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval_at, sleep, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

/// Original hbbs/hbbr control port. UDP registration and TCP control connections share it.
const RENDEZVOUS_PORT: u16 = 21116;
/// Original hbbr port.
const RELAY_PORT: u16 = 21117;
/// Original NAT/presence listener port answering `OnlineRequest`.
const PRESENCE_PORT: u16 = 21115;
/// Largest UDP datagram this service reads.
const MAX_DATAGRAM_BYTES: usize = 2048;
/// Pinned hbb_common `REG_INTERVAL` and heartbeat timer.
const REG_INTERVAL: Duration = Duration::from_millis(15_000);
/// Pinned hbb_common TTL plus heartbeat margin: observations unrefreshed past this become Stale.
const STALE_AFTER: Duration = Duration::from_millis(45_000);
/// Pinned hbb_common `CONNECT_TIMEOUT`: ceiling for route acquisition.
const CONNECT_WINDOW: Duration = Duration::from_millis(18_000);
/// Punched dials: initial delay, per-attempt ceiling, and backoff cap.
const PUNCH_FIRST_DELAY: Duration = Duration::from_millis(150);
const PUNCH_DIAL_MAX: Duration = Duration::from_secs(3);
const PUNCH_MAX_DELAY: Duration = Duration::from_secs(2);
/// Maximum concurrent in-flight route acquisitions.
const MAX_INFLIGHT_ROUTES: usize = 32;
/// Live relay pairings plus retired tombstones; live entries are never evicted.
const MAX_RELAY_RESERVATIONS: usize = 256;
/// Pinned hbbr permits 30s for the first record, then 30s for pairing (R:461-498).
/// Local send/drop does not prove the first record arrived; cover both plus a margin.
const RELAY_RETIRE_WINDOW: Duration = Duration::from_secs(65);
/// Minimum id length accepted by pinned server profile (S:377-378).
const MIN_ID_BYTES: usize = 6;
/// Bounds on caller-supplied material.
const ID_MAX_BYTES: usize = 512;
const UUID_MAX_BYTES: usize = 64;
const RELAY_UUID_MAX_BYTES: usize = 64;
const MAX_PRESENCE_PEERS: usize = 4096;
const MAX_PRESENCE_WINDOW: Duration = Duration::from_secs(60);
const MAX_REGISTRATION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// Pinned server rate-limit window: resets per-id RegisterPk counter after 6s (S:411-416).
const KEY_SUBMISSION_WINDOW: Duration = Duration::from_secs(6);
/// Protocol generation advertised in control responses. Non-empty string gates server signing
/// of peer IdPk (S:1234-1257).
const ADVERTISED_VERSION: &str = "1.4.9";
/// Refusal reasons reported to controller through hbbs.
const UNSUPPORTED_CONN_TYPE: &str = "connection type not supported";
const NO_RELAY: &str = "no approved relay server configured";
const RELAY_MISMATCH: &str = "proposed relay server not approved";
const BAD_PAIRING: &str = "invalid pairing uuid";

/// Wrapper for owned secret UUID buffers, ensuring zeroization on normal or cancelled drop.
struct ScrubbedUuid(Vec<u8>);

impl Drop for ScrubbedUuid {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}

impl AsRef<[u8]> for ScrubbedUuid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// RAII wrapper for serialized datagram buffers, ensuring zeroization on normal or cancelled drop.
struct ScrubbedVec(Vec<u8>);

impl Drop for ScrubbedVec {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}

/// Everything the registration worker needs. Contains identity material and licence key,
/// so it deliberately does not implement `Debug`.
pub struct RegistrationConfig {
    /// This host's id. Validated at preflight (must be alphanumeric/[-_.] and >= 6 bytes).
    pub id: String,
    /// Stable registration uuid from protected storage. Never rotated on conflict.
    pub registration_uuid: Vec<u8>,
    /// This host's Ed25519 public key.
    pub public_key: sign::PublicKey,
    /// hbbs hostname/IP with optional port (default 21116).
    pub rendezvous_server: String,
    /// Explicit, independently trusted relay server endpoint. Only this relay may receive
    /// `licence_key` for relay routes. Forwarded controller hints are refused if unapproved.
    pub relay_server: Option<String>,
    /// Exact licence/public key wire value. Never logged.
    pub licence_key: String,
    /// Total registration run window. BoundedCeiling: worker stops cleanly at deadline.
    pub deadline: Duration,
}

/// Where a route to a controller came from. Routing metadata only; not controller identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRouteKind {
    /// Direct TCP connection completed on a punched port.
    TcpHolePunch,
    /// Controller connected directly to this host's intranet address.
    Local,
    /// Local end of an hbbr pairing stream where RequestRelay join was submitted.
    /// Does NOT indicate that a peer is present, that pairing succeeded, or that
    /// the peer is authenticated.
    Relay,
}

/// Uninterpreted security and context requirements attached to the controller's request.
/// Pinned protobuf and server sources define field syntax only; their authorization
/// semantics are not established by allowed sources, so this engine preserves them
/// immutably for the downstream Host owner rather than claiming they are satisfied.
#[derive(Clone, PartialEq, Eq)]
pub struct RouteRequirements {
    /// The `RequestRelay.secure` flag (false for punch and local routes, which do not
    /// carry this field in pinned protobuf).
    pub secure: bool,
    /// `ControlledContext.conn_audit_ref`, when supplied by the request.
    pub conn_audit_ref: Option<String>,
    /// Whether the controller supplied an account token. This engine implements no
    /// account flow; token presence is recorded without granting authority.
    pub token_present: bool,
    /// Whether the controller supplied a switch code.
    pub switch_code_present: bool,
}

impl std::fmt::Debug for RouteRequirements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteRequirements")
            .field("secure", &self.secure)
            .field(
                "conn_audit_ref",
                &self.conn_audit_ref.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_present", &self.token_present)
            .field("switch_code_present", &self.switch_code_present)
            .finish()
    }
}

/// One controller route handed to caller exactly once.
///
/// The stream is complete and unsplit: framing state, already buffered bytes, and
/// nonce counters move with it. Nothing is read from it here, so a relayed peer's
/// first record is never consumed.
pub struct IncomingHostRoute {
    pub stream: FramedStream,
    /// Routing metadata only. For direct/local routes, the accepted connection peer;
    /// for relay routes, the controller address reported by hbbs. Never controller identity.
    pub peer: SocketAddr,
    pub kind: HostRouteKind,
    /// Raw server-supplied `ControlPermissions.permissions` ceiling. `Some(0)` is
    /// strictly restrictive (denies all permissions). May only restrict local grants.
    pub permissions: Option<u64>,
    /// Requirements carried by the controller's request.
    pub requirements: RouteRequirements,
}

/// The server's record for this id contradicts the supplied stable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityConflict {
    /// `RegisterPkResponse::UUID_MISMATCH`: server has another uuid (or key) registered.
    UuidMismatch,
    /// `RegisterPkResponse::ID_EXISTS`: the id is claimed by another deployment.
    IdExists,
}

/// A transient server refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRefusal {
    TooFrequent,
    NotDeployed,
    ServerError,
}

/// A terminal local or protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationFailure {
    InvalidIdFormat,
    Unsupported,
    UnusableAnswer,
    Transport,
}

/// Why the worker stopped without a conflict or failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    Cancelled,
    Deadline,
    ConsumerClosed,
}

/// Observable registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    /// Registration attempt in progress.
    Registering,
    /// The server answered this run's heartbeat for the supplied id and refreshed
    /// the registered address. The supplied uuid and public key were NOT yet
    /// acknowledged in this run, so this is an address observation, not an identity
    /// observation.
    AddressObserved,
    /// The server answered this run's own `RegisterPk` submission for the supplied
    /// id+uuid+key with OK. Unverified observation over unsigned UDP, not
    /// authenticated identity or authorization. `keep_alive_raw` is the server's
    /// raw int32; pinned protobuf defines no unit, so nothing is scheduled from it.
    Observed { keep_alive_raw: i32 },
    /// An earlier observation was not refreshed within the local stale window.
    Stale,
    /// Transient server refusal.
    Refused(ServerRefusal),
    /// Server record conflicts with supplied identity. Terminal.
    Conflict(IdentityConflict),
    /// Terminal local/protocol failure.
    Failed(RegistrationFailure),
    /// Worker stopped cleanly. Terminal; route tasks were aborted and awaited before
    /// this state was published.
    Stopped(StopReason),
}

/// Configuration for presence query.
pub struct PresenceConfig {
    pub endpoint: String,
    pub local_id: String,
    pub peers: Vec<String>,
    pub timeout: Duration,
}

/// One peer's presence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceState {
    Online,
    Offline,
}

/// Runs hbbs registration, heartbeats, and controller route serving.
///
/// Preflight validation is a synchronous contract: configuration errors return immediately
/// with `ErrorKind::InvalidInput` before any I/O, without publishing state or binding sockets.
///
/// Owned registration UUID is guarded by `ScrubbedUuid` before any preflight/startup returns.
/// Protobuf clones share an owner with Drop scrub (`Bytes::from_owner`) rather than new
/// unguarded allocations.
///
/// A unified cancellation / deadline / closed boundary encloses the entire drive future.
/// Any await inside drive (startup resolve, bind, datagram send, handle, etc.) is cancelled
/// immediately if cancellation, deadline, or routes.closed() fires.
///
/// Every return outside preflight aborts and awaits all owned route tasks before publishing
/// its terminal state (`Stopped`, `Conflict`, or `Failed`). Route streams already handed off
/// to the `routes` channel are owned by the caller; worker shutdown does not revoke them.
pub async fn run_host_registration(
    config: RegistrationConfig,
    cancel: CancellationToken,
    states: watch::Sender<RegistrationState>,
    routes: mpsc::Sender<IncomingHostRoute>,
) -> io::Result<()> {
    // Guard UUID before all preflight/startup returns
    let guarded_uuid = ScrubbedUuid(config.registration_uuid);

    // Synchronous configuration preflight
    if config.id.len() < MIN_ID_BYTES
        || !valid_id(&config.id)
        || guarded_uuid.0.is_empty()
        || guarded_uuid.0.len() > UUID_MAX_BYTES
        || config.licence_key.is_empty()
        || config.licence_key.len() > 1024
        || config
            .licence_key
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        || config.deadline.is_zero()
        || config.deadline > MAX_REGISTRATION_WINDOW
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid registration configuration",
        ));
    }
    let rendezvous = endpoint(&config.rendezvous_server, RENDEZVOUS_PORT)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let relay = match &config.relay_server {
        Some(relay) => Some(
            endpoint(relay, RELAY_PORT)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        ),
        None => None,
    };

    states.send_replace(RegistrationState::Registering);

    let until = Instant::now() + config.deadline;

    // Protobuf clones share an owner with Drop scrub: Bytes::from_owner
    let uuid_bytes = Bytes::from_owner(guarded_uuid);

    let mut tasks: JoinSet<RouteOutcome> = JoinSet::new();
    // Drop the pinned future itself before joining the tasks it borrows.
    let ending = {
        // Unified drive future enclosing startup DNS/bind and the event loop.
        let drive = async {
            let (server, socket) = match async {
                let server = resolve(&rendezvous, until).await?;
                let socket = bind_udp(server, until).await?;
                Ok::<_, io::Error>((server, socket))
            }
            .await
            {
                Ok(pair) => pair,
                Err(_) => return Ending::Failed(RegistrationFailure::Transport),
            };

            let mut registration = Registration {
                id: config.id,
                uuid: uuid_bytes,
                pk: Bytes::copy_from_slice(&config.public_key.0),
                licence_key: config.licence_key,
                configured_relay: relay,
                server,
                states: states.clone(),
                routes: routes.clone(),
                serial: 0,
                keep_alive_raw: 0,
                identity_acknowledged: false,
                pk_submitted_at: None,
                last_pk_submission: None,
                answered_at: None,
                state: RegistrationState::Registering,
                pending: None,
                relay_reservations: HashMap::new(),
            };

            let mut heartbeat = interval_at(Instant::now(), REG_INTERVAL);
            heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut datagram = vec![0u8; MAX_DATAGRAM_BYTES + 1];

            loop {
                tokio::select! {
                    completion = tasks.join_next(), if !tasks.is_empty() => {
                        if matches!(completion, Some(Ok(RouteOutcome::ConsumerClosed))) {
                            return Ending::Stopped(StopReason::ConsumerClosed);
                        }
                    }
                    _ = heartbeat.tick() => {
                        if matches!(registration.state, RegistrationState::Observed { .. } | RegistrationState::AddressObserved)
                            && registration
                                .answered_at
                                .is_none_or(|at| at.elapsed() >= STALE_AFTER)
                        {
                            registration.publish(RegistrationState::Stale);
                        }
                        if send_datagram(&socket, server, &registration.heartbeat()).await.is_err() {
                            return Ending::Failed(RegistrationFailure::Transport);
                        }
                    }
                    received = socket.recv_from(&mut datagram) => {
                        let (length, origin) = match received {
                            Ok(res) => res,
                            Err(_) => return Ending::Failed(RegistrationFailure::Transport),
                        };
                        if origin != server || length > MAX_DATAGRAM_BYTES {
                            continue;
                        }
                        let Ok(message) = RendezvousMessage::parse_from_bytes(&datagram[..length]) else {
                            continue;
                        };
                        let Some(message) = message.union else {
                            continue;
                        };
                        if let Some(ending) = registration.handle(message, &socket).await {
                            return ending;
                        }
                        if let Some(mut request) = registration.pending.take() {
                            if tasks.len() < MAX_INFLIGHT_ROUTES && registration.reserve_relay(&mut request) {
                                let deadline = Instant::now() + CONNECT_WINDOW;
                                tasks.spawn(serve(request, registration.context(), deadline));
                            }
                        }
                    }
                }
            }
        };

        tokio::pin!(drive);

        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ending::Stopped(StopReason::Cancelled),
            _ = sleep_until(until) => Ending::Stopped(StopReason::Deadline),
            _ = routes.closed() => Ending::Stopped(StopReason::ConsumerClosed),
            ending = &mut drive => ending,
        }
    };

    // Reclaim and abort all in-flight route tasks before publishing terminal state.
    tasks.shutdown().await;

    match ending {
        Ending::Stopped(reason) => {
            states.send_replace(RegistrationState::Stopped(reason));
            match reason {
                StopReason::ConsumerClosed => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Host route consumer closed",
                )),
                StopReason::Cancelled | StopReason::Deadline => Ok(()),
            }
        }
        Ending::Conflict(conflict) => {
            states.send_replace(RegistrationState::Conflict(conflict));
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Registration identity conflict",
            ))
        }
        Ending::Failed(failure) => {
            states.send_replace(RegistrationState::Failed(failure));
            Err(match failure {
                RegistrationFailure::InvalidIdFormat => {
                    io::Error::new(io::ErrorKind::InvalidInput, "Server rejected the id format")
                }
                RegistrationFailure::Unsupported => {
                    io::Error::new(io::ErrorKind::Unsupported, "Registration is not supported")
                }
                RegistrationFailure::UnusableAnswer => invalid("Unusable registration answer"),
                RegistrationFailure::Transport => {
                    io::Error::new(io::ErrorKind::NotConnected, "Registration channel failed")
                }
            })
        }
    }
}

/// Executes a strict, bounded presence query.
///
/// Reads exactly one framed record expecting `OnlineResponse`. It does not inherit
/// the viewer's `KeyExchange` skip (S01), as the pinned presence listener (S:1123-1160)
/// sends only `OnlineResponse` or `TestNatResponse`.
pub async fn query_presence(config: PresenceConfig) -> io::Result<Vec<PresenceState>> {
    if config.local_id.len() < MIN_ID_BYTES
        || !valid_id(&config.local_id)
        || config.peers.is_empty()
        || config.peers.len() > MAX_PRESENCE_PEERS
        || config.peers.iter().any(|peer| !valid_id(peer))
        || config.timeout.is_zero()
        || config.timeout > MAX_PRESENCE_WINDOW
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid presence query",
        ));
    }
    let deadline = Instant::now() + config.timeout;
    let name = endpoint(&config.endpoint, PRESENCE_PORT)?;
    timeout_at(deadline, async move {
        let address = resolve(&name, deadline).await?;
        let mut wire = dial(address, None).await?;
        let mut request = RendezvousMessage::new();
        request.set_online_request(OnlineRequest {
            id: config.local_id,
            peers: config.peers.clone(),
            ..Default::default()
        });
        send(&mut wire, &request).await?;

        // Strict single-record presence response: pinned server sends OnlineResponse directly.
        let bytes = wire
            .next()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Presence closed"))?
            .map_err(|_| invalid("Invalid presence record"))?;
        let message = RendezvousMessage::parse_from_bytes(&bytes)
            .map_err(|_| invalid("Invalid presence message"))?;
        let Some(rendezvous_message::Union::OnlineResponse(response)) = message.union else {
            return Err(invalid("Presence endpoint answered a different message"));
        };
        let required = config.peers.len().div_ceil(8);
        if response.states.len() != required {
            return Err(invalid("Presence answer does not match the query"));
        }
        Ok(config
            .peers
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let byte = response.states[index / 8];
                if byte & (1u8 << (7 - index % 8)) != 0 {
                    PresenceState::Online
                } else {
                    PresenceState::Offline
                }
            })
            .collect())
    })
    .await
    .map_err(|_| timed_out())?
}

enum Ending {
    Stopped(StopReason),
    Conflict(IdentityConflict),
    Failed(RegistrationFailure),
}

enum RouteOutcome {
    Published,
    Dropped,
    ConsumerClosed,
}

struct Registration {
    id: String,
    uuid: Bytes,
    pk: Bytes,
    licence_key: String,
    configured_relay: Option<String>,
    server: SocketAddr,
    states: watch::Sender<RegistrationState>,
    routes: mpsc::Sender<IncomingHostRoute>,
    serial: i32,
    keep_alive_raw: i32,
    identity_acknowledged: bool,
    pk_submitted_at: Option<Instant>,
    last_pk_submission: Option<Instant>,
    answered_at: Option<Instant>,
    state: RegistrationState,
    pending: Option<RouteRequest>,
    relay_reservations: HashMap<String, RelayReservation>,
}

impl Registration {
    fn reserve_relay(&mut self, request: &mut RouteRequest) -> bool {
        let RouteRequest::Relay {
            uuid,
            refuse: None,
            reservation,
            ..
        } = request
        else {
            return true;
        };
        if self.configured_relay.is_none() {
            return true;
        }
        // The table is local to this registration epoch and its fixed trusted relay.
        // A stream lease survives task completion, handoff, and moving route.stream.
        let now = Instant::now();
        self.relay_reservations.retain(|_, entry| {
            if Arc::strong_count(&entry.lifetime) > 1 {
                return true;
            }
            let retired = *entry.retired_at.get_or_insert(now);
            now.duration_since(retired) < RELAY_RETIRE_WINDOW
        });
        if self.relay_reservations.contains_key(uuid)
            || self.relay_reservations.len() >= MAX_RELAY_RESERVATIONS
        {
            return false;
        }
        let lifetime = Arc::new(());
        *reservation = Some(lifetime.clone());
        self.relay_reservations.insert(
            uuid.clone(),
            RelayReservation {
                lifetime,
                retired_at: None,
            },
        );
        true
    }

    fn publish(&mut self, next: RegistrationState) {
        if self.state != next {
            self.state = next;
            self.states.send_replace(next);
        }
    }

    fn heartbeat(&self) -> RendezvousMessage {
        let mut message = RendezvousMessage::new();
        message.set_register_peer(RegisterPeer {
            id: self.id.clone(),
            serial: self.serial,
            ..Default::default()
        });
        message
    }

    fn key_submission(&self) -> RendezvousMessage {
        let mut message = RendezvousMessage::new();
        message.set_register_pk(RegisterPk {
            id: self.id.clone(),
            uuid: self.uuid.clone(),
            pk: self.pk.clone(),
            ..Default::default()
        });
        message
    }

    async fn maybe_submit_pk(&mut self, socket: &UdpSocket) -> io::Result<()> {
        let now = Instant::now();
        if let Some(last) = self.last_pk_submission {
            if now.duration_since(last) < KEY_SUBMISSION_WINDOW {
                return Ok(());
            }
        }
        send_datagram(socket, self.server, &self.key_submission()).await?;
        self.pk_submitted_at = Some(now);
        self.last_pk_submission = Some(now);
        Ok(())
    }

    fn context(&self) -> RouteContext {
        RouteContext {
            id: self.id.clone(),
            licence_key: self.licence_key.clone(),
            configured_relay: self.configured_relay.clone(),
            server: self.server,
            routes: self.routes.clone(),
        }
    }

    async fn handle(
        &mut self,
        message: rendezvous_message::Union,
        socket: &UdpSocket,
    ) -> Option<Ending> {
        match message {
            rendezvous_message::Union::RegisterPeerResponse(response) => {
                self.answered_at = Some(Instant::now());
                if response.request_pk {
                    // Server asks for public key (e.g. server has no key for id, or IP changed).
                    self.identity_acknowledged = false;
                    self.publish(RegistrationState::Registering);
                    if self.maybe_submit_pk(socket).await.is_err() {
                        return Some(Ending::Failed(RegistrationFailure::Transport));
                    }
                } else {
                    // Server refreshed registered address.
                    if self.identity_acknowledged {
                        self.publish(RegistrationState::Observed {
                            keep_alive_raw: self.keep_alive_raw,
                        });
                    } else {
                        // First address observation: server holds some key, but this run has
                        // NOT yet confirmed that the server holds OUR key (F03).
                        // Submit RegisterPk and publish AddressObserved.
                        self.publish(RegistrationState::AddressObserved);
                        if self.maybe_submit_pk(socket).await.is_err() {
                            return Some(Ending::Failed(RegistrationFailure::Transport));
                        }
                    }
                }
            }
            rendezvous_message::Union::RegisterPkResponse(response) => {
                // Expected response phase check (F04, M03):
                // Only accept RegisterPkResponse if a RegisterPk submission is currently pending.
                if self.pk_submitted_at.is_none() {
                    return None;
                }
                self.pk_submitted_at = None;
                self.answered_at = Some(Instant::now());
                self.keep_alive_raw = response.keep_alive;
                match response.result.enum_value() {
                    Ok(register_pk_response::Result::OK) => {
                        self.identity_acknowledged = true;
                        self.publish(RegistrationState::Observed {
                            keep_alive_raw: self.keep_alive_raw,
                        });
                    }
                    Ok(register_pk_response::Result::UUID_MISMATCH) => {
                        return Some(Ending::Conflict(IdentityConflict::UuidMismatch));
                    }
                    Ok(register_pk_response::Result::ID_EXISTS) => {
                        return Some(Ending::Conflict(IdentityConflict::IdExists));
                    }
                    Ok(register_pk_response::Result::TOO_FREQUENT) => {
                        self.publish(RegistrationState::Refused(ServerRefusal::TooFrequent));
                    }
                    Ok(register_pk_response::Result::NOT_DEPLOYED) => {
                        self.publish(RegistrationState::Refused(ServerRefusal::NotDeployed));
                    }
                    Ok(register_pk_response::Result::SERVER_ERROR) => {
                        self.publish(RegistrationState::Refused(ServerRefusal::ServerError));
                    }
                    Ok(register_pk_response::Result::INVALID_ID_FORMAT) => {
                        return Some(Ending::Failed(RegistrationFailure::InvalidIdFormat));
                    }
                    Ok(register_pk_response::Result::NOT_SUPPORT) => {
                        return Some(Ending::Failed(RegistrationFailure::Unsupported));
                    }
                    Err(_) => {
                        return Some(Ending::Failed(RegistrationFailure::UnusableAnswer));
                    }
                }
            }
            rendezvous_message::Union::ConfigureUpdate(update) => {
                self.serial = self.serial.max(update.serial);
            }
            rendezvous_message::Union::PunchHole(punch) => {
                self.punch(punch);
            }
            rendezvous_message::Union::FetchLocalAddr(fetch) => {
                self.local(fetch);
            }
            rendezvous_message::Union::RequestRelay(relay) => {
                self.relay_request(relay);
            }
            _ => {}
        }
        None
    }

    fn punch(&mut self, punch: PunchHole) {
        let Ok(controller) = peer_address(&punch.socket_addr) else {
            return;
        };
        let permissions = punch
            .control_permissions
            .into_option()
            .map(|p| p.permissions);
        let requirements = RouteRequirements {
            secure: false,
            conn_audit_ref: punch
                .controlled_context
                .into_option()
                .map(|c| c.conn_audit_ref),
            token_present: false,
            switch_code_present: false,
        };
        if punch.force_relay || punch.nat_type.enum_value() == Ok(NatType::SYMMETRIC) {
            self.pending = Some(RouteRequest::Relay {
                controller,
                uuid: Uuid::new_v4().to_string(),
                initiated: true,
                permissions,
                requirements,
                refuse: None,
                reservation: None,
            });
        } else {
            self.pending = Some(RouteRequest::Punch {
                controller,
                permissions,
                requirements,
            });
        }
    }

    fn local(&mut self, fetch: FetchLocalAddr) {
        let Ok(controller) = peer_address(&fetch.socket_addr) else {
            return;
        };
        let permissions = fetch
            .control_permissions
            .into_option()
            .map(|p| p.permissions);
        let requirements = RouteRequirements {
            secure: false,
            conn_audit_ref: fetch
                .controlled_context
                .into_option()
                .map(|c| c.conn_audit_ref),
            token_present: false,
            switch_code_present: false,
        };
        self.pending = Some(RouteRequest::Local {
            controller,
            permissions,
            requirements,
        });
    }

    fn relay_request(&mut self, relay: RequestRelay) {
        if !relay.id.is_empty() && relay.id != self.id {
            return;
        }
        let Ok(controller) = peer_address(&relay.socket_addr) else {
            return;
        };
        let permissions = relay
            .control_permissions
            .into_option()
            .map(|p| p.permissions);
        let requirements = RouteRequirements {
            secure: relay.secure,
            conn_audit_ref: relay
                .controlled_context
                .into_option()
                .map(|c| c.conn_audit_ref),
            token_present: !relay.token.is_empty(),
            switch_code_present: !relay.switch_code.is_empty(),
        };
        if relay.uuid.is_empty()
            || relay.uuid.len() > RELAY_UUID_MAX_BYTES
            || relay.uuid.chars().any(char::is_whitespace)
        {
            self.refuse_relay(controller, BAD_PAIRING, requirements);
            return;
        }
        let refuse = if relay.conn_type.enum_value() != Ok(ConnType::DEFAULT_CONN) {
            Some(UNSUPPORTED_CONN_TYPE)
        } else {
            match (&self.configured_relay, &relay.relay_server) {
                (None, _) => {
                    // No approved relay configured; forwarded proposal cannot be trusted (F02).
                    Some(NO_RELAY)
                }
                (Some(_configured), proposed) if !proposed.is_empty() => {
                    match endpoint(proposed, RELAY_PORT) {
                        Ok(normalized) if &normalized == _configured => None,
                        _ => Some(RELAY_MISMATCH),
                    }
                }
                (Some(_), _) => None,
            }
        };
        self.pending = Some(RouteRequest::Relay {
            controller,
            uuid: relay.uuid,
            initiated: false,
            permissions,
            requirements,
            refuse,
            reservation: None,
        });
    }

    fn refuse_relay(
        &mut self,
        controller: SocketAddr,
        reason: &'static str,
        requirements: RouteRequirements,
    ) {
        self.pending = Some(RouteRequest::Relay {
            controller,
            uuid: String::new(),
            initiated: false,
            permissions: None,
            requirements,
            refuse: Some(reason),
            reservation: None,
        });
    }
}

struct RelayReservation {
    lifetime: Arc<()>,
    retired_at: Option<Instant>,
}

/// The lease belongs to the transport, not the temporary route envelope. No extra
/// socket boxing, frame copy, or reservation-table work occurs during I/O.
struct ReservedRelayStream {
    stream: TcpStream,
    _reservation: Arc<()>,
}

impl AsyncRead for ReservedRelayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReservedRelayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

struct RouteContext {
    id: String,
    licence_key: String,
    configured_relay: Option<String>,
    server: SocketAddr,
    routes: mpsc::Sender<IncomingHostRoute>,
}

impl RouteContext {
    fn publish(self, route: IncomingHostRoute) -> RouteOutcome {
        match self.routes.try_send(route) {
            Ok(()) => RouteOutcome::Published,
            Err(mpsc::error::TrySendError::Full(_)) => RouteOutcome::Dropped,
            Err(mpsc::error::TrySendError::Closed(_)) => RouteOutcome::ConsumerClosed,
        }
    }
}

enum RouteRequest {
    Punch {
        controller: SocketAddr,
        permissions: Option<u64>,
        requirements: RouteRequirements,
    },
    Local {
        controller: SocketAddr,
        permissions: Option<u64>,
        requirements: RouteRequirements,
    },
    Relay {
        controller: SocketAddr,
        uuid: String,
        initiated: bool,
        permissions: Option<u64>,
        requirements: RouteRequirements,
        refuse: Option<&'static str>,
        reservation: Option<Arc<()>>,
    },
}

async fn serve(request: RouteRequest, context: RouteContext, deadline: Instant) -> RouteOutcome {
    if Instant::now() >= deadline {
        return RouteOutcome::Dropped;
    }
    let acquire = async {
        match request {
            RouteRequest::Punch {
                controller,
                permissions,
                requirements,
            } => punch_route(&context, controller, permissions, requirements).await,
            RouteRequest::Local {
                controller,
                permissions,
                requirements,
            } => local_route(&context, controller, permissions, requirements).await,
            RouteRequest::Relay {
                controller,
                uuid,
                initiated,
                permissions,
                requirements,
                refuse,
                reservation,
            } => {
                relay_route(
                    &context,
                    controller,
                    uuid,
                    initiated,
                    permissions,
                    requirements,
                    refuse,
                    reservation,
                )
                .await
            }
        }
    };
    match timeout_at(deadline, acquire).await {
        Ok(Ok(route)) if Instant::now() < deadline => context.publish(route),
        _ => RouteOutcome::Dropped,
    }
}

/// TCP punch route acquisition with prepare-before-announce ordering.
///
/// Binds the listening socket on port P with reuse before dialing hbbs from that same port,
/// so the listener is already live when `PunchHoleSent` is transmitted.
async fn punch_route(
    context: &RouteContext,
    controller: SocketAddr,
    permissions: Option<u64>,
    requirements: RouteRequirements,
) -> io::Result<IncomingHostRoute> {
    let local_bind: SocketAddr = if context.server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let listener_socket = new_socket(context.server)?;
    listener_socket.bind(local_bind)?;
    let listener = listener_socket.listen(64)?;
    let punch_port = listener.local_addr()?.port();

    let dial_bind: SocketAddr = if context.server.is_ipv4() {
        ([0, 0, 0, 0], punch_port).into()
    } else {
        ([0u16; 8], punch_port).into()
    };
    let dial_socket = new_socket(context.server)?;
    dial_socket.bind(dial_bind)?;
    let wire = timeout(CONNECT_WINDOW, dial_socket.connect(context.server))
        .await
        .map_err(|_| timed_out())??;
    let local = wire.local_addr()?;
    if local.port() != punch_port {
        return Err(invalid("Punch source port mapping invariant violated"));
    }
    let mut wire = FramedStream::from(wire, local);
    wire.0
        .codec_mut()
        .set_max_packet_length(AUTH_MAX_RECORD_BYTES);

    let relay_hint = context.configured_relay.clone().unwrap_or_default();
    let mut message = RendezvousMessage::new();
    message.set_punch_hole_sent(PunchHoleSent {
        socket_addr: AddrMangle::encode(controller).into(),
        id: context.id.clone(),
        relay_server: relay_hint,
        nat_type: NatType::UNKNOWN_NAT.into(),
        version: ADVERTISED_VERSION.to_owned(),
        ..Default::default()
    });
    send(&mut wire, &message).await?;

    let local_punch_addr = SocketAddr::new(
        if controller.is_ipv4() {
            [0, 0, 0, 0].into()
        } else {
            [0u16; 8].into()
        },
        punch_port,
    );
    let (stream, peer) = punched_connection(listener, local_punch_addr, controller, true).await?;
    route_from_stream(
        stream,
        peer,
        HostRouteKind::TcpHolePunch,
        permissions,
        requirements,
    )
}

/// Intranet route acquisition with prepare-before-announce ordering.
///
/// Binds an independently listening socket on the local interface before announcing
/// its address via `LocalAddr` to hbbs. Controller connects immediately without retries.
async fn local_route(
    context: &RouteContext,
    controller: SocketAddr,
    permissions: Option<u64>,
    requirements: RouteRequirements,
) -> io::Result<IncomingHostRoute> {
    let mut wire = timeout(CONNECT_WINDOW, dial(context.server, None))
        .await
        .map_err(|_| timed_out())??;
    let local_ip = wire.local_addr().ip();

    let listener = listen_local(SocketAddr::new(local_ip, 0))?;
    let advertised_addr = listener.local_addr()?;

    let relay_hint = context.configured_relay.clone().unwrap_or_default();
    let mut message = RendezvousMessage::new();
    message.set_local_addr(LocalAddr {
        socket_addr: AddrMangle::encode(controller).into(),
        local_addr: AddrMangle::encode(advertised_addr).into(),
        relay_server: relay_hint,
        id: context.id.clone(),
        version: ADVERTISED_VERSION.to_owned(),
        ..Default::default()
    });
    send(&mut wire, &message).await?;

    let accept = timeout(CONNECT_WINDOW, listener.accept())
        .await
        .map_err(|_| timed_out())??;
    let (stream, peer) = accept;
    route_from_stream(
        stream,
        peer,
        HostRouteKind::Local,
        permissions,
        requirements,
    )
}

/// Relay pairing through hbbr with relay readiness before positive notification.
///
/// Only the configured, independently trusted relay is used. The hbbr connection and
/// RequestRelay join are submitted BEFORE announcing positive confirmation to hbbs.
/// hbbr has no success acknowledgement; the stream is handed off intact and unread.
async fn relay_route(
    context: &RouteContext,
    controller: SocketAddr,
    uuid: String,
    initiated: bool,
    permissions: Option<u64>,
    requirements: RouteRequirements,
    refuse: Option<&'static str>,
    reservation: Option<Arc<()>>,
) -> io::Result<IncomingHostRoute> {
    if let Some(reason) = refuse {
        let mut response = RelayResponse {
            socket_addr: AddrMangle::encode(controller).into(),
            refuse_reason: reason.to_owned(),
            version: ADVERTISED_VERSION.to_owned(),
            ..Default::default()
        };
        if !uuid.is_empty() {
            response.uuid = uuid;
        }
        announce(context, response).await?;
        return Err(invalid("Relay request refused"));
    }

    let Some(relay_target) = &context.configured_relay else {
        announce_refusal(context, controller, &uuid, NO_RELAY).await?;
        return Err(invalid("No approved relay server configured"));
    };
    let Some(reservation) = reservation else {
        return Err(invalid("Relay acquisition has no pairing reservation"));
    };

    let connect_deadline = Instant::now() + CONNECT_WINDOW;
    let hbbr_addr = match resolve(relay_target, connect_deadline).await {
        Ok(addr) => addr,
        Err(_) => {
            announce_refusal(context, controller, &uuid, "relay resolution failed").await?;
            return Err(invalid("Relay resolution failed"));
        }
    };

    let stream = match timeout(CONNECT_WINDOW, dial_socket(hbbr_addr, None)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            announce_refusal(context, controller, &uuid, "relay connection failed").await?;
            return Err(invalid("Relay connection failed"));
        }
    };
    let local = stream.local_addr()?;
    let mut hbbr_wire = FramedStream::from(
        ReservedRelayStream {
            stream,
            _reservation: reservation,
        },
        local,
    );
    hbbr_wire
        .0
        .codec_mut()
        .set_max_packet_length(AUTH_MAX_RECORD_BYTES);

    let mut join_msg = RendezvousMessage::new();
    join_msg.set_request_relay(RequestRelay {
        licence_key: context.licence_key.clone(),
        uuid: uuid.clone(),
        ..Default::default()
    });
    if send(&mut hbbr_wire, &join_msg).await.is_err() {
        announce_refusal(context, controller, &uuid, "relay join failed").await?;
        return Err(invalid("Relay join submission failed"));
    }

    let mut response = RelayResponse {
        socket_addr: AddrMangle::encode(controller).into(),
        uuid: uuid.clone(),
        relay_server: relay_target.clone(),
        version: ADVERTISED_VERSION.to_owned(),
        ..Default::default()
    };
    if initiated {
        response.set_id(context.id.clone());
    }
    announce(context, response).await?;

    Ok(IncomingHostRoute {
        stream: hbbr_wire,
        peer: controller,
        kind: HostRouteKind::Relay,
        permissions,
        requirements,
    })
}

async fn announce_refusal(
    context: &RouteContext,
    controller: SocketAddr,
    uuid: &str,
    reason: &'static str,
) -> io::Result<()> {
    let mut response = RelayResponse {
        socket_addr: AddrMangle::encode(controller).into(),
        refuse_reason: reason.to_owned(),
        version: ADVERTISED_VERSION.to_owned(),
        ..Default::default()
    };
    if !uuid.is_empty() {
        response.uuid = uuid.to_owned();
    }
    announce(context, response).await
}

async fn announce(context: &RouteContext, response: RelayResponse) -> io::Result<()> {
    let mut wire = timeout(CONNECT_WINDOW, dial(context.server, None))
        .await
        .map_err(|_| timed_out())??;
    let mut message = RendezvousMessage::new();
    message.set_relay_response(response);
    send(&mut wire, &message).await
}

async fn punched_connection(
    listener: TcpListener,
    local: SocketAddr,
    controller: SocketAddr,
    dial_back: bool,
) -> io::Result<(TcpStream, SocketAddr)> {
    let until = Instant::now() + CONNECT_WINDOW;
    let accept = async { listener.accept().await };
    let dial = async {
        if !dial_back || local.is_ipv4() != controller.is_ipv4() {
            return std::future::pending().await;
        }
        dial_backs(local, controller, until).await
    };
    tokio::select! {
        biased;
        result = dial => result,
        result = accept => result,
        _ = sleep_until(until) => Err(timed_out()),
    }
}

async fn dial_backs(
    local: SocketAddr,
    controller: SocketAddr,
    until: Instant,
) -> io::Result<(TcpStream, SocketAddr)> {
    let mut delay = PUNCH_FIRST_DELAY;
    loop {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let attempt = dial_local(local, controller);
        if let Ok(stream) = timeout(remaining.min(PUNCH_DIAL_MAX), attempt).await {
            if let Ok(stream) = stream {
                return Ok((stream, controller));
            }
        }
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        sleep(delay.min(remaining)).await;
        delay = (delay.mul_f32(1.5)).min(PUNCH_MAX_DELAY);
    }
}

async fn dial_local(local: SocketAddr, controller: SocketAddr) -> io::Result<TcpStream> {
    if !valid_address(controller) || local.is_ipv4() != controller.is_ipv4() {
        return Err(invalid("Invalid punched address"));
    }
    let socket = new_socket(controller)?;
    socket.bind(local)?;
    let stream = socket.connect(controller).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn listen_local(local: SocketAddr) -> io::Result<TcpListener> {
    // Port zero asks the OS for an ephemeral listener; it is not a remote route.
    if local.ip().is_unspecified() || local.ip().is_multicast() {
        return Err(invalid("Invalid listen address"));
    }
    let socket = new_socket(local)?;
    socket.bind(local)?;
    socket.listen(64)
}

fn new_socket(address: SocketAddr) -> io::Result<TcpSocket> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(all(unix, not(target_os = "illumos")))]
    socket.set_reuseport(true)?;
    Ok(socket)
}

fn route_from_stream(
    stream: TcpStream,
    peer: SocketAddr,
    kind: HostRouteKind,
    permissions: Option<u64>,
    requirements: RouteRequirements,
) -> io::Result<IncomingHostRoute> {
    let local = stream.local_addr()?;
    let mut wire = FramedStream::from(stream, local);
    wire.0
        .codec_mut()
        .set_max_packet_length(AUTH_MAX_RECORD_BYTES);
    Ok(IncomingHostRoute {
        stream: wire,
        peer,
        kind,
        permissions,
        requirements,
    })
}

async fn send_datagram(
    socket: &UdpSocket,
    server: SocketAddr,
    message: &RendezvousMessage,
) -> io::Result<()> {
    let bytes = ScrubbedVec(
        message
            .write_to_bytes()
            .map_err(|_| invalid("Registration serialization failed"))?,
    );
    if bytes.0.len() > MAX_DATAGRAM_BYTES {
        return Err(invalid("Oversized registration datagram"));
    }
    timeout(Duration::from_secs(2), socket.send_to(&bytes.0, server))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP send stalled"))??;
    Ok(())
}

async fn bind_udp(server: SocketAddr, until: Instant) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let remaining = until.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(timed_out());
    }
    timeout(remaining, UdpSocket::bind(bind))
        .await
        .map_err(|_| timed_out())?
}

async fn resolve(name: &str, deadline: Instant) -> io::Result<SocketAddr> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(timed_out());
    }
    let resolved = timeout(remaining, lookup_host(name))
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "Server resolution failed"))?;
    let candidates: Vec<SocketAddr> = resolved.filter(|address| valid_address(*address)).collect();
    candidates
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| candidates.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Server has no usable address"))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= ID_MAX_BYTES
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_route_listener_cannot_restart_the_acquisition_budget() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (routes, mut receiver) = mpsc::channel(1);
        let context = RouteContext {
            id: "host01".into(),
            licence_key: "test-key".into(),
            configured_relay: None,
            server: server.local_addr().unwrap(),
            routes,
        };
        let request = RouteRequest::Local {
            controller: "127.0.0.1:44332".parse().unwrap(),
            permissions: None,
            requirements: RouteRequirements {
                secure: false,
                conn_audit_ref: None,
                token_present: false,
                switch_code_present: false,
            },
        };
        // An acquisition may enter a phase with less than a fresh CONNECT_WINDOW.
        let deadline = Instant::now() + CONNECT_WINDOW / 2;
        let worker = tokio::spawn(serve(request, context, deadline));
        let (stream, address) = timeout(Duration::from_secs(3), server.accept())
            .await
            .unwrap()
            .unwrap();
        let mut wire = FramedStream::from(stream, address);
        let announcement = timeout(Duration::from_secs(3), wire.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let message = RendezvousMessage::parse_from_bytes(&announcement).unwrap();
        let Some(rendezvous_message::Union::LocalAddr(local)) = message.union else {
            panic!("Expected local listener announcement");
        };
        let listener_address = AddrMangle::decode(&local.local_addr);

        // Real socket setup is complete; only the waiting clock is simulated.
        tokio::time::pause();
        tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
        let outcome = timeout(Duration::from_millis(1), worker)
            .await
            .expect("Listener reset the whole acquisition deadline")
            .unwrap();
        assert!(matches!(outcome, RouteOutcome::Dropped));
        assert!(
            receiver.recv().await.is_none(),
            "Expired route was published"
        );
        tokio::time::resume();
        assert!(
            TcpStream::connect(listener_address).await.is_err(),
            "Expired acquisition retained its listener"
        );
    }
}
