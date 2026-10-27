//! Explicitly approved viewing host. No legacy app runtime.
//! Authentication is not capture consent; the publisher retains the OS prompt.
//! Remote keyboard/pointer input is a separate local grant that stays off unless
//! this machine asked for it, and it exists only where an injection adapter and
//! a bound output do. Clipboard/file/audio adapters are absent and never granted.
#[cfg(all(target_os = "windows", feature = "official-account"))]
pub mod control;
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
use crate::windows_input::{InputError, InputSession, TargetBinding, bind_output_key};
mod ingress;
use ingress::{Ingress, authenticate, serve};
use crate::{
    authentication::{
        Approval, ApprovalProvider, AttemptPolicy, HostAuthConfig, NoSecondFactor, Passwords,
        Permissions, PrimaryPolicy,
    },
    handshake::{self, HostIdentity, Security},
    publisher::{
        Codec, CodecSelection, EncodedUnit, Publisher, PublisherBackend, PublisherConfig,
        PublisherError,
    },
    session::{AuthenticatedParts, HostEvent, HostSession},
    transport::{WireReader, WireWriter},
    rendezvous::IncomingHostRoute,
};
use base::message_proto::{
    self as proto, DisplayInfo, EncodedVideoFrame, EncodedVideoFrames, KeyEvent, LoginRequest,
    Message, MouseEvent, PeerInfo, SupportedEncoding, VideoFrame, message, misc,
    supported_decoding::PreferCodec,
};
use hbb_common::{futures::future::join_all, sodiumoxide::{self, crypto::sign}, tcp::FramedStream};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch, Semaphore},
    task::{Id, JoinSet},
};
use tokio_util::sync::CancellationToken;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The display this host publishes, resolved exactly once in [`Host::start`].
///
/// On Windows it is the operator's selected output: an opaque stable key bound
/// to the adapter LUID and native output index, re-verified before and after
/// every capture open. It is never re-resolved by ordinal after start, so a
/// reordered or detached output cannot be published under the requested
/// configuration. Every other publisher still selects a display by enumeration
/// index and has no binding or injection adapter.
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
#[derive(Clone)]
struct DisplayBinding(TargetBinding);
#[cfg(not(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
)))]
#[derive(Clone, Copy)]
struct DisplayBinding(usize);

#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
impl DisplayBinding {
    fn bind(options: &HostOptions) -> Result<Self, HostError> {
        let binding = bind_output_key(&options.output_key).map_err(display_binding_error)?;
        // The configured geometry is what the peer is told and what the encoder
        // is opened with: a mismatch would advertise one screen and capture
        // another.
        if binding.width() != options.width || binding.height() != options.height {
            return Err(HostError::InvalidOptions);
        }
        Ok(Self(binding))
    }
}
#[cfg(not(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
)))]
impl DisplayBinding {
    fn bind(options: &HostOptions) -> Result<Self, HostError> {
        Ok(Self(options.output_index))
    }
}

/// Maps a refused display binding onto the host's own error. A missing or
/// changed output is never silently replaced by another one.
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
fn display_binding_error(error: InputError) -> HostError {
    match error {
        InputError::InvalidInput => HostError::InvalidOptions,
        InputError::ReclamationUnconfirmed => HostError::ReclamationUnconfirmed,
        _ => HostError::UnsupportedDisplay,
    }
}

/// Maps a refused input grant. The grant was asked for locally and is advertised
/// during authentication, so a desktop or binding the adapter cannot inject into
/// is reported instead of becoming a silent view-only session. An unconfirmed
/// reclamation is never reported as anything else.
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
fn input_grant_error(error: InputError) -> HostError {
    match error {
        InputError::ReclamationUnconfirmed => HostError::ReclamationUnconfirmed,
        _ => HostError::InputUnavailable,
    }
}

/// Classifies one refused injected event. Malformed and unsupported events are
/// refused without being claimed as injected; a lost desktop, output or
/// injection path ends this peer's input instead of pretending it still works.
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
fn input_event_error(error: InputError) -> Option<HostError> {
    match error {
        InputError::InvalidInput | InputError::Unsupported => None,
        InputError::ReclamationUnconfirmed => Some(HostError::ReclamationUnconfirmed),
        InputError::DesktopUnavailable
        | InputError::OutputChanged
        | InputError::InjectionFailed => Some(HostError::InputFailed),
    }
}

/// One peer session's injected-input lease. A lease exists only for an
/// authenticated session whose negotiated permissions included this machine's
/// keyboard/pointer grant, and only on a platform whose publisher has an
/// injection adapter. Everywhere else there is nothing to open, inject or
/// release, and nothing can be created either: the local grant is refused at
/// start.
#[derive(Default)]
struct PeerLease {
    #[cfg(all(
        any(target_os = "windows", dsh_windows_typecheck),
        feature = "windows-modern-producer"
    ))]
    session: Option<InputSession>,
}

#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
impl PeerLease {
    /// Opens the lease for a session this machine's grant covers. The adapter
    /// verifies the ordinary interactive desktop and the bound output before it
    /// is handed out.
    fn open(granted: bool, display: &DisplayBinding) -> Result<Self, HostError> {
        if !granted {
            return Ok(Self { session: None });
        }
        let session = InputSession::open(display.0.clone()).map_err(input_grant_error)?;
        Ok(Self {
            session: Some(session),
        })
    }

    fn apply_mouse(&mut self, event: &MouseEvent) -> Result<(), HostError> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        match input_event_error_of(session.mouse(event)) {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }

    fn apply_key(&mut self, event: &KeyEvent) -> Result<(), HostError> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        match input_event_error_of(session.key(event)) {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }

    /// Gives up every key and button this session injected down. Drop is only a
    /// last-defense best effort; this call is the boundary the host reports, and
    /// anything the adapter cannot confirm stays unconfirmed.
    fn release(&mut self) -> Result<(), HostError> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        session
            .release_all()
            .map_err(|_| HostError::ReclamationUnconfirmed)
    }
}
#[cfg(not(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
)))]
impl PeerLease {
    fn open(granted: bool, _: &DisplayBinding) -> Result<Self, HostError> {
        // A local grant cannot be reached here: `Host::start` refuses it, so no
        // session can negotiate input and this lease stays empty.
        debug_assert!(!granted);
        Ok(Self {})
    }

    fn apply_mouse(&mut self, _: &MouseEvent) -> Result<(), HostError> {
        Ok(())
    }

    fn apply_key(&mut self, _: &KeyEvent) -> Result<(), HostError> {
        Ok(())
    }

    fn release(&mut self) -> Result<(), HostError> {
        Ok(())
    }
}

#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
fn input_event_error_of(result: Result<(), InputError>) -> Option<HostError> {
    result.err().and_then(input_event_error)
}

/// Native-only verifier material. No plaintext, Debug or secret cloning.
pub struct HostCredentials {
    pub revision: u64,
    pub salt: String,
    pub passwords: Passwords,
    pub policy: PrimaryPolicy,
    temporary: Arc<Mutex<TemporaryPasswordState>>,
    automatic_rotation: bool,
}
#[derive(Default)]
struct TemporaryPasswordState { failures: u8, rotation_requested: bool }
impl HostCredentials {
    pub fn new(revision: u64, salt: String, passwords: Passwords, policy: PrimaryPolicy) -> Self {
        Self { revision, salt, passwords, policy, temporary: Arc::new(Mutex::new(TemporaryPasswordState::default())), automatic_rotation: false }
    }
    pub(crate) fn managed(revision: u64, salt: String, passwords: Passwords, policy: PrimaryPolicy) -> Self {
        let mut credentials = Self::new(revision, salt, passwords, policy);
        credentials.automatic_rotation = true;
        credentials
    }
    pub(crate) fn revised(revision: u64, salt: String, passwords: Passwords, policy: PrimaryPolicy, previous: &Self) -> Self {
        Self { revision, salt, passwords, policy, temporary: previous.temporary.clone(), automatic_rotation: previous.automatic_rotation }
    }
    pub(crate) fn take_temporary_rotation(&self) -> bool {
        std::mem::take(&mut lock(&self.temporary).rotation_requested)
    }
    pub(crate) fn reset_temporary_failures(&self) {
        *lock(&self.temporary) = TemporaryPasswordState::default();
    }
}

pub struct HostOptions {
    /// A direct listener exists only when explicitly enabled locally.
    pub listen: Option<SocketAddr>,
    /// Explicit compatibility policy; routed secure requirements always win.
    pub allow_legacy_plain: bool,
    pub id: String,
    /// Human-readable device name, not the signed peer identity or login target.
    pub display_name: String,
    pub signing_key: sign::SecretKey,
    pub width: i32,
    pub height: i32,
    pub bitrate: i64,
    pub platform: String,
    pub credentials: Arc<HostCredentials>,
    pub publisher_backend: PublisherBackend,
    /// The exact desktop output this host may publish, by its stable binding key
    /// (adapter LUID plus native output index).
    #[cfg(all(
        any(target_os = "windows", dsh_windows_typecheck),
        feature = "windows-modern-producer"
    ))]
    pub output_key: String,
    /// Every non-Windows publisher still selects a display by enumeration index
    /// and has no binding or injection adapter.
    #[cfg(not(all(
        any(target_os = "windows", dsh_windows_typecheck),
        feature = "windows-modern-producer"
    )))]
    pub output_index: usize,
    /// Local grant of remote keyboard/pointer input. Only this process can set
    /// it, and every remote preference can only remove from it.
    pub allow_input: bool,
    pub codec_selection: CodecSelection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    InvalidOptions,
    NoRuntime,
    NoHardwareCodec,
    ListenFailed,
    TransportFailed,
    AuthenticationFailed,
    ApprovalDenied,
    NoCommonCodec,
    /// A signed frame-rate request that is neither zero (unspecified) nor inside
    /// the range this engine can publish. The session is refused instead of
    /// clamped: a post-authentication configuration failure, not an
    /// authentication verdict.
    InvalidFrameRate,
    CaptureFailed,
    InvalidAccessUnit,
    UnsupportedDisplay,
    /// The local grant asked for remote input this platform or adapter cannot
    /// inject into. There is no silent view-only fallback.
    InputUnavailable,
    /// An authorized session's input could not be applied while it was live.
    InputFailed,
    ReclamationUnconfirmed,
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for HostError {}

#[derive(Clone)]
pub struct HostSnapshot {
    pub ready: bool,
    pub phase: &'static str,
    pub error: Option<HostError>,
    /// Locally generated request epoch, not a remote identity/credential.
    pub approval_request: String,
    /// Observed TCP origin only. It is not a cryptographic controller identity.
    pub approval_origin: String,
    pub width: i32,
    pub height: i32,
    /// The cadence the most recently begun session's client asked for, `0` when
    /// that peer named none. It is the request [`HostSnapshot::fps`] was resolved
    /// from: never a rate this host chose and never a measurement.
    pub client_requested_fps: u32,
    /// The resolved target of that same session attempt: the client's exact
    /// request, or the engine's own default when the request was absent. `0`
    /// before any peer begins. Only a request that resolved is published here, so
    /// a refused one cannot displace the last valid rate.
    pub fps: u32,
    pub codec: &'static str,
    pub connected: bool,
    pub encrypted: bool,
    /// Authorized live peers. Accepted sockets that have not authenticated are
    /// not peers yet.
    pub active_peers: u32,
    /// Whether this host may still inject remote input: true only while the
    /// local grant is on and the host has not been asked to stop.
    pub input_enabled: bool,
    pub sent_units: u64,
    pub sent_bytes: u64,
    pub closed: bool,
}
impl HostSnapshot {
    /// A closing host and a host that reached a terminal phase own their status.
    /// One peer's asynchronous progress may not rewind either.
    fn is_final(&self) -> bool {
        matches!(self.phase, "closing" | "closed" | "reclamation_unconfirmed")
    }
}

/// One authentication epoch's own request. The decision and the wake-up it owns
/// belong to this epoch alone: another peer's approval, denial, timeout or
/// disconnect can neither satisfy nor clear it.
struct PendingApproval {
    origin: String,
    decision: Mutex<Decision>,
    notify: tokio::sync::Notify,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Pending,
    Approve,
    Deny,
}

/// Everything the host publishes about one accepted peer, plus the native
/// ownership the accept loop needs when that peer's task ends.
#[derive(Default)]
struct PeerRecord {
    /// Set once authentication authorized this session. `active_peers` counts
    /// authorized sessions, not accepted sockets.
    authorized: AtomicBool,
    encrypted: AtomicBool,
    /// Set before the task creates its first native owner (capture/encoder or
    /// input lease). A task that panics after this point cannot prove that its
    /// native teardown finished.
    native: AtomicBool,
    control: Option<Arc<PeerControl>>,
}

#[derive(Clone)]
pub struct HostPeerSnapshot {
    pub conn_id: i32,
    pub connection_token: u64,
    pub approval_epoch: Option<u64>,
    pub policy_revision: u64,
    pub peer_id: String,
    pub name: String,
    pub authorized: bool,
    pub disconnected: bool,
    pub phase: &'static str,
    pub keyboard: bool,
    pub error: Option<HostError>,
}

enum PeerCommand {
    Keyboard { enabled: bool, deadline: Instant, reply: oneshot::Sender<Result<(), HostError>> },
    Disconnect { deadline: tokio::time::Instant, reply: oneshot::Sender<Result<(), HostError>> },
}

struct PeerControl {
    snapshot: Mutex<HostPeerSnapshot>,
    cancel: CancellationToken,
    commands: mpsc::Sender<PeerCommand>,
    finished: watch::Sender<Option<Result<(), HostError>>>,
}

impl PeerControl {
    async fn cancel_and_wait(&self) -> Result<(), HostError> {
        let mut finished = self.finished.subscribe();
        self.cancel.cancel();
        loop {
            if let Some(result) = *finished.borrow() { return result; }
            finished.changed().await.map_err(|_| HostError::ReclamationUnconfirmed)?;
        }
    }
}

struct ApprovalGuard { state: Arc<State>, epoch: u64, record: Arc<PeerRecord> }
impl Drop for ApprovalGuard {
    fn drop(&mut self) {
        self.state.clear_approval(self.epoch);
        if let Some(control) = &self.record.control {
            lock(&control.snapshot).approval_epoch = None;
            self.state.changed();
        }
    }
}

struct State {
    cancel: CancellationToken,
    snapshot: Mutex<HostSnapshot>,
    /// Requests awaiting a local decision, oldest epoch first.
    pending: Mutex<BTreeMap<u64, Arc<PendingApproval>>>,
    /// Every accepted peer task by task id. Held for the aggregate snapshot and
    /// for attributing a JoinError to the ownership of that task.
    peers: Mutex<HashMap<Id, Arc<PeerRecord>>>,
    unreclaimed: AtomicBool,
    controls: Mutex<BTreeMap<i32, Arc<PeerControl>>>,
    credentials: Mutex<Arc<HostCredentials>>,
    changes: watch::Sender<u64>,
    finished: AtomicBool,
    allow_remote_cm: AtomicBool,
    auth_admission: AtomicBool,
}

// Tokens never reset when the local listener is stopped/restarted.
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(0);
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(0);
const MAX_PREAUTH: usize = 16;
const MAX_PEER_RECORDS: usize = 256;
// Bounds notification only; native creation and checked cleanup remain joined.
const MANUAL_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

impl State {
    fn close_auth_admission(&self) {
        self.auth_admission.store(false, Ordering::Release);
        for peer in lock(&self.controls).values() {
            if !lock(&peer.snapshot).authorized { peer.cancel.cancel(); }
        }
    }
    fn request_temporary_rotation(&self) {
        let credentials = lock(&self.credentials);
        if !credentials.automatic_rotation { return; }
        lock(&credentials.temporary).rotation_requested = true;
        self.close_auth_admission();
        self.changed();
    }
    fn temporary_password_outcome(&self, revision: u64, matched: bool) {
        let credentials = lock(&self.credentials);
        if credentials.revision != revision || !self.auth_admission.load(Ordering::Acquire) { return; }
        let mut temporary = lock(&credentials.temporary);
        if matched { temporary.failures = 0; return; }
        temporary.failures = temporary.failures.saturating_add(1);
        if temporary.failures < 10 { return; }
        temporary.rotation_requested = true;
        drop(temporary);
        self.close_auth_admission();
        self.changed();
    }
    fn changed(&self) { self.changes.send_modify(|revision| *revision = revision.wrapping_add(1)); }
    fn update(&self, change: impl FnOnce(&mut HostSnapshot)) {
        change(&mut lock(&self.snapshot));
        self.changed();
    }
    /// Publishes one peer's asynchronous progress. Closing and terminal phases
    /// are owned by the host lifecycle, so a late peer update cannot overwrite
    /// them.
    fn progress(&self, change: impl FnOnce(&mut HostSnapshot)) {
        self.update(|snapshot| {
            if !snapshot.is_final() {
                change(snapshot);
            }
        });
    }
    fn finish(&self, result: Result<(), HostError>) {
        // A startup probe can retain native owners before any peer is tracked.
        if result == Err(HostError::ReclamationUnconfirmed) {
            self.unreclaimed.store(true, Ordering::Release);
        }
        self.clear_approvals();
        let safe = !self.unreclaimed.load(Ordering::Acquire);
        self.update(|s| {
            s.ready = false;
            if let Err(error) = result {
                s.error = Some(error);
            }
            s.connected = false;
            s.encrypted = false;
            s.active_peers = 0;
            s.input_enabled = false;
            s.closed = safe;
            s.phase = if safe {
                "closed"
            } else {
                "reclamation_unconfirmed"
            };
        });
        self.finished.store(true, Ordering::Release);
        self.changed();
    }
    /// Publishes one completed access unit. The counters are host-lifetime
    /// totals of transport writes that finished; they never restart because
    /// another socket authenticated.
    fn streamed(&self, bytes: usize) {
        let edge = {
            let mut snapshot = lock(&self.snapshot);
            let edge = !snapshot.is_final() && snapshot.phase != "streaming";
            if edge { snapshot.phase = "streaming"; }
            snapshot.sent_units = snapshot.sent_units.saturating_add(1);
            snapshot.sent_bytes = snapshot.sent_bytes.saturating_add(bytes as u64);
            edge
        };
        if edge { self.changed(); }
    }

    /// Registers this epoch's request, keeping the entry and any decision
    /// already latched for it when the same peer asks again.
    fn request_approval(&self, epoch: u64, origin: &str) -> Arc<PendingApproval> {
        let entry = {
            let mut pending = lock(&self.pending);
            Arc::clone(pending.entry(epoch).or_insert_with(|| {
                Arc::new(PendingApproval {
                    origin: origin.to_owned(),
                    decision: Mutex::new(Decision::Pending),
                    notify: tokio::sync::Notify::new(),
                })
            }))
        };
        self.publish_oldest_pending();
        entry
    }
    /// Latches one operator decision. Only the exact epoch that is still
    /// awaiting a decision can be answered, and only that epoch is woken.
    fn decide(&self, epoch: u64, allow: bool) -> bool {
        let entry = {
            let mut pending = lock(&self.pending);
            let Some(entry) = pending.get_mut(&epoch) else {
                return false;
            };
            let mut decision = lock(&entry.decision);
            if *decision != Decision::Pending {
                return false;
            }
            *decision = if allow {
                Decision::Approve
            } else {
                Decision::Deny
            };
            Arc::clone(entry)
        };
        // The decision is published before the wake-up; the awaiting peer
        // re-reads it under the same lock.
        entry.notify.notify_one();
        self.publish_oldest_pending();
        true
    }
    /// Drops exactly one epoch's request. Every other peer keeps its own.
    fn clear_approval(&self, epoch: u64) {
        if lock(&self.pending).remove(&epoch).is_some() {
            self.publish_oldest_pending();
        }
    }
    /// Drops every request. Only a host that has no peer left may do this, so it
    /// is called where the host itself reaches a terminal state.
    fn clear_approvals(&self) {
        lock(&self.pending).clear();
        self.publish_oldest_pending();
    }
    /// The oldest request still awaiting a local decision is the singular one the
    /// snapshot shows. An answered request is not displayed again.
    fn publish_oldest_pending(&self) {
        let pending = lock(&self.pending);
        let oldest = pending
            .iter()
            .find(|(_, entry)| *lock(&entry.decision) == Decision::Pending)
            .map(|(epoch, entry)| (epoch.to_string(), entry.origin.clone()));
        self.update(|snapshot| match oldest {
            Some((request, origin)) => {
                snapshot.approval_request = request;
                snapshot.approval_origin = origin;
            }
            None => {
                snapshot.approval_request.clear();
                snapshot.approval_origin.clear();
            }
        });
    }

    /// Closes the host from this point on: nothing new is accepted and no further
    /// input is injected, while every peer that exists is still put through its
    /// own cleanup. A terminal snapshot is never rewound by a repeated request.
    fn request_close(&self) {
        self.cancel.cancel();
        self.update(|s| {
            s.ready = false;
            s.input_enabled = false;
            if !s.is_final() {
                s.phase = "closing";
            }
        });
    }

    /// Tracks one accepted peer task. Called before its completion can be
    /// observed, so a finished task is never mistaken for one that owns nothing.
    fn track_peer(&self, id: Id, record: Arc<PeerRecord>) {
        lock(&self.peers).insert(id, record);
    }
    /// Marks one session authorized for the host-wide snapshot.
    fn authorize_peer(&self, record: &PeerRecord, encrypted: bool) {
        record.encrypted.store(encrypted, Ordering::Release);
        record.authorized.store(true, Ordering::Release);
        self.publish_peers();
    }
    /// Publishes the aggregate the live peer set implies.
    fn publish_peers(&self) {
        let (active, encrypted) = {
            let peers = lock(&self.peers);
            peers_aggregate(peers.values().map(|record| &**record))
        };
        self.update(|snapshot| {
            snapshot.active_peers = active;
            snapshot.connected = active > 0;
            snapshot.encrypted = encrypted;
        });
    }
}

/// The aggregate every live peer set implies, exactly as the snapshot publishes
/// it: `active` counts authorized sessions (not accepted sockets), and
/// `encrypted` is true only when every one of them is encrypted — never for
/// zero, mixed or plaintext peers.
fn peers_aggregate<'a>(records: impl IntoIterator<Item = &'a PeerRecord>) -> (u32, bool) {
    let mut active = 0_u32;
    let mut encrypted = true;
    for record in records {
        if !record.authorized.load(Ordering::Acquire) {
            continue;
        }
        active = active.saturating_add(1);
        encrypted &= record.encrypted.load(Ordering::Acquire);
    }
    (active, active > 0 && encrypted)
}

pub struct Host {
    state: Arc<State>,
    join: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Host {
    pub fn start(options: HostOptions, routes: Option<mpsc::Receiver<IncomingHostRoute>>) -> Result<Self, HostError> {
        if options.id.is_empty()
            || options.id.len() > 512
            || options.display_name.is_empty()
            || options.display_name.len() > 512
            || options.display_name.chars().any(char::is_control)
            || options.listen.is_some_and(|listen| listen.port() == 0)
            || (options.listen.is_none() && routes.is_none())
            || options.credentials.salt.is_empty()
            || !(1..=8192).contains(&options.width)
            || !(1..=8192).contains(&options.height)
            || i64::from(options.width) * i64::from(options.height) > 33_554_432
            || !(100_000..=200_000_000).contains(&options.bitrate)
            || options.platform.is_empty()
        {
            return Err(HostError::InvalidOptions);
        }
        // The display is bound once, before anything is advertised or captured.
        let display = DisplayBinding::bind(&options)?;
        // Without the Windows producer no publisher or input adapter exists, so
        // a local input grant cannot be honored and is not advertised.
        #[cfg(not(all(
            any(target_os = "windows", dsh_windows_typecheck),
            feature = "windows-modern-producer"
        )))]
        if options.allow_input {
            return Err(HostError::InputUnavailable);
        }
        // The grant is advertised to a peer during authentication, so this
        // machine must be able to inject into its ordinary interactive desktop
        // before that. Opening the lease verifies the desktop and the binding
        // without changing OS state, and the lease is released through the same
        // checked boundary a peer uses.
        #[cfg(all(
            any(target_os = "windows", dsh_windows_typecheck),
            feature = "windows-modern-producer"
        ))]
        if options.allow_input {
            let mut lease = InputSession::open(display.0.clone()).map_err(input_grant_error)?;
            lease.release_all().map_err(input_grant_error)?;
        }
        sodiumoxide::init().map_err(|_| HostError::InvalidOptions)?;
        let runtime = crate::executor::runtime().map_err(|_| HostError::NoRuntime)?;
        let state = Arc::new(State {
            cancel: CancellationToken::new(),
            pending: Mutex::new(BTreeMap::new()),
            peers: Mutex::new(HashMap::new()),
            unreclaimed: AtomicBool::new(false),
            controls: Mutex::new(BTreeMap::new()),
            credentials: Mutex::new(options.credentials.clone()),
            changes: watch::channel(0).0,
            finished: AtomicBool::new(false),
            allow_remote_cm: AtomicBool::new(false),
            auth_admission: AtomicBool::new(true),
            snapshot: Mutex::new(HostSnapshot {
                ready: false,
                phase: "starting",
                error: None,
                approval_request: String::new(),
                approval_origin: String::new(),
                width: options.width,
                height: options.height,
                // No peer has begun yet: the singular rate fields stay idle
                // until an authenticated session resolves its own request.
                client_requested_fps: 0,
                fps: 0,
                codec: "",
                connected: false,
                encrypted: false,
                active_peers: 0,
                input_enabled: options.allow_input,
                sent_units: 0,
                sent_bytes: 0,
                closed: false,
            }),
        });
        let task_state = state.clone();
        let join = runtime.spawn(async move {
            let result = serve(task_state.clone(), Arc::new(options), display, routes).await;
            task_state.finish(result);
        });
        Ok(Self {
            state,
            join: Mutex::new(Some(join)),
        })
    }
    pub fn snapshot(&self) -> HostSnapshot {
        lock(&self.state.snapshot).clone()
    }
    pub fn approve(&self, request_id: &str, allow: bool) -> bool {
        let Ok(epoch) = request_id.parse::<u64>() else {
            return false;
        };
        // A stopped host authorizes nothing: the pending request belongs to an
        // authentication that is already failing closed.
        !self.state.cancel.is_cancelled() && self.state.decide(epoch, allow)
    }
    pub fn request_close(&self) {
        self.state.request_close();
    }
    pub async fn close(&self) -> Result<(), HostError> {
        self.request_close();
        let task = lock(&self.join).take();
        if let Some(task) = task {
            if task.await.is_err() {
                self.state.finish(Err(HostError::ReclamationUnconfirmed));
            }
        } else {
            let mut changes = self.subscribe_changes();
            while !self.state.finished.load(Ordering::Acquire) {
                if changes.changed().await.is_err() { break; }
            }
        }
        if self.state.unreclaimed.load(Ordering::Acquire) || !self.snapshot().closed {
            Err(HostError::ReclamationUnconfirmed)
        } else {
            Ok(())
        }
    }
    pub fn subscribe_changes(&self) -> watch::Receiver<u64> { self.state.changes.subscribe() }
    pub async fn wait_ready(&self) -> Result<(), HostError> {
        let mut changes = self.subscribe_changes();
        loop {
            let snapshot = self.snapshot();
            if snapshot.ready { return Ok(()); }
            if self.state.finished.load(Ordering::Acquire) {
                return Err(snapshot.error.unwrap_or(HostError::TransportFailed));
            }
            changes.changed().await.map_err(|_| HostError::TransportFailed)?;
        }
    }
    pub fn peers(&self) -> Vec<HostPeerSnapshot> {
        lock(&self.state.controls).values().map(|peer| lock(&peer.snapshot).clone()).collect()
    }
    fn peer_control(&self, conn_id: i32) -> Result<Arc<PeerControl>, HostError> {
        lock(&self.state.controls).get(&conn_id).cloned().ok_or(HostError::InvalidOptions)
    }
    pub fn approve_peer(&self, conn_id: i32, epoch: u64, revision: u64, allow: bool) -> Result<(), HostError> {
        let peer = self.peer_control(conn_id)?;
        let credentials = lock(&self.state.credentials);
        let snapshot = lock(&peer.snapshot);
        if snapshot.disconnected || peer.cancel.is_cancelled() || snapshot.approval_epoch != Some(epoch)
            || snapshot.policy_revision != revision || credentials.revision != revision
            || !self.approve(&epoch.to_string(), allow) {
            return Err(HostError::ApprovalDenied);
        }
        Ok(())
    }
    pub async fn disconnect(&self, conn_id: i32) -> Result<(), HostError> {
        let peer = self.peer_control(conn_id)?;
        // A dropped caller requests cancellation, never claims reclamation. The
        // accept loop still owns and joins this peer and its native cleanup.
        let _cancel_on_drop = peer.cancel.clone().drop_guard();
        let deadline = tokio::time::Instant::now() + MANUAL_CLOSE_TIMEOUT;
        let notification = self.notify_manual_close(&peer, deadline).await.map(|_| ());
        // Notification failure cannot bypass cleanup or erase quarantine, and a
        // clean native teardown cannot turn a failed notification into a receipt.
        peer.cancel_and_wait().await?;
        notification
    }
    // This stage observes only the sole writer's completed send. It deliberately
    // does not wait for native retirement, which the owning run joins on stop.
    async fn notify_manual_close(&self, peer: &PeerControl, deadline: tokio::time::Instant) -> Result<bool, HostError> {
        let notify = {
            let mut snapshot = lock(&peer.snapshot);
            if snapshot.authorized && !snapshot.disconnected && !peer.cancel.is_cancelled() {
                snapshot.phase = "disconnecting";
                snapshot.keyboard = false;
                true
            } else {
                false
            }
        };
        if !notify { return Ok(false); }
        self.state.changed();
        let (reply, result) = oneshot::channel();
        if peer.commands.try_send(PeerCommand::Disconnect { deadline, reply }).is_err() {
            return Err(HostError::TransportFailed);
        }
        tokio::select! {
            biased;
            // The writer acknowledges a completed send before it cancels.
            result = result => result.unwrap_or(Err(HostError::TransportFailed)).map(|_| true),
            _ = peer.cancel.cancelled() => Err(HostError::TransportFailed),
            _ = tokio::time::sleep_until(deadline) => Err(HostError::TransportFailed),
        }
    }

    /// Owner-only StopService notification, before the run cancels registration
    /// or ingress. The original run remains responsible for every native join.
    pub(crate) async fn notify_stop_service(&self, command_deadline: Option<Instant>) -> Result<(), HostError> {
        self.invalidate_authentication();
        let targets: Vec<_> = lock(&self.state.controls).values().filter(|peer| {
            let snapshot = lock(&peer.snapshot);
            snapshot.authorized && !snapshot.disconnected
        }).cloned().collect();
        if targets.is_empty() { return Ok(()); }
        let deadline = tokio::time::Instant::now() + MANUAL_CLOSE_TIMEOUT;
        let deadline = command_deadline.map_or(deadline, |original| deadline.min(tokio::time::Instant::from_std(original)));
        // Collect every result, not fail-fast: one broken writer cannot prevent
        // another live peer from receiving its own terminal reason. The single
        // absolute deadline bounds only sends; stop() always joins the cleanup.
        let receipts = tokio::time::timeout_at(deadline, join_all(targets.iter().map(|peer| {
            self.notify_manual_close(peer, deadline)
        }))).await;
        match receipts {
            Ok(receipts) if receipts.iter().all(|result| *result == Ok(true)) => Ok(()),
            _ => Err(HostError::TransportFailed),
        }
    }

    /// Fault/deadline cleanup, deliberately without the manual wire reason.
    pub async fn cancel_peer(&self, conn_id: i32) -> Result<(), HostError> {
        self.peer_control(conn_id)?.cancel_and_wait().await
    }
    pub async fn set_keyboard(&self, conn_id: i32, enabled: bool, deadline: Instant) -> Result<(), HostError> {
        let peer = self.peer_control(conn_id)?;
        {
            let snapshot = lock(&peer.snapshot);
            if !snapshot.authorized || snapshot.phase == "disconnecting" || peer.cancel.is_cancelled()
                || (enabled && Instant::now() >= deadline) { return Err(HostError::InputUnavailable); }
        }
        let (reply, result) = oneshot::channel();
        peer.commands.try_send(PeerCommand::Keyboard { enabled, deadline, reply }).map_err(|_| HostError::InputUnavailable)?;
        result.await.map_err(|_| HostError::InputFailed)?
    }
    pub fn remove_disconnected(&self, conn_id: i32) -> Result<(), HostError> {
        let mut peers = lock(&self.state.controls);
        let peer = peers.get(&conn_id).ok_or(HostError::InvalidOptions)?;
        let snapshot = lock(&peer.snapshot);
        if !snapshot.disconnected || snapshot.error == Some(HostError::ReclamationUnconfirmed) { return Err(HostError::ReclamationUnconfirmed); }
        drop(snapshot);
        peers.remove(&conn_id);
        drop(peers);
        self.state.changed();
        Ok(())
    }
    pub fn update_credentials(&self, credentials: Arc<HostCredentials>) {
        let mut current = lock(&self.state.credentials);
        *current = credentials;
        for peer in lock(&self.state.controls).values() {
            if !lock(&peer.snapshot).authorized { peer.cancel.cancel(); }
        }
        self.state.auth_admission.store(!lock(&current.temporary).rotation_requested, Ordering::Release);
        drop(current);
        self.state.changed();
    }
    pub fn invalidate_authentication(&self) {
        // Serialize the invalidation boundary with final authorization and CM
        // approval, not merely with the actor that eventually writes storage.
        let _credentials = lock(&self.state.credentials);
        self.state.close_auth_admission();
        self.state.changed();
    }
    pub fn set_remote_cm_policy(&self, enabled: bool) {
        self.state.allow_remote_cm.store(enabled, Ordering::Release);
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        self.request_close();
    }
}

struct LocalApproval {
    state: Arc<State>,
    epoch: u64,
    /// The local capability this machine offers when the operator approves. A
    /// remote preference can only remove from it.
    grant: Permissions,
}
impl ApprovalProvider for LocalApproval {
    fn check(&mut self, _: &LoginRequest) -> Approval {
        let pending = lock(&self.state.pending);
        match pending.get(&self.epoch).map(|entry| *lock(&entry.decision)) {
            Some(Decision::Approve) => Approval::Approved(self.grant),
            Some(Decision::Deny) => Approval::Denied,
            // A request this host has not registered yet, and one still waiting
            // for the operator, are both pending.
            Some(Decision::Pending) | None => Approval::Pending,
        }
    }
}
// Pinned connection::check_failure uses >6 failures in a minute and >30 total,
// clearing on authentication success. This host conservatively shares ONE
// bucket: unauthenticated relay metadata/claims cannot create fresh IP buckets.
// In-flight reservations close the cross-thread check/outcome race.
struct AttemptWindow { start: Instant, failures: u32, total: u32, in_flight: u32 }
struct SharedAttempts { state: Arc<State>, revision: u64 }
static ATTEMPTS: std::sync::LazyLock<Mutex<AttemptWindow>> = std::sync::LazyLock::new(|| Mutex::new(AttemptWindow {
    start: Instant::now(), failures: 0, total: 0, in_flight: 0,
}));
impl AttemptPolicy for SharedAttempts {
    fn allow(&mut self, second_factor: bool) -> Result<(), &'static str> {
        if second_factor { return Err("2FA verification unsupported"); }
        let mut window = lock(&ATTEMPTS);
        if window.start.elapsed() >= Duration::from_secs(60) { window.start = Instant::now(); window.failures = 0; }
        if window.total + window.in_flight > 30 { return Err("Too many wrong attempts"); }
        if window.failures + window.in_flight > 6 { return Err("Please try 1 minute later"); }
        window.in_flight += 1;
        Ok(())
    }
    fn outcome(&mut self, _: bool, accepted: bool) {
        let mut window = lock(&ATTEMPTS);
        window.in_flight = window.in_flight.saturating_sub(1);
        if accepted { window.failures = 0; window.total = 0; }
        else { window.failures = window.failures.saturating_add(1); window.total = window.total.saturating_add(1); }
    }
    fn temporary_password_outcome(&mut self, matched: bool) {
        self.state.temporary_password_outcome(self.revision, matched);
    }
}
fn authentication_succeeded() {
    let mut window = lock(&ATTEMPTS);
    window.failures = 0;
    window.total = 0;
}

/// The local effective permission set: only keyboard/pointer input can ever be
/// granted, and only because this machine asked for it.
fn local_permissions(options: &HostOptions) -> Permissions {
    Permissions {
        keyboard: options.allow_input,
        clipboard: false,
        audio: false,
        file: false,
    }
}

#[derive(Clone, Copy)]
struct Encoders {
    h264: bool,
    h265: bool,
}
fn publisher_config(
    options: &HostOptions,
    display: &DisplayBinding,
    codec: Codec,
    fps: u32,
) -> PublisherConfig {
    PublisherConfig {
        codec,
        width: options.width,
        height: options.height,
        fps,
        bitrate: options.bitrate,
        // Includes the AU currently being written. Two credits keep one ready
        // frame without accumulating a multi-frame capture-to-display tail.
        max_queued_units: 2,
        max_queued_bytes: 32 * 1024 * 1024,
        backend: options.publisher_backend,
        #[cfg(all(
            any(target_os = "windows", dsh_windows_typecheck),
            feature = "windows-modern-producer"
        ))]
        binding: display.0.clone(),
        #[cfg(not(all(
            any(target_os = "windows", dsh_windows_typecheck),
            feature = "windows-modern-producer"
        )))]
        output_index: display.0,
    }
}

/// The cadence this engine publishes to a peer whose signed request names none.
/// This is the engine's own default, not a protocol constant and not
/// independently configurable: only the client's request can move a session off
/// it.
const DEFAULT_REQUESTED_FPS: u32 = 60;
/// Highest cadence a peer's signed request may name. It matches what the
/// publishers accept; it is this implementation's policy, not a protocol
/// constant.
const MAX_REQUESTED_FPS: i32 = 240;

/// One authenticated session's frame-rate request, resolved once. Both fields
/// are published together and differ only for an absent request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameRateRequest {
    /// What the client asked for, `0` when it named none.
    client_requested_fps: u32,
    /// The cadence the publisher opens with.
    target_fps: u32,
}

/// Resolves one peer's signed `custom_fps` request.
///
/// The wire field is a plain signed int32 whose zero has no protocol-defined
/// meaning, so it is matched on its signed value before any conversion: zero
/// (and an absent option message) means the client named no cadence and the
/// engine's default applies, `1..=240` is used exactly as asked, and anything
/// else is a malformed request. A refused request is never clamped, wrapped or
/// published at a guessed cadence. Allocation-free: it runs inside one peer's
/// authenticated session setup.
fn resolve_frame_rate(requested: i32) -> Result<FrameRateRequest, HostError> {
    match requested {
        0 => Ok(FrameRateRequest {
            client_requested_fps: 0,
            target_fps: DEFAULT_REQUESTED_FPS,
        }),
        1..=MAX_REQUESTED_FPS => Ok(FrameRateRequest {
            client_requested_fps: requested as u32,
            target_fps: requested as u32,
        }),
        _ => Err(HostError::InvalidFrameRate),
    }
}
/// A capability probe that could not complete is not a codec verdict: a probe
/// that left native owners in doubt keeps the host from restarting as if
/// nothing were held.
fn probe_failure(error: PublisherError) -> HostError {
    if error.resources_unconfirmed() {
        HostError::ReclamationUnconfirmed
    } else {
        HostError::NoHardwareCodec
    }
}
/// A publisher that was already closing is not a failure; an unconfirmed
/// teardown is never reported as an ordinary capture failure.
fn publisher_failure(error: PublisherError) -> Option<HostError> {
    match error {
        PublisherError::Closed => None,
        error if error.resources_unconfirmed() => Some(HostError::ReclamationUnconfirmed),
        _ => Some(HostError::CaptureFailed),
    }
}
/// Cadence handed to the pre-authentication codec discovery probe.
///
/// The probe really initializes an encoder, so it needs a configuration the
/// publishers accept; the lowest accepted cadence is the most conservative one.
/// It answers only whether that codec initializes on this output, at that one
/// configuration: it is not a throughput measurement, not a transmission
/// ceiling for any session, and it does not claim that encoder initialization is
/// monotone in cadence. Every session later opens the publisher at its own
/// resolved target and keeps its own real failure path.
const DISCOVERY_FPS: u32 = 1;
fn encoders(options: &HostOptions, display: &DisplayBinding) -> Result<Encoders, HostError> {
    let supported = crate::publisher::supported_codecs_for(&publisher_config(
        options,
        display,
        Codec::H264,
        DISCOVERY_FPS,
    ))
    .map_err(probe_failure)?;
    let mut h264 = supported.h264;
    let mut h265 = supported.h265;
    match options.codec_selection {
        CodecSelection::Auto => {}
        CodecSelection::H264 => h265 = false,
        CodecSelection::H265 => h264 = false,
    }
    if !h264 && !h265 {
        return Err(HostError::NoHardwareCodec);
    }
    Ok(Encoders { h264, h265 })
}
fn peer_info(options: &HostOptions, codecs: Encoders) -> PeerInfo {
    PeerInfo {
        hostname: options.display_name.clone(),
        platform: options.platform.clone(),
        version: "1.4.9".into(),
        displays: vec![DisplayInfo {
            width: options.width,
            height: options.height,
            name: "Screen".into(),
            online: true,
            scale: 1.0,
            ..Default::default()
        }],
        encoding: Some(SupportedEncoding {
            h264: codecs.h264,
            h265: codecs.h265,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}


enum Control {
    Reply(Message),
    Keyframe,
    Permission { enabled: bool, deadline: Instant, reply: oneshot::Sender<Result<(), HostError>> },
    Disconnect { deadline: tokio::time::Instant, reply: oneshot::Sender<Result<(), HostError>> },
}
async fn peer(
    state: Arc<State>,
    options: Arc<HostOptions>,
    codecs: Encoders,
    incoming: Ingress,
    display: DisplayBinding,
    record: Arc<PeerRecord>,
    commands: mpsc::Receiver<PeerCommand>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), HostError> {
    let control = record.control.as_ref().ok_or(HostError::InvalidOptions)?.clone();
    let cancel = control.cancel.clone();
    let parts = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        value = authenticate(state.clone(), &options, codecs, incoming, record.clone(), &control) => value?,
    };
    drop(permit);
    let decoding = parts
        .context
        .claims
        .options
        .as_ref()
        .and_then(|o| o.supported_decoding.as_ref());
    let Some(decoding) = decoding else {
        return Err(HostError::NoCommonCodec);
    };
    let codec = if codecs.h264
        && decoding.ability_h264 > 0
        && decoding.prefer.enum_value() == Ok(PreferCodec::H264)
    {
        Codec::H264
    } else if codecs.h265 && decoding.ability_h265 > 0 {
        Codec::H265
    } else if codecs.h264 && decoding.ability_h264 > 0 {
        Codec::H264
    } else {
        return Err(HostError::NoCommonCodec);
    };
    // This peer's own request, resolved before the session takes any native
    // ownership, input lease or rate snapshot update: a malformed request ends
    // this session attempt as a post-authentication configuration failure
    // without displacing the last valid rate or leaving anything to reclaim.
    let request = resolve_frame_rate(
        parts
            .context
            .claims
            .options
            .as_ref()
            .map(|o| o.custom_fps)
            .unwrap_or(0),
    )?;
    // Native ownership starts here: a task that panics from this point on cannot
    // be reported as a clean teardown.
    let granted = parts.context.permissions.keyboard;
    let remote_disabled = parts.context.claims.options.as_ref().is_some_and(|options|
        options.disable_keyboard.enum_value() == Ok(proto::option_message::BoolOption::Yes));
    if granted {
        record.native.store(true, Ordering::Release);
    }
    state.authorize_peer(
        &record,
        matches!(parts.context.security, Security::Encrypted { .. }),
    );
    state.progress(|s| {
        s.phase = "awaiting_capture_consent";
        // The singular codec/rate fields describe the session that last began;
        // both rates come from this one resolved request under this lock, and
        // `connected`/`active_peers`/`encrypted` are the live-peer aggregate.
        s.client_requested_fps = request.client_requested_fps;
        s.fps = request.target_fps;
        s.codec = match codec {
            Codec::H264 => "H264",
            Codec::H265 => "H265",
        };
    });
    // CM/PermissionInfo retain the local grant. The viewer's mutable preference
    // is an additional veto, never a new authority or an irreversible ceiling.
    let lease = {
        let snapshot = lock(&control.snapshot);
        PeerLease::open(granted && !remote_disabled && snapshot.phase != "disconnecting"
            && !cancel.is_cancelled(), &display)?
    };
    let (tx, rx) = mpsc::channel(16);
    let config = publisher_config(&options, &display, codec, request.target_fps);
    let writer = parts.writer;
    let reading = read_peer(
        parts.reader,
        tx,
        cancel.clone(),
        options.width,
        options.height,
        lease,
        commands, state.clone(), control, display, granted, remote_disabled,
    );
    let publishing = publish(state.clone(), writer, rx, cancel.clone(), config, record);
    // Both halves are this task's own futures: every path below waits for each
    // one's own cleanup, so nothing is left detached from the peer that owns it.
    tokio::pin! {
        let reading = reading;
        let publishing = publishing;
    }
    let (rx_result, tx_result) = tokio::select! {
        biased;
        _ = cancel.cancelled() => (reading.as_mut().await, publishing.as_mut().await),
        result = reading.as_mut() => {
            cancel.cancel();
            (result, publishing.as_mut().await)
        }
        result = publishing.as_mut() => {
            cancel.cancel();
            (reading.as_mut().await, result)
        }
    };
    // An unconfirmed teardown wins over a normal disconnect, cancel or send
    // error: it is the only answer this peer can honestly give.
    if rx_result == Err(HostError::ReclamationUnconfirmed)
        || tx_result == Err(HostError::ReclamationUnconfirmed)
    {
        return Err(HostError::ReclamationUnconfirmed);
    }
    if state.cancel.is_cancelled() {
        return Ok(());
    }
    tx_result?;
    rx_result
}

async fn read_peer(
    reader: WireReader,
    control: mpsc::Sender<Control>,
    cancel: CancellationToken,
    width: i32,
    height: i32,
    mut lease: PeerLease,
    mut commands: mpsc::Receiver<PeerCommand>,
    state: Arc<State>,
    peer: Arc<PeerControl>,
    display: DisplayBinding,
    ceiling: bool,
    remote_disabled: bool,
) -> Result<(), HostError> {
    let result = read_loop(reader, &control, &cancel, width, height, &mut lease,
        &mut commands, &state, &peer, &display, ceiling, remote_disabled).await;
    // Every exit path — a remote close, a transport error, cancellation or a
    // refused event — gives up this session's injected buttons and keys through
    // the checked boundary. Drop is only a last-defense best effort and is never
    // what the host reports.
    lease.release()?;
    result
}

async fn read_loop(
    mut reader: WireReader,
    control: &mpsc::Sender<Control>,
    cancel: &CancellationToken,
    width: i32,
    height: i32,
    lease: &mut PeerLease,
    commands: &mut mpsc::Receiver<PeerCommand>,
    state: &State,
    peer: &PeerControl,
    display: &DisplayBinding,
    ceiling: bool,
    mut remote_disabled: bool,
) -> Result<(), HostError> {
    let mut local_enabled = ceiling;
    // Pinned remote-session liveness: a 1s TestDelay cadence and a 30s
    // receive deadline. These stay in the original reader/writer owner pair.
    let mut receive_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat_sent: Option<tokio::time::Instant> = None;
    let mut last_delay = 0;
    loop {
        let message = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = tokio::time::sleep_until(receive_deadline) => return Err(HostError::TransportFailed),
            _ = heartbeat.tick() => {
                if heartbeat_sent.is_none() {
                    let mut message = Message::new();
                    message.set_test_delay(proto::TestDelay { last_delay, ..Default::default() });
                    control.try_send(Control::Reply(message)).map_err(|_| HostError::TransportFailed)?;
                    heartbeat_sent = Some(tokio::time::Instant::now());
                }
                continue;
            }
            command = commands.recv() => match command {
                Some(PeerCommand::Disconnect { deadline, reply }) => {
                    // This sole input owner stops reading/granting until close.
                    // Keep WireReader alive: dropping it would poison the writer
                    // before the manual reason has finished sending.
                    lease.release()?;
                    *lease = PeerLease::default();
                    if cancel.is_cancelled() || tokio::time::Instant::now() >= deadline {
                        return Err(HostError::TransportFailed);
                    }
                    control.try_send(Control::Disconnect { deadline, reply }).map_err(|_| HostError::TransportFailed)?;
                    let result = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => Ok(()),
                        _ = tokio::time::sleep_until(deadline) => Err(HostError::TransportFailed),
                    };
                    drop(reader);
                    return result;
                }
                Some(PeerCommand::Keyboard { enabled, deadline, reply }) => {
                    // A policy/activity/deadline refusal is not a native teardown
                    // failure: reject it without destroying the view lease.
                    if enabled && (!ceiling || Instant::now() >= deadline
                        || lock(&peer.snapshot).phase == "disconnecting") {
                        let _ = reply.send(Err(HostError::InputUnavailable));
                        continue;
                    }
                    #[cfg(all(any(target_os = "windows", dsh_windows_typecheck), feature = "windows-modern-producer"))]
                    if enabled {
                        let activity = crate::windows_input::remote_activity_snapshot();
                        if activity.uncertain || (!state.allow_remote_cm.load(Ordering::Acquire)
                            && !crate::windows_input::remote_input_allows_sensitive_action()) {
                            let _ = reply.send(Err(HostError::InputUnavailable));
                            continue;
                        }
                    }
                    let result = change_keyboard(enabled, remote_disabled, lease, display, control, cancel,
                        peer, state, receive_deadline, deadline).await;
                    // A late grant refused after releasing the old lease leaves
                    // local input disabled, including a later remote Option(No).
                    local_enabled = lock(&peer.snapshot).keyboard;
                    let response = match result {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(HostError::InputUnavailable),
                        Err(error) => Err(error),
                    };
                    let _ = reply.send(response);
                    result?;
                    continue;
                }
                None => return Ok(()),
            },
            value = reader.recv() => value.map_err(|_| HostError::TransportFailed)?.ok_or(HostError::TransportFailed)?,
        };
        receive_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        // Checked between the last receive and the actual injection, not only at
        // the top of the loop: a stopped host injects nothing.
        if cancel.is_cancelled() {
            return Ok(());
        }
        let output = match message.union {
            Some(message::Union::TestDelay(probe)) if probe.from_client => {
                let mut m = Message::new();
                m.set_test_delay(probe);
                Some(Control::Reply(m))
            }
            Some(message::Union::TestDelay(_)) => {
                if let Some(sent) = heartbeat_sent.take() {
                    last_delay = sent.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
                }
                None
            }
            Some(message::Union::MouseEvent(event)) => {
                let snapshot = lock(&peer.snapshot);
                if snapshot.phase != "disconnecting" && local_enabled && !remote_disabled { lease.apply_mouse(&event)?; }
                None
            }
            Some(message::Union::KeyEvent(event)) => {
                let snapshot = lock(&peer.snapshot);
                if snapshot.phase != "disconnecting" && local_enabled && !remote_disabled { lease.apply_key(&event)?; }
                None
            }
            Some(message::Union::Misc(m)) => match m.union {
                Some(misc::Union::CloseReason(_)) => return Ok(()),
                Some(misc::Union::Option(options)) => {
                    let snapshot = lock(&peer.snapshot);
                    if snapshot.phase == "disconnecting" { continue; }
                    let disabled = match options.disable_keyboard.enum_value() {
                        Ok(proto::option_message::BoolOption::Yes) => true,
                        Ok(proto::option_message::BoolOption::No) => false,
                        _ => remote_disabled,
                    };
                    if disabled != remote_disabled {
                        // Close admission in this sole reader before releasing
                        // held input. Failure terminates/quarantines the peer.
                        remote_disabled = disabled;
                        lease.release()?;
                        *lease = PeerLease::default();
                        if local_enabled && !remote_disabled && !cancel.is_cancelled() {
                            *lease = PeerLease::open(true, display)?;
                        }
                    }
                    // Upstream changes its remote veto, not its local keyboard
                    // permission; CM and PermissionInfo must not echo a false revoke.
                    None
                }
                Some(misc::Union::RefreshVideo(true))
                | Some(misc::Union::RefreshVideoDisplay(0)) => Some(Control::Keyframe),
                Some(misc::Union::MessageQuery(q)) if q.switch_display == 0 => {
                    let mut misc = proto::Misc::new();
                    misc.set_switch_display(proto::SwitchDisplay {
                        width,
                        height,
                        ..Default::default()
                    });
                    let mut m = Message::new();
                    m.set_misc(misc);
                    Some(Control::Reply(m))
                }
                Some(misc::Union::CaptureDisplays(displays)) => {
                    if displays
                        .add
                        .iter()
                        .chain(displays.set.iter())
                        .any(|v| *v != 0)
                    {
                        return Err(HostError::UnsupportedDisplay);
                    }
                    // A withdrawn subscription must stop capture, not keep sending
                    // an unrequested display. Re-subscribing needs a fresh session
                    // in this explicitly single-display first host slice.
                    if displays.sub.contains(&0) {
                        return Ok(());
                    }
                    None
                }
                // No silent resolution changes or unauthorized system operations.
                Some(misc::Union::ChangeResolution(_))
                | Some(misc::Union::ChangeDisplayResolution(_)) => {
                    return Err(HostError::UnsupportedDisplay);
                }
                _ => None,
            },
            // Clipboard/file/audio are not granted and have no adapter.
            _ => None,
        };
        if let Some(output) = output {
            control
                .try_send(output)
                .map_err(|_| HostError::TransportFailed)?;
        }
    }
}

async fn change_keyboard(enabled: bool, remote_disabled: bool, lease: &mut PeerLease,
    display: &DisplayBinding, control: &mpsc::Sender<Control>, cancel: &CancellationToken,
    peer: &PeerControl, state: &State, receive_deadline: tokio::time::Instant,
    deadline: Instant) -> Result<bool, HostError> {
    if cancel.is_cancelled() || (enabled && (Instant::now() >= deadline
        || lock(&peer.snapshot).phase == "disconnecting")) { return Ok(false); }
    // This is the sole read/injection owner: no queued remote input can be
    // processed during revoke or while its release is unconfirmed.
    lease.release()?;
    *lease = PeerLease::default();
    lock(&peer.snapshot).keyboard = false;
    state.changed();
    let mut accepted = if enabled {
        // Release may block in native cleanup. Recheck the original deadline and
        // admission immediately before open, under the manual-disconnect gate.
        let snapshot = lock(&peer.snapshot);
        if cancel.is_cancelled() || snapshot.phase == "disconnecting" || Instant::now() >= deadline {
            false
        } else {
            if !remote_disabled { *lease = PeerLease::open(true, display)?; }
            true
        }
    } else {
        true
    };
    if enabled && (cancel.is_cancelled() || lock(&peer.snapshot).phase == "disconnecting"
        || Instant::now() >= deadline) { accepted = false; }
    if accepted {
        match send_keyboard_permission(enabled, deadline, control, cancel, receive_deadline).await {
            Err(HostError::InputUnavailable) if enabled => accepted = false,
            result => result?,
        }
    }
    if accepted {
        let mut snapshot = lock(&peer.snapshot);
        if enabled && (cancel.is_cancelled() || snapshot.phase == "disconnecting" || Instant::now() >= deadline) {
            accepted = false;
        } else {
            snapshot.keyboard = enabled;
        }
    }
    if !accepted {
        // Open/send may finish after the deadline. No input ran meanwhile. Give
        // back the new lease through checked release, not Drop, and correct any
        // already-completed PermissionInfo(true) with a restrictive write.
        lease.release()?;
        *lease = PeerLease::default();
        send_keyboard_permission(false, deadline, control, cancel, receive_deadline).await?;
    }
    state.changed();
    Ok(accepted)
}

async fn send_keyboard_permission(enabled: bool, deadline: Instant, control: &mpsc::Sender<Control>,
    cancel: &CancellationToken, receive_deadline: tokio::time::Instant) -> Result<(), HostError> {
    let (reply, result) = oneshot::channel();
    control.try_send(Control::Permission { enabled, deadline, reply }).map_err(|_| HostError::TransportFailed)?;
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(HostError::TransportFailed),
        _ = tokio::time::sleep_until(receive_deadline) => Err(HostError::TransportFailed),
        result = result => result.map_err(|_| HostError::TransportFailed)?,
    }
}

fn video(unit: &EncodedUnit, codec: Codec) -> Result<Message, HostError> {
    if unit.data.is_empty() || unit.data.len() > 32 * 1024 * 1024 || unit.pts_us < 0 {
        return Err(HostError::InvalidAccessUnit);
    }
    let frames = EncodedVideoFrames {
        frames: vec![EncodedVideoFrame {
            data: unit.data.clone(),
            key: unit.key,
            pts: unit.pts_us / 1000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut frame = VideoFrame::new();
    match codec {
        Codec::H264 => frame.set_h264s(frames),
        Codec::H265 => frame.set_h265s(frames),
    }
    let mut message = Message::new();
    message.set_video_frame(frame);
    Ok(message)
}

async fn publish(
    state: Arc<State>,
    mut writer: WireWriter,
    mut control: mpsc::Receiver<Control>,
    cancel: CancellationToken,
    config: PublisherConfig,
    record: Arc<PeerRecord>,
) -> Result<(), HostError> {
    let codec = config.codec;
    // A peer may disconnect between spawning this future and its first poll.
    // Do not open a native capture or display a system consent prompt after the
    // session is already cancelled. Once open starts, however, it must finish
    // and be joined below rather than being cancelled mid-creation.
    if cancel.is_cancelled() {
        return Ok(());
    }
    // Marked before the capture/encoder exists, so a panic inside `open` is still
    // attributed to a task that may own native resources.
    record.native.store(true, Ordering::Release);
    // Never abort a native creation/join just because its caller canceled.
    let publisher = match Publisher::open(config).await {
        Ok(value) => value,
        Err(error) => {
            return match publisher_failure(error) {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }
    };
    let result = async {
        loop {
            let (message, unit) = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                value = control.recv() => match value {
                    Some(Control::Reply(message)) => (message, None),
                    Some(Control::Permission { enabled, deadline, reply }) => {
                        let mut misc = proto::Misc::new();
                        misc.set_permission_info(proto::PermissionInfo {
                            permission: proto::permission_info::Permission::Keyboard.into(), enabled, ..Default::default()
                        });
                        let mut message = Message::new();
                        message.set_misc(misc);
                        let sent = if enabled && (Instant::now() >= deadline || record.control.as_ref()
                            .is_some_and(|peer| lock(&peer.snapshot).phase == "disconnecting")) {
                            // Nothing started: rejecting this queued grant does
                            // not cancel or resume a partially written frame.
                            let _ = reply.send(Err(HostError::InputUnavailable));
                            continue;
                        } else {
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => Err(HostError::TransportFailed),
                                sent = writer.send(&message) => sent.map_err(|_| HostError::TransportFailed),
                            }
                        };
                        let _ = reply.send(sent);
                        sent?;
                        continue;
                    }
                    Some(Control::Disconnect { deadline, reply }) => {
                        let mut misc = proto::Misc::new();
                        misc.set_close_reason("Closed manually by the peer".into());
                        let mut message = Message::new();
                        message.set_misc(misc);
                        let sent = tokio::select! {
                            biased;
                            _ = cancel.cancelled() => Err(HostError::TransportFailed),
                            _ = tokio::time::sleep_until(deadline) => Err(HostError::TransportFailed),
                            sent = writer.send(&message) => sent.map_err(|_| HostError::TransportFailed),
                        };
                        // Local wire-send completion, not a remote read receipt.
                        // Timeout/cancel terminates this writer: never reuse a
                        // send whose nonce/frame may have been partly consumed.
                        let _ = reply.send(sent);
                        return sent;
                    }
                    Some(Control::Keyframe) => {
                        if let Some(error) = publisher
                            .request_keyframe()
                            .err()
                            .and_then(publisher_failure)
                        {
                            return Err(error);
                        }
                        continue;
                    }
                    None => return Ok(()),
                },
                unit = publisher.recv(&cancel) => match unit {
                    Ok(Some(unit)) => { let m = video(&unit, codec)?; (m, Some(unit)) },
                    Ok(None) => return Ok(()),
                    Err(error) => return match publisher_failure(error) {
                        Some(error) => Err(error),
                        None => Ok(()),
                    },
                },
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                sent = writer.send(&message) => sent.map_err(|_| HostError::TransportFailed)?,
            }
            // The publisher's AU credit guard stays alive through the send. Only
            // compressed Bytes are cloned into protobuf; no pixels are touched.
            if let Some(unit) = unit {
                state.streamed(unit.data.len());
            }
        }
    }
    .await;
    // A failed/finished writer must wake the original input/command reader
    // before waiting for native close; queued PermissionInfo acknowledgments
    // cannot keep the controller actor waiting behind capture retirement.
    cancel.cancel();
    publisher.request_close();
    if publisher.close().await.is_err() {
        return Err(HostError::ReclamationUnconfirmed);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State {
            cancel: CancellationToken::new(),
            pending: Mutex::new(BTreeMap::new()),
            peers: Mutex::new(HashMap::new()),
            unreclaimed: AtomicBool::new(false),
            controls: Mutex::new(BTreeMap::new()),
            credentials: Mutex::new(Arc::new(HostCredentials::new(1, "test-salt".into(),
                Passwords::from_salted(Vec::new()), PrimaryPolicy::ClickOnly))),
            changes: watch::channel(0).0,
            finished: AtomicBool::new(false),
            allow_remote_cm: AtomicBool::new(false),
            auth_admission: AtomicBool::new(true),
            snapshot: Mutex::new(HostSnapshot {
                ready: false,
                phase: "listening",
                error: None,
                approval_request: String::new(),
                approval_origin: String::new(),
                width: 1920,
                height: 1080,
                client_requested_fps: 0,
                fps: 0,
                codec: "",
                connected: false,
                encrypted: false,
                active_peers: 0,
                input_enabled: false,
                sent_units: 0,
                sent_bytes: 0,
                closed: false,
            }),
        }
    }

    #[test]
    fn one_epochs_decision_cannot_answer_or_clear_another_request() {
        let state = state();
        let first = state.request_approval(7, "10.0.0.1:5000");
        let second = state.request_approval(8, "10.0.0.2:5000");
        // The singular snapshot field is the oldest request still waiting.
        assert_eq!(lock(&state.snapshot).approval_request, "7");
        assert_eq!(lock(&state.snapshot).approval_origin, "10.0.0.1:5000");

        assert!(!state.decide(9, true), "an unknown epoch is not answerable");
        assert!(state.decide(8, true));
        assert_eq!(*lock(&second.decision), Decision::Approve);
        assert_eq!(*lock(&first.decision), Decision::Pending);
        // A repeated decision for the same epoch is refused, whatever it asks.
        assert!(!state.decide(8, false));
        assert_eq!(*lock(&second.decision), Decision::Approve);

        // The answered epoch is no longer displayed, and the other peer's
        // request is still exactly as it was.
        assert_eq!(lock(&state.snapshot).approval_request, "7");
        state.clear_approval(8);
        assert_eq!(lock(&state.snapshot).approval_request, "7");
        state.clear_approval(7);
        assert!(lock(&state.snapshot).approval_request.is_empty());
        assert!(lock(&state.snapshot).approval_origin.is_empty());
    }

    #[test]
    fn peers_aggregate_only_counts_authorized_encrypted_sessions() {
        // An accepted socket that has not authorized is not an active peer.
        let accepted = PeerRecord::default();
        assert_eq!(peers_aggregate([&accepted]), (0, false));
        // Zero peers are never reported as an encrypted session.
        let none: [&PeerRecord; 0] = [];
        assert_eq!(peers_aggregate(none), (0, false));

        let encrypted = PeerRecord::default();
        encrypted.authorized.store(true, Ordering::Release);
        encrypted.encrypted.store(true, Ordering::Release);
        assert_eq!(peers_aggregate([&encrypted]), (1, true));

        // One plaintext peer makes the host-wide answer conservative.
        let plaintext = PeerRecord::default();
        plaintext.authorized.store(true, Ordering::Release);
        assert_eq!(peers_aggregate([&encrypted, &plaintext]), (2, false));
        assert_eq!(peers_aggregate([&encrypted, &accepted]), (1, true));
    }

    #[test]
    fn a_terminal_snapshot_is_not_rewound_by_late_peer_progress() {
        let state = state();
        state.update(|s| {
            s.phase = "closing";
            s.input_enabled = false;
        });
        state.progress(|s| s.phase = "streaming");
        assert_eq!(lock(&state.snapshot).phase, "closing");
        state.update(|s| {
            s.phase = "closed";
            s.closed = true;
        });
        state.progress(|s| {
            s.phase = "authenticating";
            s.error = Some(HostError::TransportFailed);
        });
        assert_eq!(lock(&state.snapshot).phase, "closed");
        assert!(lock(&state.snapshot).closed);
        assert_eq!(lock(&state.snapshot).error, None);
    }

    #[tokio::test]
    async fn an_unconfirmed_startup_probe_never_reports_a_clean_close() {
        let state = Arc::new(state());
        // Startup can fail before any peer exists to latch its native owners.
        state.finish(Err(HostError::ReclamationUnconfirmed));
        let host = Host {
            state,
            join: Mutex::new(None),
        };
        assert!(!host.snapshot().closed);
        assert_eq!(
            host.snapshot().error,
            Some(HostError::ReclamationUnconfirmed)
        );
        assert_eq!(host.close().await, Err(HostError::ReclamationUnconfirmed));
        // Neither repeated close nor a later clean finish may erase quarantine.
        host.state.finish(Ok(()));
        assert!(!host.snapshot().closed);
        assert_eq!(host.close().await, Err(HostError::ReclamationUnconfirmed));
    }

    #[test]
    fn a_peer_frame_rate_request_is_used_exactly_and_never_capped() {
        // Regression: a 120 FPS request used to be capped by the host's own 60.
        let explicit = resolve_frame_rate(120).expect("120 is an accepted request");
        assert_eq!(explicit.client_requested_fps, 120);
        assert_eq!(explicit.target_fps, 120);

        // Unspecified is not a refusal: an absent (or explicitly zero) request
        // takes the engine's own default, while the snapshot still shows that
        // this client named no rate.
        let absent = resolve_frame_rate(0).expect("an absent request is accepted");
        assert_eq!(absent.client_requested_fps, 0);
        assert_eq!(absent.target_fps, 60);

        // Both accepted bounds are used exactly as asked.
        assert_eq!(
            resolve_frame_rate(1),
            Ok(FrameRateRequest {
                client_requested_fps: 1,
                target_fps: 1
            })
        );
        assert_eq!(
            resolve_frame_rate(240),
            Ok(FrameRateRequest {
                client_requested_fps: 240,
                target_fps: 240
            })
        );

        // The signed field is matched before any conversion: a negative or
        // oversized request is refused rather than clamped, wrapped or read as
        // the default, so it can never become a publishable cadence.
        assert_eq!(resolve_frame_rate(-1), Err(HostError::InvalidFrameRate));
        assert_eq!(resolve_frame_rate(241), Err(HostError::InvalidFrameRate));
    }
}
