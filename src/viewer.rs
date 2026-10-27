//! First original-peer direct TCP viewer. No legacy Connection/VideoHandler.
//! Surface ownership comes from the trusted HAR, not a retained numeric ID.
//! RX, one writer, and one ordered video feeder are independent persistent tasks.
//! SDK creation/destruction run on blocking workers; compressed admission waits
//! are cancellation-aware notifications, never sleep retries or frame tasks.
//! A native consumer is joined even when cancellation wins its creation, and a
//! reclamation that cannot be confirmed fails `Viewer::close` rather than only
//! appearing as a session error.

#[path = "platform/decoder.rs"]
pub mod decoder;
use crate::{
    handshake::ViewerIdentity,
    protocol::Protocol,
    rendezvous::{RendezvousConfig, RouteKind},
    session::{AuthenticatedParts, PeerCloseReason, ViewerEvent, ViewerSession},
    transport::{WireReader, WireWriter},
};
pub use decoder::SurfaceLease;
use decoder::{DecoderError, DecoderObserver, DecoderProjection, RenderTiming, VideoCodec};
use crate::video::{self, Decoders, Geometry};
use base::message_proto::{
    self as proto, KeyEvent, LoginRequest, Message, MouseEvent, OptionMessage, message, misc,
    option_message::BoolOption, permission_info::Permission,
};
use ironrdp_pdu::input::{
    fast_path::{FastPathInputEvent, KeyboardFlags},
    mouse::PointerFlags, mouse_rel::PointerRelFlags, mouse_x::PointerXFlags,
    MousePdu, MouseRelPdu, MouseXPdu,
};
use ironrdp_pdu::rdp::capability_sets::InputFlags as RdpInputFlags;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};
use tokio::{
    runtime::Runtime,
    sync::{Notify, mpsc},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

/// Where a session dials, and which wire it speaks once it is there.
///
/// The engine has one session shell; this is the only thing that selects a
/// protocol. `RustDesk` keeps the original wire, including the rendezvous arm
/// that a peer id needs. RFB and RDP dial their endpoints directly; neither
/// server has a RustDesk peer id, so there is nothing to route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerTarget {
    /// The original RustDesk wire. A direct address when there is one;
    /// otherwise the session is dialled through rendezvous.
    RustDesk { address: Option<SocketAddr> },
    /// RFB (VNC), dialled directly.
    Vnc(crate::protocol::Endpoint),
    /// RDP, dialled directly with mandatory NLA and system certificate roots.
    Rdp(crate::protocol::Endpoint),
}

impl ViewerTarget {
    /// Stable token for the snapshot, so a UI can tell which wire is live.
    pub fn protocol(&self) -> crate::protocol::Protocol {
        match self {
            Self::RustDesk { .. } => crate::protocol::Protocol::RustDesk,
            Self::Vnc(_) => crate::protocol::Protocol::Vnc,
            Self::Rdp(_) => crate::protocol::Protocol::Rdp,
        }
    }
}
/// The original RustDesk direct-access port (`RELAY_PORT + 1`). A bare IP
/// entered by the user is a direct-LAN target on this port, matching the
/// canonical client's `check_port(peer, RELAY_PORT + 1)` behavior.
pub const DIRECT_ACCESS_PORT: u16 = (hbb_common::config::RELAY_PORT + 1) as u16;

/// Parses the direct target forms supported by the original client: a
/// `host:port` socket address, or a bare IPv4/IPv6 address using the direct
/// access port. It deliberately does not resolve bare host names, which remain
/// peer ids and require the rendezvous path.
pub fn direct_address(target: &str) -> Option<SocketAddr> {
    let target = target.trim();
    target
        .parse::<SocketAddr>()
        .ok()
        .filter(|address| address.port() != 0)
        .or_else(|| {
            target
                .parse::<IpAddr>()
                .ok()
                .map(|address| SocketAddr::new(address, DIRECT_ACCESS_PORT))
        })
}

/// One input event from the UI, in protocol-neutral terms.
///
/// `Mouse.kind` and `Mouse.button` keep the original protocol's encoding; a
/// driver that speaks another wire maps them. RustDesk keys are already their
/// native protocol messages, while RFB keys remain X11 keysyms.
#[derive(Debug, Clone)]
pub enum ViewerInput {
    Mouse {
        kind: u32,
        button: u32,
        x: i32,
        y: i32,
    },
    /// An RFB key press or release expressed as an X11 keysym.
    Key { keysym: u32, down: bool },
    /// A RustDesk-wire key event built from the UI's legacy key contract.
    RustDeskKey { event: KeyEvent },
}

/// This client's own decision about the input one viewer may send.
///
/// It is one typed value rather than a flag kept beside the bridge, so a viewer
/// can be started with a policy that is already in force: a read-only session
/// refuses its first event instead of waiting for the first caller that happens
/// to remember, and the engine — not its caller — is what enforces it. Every
/// boundary reads this same value: the enqueue a caller sees, the writer that
/// owns the wire, and the release that follows a revocation.
///
/// It is a local decision and never a reading of what the peer reports about
/// itself; the peer's own permission still bounds what this policy may admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ViewerInputPolicy {
    /// The operator's read-only switch. While it is set this viewer sends no
    /// input at all, and the change itself invalidates input already queued
    /// under the previous policy.
    pub view_only: bool,
    /// This session's acceptance of a RustDesk peer whose encryption and
    /// identity the handshake did not prove.
    ///
    /// It belongs to the viewer it was given to: a new viewer starts from its
    /// own options, so an acceptance is never carried into a reconnect. The RFB
    /// wire carries no such evidence and is never gated on this.
    pub unverified_accepted: bool,
}

impl ViewerInputPolicy {
    /// Input is admitted once the session is authorized and the peer grants it.
    /// A RustDesk peer must also have been proven by the handshake.
    pub const fn interactive() -> Self {
        Self {
            view_only: false,
            unverified_accepted: false,
        }
    }

    /// Read-only: nothing this viewer sends reaches the peer, whatever its
    /// caller asks for and whatever the peer's permission says.
    pub const fn read_only() -> Self {
        Self {
            view_only: true,
            unverified_accepted: false,
        }
    }
}

/// What one policy change did to one viewer.
///
/// The two facts are deliberately separate: `revoked` is what the call has
/// already done, while the release it made necessary is on its way to the peer
/// through the viewer's writer. A caller is therefore never told that a release
/// completed just because the policy that stopped the input was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputPolicyOutcome {
    /// The policy now in force.
    pub policy: ViewerInputPolicy,
    /// The generation this viewer's input gate is at now.
    ///
    /// It advances with every policy change and every peer-grant change, so a
    /// client that keeps input state of its own can tell that the engine
    /// invalidated what came before this answer — including a withdrawal and
    /// the grant that followed it, which leave the policy and the admission
    /// answer unchanged.
    pub input_generation: u64,
    /// This change stopped admitting input that the previous policy admitted.
    pub revoked: bool,
    /// Keys and buttons this viewer's writer emitted and has not released: holds
    /// the writer reserved. A hold is either a key or button the operator is
    /// holding right now or a release still on its way, never one that happened.
    ///
    /// This is the total it owns, so it also counts a key or button the operator
    /// is still holding. What a caller is waiting for is `releases_retired`.
    pub releases_owed: u64,
    /// The part of `releases_owed` a change retired: holds admitted under a
    /// generation this viewer has left behind and not yet released. These are
    /// the releases the change made necessary, and the only ones that are still
    /// pending because of it.
    pub releases_retired: u64,
    /// Holds whose writer stopped before releasing them. The release is
    /// unconfirmed rather than known to be absent: the write stopped, so whether
    /// the peer still holds the key or button is unknown. Kept separate from a
    /// completed release.
    pub releases_unreleased: u64,
}

impl InputPolicyOutcome {
    /// Whether every hold this viewer emitted has been released.
    pub fn released(&self) -> bool {
        self.releases_owed == 0 && self.releases_unreleased == 0
    }
}

const COMMANDS: usize = 128;
/// How long a session waits for the client to bind its surface before the first
/// native consumer opens, and how often the lease is checked while it does.
pub(crate) const SURFACE_WAIT: Duration = Duration::from_secs(20);
pub(crate) const SURFACE_POLL: Duration = Duration::from_millis(20);
/// How many keys and buttons one writer may hold at once.
///
/// A keyboard cannot physically hold more than a handful of keys and the wire
/// carries five pointer buttons, so this is only a backstop against a caller
/// that sends downs without ups. A down that would pass it is refused rather
/// than emitted: a hold this writer could not remember is a key it could never
/// release, and refusing it keeps everything on the wire accounted for.
const MAX_HELD_INPUTS: u64 = 64;

// Deliberately no Debug: credentials and peer identities must not enter logs.
pub struct ViewerOptions {
    /// Which wire to speak and where to dial it. `RustDesk { address: None }`
    /// is the rendezvous route; everything else dials directly.
    pub target: ViewerTarget,
    pub username: String,
    pub local_id: String,
    pub local_name: String,
    pub password: String,
    pub requested_fps: u32,
    /// The local input policy this viewer is started under.
    ///
    /// It is in force before the asynchronous start, so a read-only session
    /// refuses input from its first event, and an unproven RustDesk session
    /// refuses it until its own operator accepts the connection (see
    /// `Viewer::set_input_policy`).
    pub input_policy: ViewerInputPolicy,
}
impl Drop for ViewerOptions {
    fn drop(&mut self) {
        let mut password = std::mem::take(&mut self.password).into_bytes();
        hbb_common::sodiumoxide::utils::memzero(&mut password);
    }
}

#[derive(Debug, Clone, Default)]
pub struct ViewerSnapshot {
    pub phase: String,
    /// Which wire this session speaks: `rustdesk`, `vnc` or `rdp`. The UI needs
    /// it to label a session, and it is set from the target rather than guessed
    /// from the port or the address.
    pub protocol: String,
    pub error: Option<String>,
    /// Why the peer refused this login, when it refused one.
    ///
    /// The category is a field rather than part of `error` on purpose: the error
    /// string stays the local constant this engine has always reported, and this
    /// is what a client reads to tell a password it can correct from a refusal no
    /// password can answer.
    pub login_failure: Option<LoginFailure>,
    /// Recognized RustDesk close reason, published only after a RemoteClosed
    /// result and confirmed native reclamation. Arbitrary peer text is not kept.
    pub peer_close_reason: Option<PeerCloseReason>,
    pub width: i32,
    pub height: i32,
    pub codec: String,
    /// `direct_tcp`, `tcp_hole_punch` or `relay`; never inferred from an address.
    pub route: String,
    pub received_units: u64,
    pub pushed_units: u64,
    pub render_submissions: u64,
    /// Measured push-to-submission latency, aggregated only over actual samples.
    /// `None` means this session has no actual timing observation.
    pub render_timing: Option<RenderTiming>,
    /// Units admitted but not yet pushed into the decoder at this snapshot.
    pub queued_units: u64,
    pub keyboard_allowed: bool,
    /// The generation of the local policy and the peer's grant this snapshot
    /// was read under.
    ///
    /// It advances on every policy change and every peer keyboard grant change,
    /// so a client can tell that the engine invalidated input it had taken
    /// before. `keyboard_allowed` cannot say that on its own: a withdrawal and
    /// the grant that follows it leave that answer exactly as it was, while the
    /// input admitted under the previous one is released and never replayed.
    ///
    /// This is also the value an input call names as its own generation. The
    /// engine admits an event only under the generation in force and refuses one
    /// named with a generation it has left, so a client that sends this value
    /// back gets a receipt that says which epoch its event was queued under.
    pub input_generation: u64,
    /// Keys and buttons this viewer's writer emitted and has not released: a
    /// release still on its way, never one that happened. A hold the operator is
    /// holding right now counts here too, so this is not by itself evidence of
    /// an interrupted release.
    pub releases_owed: u64,
    /// The part of `releases_owed` a change retired: holds admitted under a
    /// generation this viewer has left behind and not yet released. A non-zero
    /// value is the release a client is waiting for, and the reason
    /// `keyboard_allowed` can be true again while input is still not settled.
    pub releases_retired: u64,
    /// Holds whose writer stopped before releasing them: a release whose
    /// completion is unconfirmed, because the write stopped before it was made.
    /// Whether the peer still holds the key or button is unknown, so this is
    /// neither a completed release nor a claim that nothing arrived.
    pub releases_unreleased: u64,
    pub closed: bool,
    /// The peer's authentication decision as the session records it: set when
    /// the session is authorized and cleared when it is closing or finished.
    ///
    /// This is a fact about the connection, not a reading of `phase`: a session
    /// that is authenticated and still binding its Surface reads `true` here
    /// while its phase is `awaiting_surface`, and a session that has finished
    /// reads `false` even though `phase` still names the last media state.
    pub authenticated: bool,
    /// Actual authenticated connection evidence, never inferred from options.
    pub encrypted: bool,
    pub peer_verified: bool,
    /// The peer's own identity, exactly as its login response carried it. The
    /// client labels the session with the platform and version and builds its
    /// viewport from the displays, so this is copied from the peer's `PeerInfo`
    /// rather than re-derived from the geometry of the display being shown.
    pub platform: String,
    pub version: String,
    pub displays: Vec<PeerDisplayInfo>,
    pub current_display: i32,
}

/// One of the peer's displays in the terms the peer's own protocol uses. The
/// resolution the display was captured at is kept beside the size it is being
/// sent at, because a viewport that scales one to the other needs both.
#[derive(Debug, Clone, Default)]
pub struct PeerDisplayInfo {
    pub width: i32,
    pub height: i32,
    pub x: i32,
    pub y: i32,
    pub cursor_embedded: bool,
    pub original_width: i32,
    pub original_height: i32,
}

#[derive(Debug, Clone)]
pub enum ViewerError {
    InvalidOptions,
    UnsupportedPlatform,
    NoHardwareCodec,
    /// No software VP8/VP9 decoder is usable in this build, and why.
    ///
    /// The refusal a target without a hardware decoder states when its software
    /// backend cannot answer at all: the `software-vpx` feature is off, no
    /// library was linked, or the loaded library's own version/ABI/interface gate
    /// refused. The reason is this build's own diagnosis — the backend's
    /// provenance or the library's error text: text about the build, never about
    /// the connection and never peer text — and it is stated rather than reported
    /// as an unexplained absence.
    NoSoftwareVpx(String),
    RuntimeUnavailable,
    ConnectFailed,
    RendezvousFailed,
    AuthenticationFailed,
    SecondFactorUnsupported,
    TransportFailed,
    RemoteClosed,
    InvalidPeerGeometry,
    UnsupportedCodec,
    InvalidVideoRecord,
    VideoRecordTooLarge,
    TimestampOverflow,
    InputNotAllowed,
    /// The caller named a policy generation this viewer has already left.
    ///
    /// Input is admitted only under the generation its caller has actually seen.
    /// An event stamped with an older one would reach the peer after the
    /// boundary that retired it, so it is refused here instead of being
    /// relabelled under the generation in force.
    StaleInputGeneration,
    InvalidMouse,
    Backpressure,
    Closed,
    TaskFailed,
    ReclamationUnconfirmed,
    Decoder(DecoderError),
    /// Safe adapter errors retain TLS, protocol and graceful-close distinctions.
    Rdp(crate::protocol::rdp::RdpError),
    /// An unavailable protocol capability. A local constant, never peer text.
    UnsupportedProtocol(&'static str),
    /// The peer refused the login, classified instead of folded into one opaque
    /// failure.
    ///
    /// The error string is unchanged (`AuthenticationFailed`), so a consumer that
    /// only reads strings sees what it always saw; the category travels as a
    /// field, in this variant and in `ViewerSnapshot::login_failure`.
    LoginFailed(LoginFailure),
}
impl fmt::Display for ViewerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // All variants contain local constants/native error codes only. Never
        // embed peer LoginError/MessageBox/CloseReason strings or I/O diagnostics.
        match self {
            Self::Decoder(error) => write!(f, "Surface decoder: {error:?}"),
            Self::Rdp(error) => write!(f, "{error}"),
            Self::NoSoftwareVpx(reason) => write!(f, "no software VP8/VP9 decoder: {reason}"),
            // The string a refused login has always reported here: the category is
            // a field, so a consumer that reads only strings is unaffected by its
            // arrival.
            Self::LoginFailed(_) => write!(f, "AuthenticationFailed"),
            other => write!(f, "{other:?}"),
        }
    }
}
impl std::error::Error for ViewerError {}

/// Why a peer refused a login, in the categories this engine acts on.
///
/// The peer names its reason in `LoginResponse.error`, and the categories need
/// different behavior from a client: a password it can ask for or correct, against
/// a refusal no password can answer (a policy, an allow-list, a message this
/// engine does not classify). The engine classifies once and keeps the peer's text
/// out of every error string, so a peer cannot put words of its choosing into the
/// UI.
///
/// `No Password Access` (awaiting approval) and the second-factor refusals do not
/// appear here: they have their own states (`phase == "awaiting_approval"` and
/// `SecondFactorUnsupported`), and this is the vocabulary of a login that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFailure {
    /// `Empty Password`: the peer wants a password this client did not send.
    EmptyPassword,
    /// `Wrong Password`: the peer refused the password this client sent.
    WrongPassword,
    /// A refusal neither of those names. It is not about the credential this
    /// client holds, so no password form can settle it.
    Refused,
}

impl LoginFailure {
    /// Classifies one `LoginResponse.error` that names a failed login.
    ///
    /// The approval and second-factor reasons are handled before this is reached,
    /// so every other reason is a refusal rather than a mis-filed credential
    /// answer.
    fn of(reason: &str) -> Self {
        match reason {
            "Empty Password" => Self::EmptyPassword,
            "Wrong Password" => Self::WrongPassword,
            _ => Self::Refused,
        }
    }
}

struct Inner {
    snapshot: ViewerSnapshot,
    geometry: Option<Geometry>,
    decoder: Option<DecoderObserver>,
    // Observation only; State::finish decides whether cleanup permits publishing it.
    observed_peer_close_reason: Option<PeerCloseReason>,
}
struct State {
    inner: Mutex<Inner>,
    cancel: CancellationToken,
    done: Notify,
    result: Mutex<Option<Result<(), ViewerError>>>,
    /// Which wire this viewer speaks. Kept beside the state instead of being
    /// read back out of the snapshot's label, so an admission decision is one
    /// field read rather than a clone of the whole snapshot.
    protocol: Protocol,
    authenticated: AtomicBool,
    /// DemandActive evidence from the adapter, never the client's advertised
    /// flags. Empty before confirmation and while activation is incomplete.
    rdp_input_flags: AtomicU16,
    /// The RustDesk handshake's own proof of the peer: encrypted, with the
    /// peer's identity verified. Evidence about this connection and never a
    /// local policy; the RFB wire produces none and requires none.
    peer_proven: AtomicBool,
    /// The local input policy in force, the peer's keyboard grant, the
    /// generation that stamps the input they admit, and the holds this viewer's
    /// writer owes a release for.
    input: InputGate,
    // Independent from operational/auth/network errors. Set BEFORE creating a
    // native decoder and cleared only by confirmed destruction/no allocation.
    resources_unconfirmed: AtomicBool,
    // Installed by authenticate once the writer task owns the control channel,
    // so out-of-band control (keyframe requests) can be sent after login.
    control: Mutex<Option<mpsc::Sender<Message>>>,
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The facts one local admission decision is made from, apart from the ones the
/// gate itself owns.
///
/// They are gathered from the viewer's own state, so the enqueue boundary, the
/// writer that owns the wire and the release that follows a revocation all
/// decide from the same evidence — there is nowhere else an input event's
/// permission is decided. The local policy, the peer's keyboard grant and the
/// generation that stamps the input they admit come from the gate in the same
/// critical section as the decision (`GateView`), so they are never read
/// halfway through a change.
#[derive(Debug, Clone, Copy)]
struct Facts {
    protocol: Protocol,
    /// The session is authorized.
    authenticated: bool,
    /// The RustDesk handshake proved the peer.
    proven: bool,
    /// The viewer is cancelling or finished.
    closed: bool,
}

impl Facts {
    fn of(state: &State) -> Self {
        Self {
            protocol: state.protocol,
            authenticated: state.authenticated.load(Ordering::Acquire),
            proven: state.peer_proven.load(Ordering::Acquire),
            closed: state.cancel.is_cancelled(),
        }
    }

    /// Whether this wire's own evidence is required before input may be sent.
    ///
    /// The RustDesk wire is the one that can carry a proven peer. RFB has no
    /// identity evidence to wait for, and this viewer does not invent one: a
    /// VNC session is admitted on its authentication and the peer's grant, as
    /// it always was.
    fn proof_required(self) -> bool {
        self.protocol == Protocol::RustDesk
    }

    /// Whether this viewer may send input at this instant.
    ///
    /// One predicate for both boundaries — the enqueue a caller sees and the
    /// writer that owns the wire — so a policy that stops admitting input stops
    /// it at both ends, and nothing already queued can outlive it. The peer's
    /// keyboard grant is the only permission channel this viewer has: it bounds
    /// every input event, pointer included, exactly as it did before this policy
    /// existed.
    fn admits(self, gate: GateView) -> bool {
        !gate.policy.view_only
            && self.authenticated
            && gate.keyboard
            && !self.closed
            && (!self.proof_required() || self.proven || gate.policy.unverified_accepted)
    }
}

/// What one viewer's input gate publishes as one fact: the local policy in
/// force, the peer's own keyboard grant, the generation that stamps the input
/// they admit, and the release its writer owes.
///
/// The grant lives here rather than beside the snapshot so that a change to it
/// is published under the same lock that stamps input: a withdrawal, and the
/// grant that follows it, both advance the generation, which is what makes
/// input queued or emitted before them invalid — even though that input is
/// admitted again by the time a writer sees it.
#[derive(Debug, Clone, Copy)]
struct GateView {
    policy: ViewerInputPolicy,
    keyboard: bool,
    generation: u64,
    /// Holds a live writer owes a release for, and holds whose writer stopped
    /// before releasing them. They are read here so that a snapshot reports the
    /// release the generation above belongs to, and never a stale pair.
    owed: u64,
    /// The part of `owed` a change retired: holds admitted under an older
    /// generation that this writer has not released yet. A client is waiting for
    /// exactly these, so they are reported separately from the total, which also
    /// counts the keys and buttons the operator is holding right now.
    retired: u64,
    unreleased: u64,
}

/// One viewer's live input policy: the typed policy in force, the peer's
/// keyboard grant, the generation that stamps the input they admit, and the
/// holds its writer owes.
///
/// All of them live under one lock, so a change is published as one fact. A
/// decision reads the generation that goes with the policy and the grant it
/// decided under, and a revocation reads the holds that were owned before it —
/// which is what lets the release that follows be exact rather than best
/// effort. A hold is reserved under this same lock before its event can reach
/// the wire, so a change that publishes here can never run between an event's
/// admission and the writer's ledger.
struct InputGate {
    state: Mutex<GateState>,
    /// Wakes the one writer when the policy or the peer's grant changes. A
    /// permit survives a writer that is busy, and the pass it triggers reads
    /// the gate instead of replaying the change, so a notification is never
    /// replayed as an event.
    changed: Notify,
}

#[derive(Debug, Clone, Copy)]
struct GateState {
    policy: ViewerInputPolicy,
    /// The peer's own keyboard grant: the only permission channel this viewer
    /// has. It is kept here, rather than beside the snapshot, so that a change
    /// to it is published under the lock that stamps input.
    keyboard: bool,
    /// Bumped on every policy change and every grant change, so input queued or
    /// emitted under the previous one can never be emitted after it — including
    /// the input queued, or held, before a revocation when admission is granted
    /// again.
    generation: u64,
    /// Holds a live writer owes a release for, whatever admitted them.
    owed: u64,
    /// The part of `owed` a change retired: every hold the writer owned when the
    /// generation advanced was admitted under the one that retired, so a change
    /// makes the whole of `owed` pending a release. A hold released with the
    /// stamp it was admitted under settles this count and never an ordinary hold
    /// the operator is simply still holding.
    retired: u64,
    /// Holds whose writer stopped before releasing them. Kept past the writer
    /// rather than cleared with it, so a viewer that ended this way is reported
    /// as owing a release instead of looking like one that released.
    unreleased: u64,
}

impl GateState {
    /// This state as one fact, for a decision made under its own lock.
    fn view(&self) -> GateView {
        GateView {
            policy: self.policy,
            keyboard: self.keyboard,
            generation: self.generation,
            owed: self.owed,
            retired: self.retired,
            unreleased: self.unreleased,
        }
    }
}

impl InputGate {
    fn new(policy: ViewerInputPolicy) -> Self {
        Self {
            state: Mutex::new(GateState {
                policy,
                // Nothing is granted until the peer says so: the handshake's
                // permissions, or the message that carries a change to them.
                keyboard: false,
                generation: 1,
                owed: 0,
                retired: 0,
                unreleased: 0,
            }),
            changed: Notify::new(),
        }
    }

    /// The policy in force, the peer's grant and the generation that stamps the
    /// input they admit, read as one fact.
    fn read(&self) -> GateView {
        lock(&self.state).view()
    }

    fn policy(&self) -> ViewerInputPolicy {
        lock(&self.state).policy
    }

    /// Publishes the peer's keyboard grant.
    ///
    /// The grant is the peer's, but what it invalidates is this viewer's: a
    /// change advances the generation exactly as a policy change does, so input
    /// queued or emitted under the previous grant is dropped and released even
    /// though a withdrawal and the grant that follows it admit input again. A
    /// writer that is busy when the grant moves sees it on its next event,
    /// whether or not the wake-up below has been delivered yet.
    fn grant(&self, keyboard: bool) {
        let advanced = {
            let mut state = lock(&self.state);
            if state.keyboard == keyboard {
                false
            } else {
                state.keyboard = keyboard;
                state.generation += 1;
                // Every hold the writer owns was admitted under the generation
                // that just retired, so all of them are now waiting to be
                // released.
                state.retired = state.owed;
                true
            }
        };
        if advanced {
            self.changed.notify_one();
        }
    }

    /// Publishes a policy and reports what it did.
    ///
    /// A change advances the generation, which is what invalidates input already
    /// queued under the previous policy; a policy that is already in force
    /// changes nothing and invalidates nothing. What it revoked is decided from
    /// the admission answer before and after, both read under this lock.
    fn set(&self, policy: ViewerInputPolicy, facts: &Facts) -> InputPolicyOutcome {
        let mut state = lock(&self.state);
        let admitted = facts.admits(state.view());
        if state.policy != policy {
            state.policy = policy;
            state.generation += 1;
            // As in `grant`: the holds the writer owns were admitted under the
            // generation this change retired, so releasing them is now owed.
            state.retired = state.owed;
        }
        InputPolicyOutcome {
            policy: state.policy,
            input_generation: state.generation,
            revoked: admitted && !facts.admits(state.view()),
            releases_owed: state.owed,
            releases_retired: state.retired,
            releases_unreleased: state.unreleased,
        }
    }

    /// Whether one queued event may still be emitted, taking this writer's
    /// ownership of the hold it creates in the same critical section.
    ///
    /// `adds_hold` is the writer's own answer — from its ledger, not from the
    /// event alone — to whether this event creates a hold it must release
    /// later. A `false` return means the event must not be emitted: the policy
    /// no longer admits it, its stamp is older than the policy in force, or the
    /// writer cannot track one more hold.
    fn own(&self, stamped: u64, adds_hold: bool, facts: &Facts) -> bool {
        self.own_many(stamped, u64::from(adds_hold), facts)
    }

    /// Reserve a bounded typed-input batch atomically with its generation.
    fn own_many(&self, stamped: u64, adds: u64, facts: &Facts) -> bool {
        let mut state = lock(&self.state);
        if stamped != state.generation || !facts.admits(state.view())
            || adds > MAX_HELD_INPUTS.saturating_sub(state.owed)
            || (facts.protocol == Protocol::Rdp && state.retired != 0)
        {
            return false;
        }
        state.owed += adds;
        true
    }

    /// Records the hold one event or release pass let go, by the generation that
    /// admitted it.
    ///
    /// It leaves the total this writer owns either way. A hold admitted under an
    /// older generation is one a change had retired, so releasing it settles the
    /// retired count a client reads as the release still on its way; a hold the
    /// policy in force still admits is the operator's own, and settles nothing
    /// but the total.
    fn released(&self, stamped: u64) {
        let mut state = lock(&self.state);
        state.owed = state.owed.saturating_sub(1);
        if stamped != state.generation {
            state.retired = state.retired.saturating_sub(1);
        }
    }

    /// Settles the holds of a writer that has stopped.
    ///
    /// Its transport stops with it, so nothing it still held can be released
    /// through it any more. The holds are reported as releases whose completion
    /// is unconfirmed — the write stopped before this writer made them, so
    /// whether the peer still holds a key or button is unknown — rather than as
    /// releases that happened or as releases known never to have arrived. That
    /// includes the ones a change had retired, which stop being a release on its
    /// way the moment the writer that owed it is gone.
    fn stopped(&self) {
        let mut state = lock(&self.state);
        state.unreleased += state.owed;
        state.owed = 0;
        state.retired = 0;
    }
}

/// One input event waiting for the writer, with the policy generation that
/// admitted it.
///
/// The stamp is what makes a revocation retroactive: an event queued under the
/// previous policy or peer grant can never be emitted after the generation that
/// admitted it is gone, so a session that stopped accepting input cannot replay
/// what it accepted a moment ago.
struct QueuedInput {
    event: ViewerInput,
    generation: u64,
}

impl State {
    fn phase(&self, phase: &str) {
        lock(&self.inner).snapshot.phase = phase.into();
    }
    fn geometry(&self, geometry: Geometry) {
        let mut inner = lock(&self.inner);
        inner.geometry = Some(geometry);
        inner.snapshot.width = geometry.width;
        inner.snapshot.height = geometry.height;
    }
    /// The geometry a rectangle protocol reports as its whole desktop: exactly
    /// one display, and it is the current one.
    ///
    /// Nothing else is published with it. RFB carries no platform, version or
    /// security evidence, so those stay empty rather than being filled with a
    /// guess the UI would label the peer with, and it reports no separate
    /// captured resolution, so the record carries none. All of it is written
    /// under one lock, so a reader never sees a new size beside the display
    /// list of the old one.
    fn desktop_geometry(&self, geometry: Geometry) {
        let mut inner = lock(&self.inner);
        inner.geometry = Some(geometry);
        inner.snapshot.width = geometry.width;
        inner.snapshot.height = geometry.height;
        inner.snapshot.current_display = geometry.display;
        inner.snapshot.displays = vec![PeerDisplayInfo {
            width: geometry.width,
            height: geometry.height,
            x: geometry.x,
            y: geometry.y,
            ..Default::default()
        }];
    }
    fn route(&self, route: &'static str) {
        lock(&self.inner).snapshot.route = route.into();
    }
    fn snapshot(&self) -> ViewerSnapshot {
        let inner = lock(&self.inner);
        let mut out = inner.snapshot.clone();
        out.authenticated = self.authenticated.load(Ordering::Acquire);
        // What the engine would actually admit, not a reading of the peer's
        // grant alone: a read-only viewer and an unaccepted unproven peer both
        // report no keyboard here. The generation that admitted it is published
        // beside it from the same critical section, so a client that keeps
        // input state of its own invalidates it on a change it can see rather
        // than on one it cannot.
        let gate = self.input.read();
        out.keyboard_allowed = Facts::of(self).admits(gate);
        out.input_generation = gate.generation;
        out.releases_owed = gate.owed;
        out.releases_retired = gate.retired;
        out.releases_unreleased = gate.unreleased;
        if let Some(observer) = &inner.decoder {
            if let Ok(stats) = observer.stats() {
                out.pushed_units = out.pushed_units.saturating_add(stats.pushed_units);
                out.render_submissions = out
                    .render_submissions
                    .saturating_add(stats.render_submissions);
                RenderTiming::accumulate(&mut out.render_timing, stats.render_timing);
                out.queued_units = stats.queued_units;
                if let Some(error) = stats.failure {
                    out.error = Some(ViewerError::Decoder(error).to_string());
                    out.peer_close_reason = None;
                }
                if stats.render_submissions > 0
                    && out.error.is_none()
                    && !self.cancel.is_cancelled()
                    && !out.closed
                {
                    out.phase = "streaming".into();
                }
            }
        }
        out
    }
    fn request_close(&self) {
        self.authenticated.store(false, Ordering::Release);
        self.cancel.cancel();
        let mut inner = lock(&self.inner);
        if !inner.snapshot.closed {
            inner.snapshot.phase = "closing".into();
        }
        if let Some(observer) = &inner.decoder {
            observer.request_close();
        }
    }
    fn finish(&self, result: Result<(), ViewerError>) {
        self.authenticated.store(false, Ordering::Release);
        let reclamation = if self.resources_unconfirmed.load(Ordering::Acquire) {
            Err(match &result {
                Err(error @ ViewerError::Decoder(DecoderError::DestroyFailed { .. })) => {
                    error.clone()
                }
                _ => ViewerError::ReclamationUnconfirmed,
            })
        } else {
            Ok(())
        };
        let mut inner = lock(&self.inner);
        inner.snapshot.closed = true;
        inner.snapshot.keyboard_allowed = false;
        // The category is published beside the string, not inside it: `error`
        // keeps the text it has always reported, and a client that has to choose
        // between a password form and another outcome reads this field instead of
        // inferring a reason from its own state.
        inner.snapshot.login_failure = match &result {
            Err(ViewerError::LoginFailed(failure)) => Some(*failure),
            _ => None,
        };
        inner.snapshot.peer_close_reason = if reclamation.is_ok()
            && matches!(&result, Err(ViewerError::RemoteClosed)) {
            inner.observed_peer_close_reason
        } else {
            None
        };
        // A peer's terminal request cannot hide a failed native reclamation.
        inner.snapshot.error = reclamation
            .as_ref()
            .err()
            .or_else(|| result.as_ref().err())
            .map(ToString::to_string);
        inner.snapshot.phase = if inner.snapshot.error.is_none() {
            "closed"
        } else {
            "failed"
        }
        .into();
        // HAR uses ONLY this result to decide whether it may release its lease
        // and registry slot. Old wrong-password/disconnect errors are not a UAF.
        *lock(&self.result) = Some(reclamation);
        self.done.notify_waiters();
    }
}

/// The engine's own session owns its RustDesk video pipeline and publishes what
/// the pipeline reports through the same snapshot every protocol shares.
impl video::VideoOwner for State {
    fn cancellation(&self) -> &CancellationToken {
        &self.cancel
    }
    fn reclamation_unconfirmed(&self) -> &AtomicBool {
        &self.resources_unconfirmed
    }
    fn video_phase(&self, phase: &'static str) {
        self.phase(phase);
    }
    fn video_received(&self, units: u64) {
        lock(&self.inner).snapshot.received_units += units;
    }
    fn video_decoder_opened(&self, codec: VideoCodec, geometry: Geometry, observer: DecoderObserver) {
        self.geometry(geometry);
        let mut inner = lock(&self.inner);
        inner.decoder = Some(observer);
        inner.snapshot.codec = video::codec_name(codec).into();
        inner.snapshot.phase = "decoding".into();
    }
    fn video_decoder_closed(&self, projection: Option<DecoderProjection>) {
        let mut inner = lock(&self.inner);
        if let Some(stats) = projection {
            inner.snapshot.pushed_units = inner
                .snapshot
                .pushed_units
                .saturating_add(stats.pushed_units);
            inner.snapshot.render_submissions = inner
                .snapshot
                .render_submissions
                .saturating_add(stats.render_submissions);
            RenderTiming::accumulate(&mut inner.snapshot.render_timing, stats.render_timing);
        }
        inner.decoder = None;
    }
    fn video_failed(&self) {
        self.request_close();
    }
}

pub struct Viewer {
    state: Arc<State>,
    mouse: mpsc::Sender<QueuedInput>,
}

enum Connector {
    Direct(ViewerIdentity),
    Rendezvous(RendezvousConfig),
}

fn runtime() -> Result<&'static Runtime, ViewerError> {
    crate::executor::runtime().map_err(|_| ViewerError::RuntimeUnavailable)
}

fn validate_rdp_options(endpoint: &crate::protocol::Endpoint, password: &str) -> Result<(), ViewerError> {
    let user = endpoint.user.as_deref().ok_or(ViewerError::InvalidOptions)?;
    if endpoint.port == 0 || endpoint.host.is_empty() || endpoint.host.len() > 255
        || endpoint.host.chars().any(|c| c.is_whitespace() || c.is_control())
        || rustls::pki_types::ServerName::try_from(endpoint.host.as_str()).is_err()
        || user.trim().is_empty() || user.len() > 128 || user.chars().any(char::is_control)
        || password.contains('\0')
    {
        return Err(ViewerError::InvalidOptions);
    }
    Ok(())
}

impl Viewer {
    pub fn start(
        options: ViewerOptions,
        lease: Arc<dyn SurfaceLease>,
    ) -> Result<Arc<Self>, ViewerError> {
        // Reject malformed direct endpoints and RDP accounts before creating
        // the runtime, channels or any connection attempt.
        // A direct address is only reachable through the original wire; the
        // other protocols carry their own endpoint in the target.
        match &options.target {
            ViewerTarget::RustDesk {
                address: Some(address),
            } if address.port() != 0 => {}
            ViewerTarget::Vnc(endpoint) if !endpoint.host.is_empty() && endpoint.port != 0 => {}
            ViewerTarget::Rdp(endpoint) => validate_rdp_options(endpoint, &options.password)?,
            _ => return Err(ViewerError::InvalidOptions),
        }
        Self::start_with_connector(
            options,
            lease,
            Connector::Direct(ViewerIdentity::LegacyUnverified),
        )
    }

    /// Trust must come from an explicit out-of-band peer pin, not this socket.
    pub fn start_verified(
        options: ViewerOptions,
        lease: Arc<dyn SurfaceLease>,
        expected_id: String,
        peer_signing_key: hbb_common::sodiumoxide::crypto::sign::PublicKey,
    ) -> Result<Arc<Self>, ViewerError> {
        if expected_id.is_empty() || expected_id.len() > 512 {
            return Err(ViewerError::InvalidOptions);
        }
        if !matches!(
            &options.target,
            ViewerTarget::RustDesk { address: Some(address) } if address.port() != 0
        ) {
            return Err(ViewerError::InvalidOptions);
        }
        Self::start_with_connector(
            options,
            lease,
            Connector::Direct(ViewerIdentity::PinnedHost {
                expected_id,
                peer_signing_key,
            }),
        )
    }

    /// Original hbbs/hbbr ID route with mandatory server-signed peer identity.
    /// The dialer completes SignedId/box/secretbox before password authentication.
    pub fn start_rendezvous(
        options: ViewerOptions,
        lease: Arc<dyn SurfaceLease>,
        config: RendezvousConfig,
    ) -> Result<Arc<Self>, ViewerError> {
        if !matches!(&options.target, ViewerTarget::RustDesk { address: None })
            || options.username != config.id
        {
            return Err(ViewerError::InvalidOptions);
        }
        Self::start_with_connector(options, lease, Connector::Rendezvous(config))
    }

    fn start_with_connector(
        options: ViewerOptions,
        lease: Arc<dyn SurfaceLease>,
        connector: Connector,
    ) -> Result<Arc<Self>, ViewerError> {
        // The surface is not required to exist yet. On OpenHarmony the UI
        // creates it after it asks for the session, and the platform reads the
        // lease when the first frame opens the surface; a lease still without
        // one fails there (`SurfaceError::LeaseInvalid`) instead of presenting
        // into nothing, so requiring it here only rejected the client's own
        // order of operations.
        if options.username.is_empty()
            || options.local_id.is_empty()
            || options.username.len() > 512
            || options.local_id.len() > 512
            || options.local_name.len() > 512
            || options.password.len() > 4096
            || !(1..=240).contains(&options.requested_fps)
        {
            return Err(ViewerError::InvalidOptions);
        }
        let runtime = runtime()?;
        let (mouse, mouse_rx) = mpsc::channel(COMMANDS);
        let state = Arc::new(State {
            control: Mutex::new(None),
            inner: Mutex::new(Inner {
                snapshot: ViewerSnapshot {
                    phase: "capability".into(),
                    protocol: options.target.protocol().as_str().into(),
                    ..Default::default()
                },
                geometry: None,
                decoder: None,
                observed_peer_close_reason: None,
            }),
            cancel: CancellationToken::new(),
            done: Notify::new(),
            result: Mutex::new(None),
            protocol: options.target.protocol(),
            authenticated: AtomicBool::new(false),
            rdp_input_flags: AtomicU16::new(0),
            peer_proven: AtomicBool::new(false),
            // The local policy is in force before the session starts, not after
            // the first caller asks: this is what makes a read-only viewer
            // read-only from its first event.
            input: InputGate::new(options.input_policy),
            resources_unconfirmed: AtomicBool::new(false),
        });
        let viewer = Arc::new(Self {
            state: state.clone(),
            mouse,
        });
        // Tasks hold State, NOT Viewer: dropping the last UI/HAR Viewer triggers
        // cancellation instead of a self-retaining session/Surface reference.
        runtime.spawn(async move {
            // Keep one final lease until run/decoder teardown ends, including
            // authentication failures; release that reference off the IO thread.
            let mut result = run(state.clone(), options, lease.clone(), mouse_rx, connector).await;
            if tokio::task::spawn_blocking(move || drop(lease))
                .await
                .is_err()
            {
                state.resources_unconfirmed.store(true, Ordering::Release);
                if result.is_ok() {
                    result = Err(ViewerError::TaskFailed);
                }
            }
            state.finish(result);
        });
        Ok(viewer)
    }
    pub fn snapshot(&self) -> ViewerSnapshot {
        self.state.snapshot()
    }

    /// Current gate epoch for a refusal report, not a successful input receipt.
    pub fn input_generation(&self) -> u64 {
        lock(&self.state.input.state).generation
    }
    /// Returns a terminal Surface-reclamation verdict once the viewer has
    /// finished. `Some(true)` means the platform release was confirmed;
    /// `Some(false)` means it was not. A connection/authentication failure can
    /// still have `Some(true)`, because safe Surface reuse is independent of
    /// why the remote session ended.
    pub fn reclamation_confirmed(&self) -> Option<bool> {
        lock(&self.state.result).as_ref().map(Result::is_ok)
    }

    /// The generation this event is queued under, or the error that stops it.
    ///
    /// The generation the caller names is compared with the one this same gate
    /// read publishes, in one critical section, so an event is never stamped
    /// with an epoch its caller did not name and a stale epoch is refused rather
    /// than relabelled under a newer one. The policy and the peer's grant are
    /// read in that same critical section, so an event queued while they admit
    /// it is still dropped by the writer if either changes before the writer
    /// reaches it — including a withdrawal and the grant that follows it.
    fn admission(&self, expected_generation: u64) -> Result<u64, ViewerError> {
        let gate = self.state.input.read();
        if !Facts::of(&self.state).admits(gate) {
            return Err(ViewerError::InputNotAllowed);
        }
        if gate.generation != expected_generation {
            return Err(ViewerError::StaleInputGeneration);
        }
        Ok(gate.generation)
    }

    /// The local input policy this viewer is enforcing.
    pub fn input_policy(&self) -> ViewerInputPolicy {
        self.state.input.policy()
    }

    /// Publishes a new local input policy for this viewer.
    ///
    /// This is the engine's own switch, not advice: input already queued under
    /// the previous policy is dropped without reaching the peer, and a policy
    /// that stops admitting input makes the one writer release exactly the keys
    /// and buttons it emitted, through that same ordered writer, before it
    /// forgets them. Nothing is reopened to do it — a release only undoes an
    /// emission this viewer made.
    ///
    /// The answer separates what this call already did from what is still on its
    /// way: `revoked` is the admission change, and `releases_owed` is the
    /// release the writer still owes the peer.
    pub fn set_input_policy(&self, policy: ViewerInputPolicy) -> InputPolicyOutcome {
        let facts = Facts::of(&self.state);
        let outcome = self.state.input.set(policy, &facts);
        // The writer releases what the new policy no longer admits; waking it
        // here is what makes that release happen without waiting for the next
        // event, and a permit it cannot consume yet is not lost.
        self.state.input.changed.notify_one();
        outcome
    }

    /// x/y are selected-display-local pixels for absolute events; the original
    /// protocol receives desktop-global coordinates. Wheel/trackpad/relative
    /// events retain signed deltas. Original mask = kind | (button_bits << 3).
    ///
    /// `expected_generation` is the policy generation the caller is acting on,
    /// and the returned generation is the one the queued event actually carries.
    /// They are the same value: the decision and the stamp come from one gate
    /// read, so a caller can tell a batch queued under one boundary from a batch
    /// queued under the next. A generation the gate has already left is refused
    /// with `StaleInputGeneration` instead of being restamped under the one in
    /// force, and a `Backpressure`/`Closed` answer means nothing was queued.
    pub fn send_mouse(
        &self,
        kind: u32,
        button: u32,
        x: i32,
        y: i32,
        expected_generation: u64,
    ) -> Result<u64, ViewerError> {
        let generation = self.admission(expected_generation)?;
        let valid = match kind {
            0 => button <= 0x1f,
            1 | 2 => matches!(button, 1 | 2 | 4 | 8 | 16),
            3..=5 => button == 0,
            _ => false,
        };
        if !valid {
            return Err(ViewerError::InvalidMouse);
        }
        let (x, y) = if kind <= 2 {
            let geometry = lock(&self.state.inner)
                .geometry
                .ok_or(ViewerError::InputNotAllowed)?;
            if x < 0 || y < 0 || x >= geometry.width || y >= geometry.height {
                return Err(ViewerError::InvalidMouse);
            }
            (
                x.checked_add(geometry.x).ok_or(ViewerError::InvalidMouse)?,
                y.checked_add(geometry.y).ok_or(ViewerError::InvalidMouse)?,
            )
        } else {
            (x, y)
        };
        if self.state.protocol == Protocol::Rdp {
            let batch = rdp_mouse(kind, button, x, y, (0, 0))?;
            rdp_preflight(&self.state, &batch.events[..batch.len])?;
        }
        self.mouse
            .try_send(QueuedInput {
                event: ViewerInput::Mouse { kind, button, x, y },
                generation,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => ViewerError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => ViewerError::Closed,
            })?;
        Ok(generation)
    }

    /// A key press or release, in X11 keysym terms.
    ///
    /// The RFB and RDP drivers consume keysyms. The original wire uses the
    /// legacy KeyEvent entry point instead; unsupported keys are refused before
    /// they can be queued.
    ///
    /// The generation contract is `send_mouse`'s: the epoch is named by the
    /// caller, a stale one is refused, and the returned generation is the stamp
    /// the queued event carries.
    pub fn send_key(
        &self,
        keysym: u32,
        down: bool,
        expected_generation: u64,
    ) -> Result<u64, ViewerError> {
        if !matches!(self.state.protocol, Protocol::Vnc | Protocol::Rdp) {
            return Err(ViewerError::InputNotAllowed);
        }
        let generation = self.admission(expected_generation)?;
        if keysym == 0 {
            return Err(ViewerError::InvalidMouse);
        }
        if self.state.protocol == Protocol::Rdp {
            let (_, key, _) = rdp_keysym(keysym)?;
            rdp_preflight(&self.state, &[key.event(down)])?;
        }
        self.mouse
            .try_send(QueuedInput {
                event: ViewerInput::Key { keysym, down },
                generation,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => ViewerError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => ViewerError::Closed,
            })?;
        Ok(generation)
    }

    /// Sends a legacy key message after authentication and keyboard admission.
    /// RustDesk preserves the original message; RDP translates the supported
    /// legacy control/character/text contract to typed upstream input. An RDP
    /// key the peer's declared capabilities cannot carry is refused before it
    /// is queued; a release is admitted when the peer carries any
    /// representation of that key, because the writer releases the one its own
    /// ledger emitted rather than the one this event alone derives.
    ///
    /// On a peer the handshake did not prove, the policy in force is what admits
    /// this event: until this session's operator accepts the connection, the
    /// engine refuses it here and again at the writer.
    ///
    /// The generation contract is `send_mouse`'s: the epoch is named by the
    /// caller, a stale one is refused, and the returned generation is the stamp
    /// the queued event carries.
    pub fn send_rustdesk_key(
        &self,
        event: KeyEvent,
        expected_generation: u64,
    ) -> Result<u64, ViewerError> {
        if !matches!(self.state.protocol, Protocol::RustDesk | Protocol::Rdp) {
            return Err(ViewerError::InputNotAllowed);
        }
        let generation = self.admission(expected_generation)?;
        if self.state.protocol == Protocol::Rdp {
            rdp_legacy_admission(&self.state, &event)?;
        }
        self.mouse
            .try_send(QueuedInput {
                event: ViewerInput::RustDeskKey { event },
                generation,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => ViewerError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => ViewerError::Closed,
            })?;
        Ok(generation)
    }
    /// Ask the peer for a fresh keyframe (RefreshVideo). Out-of-band control, so
    /// it is not subject to the local input-permission gate. Before login there
    /// is no writer channel yet and this reports failure instead of queueing.
    pub fn request_keyframe(&self) -> Result<(), ViewerError> {
        let sender = lock(&self.state.control)
            .clone()
            .ok_or(ViewerError::TransportFailed)?;
        let mut misc = proto::Misc::new();
        misc.set_refresh_video(true);
        let mut message = Message::new();
        message.set_misc(misc);
        sender
            .try_send(message)
            .map_err(|_| ViewerError::TransportFailed)
    }

    pub fn request_close(&self) {
        self.state.request_close();
    }
    /// Confirms resource reclamation only. Authentication/network/media errors
    /// stay in snapshot.error; they do not prevent a safe retry on this Surface.
    pub async fn close(&self) -> Result<(), ViewerError> {
        self.request_close();
        loop {
            let done = self.state.done.notified();
            tokio::pin!(done);
            done.as_mut().enable();
            if let Some(result) = lock(&self.state.result).clone() {
                return result;
            }
            done.await;
        }
    }
}
impl Drop for Viewer {
    fn drop(&mut self) {
        self.state.request_close();
    }
}

struct Password(Vec<u8>);
impl Drop for Password {
    fn drop(&mut self) {
        hbb_common::sodiumoxide::utils::memzero(&mut self.0);
    }
}

/// The official-client version whose wire behavior this engine implements.
///
/// One constant, because a peer gates features on it (`get_version_number` in its
/// own `server/connection.rs`): the version of this engine's own crate would tell
/// a peer its viewer predates the acknowledgement and decode behavior the engine
/// already implements. It is the client baseline the whole engine speaks — the
/// same value `host.rs`, `rendezvous.rs` and `rendezvous::registration` put in
/// their own messages.
pub const CLIENT_VERSION: &str = "1.4.9";

/// This engine's own platform, in the terms a peer receives it.
///
/// The official client sends `whoami::platform()`, and so does this one, with the
/// one exception the compiler can name: on HarmonyOS `target_os` is `linux` and
/// the pinned `whoami` has no HarmonyOS arm, so it would answer "Linux" for a
/// device that is not one. Everywhere else the answer comes from the platform
/// itself rather than from a literal.
fn my_platform() -> String {
    #[cfg(target_env = "ohos")]
    {
        "HarmonyOS".to_owned()
    }
    #[cfg(not(target_env = "ohos"))]
    {
        hbb_common::whoami::platform().to_string()
    }
}

fn login_request(options: &ViewerOptions, decoders: Decoders) -> LoginRequest {
    // Key handshake has initialized sodium before Challenge. Never reuse a
    // process-local counter as an original-peer reconnect session identifier.
    let mut session_bytes = [0u8; 8];
    hbb_common::sodiumoxide::randombytes::randombytes_into(&mut session_bytes);
    let supported = decoders.supported_decoding();
    LoginRequest {
        username: options.username.clone(),
        my_id: options.local_id.clone(),
        my_name: options.local_name.clone(),
        my_platform: my_platform(),
        version: CLIENT_VERSION.into(),
        session_id: u64::from_le_bytes(session_bytes).max(1),
        video_ack_required: false,
        option: Some(OptionMessage {
            supported_decoding: Some(supported).into(),
            custom_fps: options.requested_fps as i32,
            disable_audio: BoolOption::Yes.into(),
            disable_clipboard: BoolOption::Yes.into(),
            enable_file_transfer: BoolOption::No.into(),
            // The keyboard channel is asked for whatever the local policy is:
            // the local policy is what stops input, and a read-only switch that
            // is turned off again must not be left waiting for a grant the peer
            // was told never to send.
            disable_keyboard: BoolOption::No.into(),
            disable_camera: BoolOption::Yes.into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

async fn authenticate(
    state: &State,
    mut options: ViewerOptions,
    decoders: Decoders,
    connector: Connector,
) -> Result<AuthenticatedParts, ViewerError> {
    let password = Password(std::mem::take(&mut options.password).into_bytes());
    let mut session = match connector {
        Connector::Direct(identity) => {
            state.phase("connecting");
            let ViewerTarget::RustDesk {
                address: Some(address),
            } = options.target
            else {
                return Err(ViewerError::InvalidOptions);
            };
            let session = ViewerSession::connect_direct(address, identity, Duration::from_secs(30))
                .await
                .map_err(|_| ViewerError::ConnectFailed)?;
            state.route("direct_tcp");
            session
        }
        Connector::Rendezvous(config) => {
            state.phase("rendezvous");
            let timeout = config.connect_timeout;
            let (established, evidence) = crate::rendezvous::connect_viewer(config)
                .await
                .map_err(|_| ViewerError::RendezvousFailed)?;
            if !evidence.encrypted || !evidence.peer_verified {
                return Err(ViewerError::RendezvousFailed);
            }
            state.route(match evidence.route {
                RouteKind::TcpHolePunch => "tcp_hole_punch",
                RouteKind::Relay => "relay",
            });
            ViewerSession::from_established(established, timeout, Duration::from_secs(30))
        }
    };
    state.phase("authenticating");
    loop {
        match session
            .recv()
            .await
            // A recv failure is a transport outcome, not an authentication
            // verdict: the peer said nothing about this login, and folding it into
            // a login failure would make a client offer a password form for a
            // broken wire.
            .map_err(|_| ViewerError::TransportFailed)?
        {
            ViewerEvent::Challenge => {
                let request = login_request(&options, decoders);
                session
                    .login(
                        request,
                        if password.0.is_empty() {
                            None
                        } else {
                            Some(&password.0)
                        },
                    )
                    .await
                    // The login could not be sent, which is the same transport
                    // outcome and not the peer's decision about the credential.
                    .map_err(|_| ViewerError::TransportFailed)?;
            }
            ViewerEvent::Authorized(_) => {
                return session
                    .into_authenticated_parts()
                    .map_err(|_| ViewerError::AuthenticationFailed);
            }
            ViewerEvent::LoginError(error) if error == "No Password Access" => {
                state.phase("awaiting_approval")
            }
            ViewerEvent::LoginError(error)
                if error == "2FA Required" || error == "Wrong 2FA Code" =>
            {
                return Err(ViewerError::SecondFactorUnsupported);
            }
            // Every other refusal keeps its category: the peer's text is what the
            // classification reads, and the category is what a client decides
            // with.
            ViewerEvent::LoginError(error) => {
                return Err(ViewerError::LoginFailed(LoginFailure::of(&error)));
            }
            ViewerEvent::Closed => {
                lock(&state.inner).observed_peer_close_reason = session.peer_close_reason();
                return Err(ViewerError::RemoteClosed);
            }
            ViewerEvent::Progress | ViewerEvent::PreAuthControl(_) => {}
            _ => return Err(ViewerError::AuthenticationFailed),
        }
    }
}

/// The one entry point every protocol goes through.
///
/// The shell — cancellation, snapshot, teardown, surface ownership and the
/// blocking-worker rule — is shared. Only the wire differs, and RFB and RDP
/// have no RustDesk handshake to share, so they take their endpoint directly
/// instead of a `Connector`.
async fn run(
    state: Arc<State>,
    options: ViewerOptions,
    lease: Arc<dyn SurfaceLease>,
    mouse: mpsc::Receiver<QueuedInput>,
    connector: Connector,
) -> Result<(), ViewerError> {
    match options.target.clone() {
        ViewerTarget::RustDesk { .. } => {
            run_rustdesk(state, options, lease, mouse, connector).await
        }
        ViewerTarget::Vnc(endpoint) => run_rfb(state, options, lease, mouse, endpoint).await,
        ViewerTarget::Rdp(endpoint) => run_rdp(state, options, lease, mouse, endpoint).await,
    }
}

async fn run_rustdesk(
    state: Arc<State>,
    options: ViewerOptions,
    lease: Arc<dyn SurfaceLease>,
    mouse: mpsc::Receiver<QueuedInput>,
    connector: Connector,
) -> Result<(), ViewerError> {
    // Metadata IPC is also off the UI / network worker. Do not discard a native
    // creation JoinHandle on cancellation; the feeder always joins and closes it.
    let caps = tokio::task::spawn_blocking(video::capabilities)
        .await
        .map_err(|_| ViewerError::TaskFailed)??;
    let parts = tokio::select! {
        biased;
        _ = state.cancel.cancelled() => return Ok(()),
        parts = authenticate(&state, options, caps, connector) => parts?,
    };
    {
        let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.snapshot.encrypted = matches!(
            &parts.context.security,
            crate::handshake::Security::Encrypted { .. }
        );
        inner.snapshot.peer_verified = matches!(
            &parts.context.security,
            crate::handshake::Security::Encrypted { peer_id: Some(_) }
        );
        if let Some(info) = &parts.context.peer_info {
            inner.snapshot.platform = info.platform.clone();
            inner.snapshot.version = info.version.clone();
            inner.snapshot.current_display = info.current_display;
            inner.snapshot.displays = info
                .displays
                .iter()
                .map(|display| PeerDisplayInfo {
                    width: display.width,
                    height: display.height,
                    x: display.x,
                    y: display.y,
                    cursor_embedded: display.cursor_embedded,
                    original_width: display
                        .original_resolution
                        .as_ref()
                        .map_or(0, |size| size.width),
                    original_height: display
                        .original_resolution
                        .as_ref()
                        .map_or(0, |size| size.height),
                })
                .collect();
        }
    }
    let source = Geometry::of_peer(
        parts
            .context
            .peer_info
            .as_ref()
            .ok_or(ViewerError::InvalidPeerGeometry)?,
    )?;
    state.geometry(source);
    // The handshake's grant goes through the gate rather than beside it: it is
    // the same permission channel a later message changes, so it is published
    // under the lock that stamps input, and turning it off and on again cannot
    // leave input admitted under either of the older states.
    state.input.grant(parts.context.permissions.keyboard);
    // The handshake's own proof, recorded before the session is authorized so
    // an admitted event can never be raced ahead of the evidence that admits it.
    // A direct dial to a peer this client has no key for reads `false` here,
    // which is what makes the session's own acceptance the only way in.
    state.peer_proven.store(
        matches!(
            &parts.context.security,
            crate::handshake::Security::Encrypted { peer_id: Some(_) }
        ),
        Ordering::Release,
    );
    state.authenticated.store(true, Ordering::Release);
    state.phase("authenticated");
    let (admission, feed) = video::pipeline(state.clone(), caps, source);
    let (control_tx, control_rx) = mpsc::channel(COMMANDS);
    *lock(&state.control) = Some(control_tx.clone());
    let mut tasks = JoinSet::new();
    tasks.spawn(receive(state.clone(), parts.reader, admission, control_tx));
    tasks.spawn(write(state.clone(), parts.writer, mouse, control_rx));
    tasks.spawn(feed.run(lease));
    let first = tokio::select! {
        biased;
        _ = state.cancel.cancelled() => Ok(()),
        result = tasks.join_next() => match result {
            Some(Ok(result)) => result,
            _ => Err(ViewerError::TaskFailed),
        },
    };
    state.request_close();
    // Reader drop closes the paired writer, so its TransportFailed/Closed may
    // join before the reader's observed close. Only that narrow fallout can be
    // replaced by the explicit request; any substantive failure keeps priority.
    let mut only_close_fallout = matches!(&first, Ok(())
        | Err(ViewerError::RemoteClosed | ViewerError::TransportFailed | ViewerError::Closed));
    let mut result = first;
    // Never abort the feeder: it owns the native decoder and its blocking join.
    while let Some(joined) = tasks.join_next().await {
        let next = joined.unwrap_or(Err(ViewerError::TaskFailed));
        if let Err(error) = next {
            only_close_fallout &= matches!(&error,
                ViewerError::RemoteClosed | ViewerError::TransportFailed | ViewerError::Closed);
            // A teardown failure must reach HAR even when localClose was first.
            if result.is_ok()
                || matches!(
                    &error,
                    ViewerError::Decoder(DecoderError::DestroyFailed { .. })
                )
                || (matches!(&error, ViewerError::ReclamationUnconfirmed)
                    && !matches!(&result, Err(ViewerError::Decoder(DecoderError::DestroyFailed { .. }))))
                || (matches!(&result, Err(ViewerError::RemoteClosed | ViewerError::TransportFailed | ViewerError::Closed))
                    && !matches!(&error, ViewerError::RemoteClosed | ViewerError::TransportFailed | ViewerError::Closed)
                    && lock(&state.inner).observed_peer_close_reason == Some(PeerCloseReason::ManualRequest))
            {
                result = Err(error);
            }
        }
    }
    if only_close_fallout && !state.resources_unconfirmed.load(Ordering::Acquire)
        && lock(&state.inner).observed_peer_close_reason == Some(PeerCloseReason::ManualRequest) {
        return Err(ViewerError::RemoteClosed);
    }
    result
}

async fn receive(
    state: Arc<State>,
    mut reader: WireReader,
    mut admission: video::VideoAdmission<State>,
    control: mpsc::Sender<Message>,
) -> Result<(), ViewerError> {
    loop {
        let message = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => return Ok(()),
            result = reader.recv() => result.map_err(|_| ViewerError::TransportFailed)?.ok_or(ViewerError::RemoteClosed)?,
        };
        match message.union {
            Some(message::Union::VideoFrame(frame)) => {
                if admission.admit(frame).await? == video::Admitted::Cancelled {
                    return Ok(());
                }
            }
            Some(message::Union::TestDelay(probe)) => {
                if !probe.from_client {
                    let mut response = Message::new();
                    response.set_test_delay(probe);
                    control
                        .try_send(response)
                        .map_err(|_| ViewerError::Backpressure)?;
                }
            }
            Some(message::Union::Misc(m)) => match m.union {
                Some(misc::Union::PermissionInfo(permission)) => {
                    if permission.permission.enum_value().ok() == Some(Permission::Keyboard) {
                        // The grant is published under the gate's own lock, so a
                        // withdrawal — and the grant that follows it — advances
                        // the generation and invalidates what this writer queued
                        // and emitted under the previous one. The gate wakes the
                        // writer itself when the grant moves; a writer that is
                        // busy when it does still releases on its next event.
                        state.input.grant(permission.enabled);
                    }
                }
                Some(misc::Union::CloseReason(reason)) => {
                    lock(&state.inner).observed_peer_close_reason = PeerCloseReason::of(&reason);
                    return Err(ViewerError::RemoteClosed);
                }
                Some(misc::Union::SwitchDisplay(display)) => admission.switch_display(&display)?,
                _ => {}
            },
            // Audio/clipboard/file features were explicitly disabled. Cursor and
            // informational messages do not authorize input or fake video state.
            _ => {}
        }
    }
}

/// The keys and buttons this writer emitted as down and has not released.
///
/// Each hold carries the generation that admitted it, so the release pass can
/// tell a hold from before a policy change from one the policy in force still
/// admits: what the operator's read-only switch, the withdrawal of an
/// acceptance or the peer's own permission stopped is released, and nothing
/// else ever is.
#[derive(Default)]
struct RustDeskHeld {
    /// One entry per key this writer is holding on the peer: the generation
    /// that admitted the down, and the release that down owes. The release is
    /// the down's own payload with `down` cleared and no modifier state of its
    /// own, which is the shape the client's own key up carries.
    keys: Vec<(u64, KeyEvent)>,
    /// One slot per wire button bit, holding the generation that admitted its
    /// down. `None` is a button this writer is not holding.
    buttons: [Option<u64>; BUTTON_BITS.len()],
    /// Where this writer's last pointer event put the peer's pointer: a release
    /// repeats the position the peer already has instead of moving it back to
    /// wherever the button went down.
    pointer: (i32, i32),
}

/// The original wire's button bits, in the order a release lets them go.
///
/// `MouseEvent.mask` is `kind | (button_bits << 3)`, and these are the bits a
/// down or an up can carry: `Viewer::send_mouse` accepts exactly them.
const BUTTON_BITS: [u32; 5] = [0x01, 0x02, 0x04, 0x08, 0x10];
/// The original wire's mouse kinds, matching `MouseEvent.mask`'s low bits.
const MOUSE_MOVE: u32 = 0;
const MOUSE_DOWN: u32 = 1;
const MOUSE_UP: u32 = 2;

impl RustDeskHeld {
    /// The button slot `button` occupies, for the bits the wire can hold.
    fn slot(button: u32) -> Option<usize> {
        BUTTON_BITS.iter().position(|bit| *bit == button)
    }

    /// Whether this event would take one more key or button, read from the
    /// event and the holds already taken. A hold that would pass the ledger's
    /// bound is refused by the gate, so a down this writer could not remember is
    /// never emitted.
    fn adds(&self, event: &ViewerInput) -> bool {
        match event {
            ViewerInput::Mouse { kind, button, .. } => {
                *kind == MOUSE_DOWN
                    && Self::slot(*button).is_some_and(|slot| self.buttons[slot].is_none())
            }
            ViewerInput::RustDeskKey { event } => match key_identity(event) {
                Some(release) if holds_key(event) => {
                    !self.keys.iter().any(|entry| entry.1 == release)
                }
                _ => false,
            },
            ViewerInput::Key { .. } => false,
        }
    }

    /// Records one event the wire took, and reports the hold it let go, by the
    /// generation that admitted it.
    ///
    /// A down becomes a hold with the generation that admitted it; an up drops
    /// the hold it named, whoever asked for it, and hands back the stamp that
    /// hold carried. Everything here is recorded after the write it describes,
    /// so a hold exists only for an emission the peer can have seen.
    fn record(&mut self, event: &ViewerInput, generation: u64) -> Option<u64> {
        match event {
            ViewerInput::Mouse { kind, button, .. } => {
                let Some(slot) = Self::slot(*button) else {
                    return None;
                };
                match *kind {
                    MOUSE_DOWN => {
                        self.buttons[slot] = Some(generation);
                        None
                    }
                    MOUSE_UP => self.buttons[slot].take(),
                    _ => None,
                }
            }
            ViewerInput::RustDeskKey { event } => {
                let Some(identity) = key_identity(event) else {
                    return None;
                };
                if holds_key(event) {
                    match self.keys.iter_mut().find(|entry| entry.1 == identity) {
                        // The peer's key is one key: a repeat of a down this
                        // writer already holds keeps the one hold it has.
                        Some(entry) => entry.0 = generation,
                        None => self.keys.push((generation, identity)),
                    }
                    return None;
                }
                match self.keys.iter().position(|entry| entry.1 == identity) {
                    Some(index) => Some(self.keys.remove(index).0),
                    None => None,
                }
            }
            ViewerInput::Key { .. } => None,
        }
    }
}

/// Whether one key event holds the key it names.
///
/// A tap (`press`) carries its own release and an up is a release, so neither
/// holds anything this writer would have to release later.
fn holds_key(event: &KeyEvent) -> bool {
    event.down && !event.press
}

/// The key one event names, in the shape its release carries: the same payload
/// with `down` cleared and no modifier state of its own.
///
/// This is both what a hold is remembered as and what its release repeats. The
/// original wire has no key id, so the payload is the identity; `None` is an
/// event that names no key at all (a text sequence, a hotkey action), which
/// therefore holds nothing.
fn key_identity(event: &KeyEvent) -> Option<KeyEvent> {
    match event.union.as_ref()? {
        proto::key_event::Union::ControlKey(_)
        | proto::key_event::Union::Chr(_)
        | proto::key_event::Union::Unicode(_) => {
            let mut release = event.clone();
            release.down = false;
            release.press = false;
            release.modifiers.clear();
            Some(release)
        }
        // A text sequence and a hotkey action name no key, and neither does a
        // variant this build does not know.
        _ => None,
    }
}

async fn write(
    state: Arc<State>,
    mut writer: WireWriter,
    mut mouse: mpsc::Receiver<QueuedInput>,
    mut control: mpsc::Receiver<Message>,
) -> Result<(), ViewerError> {
    let mut held = RustDeskHeld::default();
    let outcome = write_loop(&state, &mut writer, &mut mouse, &mut control, &mut held).await;
    // The transport stops with the writer, so nothing it still held can be
    // released through it any more. Those holds are reported as releases whose
    // completion is unconfirmed: whether the peer still holds a key or button is
    // unknown, so no claim is made that a release arrived or that it did not.
    state.input.stopped();
    outcome
}

/// One loop over the writer's own channels: session messages, queued input, and
/// the policy changes that must be answered before either.
async fn write_loop(
    state: &State,
    writer: &mut WireWriter,
    mouse: &mut mpsc::Receiver<QueuedInput>,
    control: &mut mpsc::Receiver<Message>,
    held: &mut RustDeskHeld,
) -> Result<(), ViewerError> {
    loop {
        tokio::select! {
            biased;
            _ = state.cancel.cancelled() => return Ok(()),
            // A policy change is handled before anything else on the queue: the
            // release it owes is ordered ahead of the input that would otherwise
            // follow it, and the pass reads the policy it finds rather than
            // replaying the change.
            _ = state.input.changed.notified() => {
                release_unadmitted(state, writer, held).await?;
            }
            value = control.recv() => match value {
                Some(message) => {
                    wire_send(state, writer, &message).await?;
                }
                None => return Ok(()),
            },
            value = mouse.recv() => match value {
                Some(queued) => take_input(state, writer, held, queued).await?,
                None => return Ok(()),
            },
        }
    }
}

/// Emits one queued input event, or drops it.
///
/// The policy in force is asked again here, at the writer that owns the wire,
/// and its answer is taken under the same lock that publishes it: an event the
/// policy no longer admits owns nothing, so dropping it owes no release, while
/// an event that reaches the wire becomes a hold whose release this writer owes.
async fn take_input(
    state: &State,
    writer: &mut WireWriter,
    held: &mut RustDeskHeld,
    queued: QueuedInput,
) -> Result<(), ViewerError> {
    // The release this writer owes is ordered ahead of every event it takes,
    // and not only ahead of the change that asked for it: a change is published
    // under the gate's own lock before the writer is woken, so an event queued
    // under the new generation can reach this point first — and a hold from
    // before the change would then be adopted and restamped by the event that
    // followed it instead of being released. Running the pass here is what
    // makes that order independent of when the wake-up is delivered.
    release_unadmitted(state, writer, held).await?;
    let Some(message) = input_message(&queued.event) else {
        // An RFB key has no representation on this wire.
        return Ok(());
    };
    let facts = Facts::of(state);
    let adds = held.adds(&queued.event);
    if !state.input.own(queued.generation, adds, &facts) {
        return Ok(());
    }
    if !wire_send(state, writer, &message).await? {
        return Ok(());
    }
    if let ViewerInput::Mouse { kind, x, y, .. } = &queued.event {
        if matches!(*kind, MOUSE_MOVE | MOUSE_DOWN | MOUSE_UP) {
            held.pointer = (*x, *y);
        }
    }
    let released = held.record(&queued.event, queued.generation);
    if let Some(stamped) = released {
        state.input.released(stamped);
    }
    Ok(())
}

/// Sends one message on the session's one writer.
///
/// `false` means it was not taken because the session is cancelling. The
/// transport's own rule is preserved: a partial write is never retried and a
/// failed write ends the session. A release that was not taken is therefore
/// never recorded as one that was made — and never as one known not to have
/// arrived either, because a failed write may have put part of itself on the
/// wire, leaving the peer's state unknown.
async fn wire_send(
    state: &State,
    writer: &mut WireWriter,
    message: &Message,
) -> Result<bool, ViewerError> {
    tokio::select! {
        biased;
        _ = state.cancel.cancelled() => Ok(false),
        result = writer.send(message) => {
            result.map_err(|_| ViewerError::TransportFailed)?;
            Ok(true)
        }
    }
}

/// Releases every key and button this writer emitted which the policy or the
/// peer's grant in force no longer admits.
///
/// It runs on the one ordered writer, so a release is ordered with the input
/// that preceded it and can never overtake an event still on its way out, and it
/// asks the policy for nothing: a release only undoes this writer's own
/// emission, which is why revoking input never means reopening it.
///
/// The gate is read once here, and the pass never holds its lock across a send:
/// what it decided about the holds it started with still holds while it releases
/// them, because only this writer creates holds, and it is the one running the
/// pass.
async fn release_unadmitted(
    state: &State,
    writer: &mut WireWriter,
    held: &mut RustDeskHeld,
) -> Result<(), ViewerError> {
    let gate = state.input.read();
    let admitted = Facts::of(state).admits(gate);
    // A hold is released when the policy or the grant in force no longer admits
    // it. Both changes advance the generation, so a hold from before one is
    // released even if admission was granted again in the meantime; a hold the
    // peer's own permission stopped is released by the gate's answer alone.
    let stale = |stamped: u64| !admitted || stamped != gate.generation;
    for slot in 0..BUTTON_BITS.len() {
        let Some(stamped) = held.buttons[slot] else {
            continue;
        };
        if !stale(stamped) {
            continue;
        }
        let mut message = Message::new();
        message.set_mouse_event(MouseEvent {
            mask: (MOUSE_UP | (BUTTON_BITS[slot] << 3)) as i32,
            x: held.pointer.0,
            y: held.pointer.1,
            ..Default::default()
        });
        if !wire_send(state, writer, &message).await? {
            return Ok(());
        }
        held.buttons[slot] = None;
        state.input.released(stamped);
    }
    let mut index = 0;
    while index < held.keys.len() {
        if !stale(held.keys[index].0) {
            index += 1;
            continue;
        }
        let mut message = Message::new();
        message.set_key_event(held.keys[index].1.clone());
        if !wire_send(state, writer, &message).await? {
            return Ok(());
        }
        let (stamped, _) = held.keys.remove(index);
        state.input.released(stamped);
    }
    Ok(())
}

/// Encodes one neutral input as an original-wire input message.
///
/// RFB key events have a different wire representation and therefore cannot be
/// emitted on this writer. RustDesk key events arrive here already encoded by
/// the NAPI boundary and retain the original client's legacy semantics.
fn input_message(input: &ViewerInput) -> Option<Message> {
    match input {
        ViewerInput::Mouse { kind, button, x, y } => {
            let mut message = Message::new();
            message.set_mouse_event(MouseEvent {
                mask: (kind | (button << 3)) as i32,
                x: *x,
                y: *y,
                ..Default::default()
            });
            Some(message)
        }
        ViewerInput::RustDeskKey { event } => {
            let mut message = Message::new();
            message.set_key_event(event.clone());
            Some(message)
        }
        ViewerInput::Key { .. } => None,
    }
}

/// The presentation sink a rectangle protocol writes into.
///
/// On a device this is the same `SurfaceLease` the decoder path uses, with a
/// CPU-writable buffer instead of a codec. Off-device there is no Surface, and
/// the in-memory sink keeps the driver exercisable on a host build; the choice
/// is made at compile time, so a device build cannot silently fall back to a
/// buffer nobody displays.
enum Sink {
    #[cfg(target_env = "ohos")]
    Surface(crate::surface::OhosSurface),
    #[cfg(not(target_env = "ohos"))]
    Memory(crate::surface::MemorySurface),
}

impl Sink {
    fn open(
        lease: Arc<dyn SurfaceLease>,
        width: i32,
        height: i32,
    ) -> Result<Self, crate::surface::SurfaceError> {
        #[cfg(target_env = "ohos")]
        {
            Ok(Self::Surface(crate::surface::OhosSurface::open(
                lease, width, height,
            )?))
        }
        #[cfg(not(target_env = "ohos"))]
        {
            let _ = lease;
            Ok(Self::Memory({
                let mut surface = crate::surface::MemorySurface::new(width, height)?;
                // The lease carries the observer for the clients that publish
                // through a caller: without this the frames never leave the sink.
                if let Some(observer) = lease.frame_observer() {
                    surface.observe(observer);
                }
                surface
            }))
        }
    }

    fn present(&mut self) -> Result<(), crate::surface::SurfaceError> {
        match self {
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => surface.present(),
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(surface) => {
                surface.take_damage();
                Ok(())
            }
        }
    }

    fn close(self) -> Result<(), crate::surface::SurfaceError> {
        match self {
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => surface.close(),
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(_) => Ok(()),
        }
    }
}

impl crate::protocol::rect::PixelTarget for Sink {
    fn layout(&self) -> crate::protocol::rect::PixelLayout {
        crate::protocol::rect::PixelLayout::bgra8888()
    }
    fn size(&self) -> (i32, i32) {
        match self {
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => crate::protocol::rect::PixelTarget::size(surface),
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(surface) => crate::protocol::rect::PixelTarget::size(surface),
        }
    }
    fn rect_mut(
        &mut self,
        rect: crate::protocol::rect::Rect,
    ) -> Result<crate::protocol::rect::RectBuf<'_>, crate::protocol::rect::PixelError> {
        match self {
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => surface.rect_mut(rect),
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(surface) => surface.rect_mut(rect),
        }
    }
    fn damage(&mut self, rect: crate::protocol::rect::Rect) {
        match self {
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => surface.damage(rect),
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(surface) => surface.damage(rect),
        }
    }
    fn copy_rect(
        &mut self,
        dst: crate::protocol::rect::Rect,
        src_x: i32,
        src_y: i32,
    ) -> Result<(), crate::protocol::rect::PixelError> {
        match self {
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => surface.copy_rect(dst, src_x, src_y),
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(surface) => surface.copy_rect(dst, src_x, src_y),
        }
    }
    fn resize(&mut self, width: i32, height: i32) -> Result<(), crate::protocol::rect::PixelError> {
        match self {
            // Fully qualified: `OhosSurface` has an inherent `resize` that
            // returns `SurfaceError`, and it would shadow the trait method here.
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => {
                crate::protocol::rect::PixelTarget::resize(surface, width, height)
            }
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(surface) => surface.resize(width, height),
        }
    }
}

/// The RFB pointer button one original-wire button carries.
///
/// Original button codes (`src/common.rs::input`): LEFT 0x01, RIGHT 0x02,
/// WHEEL 0x04, BACK 0x08, FORWARD 0x10. RFB's mask is 1 left, 2 middle, 4
/// right, 8 wheel-up, 16 wheel-down. Back and forward have no RFB bit and are
/// dropped rather than mapped onto something they are not, and the wire's
/// middle button is not mapped either: this driver has never sent RFB's middle
/// bit, and inventing the mapping now would be a new behavior rather than a
/// preserved one.
fn rfb_button_bit(button: u32) -> Option<u8> {
    match button {
        0x01 => Some(0x01),
        0x02 => Some(0x04),
        _ => None,
    }
}

/// RFB's pointer button bits that stay down, in the order a release clears
/// them. Bits 8 and 16 are the wheel's transient pair, which no event holds,
/// and the middle bit is one this driver never sets.
const RFB_BUTTON_BITS: [u8; 2] = [0x01, 0x04];

/// The pointer buttons and keys one RFB writer emitted as down and has not
/// released.
///
/// Each hold carries the generation that admitted it, so the release pass can
/// tell a hold from before a policy change from one the policy in force still
/// admits: what the operator's read-only switch or the peer's permission
/// stopped is released, and nothing else ever is.
#[derive(Default)]
struct RfbHeld {
    /// One slot per button RFB can hold, holding the generation that admitted
    /// its down. `None` is a button this writer is not holding.
    buttons: [Option<u64>; RFB_BUTTON_BITS.len()],
    /// Held keysyms with the generation that admitted their down, in the order
    /// they went down.
    keysyms: Vec<(u64, u32)>,
    /// Where this writer's last pointer event put the peer's pointer: a release
    /// repeats the position the peer already has.
    pointer: (u16, u16),
}

impl RfbHeld {
    /// The slot one RFB button bit occupies.
    fn slot(bit: u8) -> Option<usize> {
        RFB_BUTTON_BITS
            .iter()
            .position(|candidate| *candidate == bit)
    }

    /// The held set as RFB's own mask, which is the whole pointer state the
    /// wire carries.
    fn mask(&self) -> u8 {
        RFB_BUTTON_BITS
            .iter()
            .enumerate()
            .filter(|(slot, _)| self.buttons[*slot].is_some())
            .fold(0, |mask, (_, bit)| mask | bit)
    }
}

/// Emits one queued input event on the RFB session, or drops it.
///
/// The policy in force is asked here, at the writer that owns the socket, and
/// its answer is taken under the same lock that publishes it: an event the
/// policy no longer admits owns nothing, so dropping it owes no release, while
/// an event that reaches the wire becomes a hold whose release this writer owes.
async fn rfb_input(
    state: &State,
    session: &mut crate::protocol::rfb::session::RfbSession,
    held: &mut RfbHeld,
    queued: QueuedInput,
) -> Result<(), ViewerError> {
    // The same rule the original wire's writer keeps: the release this writer
    // owes goes out before the event it is about to take. A change is published
    // under the gate's lock before the writer is woken, so an event queued under
    // the new generation can arrive in that window — and without this pass, RFB
    // would carry the stale held bit in the event's whole-pointer state and the
    // button or key it stands for would never be released.
    rfb_release_unadmitted(state, session, held).await?;
    let facts = Facts::of(state);
    let generation = queued.generation;
    match queued.event {
        ViewerInput::Mouse { kind, button, x, y } => {
            let (px, py) = if kind <= 2 {
                (x.clamp(0, i32::from(u16::MAX)) as u16, y.clamp(0, i32::from(u16::MAX)) as u16)
            } else {
                // Wheel/relative payloads are deltas, never framebuffer
                // coordinates (the migrated adapter validates the latter).
                held.pointer
            };
            // RFB carries *which buttons are down*, not the original wire's
            // move/down/up kinds, so this driver keeps the held set and
            // translates. A press or a release changes one bit of it; a move, a
            // wheel and a wire button RFB has no bit for carry it as it is.
            let mut mask = held.mask();
            let mut take = None;
            let mut let_go = None;
            let mut transient = None;
            match (kind, rfb_button_bit(button)) {
                (1 | 2, Some(bit)) => match RfbHeld::slot(bit) {
                    Some(slot) if kind == 1 => {
                        mask |= RFB_BUTTON_BITS[slot];
                        take = Some(slot);
                    }
                    Some(slot) => {
                        mask &= !RFB_BUTTON_BITS[slot];
                        let_go = Some(slot);
                    }
                    None => {}
                },
                // A wheel event is transient in RFB: the bit is set for one
                // event and cleared by the next, so it is sent as a pair and
                // never becomes a hold.
                (3, _) if y != 0 => {
                    let bit = if y < 0 { 0x08 } else { 0x10 };
                    transient = Some(mask);
                    mask |= bit;
                }
                _ => {}
            }
            let adds = take.is_some_and(|slot| held.buttons[slot].is_none());
            if !state.input.own(generation, adds, &facts) {
                return Ok(());
            }
            if !rfb_send_pointer(state, session, px, py, mask).await? {
                return Ok(());
            }
            if let Some(cleared) = transient {
                if !rfb_send_pointer(state, session, px, py, cleared).await? {
                    return Ok(());
                }
            }
            // Only what the socket took is recorded: the button this event took
            // becomes a hold, and the one it let go stops being one.
            if let Some(slot) = take {
                held.buttons[slot] = Some(generation);
            }
            if let Some(slot) = let_go {
                if let Some(stamped) = held.buttons[slot].take() {
                    state.input.released(stamped);
                }
            }
            // Only an event that carries a position moves the peer's pointer.
            // A wheel and a trackpad event carry notches and deltas, so they
            // must not become the position a release repeats.
            if kind <= 2 {
                held.pointer = (px, py);
            }
        }
        ViewerInput::Key { keysym, down } => {
            let existing = held.keysyms.iter().position(|entry| entry.1 == keysym);
            let adds = down && existing.is_none();
            if !state.input.own(generation, adds, &facts) {
                return Ok(());
            }
            if !rfb_send_key(state, session, keysym, down).await? {
                return Ok(());
            }
            match (down, existing) {
                // The peer's key is one key: a press of a key this writer
                // already holds keeps the one hold it has.
                (true, Some(index)) => held.keysyms[index].0 = generation,
                (true, None) => held.keysyms.push((generation, keysym)),
                (false, Some(index)) => {
                    let (stamped, _) = held.keysyms.remove(index);
                    state.input.released(stamped);
                }
                (false, None) => {}
            }
        }
        // A RustDesk key has no RFB representation.
        ViewerInput::RustDeskKey { .. } => {}
    }
    Ok(())
}

/// Sends one pointer event on this session's socket.
///
/// `false` means it was not taken because the session is cancelling: the caller
/// keeps the hold it was about to record, so nothing is recorded as released
/// that the peer never received.
async fn rfb_send_pointer(
    state: &State,
    session: &mut crate::protocol::rfb::session::RfbSession,
    x: u16,
    y: u16,
    buttons: u8,
) -> Result<bool, ViewerError> {
    tokio::select! {
        biased;
        _ = state.cancel.cancelled() => Ok(false),
        result = session.send_pointer(x, y, buttons) => {
            result.map_err(rfb_error)?;
            Ok(true)
        }
    }
}

/// Sends one key event on this session's socket, with the same not-taken rule as
/// `rfb_send_pointer`.
async fn rfb_send_key(
    state: &State,
    session: &mut crate::protocol::rfb::session::RfbSession,
    keysym: u32,
    down: bool,
) -> Result<bool, ViewerError> {
    tokio::select! {
        biased;
        _ = state.cancel.cancelled() => Ok(false),
        result = session.send_key(keysym, down) => {
            result.map_err(rfb_error)?;
            Ok(true)
        }
    }
}

/// Releases the buttons and keys this RFB writer emitted which the policy in
/// force no longer admits.
///
/// The buttons go out in one pointer event that clears exactly the bits the
/// policy no longer admits, at the position the peer already has, because RFB
/// carries the whole pointer state in every event; the keys follow one at a
/// time, in the order they went down. It runs on the session's own writer, so a
/// release is ordered with the input that preceded it, and it asks the policy
/// for nothing: a release only undoes this writer's own emission.
async fn rfb_release_unadmitted(
    state: &State,
    session: &mut crate::protocol::rfb::session::RfbSession,
    held: &mut RfbHeld,
) -> Result<(), ViewerError> {
    let gate = state.input.read();
    let admitted = Facts::of(state).admits(gate);
    // A hold is released when the policy or the grant in force no longer admits
    // it. Both changes advance the generation, so a hold from before one is
    // released even if admission was granted again in the meantime.
    let stale = |stamped: u64| !admitted || stamped != gate.generation;
    let mut mask = held.mask();
    let mut cleared = 0u64;
    for slot in 0..RFB_BUTTON_BITS.len() {
        if held.buttons[slot].is_some_and(stale) {
            mask &= !RFB_BUTTON_BITS[slot];
            cleared += 1;
        }
    }
    if cleared > 0 {
        if !rfb_send_pointer(state, session, held.pointer.0, held.pointer.1, mask).await? {
            return Ok(());
        }
        for slot in 0..RFB_BUTTON_BITS.len() {
            let Some(stamped) = held.buttons[slot] else {
                continue;
            };
            if !stale(stamped) {
                continue;
            }
            held.buttons[slot] = None;
            state.input.released(stamped);
        }
    }
    let mut index = 0;
    while index < held.keysyms.len() {
        if !stale(held.keysyms[index].0) {
            index += 1;
            continue;
        }
        let keysym = held.keysyms[index].1;
        if !rfb_send_key(state, session, keysym, false).await? {
            return Ok(());
        }
        let (stamped, _) = held.keysyms.remove(index);
        state.input.released(stamped);
    }
    Ok(())
}

/// Drives an RFB session on the shared shell.
///
/// The shell's guarantees are kept exactly as the RustDesk path keeps them:
/// one cancellation token, one snapshot, one surface lease, native creation and
/// teardown on blocking workers. LibVNCClient owns update requests and pacing;
/// this loop only pumps, presents and writes admitted input.
async fn run_rfb(
    state: Arc<State>,
    mut options: ViewerOptions,
    lease: Arc<dyn SurfaceLease>,
    mut input: mpsc::Receiver<QueuedInput>,
    endpoint: crate::protocol::Endpoint,
) -> Result<(), ViewerError> {
    use crate::protocol::rfb::session::{RfbOptions, RfbSession};

    state.phase("connecting");
    let password = std::mem::take(&mut options.password);
    let connecting = RfbSession::connect(
        RfbOptions {
            endpoint,
            password,
            shared: true,
        },
        crate::protocol::rect::PixelLayout::bgra8888(),
    );
    let mut session = tokio::select! {
        biased;
        _ = state.cancel.cancelled() => return Ok(()),
        result = connecting => result.map_err(rfb_error)?,
    };

    rectangle_authenticated(&state, session.desktop());
    // Keep every established-session exit inside this block so even a late
    // surface refusal or cancellation goes through explicit worker close/join.
    let streaming = async {
        let Some(sink) = open_sink(&state, lease, session.desktop()).await? else {
            return Ok(());
        };
        let (sink, outcome) = rfb_loop(&state, sink, &mut session, &mut input).await;
        let sink = sink.ok_or(ViewerError::ReclamationUnconfirmed)?;
        close_sink(&state, sink).await?;
        outcome
    }.await;
    state.input.stopped();
    let closed = session.close().await.map_err(rfb_error);
    finish_rectangle(&state, streaming, closed)
}

fn rectangle_authenticated(state: &State, (width, height): (i32, i32)) {
    state.route("direct_tcp");
    state.desktop_geometry(Geometry { display: 0, x: 0, y: 0, width, height });
    // Both adapters return only after their actual authentication/activation.
    // Neither exposes a later peer input-permission channel.
    if state.protocol != Protocol::Rdp {
        state.input.grant(true);
    }
    state.authenticated.store(true, Ordering::Release);
    state.phase("authenticated");
}

fn finish_rectangle(
    state: &State,
    streaming: Result<(), ViewerError>,
    closed: Result<(), ViewerError>,
) -> Result<(), ViewerError> {
    if state.resources_unconfirmed.load(Ordering::Acquire) {
        return Err(ViewerError::ReclamationUnconfirmed);
    }
    // A close timeout/failure is not hidden by cancellation or an earlier
    // stream failure. Safe Surface reuse is reported separately by State.
    closed.and(streaming)
}

async fn open_sink(
    state: &State,
    lease: Arc<dyn SurfaceLease>,
    (width, height): (i32, i32),
) -> Result<Option<Sink>, ViewerError> {
    // Authentication publishes geometry before the client binds its Surface.
    if !lease.is_ready() {
        state.phase("awaiting_surface");
        let waiting = async {
            while !lease.is_ready() {
                if state.cancel.is_cancelled() {
                    return false;
                }
                tokio::time::sleep(SURFACE_POLL).await;
            }
            true
        };
        match tokio::time::timeout(SURFACE_WAIT, waiting).await {
            Ok(true) => {}
            // Closing while no Surface exists is a stop, not a failure.
            _ if state.cancel.is_cancelled() => return Ok(None),
            _ => return Err(ViewerError::UnsupportedPlatform),
        }
    }
    if state.cancel.is_cancelled() {
        return Ok(None);
    }
    state.phase("opening_surface");
    // Native ownership starts here. The blocking open is joined even when
    // cancellation wins the race, because the surface it returns exists either
    // way: it is closed below instead of being left in a dropped JoinHandle.
    state.resources_unconfirmed.store(true, Ordering::Release);
    let opening = {
        let lease = lease.clone();
        tokio::task::spawn_blocking(move || Sink::open(lease, width, height))
    };
    let sink = match opening.await {
        Ok(Ok(sink)) => sink,
        // `open` releases everything it acquired before it reports a refusal,
        // so a lease or geometry it rejected leaves nothing behind; only the
        // unwind in the arm below leaves native ownership unproven.
        Ok(Err(_)) => {
            state.resources_unconfirmed.store(false, Ordering::Release);
            return Err(ViewerError::UnsupportedPlatform);
        }
        Err(_) => return Err(ViewerError::TaskFailed),
    };
    if state.cancel.is_cancelled() {
        close_sink(state, sink).await?;
        return Ok(None);
    }
    state.phase("streaming");

    Ok(Some(sink))
}

/// Closes one rectangle sink on a blocking worker and records whether the
/// platform confirmed the release.
///
/// `resources_unconfirmed` is what `Viewer::close` reads to decide whether the
/// caller may release its Surface lease, so a created sink clears it only
/// through this call, and only when the close reported success. A refused close
/// and a worker that never returned both leave it set, which `State::finish`
/// reports as `ReclamationUnconfirmed` rather than as a successful close.
async fn close_sink(state: &State, sink: Sink) -> Result<(), ViewerError> {
    match tokio::task::spawn_blocking(move || sink.close()).await {
        Ok(Ok(())) => {
            state.resources_unconfirmed.store(false, Ordering::Release);
            Ok(())
        }
        // A panicked worker dropped the sink without its verdict, which is the
        // same uncertainty as a close that refused.
        Ok(Err(_)) | Err(_) => Err(ViewerError::ReclamationUnconfirmed),
    }
}

async fn present_sink(surface: &mut Option<Sink>) -> Result<(), ViewerError> {
    // Never cancel this worker: it temporarily owns the native sink. A panic
    // leaves None and the owner's reclamation flag remains unconfirmed.
    let mut taken = surface.take().ok_or(ViewerError::TaskFailed)?;
    let returning = tokio::task::spawn_blocking(move || {
        let result = taken.present();
        (taken, result)
    });
    let (returned, presented) = returning.await.map_err(|_| ViewerError::TaskFailed)?;
    *surface = Some(returned);
    presented.map_err(|_| ViewerError::UnsupportedPlatform)
}

async fn rfb_loop(
    state: &State,
    sink: Sink,
    session: &mut crate::protocol::rfb::session::RfbSession,
    input: &mut mpsc::Receiver<QueuedInput>,
) -> (Option<Sink>, Result<(), ViewerError>) {
    // The surface is held in an `Option` so a blocking present can take it and
    // give it back; `None` on return means it could not be recovered.
    let mut surface = Some(sink);
    let mut held = RfbHeld::default();
    let outcome = rfb_stream(state, &mut surface, session, input, &mut held).await;
    // The transport stops with the writer, so nothing it still held can be
    // released through it any more. Those holds are reported as releases whose
    // completion is unconfirmed: whether the peer still holds a key or button is
    // unknown, so no claim is made that a release arrived or that it did not.
    state.input.stopped();
    (surface, outcome)
}

async fn rfb_stream(
    state: &State,
    surface: &mut Option<Sink>,
    session: &mut crate::protocol::rfb::session::RfbSession,
    input: &mut mpsc::Receiver<QueuedInput>,
    held: &mut RfbHeld,
) -> Result<(), ViewerError> {
    use crate::protocol::rfb::session::RfbEvent;
    loop {
        let event = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => return Ok(()),
            // A policy change is handled before anything else on the queue: the
            // release it owes is ordered ahead of the input that would otherwise
            // follow it, and the pass reads the policy it finds rather than
            // replaying the change.
            _ = state.input.changed.notified() => {
                rfb_release_unadmitted(state, session, held).await?;
                continue;
            }
            value = input.recv() => {
                match value {
                    Some(queued) => rfb_input(state, session, held, queued).await?,
                    None => return Ok(()),
                }
                continue;
            }
            event = session.pump(surface.as_mut().ok_or(ViewerError::TaskFailed)?) => {
                event.map_err(rfb_error)?
            },
        };
        match event {
            Some(RfbEvent::Painted) => present_sink(surface).await?,
            Some(RfbEvent::Desktop { width, height }) => {
                state.desktop_geometry(Geometry {
                    display: 0,
                    x: 0,
                    y: 0,
                    width,
                    height,
                });
                // A native Desktop event may include pixels from the same
                // update. Drain that damage now, without requesting again.
                present_sink(surface).await?;
            }
            // A bell and a clipboard announcement carry no pixels.
            Some(RfbEvent::Bell) | Some(RfbEvent::Clipboard(_)) | None => {}
        }
    }
}

/// Maps an RFB failure onto a viewer error.
///
/// The mapping is deliberate: an RFB failure that carries server text (an
/// authentication reason) is reported as a local authentication failure, so a
/// peer cannot put text of its choosing into the UI. The reason itself stays in
/// the RFB layer, where a caller that wants it can ask.
fn rfb_error(error: crate::protocol::rfb::RfbError) -> ViewerError {
    use crate::protocol::rfb::RfbError;
    match error {
        RfbError::AuthenticationFailed(_) => ViewerError::AuthenticationFailed,
        RfbError::PasswordTooLong | RfbError::CredentialUnavailable | RfbError::NoUsableSecurityType => {
            ViewerError::UnsupportedProtocol("RFB authentication is not usable")
        }
        RfbError::BadServerVersion => {
            ViewerError::UnsupportedProtocol("RFB server speaks no supported version")
        }
        RfbError::SecurityRefused(_) => ViewerError::AuthenticationFailed,
        RfbError::Transport => ViewerError::TransportFailed,
        RfbError::Closed => ViewerError::RemoteClosed,
        RfbError::Geometry | RfbError::Sink => ViewerError::InvalidPeerGeometry,
        RfbError::Allocation => ViewerError::UnsupportedPlatform,
        RfbError::Cancelled => ViewerError::Closed,
        RfbError::Protocol(_) => ViewerError::InvalidVideoRecord,
    }
}

// IronRDP FastPathInput::new accepts 1..=255 events. Keep one bounded stack
// batch, not a large allocation per character or an unbounded text expansion.
const RDP_INPUT_EVENTS: usize = u8::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RdpKey {
    Scan(u8, KeyboardFlags),
    Unicode(u16),
}

impl RdpKey {
    fn event(self, down: bool) -> FastPathInputEvent {
        let release = if down { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE };
        match self {
            Self::Scan(code, flags) => FastPathInputEvent::KeyboardEvent(flags | release, code),
            Self::Unicode(code) => FastPathInputEvent::UnicodeKeyboardEvent(release, code),
        }
    }

    fn identity(self) -> u32 {
        match self {
            Self::Scan(code, flags) => 0x8000_0000 | (u32::from(flags.bits()) << 8) | u32::from(code),
            Self::Unicode(code) => u32::from(code),
        }
    }
}

#[derive(Clone, Copy)]
enum RdpHold {
    Key { identity: u32, key: RdpKey },
    Button(u32),
}

impl RdpHold {
    fn identity(self) -> u32 {
        match self {
            Self::Key { identity, .. } => identity,
            Self::Button(button) => 0x4000_0000 | button,
        }
    }

    fn event(self, down: bool, (x, y): (u16, u16)) -> FastPathInputEvent {
        match self {
            Self::Key { key, .. } => key.event(down),
            Self::Button(button) if button >= 8 => FastPathInputEvent::MouseEventEx(MouseXPdu {
                flags: (if button == 8 { PointerXFlags::BUTTON1 } else { PointerXFlags::BUTTON2 })
                    | if down { PointerXFlags::DOWN } else { PointerXFlags::empty() },
                x_position: x, y_position: y,
            }),
            Self::Button(button) => FastPathInputEvent::MouseEvent(MousePdu {
                flags: (match button {
                    1 => PointerFlags::LEFT_BUTTON,
                    2 => PointerFlags::RIGHT_BUTTON,
                    _ => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                }) | if down { PointerFlags::DOWN } else { PointerFlags::empty() },
                number_of_wheel_rotation_units: 0, x_position: x, y_position: y,
            }),
        }
    }
}

#[derive(Clone, Copy)]
struct RdpHeld {
    entries: [(u64, RdpHold); MAX_HELD_INPUTS as usize],
    len: usize,
    pointer: (u16, u16),
    relative: bool,
}

impl Default for RdpHeld {
    fn default() -> Self {
        Self { entries: [(0, RdpHold::Button(0)); MAX_HELD_INPUTS as usize], len: 0, pointer: (0, 0), relative: false }
    }
}

impl RdpHeld {
    fn position(&self, identity: u32) -> Option<usize> {
        self.entries[..self.len].iter().position(|(_, hold)| hold.identity() == identity)
    }

    fn remove(&mut self, index: usize) -> u64 {
        let generation = self.entries[index].0;
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        generation
    }

    fn release_event(&self, index: usize) -> FastPathInputEvent {
        match self.entries[index].1 {
            RdpHold::Button(button) if self.relative => FastPathInputEvent::MouseEventRel(MouseRelPdu {
                // After relative motion the old absolute point is not the
                // server's current pointer. Release in place, without a warp.
                flags: match button {
                    1 => PointerRelFlags::BUTTON1, 2 => PointerRelFlags::BUTTON2,
                    4 => PointerRelFlags::BUTTON3, 8 => PointerRelFlags::XBUTTON1,
                    _ => PointerRelFlags::XBUTTON2,
                },
                x_delta: 0, y_delta: 0,
            }),
            hold => hold.event(false, self.pointer),
        }
    }
}

struct RdpBatch {
    events: [FastPathInputEvent; RDP_INPUT_EVENTS],
    len: usize,
    held: RdpHeld,
    peak: usize,
    generation: u64,
}

impl RdpBatch {
    fn new(held: &RdpHeld, generation: u64) -> Self {
        Self {
            events: [FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), 0); RDP_INPUT_EVENTS],
            len: 0, held: *held, peak: held.len, generation,
        }
    }

    fn push(&mut self, event: FastPathInputEvent) -> Result<(), ViewerError> {
        let slot = self.events.get_mut(self.len).ok_or(ViewerError::InputNotAllowed)?;
        *slot = event;
        self.len += 1;
        Ok(())
    }

    fn transition(&mut self, hold: RdpHold, down: bool) -> Result<(), ViewerError> {
        let existing = self.held.position(hold.identity()).or_else(|| {
            self.held.entries[..self.held.len].iter().position(|(_, previous)| {
                matches!((previous, hold), (RdpHold::Key { key: old, .. }, RdpHold::Key { key: new, .. }) if *old == new)
            })
        });
        // An up/repeat uses the key actually emitted by the down, even when
        // this event's modifier list would choose a different representation.
        let hold = existing.map_or(hold, |index| self.held.entries[index].1);
        self.push(hold.event(down, self.held.pointer))?;
        match (down, existing) {
            (true, None) => {
                let slot = self.held.entries.get_mut(self.held.len).ok_or(ViewerError::Backpressure)?;
                *slot = (self.generation, hold);
                self.held.len += 1;
                self.peak = self.peak.max(self.held.len);
            }
            (false, Some(index)) => { self.held.remove(index); }
            _ => {}
        }
        Ok(())
    }

    fn key(&mut self, identity: u32, key: RdpKey, down: bool) -> Result<(), ViewerError> {
        self.transition(RdpHold::Key { identity, key }, down)
    }
}

fn rdp_scan(code: u8, extended: bool) -> RdpKey {
    RdpKey::Scan(code, if extended { KeyboardFlags::EXTENDED } else { KeyboardFlags::empty() })
}

fn rdp_control(key: proto::ControlKey) -> Result<RdpKey, ViewerError> {
    use proto::ControlKey as C;
    let (code, extended) = match key {
        C::Escape => (0x01, false), C::Backspace => (0x0e, false), C::Tab => (0x0f, false),
        C::Return => (0x1c, false), C::Control => (0x1d, false), C::Shift => (0x2a, false),
        C::RShift => (0x36, false), C::Alt => (0x38, false), C::Space => (0x39, false),
        C::CapsLock => (0x3a, false), C::F1 => (0x3b, false), C::F2 => (0x3c, false),
        C::F3 => (0x3d, false), C::F4 => (0x3e, false), C::F5 => (0x3f, false),
        C::F6 => (0x40, false), C::F7 => (0x41, false), C::F8 => (0x42, false),
        C::F9 => (0x43, false), C::F10 => (0x44, false), C::F11 => (0x57, false),
        C::F12 => (0x58, false), C::NumLock => (0x45, false), C::Scroll => (0x46, false),
        C::Numpad7 => (0x47, false), C::Numpad8 => (0x48, false), C::Numpad9 => (0x49, false),
        C::Numpad4 => (0x4b, false), C::Numpad5 => (0x4c, false), C::Numpad6 => (0x4d, false),
        C::Numpad1 => (0x4f, false), C::Numpad2 => (0x50, false), C::Numpad3 => (0x51, false),
        C::Numpad0 => (0x52, false), C::Decimal => (0x53, false), C::Multiply => (0x37, false),
        C::Subtract => (0x4a, false), C::Add => (0x4e, false), C::Equals => (0x0d, false),
        C::NumpadEnter => (0x1c, true), C::RControl => (0x1d, true), C::Divide => (0x35, true),
        C::Snapshot => (0x37, true), C::RAlt => (0x38, true), C::Home => (0x47, true),
        C::UpArrow => (0x48, true), C::PageUp => (0x49, true), C::LeftArrow => (0x4b, true),
        C::RightArrow => (0x4d, true), C::End => (0x4f, true), C::DownArrow => (0x50, true),
        C::PageDown => (0x51, true), C::Insert => (0x52, true), C::Delete => (0x53, true),
        C::Meta => (0x5b, true), C::RWin => (0x5c, true), C::Apps => (0x5d, true),
        // Pause/IME/system actions require more than an ordinary make/break;
        // refuse them rather than guess an encoding or silently ignore them.
        _ => return Err(ViewerError::InputNotAllowed),
    };
    Ok(rdp_scan(code, extended))
}

/// US scancode set 1, matching the adapter's explicit 0x0409 keyboard layout.
/// This is a boundary key map, not a claim about arbitrary remote layouts.
fn rdp_ascii(character: u32) -> Result<(RdpKey, bool), ViewerError> {
    const ROWS: [(&[u8], &[u8], u8); 4] = [
        (b"1234567890-=", b"!@#$%^&*()_+", 0x02),
        (b"qwertyuiop[]", b"QWERTYUIOP{}", 0x10),
        (b"asdfghjkl;'`", b"ASDFGHJKL:\"~", 0x1e),
        (b"zxcvbnm,./", b"ZXCVBNM<>?", 0x2c),
    ];
    let byte = u8::try_from(character).map_err(|_| ViewerError::InputNotAllowed)?;
    for (plain, shifted, first) in ROWS {
        if let Some(index) = plain.iter().position(|value| *value == byte) {
            return Ok((rdp_scan(first + index as u8, false), false));
        }
        if let Some(index) = shifted.iter().position(|value| *value == byte) {
            return Ok((rdp_scan(first + index as u8, false), true));
        }
    }
    match byte {
        b' ' => Ok((rdp_scan(0x39, false), false)),
        b'\\' | b'|' => Ok((rdp_scan(0x2b, false), byte == b'|')),
        _ => Err(ViewerError::InputNotAllowed),
    }
}

fn rdp_keysym(keysym: u32) -> Result<(u32, RdpKey, bool), ViewerError> {
    use proto::ControlKey as C;
    if (0x20..=0x7e).contains(&keysym) {
        let (key, shift) = rdp_ascii(keysym)?;
        return Ok((keysym, key, shift));
    }
    let key = rdp_control(match keysym {
        0xff08 => C::Backspace, 0xff09 => C::Tab, 0xff0d => C::Return, 0xff1b => C::Escape,
        0xff50 => C::Home, 0xff51 => C::LeftArrow, 0xff52 => C::UpArrow, 0xff53 => C::RightArrow,
        0xff54 => C::DownArrow, 0xff55 => C::PageUp, 0xff56 => C::PageDown, 0xff57 => C::End,
        0xff63 => C::Insert, 0xffff => C::Delete, 0xffe1 => C::Shift, 0xffe2 => C::RShift,
        0xffe3 => C::Control, 0xffe4 => C::RControl, 0xffe5 => C::CapsLock,
        0xffe9 => C::Alt, 0xffea => C::RAlt, 0xffeb => C::Meta, 0xffec => C::RWin,
        0xffbe => C::F1, 0xffbf => C::F2, 0xffc0 => C::F3, 0xffc1 => C::F4,
        0xffc2 => C::F5, 0xffc3 => C::F6, 0xffc4 => C::F7, 0xffc5 => C::F8,
        0xffc6 => C::F9, 0xffc7 => C::F10, 0xffc8 => C::F11, 0xffc9 => C::F12,
        _ => return Err(ViewerError::InputNotAllowed),
    })?;
    Ok((key.identity(), key, false))
}

fn rdp_modifier(key: proto::ControlKey) -> Result<RdpKey, ViewerError> {
    use proto::ControlKey as C;
    match key {
        C::Shift | C::RShift | C::Control | C::RControl | C::Alt | C::RAlt | C::Meta | C::RWin => rdp_control(key),
        _ => Err(ViewerError::InputNotAllowed),
    }
}

/// Whether one legacy event only releases a key instead of creating input.
///
/// A text sequence, a hotkey action and a tap (`press`) all name input that has
/// to reach the peer, so only a plain up is a release.
fn legacy_release(event: &KeyEvent) -> bool {
    use proto::key_event::Union;
    !event.down
        && !event.press
        && matches!(
            &event.union,
            Some(Union::ControlKey(_) | Union::Chr(_) | Union::Unicode(_))
        )
}

/// Every representation the key one legacy release names could have gone down
/// as. A control key has exactly one; a character can be its own Unicode unit
/// and, when it is ASCII, a US scan code — and which of them the peer is
/// holding is the ledger's answer, not this event's, because the modifiers that
/// chose the representation at the down may be gone by the up.
fn legacy_release_keys(event: &KeyEvent) -> [Option<RdpKey>; 2] {
    use proto::key_event::Union;
    let mut keys = [None; 2];
    match &event.union {
        Some(Union::Chr(value) | Union::Unicode(value)) => {
            keys[0] = char::from_u32(*value)
                .filter(|c| !c.is_control())
                .and_then(|c| u16::try_from(c as u32).ok())
                .filter(|unit| *unit != 0)
                .map(RdpKey::Unicode);
            keys[1] = rdp_ascii(*value).ok().map(|(key, _)| key);
        }
        Some(Union::ControlKey(key)) => {
            keys[0] = key.enum_value().ok().and_then(|key| rdp_control(key).ok());
        }
        _ => {}
    }
    keys
}

/// The RDP preflight of one legacy key event at the enqueue boundary.
///
/// A down, a tap and a text sequence are checked exactly as the writer will
/// emit them, so input the peer's declared capabilities cannot carry is refused
/// before it is queued. A release is the one event whose representation the
/// writer may have to take from its ledger instead: an ASCII character with
/// explicit modifiers went down as a US scan code and, without them, derives as
/// Unicode, so judging the up by that derivation alone would strand the key the
/// peer is really holding. It is therefore admitted when the peer carries any
/// representation of that key and refused when it carries none; the writer
/// still validates the batch it actually derived against the capabilities in
/// force before it writes it.
fn rdp_legacy_admission(state: &State, event: &KeyEvent) -> Result<(), ViewerError> {
    // The structural rules the writer applies, at the same boundary: a mode
    // this side does not speak, a modifier it cannot resolve and a key it
    // cannot name never become queued, whatever the event goes on to release.
    if event.mode.enum_value().ok() != Some(proto::KeyboardMode::Legacy) || event.modifiers.len() > 8 {
        return Err(ViewerError::InputNotAllowed);
    }
    for modifier in &event.modifiers {
        rdp_modifier(modifier.enum_value().map_err(|_| ViewerError::InputNotAllowed)?)?;
    }
    if !legacy_release(event) {
        let batch = rdp_legacy(event, &RdpHeld::default())?;
        return rdp_preflight(state, &batch.events[..batch.len]);
    }
    if legacy_release_keys(event)
        .into_iter()
        .flatten()
        .any(|key| rdp_preflight(state, &[key.event(false)]).is_ok())
    {
        return Ok(());
    }
    Err(ViewerError::InputNotAllowed)
}

fn rdp_legacy(event: &KeyEvent, held: &RdpHeld) -> Result<RdpBatch, ViewerError> {
    use proto::key_event::Union;
    if event.mode.enum_value().ok() != Some(proto::KeyboardMode::Legacy) || event.modifiers.len() > 8 {
        return Err(ViewerError::InputNotAllowed);
    }
    let mut batch = RdpBatch::new(held, 0);
    if let Some(Union::Seq(text)) = &event.union {
        if text.is_empty() || !event.modifiers.is_empty() || text.len() > RDP_INPUT_EVENTS * 2 {
            return Err(ViewerError::InputNotAllowed);
        }
        for unit in text.encode_utf16() {
            if unit == 0 { return Err(ViewerError::InputNotAllowed); }
            // Text must stay Unicode even if a physical shortcut key with the
            // same character identity is held. If this Unicode key itself is
            // held, its tap really releases it and the ledger records that.
            let identity = batch.held.entries[..batch.held.len].iter().find_map(|(_, hold)| {
                match hold {
                    RdpHold::Key { identity, key: RdpKey::Unicode(value) } if *value == unit => Some(*identity),
                    _ => None,
                }
            }).unwrap_or(0x2000_0000 | u32::from(unit));
            batch.key(identity, RdpKey::Unicode(unit), true)?;
            batch.key(identity, RdpKey::Unicode(unit), false)?;
        }
        return Ok(batch);
    }
    let (identity, key, shift) = match &event.union {
        Some(Union::ControlKey(key)) => {
            let key = rdp_control(key.enum_value().map_err(|_| ViewerError::InputNotAllowed)?)?;
            (key.identity(), key, false)
        }
        Some(Union::Chr(value)) | Some(Union::Unicode(value)) => {
            let character = char::from_u32(*value).filter(|c| !c.is_control())
                .ok_or(ViewerError::InputNotAllowed)?;
            let unit = u16::try_from(character as u32).map_err(|_| ViewerError::InputNotAllowed)?;
            if event.modifiers.is_empty() {
                (*value, RdpKey::Unicode(unit), false)
            } else if let Ok((key, shift)) = rdp_ascii(*value) {
                (*value, key, shift)
            } else if event.down || event.press {
                // A shortcut is a physical key: a character the US scan map has
                // no code for cannot be pressed as one.
                return Err(ViewerError::InputNotAllowed);
            } else {
                // A release only undoes an emission this writer made, and a
                // character with no scan code can only have gone down as its
                // own Unicode unit.
                (*value, RdpKey::Unicode(unit), false)
            }
        }
        _ => return Err(ViewerError::InputNotAllowed),
    };
    let mut temporary = [None; 9];
    for (index, modifier) in event.modifiers.iter().enumerate() {
        let key = rdp_modifier(modifier.enum_value().map_err(|_| ViewerError::InputNotAllowed)?)?;
        if (event.down || event.press) && key.identity() != identity && batch.held.position(key.identity()).is_none() {
            batch.key(key.identity(), key, true)?;
            temporary[index] = Some(key);
        }
    }
    let shift_key = rdp_scan(0x2a, false);
    if (event.down || event.press) && shift && batch.held.position(shift_key.identity()).is_none()
        && batch.held.position(rdp_scan(0x36, false).identity()).is_none()
    {
        batch.key(shift_key.identity(), shift_key, true)?;
        temporary[8] = Some(shift_key);
    }
    batch.key(identity, key, event.down || event.press)?;
    if event.press { batch.key(identity, key, false)?; }
    for key in temporary.into_iter().rev().flatten() {
        batch.key(key.identity(), key, false)?;
    }
    Ok(batch)
}

fn rdp_mouse(kind: u32, button: u32, x: i32, y: i32, pointer: (u16, u16)) -> Result<RdpBatch, ViewerError> {
    let mut batch = RdpBatch::new(&RdpHeld::default(), 0);
    batch.held.pointer = pointer;
    match kind {
        0..=2 => {
            let px = u16::try_from(x).map_err(|_| ViewerError::InvalidMouse)?;
            let py = u16::try_from(y).map_err(|_| ViewerError::InvalidMouse)?;
            batch.held.pointer = (px, py);
            if kind == 0 && button == 0 {
                batch.push(FastPathInputEvent::MouseEvent(MousePdu {
                    flags: PointerFlags::MOVE, number_of_wheel_rotation_units: 0,
                    x_position: px, y_position: py,
                }))?;
            } else if kind != 0 && matches!(button, 1 | 2 | 4 | 8 | 16) {
                batch.transition(RdpHold::Button(button), kind == 1)?;
            } else { return Err(ViewerError::InvalidMouse); }
        }
        3 | 4 if button == 0 && (x != 0 || y != 0) => {
            // Original wheel units are notches; trackpad units are eighths.
            // RDP uses 120 units/notch with each PDU bounded to [-256,255].
            let scale = if kind == 3 { 120 } else { 15 };
            let horizontal = x.checked_mul(scale).ok_or(ViewerError::InvalidMouse)?;
            let vertical = y.checked_mul(-scale).ok_or(ViewerError::InvalidMouse)?;
            let count = |value: i32| u64::from(value.unsigned_abs()).div_ceil(if value < 0 { 256 } else { 255 });
            if count(horizontal) + count(vertical) > RDP_INPUT_EVENTS as u64 {
                return Err(ViewerError::InvalidMouse);
            }
            for (mut units, flags) in [(horizontal, PointerFlags::HORIZONTAL_WHEEL), (vertical, PointerFlags::VERTICAL_WHEEL)] {
                while units != 0 {
                    let part = units.clamp(-256, 255);
                    batch.push(FastPathInputEvent::MouseEvent(MousePdu {
                        flags, number_of_wheel_rotation_units: part as i16,
                        x_position: pointer.0, y_position: pointer.1,
                    }))?;
                    units -= part;
                }
            }
        }
        5 if button == 0 => {
            batch.push(FastPathInputEvent::MouseEventRel(MouseRelPdu {
                flags: PointerRelFlags::MOVE,
                x_delta: i16::try_from(x).map_err(|_| ViewerError::InvalidMouse)?,
                y_delta: i16::try_from(y).map_err(|_| ViewerError::InvalidMouse)?,
            }))?;
        }
        _ => return Err(ViewerError::InvalidMouse),
    }
    Ok(batch)
}

fn rdp_preflight(state: &State, events: &[FastPathInputEvent]) -> Result<(), ViewerError> {
    let flags = RdpInputFlags::from_bits_retain(state.rdp_input_flags.load(Ordering::Acquire));
    crate::protocol::rdp::validate_input_flags(flags, events).map_err(|_| ViewerError::InputNotAllowed)
}

fn rdp_input_capabilities(state: &State, session: &crate::protocol::rdp::RdpSession) {
    let flags = session.input_flags();
    state.rdp_input_flags.store(flags.bits(), Ordering::Release);
    // Reuse the adapter's actual checks rather than treating the client-side
    // advertised flags as a grant. Unknown/reactivating input retires old holds.
    let keyboard = crate::protocol::rdp::validate_input_flags(flags, &[rdp_scan(0x1e, false).event(true)]).is_ok()
        || crate::protocol::rdp::validate_input_flags(flags, &[RdpKey::Unicode(0x61).event(true)]).is_ok();
    state.input.grant(keyboard);
}

async fn rdp_send(
    state: &State,
    session: &mut crate::protocol::rdp::RdpSession,
    events: &[FastPathInputEvent],
) -> Result<bool, ViewerError> {
    let sent = tokio::select! {
        biased;
        _ = state.cancel.cancelled() => Ok(false),
        result = session.send_input(events) => result.map(|()| true).map_err(rdp_error),
    };
    rdp_input_capabilities(state, session);
    sent
}

async fn rdp_release_unadmitted(
    state: &State,
    session: &mut crate::protocol::rdp::RdpSession,
    held: &mut RdpHeld,
) -> Result<(), ViewerError> {
    rdp_input_capabilities(state, session);
    let gate = state.input.read();
    let admitted = Facts::of(state).admits(gate);
    let mut index = 0;
    while index < held.len {
        let generation = held.entries[index].0;
        if admitted && generation == gate.generation { index += 1; continue; }
        if !rdp_send(state, session, &[held.release_event(index)]).await? { return Ok(()); }
        state.input.released(held.remove(index));
    }
    Ok(())
}

async fn rdp_input(
    state: &State,
    session: &mut crate::protocol::rdp::RdpSession,
    held: &mut RdpHeld,
    queued: QueuedInput,
) -> Result<(), ViewerError> {
    let batch = loop {
        rdp_release_unadmitted(state, session, held).await?;
        let gate = state.input.read();
        if queued.generation != gate.generation || !Facts::of(state).admits(gate) { return Ok(()); }
        let batch = match rdp_batch(held, &queued) {
            Ok(batch) => batch,
            // Like the other writers, never emit a hold the ledger cannot
            // retain. Dynamic hold pressure does not terminate the connection.
            Err(ViewerError::Backpressure) => return Ok(()),
            Err(error) => return Err(error),
        };
        // The peer's capabilities can move between an event's enqueue and this
        // write: a reactivation publishes a new DemandActive. What they no
        // longer carry is dropped here instead of being written as a batch the
        // adapter would refuse, and nothing is held, so nothing is owed.
        if rdp_preflight(state, &batch.events[..batch.len]).is_err() { return Ok(()); }
        let adds = batch.peak - held.len;
        if state.input.own_many(queued.generation, adds as u64, &Facts::of(state)) { break batch; }
        // A revoke/regrant can race the release pass itself. Never adopt a
        // retired hold: settle it and prepare the still-current event again.
        if state.input.read().retired == 0 { return Ok(()); }
    };
    if !rdp_send(state, session, &batch.events[..batch.len]).await? { return Ok(()); }
    // A cancelled/failed write keeps the reservation unconfirmed on stop.
    let released = batch.peak - batch.held.len;
    *held = batch.held;
    for _ in 0..released { state.input.released(queued.generation); }
    Ok(())
}

fn rdp_batch(held: &RdpHeld, queued: &QueuedInput) -> Result<RdpBatch, ViewerError> {
    let mut batch = match &queued.event {
        ViewerInput::RustDeskKey { event } => rdp_legacy(event, held)?,
        ViewerInput::Key { keysym, down } => {
            let (identity, key, shift) = rdp_keysym(*keysym)?;
            let mut batch = RdpBatch::new(held, queued.generation);
            let shift_key = rdp_scan(0x2a, false);
            let temporary_shift = *down && shift && batch.held.position(shift_key.identity()).is_none()
                && batch.held.position(rdp_scan(0x36, false).identity()).is_none();
            if temporary_shift { batch.key(shift_key.identity(), shift_key, true)?; }
            batch.key(identity, key, *down)?;
            if temporary_shift { batch.key(shift_key.identity(), shift_key, false)?; }
            batch
        }
        ViewerInput::Mouse { kind, button, x, y } => {
            let mouse = rdp_mouse(*kind, *button, *x, *y, held.pointer)?;
            let mut batch = RdpBatch::new(held, queued.generation);
            batch.held.pointer = mouse.held.pointer;
            if *kind <= 2 { batch.held.relative = false; }
            if *kind == 5 { batch.held.relative = true; }
            if matches!(*kind, 1 | 2) {
                batch.transition(RdpHold::Button(*button), *kind == 1)?;
            } else {
                for event in &mouse.events[..mouse.len] { batch.push(*event)?; }
            }
            batch
        }
    };
    // Preparation may have used generation zero for synchronous validation;
    // only newly added holds get this event's actual (never refreshed) stamp.
    for (generation, _) in &mut batch.held.entries[..batch.held.len] {
        if *generation == 0 { *generation = queued.generation; }
    }
    Ok(batch)
}

/// Drives the upstream NLA/TLS RDP adapter through the shared rectangle sink.
async fn run_rdp(
    state: Arc<State>,
    mut options: ViewerOptions,
    lease: Arc<dyn SurfaceLease>,
    mut input: mpsc::Receiver<QueuedInput>,
    endpoint: crate::protocol::Endpoint,
) -> Result<(), ViewerError> {
    use crate::protocol::rdp::{RdpOptions, RdpSession, RdpTrust};
    state.phase("connecting");
    let connecting = RdpSession::connect(RdpOptions {
        endpoint,
        password: std::mem::take(&mut options.password).into_bytes(),
        width: 1280,
        height: 720,
        trust: RdpTrust::SystemRoots,
    });
    let mut session = tokio::select! {
        biased;
        _ = state.cancel.cancelled() => return Ok(()),
        result = connecting => result.map_err(rdp_error)?,
    };
    // connect has completed NLA and certificate validation, not merely dialled.
    {
        let mut inner = lock(&state.inner);
        inner.snapshot.encrypted = true;
        inner.snapshot.peer_verified = true;
    }
    rdp_input_capabilities(&state, &session);
    rectangle_authenticated(&state, session.desktop());
    let streaming = async {
        let Some(sink) = open_sink(&state, lease, session.desktop()).await? else {
            return Ok(());
        };
        let mut surface = Some(sink);
        let mut held = RdpHeld::default();
        let outcome = rdp_stream(&state, &mut surface, &mut session, &mut input, &mut held).await;
        let sink = surface.ok_or(ViewerError::ReclamationUnconfirmed)?;
        close_sink(&state, sink).await?;
        outcome
    }.await;
    state.input.stopped();
    // Consume every established session, including cancellation during sink
    // creation/presentation. Its own bounded graceful shutdown drops the socket.
    let closed = session.close().await.map_err(rdp_error);
    finish_rectangle(&state, streaming, closed)
}

async fn rdp_stream(
    state: &State,
    surface: &mut Option<Sink>,
    session: &mut crate::protocol::rdp::RdpSession,
    input: &mut mpsc::Receiver<QueuedInput>,
    held: &mut RdpHeld,
) -> Result<(), ViewerError> {
    use crate::protocol::rdp::RdpEvent;
    loop {
        let event = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => return Ok(()),
            _ = state.input.changed.notified() => {
                rdp_release_unadmitted(state, session, held).await?;
                continue;
            }
            value = input.recv() => {
                match value {
                    Some(queued) => rdp_input(state, session, held, queued).await?,
                    None => return Ok(()),
                }
                continue;
            }
            event = session.pump(surface.as_mut().ok_or(ViewerError::TaskFailed)?) => {
                event
            }
        };
        // A control-only pump can start reactivation and clear confirmed input
        // capabilities before the later Desktop event publishes new geometry.
        rdp_input_capabilities(state, session);
        match event.map_err(rdp_error)? {
            Some(RdpEvent::Painted) => present_sink(surface).await?,
            Some(RdpEvent::Desktop { width, height }) => {
                state.desktop_geometry(Geometry { display: 0, x: 0, y: 0, width, height });
            }
            Some(RdpEvent::Closed) => return Ok(()),
            // Control progress is not EOF; clipboard delivery is not a frame.
            Some(RdpEvent::Clipboard(_)) | None => {}
        }
    }
}

fn rdp_error(error: crate::protocol::rdp::RdpError) -> ViewerError {
    use crate::protocol::rdp::RdpError;
    match error {
        RdpError::MissingUser | RdpError::InvalidCredentials => ViewerError::InvalidOptions,
        RdpError::Authentication => ViewerError::AuthenticationFailed,
        RdpError::Geometry(_) => ViewerError::InvalidPeerGeometry,
        other => ViewerError::Rdp(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMMANDS, DIRECT_ACCESS_PORT, Facts, GateView, Inner, InputGate, MAX_HELD_INPUTS, Protocol,
        QueuedInput, RustDeskHeld, State, Viewer, ViewerError, ViewerInput, ViewerInputPolicy,
        ViewerSnapshot, WireReader, WireWriter, direct_address, take_input,
    };
    use crate::transport;
    use base::message_proto::{ControlKey, KeyEvent, Message, message};
    use hbb_common::tcp::FramedStream;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex, atomic::AtomicBool},
        time::Duration,
    };
    use tokio::sync::{Notify, mpsc};
    use tokio_util::sync::CancellationToken;

    /// How long a step that expects one message on the test wire waits for it.
    const RECEIVE_LIMIT: Duration = Duration::from_secs(5);

    /// A viewer that is authorized on a wire. The peer's grant is the gate's
    /// own fact and is published there, not here.
    fn facts(protocol: Protocol, proven: bool) -> Facts {
        Facts {
            protocol,
            authenticated: true,
            proven,
            closed: false,
        }
    }

    /// What a gate publishes, for a decision a test makes without a viewer.
    fn view(policy: ViewerInputPolicy, keyboard: bool) -> GateView {
        GateView {
            policy,
            keyboard,
            generation: 1,
            owed: 0,
            retired: 0,
            unreleased: 0,
        }
    }

    /// What the viewer still owes, read the way a caller reads it: a policy
    /// change that changes nothing.
    fn owed(gate: &InputGate, facts: &Facts) -> u64 {
        gate.set(gate.policy(), facts).releases_owed
    }

    /// A gate the peer has granted the keyboard on, which is where every viewer
    /// that can send input starts.
    fn granted(policy: ViewerInputPolicy) -> InputGate {
        let gate = InputGate::new(policy);
        gate.grant(true);
        gate
    }

    /// A viewer's input state with no session behind it: only the facts an
    /// admission decision reads are set, so one writer step can be driven at a
    /// time.
    fn writer_state() -> Arc<State> {
        Arc::new(State {
            inner: Mutex::new(Inner {
                snapshot: ViewerSnapshot::default(),
                geometry: None,
                decoder: None,
                observed_peer_close_reason: None,
            }),
            cancel: CancellationToken::new(),
            done: Notify::new(),
            result: Mutex::new(None),
            protocol: Protocol::RustDesk,
            authenticated: AtomicBool::new(true),
            rdp_input_flags: super::AtomicU16::new(0),
            peer_proven: AtomicBool::new(true),
            input: InputGate::new(ViewerInputPolicy::interactive()),
            resources_unconfirmed: AtomicBool::new(false),
            control: Mutex::new(None),
        })
    }

    /// One queued event, stamped the way the enqueue boundary stamps it: with
    /// the generation the gate is at now.
    fn queued(state: &State, event: ViewerInput) -> QueuedInput {
        QueuedInput {
            event,
            generation: state.input.read().generation,
        }
    }

    /// The enqueue boundary of one viewer, with no session behind it: the real
    /// `Viewer` methods over the state a writer step is driven with, so a test
    /// asserts both what a caller is answered and what was actually queued.
    fn writer_viewer() -> (Arc<Viewer>, mpsc::Receiver<QueuedInput>) {
        let state = writer_state();
        state.input.grant(true);
        let (mouse, queue) = mpsc::channel(COMMANDS);
        (Arc::new(Viewer { state, mouse }), queue)
    }

    /// One written wire and its peer, with every half of the client's own
    /// transport kept alive.
    ///
    /// That is not tidiness: a reader and a writer split from one stream share
    /// one cancellation token, so dropping the half a test does not read would
    /// cancel the half it drives, and the first write would fail as a closed
    /// transport.
    struct Wire {
        writer: WireWriter,
        peer: WireReader,
        _client_reader: WireReader,
        _peer_writer: WireWriter,
    }

    /// One writer and the peer's end of one in-memory wire.
    ///
    /// The peer reads through the transport's own receiver, so a test asserts
    /// what the peer received rather than what a call returned.
    fn writer_wire() -> Wire {
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (local, peer) = tokio::io::duplex(4096);
        let (client_reader, writer) = transport::split(FramedStream::from(local, address));
        let (peer_reader, peer_writer) = transport::split(FramedStream::from(peer, address));
        Wire {
            writer,
            peer: peer_reader,
            _client_reader: client_reader,
            _peer_writer: peer_writer,
        }
    }

    /// The next message the peer received on that wire.
    ///
    /// The wait is bounded, so a writer that emitted nothing where this step
    /// expects an event fails the test instead of hanging it.
    async fn received(peer: &mut WireReader) -> Message {
        tokio::time::timeout(RECEIVE_LIMIT, peer.recv())
            .await
            .expect("the writer emitted the message this step expects")
            .expect("the peer's end stays open")
            .expect("the writer emitted a well-formed message")
    }

    /// The key state one message the peer received carries.
    fn key_state(message: Message) -> bool {
        match message.union {
            Some(message::Union::KeyEvent(event)) => event.down,
            other => panic!("expected a key event, got {other:?}"),
        }
    }

    /// The pointer state one message the peer received carries: the buttons it
    /// holds and where it put the pointer.
    fn pointer(message: Message) -> (u32, i32, i32) {
        match message.union {
            Some(message::Union::MouseEvent(event)) => (event.mask as u32, event.x, event.y),
            other => panic!("expected a mouse event, got {other:?}"),
        }
    }

    #[test]
    fn rdp_legacy_shortcuts_emit_scancodes_and_do_not_release_an_existing_modifier() {
        use super::{RdpHeld, FastPathInputEvent as E, KeyboardFlags as F, rdp_legacy};
        let mut control = control_key_event(true);
        let held = rdp_legacy(&control, &RdpHeld::default()).unwrap().held;
        let mut shortcut = KeyEvent::new();
        shortcut.set_chr(u32::from(b'a'));
        shortcut.press = true;
        shortcut.modifiers.push(ControlKey::Control.into());
        let batch = rdp_legacy(&shortcut, &held).unwrap();
        assert_eq!(&batch.events[..batch.len], &[
            E::KeyboardEvent(F::empty(), 0x1e),
            E::KeyboardEvent(F::RELEASE, 0x1e),
        ]);
        // The modifier belongs to the earlier down, not to the shortcut tap.
        control.down = false;
        let release = rdp_legacy(&control, &batch.held).unwrap();
        assert_eq!(&release.events[..release.len], &[E::KeyboardEvent(F::RELEASE, 0x1d)]);
        let complete = rdp_legacy(&shortcut, &RdpHeld::default()).unwrap();
        assert_eq!(&complete.events[..complete.len], &[
            E::KeyboardEvent(F::empty(), 0x1d), E::KeyboardEvent(F::empty(), 0x1e),
            E::KeyboardEvent(F::RELEASE, 0x1e), E::KeyboardEvent(F::RELEASE, 0x1d),
        ]);
    }

    #[test]
    fn rdp_uppercase_shortcuts_and_changed_modifier_ups_preserve_the_downs_key() {
        use super::{RdpHeld, FastPathInputEvent as E, KeyboardFlags as F, rdp_legacy};
        let mut key = KeyEvent::new();
        key.set_chr(u32::from(b'A'));
        key.down = true;
        key.modifiers.push(ControlKey::Control.into());
        let down = rdp_legacy(&key, &RdpHeld::default()).unwrap();
        assert_eq!(&down.events[..down.len], &[
            E::KeyboardEvent(F::empty(), 0x1d), E::KeyboardEvent(F::empty(), 0x2a),
            E::KeyboardEvent(F::empty(), 0x1e), E::KeyboardEvent(F::RELEASE, 0x2a),
            E::KeyboardEvent(F::RELEASE, 0x1d),
        ]);
        key.down = false;
        key.modifiers.clear();
        let up = rdp_legacy(&key, &down.held).unwrap();
        assert_eq!(&up.events[..up.len], &[E::KeyboardEvent(F::RELEASE, 0x1e)]);
    }

    #[test]
    fn rdp_text_is_unicode_and_batches_stop_at_the_upstream_event_limit() {
        use super::{RdpHeld, FastPathInputEvent as E, KeyboardFlags as F, rdp_legacy};
        let mut key = KeyEvent::new();
        key.set_seq("中".into());
        let batch = rdp_legacy(&key, &RdpHeld::default()).unwrap();
        assert_eq!(&batch.events[..batch.len], &[
            E::UnicodeKeyboardEvent(F::empty(), 0x4e2d),
            E::UnicodeKeyboardEvent(F::RELEASE, 0x4e2d),
        ]);
        key.set_seq("a".repeat(127));
        let batch = rdp_legacy(&key, &RdpHeld::default()).unwrap();
        assert_eq!(batch.len, 254);
        key.set_seq("a".repeat(128));
        assert!(matches!(rdp_legacy(&key, &RdpHeld::default()), Err(ViewerError::InputNotAllowed)));
    }

    #[test]
    fn rdp_relative_pointer_survives_the_upstream_fastpath_encoder() {
        use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
        let mut batch = super::rdp_mouse(5, 0, -17, 23, (10, 20)).unwrap();
        let key = FastPathInputEvent::KeyboardEvent(super::KeyboardFlags::empty(), 0x1e);
        batch.push(key).unwrap();
        let input = FastPathInput::new(batch.events[..batch.len].to_vec()).unwrap();
        let bytes = ironrdp_core::encode_vec(&input).unwrap();
        let decoded: FastPathInput = ironrdp_core::decode(&bytes).unwrap();
        assert_eq!(decoded.input_events(), &[
            FastPathInputEvent::MouseEventRel(super::MouseRelPdu {
                flags: super::PointerRelFlags::MOVE, x_delta: -17, y_delta: 23,
            }),
            key,
        ]);
    }

    #[test]
    fn rdp_revocation_after_relative_motion_releases_without_warping_the_pointer() {
        let down = super::rdp_batch(&super::RdpHeld::default(), &QueuedInput {
            event: ViewerInput::Mouse { kind: 1, button: 1, x: 10, y: 20 }, generation: 3,
        }).unwrap();
        let moved = super::rdp_batch(&down.held, &QueuedInput {
            event: ViewerInput::Mouse { kind: 5, button: 0, x: -7, y: 9 }, generation: 3,
        }).unwrap();
        assert_eq!(moved.held.release_event(0), super::FastPathInputEvent::MouseEventRel(super::MouseRelPdu {
            flags: super::PointerRelFlags::BUTTON1, x_delta: 0, y_delta: 0,
        }));
    }

    #[test]
    fn rdp_wheel_units_preserve_both_axes_without_overflow_or_truncation() {
        use super::{FastPathInputEvent, PointerFlags};
        let batch = super::rdp_mouse(3, 0, 3, -3, (10, 20)).unwrap();
        let mut horizontal = 0;
        let mut vertical = 0;
        for event in &batch.events[..batch.len] {
            let FastPathInputEvent::MouseEvent(event) = event else { panic!("wheel event"); };
            assert!((-256..=255).contains(&event.number_of_wheel_rotation_units));
            if event.flags.contains(PointerFlags::HORIZONTAL_WHEEL) {
                horizontal += i32::from(event.number_of_wheel_rotation_units);
            } else {
                assert!(event.flags.contains(PointerFlags::VERTICAL_WHEEL));
                vertical += i32::from(event.number_of_wheel_rotation_units);
            }
        }
        assert_eq!((horizontal, vertical), (360, 360));
        assert!(matches!(super::rdp_mouse(3, 0, i32::MAX, 0, (0, 0)), Err(ViewerError::InvalidMouse)));
    }

    /// A peer that carries scan codes but not Unicode still releases the key
    /// its own shortcut went down as: the up is derived as Unicode, the ledger
    /// holds the scan code, and the enqueue check admits a representation the
    /// peer has rather than the one this event alone names.
    #[test]
    fn rdp_scan_code_shortcut_releases_when_only_scan_codes_are_carried() {
        use super::{
            FastPathInputEvent as E, KeyboardFlags as F, RdpHeld, RdpInputFlags, rdp_legacy,
            rdp_legacy_admission,
        };
        let mut state = writer_state();
        Arc::get_mut(&mut state).unwrap().protocol = Protocol::Rdp;
        let scan_codes = RdpInputFlags::FASTPATH_INPUT | RdpInputFlags::SCANCODES;
        state.rdp_input_flags.store(scan_codes.bits(), super::Ordering::Release);

        let mut down = KeyEvent::new();
        down.set_chr(u32::from(b'a'));
        down.down = true;
        down.modifiers.push(ControlKey::Control.into());
        assert!(rdp_legacy_admission(&state, &down).is_ok());
        let held = rdp_legacy(&down, &RdpHeld::default()).unwrap().held;

        let mut up = KeyEvent::new();
        up.set_chr(u32::from(b'a'));
        assert!(
            rdp_legacy_admission(&state, &up).is_ok(),
            "the up of a scan-code hold is admitted even though it derives as Unicode"
        );
        let released = rdp_legacy(&up, &held).unwrap();
        assert_eq!(
            &released.events[..released.len],
            &[E::KeyboardEvent(F::RELEASE, 0x1e)],
            "the wire carries the release of the scan code the peer actually holds"
        );
        assert_eq!(released.held.len, 0, "the released hold leaves the ledger");

        // New input the peer cannot carry is still refused before it is queued,
        // and a peer with neither representation refuses even a release.
        let mut text = KeyEvent::new();
        text.set_seq("text".into());
        assert!(matches!(
            rdp_legacy_admission(&state, &text),
            Err(ViewerError::InputNotAllowed)
        ));
        state.rdp_input_flags.store(RdpInputFlags::FASTPATH_INPUT.bits(), super::Ordering::Release);
        assert!(matches!(
            rdp_legacy_admission(&state, &up),
            Err(ViewerError::InputNotAllowed)
        ));
        assert!(matches!(
            rdp_legacy_admission(&state, &control_key_event(false)),
            Err(ViewerError::InputNotAllowed)
        ));
    }

    #[test]
    fn rdp_refuses_unsupported_input_and_stale_generations_at_enqueue() {
        let mut state = writer_state();
        Arc::get_mut(&mut state).unwrap().protocol = Protocol::Rdp;
        state.input.grant(true);
        let (mouse, _queue) = mpsc::channel(COMMANDS);
        let viewer = Viewer { state, mouse };
        let generation = viewer.input_generation();
        // Authentication alone cannot prove the server's optional input modes.
        assert!(matches!(viewer.send_key(0xffe3, true, generation), Err(ViewerError::InputNotAllowed)));
        let flags = super::RdpInputFlags::FASTPATH_INPUT | super::RdpInputFlags::SCANCODES;
        viewer.state.rdp_input_flags.store(flags.bits(), super::Ordering::Release);
        assert!(matches!(viewer.send_mouse(5, 0, 1, -1, generation), Err(ViewerError::InputNotAllowed)));
        let mut unicode = KeyEvent::new();
        unicode.set_seq("text".into());
        assert!(matches!(viewer.send_rustdesk_key(unicode, generation), Err(ViewerError::InputNotAllowed)));
        viewer.state.rdp_input_flags.store((flags | super::RdpInputFlags::MOUSE_RELATIVE).bits(), super::Ordering::Release);
        assert_eq!(viewer.send_mouse(5, 0, 1, -1, generation).unwrap(), generation);
        // A new input the peer cannot carry is refused: with scan codes only,
        // this character has no physical key to press.
        let mut key = KeyEvent::new();
        key.set_chr('中' as u32);
        key.down = true;
        key.modifiers.push(ControlKey::Control.into());
        assert!(matches!(viewer.send_rustdesk_key(key, generation), Err(ViewerError::InputNotAllowed)));
        assert!(matches!(viewer.send_key(0x1008ff12, true, generation), Err(ViewerError::InputNotAllowed)));
        viewer.set_input_policy(ViewerInputPolicy::read_only());
        let current = viewer.set_input_policy(ViewerInputPolicy::interactive()).input_generation;
        assert!(matches!(viewer.send_key(0xffe3, false, generation), Err(ViewerError::StaleInputGeneration)));
        assert!(matches!(viewer.send_rustdesk_key(control_key_event(false), generation), Err(ViewerError::StaleInputGeneration)));
        assert_eq!(viewer.send_key(0xffe3, true, current).unwrap(), current);
    }

    #[test]
    fn rdp_cannot_adopt_a_retired_hold_when_regrant_races_the_release_pass() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Rdp, false);
        let old = gate.read().generation;
        assert!(gate.own_many(old, 1, &facts));
        // The writer could have read its release-pass gate just before this.
        gate.set(ViewerInputPolicy::read_only(), &facts);
        let new = gate.set(ViewerInputPolicy::interactive(), &facts).input_generation;
        assert!(!gate.own_many(new, 0, &facts), "same-key repeat cannot adopt an old hold");
        gate.released(old);
        assert!(gate.own_many(new, 1, &facts));
        assert!(!gate.own_many(old, 0, &facts));
    }

    #[test]
    fn direct_address_uses_the_standard_port_for_bare_ips() {
        assert_eq!(
            direct_address("192.168.108.155"),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 108, 155)),
                DIRECT_ACCESS_PORT,
            )),
        );
        assert_eq!(
            direct_address("::1"),
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                DIRECT_ACCESS_PORT
            )),
        );
    }

    #[test]
    fn direct_address_preserves_explicit_ports_and_rejects_non_addresses() {
        assert_eq!(
            direct_address("192.168.108.155:24444"),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 108, 155)),
                24444,
            )),
        );
        assert_eq!(direct_address("192.168.108.155:0"), None);
        assert_eq!(direct_address("peer-id"), None);
    }

    /// One key event on the original wire, down or up, for the same key.
    fn control_key(down: bool) -> ViewerInput {
        ViewerInput::RustDeskKey {
            event: control_key_event(down),
        }
    }

    /// The same key event as the wire message it is.
    fn control_key_event(down: bool) -> KeyEvent {
        let mut event = KeyEvent::new();
        event.set_control_key(ControlKey::Control);
        event.down = down;
        event
    }

    #[test]
    fn an_unproven_rustdesk_peer_admits_nothing_until_this_viewer_accepts_it() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::RustDesk, false);
        let start = gate.read();
        assert!(
            !facts.admits(start),
            "a wire the handshake did not encrypt and verify admits nothing on its own"
        );
        assert!(
            !gate.own(start.generation, true, &facts),
            "the writer drops what the gate refuses"
        );

        // The operator's answer is this session's own state. It opens input for
        // this viewer, and it says nothing about a later one.
        let accepted = gate.set(
            ViewerInputPolicy {
                view_only: false,
                unverified_accepted: true,
            },
            &facts,
        );
        assert!(accepted.policy.unverified_accepted);
        assert!(
            !accepted.revoked,
            "an acceptance that opens input revokes nothing"
        );
        assert!(
            !gate.own(start.generation, true, &facts),
            "the event queued under the previous policy is still dropped"
        );
        let current = gate.read();
        assert!(
            current.generation > start.generation,
            "a policy change advances the generation"
        );
        assert_eq!(
            accepted.input_generation, current.generation,
            "the answer names the generation the change published"
        );
        assert!(
            gate.own(current.generation, true, &facts),
            "an event admitted under this session's acceptance is emitted"
        );
    }

    #[test]
    fn view_only_admits_no_input_on_either_wire() {
        let read_only = ViewerInputPolicy::read_only();
        assert!(
            !facts(Protocol::Vnc, false).admits(view(read_only, true)),
            "RFB input is refused too"
        );
        assert!(
            !facts(Protocol::RustDesk, true).admits(view(read_only, true)),
            "a peer the handshake proved does not outrank the read-only switch"
        );
        let gate = granted(read_only);
        let current = gate.read();
        assert_eq!(current.policy, read_only);
        assert!(
            !gate.own(current.generation, true, &facts(Protocol::Vnc, false)),
            "a viewer started read-only emits nothing"
        );
    }

    #[test]
    fn rfb_input_is_admitted_without_peer_evidence() {
        // RFB carries no identity evidence, and this viewer does not invent a
        // question for it: an authenticated session with the peer's grant admits
        // input exactly as it did before the policy existed.
        assert!(
            facts(Protocol::Vnc, false).admits(view(ViewerInputPolicy::interactive(), true)),
            "VNC input is not gated on evidence its wire cannot carry"
        );
    }

    #[test]
    fn a_hold_the_writer_could_not_remember_is_refused_rather_than_emitted() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        for _ in 0..MAX_HELD_INPUTS {
            assert!(gate.own(generation, true, &facts));
        }
        assert!(
            !gate.own(generation, true, &facts),
            "the ledger's bound refuses one hold too many"
        );
        gate.released(generation);
        assert!(
            gate.own(generation, true, &facts),
            "a released hold is available again"
        );
    }

    #[test]
    fn only_what_the_writer_emitted_becomes_a_hold_it_can_release() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        let mut held = RustDeskHeld::default();

        // Admitted and queued is not yet held: the writer takes the hold before
        // the wire, and records it as one it owns.
        assert!(held.adds(&control_key(true)));
        assert!(gate.own(generation, held.adds(&control_key(true)), &facts));
        assert_eq!(owed(&gate, &facts), 1, "the gate owns the hold it admitted");
        assert_eq!(held.record(&control_key(true), generation), None);

        // The peer's key is one key, so a repeat of the same down is one hold.
        assert!(!held.adds(&control_key(true)));
        assert_eq!(held.record(&control_key(true), generation), None);
        assert_eq!(owed(&gate, &facts), 1);

        // Its release is what drops the hold, and it drops it once — reporting
        // the stamp the hold carried, so the gate can tell a hold the operator
        // let go from one a change retired.
        assert_eq!(
            held.record(&control_key(false), generation),
            Some(generation)
        );
        gate.released(generation);
        assert_eq!(owed(&gate, &facts), 0);
        assert_eq!(
            held.record(&control_key(false), generation),
            None,
            "a release for a key this writer never held releases nothing"
        );

        // A button is the same: the down holds it, the up that follows releases
        // it, and an up with no hold releases nothing.
        let down = ViewerInput::Mouse {
            kind: 1,
            button: 0x01,
            x: 4,
            y: 3,
        };
        let up = ViewerInput::Mouse {
            kind: 2,
            button: 0x01,
            x: 4,
            y: 3,
        };
        assert!(held.adds(&down));
        assert!(gate.own(generation, held.adds(&down), &facts));
        assert_eq!(held.record(&down, generation), None);
        assert_eq!(owed(&gate, &facts), 1);
        assert!(!held.adds(&down), "a button already held takes nothing");
        assert_eq!(held.record(&up, generation), Some(generation));
        gate.released(generation);
        assert_eq!(owed(&gate, &facts), 0);
        assert_eq!(held.record(&up, generation), None);
    }

    #[test]
    fn a_writer_that_stopped_reports_its_holds_as_unreleased_not_as_released() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        assert!(gate.own(generation, true, &facts));

        let revoked = gate.set(ViewerInputPolicy::read_only(), &facts);
        assert!(revoked.revoked, "read-only revokes the admission it had");
        assert_eq!(revoked.releases_owed, 1, "the release is still owed");
        assert_eq!(
            revoked.releases_retired, 1,
            "the change retired the hold, so its release is now pending"
        );
        assert!(
            !revoked.released(),
            "an owed release is not a completed one"
        );

        // The writer stopped before it made that release.
        gate.stopped();
        let after = gate.set(gate.policy(), &facts);
        assert_eq!(after.releases_owed, 0);
        assert_eq!(
            after.releases_retired, 0,
            "a writer that stopped has no release on its way"
        );
        assert_eq!(
            after.releases_unreleased, 1,
            "a release whose writer stopped is reported as unconfirmed, never as a completed one"
        );
        assert!(!after.released());
    }

    #[test]
    fn only_a_hold_a_change_retired_is_reported_as_a_release_on_its_way() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        assert!(gate.own(generation, true, &facts));

        // A key the operator is holding is not a release the engine owes: the
        // policy in force still admits it.
        let holding = gate.set(gate.policy(), &facts);
        assert_eq!(holding.releases_owed, 1, "the writer owns the hold");
        assert_eq!(
            holding.releases_retired, 0,
            "nothing was retired, so no release is pending"
        );

        // The change that stops admitting it is what makes the release pending.
        let revoked = gate.set(ViewerInputPolicy::read_only(), &facts);
        assert_eq!(revoked.releases_owed, 1);
        assert_eq!(revoked.releases_retired, 1);

        // Releasing the hold the change retired settles the pending release,
        // and the hold's own stamp is what says so.
        gate.released(generation);
        let settled = gate.set(gate.policy(), &facts);
        assert_eq!(settled.releases_owed, 0);
        assert_eq!(settled.releases_retired, 0);
    }

    #[test]
    fn a_peer_grant_change_moves_the_generation_in_both_directions() {
        let gate = InputGate::new(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::RustDesk, true);
        let withheld = gate.read();
        assert!(
            !facts.admits(withheld),
            "nothing is admitted before the peer grants the keyboard"
        );

        gate.grant(true);
        let given = gate.read();
        assert!(facts.admits(given), "the peer's grant admits input");
        assert!(
            !gate.own(withheld.generation, true, &facts),
            "input queued before the grant is not admitted by it"
        );
        gate.grant(true);
        assert_eq!(
            gate.read().generation,
            given.generation,
            "a grant already in force changes nothing"
        );

        // Withdrawn and granted again: input is admitted, and the generation
        // says so, because what was queued or emitted under the old grant is
        // still invalid.
        gate.grant(false);
        let withdrawn = gate.read();
        assert!(!facts.admits(withdrawn));
        gate.grant(true);
        let regranted = gate.read();
        assert!(facts.admits(regranted), "input is admitted again");
        assert!(
            regranted.generation > withdrawn.generation,
            "the grant that follows a withdrawal is a change of its own"
        );
        assert!(
            !gate.own(withdrawn.generation, true, &facts),
            "an event queued across the withdrawal is not replayed by the grant that followed it"
        );
    }

    /// A peer that withdraws and re-grants the keyboard while this writer is
    /// between events must not leave the key it emitted standing.
    ///
    /// The writer's own path is driven directly here, with a real wire on the
    /// other end and no select loop to schedule: the order asserted is the
    /// writer's own, and not a product of when a wake-up happened to be polled.
    #[tokio::test]
    async fn a_peer_grant_change_releases_old_holds_before_fresh_same_key_input() {
        let state = writer_state();
        state.input.grant(true);
        let mut wire = writer_wire();
        let mut held = RustDeskHeld::default();

        // The peer granted the keyboard, and this writer emitted a key down it
        // now holds.
        take_input(
            &state,
            &mut wire.writer,
            &mut held,
            queued(&state, control_key(true)),
        )
        .await
        .expect("the writer takes the event the grant admits");
        assert!(
            key_state(received(&mut wire.peer).await),
            "the down reached the peer"
        );

        // The peer withdraws the grant and grants it again, and a fresh down for
        // the same key is queued under the grant in force now.
        state.input.grant(false);
        state.input.grant(true);
        take_input(
            &state,
            &mut wire.writer,
            &mut held,
            queued(&state, control_key(true)),
        )
        .await
        .expect("the writer takes the event the new grant admits");

        // In order: the hold the withdrawal ended is released, and only then is
        // the fresh down emitted. An old hold adopted by the event that follows
        // it would leave the peer's key down with no release behind it.
        assert!(
            !key_state(received(&mut wire.peer).await),
            "the hold from before the change is released first"
        );
        assert!(
            key_state(received(&mut wire.peer).await),
            "and the fresh down follows the release"
        );
    }

    /// Input queued under a grant the peer withdrew is never replayed by the
    /// grant that follows it.
    #[tokio::test]
    async fn input_queued_across_a_peer_grant_change_is_not_replayed() {
        let state = writer_state();
        state.input.grant(true);
        let mut wire = writer_wire();
        let mut held = RustDeskHeld::default();

        // Queued while the peer granted the keyboard, and reached by the writer
        // only after the grant was withdrawn and given again.
        let stale = queued(
            &state,
            ViewerInput::Mouse {
                kind: 0,
                button: 0,
                x: 3,
                y: 4,
            },
        );
        state.input.grant(false);
        state.input.grant(true);
        take_input(&state, &mut wire.writer, &mut held, stale)
            .await
            .expect("a dropped event is not a writer failure");

        let fresh = queued(
            &state,
            ViewerInput::Mouse {
                kind: 0,
                button: 0,
                x: 5,
                y: 6,
            },
        );
        take_input(&state, &mut wire.writer, &mut held, fresh)
            .await
            .expect("the writer takes the event the new grant admits");

        // The first thing the peer receives is the event queued under the grant
        // in force, so the one queued across the change never reached it.
        let (_, x, y) = pointer(received(&mut wire.peer).await);
        assert_eq!(
            (x, y),
            (5, 6),
            "the event queued under the withdrawn grant was not replayed"
        );
    }

    /// The enqueue boundary answers with the generation it stamped, and the
    /// answer is a receipt a caller can act on: the event queued behind it
    /// carries exactly that generation.
    #[test]
    fn a_queued_event_is_answered_with_the_generation_that_stamps_it() {
        let (viewer, mut queue) = writer_viewer();
        let admitted = viewer.snapshot().input_generation;
        assert!(
            admitted > 0,
            "a started viewer reports the generation its admission belongs to"
        );

        let receipt = viewer
            .send_mouse(3, 0, 0, 1, admitted)
            .expect("the generation in force is admitted");
        assert_eq!(
            receipt, admitted,
            "the answer is the stamp the queued event carries"
        );
        let keyed = viewer
            .send_rustdesk_key(control_key_event(true), receipt)
            .expect("the event named with that receipt's generation is admitted");
        assert_eq!(
            keyed, receipt,
            "a receipt is a generation a caller may name"
        );

        let pointer = queue.try_recv().expect("the pointer event was queued");
        assert_eq!(pointer.generation, admitted);
        let key = queue.try_recv().expect("the key event was queued");
        assert_eq!(key.generation, admitted);
    }

    /// A generation a boundary change has left behind is refused at the enqueue
    /// boundary: it is never restamped under the generation in force, and a
    /// refused event queues nothing.
    #[test]
    fn a_stale_generation_is_refused_rather_than_restamped() {
        let (viewer, mut queue) = writer_viewer();
        let first = viewer.snapshot().input_generation;

        // A revocation refuses first, because the policy in force is what stops
        // this event before its generation is even compared.
        let revoked = viewer.set_input_policy(ViewerInputPolicy::read_only());
        assert!(revoked.revoked, "read-only stops admitting input");
        assert!(matches!(
            viewer.send_rustdesk_key(control_key_event(true), first),
            Err(ViewerError::InputNotAllowed)
        ));

        // Admitted again: the generation the caller named is gone, so the event
        // is refused instead of being emitted under the new one.
        let regranted = viewer.set_input_policy(ViewerInputPolicy::interactive());
        assert!(
            regranted.input_generation > first,
            "the boundary moved while the caller was acting on the old one"
        );
        assert!(matches!(
            viewer.send_rustdesk_key(control_key_event(true), first),
            Err(ViewerError::StaleInputGeneration)
        ));
        assert!(matches!(
            viewer.send_mouse(3, 0, 0, 1, first),
            Err(ViewerError::StaleInputGeneration)
        ));
        assert!(
            queue.try_recv().is_err(),
            "a refused event queues nothing for the peer"
        );

        // The generation the boundary published now is admitted, and its receipt
        // is that generation — never the stale one the caller started with.
        let receipt = viewer
            .send_rustdesk_key(control_key_event(true), regranted.input_generation)
            .expect("the generation in force is admitted");
        assert_eq!(receipt, regranted.input_generation);
        let event = queue.try_recv().expect("the admitted event was queued");
        assert_eq!(event.generation, regranted.input_generation);
    }
}
