//! First original-peer direct TCP viewer. No legacy Connection/VideoHandler.
//! Surface ownership comes from the trusted HAR, not a retained numeric ID.
//! RX, one writer, and one ordered video feeder are independent persistent tasks.
//! SDK creation/destruction run on blocking workers; compressed admission waits
//! are cancellation-aware notifications, never sleep retries or frame tasks.
//! A native consumer is joined even when cancellation wins its creation, and a
//! reclamation that cannot be confirmed fails `Viewer::close` rather than only
//! appearing as a session error.
//!
//! Audio is one optional worker on that same reader: the peer's format and
//! frames are handed to a shared, bounded audio owner and never decoded, copied
//! or awaited here. Its device failures stay its own, and its own reclamation
//! fact is reported separately from the video pipeline's.

mod auth;
mod cursor;
pub use cursor::{CursorImage, CursorSnapshot};
use auth::authenticate;
#[cfg(test)]
use auth::authenticate_loop;

#[path = "platform/decoder.rs"]
pub mod decoder;
use crate::video::{self, Decoders, Geometry};
use crate::{
    clipboard::{
        ClipboardError, ClipboardImage, ClipboardMetadata, ClipboardPayload, ClipboardState,
        PeerClipboardSupport,
    },
    conn_token::ConnToken,
    handshake::ViewerIdentity,
    protocol::Protocol,
    rendezvous::RendezvousConfig,
    session::{AuthenticatedParts, PeerCloseReason, SessionMode},
    session_options::{OptionContext, OptionError, SessionOptionChange, SessionOptions},
    transport::{WireReader, WireWriter},
};
use base::message_proto::{
    self as proto, KeyEvent, Message, MouseEvent, OptionMessage, message, misc,
    option_message::BoolOption, permission_info::Permission,
};
pub use decoder::SurfaceLease;
use decoder::{DecoderError, DecoderObserver, DecoderProjection, RenderTiming, VideoCodec};
use ironrdp_pdu::input::{
    MousePdu, MouseRelPdu, MouseXPdu,
    fast_path::{FastPathInputEvent, KeyboardFlags},
    mouse::PointerFlags,
    mouse_rel::PointerRelFlags,
    mouse_x::PointerXFlags,
};
use ironrdp_pdu::rdp::capability_sets::InputFlags as RdpInputFlags;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
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
    /// It advances with every policy change, peer-grant change and explicit
    /// input retirement, so a client that keeps input state of its own can tell
    /// that the engine invalidated what came before this answer even when the
    /// policy and the admission answer remain unchanged.
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
/// How many encoded clipboard payloads one writer may have queued.
///
/// Two, not `COMMANDS`: one payload can be a 64 MiB image, so this bound is
/// about how many bytes a slow writer may hold. Two is one being written and one
/// waiting; a third is refused with `Backpressure` rather than held.
const CLIPBOARD_QUEUE: usize = 2;
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
    pub mode: SessionMode,
    /// Local filesystem authority captured for this file-transfer session.
    pub transfer_root: Option<PathBuf>,
    pub username: String,
    pub local_id: String,
    pub local_name: String,
    pub password: String,
    /// Password-equivalent material explicitly supplied for this RustDesk login.
    pub conn_token: Option<ConnToken>,
    pub requested_fps: u32,
    /// The local input policy this viewer is started under.
    ///
    /// It is in force before the asynchronous start, so a read-only session
    /// refuses input from its first event, and an unproven RustDesk session
    /// refuses it until its own operator accepts the connection (see
    /// `Viewer::set_input_policy`).
    pub input_policy: ViewerInputPolicy,
    pub session_options: SessionOptions,
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
    pub mode: SessionMode,
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
    /// Last positive RTT in milliseconds reported by a peer TestDelay.
    /// `None` means the peer has not supplied a positive measurement.
    pub network_rtt_ms: Option<u32>,
    pub received_units: u64,
    pub pushed_units: u64,
    pub render_submissions: u64,
    /// Measured push-to-submission latency, aggregated only over actual samples.
    /// `None` means this session has no actual timing observation.
    pub render_timing: Option<RenderTiming>,
    /// Units admitted but not yet pushed into the decoder at this snapshot.
    pub queued_units: u64,
    /// This session's audio playback, or `None` when the session never had an
    /// audio owner (anything but an authenticated RustDesk desktop session).
    ///
    /// Every field is the audio core's own reading, kept apart on purpose:
    /// `active` is the platform sink's answer and never an assumption,
    /// `played_samples` is what a device callback really consumed, and
    /// `queued_samples` is what still waits in the sink. `received_packets` is
    /// what this session admitted, so it stays zero while the local option or
    /// the peer's own grant refuses playback — a live peer sending audio is not
    /// evidence that anything was heard.
    pub audio: Option<crate::audio::AudioSnapshot>,
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
    /// Whether a decoded peer clipboard update is waiting in this viewer's
    /// mailbox, unconsumed.
    ///
    /// It says one thing: there is something a platform clipboard owner could
    /// take right now. It is not a permission, it never carries content, and it
    /// is not evidence that anything was applied — reading it takes nothing, so
    /// a client may see it more than once for one update. It turns false when
    /// the update is taken out of the mailbox, and also when a withdrawal, a
    /// `disable-clipboard` change or a close empties the mailbox.
    pub clipboard_pending: bool,
    /// File clipboard facts are retained for the applying consumer, not drained
    /// by a background notifier. Its ticket is distinct from text/image updates.
    pub file_clipboard_pending: bool,
    pub file_clipboard_revision: u64,
    pub closed: bool,
    /// The peer's authentication decision as the session records it: set when
    /// the session is authorized and cleared when it is closing or finished.
    ///
    /// This is a fact about the connection, not a reading of `phase`: a session
    /// that is authenticated and still binding its Surface reads `true` here
    /// while its phase is `awaiting_surface`, and a session that has finished
    /// reads `false` even though `phase` still names the last media state.
    pub authenticated: bool,
    /// Advances only when the peer actually requests or rejects a second
    /// factor. Repeated Wrong replies remain observable between polls.
    pub second_factor_challenge: u64,
    /// Advances only when the peer demands a password this attempt did not send,
    /// or refuses the one it sent. Like the second-factor counter it is what
    /// makes one demand one prompt: a client that already raised a form for this
    /// value reads the same phase on every poll and asks for nothing more, and a
    /// refusal is a new value rather than the same demand repeated.
    pub password_challenge: u64,
    /// The peer's last password demand or refusal, in the typed terms of
    /// `login_failure`: `EmptyPassword` is a session that sent none,
    /// `WrongPassword` one whose answer the peer refused.
    ///
    /// It describes an authentication that is still open — the session is waiting
    /// on the same wire for the answer — so `None` is everything else, including
    /// an answer that is already on its way to the peer (the phase says
    /// `verifying_password` while its outcome is unknown). A login the peer has
    /// ended keeps its category in `login_failure` instead.
    pub password_failure: Option<LoginFailure>,
    /// Exact LoginResponse metadata; None before any peer report.
    pub enable_trusted_devices: Option<bool>,
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
    /// Latest real RustDesk cursor messages; bitmap bytes are shared, not copied
    /// with each frame/snapshot. Empty before authorization and after close.
    pub cursor: CursorSnapshot,
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
    /// Kept as a public spelling; this viewer no longer ends here.
    ///
    /// The viewer used to stop as soon as the peer asked for a second factor.
    /// It now keeps that one session and carries the step through
    /// [`Viewer::send_second_factor`]: a peer still waiting is reported by the
    /// snapshot's own state (`awaiting_second_factor` / `second_factor_rejected`)
    /// and a refusal no code can answer is a [`ViewerError::LoginFailed`]
    /// category. The variant and its string stay so existing consumers' matches
    /// keep compiling.
    SecondFactorUnsupported,
    /// The caller offered a second-factor code this session is not waiting for.
    ///
    /// Refused rather than held: before the peer asks, after it has stopped
    /// asking, on a wire with no such step, and on a viewer that is already
    /// closing, a code would otherwise cross into an attempt it was not typed
    /// for.
    SecondFactorNotAwaiting,
    /// The caller offered a password this session is not waiting for.
    ///
    /// Refused rather than held: before the peer asks, after it has stopped
    /// asking, on a wire with no such step, and on a viewer that is already
    /// closing, a password would otherwise cross into an attempt it was not
    /// typed for.
    PasswordNotAwaiting,
    /// An empty password cannot answer a peer's demand.
    ///
    /// The original wire spells "no password" as an empty
    /// `LoginRequest.password`, which is exactly the attempt the peer refused, so
    /// an empty string is not a retry. It is refused here — the session stays
    /// open and the peer still waits — instead of being written as another login
    /// that carries nothing.
    InvalidPassword,
    SessionOption(OptionError),
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
    /// A clipboard payload this viewer refused, could not interpret, or owes a
    /// peer that cannot receive it.
    ///
    /// The typed reason travels with it rather than being folded into one
    /// string: an oversized, corrupt, undeliverable and permission-refused
    /// payload are four different answers, and a caller that reports a send has
    /// to be able to tell "nothing was queued" from "queued".
    Clipboard(ClipboardError),
    FileClipboard(crate::cliprdr::CliprdrError),
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
            Self::Clipboard(error) => write!(f, "{error}"),
            Self::FileClipboard(error) => write!(f, "{error}"),
            Self::SessionOption(error) => write!(f, "{error}"),
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
/// `No Password Access` (awaiting approval) and the peer's second-factor step do
/// not appear here: they have their own states (`phase == "awaiting_approval"`,
/// `"awaiting_second_factor"` and `"second_factor_rejected"`), and this is the
/// vocabulary of a login that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFailure {
    /// `Empty Password`: the peer wants a password this client did not send. A
    /// login that went out with none is also offered this step while the peer's
    /// operator decides, as the official client does, so a typed password can
    /// settle the same attempt.
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
    // Explicit export only: never included in snapshots or events.
    conn_token: Option<ConnToken>,
    geometry: Option<Geometry>,
    decoder: Option<DecoderObserver>,
    cursor: cursor::CursorState,
    // Observation only; State::finish decides whether cleanup permits publishing it.
    observed_peer_close_reason: Option<PeerCloseReason>,
}
struct State {
    inner: Mutex<Inner>,
    presentation: Option<Arc<crate::presentation::LocalPresentation>>,
    cancel: CancellationToken,
    done: Notify,
    result: Mutex<Option<Result<(), ViewerError>>>,
    /// Which wire this viewer speaks. Kept beside the state instead of being
    /// read back out of the snapshot's label, so an admission decision is one
    /// field read rather than a clone of the whole snapshot.
    protocol: Protocol,
    mode: SessionMode,
    transfer: Mutex<Option<Arc<crate::transfer::TransferHandle>>>,
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
    control: Mutex<Option<mpsc::Sender<Vec<Message>>>>,
    session_options: Mutex<SessionOptions>,
    advertised_decoding: Mutex<Option<proto::SupportedDecoding>>,
    /// The peer's second-factor step: installed by authentication only while
    /// this session really waits for a code on its own wire, and taken away
    /// when it leaves that step.
    second_factor: Mutex<SecondFactorGate>,
    /// The peer's password demand, in the same shape: installed by
    /// authentication only while this session really waits for an answer on its
    /// own wire, and taken away when it leaves that step.
    password: Mutex<PasswordGate>,
    /// This viewer's clipboard mailbox: the one place a decoded peer update
    /// waits, and the permission fence it waits behind.
    clipboard: ClipboardState,
    /// The peer's own clipboard grant, mirrored so this viewer can recompute
    /// the combined fence when a *local* switch moves. It is never raised from
    /// this side: a grant the peer withdrew stays withdrawn until the peer
    /// grants it again.
    peer_clipboard: AtomicBool,
    peer_file: AtomicBool,
    /// The peer's own audio grant, mirrored like the clipboard's: it is the
    /// peer's channel, never raised from this side, so a grant the peer
    /// withdrew stays withdrawn until the peer grants it again.
    peer_audio: AtomicBool,
    /// This session's shared audio handle: the one path the peer's format and
    /// frames take. It exists only for an authenticated RustDesk desktop
    /// session, and is never replaced by a second owner.
    audio: Mutex<Option<Arc<crate::audio::AudioHandle>>>,
    cliprdr: Mutex<Option<Arc<crate::cliprdr::CliprdrHandle>>>,
    /// The way an encoded clipboard payload reaches this session's one writer.
    /// A second channel into the same writer, not a second writer: the same
    /// `write` loop takes it, in order with every other message, after the same
    /// re-checks.
    clipboard_out: Mutex<Option<mpsc::Sender<QueuedClipboard>>>,
    /// The bounded decode this viewer owns: one slot being decoded and one
    /// pending, so a peer cannot make this session inflate frames in parallel
    /// or build a backlog, and the reader never waits for either.
    clipboard_in: ClipboardDecoder,
}

/// One clipboard message as the reader hands it to the decode worker.
///
/// It is the wire's own union and not a decoded payload: the reader does no
/// inflation, so the work that can take a quarter of a gigabyte happens on the
/// decode worker and never on the reader.
enum ClipboardMessage {
    Single(proto::Clipboard),
    Multi(proto::MultiClipboards),
}

/// The one bounded slot this viewer's clipboard decode waits in.
///
/// A clipboard is a value, not a stream, so this holds the newest message that
/// has not been decoded yet and lets a newer one replace it. That replacement is
/// the whole bound: one message being decoded plus one pending, whatever rate
/// the peer sends at.
#[derive(Default)]
struct ClipboardDecoder {
    pending: Mutex<Option<(u64, ClipboardMessage)>>,
    ready: Notify,
}

impl ClipboardDecoder {
    /// Offers one message, stamped with the clipboard generation it arrived
    /// under. A newer message replaces one that has not been decoded yet.
    fn offer(&self, generation: u64, message: ClipboardMessage) {
        *lock(&self.pending) = Some((generation, message));
        self.ready.notify_one();
    }

    /// The newest message that has not been decoded yet, with the generation it
    /// was offered under.
    ///
    /// The slot is checked before the wait and the notification permit survives
    /// that check, so a message offered between the two is taken rather than
    /// waited behind.
    async fn next(&self) -> (u64, ClipboardMessage) {
        loop {
            if let Some(job) = lock(&self.pending).take() {
                return job;
            }
            self.ready.notified().await;
        }
    }
}

/// One encoded clipboard payload waiting for the session's one writer, with the
/// clipboard generation that admitted it.
///
/// The generation is fixed when the payload is queued and never re-read: the
/// writer asks whether *that* generation is still the one in force instead of
/// taking a fresh stamp, so a payload queued before a withdrawal cannot be
/// relabelled under the generation that follows it.
struct QueuedClipboard {
    generation: u64,
    message: Message,
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
            authenticated: state.mode == SessionMode::Desktop
                && state.authenticated.load(Ordering::Acquire),
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
    /// Wakes the one writer when the policy or the peer's grant changes, or
    /// input is explicitly retired. A permit survives a writer that is busy,
    /// and the pass it triggers reads
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
    /// Bumped on every policy change, grant change and explicit retirement, so
    /// prior-generation input cannot be emitted afterwards — including
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

    /// Retires queued input and every hold the writer already owns, without
    /// changing the policy or the peer's grant. The existing release pass sees
    /// the old generation as stale; it alone settles the retired holds.
    fn retire(&self) -> InputPolicyOutcome {
        let outcome = {
            let mut state = lock(&self.state);
            state.generation += 1;
            state.retired = state.owed;
            InputPolicyOutcome {
                policy: state.policy,
                input_generation: state.generation,
                revoked: false,
                releases_owed: state.owed,
                releases_retired: state.retired,
                releases_unreleased: state.unreleased,
            }
        };
        self.changed.notify_one();
        outcome
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
        if stamped != state.generation
            || !facts.admits(state.view())
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

/// One viewer's second-factor entry point, installed by authentication only
/// while its session is really waiting for a code.
///
/// Both facts live under one lock because they only mean anything together:
/// `code` exists exactly between the peer asking for a second factor and this
/// session leaving that step, and `submitted` says a code admitted through it
/// has not been answered yet. A code offered with no sender installed is
/// refused instead of kept, and a second code offered before the peer answered
/// the first is refused rather than queued into the attempt that follows.
#[derive(Default)]
struct SecondFactorGate {
    /// The channel the authentication loop is reading; `None` outside that step.
    code: Option<mpsc::Sender<String>>,
    /// Whether an admitted code is still waiting for the peer's answer.
    submitted: bool,
}

/// One viewer's password entry point, installed by authentication only while its
/// session is really waiting for one.
///
/// It has the second-factor gate's shape because it is the same kind of step: a
/// secret the peer asked for, on the wire this session already has, answered
/// once. `password` exists exactly between the peer demanding one that this
/// attempt did not send (or refusing the one it sent) and this authentication
/// leaving that step, and `submitted` says an answer admitted through it has not
/// been written yet. A password offered with no sender installed is refused
/// instead of kept, and a second one offered before the peer answered the first
/// is refused rather than queued into the attempt that follows — a password
/// typed for one attempt never becomes the answer to the next.
#[derive(Default)]
struct PasswordGate {
    /// The channel the authentication loop is reading; `None` outside that step.
    password: Option<mpsc::Sender<String>>,
    /// Whether an admitted password is still waiting to be written.
    submitted: bool,
}

/// The receiving ends of one viewer's pre-authentication answers.
///
/// Authentication reads both, which is what lets an admitted secret reach the
/// session's own writer. Each also clears whatever is still in it when that
/// exchange ends: a secret the peer never got — it authorized first, or the
/// viewer was cancelled while one was queued — is single-use, and must not be
/// left for the allocator to hand back.
struct AuthAnswers {
    codes: mpsc::Receiver<String>,
    passwords: mpsc::Receiver<String>,
}

impl AuthAnswers {
    fn clear(&mut self) {
        while let Ok(code) = self.codes.try_recv() {
            discard_code(code);
        }
        while let Ok(password) = self.passwords.try_recv() {
            discard_password(password);
        }
    }
}

impl Drop for AuthAnswers {
    fn drop(&mut self) {
        self.clear();
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
    /// Whether this viewer may exchange clipboard content with its peer right
    /// now: the AND of every fact that has to hold, collected in one place.
    ///
    /// Each term is a real fact this session owns — the peer's own clipboard
    /// grant, the operator's read-only switch, the local `disable-clipboard`
    /// option that the login and every later `OptionMessage` state, the
    /// authenticated connection, and the cancellation that ends it. None is
    /// inferred from another, and no term is defaulted to true on this side.
    fn clipboard_facts(&self) -> bool {
        self.mode == SessionMode::Desktop
            && self.authenticated.load(Ordering::Acquire)
            && !self.cancel.is_cancelled()
            && !self.input.policy().view_only
            && self.peer_clipboard.load(Ordering::Acquire)
            && lock(&self.session_options).clipboard_enabled()
    }

    /// Publishes the combined clipboard fence, and returns the generation in
    /// force afterwards.
    ///
    /// Called from every place one of those facts moves. A change in either
    /// direction advances the mailbox's generation and empties it, so a payload
    /// queued or decoded under the previous answer can neither be written to the
    /// peer nor applied from it. A repeated report changes nothing, so a peer
    /// re-sending a grant it already gave does not refuse a decode in flight.
    fn refresh_clipboard(&self) -> u64 {
        let generation = self.clipboard.set_accepted(self.clipboard_facts());
        if let Some(handle) = lock(&self.cliprdr).as_ref() {
            handle.set_allowed(self.file_clipboard_facts());
        }
        generation
    }

    fn file_clipboard_facts(&self) -> bool {
        self.clipboard_facts() && self.peer_file.load(Ordering::Acquire)
    }

    /// Whether a clipboard payload queued under `generation` may still be
    /// written, asked at the writer that owns the wire.
    ///
    /// Both answers are needed and they are different questions: the facts say
    /// whether delivery is allowed at this instant, and the mailbox's generation
    /// says whether the permission that admitted *this* payload is still the one
    /// in force. A payload queued before a withdrawal, a read-only switch or a
    /// close therefore fails both, and one queued before a withdrawal that was
    /// then granted again fails the generation while passing the facts.
    fn clipboard_write_allowed(&self, generation: u64) -> bool {
        self.clipboard_facts() && self.clipboard.admits(generation)
    }

    /// Hands one peer clipboard message to the decode worker, stamped with the
    /// generation it arrived under.
    ///
    /// That generation is read before the fence is consulted, so a change in
    /// between makes the message stale rather than stamping earlier content with
    /// a later generation. Nothing is offered while the fence is closed.
    fn offer_clipboard(&self, message: ClipboardMessage) {
        let generation = self.clipboard.revision();
        if !self.clipboard_facts() {
            return;
        }
        self.clipboard_in.offer(generation, message);
    }

    /// Whether this viewer may play the peer's audio right now: the AND of every
    /// fact that has to hold, collected in one place like the clipboard's.
    ///
    /// A desktop session on the wire that carries audio, its authenticated
    /// state, the peer's own audio grant, the local option that asks for audio,
    /// and the cancellation that ends it. The operator's read-only switch is
    /// deliberately not a term: it stops what this viewer *sends*, and listening
    /// sends nothing.
    ///
    /// Nothing here raises the peer's grant. Turning the local option off and on
    /// again can only restore an allowance the peer still holds; a grant the
    /// peer withdrew is not recoverable from this side.
    fn audio_facts(&self) -> bool {
        self.mode == SessionMode::Desktop
            && self.authenticated.load(Ordering::Acquire)
            && !self.cancel.is_cancelled()
            && self.peer_audio.load(Ordering::Acquire)
            && lock(&self.session_options).audio_enabled()
    }

    /// Publishes the combined audio answer to this session's audio owner.
    ///
    /// Read facts while holding the handle lock: two refreshes cannot apply an
    /// old grant after a newer withdrawal. Option callers release their lock
    /// before entering here. An unchanged allowance leaves the generation alone.
    fn refresh_audio(&self) {
        if let Some(handle) = lock(&self.audio).as_ref() {
            handle.set_allowed(self.audio_facts());
        }
    }

    /// Hands one peer format declaration to this session's audio owner.
    ///
    /// A refusal is the core's own answer (`Closed`, `InvalidFormat`) and is
    /// already recorded in its snapshot; no other wire message is affected.
    fn offer_audio_format(&self, format: proto::AudioFormat) {
        if let Some(handle) = lock(&self.audio).as_ref() {
            let _ = handle.offer_format(format);
        }
    }

    /// Hands one encoded peer packet to this session's audio owner, without
    /// copying it and without waiting.
    ///
    /// The offer is bounded inside the core: the packet's buffer moves into an
    /// eight-deep queue, a full queue answers with `Backpressure` and the packet
    /// is dropped and counted there. The reader therefore never waits for the
    /// audio device, and a refused packet cannot delay video, clipboard or input.
    fn offer_audio_frame(&self, frame: proto::AudioFrame) {
        if let Some(handle) = lock(&self.audio).as_ref() {
            let _ = handle.offer_frame(frame);
        }
    }

    /// This session's audio reading, or nothing when it never had an owner.
    fn audio_snapshot(&self) -> Option<crate::audio::AudioSnapshot> {
        lock(&self.audio).as_ref().map(|handle| handle.snapshot())
    }

    /// Whether this session's audio owner has a native resource it could not
    /// confirm released, read from the audio core's own flag.
    ///
    /// It is asked separately from the video pipeline's flag: one release never
    /// clears the other's failure, and a session with no audio owner has nothing
    /// unconfirmed here.
    fn audio_unconfirmed(&self) -> bool {
        self.audio_snapshot()
            .is_some_and(|audio| audio.resources_unconfirmed)
    }

    /// Whether any native resource this session created may still exist: the
    /// video pipeline's own answer or the audio owner's.
    fn resources_unconfirmed_any(&self) -> bool {
        self.resources_unconfirmed.load(Ordering::Acquire) || self.audio_unconfirmed()
    }

    fn snapshot(&self) -> ViewerSnapshot {
        let inner = lock(&self.inner);
        let mut out = inner.snapshot.clone();
        out.authenticated = self.authenticated.load(Ordering::Acquire);
        out.cursor = if self.cursor_active() && !out.closed {
            inner.cursor.snapshot()
        } else {
            CursorSnapshot::default()
        };
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
        // Read from the mailbox itself rather than remembered here: a client
        // that asks again before taking gets the same answer, and the answer
        // goes away exactly when the update is taken or the fence drops it.
        out.clipboard_pending = self.clipboard.has_pending();
        if let Some(handle) = lock(&self.cliprdr).as_ref() {
            out.file_clipboard_pending = handle.has_events();
            out.file_clipboard_revision = handle.revision();
        }
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
        // The audio owner's own reading, beside the video pipeline's: neither is
        // derived from the other, and `None` says this session never had one.
        out.audio = self.audio_snapshot();
        out
    }
    fn request_close(&self) {
        self.authenticated.store(false, Ordering::Release);
        self.cancel.cancel();
        // The clipboard fence is withdrawn with the session: what a peer sent
        // and what a client queued belong to a session that is ending, so the
        // mailbox is emptied (including any image a descriptor reserved) and a
        // decode or a write that outlives this point is refused rather than
        // applied to the next generation.
        self.clipboard.revoke();
        if let Some(handle) = lock(&self.cliprdr).as_ref() {
            handle.revoke();
        }
        // Audio is withdrawn with the session in the same way: the cancellation
        // already ends the owner, and publishing the answer advances its
        // generation, so nothing admitted under the allowance in force before
        // this point can reach the sink after it.
        self.refresh_audio();
        let mut inner = lock(&self.inner);
        inner.conn_token = None;
        if !inner.snapshot.closed {
            inner.cursor = cursor::CursorState::default();
            inner.snapshot.phase = "closing".into();
        }
        if let Some(observer) = &inner.decoder {
            observer.request_close();
        }
    }
    fn finish(&self, result: Result<(), ViewerError>) {
        self.authenticated.store(false, Ordering::Release);
        // A viewer that ends without `request_close` — an authentication
        // failure, a transport failure, a cancelled start — closes the fence
        // here too, so no descriptor can be handed out and no reserved image
        // can be read after the session it belonged to is over.
        self.clipboard.revoke();
        if let Some(handle) = lock(&self.cliprdr).as_ref() {
            handle.revoke();
        }
        // The audio allowance is withdrawn here too, for a session that ends
        // without `request_close`.
        self.refresh_audio();
        // The audio owner's own reclamation fact is joined with the video
        // pipeline's, and neither can clear the other: an audio device that could
        // not confirm its release fails the close exactly like a Surface that
        // could not.
        let reclamation = if self.resources_unconfirmed_any() {
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
        inner.conn_token = None;
        inner.snapshot.closed = true;
        inner.cursor = cursor::CursorState::default();
        inner.snapshot.keyboard_allowed = false;
        // The category is published beside the string, not inside it: `error`
        // keeps the text it has always reported, and a client that has to choose
        // between a password form and another outcome reads this field instead of
        // inferring a reason from its own state.
        inner.snapshot.login_failure = match &result {
            Err(ViewerError::LoginFailed(failure)) => Some(*failure),
            _ => None,
        };
        // A password demand describes an authentication that is still open. Once
        // this session is finished the terminal answer is the category above, so
        // a mid-flight reason is not published beside a closed session.
        inner.snapshot.password_failure = None;
        inner.snapshot.peer_close_reason =
            if reclamation.is_ok() && matches!(&result, Err(ViewerError::RemoteClosed)) {
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
    fn video_decoder_opened(
        &self,
        codec: VideoCodec,
        geometry: Geometry,
        observer: DecoderObserver,
    ) {
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

fn validate_rdp_options(
    endpoint: &crate::protocol::Endpoint,
    password: &str,
) -> Result<(), ViewerError> {
    let user = endpoint
        .user
        .as_deref()
        .ok_or(ViewerError::InvalidOptions)?;
    if endpoint.port == 0
        || endpoint.host.is_empty()
        || endpoint.host.len() > 255
        || endpoint
            .host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || rustls::pki_types::ServerName::try_from(endpoint.host.as_str()).is_err()
        || user.trim().is_empty()
        || user.len() > 128
        || user.chars().any(char::is_control)
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
            || (options.conn_token.is_some() && options.target.protocol() != Protocol::RustDesk)
            || (options.mode == SessionMode::Desktop && !(1..=240).contains(&options.requested_fps))
            || (options.mode == SessionMode::FileTransfer
                && options.target.protocol() != Protocol::RustDesk)
        {
            return Err(ViewerError::InvalidOptions);
        }
        let runtime = runtime()?;
        let (mouse, mouse_rx) = mpsc::channel(COMMANDS);
        let state = Arc::new(State {
            presentation: lease.local_presentation(),
            control: Mutex::new(None),
            second_factor: Mutex::new(SecondFactorGate::default()),
            password: Mutex::new(PasswordGate::default()),
            session_options: Mutex::new(options.session_options.clone()),
            advertised_decoding: Mutex::new(None),
            inner: Mutex::new(Inner {
                conn_token: None,
                snapshot: ViewerSnapshot {
                    phase: "capability".into(),
                    mode: options.mode,
                    protocol: options.target.protocol().as_str().into(),
                    ..Default::default()
                },
                geometry: None,
                decoder: None,
                observed_peer_close_reason: None,
                cursor: cursor::CursorState::default(),
            }),
            cancel: CancellationToken::new(),
            done: Notify::new(),
            result: Mutex::new(None),
            protocol: options.target.protocol(),
            mode: options.mode,
            transfer: Mutex::new(None),
            authenticated: AtomicBool::new(false),
            rdp_input_flags: AtomicU16::new(0),
            peer_proven: AtomicBool::new(false),
            // The local policy is in force before the session starts, not after
            // the first caller asks: this is what makes a read-only viewer
            // read-only from its first event.
            input: InputGate::new(options.input_policy),
            // The mailbox exists from the start, but the fence opens only once
            // the handshake has reported the peer's grant: `run_rustdesk` calls
            // `refresh_clipboard` as soon as those facts are in, and nothing can
            // decode or send before it does.
            clipboard: ClipboardState::new(),
            peer_clipboard: AtomicBool::new(false),
            peer_file: AtomicBool::new(false),
            // Audio follows the clipboard's shape: the peer's grant mirrored
            // beside the local option, and one owner that only an authenticated
            // desktop session starts.
            peer_audio: AtomicBool::new(false),
            audio: Mutex::new(None),
            cliprdr: Mutex::new(None),
            clipboard_out: Mutex::new(None),
            clipboard_in: ClipboardDecoder::default(),
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

    /// Non-secret availability; registering a share gesture need not export h1.
    pub fn has_conn_token(&self) -> bool {
        let inner = lock(&self.state.inner);
        !self.state.cancel.is_cancelled()
            && self.state.authenticated.load(Ordering::Acquire)
            && !inner.snapshot.closed
            && inner.conn_token.is_some()
    }

    /// Explicit, repeatable export of the current authenticated login's h1.
    pub fn conn_token_json(&self) -> Option<String> {
        let inner = lock(&self.state.inner);
        if self.state.cancel.is_cancelled()
            || !self.state.authenticated.load(Ordering::Acquire)
            || inner.snapshot.closed
        {
            return None;
        }
        inner.conn_token.as_ref().map(ConnToken::to_json)
    }

    /// A session-owned mailbox retained for terminal event consumption too.
    pub fn transfer_handle(&self) -> Option<Arc<crate::transfer::TransferHandle>> {
        lock(&self.state.transfer).clone()
    }

    pub fn submit_transfer(
        &self,
        command: crate::transfer::TransferCommand,
    ) -> Result<(), crate::transfer::TransferError> {
        if self.state.cancel.is_cancelled() {
            return Err(crate::transfer::TransferError::Closed);
        }
        if !self.state.authenticated.load(Ordering::Acquire) {
            return Err(crate::transfer::TransferError::Closed);
        }
        self.transfer_handle()
            .ok_or(crate::transfer::TransferError::Closed)?
            .submit(command)
    }

    /// Current gate epoch for a refusal report, not a successful input receipt.
    pub fn session_options_snapshot(&self) -> SessionOptions {
        lock(&self.state.session_options).clone()
    }

    /// Queues the RustDesk frame-rate increment on this session's one writer.
    ///
    /// Only `custom_fps` is stated: replaying login options would overwrite
    /// unrelated choices. `Ok(())` means queued, not written or peer-applied;
    /// the peer may impose its own cap and sends no applied-rate receipt.
    pub fn set_custom_fps(&self, fps: u32) -> Result<(), ViewerError> {
        if !(1..=240).contains(&fps) {
            return Err(ViewerError::InvalidOptions);
        }
        if self.state.protocol != Protocol::RustDesk || self.state.mode != SessionMode::Desktop {
            return Err(ViewerError::SessionOption(OptionError::UnsupportedProtocol));
        }
        if self.state.cancel.is_cancelled() || lock(&self.state.inner).snapshot.closed {
            return Err(ViewerError::Closed);
        }
        if !self.state.authenticated.load(Ordering::Acquire) {
            return Err(ViewerError::SessionOption(OptionError::SessionNotStarted));
        }
        let sender = lock(&self.state.control)
            .clone()
            .ok_or(ViewerError::Closed)?;
        let mut misc = proto::Misc::new();
        misc.set_option(OptionMessage {
            custom_fps: fps as i32,
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_misc(misc);
        sender.try_send(vec![message]).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ViewerError::Backpressure,
            mpsc::error::TrySendError::Closed(_) => ViewerError::Closed,
        })
    }

    /// Commit requested state only after the entire change enters the one
    /// writer queue. No option here claims the peer applied its request.
    pub fn set_session_option(&self, change: SessionOptionChange) -> Result<(), ViewerError> {
        if self.state.protocol != Protocol::RustDesk || self.state.mode != SessionMode::Desktop {
            return Err(ViewerError::SessionOption(OptionError::UnsupportedProtocol));
        }
        if self.state.cancel.is_cancelled() {
            return Err(ViewerError::Closed);
        }
        if !self.state.authenticated.load(Ordering::Acquire) {
            return Err(ViewerError::SessionOption(OptionError::SessionNotStarted));
        }
        // Snapshot reads the audio handle. Do not hold the option lock across
        // it: allowance refresh takes the handle lock before reading options.
        let snapshot = self.snapshot();
        let mut requested = lock(&self.state.session_options);
        let advertised = lock(&self.state.advertised_decoding)
            .clone()
            .ok_or(ViewerError::SessionOption(OptionError::SessionNotStarted))?;
        let prepared = requested
            .prepare(
                change,
                &OptionContext {
                    protocol: self.state.protocol,
                    peer_version: &snapshot.version,
                    advertised_decoding: &advertised,
                    displays: &snapshot.displays,
                    current_display: snapshot.current_display,
                },
            )
            .map_err(ViewerError::SessionOption)?;
        let sender = lock(&self.state.control)
            .clone()
            .ok_or(ViewerError::Closed)?;
        sender
            .try_send(prepared.messages)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ViewerError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => ViewerError::Closed,
            })?;
        *requested = prepared.next;
        drop(requested);
        // `disable-clipboard` is one of the facts the clipboard fence is the AND
        // of, so a change to it is published where the fence lives rather than
        // only on the wire: the option and the mailbox can never disagree about
        // whether this session exchanges clipboard content.
        self.state.refresh_clipboard();
        // `disable-audio` is one of the facts the audio answer is the AND of, so
        // it reaches the audio owner here as well: the option this session holds
        // and what it is willing to play cannot disagree, and a withdrawal stops
        // playback without waiting for the next packet.
        self.state.refresh_audio();
        Ok(())
    }

    /// Sends one clipboard payload through this session's one writer.
    ///
    /// The payload is encoded for the peer's own reported version and platform,
    /// so a peer without `MultiClipboards` is sent its text format only. The
    /// answer is the clipboard generation the payload was queued under: it is in
    /// the writer's queue, which is not the peer's application of it, because the
    /// original wire has no clipboard acknowledgement to wait for.
    ///
    /// Every refusal is an error and never a quiet success: `NotDeliverable` is a
    /// peer owed nothing for this payload, `InputNotAllowed` a session that may
    /// not send right now (not authenticated, read-only, or without the peer's
    /// grant and the local option), `Closed` one that has ended, `Backpressure` a
    /// queue that took nothing.
    pub fn clipboard_send(&self, payload: ClipboardPayload) -> Result<u64, ViewerError> {
        if self.state.cancel.is_cancelled() {
            return Err(ViewerError::Closed);
        }
        // The ticket is taken first, before the permission is read and before any
        // encoding: compressing a text payload or handing on a 64 MiB image takes
        // long enough for a withdrawal, a re-grant or a close to land, and a
        // generation read after that would stamp this content with a generation
        // that never admitted it. What the writer checks is this value, re-read
        // from the mailbox only to compare it, never to replace it.
        let generation = self.state.clipboard.revision();
        if !self.state.clipboard_facts() {
            return Err(ViewerError::InputNotAllowed);
        }
        let snapshot = self.snapshot();
        let peer = PeerClipboardSupport::of(&snapshot.version, &snapshot.platform);
        let Some(message) =
            crate::clipboard::encode(payload, peer).map_err(ViewerError::Clipboard)?
        else {
            return Err(ViewerError::Clipboard(ClipboardError::NotDeliverable));
        };
        // The writer asks whether that same generation is still in force instead
        // of taking a fresh stamp, so nothing encoded here can be written after
        // the permission that admitted it is gone.
        let sender = lock(&self.state.clipboard_out)
            .clone()
            .ok_or(ViewerError::Closed)?;
        // An ordinary local clipboard value replaces a local file offer too.
        // The file owner closes its source handles and emits the protocol's
        // TryEmpty; otherwise the peer could keep requesting an obsolete offer.
        if let Some(handle) = self.cliprdr_handle() {
            handle
                .submit(crate::cliprdr::CliprdrCommand::ClearLocalOffer)
                .map_err(ViewerError::FileClipboard)?;
        }
        sender
            .try_send(QueuedClipboard {
                generation,
                message,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ViewerError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => ViewerError::Closed,
            })?;
        Ok(generation)
    }

    /// Takes the next decoded clipboard update with its bytes, as one value.
    ///
    /// The revision and the content come from one mailbox hand-out, so a caller
    /// that keeps that pair cannot end up with metadata from one update beside
    /// bytes from another.
    pub fn clipboard_take(&self) -> Option<crate::clipboard::ClipboardUpdate> {
        self.state.clipboard.take()
    }

    /// Rechecks the original clipboard ticket at the platform commit boundary.
    /// Taking an update does not grant permission to apply it after revocation.
    pub fn clipboard_admits(&self, revision: u64) -> bool {
        !self.state.cancel.is_cancelled() && self.state.clipboard.admits(revision)
    }

    /// Whether the platform owner may read the local clipboard for this viewer.
    pub fn clipboard_enabled(&self) -> bool {
        !self.state.cancel.is_cancelled() && self.state.clipboard.is_accepted()
    }

    /// Takes the next update's metadata and reserves its image, if it had one,
    /// for [`Self::clipboard_take_image`].
    ///
    /// This is the two-call shape a platform clipboard owner uses. The descriptor
    /// handed out here and the bytes handed out next are the same accepted
    /// update, so a withdrawal between the two calls withholds the bytes instead
    /// of writing an image the permission no longer covers.
    pub fn clipboard_take_metadata(&self) -> Option<ClipboardMetadata> {
        self.state.clipboard.take_metadata()
    }

    /// Hands out the image bytes [`Self::clipboard_take_metadata`] described, at
    /// most once.
    pub fn clipboard_take_image(&self) -> Option<ClipboardImage> {
        self.state.clipboard.take_image()
    }

    /// The Desktop's own file clipboard owner. Commands only enter its bounded
    /// queue; its events separately report written offers and completed files.
    pub fn cliprdr_handle(&self) -> Option<Arc<crate::cliprdr::CliprdrHandle>> {
        lock(&self.state.cliprdr).clone()
    }

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

    /// Retires this generation's queued and held input without changing policy.
    ///
    /// The existing ordered writer releases exactly the holds it emitted. The
    /// answer names the new generation and any release still pending, not a
    /// remote release acknowledgement. Clipboard permission and pending content
    /// are independent and untouched.
    pub fn release_input(&self) -> InputPolicyOutcome {
        self.state.input.retire()
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
        // The read-only switch is one of the facts the clipboard fence is the
        // AND of, so it is published to the mailbox here: turning it on stops
        // clipboard delivery in both directions and empties what waited, and
        // turning it off can only restore a grant the peer still holds.
        self.state.refresh_clipboard();
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
            .try_send(vec![message])
            .map_err(|_| ViewerError::TransportFailed)
    }

    /// Answers the peer's second-factor step on this same, still-open session.
    ///
    /// A code is admitted only while this viewer's own RustDesk session is
    /// waiting for one: authentication installs the entry point when the peer
    /// asks and takes it away when the session leaves that step, so a code
    /// offered before the peer asks, after it stopped asking, on another wire,
    /// or after this viewer closed is refused instead of kept for a later
    /// attempt. One code per peer answer is admitted — a second one offered
    /// while the first is still unanswered is `Backpressure`, never a queue —
    /// which is what stops an answer typed for one attempt from travelling as
    /// part of the next.
    ///
    /// `Ok(())` is the receipt that the code reached the session's own
    /// authentication loop, which writes it on the same wire; it is never a
    /// claim that the peer accepted it. Acceptance is the snapshot's
    /// `authenticated`/`Authorized` fact, and a refusal is the peer's next
    /// `second_factor_rejected` state.
    pub fn send_second_factor(&self, code: String) -> Result<(), ViewerError> {
        if self.state.cancel.is_cancelled() {
            discard_code(code);
            return Err(ViewerError::Closed);
        }
        let mut gate = lock(&self.state.second_factor);
        // Cloned, so the refusals below neither hold nor extend a borrow of the
        // gate they are about to mutate.
        let Some(sender) = gate.code.clone() else {
            discard_code(code);
            return Err(ViewerError::SecondFactorNotAwaiting);
        };
        if gate.submitted {
            discard_code(code);
            return Err(ViewerError::Backpressure);
        }
        match sender.try_send(code) {
            Ok(()) => {
                gate.submitted = true;
                self.state.phase("verifying_second_factor");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(code)) => {
                discard_code(code);
                Err(ViewerError::Backpressure)
            }
            Err(mpsc::error::TrySendError::Closed(code)) => {
                discard_code(code);
                Err(ViewerError::Closed)
            }
        }
    }

    /// Answers the peer's password demand on this same, still-open session.
    ///
    /// The engine keeps its authentication attempt open across the peer's
    /// `Empty Password`/`Wrong Password` answer, so this is that attempt's retry
    /// and not a new one: the login is written on the wire this session already
    /// opened, under the identity, session id and role (desktop or file
    /// transfer) its first request carried, and under the original absolute
    /// authentication deadline. No socket, no writer and no viewer is created to
    /// ask again.
    ///
    /// A password is admitted only while this viewer's own RustDesk session is
    /// waiting for one: authentication installs the entry point when the peer
    /// demands a password this attempt did not send or refuses the one it sent,
    /// and takes it away when the session leaves that step, so a password
    /// offered before the peer asks, after it stopped asking, on another wire, or
    /// after this viewer closed is refused instead of kept for a later attempt.
    /// One answer per peer demand is admitted — a second one offered while the
    /// first is still unwritten is `Backpressure`, never a queue.
    ///
    /// `Ok(())` is the receipt that the password reached the session's own
    /// authentication loop, which writes it; it is never a claim that the peer
    /// accepted it. Acceptance stays the snapshot's `authenticated` fact, and a
    /// refusal is the peer's next `password_rejected` state.
    pub fn send_password(&self, password: String) -> Result<(), ViewerError> {
        if self.state.cancel.is_cancelled() {
            discard_password(password);
            return Err(ViewerError::Closed);
        }
        // An empty string is not an answer: the original wire spells "no
        // password" as an empty `LoginRequest.password`, which is the attempt
        // the peer just refused.
        if password.is_empty() {
            return Err(ViewerError::InvalidPassword);
        }
        let mut gate = lock(&self.state.password);
        // Cloned, so the refusals below neither hold nor extend a borrow of the
        // gate they are about to mutate.
        let Some(sender) = gate.password.clone() else {
            discard_password(password);
            return Err(ViewerError::PasswordNotAwaiting);
        };
        if gate.submitted {
            discard_password(password);
            return Err(ViewerError::Backpressure);
        }
        match sender.try_send(password) {
            Ok(()) => {
                gate.submitted = true;
                // The answer is on its way to the wire. The peer's previous
                // reason no longer describes this attempt; what is still
                // unknown is its outcome, and `authenticated` stays false until
                // the peer says otherwise.
                let mut inner = lock(&self.state.inner);
                inner.snapshot.phase = "verifying_password".into();
                inner.snapshot.password_failure = None;
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(password)) => {
                discard_password(password);
                Err(ViewerError::Backpressure)
            }
            Err(mpsc::error::TrySendError::Closed(password)) => {
                discard_password(password);
                Err(ViewerError::Closed)
            }
        }
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

/// Drops one second-factor code without leaving its bytes for the allocator.
///
/// A code is single-use and never logged or written anywhere. One this viewer
/// refused never reached the peer, so its bytes are cleared here instead of
/// being kept until the allocation happens to be reused.
fn discard_code(mut code: String) {
    let mut bytes = std::mem::take(&mut code).into_bytes();
    hbb_common::sodiumoxide::utils::memzero(&mut bytes);
}

/// Drops one password that was handed in and is not going to be written.
///
/// A password is a single-use secret in the same sense: one this viewer refused
/// never reached the peer, so its bytes are cleared here instead of being kept
/// until the allocation happens to be reused. The answer that *is* written is
/// cleared by the authentication loop as soon as the login is on the wire.
fn discard_password(mut password: String) {
    let mut bytes = std::mem::take(&mut password).into_bytes();
    hbb_common::sodiumoxide::utils::memzero(&mut bytes);
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
    let mode = options.mode;
    let transfer_root = options.transfer_root.clone();
    // A file connection does not probe a decoder or promise desktop codecs.
    let caps = if mode == SessionMode::Desktop {
        Some(
            tokio::task::spawn_blocking(video::capabilities)
                .await
                .map_err(|_| ViewerError::TaskFailed)??,
        )
    } else {
        None
    };
    let advertised = caps.map(Decoders::supported_decoding).unwrap_or_default();
    if mode == SessionMode::Desktop {
        options
            .session_options
            .validate_advertisement(&advertised)
            .map_err(ViewerError::SessionOption)?;
        *lock(&state.advertised_decoding) = Some(advertised.clone());
    }
    let parts = tokio::select! {
        biased;
        _ = state.cancel.cancelled() => return Ok(()),
        parts = authenticate(&state, options, advertised, connector) => parts?,
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
    let media = if let Some(caps) = caps {
        let source = Geometry::of_peer(
            parts
                .context
                .peer_info
                .as_ref()
                .ok_or(ViewerError::InvalidPeerGeometry)?,
        )?;
        state.geometry(source);
        Some(video::pipeline(state.clone(), caps, source))
    } else {
        None
    };
    // The handshake's grant goes through the gate rather than beside it: it is
    // the same permission channel a later message changes, so it is published
    // under the lock that stamps input, and turning it off and on again cannot
    // leave input admitted under either of the older states.
    state
        .input
        .grant(mode == SessionMode::Desktop && parts.context.permissions.keyboard);
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
    // The handshake's own clipboard grant, mirrored beside the local switches:
    // the fence is the AND of them, and it can only open now because those facts
    // only exist now. An omitted report keeps upstream's viewer default, which is
    // exactly what `permissions` already holds, and a host-side permission is
    // never read as this viewer's own.
    state.peer_clipboard.store(
        mode == SessionMode::Desktop && parts.context.permissions.clipboard,
        Ordering::Release,
    );
    state
        .peer_file
        .store(parts.context.permissions.file, Ordering::Release);
    // The handshake's own audio grant, mirrored in the same shape. The audio
    // owner started below plays only the AND of this grant with the local
    // option, so a peer that merely has audio enabled is not heard until this
    // session asks for it, and this side never raises the peer's grant itself.
    state.peer_audio.store(
        mode == SessionMode::Desktop && parts.context.permissions.audio,
        Ordering::Release,
    );
    let file_clipboard =
        (mode == SessionMode::Desktop).then(|| crate::cliprdr::start(state.cancel.clone()));
    if let Some(start) = &file_clipboard {
        *lock(&state.cliprdr) = Some(Arc::clone(&start.handle));
    }
    state.refresh_clipboard();
    state.phase(if mode == SessionMode::FileTransfer {
        "file_transfer_ready"
    } else {
        "authenticated"
    });
    let info = parts
        .context
        .peer_info
        .as_ref()
        .ok_or(ViewerError::AuthenticationFailed)?;
    let transfer = crate::transfer::start(
        crate::transfer::TransferConfig::new(transfer_root, &info.platform, &info.version),
        state.cancel.clone(),
    );
    let transfer_handle = Arc::new(transfer.handle);
    transfer_handle.set_enabled(parts.context.permissions.file);
    *lock(&state.transfer) = Some(transfer_handle);
    // This session's audio playback: one shared handle for the wire and one
    // owner for the device. It is started only here — after authentication and
    // after the last fallible step of the handshake — and only on the wire that
    // carries audio, so a session that never plays audio never creates one.
    let audio = (mode == SessionMode::Desktop).then(|| crate::audio::start(state.cancel.clone()));
    if let Some(start) = &audio {
        *lock(&state.audio) = Some(Arc::clone(&start.handle));
    }
    // Published from the facts that arrived above: a session whose option or
    // whose peer refuses audio starts an owner that waits, not one that plays.
    state.refresh_audio();
    let (control_tx, control_rx) = mpsc::channel(COMMANDS);
    *lock(&state.control) = Some(control_tx.clone());
    // The clipboard reaches the wire through this same writer, on its own
    // bounded channel: a payload is a value the writer either writes or drops,
    // never a second socket, runtime or writer.
    let (clipboard_tx, clipboard_rx) = mpsc::channel(CLIPBOARD_QUEUE);
    *lock(&state.clipboard_out) = Some(clipboard_tx);
    let mut tasks = JoinSet::new();
    let (file_clipboard_owner, file_clipboard_out) = match file_clipboard {
        Some(start) => (Some(start.owner), Some(start.outbound)),
        None => (None, None),
    };
    // Move the optional media pair once; the file role owns no feed or Surface.
    let (admission, feed) = match media {
        Some((admission, feed)) => (Some(admission), Some(feed)),
        None => (None, None),
    };
    tasks.spawn(receive(
        state.clone(),
        parts.reader,
        admission,
        control_tx,
        transfer.inbound,
    ));
    tasks.spawn(write(
        state.clone(),
        parts.writer,
        mouse,
        control_rx,
        transfer.outbound,
        clipboard_rx,
        file_clipboard_out,
    ));
    // The clipboard decode is a task in this same set, not a `spawn_blocking`
    // call the reader throws away: every decode is joined here before the run is
    // over, so a close cannot be acknowledged over a decode still in flight, and
    // the reader only ever hands the message over.
    tasks.spawn(clipboard_decode(state.clone()));
    if let Some(start) = audio {
        // The sink this owner drives is not `Send`: it is created, run and
        // destroyed on one blocking worker of this same runtime — never
        // `tokio::spawn`, never a second runtime, never a detached thread.
        //
        // Its answer is a worker's, not the session's. An audio device that
        // cannot be opened, or a native stream whose release cannot be
        // confirmed, must not end a live remote-control wire, so the result is
        // held here and joined only once this session itself has ended. What it
        // reports then is the one fact the final close has to see — an
        // unconfirmed reclamation — read from the audio core's own flag instead
        // of assumed, so a failure cannot be swallowed into a clean close.
        let runtime = tokio::runtime::Handle::current();
        let cancel = state.cancel.clone();
        let reclamation = Arc::clone(&start.handle);
        let owner = start.owner;
        tasks.spawn_blocking(move || {
            let outcome = runtime.block_on(owner.run());
            if !cancel.is_cancelled() {
                runtime.block_on(cancel.cancelled());
            }
            match outcome {
                Ok(()) if !reclamation.snapshot().resources_unconfirmed => Ok(()),
                _ => Err(ViewerError::ReclamationUnconfirmed),
            }
        });
    }
    if let Some(owner) = file_clipboard_owner {
        // This owner performs bounded synchronous filesystem work. Keep that
        // work off the IO workers, but join it in this same session set using
        // the existing runtime, never a second runtime or detached disk task.
        let runtime = tokio::runtime::Handle::current();
        tasks.spawn_blocking(move || match runtime.block_on(owner.run()) {
            crate::cliprdr::CliprdrExit::Cancelled => Ok(()),
            _ => Err(ViewerError::Closed),
        });
    }
    tasks.spawn(async move {
        match transfer.owner.run().await {
            crate::transfer::TransferExit::Cancelled => Ok(()),
            _ => Err(ViewerError::Closed),
        }
    });
    if let Some(feed) = feed {
        tasks.spawn(feed.run(lease));
    }
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
    let mut only_close_fallout = matches!(
        &first,
        Ok(())
            | Err(ViewerError::RemoteClosed | ViewerError::TransportFailed | ViewerError::Closed)
    );
    let mut result = first;
    // Never abort the feeder: it owns the native decoder and its blocking join.
    while let Some(joined) = tasks.join_next().await {
        let next = joined.unwrap_or(Err(ViewerError::TaskFailed));
        if let Err(error) = next {
            only_close_fallout &= matches!(
                &error,
                ViewerError::RemoteClosed | ViewerError::TransportFailed | ViewerError::Closed
            );
            // A teardown failure must reach HAR even when localClose was first.
            if result.is_ok()
                || matches!(
                    &error,
                    ViewerError::Decoder(DecoderError::DestroyFailed { .. })
                )
                || (matches!(&error, ViewerError::ReclamationUnconfirmed)
                    && !matches!(
                        &result,
                        Err(ViewerError::Decoder(DecoderError::DestroyFailed { .. }))
                    ))
                || (matches!(
                    &result,
                    Err(ViewerError::RemoteClosed
                        | ViewerError::TransportFailed
                        | ViewerError::Closed)
                ) && !matches!(
                    &error,
                    ViewerError::RemoteClosed | ViewerError::TransportFailed | ViewerError::Closed
                ) && lock(&state.inner).observed_peer_close_reason
                    == Some(PeerCloseReason::ManualRequest))
            {
                result = Err(error);
            }
        }
    }
    if only_close_fallout
        && !state.resources_unconfirmed_any()
        && lock(&state.inner).observed_peer_close_reason == Some(PeerCloseReason::ManualRequest)
    {
        return Err(ViewerError::RemoteClosed);
    }
    result
}

async fn receive(
    state: Arc<State>,
    mut reader: WireReader,
    mut admission: Option<video::VideoAdmission<State>>,
    control: mpsc::Sender<Vec<Message>>,
    transfer: mpsc::Sender<crate::transfer::Inbound>,
) -> Result<(), ViewerError> {
    loop {
        let message = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => return Ok(()),
            result = reader.recv() => result.map_err(|_| ViewerError::TransportFailed)?.ok_or(ViewerError::RemoteClosed)?,
        };
        match message.union {
            Some(message::Union::VideoFrame(frame)) => {
                if let Some(admission) = admission.as_mut() {
                    if admission.admit(frame).await? == video::Admitted::Cancelled {
                        return Ok(());
                    }
                }
            }
            // The peer's audio goes to this session's own audio owner and
            // nowhere else: no decode, no copy, no per-packet task and no wait
            // here. A refused packet — muted, no format yet, or a full queue —
            // is the owner's to count, and it cannot affect video, clipboard or
            // input.
            Some(message::Union::AudioFrame(frame)) => {
                state.offer_audio_frame(frame);
            }
            Some(message::Union::CursorData(data)) => state.cursor_data(data),
            Some(message::Union::CursorId(id)) => state.cursor_id(id),
            Some(message::Union::CursorPosition(position)) => state.cursor_position(position),
            Some(message::Union::FileAction(action)) => {
                tokio::select! {
                    biased;
                    _ = state.cancel.cancelled() => return Ok(()),
                    sent = transfer.send(crate::transfer::Inbound::Action(action)) => {
                        sent.map_err(|_| ViewerError::Closed)?;
                    }
                }
            }
            Some(message::Union::FileResponse(response)) => {
                tokio::select! {
                    biased;
                    _ = state.cancel.cancelled() => return Ok(()),
                    sent = transfer.send(crate::transfer::Inbound::Response(response)) => {
                        sent.map_err(|_| ViewerError::Closed)?;
                    }
                }
            }
            Some(message::Union::TestDelay(probe)) => {
                if !probe.from_client {
                    if probe.last_delay > 0 {
                        lock(&state.inner).snapshot.network_rtt_ms = Some(probe.last_delay);
                    }
                    let mut response = Message::new();
                    response.set_test_delay(probe);
                    control
                        .try_send(vec![response])
                        .map_err(|_| ViewerError::Backpressure)?;
                }
            }
            // Clipboard content is handed to this viewer's decode worker and
            // never decoded here: the reader stays responsive whatever size the
            // peer sends, and the permission generation is captured before the
            // decode runs.
            Some(message::Union::Clipboard(clipboard)) => {
                state.offer_clipboard(ClipboardMessage::Single(clipboard));
            }
            Some(message::Union::MultiClipboards(multi)) => {
                state.offer_clipboard(ClipboardMessage::Multi(multi));
            }
            Some(message::Union::Cliprdr(message)) => {
                let handle = lock(&state.cliprdr).clone();
                if let Some(handle) = handle {
                    // The one reader stamps before waiting for queue space.
                    // Even withdrawn traffic must reach the owner so a late
                    // descriptor answer can retire its no-ID protocol slot.
                    tokio::select! {
                        biased;
                        _ = state.cancel.cancelled() => return Ok(()),
                        sent = handle.offer_inbound(message) => {
                            sent.map_err(|_| ViewerError::Closed)?;
                        }
                    }
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
                        state
                            .input
                            .grant(state.mode == SessionMode::Desktop && permission.enabled);
                    }
                    if permission.permission.enum_value().ok() == Some(Permission::File) {
                        state.peer_file.store(permission.enabled, Ordering::Release);
                        if let Some(handle) = lock(&state.transfer).as_ref() {
                            handle.set_enabled(permission.enabled);
                        }
                        state.refresh_clipboard();
                    }
                    if permission.permission.enum_value().ok() == Some(Permission::Clipboard) {
                        // The peer's own clipboard grant, mirrored and then
                        // combined with the local facts. A withdrawal closes the
                        // fence in both directions and empties what was waiting;
                        // this side never re-grants on its own, so turning the
                        // local read-only switch off cannot recover a grant the
                        // peer took away.
                        state.peer_clipboard.store(
                            state.mode == SessionMode::Desktop && permission.enabled,
                            Ordering::Release,
                        );
                        state.refresh_clipboard();
                    }
                    if permission.permission.enum_value().ok() == Some(Permission::Audio) {
                        // The peer's own audio grant, mirrored and then combined
                        // with the local facts. A withdrawal stops playback where
                        // it is: the owner closes its sink, and nothing decoded
                        // under the previous allowance can be pushed afterwards.
                        // This side never re-grants on its own either, so turning
                        // the local option off and on again cannot recover what
                        // the peer took away.
                        state.peer_audio.store(
                            state.mode == SessionMode::Desktop && permission.enabled,
                            Ordering::Release,
                        );
                        state.refresh_audio();
                    }
                }
                Some(misc::Union::AudioFormat(format)) => {
                    // The format the peer declares for the audio it is about to
                    // send, handed to the same owner the frames go to. It is
                    // stored rather than queued inside that core, so a full
                    // packet queue cannot lose it, and an impossible format is
                    // refused and recorded there instead of being decoded.
                    state.offer_audio_format(format);
                }
                Some(misc::Union::CloseReason(reason)) => {
                    lock(&state.inner).observed_peer_close_reason = PeerCloseReason::of(&reason);
                    return Err(ViewerError::RemoteClosed);
                }
                Some(misc::Union::SwitchDisplay(display)) => {
                    if let Some(admission) = admission.as_mut() {
                        admission.switch_display(&display)?;
                        // Only a real peer confirmation changes peer geometry.
                        // Local renderer sizing never enters this branch.
                        let mut inner = lock(&state.inner);
                        let peer = inner.snapshot.displays.get_mut(display.display as usize)
                            .ok_or(ViewerError::InvalidPeerGeometry)?;
                        peer.width = display.width;
                        peer.height = display.height;
                        peer.x = display.x;
                        peer.y = display.y;
                        inner.snapshot.current_display = display.display;
                    }
                }
                _ => {}
            },
            // Informational messages neither authorize input nor fake video
            // state. Cursor, clipboard and audio have their own owners above.
            _ => {}
        }
    }
}

/// The one worker that decodes this viewer's clipboard messages.
///
/// It runs as a task in the session's own `JoinSet`, so the run cannot end while
/// a decode is still in flight: the close is acknowledged only after this
/// returns. Each decode runs on a blocking worker and its handle is awaited
/// rather than dropped, and the mailbox it delivers into refuses anything that
/// outlived the generation it was read under.
async fn clipboard_decode(state: Arc<State>) -> Result<(), ViewerError> {
    loop {
        let (generation, message) = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => return Ok(()),
            job = state.clipboard_in.next() => job,
        };
        clipboard_decode_once(&state, generation, message).await?;
    }
}

/// One decode step, joined by its caller.
///
/// The inflation is real CPU work, so it runs on a blocking worker; the handle is
/// awaited instead of dropped, which is what makes the join real when the run's
/// teardown reaches this task. Nothing here decides whether the result is wanted —
/// the mailbox does, from the generation the message was offered under.
async fn clipboard_decode_once(
    state: &State,
    generation: u64,
    message: ClipboardMessage,
) -> Result<(), ViewerError> {
    let decoded = tokio::task::spawn_blocking(move || match message {
        ClipboardMessage::Single(clipboard) => crate::clipboard::decode_clipboard(clipboard),
        ClipboardMessage::Multi(multi) => crate::clipboard::decode_multi_clipboards(multi),
    })
    .await
    .map_err(|_| ViewerError::TaskFailed)?;
    match decoded {
        // The mailbox decides whether this decode is still wanted: a withdrawal,
        // a fresh grant or a close between the read and here leaves its
        // generation behind, and the update is refused rather than applied to
        // the generation in force now.
        Ok(Some(payload)) => {
            let _ = state.clipboard.accept_peer(generation, payload);
        }
        // A format this build does not know, or the peer's own ownership marker.
        Ok(None) => {}
        // One unreadable message is one refused update, never a broken session.
        Err(_error) => {}
    }
    Ok(())
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
    mut control: mpsc::Receiver<Vec<Message>>,
    mut bulk: mpsc::Receiver<crate::transfer::Outbound>,
    mut clipboard: mpsc::Receiver<QueuedClipboard>,
    mut file_clipboard: Option<mpsc::Receiver<crate::cliprdr::CliprdrEffect>>,
) -> Result<(), ViewerError> {
    let mut held = RustDeskHeld::default();
    let outcome = write_loop(
        &state,
        &mut writer,
        &mut mouse,
        &mut control,
        &mut bulk,
        &mut clipboard,
        &mut file_clipboard,
        &mut held,
    )
    .await;
    // The transport stops with the writer, so nothing it still held can be
    // released through it any more. Those holds are reported as releases whose
    // completion is unconfirmed: whether the peer still holds a key or button is
    // unknown, so no claim is made that a release arrived or that it did not.
    state.input.stopped();
    outcome
}

/// One loop over the writer's own channels: session messages, queued input,
/// queued clipboard payloads, and the policy changes that must be answered
/// before either.
async fn write_loop(
    state: &State,
    writer: &mut WireWriter,
    mouse: &mut mpsc::Receiver<QueuedInput>,
    control: &mut mpsc::Receiver<Vec<Message>>,
    bulk: &mut mpsc::Receiver<crate::transfer::Outbound>,
    clipboard: &mut mpsc::Receiver<QueuedClipboard>,
    file_clipboard: &mut Option<mpsc::Receiver<crate::cliprdr::CliprdrEffect>>,
    held: &mut RustDeskHeld,
) -> Result<(), ViewerError> {
    let mut clipboard_first = false;
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
                Some(messages) => {
                    for message in messages {
                        wire_send(state, writer, &message).await?;
                    }
                }
                None => return Ok(()),
            },
            value = mouse.recv() => match value {
                Some(queued) => take_input(state, writer, held, queued).await?,
                None => return Ok(()),
            },
            // The clipboard comes after input, under this loop's `biased`
            // ordering: a key or button already queued is taken before an image,
            // so the one message this writer can spend seconds on never makes the
            // operator's own event wait behind it. A payload refused here was
            // never written, and the fence is asked again when it is taken.
            value = clipboard.recv() => match value {
                Some(queued) => take_clipboard(state, writer, queued).await?,
                None => return Ok(()),
            },
            value = next_file_effect(bulk, file_clipboard, clipboard_first) => match value {
                FileEffect::Transfer(Some(effect)) => {
                    clipboard_first = true;
                    let result = if effect.is_permitted() {
                        wire_send(state, writer, effect.message()).await
                    } else {
                        Ok(false)
                    };
                    effect.complete(result.as_ref().copied().unwrap_or(false));
                    result?;
                }
                FileEffect::Clipboard(Some(effect)) => {
                    clipboard_first = false;
                    let result = if state.file_clipboard_facts() && effect.is_permitted() {
                        wire_send(state, writer, effect.message()).await
                    } else {
                        Ok(false)
                    };
                    // A queued or failed/unknown send is never a written ACK.
                    effect.complete(result.as_ref().copied().unwrap_or(false));
                    result?;
                }
                FileEffect::Transfer(None) | FileEffect::Clipboard(None) => return Ok(()),
            },
        }
    }
}

enum FileEffect {
    Transfer(Option<crate::transfer::Outbound>),
    Clipboard(Option<crate::cliprdr::CliprdrEffect>),
}

async fn next_cliprdr(
    receiver: &mut Option<mpsc::Receiver<crate::cliprdr::CliprdrEffect>>,
) -> Option<crate::cliprdr::CliprdrEffect> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// Rotate the two bulk producers without giving either a second socket writer.
/// Session control and input still precede this single branch in the outer loop.
async fn next_file_effect(
    transfer: &mut mpsc::Receiver<crate::transfer::Outbound>,
    clipboard: &mut Option<mpsc::Receiver<crate::cliprdr::CliprdrEffect>>,
    clipboard_first: bool,
) -> FileEffect {
    if clipboard_first {
        tokio::select! {
            biased;
            value = next_cliprdr(clipboard) => FileEffect::Clipboard(value),
            value = transfer.recv() => FileEffect::Transfer(value),
        }
    } else {
        tokio::select! {
            biased;
            value = transfer.recv() => FileEffect::Transfer(value),
            value = next_cliprdr(clipboard) => FileEffect::Clipboard(value),
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

/// Writes one queued clipboard payload, or drops it.
///
/// The permission is asked again here, at the writer that owns the wire, and it
/// is asked as two facts a payload cannot substitute for: what is allowed right
/// now, and whether the generation this payload was queued under is still the
/// one in force. A payload queued before a withdrawal, a read-only switch, a
/// `disable-clipboard` change or a close therefore owns nothing and is dropped
/// without being written; one the current generation still admits is the only
/// thing that reaches the wire.
///
/// Nothing here waits for the peer. The original wire has no clipboard
/// acknowledgement — upstream applies what it receives — so a write is the end of
/// this side's responsibility, and the receipt a client got said "queued", which
/// is exactly what was true.
async fn take_clipboard(
    state: &State,
    writer: &mut WireWriter,
    queued: QueuedClipboard,
) -> Result<(), ViewerError> {
    if !state.clipboard_write_allowed(queued.generation) {
        return Ok(());
    }
    wire_send(state, writer, &queued.message).await?;
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

    fn present(&mut self) -> Result<bool, crate::surface::SurfaceError> {
        match self {
            #[cfg(target_env = "ohos")]
            Self::Surface(surface) => surface.present(),
            #[cfg(not(target_env = "ohos"))]
            Self::Memory(surface) => {
                Ok(surface.take_damage().is_some())
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
                (
                    x.clamp(0, i32::from(u16::MAX)) as u16,
                    y.clamp(0, i32::from(u16::MAX)) as u16,
                )
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
    }
    .await;
    state.input.stopped();
    let closed = session.close().await.map_err(rfb_error);
    finish_rectangle(&state, streaming, closed)
}

fn rectangle_authenticated(state: &State, (width, height): (i32, i32)) {
    state.route("direct_tcp");
    state.desktop_geometry(Geometry {
        display: 0,
        x: 0,
        y: 0,
        width,
        height,
    });
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

async fn present_sink(state: &State, surface: &mut Option<Sink>) -> Result<(), ViewerError> {
    // Never cancel this worker: it temporarily owns the native sink. A panic
    // leaves None and the owner's reclamation flag remains unconfirmed.
    let mut taken = surface.take().ok_or(ViewerError::TaskFailed)?;
    let presentation = state.presentation.clone();
    let returning = tokio::task::spawn_blocking(move || {
        let (width, height) = crate::protocol::rect::PixelTarget::size(&taken);
        let ticket = presentation.as_ref().and_then(|owner| owner.begin_output(width, height));
        if presentation.is_some() && ticket.is_none() {
            // Keep the same upstream framebuffer AND its accumulated damage.
            return (taken, Ok(false));
        }
        let result = taken.present();
        if matches!(result, Ok(true)) {
            if let (Some(owner), Some(ticket)) = (presentation, ticket) {
                owner.submitted(ticket);
            }
        }
        (taken, result)
    });
    let (returned, presented) = returning.await.map_err(|_| ViewerError::TaskFailed)?;
    *surface = Some(returned);
    presented.map(|_| ()).map_err(|_| ViewerError::UnsupportedPlatform)
}

async fn presentation_changed(state: &State) {
    match &state.presentation {
        Some(owner) => owner.changed().await,
        None => std::future::pending().await,
    }
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
            _ = presentation_changed(state) => {
                present_sink(state, surface).await?;
                continue;
            }
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
            Some(RfbEvent::Painted) => present_sink(state, surface).await?,
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
                present_sink(state, surface).await?;
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
        RfbError::PasswordTooLong
        | RfbError::CredentialUnavailable
        | RfbError::NoUsableSecurityType => {
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
        let release = if down {
            KeyboardFlags::empty()
        } else {
            KeyboardFlags::RELEASE
        };
        match self {
            Self::Scan(code, flags) => FastPathInputEvent::KeyboardEvent(flags | release, code),
            Self::Unicode(code) => FastPathInputEvent::UnicodeKeyboardEvent(release, code),
        }
    }

    fn identity(self) -> u32 {
        match self {
            Self::Scan(code, flags) => {
                0x8000_0000 | (u32::from(flags.bits()) << 8) | u32::from(code)
            }
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
                flags: (if button == 8 {
                    PointerXFlags::BUTTON1
                } else {
                    PointerXFlags::BUTTON2
                }) | if down {
                    PointerXFlags::DOWN
                } else {
                    PointerXFlags::empty()
                },
                x_position: x,
                y_position: y,
            }),
            Self::Button(button) => FastPathInputEvent::MouseEvent(MousePdu {
                flags: (match button {
                    1 => PointerFlags::LEFT_BUTTON,
                    2 => PointerFlags::RIGHT_BUTTON,
                    _ => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                }) | if down {
                    PointerFlags::DOWN
                } else {
                    PointerFlags::empty()
                },
                number_of_wheel_rotation_units: 0,
                x_position: x,
                y_position: y,
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
        Self {
            entries: [(0, RdpHold::Button(0)); MAX_HELD_INPUTS as usize],
            len: 0,
            pointer: (0, 0),
            relative: false,
        }
    }
}

impl RdpHeld {
    fn position(&self, identity: u32) -> Option<usize> {
        self.entries[..self.len]
            .iter()
            .position(|(_, hold)| hold.identity() == identity)
    }

    fn remove(&mut self, index: usize) -> u64 {
        let generation = self.entries[index].0;
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        generation
    }

    fn release_event(&self, index: usize) -> FastPathInputEvent {
        match self.entries[index].1 {
            RdpHold::Button(button) if self.relative => {
                FastPathInputEvent::MouseEventRel(MouseRelPdu {
                    // After relative motion the old absolute point is not the
                    // server's current pointer. Release in place, without a warp.
                    flags: match button {
                        1 => PointerRelFlags::BUTTON1,
                        2 => PointerRelFlags::BUTTON2,
                        4 => PointerRelFlags::BUTTON3,
                        8 => PointerRelFlags::XBUTTON1,
                        _ => PointerRelFlags::XBUTTON2,
                    },
                    x_delta: 0,
                    y_delta: 0,
                })
            }
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
            events: [FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), 0);
                RDP_INPUT_EVENTS],
            len: 0,
            held: *held,
            peak: held.len,
            generation,
        }
    }

    fn push(&mut self, event: FastPathInputEvent) -> Result<(), ViewerError> {
        let slot = self
            .events
            .get_mut(self.len)
            .ok_or(ViewerError::InputNotAllowed)?;
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
                let slot = self
                    .held
                    .entries
                    .get_mut(self.held.len)
                    .ok_or(ViewerError::Backpressure)?;
                *slot = (self.generation, hold);
                self.held.len += 1;
                self.peak = self.peak.max(self.held.len);
            }
            (false, Some(index)) => {
                self.held.remove(index);
            }
            _ => {}
        }
        Ok(())
    }

    fn key(&mut self, identity: u32, key: RdpKey, down: bool) -> Result<(), ViewerError> {
        self.transition(RdpHold::Key { identity, key }, down)
    }
}

fn rdp_scan(code: u8, extended: bool) -> RdpKey {
    RdpKey::Scan(
        code,
        if extended {
            KeyboardFlags::EXTENDED
        } else {
            KeyboardFlags::empty()
        },
    )
}

fn rdp_control(key: proto::ControlKey) -> Result<RdpKey, ViewerError> {
    use proto::ControlKey as C;
    let (code, extended) = match key {
        C::Escape => (0x01, false),
        C::Backspace => (0x0e, false),
        C::Tab => (0x0f, false),
        C::Return => (0x1c, false),
        C::Control => (0x1d, false),
        C::Shift => (0x2a, false),
        C::RShift => (0x36, false),
        C::Alt => (0x38, false),
        C::Space => (0x39, false),
        C::CapsLock => (0x3a, false),
        C::F1 => (0x3b, false),
        C::F2 => (0x3c, false),
        C::F3 => (0x3d, false),
        C::F4 => (0x3e, false),
        C::F5 => (0x3f, false),
        C::F6 => (0x40, false),
        C::F7 => (0x41, false),
        C::F8 => (0x42, false),
        C::F9 => (0x43, false),
        C::F10 => (0x44, false),
        C::F11 => (0x57, false),
        C::F12 => (0x58, false),
        C::NumLock => (0x45, false),
        C::Scroll => (0x46, false),
        C::Numpad7 => (0x47, false),
        C::Numpad8 => (0x48, false),
        C::Numpad9 => (0x49, false),
        C::Numpad4 => (0x4b, false),
        C::Numpad5 => (0x4c, false),
        C::Numpad6 => (0x4d, false),
        C::Numpad1 => (0x4f, false),
        C::Numpad2 => (0x50, false),
        C::Numpad3 => (0x51, false),
        C::Numpad0 => (0x52, false),
        C::Decimal => (0x53, false),
        C::Multiply => (0x37, false),
        C::Subtract => (0x4a, false),
        C::Add => (0x4e, false),
        C::Equals => (0x0d, false),
        C::NumpadEnter => (0x1c, true),
        C::RControl => (0x1d, true),
        C::Divide => (0x35, true),
        C::Snapshot => (0x37, true),
        C::RAlt => (0x38, true),
        C::Home => (0x47, true),
        C::UpArrow => (0x48, true),
        C::PageUp => (0x49, true),
        C::LeftArrow => (0x4b, true),
        C::RightArrow => (0x4d, true),
        C::End => (0x4f, true),
        C::DownArrow => (0x50, true),
        C::PageDown => (0x51, true),
        C::Insert => (0x52, true),
        C::Delete => (0x53, true),
        C::Meta => (0x5b, true),
        C::RWin => (0x5c, true),
        C::Apps => (0x5d, true),
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
        0xff08 => C::Backspace,
        0xff09 => C::Tab,
        0xff0d => C::Return,
        0xff1b => C::Escape,
        0xff50 => C::Home,
        0xff51 => C::LeftArrow,
        0xff52 => C::UpArrow,
        0xff53 => C::RightArrow,
        0xff54 => C::DownArrow,
        0xff55 => C::PageUp,
        0xff56 => C::PageDown,
        0xff57 => C::End,
        0xff63 => C::Insert,
        0xffff => C::Delete,
        0xffe1 => C::Shift,
        0xffe2 => C::RShift,
        0xffe3 => C::Control,
        0xffe4 => C::RControl,
        0xffe5 => C::CapsLock,
        0xffe9 => C::Alt,
        0xffea => C::RAlt,
        0xffeb => C::Meta,
        0xffec => C::RWin,
        0xffbe => C::F1,
        0xffbf => C::F2,
        0xffc0 => C::F3,
        0xffc1 => C::F4,
        0xffc2 => C::F5,
        0xffc3 => C::F6,
        0xffc4 => C::F7,
        0xffc5 => C::F8,
        0xffc6 => C::F9,
        0xffc7 => C::F10,
        0xffc8 => C::F11,
        0xffc9 => C::F12,
        _ => return Err(ViewerError::InputNotAllowed),
    })?;
    Ok((key.identity(), key, false))
}

fn rdp_modifier(key: proto::ControlKey) -> Result<RdpKey, ViewerError> {
    use proto::ControlKey as C;
    match key {
        C::Shift | C::RShift | C::Control | C::RControl | C::Alt | C::RAlt | C::Meta | C::RWin => {
            rdp_control(key)
        }
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
    if event.mode.enum_value().ok() != Some(proto::KeyboardMode::Legacy)
        || event.modifiers.len() > 8
    {
        return Err(ViewerError::InputNotAllowed);
    }
    for modifier in &event.modifiers {
        rdp_modifier(
            modifier
                .enum_value()
                .map_err(|_| ViewerError::InputNotAllowed)?,
        )?;
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
    if event.mode.enum_value().ok() != Some(proto::KeyboardMode::Legacy)
        || event.modifiers.len() > 8
    {
        return Err(ViewerError::InputNotAllowed);
    }
    let mut batch = RdpBatch::new(held, 0);
    if let Some(Union::Seq(text)) = &event.union {
        if text.is_empty() || !event.modifiers.is_empty() || text.len() > RDP_INPUT_EVENTS * 2 {
            return Err(ViewerError::InputNotAllowed);
        }
        for unit in text.encode_utf16() {
            if unit == 0 {
                return Err(ViewerError::InputNotAllowed);
            }
            // Text must stay Unicode even if a physical shortcut key with the
            // same character identity is held. If this Unicode key itself is
            // held, its tap really releases it and the ledger records that.
            let identity = batch.held.entries[..batch.held.len]
                .iter()
                .find_map(|(_, hold)| match hold {
                    RdpHold::Key {
                        identity,
                        key: RdpKey::Unicode(value),
                    } if *value == unit => Some(*identity),
                    _ => None,
                })
                .unwrap_or(0x2000_0000 | u32::from(unit));
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
            let character = char::from_u32(*value)
                .filter(|c| !c.is_control())
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
        let key = rdp_modifier(
            modifier
                .enum_value()
                .map_err(|_| ViewerError::InputNotAllowed)?,
        )?;
        if (event.down || event.press)
            && key.identity() != identity
            && batch.held.position(key.identity()).is_none()
        {
            batch.key(key.identity(), key, true)?;
            temporary[index] = Some(key);
        }
    }
    let shift_key = rdp_scan(0x2a, false);
    if (event.down || event.press)
        && shift
        && batch.held.position(shift_key.identity()).is_none()
        && batch
            .held
            .position(rdp_scan(0x36, false).identity())
            .is_none()
    {
        batch.key(shift_key.identity(), shift_key, true)?;
        temporary[8] = Some(shift_key);
    }
    batch.key(identity, key, event.down || event.press)?;
    if event.press {
        batch.key(identity, key, false)?;
    }
    for key in temporary.into_iter().rev().flatten() {
        batch.key(key.identity(), key, false)?;
    }
    Ok(batch)
}

fn rdp_mouse(
    kind: u32,
    button: u32,
    x: i32,
    y: i32,
    pointer: (u16, u16),
) -> Result<RdpBatch, ViewerError> {
    let mut batch = RdpBatch::new(&RdpHeld::default(), 0);
    batch.held.pointer = pointer;
    match kind {
        0..=2 => {
            let px = u16::try_from(x).map_err(|_| ViewerError::InvalidMouse)?;
            let py = u16::try_from(y).map_err(|_| ViewerError::InvalidMouse)?;
            batch.held.pointer = (px, py);
            if kind == 0 && button == 0 {
                batch.push(FastPathInputEvent::MouseEvent(MousePdu {
                    flags: PointerFlags::MOVE,
                    number_of_wheel_rotation_units: 0,
                    x_position: px,
                    y_position: py,
                }))?;
            } else if kind != 0 && matches!(button, 1 | 2 | 4 | 8 | 16) {
                batch.transition(RdpHold::Button(button), kind == 1)?;
            } else {
                return Err(ViewerError::InvalidMouse);
            }
        }
        3 | 4 if button == 0 && (x != 0 || y != 0) => {
            // Original wheel units are notches; trackpad units are eighths.
            // RDP uses 120 units/notch with each PDU bounded to [-256,255].
            let scale = if kind == 3 { 120 } else { 15 };
            let horizontal = x.checked_mul(scale).ok_or(ViewerError::InvalidMouse)?;
            let vertical = y.checked_mul(-scale).ok_or(ViewerError::InvalidMouse)?;
            let count = |value: i32| {
                u64::from(value.unsigned_abs()).div_ceil(if value < 0 { 256 } else { 255 })
            };
            if count(horizontal) + count(vertical) > RDP_INPUT_EVENTS as u64 {
                return Err(ViewerError::InvalidMouse);
            }
            for (mut units, flags) in [
                (horizontal, PointerFlags::HORIZONTAL_WHEEL),
                (vertical, PointerFlags::VERTICAL_WHEEL),
            ] {
                while units != 0 {
                    let part = units.clamp(-256, 255);
                    batch.push(FastPathInputEvent::MouseEvent(MousePdu {
                        flags,
                        number_of_wheel_rotation_units: part as i16,
                        x_position: pointer.0,
                        y_position: pointer.1,
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
    crate::protocol::rdp::validate_input_flags(flags, events)
        .map_err(|_| ViewerError::InputNotAllowed)
}

fn rdp_input_capabilities(state: &State, session: &crate::protocol::rdp::RdpSession) {
    let flags = session.input_flags();
    state.rdp_input_flags.store(flags.bits(), Ordering::Release);
    // Reuse the adapter's actual checks rather than treating the client-side
    // advertised flags as a grant. Unknown/reactivating input retires old holds.
    let keyboard =
        crate::protocol::rdp::validate_input_flags(flags, &[rdp_scan(0x1e, false).event(true)])
            .is_ok()
            || crate::protocol::rdp::validate_input_flags(
                flags,
                &[RdpKey::Unicode(0x61).event(true)],
            )
            .is_ok();
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
        if admitted && generation == gate.generation {
            index += 1;
            continue;
        }
        if !rdp_send(state, session, &[held.release_event(index)]).await? {
            return Ok(());
        }
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
        if queued.generation != gate.generation || !Facts::of(state).admits(gate) {
            return Ok(());
        }
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
        if rdp_preflight(state, &batch.events[..batch.len]).is_err() {
            return Ok(());
        }
        let adds = batch.peak - held.len;
        if state
            .input
            .own_many(queued.generation, adds as u64, &Facts::of(state))
        {
            break batch;
        }
        // A revoke/regrant can race the release pass itself. Never adopt a
        // retired hold: settle it and prepare the still-current event again.
        if state.input.read().retired == 0 {
            return Ok(());
        }
    };
    if !rdp_send(state, session, &batch.events[..batch.len]).await? {
        return Ok(());
    }
    // A cancelled/failed write keeps the reservation unconfirmed on stop.
    let released = batch.peak - batch.held.len;
    *held = batch.held;
    for _ in 0..released {
        state.input.released(queued.generation);
    }
    Ok(())
}

fn rdp_batch(held: &RdpHeld, queued: &QueuedInput) -> Result<RdpBatch, ViewerError> {
    let mut batch = match &queued.event {
        ViewerInput::RustDeskKey { event } => rdp_legacy(event, held)?,
        ViewerInput::Key { keysym, down } => {
            let (identity, key, shift) = rdp_keysym(*keysym)?;
            let mut batch = RdpBatch::new(held, queued.generation);
            let shift_key = rdp_scan(0x2a, false);
            let temporary_shift = *down
                && shift
                && batch.held.position(shift_key.identity()).is_none()
                && batch
                    .held
                    .position(rdp_scan(0x36, false).identity())
                    .is_none();
            if temporary_shift {
                batch.key(shift_key.identity(), shift_key, true)?;
            }
            batch.key(identity, key, *down)?;
            if temporary_shift {
                batch.key(shift_key.identity(), shift_key, false)?;
            }
            batch
        }
        ViewerInput::Mouse { kind, button, x, y } => {
            let mouse = rdp_mouse(*kind, *button, *x, *y, held.pointer)?;
            let mut batch = RdpBatch::new(held, queued.generation);
            batch.held.pointer = mouse.held.pointer;
            if *kind <= 2 {
                batch.held.relative = false;
            }
            if *kind == 5 {
                batch.held.relative = true;
            }
            if matches!(*kind, 1 | 2) {
                batch.transition(RdpHold::Button(*button), *kind == 1)?;
            } else {
                for event in &mouse.events[..mouse.len] {
                    batch.push(*event)?;
                }
            }
            batch
        }
    };
    // Preparation may have used generation zero for synchronous validation;
    // only newly added holds get this event's actual (never refreshed) stamp.
    for (generation, _) in &mut batch.held.entries[..batch.held.len] {
        if *generation == 0 {
            *generation = queued.generation;
        }
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
    }
    .await;
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
            _ = presentation_changed(state) => {
                present_sink(state, surface).await?;
                continue;
            }
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
            Some(RdpEvent::Painted) => present_sink(state, surface).await?,
            Some(RdpEvent::Desktop { width, height }) => {
                state.desktop_geometry(Geometry {
                    display: 0,
                    x: 0,
                    y: 0,
                    width,
                    height,
                });
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
mod tests;
