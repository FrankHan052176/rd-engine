//! One explicitly armed display stream, forwarded without capture or
//! transcoding. The display is the one the caller selected; C is still offered
//! exactly one display. This owner has no route, identity or credentials for A.
use crate::{
    annex_b::ParameterSets,
    authentication::{AttemptPolicy, HostAuthConfig, NoSecondFactor, Passwords, PendingApproval,
        Permissions, PrimaryPolicy, salted_password},
    handshake::{self, HostIdentity},
    session::{HostEvent, HostSession},
    video::Geometry,
    viewer::{Viewer, ViewerError, decoder::VideoCodec},
};
use base::message_proto::{self as proto, EncodedVideoFrame, EncodedVideoFrames, Message,
    PeerInfo, SupportedDecoding, SupportedEncoding, message, misc, video_frame};
use hbb_common::{sodiumoxide::{self, crypto::sign, randombytes, utils}, tcp::FramedStream};
use std::{collections::VecDeque, io, net::{Ipv4Addr, SocketAddr}, sync::{Arc, Condvar, Mutex, MutexGuard, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::{net::TcpListener, sync::{Notify, mpsc}};
use tokio_util::sync::CancellationToken;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
fn error(message: &'static str) -> io::Error { io::Error::other(message) }

/// Non-secret run observations. Counters describe B's writes, not C's rendering.
#[derive(Clone, Default)]
pub struct Snapshot {
    pub state: &'static str,
    pub reason: &'static str,
    pub codec: Option<VideoCodec>,
    pub viewer_connected: bool,
    pub units: u64,
    pub bytes: u64,
    pub dropped: u64,
    pub resyncs: u64,
    pub keyframe_requests: u64,
    pub closed: bool,
}
pub(crate) struct Packet { message: Message, generation: u64, key: bool, units: u64, bytes: u64 }

const MAX_FEED_IMAGES: usize = 64;
const MAX_FEED_BYTES: usize = 4 * 1024 * 1024;
/// Stays below the receiving viewer's own cache bounds (256 images, 16 MiB
/// decoded), so an image counted as delivered is still there to be selected.
const MAX_DELIVERED: usize = 16;
/// Where C is told A's pointer is while it is not on the shared display. It is
/// outside any display C can be offered, so C hides the pointer instead of
/// parking it on an edge, and nothing about A's other displays is revealed.
pub const POINTER_OFF_DISPLAY: i32 = -(1 << 20);

#[derive(Default)]
struct FeedState {
    images: VecDeque<Arc<proto::CursorData>>,
    bytes: usize,
    selected: Option<u64>,
    selected_image: Option<Arc<proto::CursorData>>,
    selection: u64,
    position: Option<(i32, i32)>,
    moved: u64,
}
/// A's real pointer as the source reader saw it: the bitmaps B accepted, which
/// one is selected, and the desktop-global position. It is latest-wins state,
/// not a queue, so a slow C can neither stall B's reader nor grow memory, and a
/// C that arrives late is replayed the current pointer from it.
#[derive(Default)]
pub(crate) struct CursorFeed { state: Mutex<FeedState>, wake: Notify }
impl CursorFeed {
    /// `data` is `None` for a bitmap B refused: the previous image under this id
    /// is invalidated too, exactly as B's own cursor state does.
    pub(crate) fn data(&self, id: u64, data: Option<proto::CursorData>) {
        let mut state = lock(&self.state);
        let known = state.images.iter().position(|image| image.id == id);
        let unchanged = matches!((known, data.as_ref()), (Some(index), Some(data)) if *state.images[index] == *data);
        if !unchanged {
            if let Some(old) = known.and_then(|index| state.images.remove(index)) { state.bytes -= old.colors.len(); }
            if let Some(data) = data {
                while state.bytes + data.colors.len() > MAX_FEED_BYTES || state.images.len() >= MAX_FEED_IMAGES {
                    let Some(oldest) = state.images.pop_front() else { break; };
                    state.bytes -= oldest.colors.len();
                }
                state.bytes += data.colors.len();
                state.images.push_back(Arc::new(data));
            }
        }
        self.select(&mut state, id);
    }
    pub(crate) fn id(&self, id: u64) { self.select(&mut lock(&self.state), id); }
    pub(crate) fn position(&self, x: i32, y: i32) {
        let mut state = lock(&self.state);
        if state.position == Some((x, y)) { return; }
        state.position = Some((x, y));
        state.moved = state.moved.wrapping_add(1);
        self.wake.notify_one();
    }
    fn select(&self, state: &mut FeedState, id: u64) {
        let image = state.images.iter().find(|image| image.id == id).cloned();
        let same = state.selected == Some(id) && match (&state.selected_image, &image) {
            (Some(known), Some(image)) => Arc::ptr_eq(known, image),
            (None, None) => true,
            _ => false,
        };
        if same { return; }
        state.selected = Some(id);
        state.selected_image = image;
        state.selection = state.selection.wrapping_add(1);
        self.wake.notify_one();
    }
}
/// What C has already been given, so the writer sends a bitmap once and then
/// only its id, and re-projects A's global position onto C's one display.
struct CursorSender {
    feed: Arc<CursorFeed>,
    geometry: Geometry,
    selection: u64,
    moved: u64,
    delivered: VecDeque<Arc<proto::CursorData>>,
    hidden: bool,
}
impl CursorSender {
    fn new(feed: Arc<CursorFeed>, geometry: Geometry) -> Self {
        Self { feed, geometry, selection: 0, moved: 0, delivered: VecDeque::new(), hidden: false }
    }
    /// The messages that bring C up to the feed's current state, in order.
    fn pending(&mut self) -> Vec<Message> {
        let state = lock(&self.feed.state);
        let mut out = Vec::new();
        if state.selection != self.selection {
            self.selection = state.selection;
            if let Some(id) = state.selected {
                let mut message = Message::new();
                match state.images.iter().find(|image| image.id == id) {
                    Some(image) if !self.delivered.iter().any(|known| Arc::ptr_eq(known, image)) => {
                        message.set_cursor_data((**image).clone());
                        if self.delivered.len() >= MAX_DELIVERED { self.delivered.pop_front(); }
                        self.delivered.push_back(Arc::clone(image));
                    }
                    _ => message.set_cursor_id(id),
                }
                out.push(message);
            }
        }
        if state.moved != self.moved {
            self.moved = state.moved;
            if let Some((x, y)) = state.position {
                let geometry = self.geometry;
                let local = x.checked_sub(geometry.x).zip(y.checked_sub(geometry.y))
                    .filter(|(x, y)| (0..geometry.width).contains(x) && (0..geometry.height).contains(y));
                // The off-display marker is sent once per departure, not per move.
                if local.is_some() || !self.hidden {
                    let (x, y) = local.unwrap_or((POINTER_OFF_DISPLAY, POINTER_OFF_DISPLAY));
                    let mut message = Message::new();
                    message.set_cursor_position(proto::CursorPosition { x, y, ..Default::default() });
                    out.push(message);
                }
                self.hidden = local.is_none();
            }
        }
        out
    }
}
struct Admission {
    codec: Option<VideoCodec>,
    parameters: ParameterSets,
    waiting_key: bool,
    generation: u64,
    connected: bool,
    key_requested: Option<Instant>,
}
/// Bounded codec metadata from the current source, not retained video. A late
/// C needs the SPS/PPS (or VPS/SPS/PPS) B may have received before the share arm.
#[derive(Default)]
pub(crate) struct Seed {
    current: Option<(VideoCodec, Geometry)>,
    parameters: ParameterSets,
}
impl Seed {
    pub(crate) fn observe(&mut self, codec: VideoCodec, geometry: Geometry, frames: &[EncodedVideoFrame]) {
        if self.current != Some((codec, geometry)) {
            self.current = Some((codec, geometry)); self.parameters = ParameterSets::default();
        }
        if matches!(codec, VideoCodec::H264 | VideoCodec::H265) {
            for frame in frames {
                if self.parameters.inspect(codec, &frame.data).is_err() {
                    self.parameters = ParameterSets::default(); break;
                }
            }
        }
    }
}
/// The reader's nonblocking tap. Only validated records reach `offer`.
pub(crate) struct Tap {
    pub(crate) cancel: CancellationToken,
    source_cancel: CancellationToken,
    source: Weak<Viewer>,
    geometry: Geometry,
    added_subscription: bool,
    cursor: Arc<CursorFeed>,
    /// The selected display's own video already carries the pointer; sending
    /// the cursor messages as well would draw it twice.
    cursor_embedded: bool,
    admission: Mutex<Admission>,
    snapshot: Mutex<Snapshot>,
    sender: mpsc::Sender<Packet>,
    done: (Mutex<bool>, Condvar),
}
impl Tap {
    pub(crate) fn active(&self) -> bool { !self.cancel.is_cancelled() }
    pub(crate) fn closed(&self) -> bool { *lock(&self.done.0) }
    pub(crate) fn selected_geometry(&self) -> Geometry { self.geometry }
    pub(crate) fn separately_subscribed(&self) -> bool { self.added_subscription }
    pub(crate) fn stop(&self, reason: &'static str) {
        let mut snapshot = lock(&self.snapshot);
        if !self.cancel.is_cancelled() { snapshot.reason = reason; snapshot.state = "stopping"; }
        self.cancel.cancel();
    }
    fn request_key(&self, admission: &mut Admission) {
        if admission.key_requested.is_some_and(|last| last.elapsed() < Duration::from_secs(1)) { return; }
        admission.key_requested = Some(Instant::now());
        if self.source.upgrade().is_some_and(|source| source.request_display_keyframe(self.geometry.display).is_ok()) {
            lock(&self.snapshot).keyframe_requests += 1;
        }
    }
    fn resync(&self, admission: &mut Admission) {
        admission.waiting_key = true;
        admission.generation = admission.generation.wrapping_add(1);
        lock(&self.snapshot).resyncs += 1;
        self.request_key(admission);
    }
    pub(crate) fn geometry(&self, geometry: Geometry) {
        if geometry != self.geometry { self.stop("geometry_changed"); }
    }
    pub(crate) fn offer(&self, codec: VideoCodec, geometry: Geometry, frames: &[EncodedVideoFrame]) {
        if !self.active() { return; }
        self.geometry(geometry);
        if !self.active() { return; }
        let mut admission = lock(&self.admission);
        if admission.codec.is_some_and(|old| old != codec) { self.stop("codec_changed"); return; }
        admission.codec = Some(codec);
        lock(&self.snapshot).codec = Some(codec);
        // Parameter sets belong to this arm. They never come from another
        // viewer/display and are bounded by the shared Annex-B inspector.
        let mut output = Vec::with_capacity(frames.len());
        let mut waiting_key = admission.waiting_key;
        for frame in frames {
            let mut unit = frame.clone();
            let key = match codec {
                VideoCodec::H264 | VideoCodec::H265 => {
                    let before = admission.parameters.clone();
                    let inspected = match admission.parameters.inspect(codec, &frame.data) {
                        Ok(value) => value,
                        Err(_) => { self.stop("invalid_source_codec_data"); return; }
                    };
                    if before.length(codec).is_ok() && admission.parameters.differs_from(&before) {
                        self.stop("codec_changed"); return;
                    }
                    if !inspected.picture {
                        if admission.parameters.push_pending(&frame.data).is_err() {
                            self.stop("invalid_source_codec_data"); return;
                        }
                        continue;
                    }
                    if inspected.key {
                        let Ok(length) = admission.parameters.length(codec) else {
                            self.request_key(&mut admission); continue;
                        };
                        let mut bytes = Vec::with_capacity(length + admission.parameters.pending().len() + frame.data.len());
                        admission.parameters.prepend(&mut bytes);
                        bytes.extend_from_slice(admission.parameters.pending());
                        bytes.extend_from_slice(&frame.data);
                        unit.data = bytes.into();
                    } else if !admission.parameters.pending().is_empty() {
                        let mut bytes = admission.parameters.pending().to_vec();
                        bytes.extend_from_slice(&frame.data);
                        unit.data = bytes.into();
                    }
                    admission.parameters.clear_pending();
                    inspected.key
                }
                VideoCodec::Vp8 | VideoCodec::Vp9 => frame.key,
            };
            unit.key = key;
            if !admission.connected { continue; }
            if waiting_key && !key { self.request_key(&mut admission); continue; }
            output.push(unit);
            waiting_key = false;
        }
        if output.is_empty() { return; }
        let key = output[0].key;
        let units = output.len() as u64;
        let bytes = output.iter().map(|unit| unit.data.len() as u64).sum();
        if bytes > 32 * 1024 * 1024 {
            self.stop("invalid_source_codec_data"); return;
        }
        let encoded = EncodedVideoFrames { frames: output, ..Default::default() };
        let union = match codec {
            VideoCodec::H264 => video_frame::Union::H264s(encoded),
            VideoCodec::H265 => video_frame::Union::H265s(encoded),
            VideoCodec::Vp8 => video_frame::Union::Vp8s(encoded),
            VideoCodec::Vp9 => video_frame::Union::Vp9s(encoded),
        };
        let mut message = Message::new();
        message.set_video_frame(proto::VideoFrame { display: 0, union: Some(union), ..Default::default() });
        let packet = Packet { message, generation: admission.generation, key, units, bytes };
        match self.sender.try_send(packet) {
            Ok(()) => admission.waiting_key = false,
            Err(mpsc::error::TrySendError::Full(_)) => {
                lock(&self.snapshot).dropped += units;
                self.resync(&mut admission);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => { self.stop("forward_writer_closed"); }

        }
    }
}

/// Public invitation material is exposed only to the native invite encoder.
/// Dropping the owner cancels the worker; the worker never retains this owner.
pub struct Run {
    tap: Arc<Tap>,
    /// Where C reaches this run, when the run has an address of its own.
    ///
    /// A nearby run has none: its bytes travel the platform's own connection
    /// manager, so `None` is the whole answer rather than an address an
    /// invitation could name.
    pub endpoint: Option<SocketAddr>,
    pub id: String,
    pub public_key: sign::PublicKey,
    token: Mutex<String>,
    nearby_ready: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    pub expires_at_ms: u64,
    pub width: i32,
    pub height: i32,
    /// The source display this run republishes, exactly as arming named it. It
    /// is B's own display index; C is still offered one display, indexed 0.
    pub display: i32,
}
impl Drop for Run { fn drop(&mut self) { self.request_close(); } }
impl Run {
    /// Binds a LAN address without connecting to A, C or any probe service.
    ///
    /// `source_display` is the peer display to republish; the viewer's
    /// `arm_forward` subscribes it independently when B watches another display.
    /// B's current display and decoder are never switched by this operation.
    pub fn start(source: &Arc<Viewer>, source_display: i32, accept_unverified: bool,
        ttl: Duration) -> io::Result<Arc<Self>> {
        admitted_lifetime(ttl)?;
        let runtime = crate::executor::runtime().map_err(|_| error("Executor unavailable"))?;
        let mut addresses = default_net::get_interfaces().into_iter()
            .flat_map(|interface| interface.ipv4.into_iter().map(|v4| v4.addr))
            .filter(|ip| ip.is_private() && !ip.is_loopback())
            .collect::<Vec<Ipv4Addr>>();
        addresses.sort_unstable(); addresses.dedup();
        if addresses.len() != 1 { return Err(error("Sharing needs exactly one active LAN IPv4 address")); }
        let socket = std::net::TcpListener::bind(SocketAddr::from((addresses[0], 0)))?;
        socket.set_nonblocking(true)?;
        let endpoint = socket.local_addr()?;
        let listener = { let _entered = runtime.enter(); TcpListener::from_std(socket)? };
        Self::start_over(source, source_display, accept_unverified, ttl,
            Transport::Listening(listener), Some(endpoint), None)
    }
    /// Starts a share over an already-paired nearby byte bridge.
    ///
    /// This enumerates no interface, selects no LAN address and binds no
    /// listener: the record stream `start` would have carried over TCP travels
    /// the platform's own connection manager instead, and this run therefore has
    /// no endpoint at all. Only the transport differs; the ephemeral pin, the
    /// salted single-use token, the pointer-only shared view and the source tap are
    /// the same owner `start` builds.
    pub fn start_nearby(source: &Arc<Viewer>, source_display: i32, accept_unverified: bool,
        ttl: Duration) -> io::Result<(Arc<Self>, Arc<crate::nearby::Bridge>)> {
        admitted_lifetime(ttl)?;
        let (bridge, wire) = crate::nearby::Bridge::pair()?;
        let (ready, connected) = tokio::sync::oneshot::channel();
        let run = Self::start_over(source, source_display, accept_unverified, ttl,
            Transport::Nearby { wire, connected }, None, Some(ready))?;
        Ok((run, bridge))
    }
    /// The owner both starts share; `ttl` is already an admitted lifetime and
    /// `endpoint` is where C reaches this run, when it has an address at all.
    fn start_over(source: &Arc<Viewer>, source_display: i32, accept_unverified: bool,
        ttl: Duration, transport: Transport, endpoint: Option<SocketAddr>,
        nearby_ready: Option<tokio::sync::oneshot::Sender<()>>) -> io::Result<Arc<Self>> {
        sodiumoxide::init().map_err(|_| error("Crypto initialization failed"))?;
        let runtime = crate::executor::runtime().map_err(|_| error("Executor unavailable"))?;
        let (sender, receiver) = mpsc::channel(2);
        let (public_key, secret_key) = sign::gen_keypair();
        let random_hex = |length| randombytes::randombytes(length).iter()
            .map(|byte| format!("{byte:02x}")).collect::<String>();
        let id = random_hex(16);
        let token = random_hex(24);
        let salt = random_hex(18);
        let h1 = salted_password(token.as_bytes(), &salt);
        let expires_at_ms = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| error("Clock unavailable"))?.as_millis() as u64 + ttl.as_millis() as u64;
        let (tap, display) = source.arm_forward(source_display, accept_unverified, sender)?;
        let owner = Arc::new(Self { tap: tap.clone(), endpoint, id: id.clone(), public_key,
            token: Mutex::new(token), nearby_ready: Mutex::new(nearby_ready), expires_at_ms, width: display.width, height: display.height,
            display: source_display });
        runtime.spawn(async move {
            let result = tokio::select! {
                biased;
                _ = tap.cancel.cancelled() => Ok(()),
                _ = tap.source_cancel.cancelled() => { tap.stop("source_closed"); Ok(()) },
                result = serve(&tap, transport, receiver, id, secret_key, salt, h1, display, ttl) => result
            };
            if tap.active() {
                tap.stop(if result.is_ok() { "viewer_gone" } else { "internal" });
            }
            tap.cancel.cancel();
            if let Some(source) = tap.source.upgrade() { source.release_forward(&tap).await; }
            let mut snapshot = lock(&tap.snapshot);
            snapshot.state = "stopped"; snapshot.viewer_connected = false; snapshot.closed = true;
            drop(snapshot);
            *lock(&tap.done.0) = true;
            tap.done.1.notify_all();
        });
        Ok(owner)
    }
    /// Spends the nearby admission only after the platform reports a connected session.
    pub fn connect_nearby(&self) -> io::Result<()> {
        if !self.tap.active() { return Err(error("Share closed")); }
        let ready = lock(&self.nearby_ready).take().ok_or_else(|| error("Nearby transport already admitted"))?;
        ready.send(()).map_err(|_| error("Nearby admission expired"))
    }
    pub fn snapshot(&self) -> Snapshot { lock(&self.tap.snapshot).clone() }
    pub fn request_close(&self) { self.revoke("user_stop"); }
    pub fn revoke(&self, reason: &'static str) {
        self.tap.stop(reason);
        let mut bytes = std::mem::take(&mut *lock(&self.token)).into_bytes();
        utils::memzero(&mut bytes);
    }
    pub fn invite_token(&self) -> Option<String> {
        let snapshot = lock(&self.tap.snapshot);
        if snapshot.state != "listening" || !self.tap.active() { return None; }
        Some(lock(&self.token).clone())
    }
    pub fn wait_closed(&self, timeout: Duration) -> bool {
        let done = lock(&self.tap.done.0);
        if *done { return true; }
        let result = self.tap.done.1.wait_timeout_while(done, timeout, |done| !*done);
        match result { Ok((done, _)) => *done, Err(poisoned) => *poisoned.into_inner().0 }
    }
}

pub(crate) fn tap(source: &Arc<Viewer>, geometry: Geometry, added_subscription: bool, sender: mpsc::Sender<Packet>,
    source_cancel: CancellationToken, seed: &Seed, cursor: Arc<CursorFeed>, cursor_embedded: bool) -> Arc<Tap> {
    let codec = seed.current.filter(|(_, source)| *source == geometry).map(|(codec, _)| codec);
    let parameters = if codec.is_some() { seed.parameters.clone() } else { ParameterSets::default() };
    Arc::new(Tap { cancel: CancellationToken::new(), source_cancel, source: Arc::downgrade(source),
        geometry, added_subscription, cursor, cursor_embedded, admission: Mutex::new(Admission { codec, parameters,
            waiting_key: true, generation: 0, connected: false, key_requested: None }),
        snapshot: Mutex::new(Snapshot { state: "listening", codec, ..Default::default() }), sender,
        done: (Mutex::new(false), Condvar::new()) })
}
struct OneAttempt(bool);
impl AttemptPolicy for OneAttempt {
    fn allow(&mut self, _: bool) -> Result<(), &'static str> {
        if self.0 { return Err("Share token already attempted"); }
        self.0 = true; Ok(())
    }
    fn outcome(&mut self, _: bool, _: bool) {}
}
fn covers(decoding: &SupportedDecoding, codec: VideoCodec) -> bool {
    match codec { VideoCodec::H264 => decoding.ability_h264 > 0, VideoCodec::H265 => decoding.ability_h265 > 0,
        VideoCodec::Vp8 => decoding.ability_vp8 > 0, VideoCodec::Vp9 => decoding.ability_vp9 > 0 }
}
/// Where one run's bytes come from.
enum Transport {
    /// The first connection this run's own LAN listener admits.
    Listening(TcpListener),
    /// The engine side of a nearby bridge this run was handed, already paired.
    Nearby { wire: FramedStream, connected: tokio::sync::oneshot::Receiver<()> },
}
/// The one admission lifetime an invitation may name.
fn admitted_lifetime(ttl: Duration) -> io::Result<()> {
    if ttl.is_zero() || ttl > Duration::from_secs(600) { return Err(error("Invalid invitation lifetime")); }
    Ok(())
}
/// The one-shot admission either transport brings: one target, one credential
/// and nothing beyond the shared display and the right to send pointer intents.
/// The keyboard grant is only that gate: C's keys, files and clipboard are
/// never acted on.
fn host_config(id: &str, salt: &str, h1: [u8; 32], info: PeerInfo) -> HostAuthConfig {
    let pointer = Permissions { keyboard: true, ..Permissions::default() };
    HostAuthConfig { accepted_targets: vec![id.to_owned()], salt: salt.to_owned(),
        passwords: Passwords::from_salted(vec![h1]), policy: PrimaryPolicy::PasswordOnly,
        ceiling: pointer, password_permissions: pointer, peer_info: info,
        approval: Box::new(PendingApproval), second_factor: Box::new(NoSecondFactor), attempts: Box::new(OneAttempt(false)) }
}
/// Announced in `PeerInfo.platform_additions`: this host takes only pointer
/// intents (relative move, button at the shared pointer, wheel) from its viewer.
const SHARED_POINTER_INTENTS: &str = r#"{"shared_pointer_intents_v1":true}"#;
/// C is told about exactly this one display, indexed 0, whatever display the
/// source selected; its own geometry stays display-local.
fn shared_peer_info(codec: VideoCodec, mut display: proto::DisplayInfo) -> PeerInfo {
    display.x = 0; display.y = 0;
    PeerInfo { username: "Shared display".into(), platform: "HarmonyOS".into(),
        version: "1.5.1".into(), displays: vec![display], current_display: 0,
        platform_additions: SHARED_POINTER_INTENTS.into(),
        encoding: Some(SupportedEncoding { h264: codec == VideoCodec::H264,
            h265: codec == VideoCodec::H265, vp8: codec == VideoCodec::Vp8,
            ..Default::default() }).into(), ..Default::default() }
}
/// C's claim on B's one pointer for the life of one admitted connection. It is
/// dropped with the serving future, so a C that disconnects, is revoked or
/// whose share stops releases what it held and nothing B holds.
struct RemotePointer { source: Weak<Viewer>, id: u64 }
impl RemotePointer {
    fn admit(source: &Arc<Viewer>) -> Self {
        Self { source: Arc::downgrade(source), id: source.begin_remote_pointer() }
    }
    /// Hands one `MouseEvent` of C to the source's writer as an intent. C never
    /// positions B's pointer: an absolute move has no effect, and a button acts
    /// wherever the shared pointer is, not where C touched. Input the source's
    /// own gate refuses is dropped. A button that cannot be queued ends C's
    /// claim so its held buttons are released instead of silently sticking.
    fn deliver(&self, mask: i32, x: i32, y: i32) -> io::Result<()> {
        let Some((kind, button)) = pointer_intent(mask)? else { return Ok(()); };
        let source = self.source.upgrade().ok_or_else(|| error("Source closed"))?;
        match source.send_remote_pointer(self.id, kind, button, x, y) {
            Err(ViewerError::Backpressure) if matches!(kind, 1 | 2) => {
                Err(error("Shared pointer button queue is full"))
            }
            Ok(_) | Err(ViewerError::Backpressure | ViewerError::StaleInputGeneration
                | ViewerError::InputNotAllowed) => Ok(()),
            Err(_) => Err(error("Pointer intent refused")),
        }
    }
}
/// The kind and button of a `MouseEvent.mask` C may send, or `None` for the
/// absolute move C has no right to make.
fn pointer_intent(mask: i32) -> io::Result<Option<(u32, u32)>> {
    let mask = u32::try_from(mask).map_err(|_| error("Invalid pointer intent"))?;
    match (mask & 7, mask >> 3) {
        (0, _) => Ok(None),
        (kind @ 1..=5, button) => Ok(Some((kind, button))),
        _ => Err(error("Invalid pointer intent")),
    }
}
impl Drop for RemotePointer {
    fn drop(&mut self) {
        if let Some(source) = self.source.upgrade() { source.end_remote_pointer(self.id); }
    }
}
async fn serve(tap: &Arc<Tap>, transport: Transport, mut receiver: mpsc::Receiver<Packet>, id: String,
    secret_key: sign::SecretKey, salt: String, h1: [u8; 32], display: proto::DisplayInfo, ttl: Duration) -> io::Result<()> {
    let admitted = tokio::time::timeout(ttl, async {
    // Learn the actual source codec before advertising anything to C.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let codec = loop {
        if let Some(codec) = lock(&tap.admission).codec { break codec; }
        if tokio::time::Instant::now() >= deadline { return Err(error("Source video did not arrive")); }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    // Both transports offer exactly this admission and this one display.
    let config = host_config(&id, &salt, h1, shared_peer_info(codec, display));
    let mut session = match transport {
        Transport::Listening(listener) => {
            let (stream, _) = listener.accept().await?;
            // Exactly one TCP admission, including failures. A stolen/guessed code never
            // leaves a reusable password listener behind.
            drop(listener);
            lock(&tap.snapshot).state = "arming";
            HostSession::accept_direct(stream, HostIdentity::Signed { id, secret_key }, config,
                Duration::from_secs(10)).await?
        }
        // A nearby bridge is already paired, so there is no admission to wait
        // for: the same host handshake runs on the wire it was handed.
        Transport::Nearby { wire, connected } => {
            connected.await.map_err(|_| error("Nearby transport closed before connection"))?;
            lock(&tap.snapshot).state = "arming";
            let wire = handshake::host(wire, HostIdentity::Signed { id, secret_key },
                Duration::from_secs(10)).await?;
            HostSession::from_established(wire, config, Duration::from_secs(10),
                Duration::from_secs(30)).await?
        }
    };
    loop {
        let event = session.recv().await?;
        if let Some(request) = session.login_request() {
            let decoding = request.option.as_ref().and_then(|option| option.supported_decoding.as_ref());
            if !decoding.is_some_and(|decoding| covers(decoding, codec)) {
                tap.stop("unsupported_codec"); return Err(error("Viewer cannot decode the source codec"));
            }
        }
        match event {
            HostEvent::Authorized(_) => break,
            HostEvent::Closed => return Err(error("Share login closed")),
            _ => {}
        }
    }
    Ok::<_, io::Error>((session.into_authenticated_parts()?, codec))
    }).await.map_err(|_| { tap.stop("invite_expired"); error("Invitation expired") })??;
    let (parts, codec) = admitted;
    // The keyboard grant is what lets C's pointer intents reach B's writer.
    let remote = if parts.context.permissions.keyboard {
        tap.source.upgrade().map(|source| RemotePointer::admit(&source))
    } else { None };
    let mut reader = parts.reader;
    let mut writer = parts.writer;
    {
        let mut admission = lock(&tap.admission);
        admission.connected = true; admission.waiting_key = true;
        tap.request_key(&mut admission);
        let mut snapshot = lock(&tap.snapshot);
        snapshot.viewer_connected = true; snapshot.state = "connected";
    }
    let mut generation = 0;
    let mut waiting_key = true;
    let mut pointer = CursorSender::new(tap.cursor.clone(), tap.geometry);
    // A late C is replayed the pointer A already had, not only what changes next.
    if !tap.cursor_embedded {
        for message in pointer.pending() { writer.send(&message).await?; }
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    let mut receive_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut key_deadline = Some(Instant::now() + Duration::from_secs(15));
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(receive_deadline) => return Err(error("Viewer timed out")),
            _ = heartbeat.tick() => {
                if lock(&tap.admission).waiting_key && key_deadline.is_none() {
                    key_deadline = Some(Instant::now() + Duration::from_secs(15));
                }
                if key_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    tap.stop("resync_timeout"); return Err(error("Keyframe timed out"));
                }
                let mut message = Message::new(); message.set_test_delay(proto::TestDelay::default());
                writer.send(&message).await?;
                if lock(&tap.admission).waiting_key {
                    let mut admission = lock(&tap.admission); tap.request_key(&mut admission);
                }
            }
            incoming = reader.recv() => {
                let Some(message) = incoming? else { return Ok(()); };
                receive_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                match message.union {
                    Some(message::Union::TestDelay(delay)) if delay.from_client => {
                        let mut reply = Message::new(); reply.set_test_delay(delay);
                        writer.send(&reply).await?;
                    }
                    Some(message::Union::TestDelay(_)) => {}
                    Some(message::Union::Misc(misc)) => match misc.union {
                        Some(misc::Union::RefreshVideo(true)) | Some(misc::Union::RefreshVideoDisplay(0)) => {
                            let mut admission = lock(&tap.admission); tap.resync(&mut admission);
                            if key_deadline.is_none() { key_deadline = Some(Instant::now() + Duration::from_secs(15)); }
                        }
                        Some(misc::Union::Option(option)) => {
                            if let Some(decoding) = option.supported_decoding.as_ref() {
                                if !covers(decoding, codec) { tap.stop("unsupported_codec"); return Err(error("Viewer codec withdrawn")); }
                            }
                        }
                        Some(misc::Union::CloseReason(_)) => return Ok(()),
                        Some(misc::Union::SwitchDisplay(display)) if display.display == 0 => {},
                        _ => return Err(error("Shared view is read-only")),
                    },
                    Some(message::Union::MouseEvent(event)) => match remote.as_ref() {
                        Some(remote) => remote.deliver(event.mask, event.x, event.y)?,
                        None => return Err(error("Shared view is read-only")),
                    },
                    // Official viewers send keys once they hold the keyboard grant;
                    // that grant only opens the pointer, so keys have no effect.
                    Some(message::Union::KeyEvent(_)) if remote.is_some() => {}
                    _ => return Err(error("Shared view is read-only")),
                }
            }
            _ = tap.cursor.wake.notified(), if !tap.cursor_embedded => {
                for message in pointer.pending() { writer.send(&message).await?; }
            }
            packet = receiver.recv() => {
                let Some(packet) = packet else { return Ok(()); };
                let current = lock(&tap.admission).generation;
                if generation != current {
                    generation = current; waiting_key = true;
                    if key_deadline.is_none() { key_deadline = Some(Instant::now() + Duration::from_secs(15)); }
                }
                if packet.generation != generation || (waiting_key && !packet.key) { continue; }
                writer.send(&packet.message).await?;
                waiting_key = false; key_deadline = None;
                let mut snapshot = lock(&tap.snapshot);
                snapshot.units += packet.units; snapshot.bytes += packet.bytes;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bitmap(id: u64, value: u8) -> proto::CursorData {
        proto::CursorData { id, width: 1, height: 1, colors: vec![value].into(), ..Default::default() }
    }
    fn sender(feed: &Arc<CursorFeed>) -> CursorSender {
        // The shared display sits at (1920, 0) in A's desktop.
        CursorSender::new(feed.clone(), Geometry { display: 1, x: 1920, y: 0, width: 800, height: 600 })
    }
    fn position(message: &Message) -> (i32, i32) {
        match &message.union { Some(message::Union::CursorPosition(p)) => (p.x, p.y), _ => panic!("position") }
    }

    #[test]
    fn viewer_pointer_masks_allow_only_intents_never_an_absolute_position() {
        let mask = |kind: i32, button: i32| kind | (button << 3);
        assert_eq!(pointer_intent(mask(0, 0)).unwrap(), None, "an absolute move has no effect");
        assert_eq!(pointer_intent(mask(5, 0)).unwrap(), Some((5, 0)));
        assert_eq!(pointer_intent(mask(1, 4)).unwrap(), Some((1, 4)));
        assert_eq!(pointer_intent(mask(3, 0)).unwrap(), Some((3, 0)));
        assert!(pointer_intent(6).is_err() && pointer_intent(7).is_err());
        assert!(pointer_intent(-1).is_err());
    }

    #[test]
    fn late_viewer_gets_current_bitmap_then_only_ids_and_display_local_position() {
        let feed = Arc::new(CursorFeed::default());
        feed.data(7, Some(bitmap(7, 1)));
        feed.position(1920 + 10, 20);
        let mut pointer = sender(&feed);
        let first = pointer.pending();
        assert!(matches!(first[0].union, Some(message::Union::CursorData(ref data)) if data.id == 7));
        assert_eq!(position(&first[1]), (10, 20));
        assert!(pointer.pending().is_empty());
        feed.data(8, Some(bitmap(8, 2)));
        feed.id(7);
        // Only the final selection is sent, and C already holds that bitmap.
        assert!(matches!(pointer.pending()[0].union, Some(message::Union::CursorId(7))));
    }

    #[test]
    fn pointer_off_the_shared_display_is_hidden_once_not_leaked() {
        let feed = Arc::new(CursorFeed::default());
        let mut pointer = sender(&feed);
        feed.position(100, 100);
        assert_eq!(position(&pointer.pending()[0]), (POINTER_OFF_DISPLAY, POINTER_OFF_DISPLAY));
        feed.position(101, 100);
        assert!(pointer.pending().is_empty());
        feed.position(1920 + 799, 599);
        assert_eq!(position(&pointer.pending()[0]), (799, 599));
        feed.position(1920 + 800, 599);
        assert_eq!(position(&pointer.pending()[0]), (POINTER_OFF_DISPLAY, POINTER_OFF_DISPLAY));
    }

    #[test]
    fn refused_bitmap_invalidates_the_previous_image_for_that_id() {
        let feed = Arc::new(CursorFeed::default());
        feed.data(7, Some(bitmap(7, 1)));
        let mut pointer = sender(&feed);
        pointer.pending();
        feed.data(7, None);
        assert!(matches!(pointer.pending()[0].union, Some(message::Union::CursorId(7))));
        feed.id(7);
        assert!(lock(&feed.state).selected_image.is_none());
    }
}
