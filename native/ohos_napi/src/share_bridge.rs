//! Single forward owner for one selected display, and its ephemeral, single-use
//! invite.
//!
//! The B→C hop is a nearby byte transport, not a socket this layer listens on:
//! the core run owns the pin, the token and the framing, and this module only
//! hands already-framed bytes across to ArkTS and back.
use super::SessionRecord;
use hbb_common::{
    base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    },
    sodiumoxide::crypto::sign,
};
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task, Uint8Array},
    Env,
};
use rd_engine::forward::Run;
use rd_engine::nearby::Bridge;
use hbb_common::tcp::FramedStream;
use rd_engine::session::SessionMode;
use rd_engine::viewer::Viewer;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, MutexGuard, OnceLock,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The prefix that names this format, so an unrelated paste is refused before
/// anything is decoded.
const PREFIX: &str = "RKS1.";
/// Every field this format defines. A code carrying anything else was not issued
/// by this bridge, and guessing what an extra field meant is not parsing it.
const FIELDS: [&str; 7] = ["v", "ep", "id", "pk", "tok", "exp", "ep0"];
const FORMAT_VERSION: u64 = 1;
const MAX_CODE_BYTES: usize = 512;
const MAX_HOST_ID_BYTES: usize = 64;
const MIN_TOKEN_BYTES: usize = 16;
const MAX_TOKEN_BYTES: usize = 64;
const PUBLIC_KEY_BYTES: usize = 32;
/// One hour. This format issues minutes-long invitations (default 300 s, at most
/// 600 s), so a deadline beyond this is not one a live issuer produced; it is
/// slack for device clock skew, not a lifetime this bridge may grant.
const MAX_CLOCK_SKEW_MS: u64 = 60 * 60 * 1000;

const MAX_OPTIONS_BYTES: usize = 8 * 1024;
const DEFAULT_TTL_SECONDS: u64 = 300;
const MAX_TTL_SECONDS: u64 = 600;

/// This device's clock in unix milliseconds, as every invite decision reads it.
///
/// A clock before the epoch reads as `0`, which no live invite can satisfy: the
/// fallback is a refusal, never a deadline this layer invented.
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The one-time identity C must prove before its login.
///
/// B generates it per share and never reuses it, so pinning it is what makes C's
/// connection a proof of *that* share rather than of whatever socket answered.
pub(super) struct PinnedHost {
    pub(super) expected_id: String,
    pub(super) public_key: sign::PublicKey,
}

/// What a C-side record remembers about the share it came from.
///
/// It carries no A identity, no server route and no reconnect material: only the
/// ephemeral peer C must prove, the invite's own deadline, the run it named and
/// the nearby byte transport this record owns from `sessionAddShared` on.
pub(super) struct SharedSession {
    pub(super) pin: PinnedHost,
    /// The invite's deadline in unix milliseconds. The token is single-use and
    /// expires with it.
    pub(super) expires_at_ms: u64,
    /// The share run the code named. It is a receipt only: it grants nothing and
    /// is never used to reach B.
    pub(super) share_epoch: u64,
    /// The nearby transport, created with `Bridge::pair` while the record is
    /// registered. It exists before the dial so a collaborator's first bytes have
    /// a bounded queue to land in while the login handshake is still running; the
    /// framed stream half stays here until the dial consumes it exactly once.
    pub(super) transport: Mutex<SharedTransport>,
}

/// Advanced by every app-lifecycle fence that withdraws consent or destroys the
/// environment.
///
/// A session's nearby transport records the generation it was created under. A
/// fence runs while the app lock is held, and the session registry is taken while
/// the app lock may be requested (a dial admits an ID route), so iterating the
/// registry from the fence would invert those two locks. Comparing this number
/// instead is lock-free, and every session byte call closes its transport before
/// it touches a queue once the number has moved.
static FENCE_GENERATION: AtomicU64 = AtomicU64::new(0);

fn fence_generation() -> u64 {
    FENCE_GENERATION.load(Ordering::Acquire)
}

#[derive(Default)]
pub(super) struct SharedTransport {
    bridge: Option<Arc<Bridge>>,
    wire: Option<FramedStream>,
    /// The lifecycle fence generation this transport was created under.
    paired_at_fence: u64,
}

impl SharedTransport {
    /// The pair `sessionAddShared` created: the byte queues are live immediately,
    /// and the framed stream is held until the dial takes it.
    pub(super) fn paired(bridge: Arc<Bridge>, wire: FramedStream) -> Self {
        Self {
            bridge: Some(bridge),
            wire: Some(wire),
            paired_at_fence: fence_generation(),
        }
    }
}

impl SharedSession {
    /// A record whose invite has expired must not dial: the token it holds can no
    /// longer be accepted, and dialling would spend the one use of a credential
    /// that is already dead.
    pub(super) fn expired(&self, now_ms: u64) -> bool {
        self.expires_at_ms <= now_ms
    }

    fn transport(&self) -> MutexGuard<'_, SharedTransport> {
        self.transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Takes the framed stream the dial hands the viewer.
    ///
    /// It is consumed at most once: a second dial of the same record cannot reuse
    /// a byte stream the first one already owns.
    pub(super) fn take_wire(&self) -> Option<FramedStream> {
        self.transport().wire.take()
    }

    /// The next framed chunk the core queued for this side, or `Ok(None)` when
    /// nothing is queued now. An error means the transport ended.
    pub(super) fn take_output(&self) -> Result<Option<Vec<u8>>, String> {
        self.refuse_if_fenced()?;
        let bridge = self
            .transport()
            .bridge
            .clone()
            .ok_or_else(|| "this record has no nearby transport".to_string())?;
        bridge.take_output().map_err(|error| error.to_string())
    }

    pub(super) fn push_input(&self, bytes: &[u8]) -> Result<(), String> {
        self.refuse_if_fenced()?;
        let bridge = self
            .transport()
            .bridge
            .clone()
            .ok_or_else(|| "this record has no nearby transport".to_string())?;
        bridge.push_input(bytes).map_err(|error| error.to_string())
    }

    /// Closes this record's transport if a lifecycle fence happened after it was
    /// created, and refuses the current call.
    ///
    /// The fence itself cannot reach into the registry (see `FENCE_GENERATION`),
    /// so the terminator is the next byte call — which therefore runs before
    /// anything is taken or pushed, not after.
    fn refuse_if_fenced(&self) -> Result<(), String> {
        // The guard is released at this semicolon, so closing below is not a
        // re-entrant lock of the same transport.
        let fenced = self.transport().paired_at_fence != fence_generation();
        if !fenced {
            return Ok(());
        }
        self.close_transport();
        Err("an app lifecycle fence closed this nearby transport".to_string())
    }

    /// Closes the byte transport, whether or not its stream ever reached a viewer.
    ///
    /// A record that never started still owns the bridge's bounded queues, so a
    /// terminal session, a close request and a lifecycle fence all end here.
    pub(super) fn close_transport(&self) {
        let mut transport = self.transport();
        transport.wire = None;
        if let Some(bridge) = transport.bridge.take() {
            bridge.close();
        }
    }

    pub(super) fn transport_closed(&self) -> bool {
        let transport = self.transport();
        if transport.paired_at_fence != fence_generation() {
            return true;
        }
        match transport.bridge.as_ref() {
            Some(bridge) => bridge.is_closed(),
            None => true,
        }
    }
}

/// One decoded invite. Every field is what the code said; nothing is defaulted.
pub(super) struct ShareInvite {
    pub(super) host_id: String,
    pub(super) public_key: sign::PublicKey,
    pub(super) token: String,
    pub(super) expires_at_ms: u64,
    pub(super) share_epoch: u64,
}

impl ShareInvite {
    /// Parses one pasted code.
    ///
    /// The bounds are this format's own: a field that is missing, of the wrong
    /// type, out of range or unknown to the format is a refusal, never a default.
    /// Nothing here performs I/O, so a code is either well-formed or refused
    /// before any record is created.
    ///
    pub(super) fn parse(code: &str) -> Result<Self, String> {
        if code.len() > MAX_CODE_BYTES {
            return Err("the share code is larger than this format can be".to_string());
        }
        let payload = code
            .strip_prefix(PREFIX)
            .ok_or_else(|| format!("a share code starts with {PREFIX}"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .map_err(|_| "the share code is not unpadded base64url".to_string())?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "the share code does not carry a JSON object".to_string())?;
        let object = value
            .as_object()
            .ok_or_else(|| "the share code does not carry a JSON object".to_string())?;
        for field in object.keys() {
            if !FIELDS.contains(&field.as_str()) {
                return Err(format!(
                    "the share code carries a field this format does not define: {field:?}"
                ));
            }
        }
        let text = |name: &str| {
            object
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("the share code has no string {name}"))
        };
        if object.get("v").and_then(Value::as_u64) != Some(FORMAT_VERSION) {
            return Err(format!("the share code is not version {FORMAT_VERSION}"));
        }
        let ep = text("ep")?;
        if ep != NEARBY_ENDPOINT {
            return Err(
                "this share code does not name the nearby transport; a code carrying an address \
                 is from the retired LAN route and is refused"
                    .to_string(),
            );
        }
        let host_id = text("id")?;
        if host_id.is_empty()
            || host_id.len() > MAX_HOST_ID_BYTES
            || !host_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err("the share code's host id is not a RustDesk id".to_string());
        }
        let public_key = STANDARD
            .decode(text("pk")?.as_bytes())
            .map_err(|_| "the share code's public key is not standard base64".to_string())?;
        let public_key: [u8; PUBLIC_KEY_BYTES] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| "the share code's public key is not 32 bytes".to_string())?;
        let public_key = sign::PublicKey::from_slice(&public_key)
            .ok_or_else(|| "the share code's public key is invalid".to_string())?;
        let token = text("tok")?;
        if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len())
            || !token.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err("the share code's token is not a share token".to_string());
        }
        let expires_at_ms = object.get("exp").and_then(Value::as_u64).unwrap_or(0);
        let share_epoch = object.get("ep0").and_then(Value::as_u64).unwrap_or(0);
        if expires_at_ms == 0 || share_epoch == 0 {
            return Err("the share code carries no deadline or no share epoch".to_string());
        }
        Ok(Self {
            host_id: host_id.to_owned(),
            public_key,
            token: token.to_owned(),
            expires_at_ms,
            share_epoch,
        })
    }

    /// Whether this device's clock still admits the invite.
    ///
    /// An invitation is minutes long and single-use, so a code that is already
    /// due — or one claiming a deadline far beyond anything this format issues —
    /// cannot be live. Both are refused before a record exists, rather than
    /// becoming a session that dials with a token no host will accept.
    pub(super) fn admitted_at(&self, now_ms: u64) -> Result<(), String> {
        if self.expires_at_ms <= now_ms {
            return Err("the share invite has expired; ask B for a new code".to_string());
        }
        if self.expires_at_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(
                "the share invite names a deadline this format cannot issue; ask B for a new code"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// The options `shareStart` takes, and nothing else.
///
/// The session and its lifecycle epoch are captured by this bridge from the
/// registry, never supplied by the caller: a UI cannot know an internal epoch,
/// and one that passed a guess would be asking this layer to arm a share on a
/// viewer it never checked.
struct StartOptions {
    session_id: String,
    display: i32,
    ttl: Duration,
    accept_unverified_source: bool,
}

fn parse_start(value: &Value) -> Result<StartOptions, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "shareStart options must be a JSON object".to_string())?;
    for field in object.keys() {
        if !["sessionId", "display", "ttlSeconds", "acceptUnverifiedSource"]
            .contains(&field.as_str())
        {
            return Err(format!(
                "shareStart does not take {field:?}: it captures the session's own lifecycle epoch, \
                 dials and consent from the registry"
            ));
        }
    }
    let session_id = object
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "shareStart needs the sessionId of the running session".to_string())?;
    // Any display the peer really reports can be republished, the primary one
    // included: the caller names the index, and the arm refuses one this peer
    // does not have.
    let display = object
        .get("display")
        .and_then(Value::as_i64)
        .and_then(|display| i32::try_from(display).ok())
        .filter(|display| *display >= 0)
        .ok_or_else(|| {
            "shareStart display must be the non-negative index of a peer display".to_string()
        })?;
    let ttl_seconds = match object.get("ttlSeconds") {
        None | Some(Value::Null) => DEFAULT_TTL_SECONDS,
        Some(value) => value
            .as_u64()
            .filter(|seconds| (1..=MAX_TTL_SECONDS).contains(seconds))
            .ok_or_else(|| format!("shareStart ttlSeconds must be 1..={MAX_TTL_SECONDS}"))?,
    };
    let accept_unverified_source = match object.get("acceptUnverifiedSource") {
        None | Some(Value::Null) => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "shareStart acceptUnverifiedSource must be a boolean".to_string())?,
    };
    Ok(StartOptions {
        session_id: session_id.to_owned(),
        display,
        ttl: Duration::from_secs(ttl_seconds),
        accept_unverified_source,
    })
}

/// What this bridge observed about the session a share would republish.
struct SourceFacts {
    lifecycle_epoch: u64,
    dials: u64,
    display: i32,
    width: i32,
    height: i32,
    /// The source hop's own wire evidence (A→B), reported as `sourceEncrypted`.
    /// It is not what this bridge answers as `encrypted`, which names the B→C hop
    /// the share itself always pins.
    source_encrypted: bool,
    peer_verified: bool,
}

/// The `ep` value this format issues for a nearby share.
///
/// It is a literal, not an address: the new route has no endpoint to name, and a
/// code that carried one would be asking a receiver to dial something this
/// product does not use. Parsing refuses anything else, so no LAN fallback
/// survives in the format.
const NEARBY_ENDPOINT: &str = "nearby";

/// What ArkTS reported about one rejected platform `sendData` call.
///
/// The platform's own rejection text is never retained: it can quote the frame
/// or the transport session. A caller names a fixed label and a numeric code,
/// and a label outside this set is recorded as `unknown` instead of being kept.
#[derive(Default)]
pub(super) struct SendReport {
    pub(super) failures: u64,
    pub(super) label: Option<&'static str>,
    pub(super) code: Option<i64>,
}

/// The labels `shareReportSendResult` accepts. A platform error string is not one
/// of them, so nothing platform-specific can be stored through this path.
///
/// `peer_disconnected` is accepted so ArkTS can report normal collaborator exit
/// without losing the honest event classification; this layer treats it as a
/// normal viewer termination (`viewer_gone`) rather than a send failure.
const SEND_FAILURE_LABELS: [&str; 7] = [
    "send_data_rejected",
    "send_data_timeout",
    "transport_closed",
    "transport_error",
    "peer_disconnected",
    "user_stop",
    "unknown",
];

pub(super) fn send_failure_label(label: &str) -> &'static str {
    SEND_FAILURE_LABELS
        .iter()
        .copied()
        .find(|known| *known == label)
        .unwrap_or("unknown")
}

/// What terminal reason a non-ok link report names, if it is not a send rejection.
///
/// A label that describes the nearby link ending is not a send failure: the
/// remote peer closed the link (`viewer_gone`), or the link setup / transport
/// itself failed (`transport_failed`). Only an actual platform rejection of an
/// attempted send is recorded as `send_failed`.
fn non_send_reason(label: &'static str) -> Option<&'static str> {
    match label {
        "peer_disconnected" => Some("viewer_gone"),
        "user_stop" => Some("user_stop"),
        "transport_closed" | "transport_error" => Some("transport_failed"),
        _ => None,
    }
}

pub(super) struct Publication {
    /// The core forward owner: the source subscription, the ephemeral pin, the
    /// salted single-use token and the per-viewer pacing all stay inside it,
    /// exactly as before. This layer generates no credential of its own and
    /// copies none out.
    run: Arc<Run>,
    /// The nearby byte transport this share travels on. Both directions are the
    /// core's own bounded, sequence-and-length framed queues; this layer hands
    /// bytes across and never re-frames, re-orders or retries them.
    bridge: Arc<Bridge>,
    epoch: u64,
    session_id: String,
    peer_verified: bool,
    source_encrypted: bool,
    /// Rejected platform `sendData` calls, as the fixed facts ArkTS reported.
    send: Mutex<SendReport>,
}

impl Publication {
    /// A share is over when the core run closed or the byte transport closed.
    ///
    /// The invite's deadline is not part of it: it bounds admission, and the core
    /// is what stops an already-admitted viewer. Consuming the deadline here
    /// would cut a live nearby viewer off at the invitation's expiry.
    fn is_closed(&self) -> bool {
        self.run.snapshot().closed || self.bridge.is_closed()
    }

    /// Ends this share: the transport closes (dropping the core's bounded queues
    /// with it) and the run is revoked, which zeroes its single-use token. A
    /// later epoch starts from empty queues because these ones are gone.
    fn revoke(&self, reason: &'static str) {
        // Latch the cause before closing the byte queues wakes the worker.
        self.run.revoke(reason);
        self.bridge.close();
    }
}

static SHARE: OnceLock<Mutex<Option<Publication>>> = OnceLock::new();
static NEXT_SHARE: AtomicU64 = AtomicU64::new(1);
fn publication() -> MutexGuard<'static, Option<Publication>> {
    SHARE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn invite(publication: &Publication) -> Option<String> {
    if now_ms() >= publication.run.expires_at_ms {
        return None;
    }
    let token = publication.run.invite_token()?;
    let wire = json!({
        "v": FORMAT_VERSION,
        "ep": NEARBY_ENDPOINT,
        "id": publication.run.id,
        "pk": STANDARD.encode(publication.run.public_key.0),
        "tok": token,
        "exp": publication.run.expires_at_ms,
        "ep0": publication.epoch
    });
    Some(format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(wire.to_string().as_bytes())
    ))
}

pub(super) fn request_close_after_lifecycle_fence() {
    // Lock-free by necessity: this runs with the app lock held, and a session
    // dial takes the registry lock before asking for that same app lock. Moving
    // the generation is what makes every session byte call close its own
    // transport without either lock being taken under the other.
    FENCE_GENERATION.fetch_add(1, Ordering::AcqRel);
    if let Some(publication) = publication().as_ref() {
        publication.revoke("lifecycle_fence");
    }
}

fn start_document(options: &StartOptions, scope: &super::app_context::AppScope) -> Value {
    let source = super::with_sessions(|sessions| {
        let record = sessions.get(&options.session_id);
        let facts = source_facts(record, options)?;
        let viewer = record
            .and_then(|record| record.viewer.clone())
            .ok_or_else(|| refusal("share_start", "source_closed", "source viewer closed"))?;
        Ok::<(SourceFacts, Arc<Viewer>), Value>((facts, viewer))
    });
    let (facts, viewer) = match source {
        Ok(source) => source,
        Err(document) => return document,
    };
    // APP -> SHARE, the same order as retirement. Never join a worker here.
    let _admission = match scope.hold() {
        Ok(admission) => admission,
        Err(message) => return refusal("share_start", "app_not_admitted", &message),
    };
    let mut current = publication();
    if current
        .as_ref()
        .is_some_and(|publication| !publication.is_closed())
    {
        return refusal(
            "share_start",
            "share_busy",
            "a share is running or still reclaiming",
        );
    }

    // The core owns the ephemeral pin, the salted single-use token and the source
    // subscription; this layer names only the display and the lifetime. There is
    // no listener and no address: the run is handed the nearby byte transport it
    // will prove its pin over.
    let (run, bridge) = match Run::start_nearby(
        &viewer,
        options.display,
        options.accept_unverified_source,
        options.ttl,
    ) {
        Ok(started) => started,
        Err(error) => {
            return refusal("share_start", "forward_start_failed", &error.to_string())
        }
    };

    let epoch = NEXT_SHARE.fetch_add(1, Ordering::Relaxed);
    let publication_instance = Publication {
        run,
        bridge,
        epoch,
        session_id: options.session_id.clone(),
        peer_verified: facts.peer_verified,
        source_encrypted: facts.source_encrypted,
        send: Mutex::new(SendReport::default()),
    };

    let code = match invite(&publication_instance) {
        Some(code) => code,
        None => {
            publication_instance.revoke("init_failed");
            return refusal(
                "share_start",
                "source_closed",
                "failed to create share invitation",
            );
        }
    };

    let document = json!({
        "ok": true,
        "action": "share_start",
        "shareEpoch": epoch.to_string(),
        "inviteCode": code,
        "endpoint": NEARBY_ENDPOINT,
        "expiresAtMs": publication_instance.run.expires_at_ms,
        "width": facts.width,
        "height": facts.height,
        "display": { "index": facts.display },
        "encrypted": true,
        "sourceEncrypted": facts.source_encrypted,
        "peerVerified": facts.peer_verified,
        "session": {
            "sessionId": options.session_id,
            "lifecycleEpoch": facts.lifecycle_epoch.to_string(),
            "dials": facts.dials.to_string()
        }
    });

    *current = Some(publication_instance);
    document
}

fn source_facts(
    record: Option<&SessionRecord>,
    options: &StartOptions,
) -> Result<SourceFacts, Value> {
    let Some(record) = record else {
        return Err(refusal("share_start", "unknown_session", "unknown session"));
    };
    if record.shared.is_some() {
        return Err(refusal(
            "share_start",
            "shared_view",
            "this session is a shared view of B; a shared view cannot be shared again",
        ));
    }
    if record.closed || record.closing {
        return Err(refusal(
            "share_start",
            "session_terminal",
            "this session is closed or closing; poll for confirmed reclamation and start a new one",
        ));
    }
    if record.mode != SessionMode::Desktop {
        return Err(refusal(
            "share_start",
            "not_a_desktop_session",
            "a file-transfer session has no picture to share",
        ));
    }
    let Some(viewer) = record.viewer.as_ref() else {
        return Err(refusal(
            "share_start",
            "no_viewer",
            "this session has no running viewer to share from",
        ));
    };
    let snapshot = viewer.snapshot();
    if snapshot.closed || !snapshot.authenticated {
        return Err(refusal(
            "share_start",
            "source_not_authenticated",
            "the source session is not authorized yet; a share publishes an authenticated peer only",
        ));
    }
    if snapshot.protocol != "rustdesk" {
        return Err(refusal(
            "share_start",
            "not_a_rustdesk_source",
            "only a RustDesk peer sends an encoded display list this bridge could republish",
        ));
    }
    // A plaintext source is shareable: the fact is reported as
    // `sourceEncrypted` rather than refused, and B→C stays encrypted regardless.
    if !snapshot.peer_verified && !options.accept_unverified_source {
        return Err(refusal(
            "share_start",
            "source_unverified",
            "the handshake did not prove this source peer; pass acceptUnverifiedSource only after the \
             operator accepted that fact",
        ));
    }
    let Some(display) = usize::try_from(options.display)
        .ok()
        .and_then(|index| snapshot.displays.get(index))
    else {
        return Err(refusal(
            "share_start",
            "unknown_display",
            "the peer reported no display at that index",
        ));
    };
    // The engine independently subscribes this display; B may keep watching another.
    Ok(SourceFacts {
        lifecycle_epoch: record.lifecycle_epoch,
        dials: record.dials,
        display: options.display,
        width: display.width,
        height: display.height,
        source_encrypted: snapshot.encrypted,
        peer_verified: snapshot.peer_verified,
    })
}

/// The refusal every share answer uses. `code` is the stable name a caller can
/// branch on; `message` says what happened.
fn refusal(action: &str, code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "action": action,
        "code": code,
        "reason": code,
        "error": message,
        "message": message,
    })
}

/// Status never exports the invitation token, the pin, or A's route/identity.
///
/// Every counter is the core's own observation of what B wrote, and the display is
/// the one this share asked to republish. `transportClosed` is the nearby byte
/// path, and `lastSendFailure` carries only the fixed label ArkTS named plus its
/// numeric platform code.
fn status_document() -> String {
    let current = publication();
    let Some(publication) = current.as_ref() else {
        return json!({ "ok": true, "state": "idle", "shareEpoch": "0" }).to_string();
    };
    let snapshot = publication.run.snapshot();
    let send = publication.send.lock().unwrap_or_else(|p| p.into_inner());
    json!({
        "ok": true,
        "state": snapshot.state,
        "reason": snapshot.reason,
        "shareEpoch": publication.epoch.to_string(),
        "sessionId": publication.session_id,
        "endpoint": NEARBY_ENDPOINT,
        "expiresAtMs": publication.run.expires_at_ms,
        "transportClosed": publication.bridge.is_closed(),
        "viewerConnected": snapshot.viewer_connected,
        "units": snapshot.units,
        "bytes": snapshot.bytes,
        "dropped": snapshot.dropped,
        "resyncs": snapshot.resyncs,
        "keyframeRequests": snapshot.keyframe_requests,
        "codec": snapshot.codec.map(rd_engine::video::codec_name),
        // The core tracks no per-packet `received` counter, so this layer asks the
        // transport itself instead of inventing a number.
        "sendFailures": send.failures,
        "lastSendFailure": send.label.map(|label| json!({ "label": label, "code": send.code })),
        "width": publication.run.width,
        "height": publication.run.height,
        "display": { "index": publication.run.display },
        "encrypted": true,
        "sourceEncrypted": publication.source_encrypted,
        "peerVerified": publication.peer_verified
    })
    .to_string()
}

enum ShareStage {
    Start(Box<StartOptions>),
    Stop(u64),
}

pub struct ShareWork {
    stage: Option<ShareStage>,
    document: Option<Value>,
    scope: Option<super::app_context::AppScope>,
}

impl ShareWork {
    fn refused(document: Value) -> Self {
        Self {
            stage: None,
            document: Some(document),
            scope: None,
        }
    }

    fn run(&self) -> Value {
        match &self.stage {
            Some(ShareStage::Start(options)) => match self.scope.as_ref() {
                Some(scope) => start_document(options, scope),
                None => refusal("share_start", "app_not_admitted", "share admission is absent"),
            },
            Some(ShareStage::Stop(epoch)) => stop_document(*epoch),
            None => self.document.clone().unwrap_or_else(|| {
                refusal(
                    "share",
                    "not_admitted",
                    "no share operation was admitted",
                )
            }),
        }
    }
}

impl Task for ShareWork {
    type Output = Value;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        Ok(self.run())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi_ohos::Result<Self::JsValue> {
        if let Some(scope) = &self.scope {
            if let Err(message) = scope.check() {
                return Ok(refusal("share_start", "app_not_admitted", &message).to_string());
            }
        }
        Ok(output.to_string())
    }
}

/// Stops the share this caller names.
///
/// The core run is revoked with its stop cause before closing the nearby byte
/// transport. `reclaimed` is the run's own answer, and the
/// wait happens outside the publication lock so this layer never blocks the
/// teardown it is waiting for.
fn stop_document(share_epoch: u64) -> Value {
    let (run, bridge) = {
        let current = publication();
        let Some(publication) = current
            .as_ref()
            .filter(|publication| publication.epoch == share_epoch)
        else {
            return refusal(
                "share_stop",
                "stale_share_epoch",
                "the named share is not current",
            );
        };
        publication.revoke("user_stop");
        (publication.run.clone(), publication.bridge.clone())
    };
    let reclaimed = run.wait_closed(Duration::from_secs(10));
    json!({
        "ok": reclaimed,
        "action": "share_stop",
        "shareEpoch": share_epoch.to_string(),
        "reason": "user_stop",
        "reclaimed": reclaimed,
        "bridgeClosed": bridge.is_closed(),
        "message": if reclaimed {
            ""
        } else {
            "the core forward run has not confirmed reclamation yet; poll shareGetStatus"
        }
    })
}

/// Arms one share of the display the caller names on the named session and
/// answers with the invite a third device can consume.
///
/// Admission is bound to this app generation and the source Viewer. Only the core
/// run can issue an invitation, and its code names the nearby transport rather
/// than any address: nothing here listens, binds or dials.
#[napi(ts_return_type = "Promise<string>")]
pub fn share_start(options_json: String) -> AsyncTask<ShareWork> {
    if options_json.len() > MAX_OPTIONS_BYTES {
        return AsyncTask::new(ShareWork::refused(refusal(
            "share_start",
            "options_too_large",
            "shareStart options are larger than this layer accepts",
        )));
    }
    let parsed = serde_json::from_str::<Value>(&options_json)
        .map_err(|_| "shareStart options must be a JSON object".to_string())
        .and_then(|value| parse_start(&value));
    let scope = match super::app_context::app_scope() {
        Ok(scope) => scope,
        Err(message) => return AsyncTask::new(ShareWork::refused(refusal("share_start", "app_not_admitted", &message))),
    };
    AsyncTask::new(match parsed {
        Ok(options) => ShareWork {
            stage: Some(ShareStage::Start(Box::new(options))),
            document: None,
            scope: Some(scope),
        },
        Err(message) => ShareWork::refused(refusal("share_start", "invalid_options", &message)),
    })
}

/// Stops the share this epoch names. An empty or malformed epoch is refused
/// before anything is looked up.
#[napi(ts_return_type = "Promise<string>")]
pub fn share_stop(share_epoch: String) -> AsyncTask<ShareWork> {
    let parsed = share_epoch
        .parse::<u64>()
        .ok()
        .filter(|epoch| *epoch != 0)
        .ok_or_else(|| "shareStop shareEpoch must be the decimal epoch shareStart returned".to_string());
    AsyncTask::new(match parsed {
        Ok(epoch) => ShareWork {
            stage: Some(ShareStage::Stop(epoch)),
            document: None,
            scope: None,
        },
        Err(message) => ShareWork::refused(refusal("share_stop", "invalid_share_epoch", &message)),
    })
}

/// The share's own state, without the invite code or its token.
///
/// The response contains only observed run state, never its invitation token.
#[napi]
pub fn share_get_status() -> String {
    status_document()
}

/// The invite code, only while a share is listening and the code is unconsumed.
///
/// A consumed, expired or revoked run cannot issue another code.
#[napi]
pub fn share_get_invite(share_epoch: String) -> String {
    let parsed = share_epoch
        .parse::<u64>()
        .ok()
        .filter(|epoch| *epoch != 0);
    let Some(epoch) = parsed else {
        return refusal(
            "share_invite",
            "invalid_share_epoch",
            "shareGetInvite shareEpoch must be the decimal epoch shareStart returned",
        )
        .to_string();
    };
    let scope = match super::app_context::app_scope() {
        Ok(scope) => scope,
        Err(message) => return refusal("share_invite", "app_not_admitted", &message).to_string(),
    };
    let _admission = match scope.hold() {
        Ok(admission) => admission,
        Err(message) => return refusal("share_invite", "app_not_admitted", &message).to_string(),
    };
    let current = publication();
    let Some(publication) = current.as_ref().filter(|publication| publication.epoch == epoch) else {
        return refusal("share_invite", "stale_share_epoch", "the named share is not current").to_string();
    };
    match invite(publication) {
        Some(code) => json!({ "ok": true, "shareEpoch": epoch.to_string(), "inviteCode": code }).to_string(),
        None => refusal("share_invite", "invite_spent", "the share invite is expired, consumed or revoked").to_string(),
    }
}

/// Keep these exports bound to their Rust implementations.
#[allow(dead_code)]
fn declared_share_entry_points_exist() {
    let _ = (
        share_start,
        share_stop,
        share_get_status,
        share_get_invite,
        share_poll_send_data,
        share_push_receive_data,
        share_report_send_result,
        share_connect_transport,
        share_get_transport_status,
    );
}

/// The share epoch ArkTS names, or `None` when the string is not one this layer
/// issued. An empty or malformed epoch is never resolved to the current share.
fn parse_share_epoch(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().filter(|epoch| *epoch != 0)
}

/// Takes the next already-framed byte chunk the core has queued for C.
///
/// The bytes cross as they are: the core's own sequence-and-length framing is
/// already in them, so nothing here re-frames, splits, joins or re-encodes them.
/// An empty array is the single answer for "nothing is queued right now" and for
/// a stale epoch, which is why a caller must take only a non-empty array as one
/// chunk to send and must never read the empty one as a frame or an end marker.
///
/// A transport error is not reported as an empty queue forever: the share is
/// revoked, so the next poll stays empty *and* `shareGetStatus` shows
/// `transportClosed`.
#[napi]
pub fn share_poll_send_data(share_epoch: String) -> Uint8Array {
    let Some(epoch) = parse_share_epoch(&share_epoch) else {
        return Uint8Array::new(Vec::new());
    };
    let current = publication();
    let Some(publication) = current.as_ref().filter(|p| p.epoch == epoch) else {
        return Uint8Array::new(Vec::new());
    };
    if publication.is_closed() {
        return Uint8Array::new(Vec::new());
    }
    match publication.bridge.take_output() {
        Ok(Some(chunk)) => Uint8Array::new(chunk),
        Ok(None) => Uint8Array::new(Vec::new()),
        Err(_) => {
            publication.revoke("transport_failed");
            Uint8Array::new(Vec::new())
        }
    }
}

/// Hands one byte chunk from the nearby transport to the core.
///
/// `accepted` means the chunk entered the core's bounded, framed input queue. It
/// is not evidence that the peer read it and not an acknowledgement. A full queue
/// or a closed transport is refused with `transport_rejected`: this layer does not
/// retry, because the core's own framing is what decides whether a byte run is
/// missing, duplicated or out of order.
#[napi]
pub fn share_push_receive_data(share_epoch: String, data: Uint8Array) -> String {
    const ACTION: &str = "share_receive_data";
    let Some(epoch) = parse_share_epoch(&share_epoch) else {
        return refusal(
            ACTION,
            "invalid_share_epoch",
            "shareEpoch must be a positive decimal integer",
        )
        .to_string();
    };
    if data.len() == 0 {
        return refusal(ACTION, "empty_data", "the nearby transport delivered no bytes").to_string();
    }
    let current = publication();
    let Some(publication) = current.as_ref().filter(|p| p.epoch == epoch) else {
        return refusal(ACTION, "stale_share_epoch", "the named share is not current").to_string();
    };
    if publication.is_closed() {
        return refusal(
            ACTION,
            "share_closed",
            "the share is stopped, failed, or its transport already closed",
        )
        .to_string();
    }
    let bytes = data.len();
    match publication.bridge.push_input(&data) {
        Ok(()) => json!({
            "ok": true,
            "action": ACTION,
            "shareEpoch": share_epoch,
            "accepted": true,
            "bytes": bytes
        })
        .to_string(),
        Err(error) => refusal(ACTION, "transport_rejected", &error.to_string()).to_string(),
    }
}

/// Records what the platform's `sendData` call did with one chunk.
///
/// `ok: true` means only that the platform call completed. It is not a peer read,
/// a decode or a presented frame, and this layer never reports it as one.
///
/// A rejection ends the share: a transport that refused a frame cannot be handed
/// the next one in order, so answering `ok: true` would be claiming a link that
/// is gone. The caller names a fixed `label` and a numeric platform `code`; no
/// platform message text crosses this boundary, so nothing frame-shaped or
/// session-shaped can be retained here.
#[napi]
pub fn share_report_send_result(
    share_epoch: String,
    ok: bool,
    label: String,
    code: i32,
) -> String {
    const ACTION: &str = "share_send_result";
    let Some(epoch) = parse_share_epoch(&share_epoch) else {
        return refusal(
            ACTION,
            "invalid_share_epoch",
            "shareEpoch must be a positive decimal integer",
        )
        .to_string();
    };
    let current = publication();
    let Some(publication) = current.as_ref().filter(|p| p.epoch == epoch) else {
        return refusal(ACTION, "stale_share_epoch", "the named share is not current").to_string();
    };
    if ok {
        return json!({
            "ok": true,
            "action": ACTION,
            "shareEpoch": share_epoch,
            "reported": true,
            "meaning": "platform_call_completed"
        })
        .to_string();
    }
    let label = send_failure_label(&label);
    let snapshot = publication.run.snapshot();
    if snapshot.state == "stopping" || snapshot.closed {
        return json!({
            "ok": false, "action": ACTION, "shareEpoch": share_epoch,
            "code": "share_closed", "reason": snapshot.reason,
            "shareClosed": true, "reported": false
        }).to_string();
    }
    if let Some(reason) = non_send_reason(label) {
        publication.revoke(reason);
        return json!({
            "ok": false, "action": ACTION, "shareEpoch": share_epoch,
            "code": "transport_closed", "reason": reason, "label": label,
            "shareClosed": true, "reported": true
        }).to_string();
    }
    let failures = {
        let mut send = publication.send.lock().unwrap_or_else(|p| p.into_inner());
        send.failures = send.failures.saturating_add(1);
        send.label = Some(label);
        send.code = Some(i64::from(code));
        send.failures
    };
    publication.revoke("send_failed");
    json!({
        "ok": false,
        "action": ACTION,
        "shareEpoch": share_epoch,
        "code": "send_failed",
        "label": label,
        "platformCode": code,
        "sendFailures": failures,
        "shareClosed": true,
        "message": "the platform rejected a nearby send; the share is closed"
    })
    .to_string()
}

/// Activates the nearby run this epoch names, once the DMS link is really up.
///
/// The core arms the run before a collaborator exists, and its own bounded wait
/// for the login must not start until the platform link is connected and ArkTS is
/// about to pump bytes. This call is that explicit latch: it changes no state of
/// its own, so a refusal here leaves the run exactly as it was, and the invite
/// stays valid until the connection is admitted.
///
/// Admission and the source are rechecked here rather than trusted from the
/// caller: a backgrounded app or a closed source must not activate a run.
#[napi]
pub fn share_connect_transport(share_epoch: String) -> String {
    const ACTION: &str = "share_connect_transport";
    let Some(epoch) = parse_share_epoch(&share_epoch) else {
        return refusal(
            ACTION,
            "invalid_share_epoch",
            "shareEpoch must be a positive decimal integer",
        )
        .to_string();
    };
    // APP -> SHARE: the same order publication takes, so a lifecycle fence cannot
    // retire the app between this check and the activation.
    let scope = match super::app_context::app_scope() {
        Ok(scope) => scope,
        Err(message) => return refusal(ACTION, "app_not_admitted", &message).to_string(),
    };
    let _admission = match scope.hold() {
        Ok(admission) => admission,
        Err(message) => return refusal(ACTION, "app_not_admitted", &message).to_string(),
    };
    let current = publication();
    let Some(publication) = current
        .as_ref()
        .filter(|publication| publication.epoch == epoch)
    else {
        return refusal(ACTION, "stale_share_epoch", "the named share is not current").to_string();
    };
    if publication.is_closed() {
        return refusal(
            ACTION,
            "share_closed",
            "the share is stopped, failed, or its transport already closed",
        )
        .to_string();
    }
    match publication.run.connect_nearby() {
        Ok(()) => json!({
            "ok": true,
            "action": ACTION,
            "shareEpoch": share_epoch,
            "connected": true
        })
        .to_string(),
        Err(error) => refusal(ACTION, "connect_failed", &error.to_string()).to_string(),
    }
}

/// Observed nearby-transport state for the share this epoch names.
///
/// `transportClosed` is the only fact a caller has to branch on: `ok: false` says
/// the epoch is not current, and a current epoch reports whether its byte path is
/// already closed. Nothing here is a queue depth, a peer read or a presentation
/// acknowledgement, and no address, token or pin is part of it.
#[napi]
pub fn share_get_transport_status(share_epoch: String) -> String {
    const ACTION: &str = "share_transport_status";
    let Some(epoch) = parse_share_epoch(&share_epoch) else {
        return refusal(
            ACTION,
            "invalid_share_epoch",
            "shareEpoch must be a positive decimal integer",
        )
        .to_string();
    };
    let current = publication();
    let Some(publication) = current.as_ref().filter(|p| p.epoch == epoch) else {
        return refusal(ACTION, "stale_share_epoch", "the named share is not current").to_string();
    };
    let snapshot = publication.run.snapshot();
    json!({
        "ok": true,
        "action": ACTION,
        "shareEpoch": share_epoch,
        "state": snapshot.state,
        "reason": snapshot.reason,
        "transportClosed": publication.bridge.is_closed(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{send_failure_label, ShareInvite};

    /// The wire format is one owner's contract, so the test builds a code from the
    /// documented field names and checks that the parser reads back every field —
    /// and that a tampered one is refused rather than defaulted.
    fn code(fields: serde_json::Value) -> String {
        use hbb_common::base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        format!(
            "RKS1.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&fields).unwrap())
        )
    }

    fn valid() -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "ep": "nearby",
            "id": "123456789",
            "pk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "tok": "abcdefghijklmnopqrst",
            "exp": 1_700_000_300_000u64,
            "ep0": 7,
        })
    }

    fn with_ep(ep: serde_json::Value) -> serde_json::Value {
        let mut fields = valid();
        fields["ep"] = ep;
        fields
    }

    #[test]
    fn a_nearby_share_code_round_trips_through_its_own_fields() {
        let invite = ShareInvite::parse(&code(valid())).expect("the documented code parses");
        assert_eq!(invite.host_id, "123456789");
        assert_eq!(invite.token, "abcdefghijklmnopqrst");
        assert_eq!(invite.expires_at_ms, 1_700_000_300_000);
        assert_eq!(invite.share_epoch, 7);
        assert!(invite.admitted_at(1_700_000_000_000).is_ok());
        assert!(
            invite.admitted_at(1_700_000_300_000).is_err(),
            "the deadline is exclusive"
        );
    }

    /// The retired LAN route named an address in `ep`. A receiver that still
    /// accepted one would be able to dial something this product no longer uses,
    /// so both an address and an empty value are refused rather than defaulted
    /// into the nearby transport.
    #[test]
    fn a_code_naming_an_endpoint_is_refused() {
        for ep in [
            serde_json::json!("192.168.1.24:49733"),
            serde_json::json!("127.0.0.1:49733"),
            serde_json::json!(""),
            serde_json::json!("nearby:0"),
        ] {
            assert!(
                ShareInvite::parse(&code(with_ep(ep.clone()))).is_err(),
                "ep {ep} is not the nearby transport"
            );
        }
    }

    #[test]
    fn a_tampered_share_code_is_refused_instead_of_defaulted() {
        assert!(ShareInvite::parse("rks1.e30").is_err(), "the prefix is exact");
        let mut unknown = valid();
        unknown["lifecycleEpoch"] = serde_json::json!(3);
        assert!(
            ShareInvite::parse(&code(unknown)).is_err(),
            "unknown fields are refused"
        );
        let mut version = valid();
        version["v"] = serde_json::json!(2);
        assert!(ShareInvite::parse(&code(version)).is_err());
        let mut short = valid();
        short["tok"] = serde_json::json!("short");
        assert!(ShareInvite::parse(&code(short)).is_err());
        let mut key = valid();
        key["pk"] = serde_json::json!("AAAA");
        assert!(
            ShareInvite::parse(&code(key)).is_err(),
            "the pin is a 32-byte key"
        );
        let far = ShareInvite::parse(&code(valid())).expect("valid code");
        assert!(
            far.admitted_at(1_600_000_000_000).is_err(),
            "a deadline beyond any share this format issues is refused"
        );
    }

    /// ArkTS names a fixed label, never the platform's own message: a message can
    /// quote the frame or the transport session, so anything unrecognised is
    /// recorded as `unknown` and the original text is dropped.
    #[test]
    fn a_send_failure_label_never_carries_platform_text() {
        assert_eq!(send_failure_label("send_data_rejected"), "send_data_rejected");
        assert_eq!(send_failure_label("transport_closed"), "transport_closed");
        assert_eq!(
            send_failure_label("BusinessError 401: session 7 payload AAECAwQF"),
            "unknown"
        );
        assert_eq!(send_failure_label(""), "unknown");
    }
}
