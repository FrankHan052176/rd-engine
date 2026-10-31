//! ArkTS-facing NAPI surface of rd-engine.
//!
//! This HarmonyOS-only kernel output serves the typed `rustdesk-ohrs` package.
//! Its manifest distinguishes real engine-backed exports from unsupported
//! legacy client capabilities; no entry point fabricates success or telemetry.
use base::message_proto::{ControlKey, KeyEvent, KeyboardMode};
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, JsUnknown, NapiRaw, Task},
    Env,
};
use rd_engine::protocol::Target;
use rd_engine::session::PeerCloseReason;
use rd_engine::viewer::{
    direct_address, InputPolicyOutcome, LoginFailure, SurfaceLease, Viewer, ViewerInputPolicy,
    ViewerOptions, ViewerSnapshot, ViewerTarget,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{Arc, Mutex, MutexGuard},
};
mod app_context;
mod app_directory;
mod app_presence;
mod app_profile;
mod app_storage;
mod server_profile;
mod xcomponent;
use app_context::{
    app_init, app_set_lifecycle, lan_peer_remove, lan_peers_query, lan_scan_start, lan_scan_stop,
};
use app_directory::{
    runtime_list_favorites, runtime_list_recent_peers, runtime_record_recent_peer,
    runtime_remove_recent_peer, runtime_set_favorite,
};
use app_presence::{peer_presence_cancel, peer_query_online};
use app_profile::{runtime_get_server_config, runtime_set_server_config, runtime_test_server_config};
use server_profile::{validate_server_profile, ApprovedRoute};
mod capabilities;
use capabilities::query_decoder_capabilities;

/// This session's one Surface destination: a slot filled exactly once from a
/// real native XComponent holder borrow and never redirected afterwards.
///
/// The client asks for the session before it creates its XComponent, so the
/// viewer is given this slot rather than a finished lease. It reads the
/// destination when the first frame opens the Surface; an empty slot reports
/// `is_ready() == false`, which is what makes the engine wait in
/// `awaiting_surface` (bounded by its own surface wait) instead of presenting
/// into nothing. Only `xcomponent::borrow_surface` may fill it: a decimal
/// Surface id, a node label or any other caller-supplied string is not a lease
/// and is refused before the slot is touched.
struct PendingSurfaceLease {
    published: Mutex<Option<Arc<dyn SurfaceLease>>>,
}

impl PendingSurfaceLease {
    fn new() -> Self {
        Self {
            published: Mutex::new(None),
        }
    }

    fn slot(&self) -> MutexGuard<'_, Option<Arc<dyn SurfaceLease>>> {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Publishes the real holder loan. A second fill is refused: a running
    /// viewer already holds this slot, and changing what it points at would be
    /// the hot rebind the engine does not perform.
    fn publish(&self, lease: Arc<dyn SurfaceLease>) -> Result<(), &'static str> {
        let mut slot = self.slot();
        if slot.is_some() {
            return Err("this session's Surface destination is already published");
        }
        *slot = Some(lease);
        Ok(())
    }

    /// Empties the slot, and with it the session's last strong reference to the
    /// holder loan. Only confirmed reclamation, or a binding the session never
    /// used, may do this, so no viewer or decoder can still be presenting here.
    /// No UI SDK work happens on drop; the holder's own detach does that.
    fn release(&self) {
        let taken = self.slot().take();
        drop(taken);
    }

    /// The real Surface id of the published loan, or 0 while the slot is empty.
    fn published_surface_id(&self) -> u64 {
        self.slot().as_ref().map_or(0, |lease| lease.surface_id())
    }
}

// SAFETY: this slot only ever holds the lease it was given, so retaining it
// retains that Surface exactly as the inner lease promises; `surface_id`
// reports the inner id and never a made-up one, and an empty slot reports 0
// (not ready) rather than a destination. Filling it is serialized and one-shot,
// so a live destination cannot be swapped under a decoder.
unsafe impl SurfaceLease for PendingSurfaceLease {
    fn surface_id(&self) -> u64 {
        self.published_surface_id()
    }

    fn is_ready(&self) -> bool {
        self.slot().as_ref().is_some_and(|lease| lease.is_ready())
    }
}

/// The existing direct-viewer labels remain unchanged. Explicit ID routes and
/// discovery instead capture the official Config local ID from appInit; neither
/// synchronous session operation performs lazy Config I/O.
const LOCAL_ID: &str = "rd-engine-ohos";
const LOCAL_NAME: &str = "rd-engine-ohos";

/// The `session_set_common` keys the engine acts on. Every other pair is kept on
/// the record and answered as recorded but not acted on.
const COMMON_ACTED_ON: [&str; 2] = ["view-only", "fps"];

/// Count bound, including live, quarantined and unacknowledged terminal records.
/// Capacity is never recovered by evicting a record whose receipt is still owed.
const MAX_SESSION_RECORDS: usize = 256;

struct IdRoute {
    profile: ApprovedRoute,
    admission: app_context::IdAdmission,
}

/// A real binding of this record's single lease, not a decoder destination from
/// another backend. Retain its identity after the lease is released so the
/// terminal receipt can still name what was released.
struct SurfaceBinding {
    /// The native borrow token this destination came from.
    token: u64,
    /// The holder scope whose loan this is; a different componentId may never
    /// replace it while this session owns the destination.
    component_id: String,
    /// The real Surface id of the borrowed loan at bind time.
    surface_id: u64,
    display: u32,
}

struct SessionRecord {
    lifecycle_epoch: u64,
    target: String,
    viewer_target: ViewerTarget,
    /// Explicit-save profile and local identity, owned at registration. Starts
    /// never read editable server settings or import trust from the target.
    id_route: Option<IdRoute>,
    /// A confirmed terminal record remains until receipt consumption is ACKed.
    /// Registration never overwrites an existing id, even after reclamation.
    closed: bool,
    /// Close has been requested, or its terminal verdict did not permit native
    /// Surface reuse. Only `closed && reclaimed == Some(true)` is reusable.
    closing: bool,
    /// `Some(true)` only after the engine confirmed the Surface was reclaimed;
    /// `Some(false)` means it could not prove that release. This is separate
    /// from a remote/authentication failure, which lives in the snapshot.
    reclaimed: Option<bool>,
    password: String,
    fps: u32,
    viewer: Option<Arc<Viewer>>,
    /// Final facts survive releasing the registry's Viewer and password copies.
    terminal_snapshot: Option<ViewerSnapshot>,
    terminal_elapsed_ms: Option<u64>,
    /// A complete close/poll JSON receipt was constructed for this epoch.
    /// This is not delivery proof or an ACK, and is independent of events.
    terminal_receipt_constructed: bool,
    /// Last selected-display-local absolute pointer position the engine actually
    /// admitted for this session. The canonical input contract sends button
    /// transitions without coordinates, so this record supplies the position of
    /// the most recent admitted move.
    ///
    /// A position is not a hold the engine owns, so a policy or permission
    /// change does not invalidate it and it is kept across one. What it never
    /// survives is a refusal: a call resolves its candidate without touching
    /// this field and commits it only after the engine admitted the event that
    /// carried it.
    cursor: Option<(i32, i32)>,
    /// The single destination a viewer is given. It is empty until this record
    /// borrows the native XComponent holder, so registration (which the client
    /// does before it creates that XComponent) needs no Surface, and the
    /// engine's own bounded surface wait covers the gap.
    lease: Arc<PendingSurfaceLease>,
    /// The record's own claim on one native XComponent holder: the borrow keeps
    /// the holder, its callbacks and the loan owned until the engine confirms
    /// reclamation, so nothing the decoder or the UI can still be using is
    /// dropped early.
    borrow: Option<xcomponent::SurfaceBorrow>,
    /// Receipt facts of the destination above, kept after release so a terminal
    /// receipt still names what was released.
    binding: Option<SurfaceBinding>,
    /// The local input policy this session runs under: the operator's read-only
    /// switch and this connection's acceptance of a peer the handshake did not
    /// prove. It is the engine's policy, not this layer's: `sessionSetViewOnly`
    /// and `sessionSetUnverifiedInputAccepted` publish it to the running viewer,
    /// and `dial` starts the next one with it.
    input_policy: ViewerInputPolicy,
    /// `session_set_common` pairs, keyed exactly as the client sent them.
    common: HashMap<String, String>,
    /// What `session_poll_events` has already reported for the running viewer,
    /// so a repeated poll does not repeat an event the client acted on.
    reported: Reported,
    /// How many times this record dialled a viewer, and when the running one
    /// started: the client discards its telemetry window when either identity
    /// changes, so both travel with the frame-rate snapshot.
    dials: u64,
    started: Instant,
}

impl Drop for SessionRecord {
    fn drop(&mut self) {
        scrub_password(&mut self.password);
    }
}

fn scrub_password(password: &mut String) {
    let mut bytes = std::mem::take(password).into_bytes();
    hbb_common::sodiumoxide::utils::memzero(&mut bytes);
}

/// Only called after confirmed reclamation (or a close that never had a Viewer).
fn scrub_terminal_record(record: &mut SessionRecord) {
    scrub_password(&mut record.password);
    record.viewer.take();
    record.cursor = None;
    record.common.clear();
    record.id_route = None;
}

/// Authorization and terminal facts already reported for the current viewer.
///
/// Phases are forwarded unchanged. Waiting for the host operator is not a
/// password rejection and must not fabricate an input-password event.
/// Starting a new viewer resets these one-shot facts.
#[derive(Default)]
struct Reported {
    /// The engine's own evidence that the peer authorized this session.
    authorized: bool,
    /// The viewer finished; the snapshot's error rides on that event.
    finished: bool,
}

impl Reported {
    /// The events this snapshot justifies and the client has not been told yet.
    ///
    /// Only states the engine reports become events: the phase a driver set and
    /// the error the snapshot carries. A phase this vocabulary cannot express is
    /// named in the answer's `note` instead of being turned into an event.
    fn events(&mut self, snapshot: &ViewerSnapshot) -> Vec<serde_json::Value> {
        let mut events = Vec::new();
        // Authentication is an explicit snapshot fact, not a phase inference.
        // In particular RFB is already authenticated while it waits for the
        // client to bind its Surface, so peer_info must reach ArkTS in that
        // window or the client can never create the binding the viewer awaits.
        if snapshot.authenticated && !self.authorized {
            self.authorized = true;
            events.push(peer_info_event(snapshot));
            events.push(authorized_event(snapshot));
        }
        // `State::finish` is what sets `closed`; `"closing"` is a teardown that
        // has not finished, and an error a running decoder reports is not one.
        if snapshot.closed && !self.finished {
            self.finished = true;
            let mut event = serde_json::json!({ "name": "close" });
            if let Some(error) = &snapshot.error {
                event["err"] = serde_json::Value::String(error.clone());
            }
            events.push(event);
        }
        events
    }
}

static SESSIONS: Mutex<Option<HashMap<String, SessionRecord>>> = Mutex::new(None);
// One native allocation domain for record epochs and binding tokens. It never
// wraps or resets on ACK, so a reused client session id cannot inherit an epoch.
static NEXT_NATIVE_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_native_id() -> Result<u64, &'static str> {
    NEXT_NATIVE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
        .map_err(|_| "native lifecycle identity exhausted")
}

fn with_sessions<T>(change: impl FnOnce(&mut HashMap<String, SessionRecord>) -> T) -> T {
    let mut guard = SESSIONS.lock().unwrap_or_else(|error| error.into_inner());
    change(guard.get_or_insert_with(HashMap::new))
}

/// Applies the only state transition that permits a new session to take this
/// record's native surface. A terminal remote session is not sufficient: the
/// decoder's own reclamation verdict must be `Some(true)` first.
fn apply_terminal_reclamation(
    closed: &mut bool,
    closing: &mut bool,
    reclaimed: &mut Option<bool>,
    lease: &PendingSurfaceLease,
    verdict: Option<bool>,
) {
    match verdict {
        Some(true) => {
            *closed = true;
            *closing = false;
            *reclaimed = Some(true);
            // The decoder proved it no longer holds this destination, so the
            // session's published loan is emptied. Only dropping the last
            // reference lets the XComponent holder be detached; the holder's own
            // detach still performs every native release.
            lease.release();
        }
        Some(false) => {
            *closed = false;
            *closing = true;
            *reclaimed = Some(false);
        }
        None => {
            *closed = false;
            *closing = true;
        }
    }
}

/// Commits the owner's terminal facts without consuming a receipt. Unknown or
/// failed reclamation retains the Viewer, lease and registry record.
fn record_terminal_reclamation(
    record: &mut SessionRecord,
    snapshot: &ViewerSnapshot,
    verdict: Option<bool>,
) {
    if snapshot.closed {
        if verdict.is_some() && record.terminal_snapshot.is_none() {
            // Preserve the actual failure, input account and telemetry BEFORE
            // clearing the lease, password or registry's last Viewer reference.
            record.terminal_snapshot = Some(snapshot.clone());
            record.terminal_elapsed_ms = Some(
                u64::try_from(record.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
        }
        apply_terminal_reclamation(
            &mut record.closed,
            &mut record.closing,
            &mut record.reclaimed,
            record.lease.as_ref(),
            verdict,
        );
        if verdict == Some(true) {
            // Confirmed reclamation is the only point at which this record's last
            // strong reference to the holder loan can go: a viewer that failed to
            // register, a quarantined decoder and an unacknowledged receipt all
            // keep it until here, so the holder is never released early.
            record.borrow = None;
            scrub_terminal_record(record);
        }
    }
}

/// Cold lifecycle observation is not proof that a receipt was constructed.
fn observe_terminal_reclamation(record: &mut SessionRecord) -> Option<ViewerSnapshot> {
    if let Some(snapshot) = &record.terminal_snapshot {
        return Some(snapshot.clone());
    }
    let viewer = record.viewer.as_ref()?;
    let snapshot = viewer.snapshot();
    let verdict = viewer.reclamation_confirmed();
    record_terminal_reclamation(record, &snapshot, verdict);
    Some(snapshot)
}

/// No setter or dial may refill a tombstone, including one first observed here.
fn mutable_snapshot(record: &mut SessionRecord) -> Result<Option<ViewerSnapshot>, &'static str> {
    let snapshot = observe_terminal_reclamation(record);
    if record.closed {
        return Err("session closed; poll and acknowledge its terminal receipt before registering a new session");
    }
    if record.closing || snapshot.as_ref().is_some_and(|value| value.closed) {
        return Err("session is closing; wait for sessionPollEvents to confirm reclamation");
    }
    Ok(snapshot)
}

fn login_failure_name(failure: Option<LoginFailure>) -> Option<&'static str> {
    match failure {
        Some(LoginFailure::EmptyPassword) => Some("empty_password"),
        Some(LoginFailure::WrongPassword) => Some("wrong_password"),
        Some(LoginFailure::Refused) => Some("refused"),
        None => None,
    }
}

fn peer_close_reason_name(reason: Option<PeerCloseReason>) -> Option<&'static str> {
    match reason {
        Some(PeerCloseReason::ManualRequest) => Some("manual_request"),
        None => None,
    }
}

fn error_json(message: &str) -> String {
    serde_json::json!({ "ok": false, "error": message, "message": message }).to_string()
}

/// A refusal that names the generation the running viewer is at now.
///
/// The engine refused the event, so nothing was queued and this is not a
/// receipt: it is the epoch this viewer's input gate holds now, which is what a
/// client needs to retire input state it kept for an epoch the engine has left.
/// A caller that cannot be told an epoch — an unknown session, a session with no
/// running viewer — answers with `error_json` instead of inventing one.
fn refusal_json(message: &str, generation: u64) -> String {
    serde_json::json!({
        "ok": false,
        "error": message,
        "message": message,
        "input_generation": generation,
    })
    .to_string()
}

/// The largest input generation the bridge accepts from ArkTS.
///
/// ArkTS carries a generation as an IEEE-754 double, and this is the largest
/// integer it can hold exactly (`Number.MAX_SAFE_INTEGER`). A generation above
/// it could not have come from the client intact, so it is refused rather than
/// rounded into an epoch the engine would then compare against.
const MAX_SAFE_INPUT_GENERATION: f64 = 9_007_199_254_740_991.0;

/// The input generation one input call names, validated as the exact epoch the
/// engine may compare against.
///
/// The value is never inferred, rounded, clamped or defaulted: a caller that
/// cannot name the generation it is acting on has to poll the engine first.
fn expected_input_generation(action: &str, value: f64) -> Result<u64, String> {
    if !value.is_finite()
        || value.fract() != 0.0
        || value < 1.0
        || value > MAX_SAFE_INPUT_GENERATION
    {
        return Err(format!(
            "{action} inputGeneration must be a positive safe integer"
        ));
    }
    Ok(value as u64)
}

/// Parses the protocol without choosing a trust source. A RustDesk ID needs a
/// separately approved route at registration. Direct VNC/RDP retain their
/// endpoints; RDP requires an explicit account and engine certificate checks.
fn parse_viewer_target(
    target: &str,
    rustdesk_id_only: bool,
) -> Result<(ViewerTarget, String), String> {
    match Target::parse(target).map_err(|error| error.to_string())? {
        Target::RustDesk(_) if rustdesk_id_only => Ok((
            ViewerTarget::RustDesk { address: None },
            "RustDesk claimed-ID intent recorded with an explicitly approved server route"
                .to_string(),
        )),
        Target::Vnc(_) | Target::Rdp(_) if rustdesk_id_only => {
            Err("rustdeskIdOnly cannot select a VNC or RDP protocol target".to_string())
        }
        Target::RustDesk(raw) => match direct_address(&raw) {
            Some(address) => Ok((
                ViewerTarget::RustDesk {
                    address: Some(address),
                },
                format!("RustDesk direct address recorded: {address}"),
            )),
            None => Ok((
                ViewerTarget::RustDesk { address: None },
                "RustDesk ID recorded with an explicitly approved server route".to_string(),
            )),
        },
        Target::Vnc(endpoint) => {
            let destination = endpoint.to_string();
            Ok((
                ViewerTarget::Vnc(endpoint),
                format!("VNC direct endpoint recorded: {destination}"),
            ))
        }
        Target::Rdp(endpoint) => {
            if endpoint.user.as_deref().is_none_or(str::is_empty) {
                return Err("RDP requires an explicit account in the endpoint".to_string());
            }
            Ok((
                ViewerTarget::Rdp(endpoint),
                "RDP direct endpoint recorded".to_string(),
            ))
        }
    }
}

/// Starts the existing direct or strict rendezvous connector with one immutable
/// record. ID username/config.id are the same canonical target; the raw wire
/// key and decoded signer stay separate in the captured route.
///
/// The destination handed over is this session's single slot, which may still be
/// empty: a viewer that authenticates before the client has attached its
/// XComponent waits in `awaiting_surface` for the holder borrow, whose bounded
/// surface wait turns "never bound" into an explicit failure rather than a
/// permanent one.
fn dial(record: &SessionRecord) -> Result<Arc<Viewer>, String> {
    let _admission = record
        .id_route
        .as_ref()
        .map(|route| app_context::hold_id_admission(&route.admission))
        .transpose()?;
    let options = ViewerOptions {
        target: record.viewer_target.clone(),
        username: record.id_route.as_ref().map_or_else(
            || record.target.clone(),
            |route| route.profile.id().to_owned(),
        ),
        local_id: record.id_route.as_ref().map_or_else(
            || LOCAL_ID.to_owned(),
            |route| route.admission.local_id.clone(),
        ),
        local_name: LOCAL_NAME.to_owned(),
        password: record.password.clone(),
        requested_fps: record.fps,
        input_policy: record.input_policy,
    };
    let lease: Arc<dyn SurfaceLease> = record.lease.clone();
    match &record.id_route {
        Some(route) => Viewer::start_rendezvous(options, lease, route.profile.configuration()),
        None => Viewer::start(options, lease),
    }
    .map_err(|error| format!("{error:?}"))
}

/// Publishes one session's input policy to whatever is running for it.
///
/// The engine is the enforcer, not this layer: a running viewer is told, and it
/// answers with the release its own writer still owes the peer. A session with
/// no viewer has emitted nothing, so there is nothing to release and the policy
/// is simply the one its next dial starts under.
fn publish_input_policy(
    record: &SessionRecord,
    policy: ViewerInputPolicy,
) -> Option<InputPolicyOutcome> {
    record
        .viewer
        .as_ref()
        .map(|viewer| viewer.set_input_policy(policy))
}

/// What one viewer's writer still owes the peer, in the words every answer that
/// carries the release counters uses.
///
/// It is chosen from those counters alone — never from whether this particular
/// call revoked admission — so a repeated setter or a poll can never describe a
/// release that has not been made as one that does not exist. `retired` is the
/// pending part: holds a change retired that the writer has not released, which
/// is what a client is waiting for; `owed` alone would also count the keys and
/// buttons the operator is holding right now.
fn release_note(retired: u64, unreleased: u64) -> Option<&'static str> {
    if retired > 0 {
        Some("this viewer's writer has not yet released the keys and buttons a policy or permission change retired; release_pending says that release has not completed")
    } else if unreleased > 0 {
        Some("a release this viewer owed is unconfirmed: its writer stopped before the release was made, so whether the peer still holds the key or button is unknown; releases_unreleased counts it")
    } else {
        None
    }
}

/// The answer a policy change returns.
///
/// `admission_revoked` is what the call already did, and `release_pending` is
/// what the engine's writer still owes the peer for the keys and buttons a
/// change retired. `releases_owed` is everything the writer owns, a key the
/// operator is holding included; `releases_unreleased` counts holds whose writer
/// stopped before it could release them. A release is never reported as
/// completed merely because a setter returned, and `input_generation` names the
/// generation this viewer's gate is at now, so a client that keeps input state
/// of its own can tell that the engine invalidated what came before this answer
/// even when this particular call changed nothing.
fn policy_json(
    action: &str,
    policy: ViewerInputPolicy,
    outcome: Option<InputPolicyOutcome>,
) -> String {
    let revoked = outcome.is_some_and(|outcome| outcome.revoked);
    let owed = outcome.map_or(0, |outcome| outcome.releases_owed);
    let retired = outcome.map_or(0, |outcome| outcome.releases_retired);
    let unreleased = outcome.map_or(0, |outcome| outcome.releases_unreleased);
    let note = if let Some(outcome) = outcome {
        if let Some(release) = release_note(outcome.releases_retired, outcome.releases_unreleased) {
            release
        } else if outcome.revoked {
            "the engine admits no input under this policy now, and no release is outstanding"
        } else if policy.view_only {
            "this session is read-only: the engine admits no input and no release is outstanding"
        } else if policy.unverified_accepted {
            "this session accepts the peer the handshake did not prove: the engine admits input under it, and nothing queued under the previous policy is replayed"
        } else {
            "the policy is in force: the engine admits input when this session is authorized, the peer grants it, and, on the RustDesk wire, the handshake has proved the peer"
        }
    } else {
        "recorded for the next session_start: no viewer is running, so this session has emitted nothing to release"
    };
    let mut answer = serde_json::json!({
        "ok": true,
        "action": action,
        "view_only": policy.view_only,
        "unverified_input_accepted": policy.unverified_accepted,
        "admission_revoked": revoked,
        "releases_owed": owed,
        "releases_retired": retired,
        // The same meaning in every answer that carries the release counters:
        // a release a change made necessary is still on its way.
        "release_pending": retired > 0,
        "releases_unreleased": unreleased,
        "note": note,
    });
    // The generation is published only when a viewer is running: this answer is
    // about the gate that viewer holds, and a session with no viewer has none.
    if let Some(outcome) = outcome {
        answer["input_generation"] = serde_json::json!(outcome.input_generation);
    }
    answer.to_string()
}

#[napi]
pub fn native_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Resk's name for the same off-UI-thread hardware decoder metadata query.
/// Preserve per-decoder/per-field failures and `not_measured`; this is not a
/// software fallback list, a codec recommendation or a throughput measurement.
#[napi(ts_return_type = "Promise<string>")]
pub fn runtime_get_decoder_capabilities() -> AsyncTask<capabilities::DecoderCapabilityQuery> {
    query_decoder_capabilities()
}

/// Registers direct targets or an explicitly approved RustDesk ID route; no dial.
/// ID routes also require current initialized foreground consent. Direct RDP
/// still requires an explicit account and uses the existing driver/security.
#[napi]
pub fn session_add(session_id: String, target: String, options: String) -> String {
    if session_id.is_empty() {
        return error_json("empty session id");
    }
    let options: serde_json::Value =
        serde_json::from_str(&options).unwrap_or(serde_json::Value::Null);
    match options.get("isViewCamera") {
        None | Some(serde_json::Value::Bool(false)) => {}
        Some(serde_json::Value::Bool(true)) => {
            return error_json("camera viewing is excluded from this product");
        }
        Some(_) => return error_json("isViewCamera must be a boolean"),
    }
    let rustdesk_id_only = match options.get("rustdeskIdOnly") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(_) => return error_json("rustdeskIdOnly must be a boolean"),
    };
    let (viewer_target, route_note) = match parse_viewer_target(&target, rustdesk_id_only) {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let id_route = if matches!(&viewer_target, ViewerTarget::RustDesk { address: None }) {
        let admission = match app_context::id_admission() {
            Ok(admission) => admission,
            Err(error) => return error_json(&error),
        };
        let profile = match ApprovedRoute::parse(&target, options.get("approvedServerProfile")) {
            Ok(profile) => profile,
            Err(error) => return error_json(&error),
        };
        Some(IdRoute { profile, admission })
    } else {
        None
    };
    let password = options
        .get("password")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let fps = options
        .get("customFps")
        .and_then(|value| value.as_u64())
        .filter(|value| (1..=240).contains(value))
        .map_or(60, |value| value as u32);
    let view_only = options
        .get("isViewOnly")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    // The engine's initial policy for this session. Acceptance is never taken
    // from registration options: a peer the handshake has not proved is only
    // accepted by `sessionSetUnverifiedInputAccepted`, after its operator has
    // seen what the connection actually established.
    let input_policy = ViewerInputPolicy {
        view_only,
        unverified_accepted: false,
    };
    let credentials_note = if password.is_empty() {
        "no password in the options: sessionLogin records one for the next dial"
    } else {
        "password and rate held for the next sessionStart"
    };
    let registered = with_sessions(|sessions| -> Result<String, String> {
        let _admission = id_route
            .as_ref()
            .map(|route| app_context::hold_id_admission(&route.admission))
            .transpose()?;
        // Cold, count-bounded observation also scrubs confirmed viewers whose
        // owner has not polled yet. It never consumes a receipt or evicts one.
        for record in sessions.values_mut() {
            if record.viewer.is_some() {
                observe_terminal_reclamation(record);
            }
        }
        if sessions.contains_key(&session_id) {
            return Err(
                "session id is still registered; poll and acknowledge its confirmed terminal receipt before registering a new session"
                    .to_string(),
            );
        }
        if sessions.len() >= MAX_SESSION_RECORDS {
            return Err(
                "session registry capacity exhausted; retire confirmed terminal receipts before registering a new session"
                    .to_string(),
            );
        }
        let record = SessionRecord {
            lifecycle_epoch: allocate_native_id().map_err(str::to_owned)?,
            target,
            viewer_target,
            id_route,
            closed: false,
            closing: false,
            reclaimed: None,
            password: password.to_owned(),
            fps,
            dials: 0,
            started: Instant::now(),
            viewer: None,
            terminal_snapshot: None,
            terminal_elapsed_ms: None,
            terminal_receipt_constructed: false,
            lease: Arc::new(PendingSurfaceLease::new()),
            borrow: None,
            binding: None,
            input_policy,
            cursor: None,
            common: HashMap::new(),
            reported: Reported::default(),
        };
        let mut response = session_response(
            true,
            "session_add",
            &session_id,
            &record,
            None,
        );
        response["routable"] = serde_json::json!(true);
        response["fps"] = serde_json::json!(fps);
        response["view_only"] = serde_json::json!(view_only);
        response["note"] = serde_json::json!(format!("{route_note}; {credentials_note}"));
        let response = response.to_string();
        sessions.insert(session_id.clone(), record);
        Ok(response)
    });
    registered.unwrap_or_else(|message| error_json(&message))
}

fn surface_receipts(record: &SessionRecord, released: bool) -> Vec<serde_json::Value> {
    record
        .binding
        .iter()
        .map(|binding| {
            serde_json::json!({
                "token": binding.token.to_string(),
                // This epoch owns the Arc<PendingSurfaceLease>; the token names
                // the native loan that actually filled it.
                "sourceIdentity": record.lifecycle_epoch.to_string(),
                "componentId": binding.component_id,
                "surfaceId": binding.surface_id.to_string(),
                "display": binding.display,
                "released": released,
                "quarantined": record.closing && !released,
            })
        })
        .collect()
}

/// One complete snapshot vocabulary for add/start/poll/close. A failed remote
/// login and an unconfirmed native release are independent facts. Keep both,
/// along with the input writer's release account and cumulative media counters.
fn session_response(
    ok: bool,
    action: &str,
    session_id: &str,
    record: &SessionRecord,
    snapshot: Option<&ViewerSnapshot>,
) -> serde_json::Value {
    let phase = snapshot.map_or_else(
        || {
            if record.closed {
                "closed"
            } else if record.closing {
                "closing"
            } else {
                "registered"
            }
        },
        |snapshot| snapshot.phase.as_str(),
    );
    let kind = match &record.viewer_target {
        ViewerTarget::RustDesk { .. } => "rustdesk",
        ViewerTarget::Vnc(_) => "vnc",
        ViewerTarget::Rdp(_) => "rdp",
    };
    let released = record.reclaimed == Some(true);
    let settle = if !released {
        "unconfirmed"
    } else if record.dials == 0 {
        "neverstarted"
    } else {
        "settled"
    };
    let mut response = serde_json::json!({
        "ok": ok,
        "action": action,
        "session": {
            "sessionId": session_id,
            "coreSessionId": session_id,
            "lifecycleEpoch": record.lifecycle_epoch.to_string(),
            "kind": kind,
            "target": record.target,
            "phase": phase,
        },
        "phase": phase,
        "protocol": kind,
        "target": record.target,
        "closed": snapshot.map_or(record.closed, |snapshot| snapshot.closed),
        "closing": record.closing,
        "reclamation_known": record.reclaimed.is_some(),
        "reclaimed": record.reclaimed,
        // Never derive this from an empty list of destinations.
        "released": released,
        "settle": settle,
        "surfaces": surface_receipts(record, released),
        "error": null,
        "login_failure": null,
        "peer_close_reason": null,
        "authenticated": false,
        "note": poll_note(phase, None),
    });
    if let Some(snapshot) = snapshot {
        response["session"]["inputGeneration"] =
            serde_json::json!(snapshot.input_generation.to_string());
        if let Some(error) = &snapshot.error {
            response["session"]["lastError"] = serde_json::json!(error);
        }
        let facts = serde_json::json!({
            "error": snapshot.error,
            "login_failure": login_failure_name(snapshot.login_failure),
            "peer_close_reason": if snapshot.closed && released {
                peer_close_reason_name(snapshot.peer_close_reason)
            } else {
                None
            },
            "route": snapshot.route,
            "codec": snapshot.codec,
            "width": snapshot.width,
            "height": snapshot.height,
            "encrypted": snapshot.encrypted,
            "peer_verified": snapshot.peer_verified,
            "keyboard_allowed": snapshot.keyboard_allowed,
            "input_generation": snapshot.input_generation,
            "releases_owed": snapshot.releases_owed,
            "releases_retired": snapshot.releases_retired,
            "release_pending": snapshot.releases_retired > 0,
            "releases_unreleased": snapshot.releases_unreleased,
            "authenticated": snapshot.authenticated,
            "received_units": snapshot.received_units,
            "pushed_units": snapshot.pushed_units,
            "render_submissions": snapshot.render_submissions,
            "queued_units": snapshot.queued_units,
            "note": release_note(snapshot.releases_retired, snapshot.releases_unreleased)
                .unwrap_or_else(|| poll_note(phase, snapshot.error.as_deref())),
        });
        if let (Some(response), serde_json::Value::Object(facts)) =
            (response.as_object_mut(), facts)
        {
            response.extend(facts);
        }
    }
    response
}

/// No native identity/lease can be claimed for an unknown or superseded request.
fn lifecycle_error_json(action: &str, message: &str) -> String {
    serde_json::json!({
        "ok": false,
        "action": action,
        "error": message,
        "message": message,
        "released": false,
        "settle": "unconfirmed",
        "surfaces": [],
    })
    .to_string()
}

fn close_receipt_json(session_id: &str, record: &mut SessionRecord) -> String {
    let mut response = session_response(
        record.reclaimed == Some(true),
        "session_close",
        session_id,
        record,
        record.terminal_snapshot.as_ref(),
    );
    if record.reclaimed != Some(true) {
        response["message"] = serde_json::json!(
            "native surface reclamation is unconfirmed; retain the Surface and session record"
        );
    }
    let response = response.to_string();
    // Constructed for the close consumer, not delivered or acknowledged. The
    // same gate is set by a complete poll, never by observing a terminal event.
    if record.closed && record.reclaimed == Some(true) {
        record.terminal_receipt_constructed = true;
    }
    response
}

/// Dials the record's target, presenting into the surface the client binds.
///
/// The engine reads the surface lease when the first frame opens the surface and
/// the client binds its surface after it asks for the session, so this dials
/// immediately and a binding that arrives after this call is what the viewer
/// presents into; a lease still without an id fails at that open rather than
/// presenting into nothing. The credentials the engine also takes at that moment
/// are whatever `session_add` or `session_login` recorded.
///
/// Starting a live session remains idempotent. A closing or terminal session
/// must be polled and explicitly ACKed before a new registration; neither
/// restarting a tombstone nor reusing an unconfirmed Surface is allowed.
#[napi]
pub fn session_start(session_id: String) -> String {
    with_sessions(|sessions| {
        let Some(record) = sessions.get_mut(&session_id) else {
            return lifecycle_error_json("session_start", "unknown session");
        };
        if let Err(message) = mutable_snapshot(record) {
            let snapshot = observe_terminal_reclamation(record);
            let mut response = session_response(
                false,
                "session_start",
                &session_id,
                record,
                snapshot.as_ref(),
            );
            response["action_error"] = serde_json::json!(message);
            response["message"] = serde_json::json!(message);
            return response.to_string();
        }
        let started = record.viewer.is_none();
        let mut surface_retirement: Option<String> = None;
        if started {
            match dial(record) {
                Ok(viewer) => {
                    record.viewer = Some(viewer.clone());
                    record.reported = Reported::default();
                    // A fresh dial has admitted no pointer position.
                    record.cursor = None;
                    record.dials += 1;
                    record.started = Instant::now();
                    // Bind this loan's retirement to exactly this viewer before
                    // this call returns. A Surface destroyed between the borrow
                    // and here has already revoked admission and asked for that
                    // viewer's close; the error says what happened, and neither
                    // the Viewer nor the SurfaceBorrow is discarded - this
                    // record's own terminal path has to prove reclamation.
                    let watched = record
                        .borrow
                        .as_ref()
                        .map_or(Ok(()), |borrow| borrow.watch_viewer(&viewer));
                    if let Err(message) = watched {
                        record.closing = true;
                        surface_retirement = Some(message);
                    }
                }
                Err(message) => {
                    let mut response =
                        session_response(false, "session_start", &session_id, record, None);
                    response["error"] = serde_json::json!(message);
                    response["message"] = serde_json::json!(message);
                    return response.to_string();
                }
            }
        }
        let snapshot = observe_terminal_reclamation(record);
        let mut response = session_response(
            true, "session_start", &session_id, record, snapshot.as_ref(),
        );
        response["started"] = serde_json::json!(started);
        response["surface_bound"] =
            serde_json::json!(record.lease.published_surface_id() != 0);
        response["note"] = serde_json::json!(if started {
            "viewer dialled; it presents into the Surface the client binds, which it may bind after this call"
        } else {
            "a viewer is already running for this session: session_start did not dial again"
        });
        if let Some(message) = surface_retirement {
            // Not a failed dial: the viewer exists and is closing, so the client
            // must poll for confirmed reclamation and ACK it like any terminal.
            response["surface_retirement_error"] = serde_json::json!(message);
            response["note"] = serde_json::json!(
                "native Surface retirement had already asked this viewer to close, so this session is closing; poll for confirmed reclamation before acknowledging it"
            );
        }
        response.to_string()
    })
}

/// Records the password the client collected for this peer.
///
/// The engine consumes credentials when it dials. Replacing them after an
/// unauthenticated dial therefore marks a restart as required; it never drops a
/// live viewer and opens another one against the same Surface lease. The client
/// must request close, poll for confirmed reclamation, ACK the terminal receipt,
/// then register and start a fresh session with its own new password copy. The
/// registry's copy is scrubbed at confirmed close, never a future credential store.
#[napi]
pub fn session_login(session_id: String, payload: String) -> String {
    let payload: serde_json::Value = match serde_json::from_str(&payload) {
        Ok(value) => value,
        Err(_) => return error_json("sessionLogin payload is not JSON"),
    };
    let Some(password) = payload.get("password").and_then(|value| value.as_str()) else {
        return error_json("sessionLogin payload has no password string");
    };
    let remember = match payload.get("remember") {
        None => false,
        Some(value) => match value.as_bool() {
            Some(value) => value,
            None => return error_json("sessionLogin 'remember' is not a boolean"),
        },
    };
    let outcome = with_sessions(|sessions| -> Result<(bool, String, bool), String> {
        let Some(record) = sessions.get_mut(&session_id) else {
            return Err("unknown session".to_string());
        };
        let snapshot = mutable_snapshot(record).map_err(str::to_owned)?;
        scrub_password(&mut record.password);
        record.password = password.to_owned();
        let Some(snapshot) = snapshot else {
            return Ok((false, "registered".to_string(), false));
        };
        if snapshot.authenticated {
            return Ok((false, snapshot.phase, true));
        }
        Ok((true, snapshot.phase, false))
    });
    match outcome {
        Ok((restart_required, phase, authenticated)) => {
            let note = if authenticated {
                "this session is already authenticated: the password is held for the next session_start"
            } else if restart_required {
                "password recorded; close this viewer and wait for confirmed surface reclamation before registering and starting a new session"
            } else {
                "recorded for the next session_start: the engine takes credentials when a viewer starts and keeps them in memory only"
            };
            serde_json::json!({
                "ok": true,
                "restart_required": restart_required,
                "phase": phase,
                "remember": remember,
                "note": note,
            })
            .to_string()
        }
        Err(message) => error_json(&message),
    }
}

/// Records this session's one Surface destination.
///
/// The third argument is the `componentId` an `xcomponentAttach` on this UI
/// environment returned - never a Surface id, a node label or any other string:
/// the bridge borrows the real lease from that holder and publishes it into the
/// record's single destination slot. An empty componentId is a give-back
/// request, not evidence of release; a running or quarantined viewer keeps the
/// loan until the engine confirms reclamation.
///
/// `env` is the UI environment that holder was attached in. The `#[napi]`
/// wrapper below passes it; a host build has none, and then no lease can be
/// borrowed.
fn bind_surface(
    env: Option<&Env>,
    session_id: String,
    display: u32,
    component_id: String,
    lifecycle_epoch: String,
) -> String {
    let component_id = component_id.trim();
    with_sessions(|sessions| match sessions.get_mut(&session_id) {
        Some(record) => {
            if lifecycle_epoch != record.lifecycle_epoch.to_string() {
                return lifecycle_error_json("session_bind_surface", "stale lifecycle epoch");
            }
            let snapshot = observe_terminal_reclamation(record);
            let mut response = session_response(
                true, "session_bind_surface", &session_id, record, snapshot.as_ref(),
            );
            if component_id.is_empty() {
                let released = record.reclaimed == Some(true)
                    || (record.dials == 0 && !record.closing);
                response["released"] = serde_json::json!(released);
                response["held"] = serde_json::json!(!released);
                response["surfaces"] = serde_json::json!(surface_receipts(record, released));
                if released {
                    // Nothing can still be presenting here, so the record's own
                    // claim on the holder goes too: only then can its detach
                    // settle. A never-started give-back has no terminal receipt
                    // to retain, while a terminal binding stays recorded for it.
                    record.lease.release();
                    record.borrow = None;
                    if !record.closed {
                        record.binding = None;
                    }
                    if record.dials == 0 {
                        response["settle"] = serde_json::json!("neverstarted");
                    }
                } else {
                    response["ok"] = serde_json::json!(false);
                    response["message"] = serde_json::json!(
                        "cannot clear a held Surface; close the viewer and wait for confirmed reclamation"
                    );
                }
                response["bound"] =
                    serde_json::json!(record.lease.published_surface_id() != 0);
                response["display"] = serde_json::json!(display);
                return response.to_string();
            }
            if record.closed || record.closing {
                response["ok"] = serde_json::json!(false);
                response["message"] = serde_json::json!(
                    "cannot bind a closing or terminal session; acknowledge its confirmed receipt first"
                );
                return response.to_string();
            }
            let existing = record
                .binding
                .as_ref()
                .map(|binding| binding.component_id == component_id);
            match existing {
                // The same holder again: answer with the destination this record
                // already holds instead of borrowing a second one.
                Some(true) => {
                    if let Some(binding) = record.binding.as_mut() {
                        binding.display = display;
                    }
                    return bound_receipt(record, &mut response, display);
                }
                Some(false) => {
                    response["ok"] = serde_json::json!(false);
                    response["message"] = serde_json::json!(
                        "cannot replace this session's single Surface binding with another component; close it and start a new session"
                    );
                    return response.to_string();
                }
                None => {}
            }
            let Some(env) = env else {
                // A host build and a detached environment have no holder to
                // borrow from, so the refusal is the real answer: no destination
                // is invented, and no string is promoted to a Surface lease.
                response["ok"] = serde_json::json!(false);
                response["message"] = serde_json::json!(
                    "a Surface binding needs the live XComponent holder on its UI environment thread; call xcomponentAttach there first"
                );
                return response.to_string();
            };
            let borrow = match xcomponent::borrow_surface(env, component_id) {
                Ok(borrow) => borrow,
                Err(message) => {
                    response["ok"] = serde_json::json!(false);
                    response["message"] = serde_json::json!(message);
                    return response.to_string();
                }
            };
            // The slot is the single-publish authority: a second fill would swap
            // the destination under a running viewer, so it is refused there.
            if let Err(message) = record.lease.publish(borrow.lease()) {
                response["ok"] = serde_json::json!(false);
                response["message"] = serde_json::json!(message);
                return response.to_string();
            }
            record.binding = Some(SurfaceBinding {
                token: borrow.token,
                component_id: component_id.to_owned(),
                surface_id: borrow.surface_id,
                display,
            });
            record.borrow = Some(borrow);
            bound_receipt(record, &mut response, display)
        }
        None => lifecycle_error_json("session_bind_surface", "unknown session"),
    })
}

/// The answer a successful bind returns: the destination facts this record now
/// holds. `released` is false because a binding is not a release, and `bound` is
/// read from the published slot, never assumed.
fn bound_receipt(
    record: &SessionRecord,
    response: &mut serde_json::Value,
    display: u32,
) -> String {
    response["surfaces"] = serde_json::json!(surface_receipts(record, false));
    response["bound"] = serde_json::json!(record.lease.published_surface_id() != 0);
    response["display"] = serde_json::json!(display);
    response["released"] = serde_json::json!(false);
    response["note"] = serde_json::json!(
        "single Surface lease borrowed from the native XComponent holder; this records the destination, not a peer display switch or hot rebind"
    );
    response.to_string()
}

/// Binds this epoch's one Surface: the `#[napi]` face of `bind_surface`.
#[napi]
pub fn session_bind_surface(
    env: Env,
    session_id: String,
    display: u32,
    component_id: String,
    lifecycle_epoch: String,
) -> String {
    bind_surface(
        Some(&env),
        session_id,
        display,
        component_id,
        lifecycle_epoch,
    )
}

/// Adopts one live ArkUI node's SurfaceHolder on the UI environment thread.
///
/// `nodeId` is only a label for this holder. The answer carries the opaque
/// `componentId` this bridge allocates (never reused, and the only value
/// `sessionBindSurface` accepts), the node's unique id and the holder state.
/// `ok:false` is a real refusal; when cleanup could not be confirmed the same
/// componentId is still returned so the caller can detach it instead of leaking
/// the holder.
#[napi]
pub fn xcomponent_attach(
    env: Env,
    node_id: String,
    frame_node: JsUnknown,
    on_surface_event: JsUnknown,
) -> String {
    // Only the raw handles are forwarded: the holder keeps its own napi
    // reference and TSFN for them, on this same environment thread.
    let frame = unsafe { frame_node.raw() } as *mut c_void;
    let callback = unsafe { on_surface_event.raw() } as *mut c_void;
    unsafe { xcomponent::attach(env, node_id, frame, callback) }
}

/// Releases this bridge's claim on one holder.
///
/// `held:true` means a borrowed loan or an active native callback still owns
/// resources: the holder, its callback and its window stay retained, and only a
/// later detach may complete. No answer here claims a release that did not
/// happen.
#[napi]
pub fn xcomponent_detach(env: Env, component_id: String) -> String {
    xcomponent::detach(env, component_id)
}

/// Declares the rate the attached node should be drawn at.
///
/// The answer separates the frame-rate call from the on-frame callback
/// registration it needed, so a registered-callback failure is not reported as a
/// rate refusal. Its `frameCallbacks` counter is native signal callbacks, not
/// decoded frames or measured presentation FPS.
#[napi]
pub fn xcomponent_set_frame_rate_range_native(
    env: Env,
    component_id: String,
    expected: i32,
    min: i32,
    max: i32,
) -> String {
    xcomponent::set_frame_rate_range(env, component_id, expected, min, max)
}

enum CloseRequest {
    Complete(String),
    Join {
        session_id: String,
        lifecycle_epoch: u64,
        viewer: Arc<Viewer>,
    },
}

pub struct CloseWork {
    request: CloseRequest,
}

impl CloseWork {
    /// Admission is synchronous: no setter/bind/start may race a queued close.
    /// The core already owns teardown, and the registry retains its Arc even if
    /// the JS promise is abandoned or the NAPI work never reaches resolve.
    fn prepare(session_id: String) -> Self {
        let request = with_sessions(|sessions| {
            let Some(record) = sessions.get_mut(&session_id) else {
                return CloseRequest::Complete(lifecycle_error_json(
                    "session_close", "unknown session",
                ));
            };
            observe_terminal_reclamation(record);
            if record.closed {
                return CloseRequest::Complete(close_receipt_json(&session_id, record));
            }
            record.closing = true;
            if let Some(viewer) = &record.viewer {
                viewer.request_close();
                return CloseRequest::Join {
                    session_id,
                    lifecycle_epoch: record.lifecycle_epoch,
                    viewer: viewer.clone(),
                };
            }
            // No Viewer ever existed: no gate or input-release counters are
            // invented, and the known absence of a native owner permits release.
            apply_terminal_reclamation(
                &mut record.closed,
                &mut record.closing,
                &mut record.reclaimed,
                record.lease.as_ref(),
                Some(true),
            );
            // Nothing was ever handed this destination, so the record's claim on
            // the holder can go with the slot: the XComponent is now detachable.
            record.borrow = None;
            scrub_terminal_record(record);
            CloseRequest::Complete(close_receipt_json(&session_id, record))
        });
        Self { request }
    }

    fn run(&self) -> String {
        match &self.request {
            CloseRequest::Complete(response) => response.clone(),
            CloseRequest::Join {
                session_id,
                lifecycle_epoch,
                viewer,
            } => {
                // compute is a synchronous NAPI worker, not the JS thread or a
                // Tokio task. Viewer::close only waits on its existing owner's
                // Notify/result; it creates no runtime and needs none here.
                // Its error remains in the terminal snapshot; the separately
                // published verdict below is the sole release authority.
                let _result = hbb_common::futures::executor::block_on(viewer.close());
                let snapshot = viewer.snapshot();
                let verdict = viewer.reclamation_confirmed();
                with_sessions(|sessions| {
                    let Some(record) = sessions.get_mut(session_id)
                        .filter(|record| record.lifecycle_epoch == *lifecycle_epoch)
                    else {
                        // A poll may have completed/ACKed this exact epoch while
                        // the worker ran. Never commit into a reused id.
                        return lifecycle_error_json(
                            "session_close", "close completed for a retired lifecycle epoch",
                        );
                    };
                    record_terminal_reclamation(record, &snapshot, verdict);
                    close_receipt_json(session_id, record)
                })
            }
        }
    }
}

impl Task for CloseWork {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<String> {
        Ok(self.run())
    }

    fn resolve(&mut self, _env: Env, output: String) -> napi_ohos::Result<String> {
        Ok(output)
    }
}

/// Resolves with the actual join/reclamation receipt, never request acceptance.
/// Neither compute nor resolve ACKs/removes the epoch.
#[napi]
pub fn session_close(session_id: String) -> AsyncTask<CloseWork> {
    AsyncTask::new(CloseWork::prepare(session_id))
}

/// Requests a fresh keyframe from the peer (the client's refresh action).
#[napi]
pub fn session_refresh(session_id: String, _display: u32) -> String {
    let viewer = with_sessions(|sessions| {
        sessions
            .get(&session_id)
            .and_then(|record| record.viewer.clone())
    });
    match viewer {
        Some(viewer) => match viewer.request_keyframe() {
            Ok(()) => serde_json::json!({ "ok": true }).to_string(),
            Err(error) => error_json(&format!("{error:?}")),
        },
        None => error_json("session has no running viewer"),
    }
}

/// ACK is separate from transfer cancellation and must name the native epoch.
#[napi]
pub fn session_acknowledge_close(session_id: String, lifecycle_epoch: String) -> String {
    with_sessions(|sessions| {
        let Some(record) = sessions.get_mut(&session_id) else {
            return lifecycle_error_json("session_acknowledge_close", "unknown session");
        };
        if lifecycle_epoch != record.lifecycle_epoch.to_string() {
            return lifecycle_error_json("session_acknowledge_close", "stale lifecycle epoch");
        }
        observe_terminal_reclamation(record);
        if record.closing || !record.closed || record.reclaimed != Some(true) {
            return lifecycle_error_json(
                "session_acknowledge_close",
                "native surface reclamation is unconfirmed; retain the terminal record",
            );
        }
        if !record.terminal_receipt_constructed {
            return lifecycle_error_json(
                "session_acknowledge_close",
                "complete terminal receipt required; consume sessionClose or sessionPollEvents before ACK",
            );
        }
        let mut response = session_response(
            true, "session_acknowledge_close", &session_id, record,
            record.terminal_snapshot.as_ref(),
        );
        response["record_removed"] = serde_json::json!(true);
        let response = response.to_string();
        sessions.remove(&session_id);
        response
    })
}

/// No transfer-job owner is wired to this bridge yet. In particular actId=0 is
/// not a terminal ACK, and no actId is permission to close an entire viewer.
#[napi]
pub fn session_cancel_job(_session_id: String, act_id: u32) -> String {
    serde_json::json!({
        "ok": false,
        "action": "session_cancel_job",
        "actId": act_id,
        "unsupported": true,
        "record_removed": false,
        "error": "transfer-job cancellation is not implemented by this engine bridge",
        "message": "transfer-job cancellation is not implemented; use sessionClose for a viewer and sessionAcknowledgeClose for its terminal receipt",
    })
    .to_string()
}

/// The client's own "the channel is up" event, carrying what this snapshot
/// observed: `secure` from the handshake's security evidence, `direct` and
/// `stream_type` from the route the engine dialled. The route keeps the engine's
/// own vocabulary (`direct_tcp`, `tcp_hole_punch`, `relay`), and a route it did
/// not record is left empty rather than reported as one it did not take.
fn authorized_event(snapshot: &ViewerSnapshot) -> serde_json::Value {
    let direct = match snapshot.route.as_str() {
        "direct_tcp" | "tcp_hole_punch" => "true",
        "relay" => "false",
        _ => "",
    };
    serde_json::json!({
        "name": "connection_ready",
        "secure": snapshot.encrypted.to_string(),
        "direct": direct,
        "stream_type": snapshot.route,
    })
}

/// The client's own peer description: it labels the session with the platform
/// and version, builds its viewport from the displays, and binds the surface the
/// engine presents into from the same handler - so this rides with the
/// authorization instead of after it. The displays are serialized because that
/// is the shape the client parses them from.
fn peer_info_event(snapshot: &ViewerSnapshot) -> serde_json::Value {
    let displays: Vec<serde_json::Value> = snapshot
        .displays
        .iter()
        .map(|display| {
            serde_json::json!({
                "width": display.width,
                "height": display.height,
                "x": display.x,
                "y": display.y,
                "cursor_embedded": display.cursor_embedded,
                "original_width": display.original_width,
                "original_height": display.original_height,
            })
        })
        .collect();
    serde_json::json!({
        "name": "peer_info",
        "platform": snapshot.platform.as_str(),
        "version": snapshot.version.as_str(),
        "displays": serde_json::to_string(&displays).unwrap_or_else(|_| "[]".to_string()),
        "current_display": snapshot.current_display.to_string(),
    })
}

/// What the answer's `note` says for the phase it reports: what the state means
/// and, where the client's own event vocabulary (`handleSessionEvent` in
/// RustDeskIndex.ets) has no event for it, that this layer says so rather than
/// inventing one.
fn poll_note(phase: &str, error: Option<&str>) -> &'static str {
    match (phase, error) {
        ("closed" | "failed", Some("SecondFactorUnsupported")) => {
            "the viewer finished after the peer answered with a 2FA requirement, which this build has no entry point to answer: the close event carries that error and the client's 2FA prompt is not used"
        }
        ("closed" | "failed", _) => {
            "the viewer finished: the close event carries the snapshot's own error string when it has one"
        }
        ("registered", _) => {
            "no viewer is dialled yet: the record is registered and this poll has no session state to report"
        }
        ("capability" | "connecting" | "rendezvous", _) => {
            "the viewer is dialling: the client has no event for a dial in flight"
        }
        ("authenticating", _) => {
            "the login exchange is in flight: the peer's challenge is consumed inside Viewer::start, so this layer reports the peer's answer rather than the challenge itself"
        }
        ("awaiting_approval", _) => {
            "the session is waiting for the host operator to allow or deny the connection"
        }
        (
            "authenticated"
            | "awaiting_surface"
            | "opening_surface"
            | "opening_decoder"
            | "decoding"
            | "streaming",
            _,
        ) => {
            "the peer authorized this session; peer_info and connection_ready carry the snapshot's peer, display, handshake and route evidence while presentation advances independently"
        }
        ("closing", _) => {
            "the viewer is tearing down after a close request: it has not finished, so no close event is due"
        }
        _ => "this phase is not one this layer translates: no event is invented for it",
    }
}

/// Reports the engine's own view of the session, translated into the client's
/// event shape.
///
/// `ViewerEvent` is consumed inside `Viewer::start` (the public API exposes no
/// event stream), so there is no stream to relay: this reads the states the
/// snapshot actually contains and reports the events the ArkTS client acts on —
/// authorization and the end of the viewer — each once per viewer. The explicit
/// login_failure category and final snapshot fields persist until terminal ACK,
/// even after confirmed reclamation releases the registry's Viewer reference.
/// A phase this vocabulary cannot express is named in `note`,
/// never invented as an event, and `Reported` on the record is what keeps a
/// repeated poll from repeating what the client already acted on.
#[napi]
pub fn session_poll_events(session_id: String, _limit: u32) -> String {
    with_sessions(|sessions| {
        let Some(record) = sessions.get_mut(&session_id) else {
            return lifecycle_error_json("session_poll_events", "unknown session");
        };
        let snapshot = observe_terminal_reclamation(record);
        let events = match &snapshot {
            Some(snapshot) => record.reported.events(snapshot),
            None if record.closed && !record.reported.finished => {
                record.reported.finished = true;
                vec![serde_json::json!({ "name": "close" })]
            }
            None => Vec::new(),
        };
        let mut response = session_response(
            true, "session_poll_events", &session_id, record, snapshot.as_ref(),
        );
        response["events"] = serde_json::json!(events);
        if snapshot.is_none() && !record.closed {
            response["routable"] = serde_json::json!(true);
        }
        let response = response.to_string();
        // Construct the complete successful response before allowing ACK. A
        // one-shot close event alone is not a consumed terminal receipt.
        if record.closed && record.reclaimed == Some(true) {
            record.terminal_receipt_constructed = true;
        }
        response
    })
}
/// ArkTS uses compact bridge button codes; `Viewer::send_mouse` accepts the
/// original RustDesk button-bit values. Keep this conversion at the NAPI
/// boundary so ArkTS never needs to know the transport bit packing.
fn client_mouse_button_to_wire(button: u32) -> Result<u32, String> {
    match button {
        0 => Ok(0),
        1 => Ok(1),
        2 => Ok(2),
        3 => Ok(4),
        4 => Ok(8),
        5 => Ok(16),
        _ => Err("sessionSendMouse button is not a supported client button code".to_string()),
    }
}

/// The absolute pointer position one mouse event carries, resolved from the
/// event and the last position this session's engine admitted.
///
/// It is a pure decision: the record's position is read, never written here, so
/// the caller commits the candidate only after the engine admitted the event.
/// A refused or stale move therefore cannot become the position a
/// coordinate-less button borrows.
fn resolve_mouse_coordinates(
    kind: u32,
    x: Option<i32>,
    y: Option<i32>,
    cursor: Option<(i32, i32)>,
) -> Result<(i32, i32), String> {
    match kind {
        0..=2 => match (x, y) {
            (Some(x), Some(y)) => Ok((x, y)),
            (None, None) if kind == 0 => {
                Err("absolute mouse movement needs both x and y".to_string())
            }
            (None, None) => cursor
                .ok_or_else(|| "mouse button needs a prior absolute pointer position".to_string()),
            _ => Err("absolute mouse input needs both x and y or neither".to_string()),
        },
        _ => Ok((x.unwrap_or(0), y.unwrap_or(0))),
    }
}

/// Mouse input, straight through to the engine's viewer.
///
/// The canonical mobile input contract sends pointer moves with coordinates,
/// then button transitions without duplicating them. This layer retains only the
/// last absolute position the engine actually admitted for that session and
/// refuses a coordinate-less button before any such position is known.
///
/// `input_generation` is the epoch the client is acting on, and it is required:
/// the engine compares it with the gate it decides under, so an event queued
/// under a boundary the engine has left is refused instead of being emitted
/// under the one in force. On success the answer carries the generation the
/// queued event actually stamps; on an engine refusal it carries the generation
/// the gate is at now, which is a snapshot for retiring stale state and never a
/// receipt.
#[napi]
pub fn session_send_mouse(session_id: String, mouse_json: String, input_generation: f64) -> String {
    let event: serde_json::Value = match serde_json::from_str(&mouse_json) {
        Ok(value) => value,
        Err(_) => return error_json("sessionSendMouse payload is not JSON"),
    };
    let generation = match expected_input_generation("sessionSendMouse", input_generation) {
        Ok(generation) => generation,
        Err(message) => return error_json(&message),
    };
    let integer = |key: &str| -> Result<Option<i64>, String> {
        match event.get(key) {
            None => Ok(None),
            Some(value) => value
                .as_i64()
                .map(Some)
                .ok_or_else(|| format!("sessionSendMouse {key} is not an integer")),
        }
    };
    let kind = match integer("kind") {
        Ok(Some(value)) => match u32::try_from(value) {
            Ok(value) => value,
            Err(_) => return error_json("sessionSendMouse kind is outside the wire integer range"),
        },
        Ok(None) => return error_json("sessionSendMouse payload needs integer kind"),
        Err(message) => return error_json(&message),
    };
    let button = match integer("button") {
        Ok(Some(value)) => match u32::try_from(value) {
            Ok(value) => value,
            Err(_) => {
                return error_json("sessionSendMouse button is outside the wire integer range")
            }
        },
        Ok(None) => return error_json("sessionSendMouse payload needs integer button"),
        Err(message) => return error_json(&message),
    };
    let button = match client_mouse_button_to_wire(button) {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let coordinate = |key: &str| -> Result<Option<i32>, String> {
        match integer(key)? {
            Some(value) => i32::try_from(value)
                .map(Some)
                .map_err(|_| format!("sessionSendMouse {key} is outside the wire integer range")),
            None => Ok(None),
        }
    };
    let x = match coordinate("x") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let y = match coordinate("y") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    // Admission is a bounded synchronous try_send. Keep the existing record
    // lock through its cursor commit so concurrent callers cannot commit in a
    // different order or replace the viewer between these operations.
    with_sessions(|sessions| {
        let Some(record) = sessions.get_mut(&session_id) else {
            return error_json("unknown session");
        };
        let Some(viewer) = record.viewer.as_ref() else {
            return error_json("session has no running viewer");
        };
        let (x, y) = match resolve_mouse_coordinates(kind, x, y, record.cursor) {
            Ok(position) => position,
            Err(message) => return error_json(&message),
        };
        match viewer.send_mouse(kind, button, x, y, generation) {
            Ok(admitted) => {
                if kind <= 2 {
                    record.cursor = Some((x, y));
                }
                serde_json::json!({ "ok": true, "input_generation": admitted }).to_string()
            }
            Err(error) => refusal_json(&format!("{error:?}"), viewer.input_generation()),
        }
    })
}

fn control_key(name: &str) -> Option<ControlKey> {
    Some(match name {
        "VK_DIVIDE" => ControlKey::Divide,
        "VK_MULTIPLY" => ControlKey::Multiply,
        "VK_SUBTRACT" => ControlKey::Subtract,
        "VK_ADD" => ControlKey::Add,
        "VK_DECIMAL" => ControlKey::Decimal,
        "VK_F1" => ControlKey::F1,
        "VK_F2" => ControlKey::F2,
        "VK_F3" => ControlKey::F3,
        "VK_F4" => ControlKey::F4,
        "VK_F5" => ControlKey::F5,
        "VK_F6" => ControlKey::F6,
        "VK_F7" => ControlKey::F7,
        "VK_F8" => ControlKey::F8,
        "VK_F9" => ControlKey::F9,
        "VK_F10" => ControlKey::F10,
        "VK_F11" => ControlKey::F11,
        "VK_F12" => ControlKey::F12,
        "VK_ENTER" | "VK_RETURN" => ControlKey::Return,
        "VK_CANCEL" => ControlKey::Cancel,
        "VK_BACK" => ControlKey::Backspace,
        "VK_TAB" => ControlKey::Tab,
        "VK_CLEAR" => ControlKey::Clear,
        "VK_SHIFT" => ControlKey::Shift,
        "VK_CONTROL" => ControlKey::Control,
        "VK_MENU" => ControlKey::Alt,
        "VK_PAUSE" => ControlKey::Pause,
        "VK_CAPITAL" => ControlKey::CapsLock,
        "VK_ESCAPE" => ControlKey::Escape,
        "VK_SPACE" => ControlKey::Space,
        "VK_PRIOR" => ControlKey::PageUp,
        "VK_NEXT" => ControlKey::PageDown,
        "VK_END" => ControlKey::End,
        "VK_HOME" => ControlKey::Home,
        "VK_LEFT" => ControlKey::LeftArrow,
        "VK_UP" => ControlKey::UpArrow,
        "VK_RIGHT" => ControlKey::RightArrow,
        "VK_DOWN" => ControlKey::DownArrow,
        "VK_SNAPSHOT" => ControlKey::Snapshot,
        "VK_SCROLL" => ControlKey::Scroll,
        "VK_INSERT" => ControlKey::Insert,
        "VK_DELETE" => ControlKey::Delete,
        "VK_NUMPAD0" => ControlKey::Numpad0,
        "VK_NUMPAD1" => ControlKey::Numpad1,
        "VK_NUMPAD2" => ControlKey::Numpad2,
        "VK_NUMPAD3" => ControlKey::Numpad3,
        "VK_NUMPAD4" => ControlKey::Numpad4,
        "VK_NUMPAD5" => ControlKey::Numpad5,
        "VK_NUMPAD6" => ControlKey::Numpad6,
        "VK_NUMPAD7" => ControlKey::Numpad7,
        "VK_NUMPAD8" => ControlKey::Numpad8,
        "VK_NUMPAD9" => ControlKey::Numpad9,
        "Apps" => ControlKey::Apps,
        "Meta" => ControlKey::Meta,
        "RAlt" => ControlKey::RAlt,
        "RWin" => ControlKey::RWin,
        "RControl" => ControlKey::RControl,
        "RShift" => ControlKey::RShift,
        "CTRL_ALT_DEL" => ControlKey::CtrlAltDel,
        "LOCK_SCREEN" => ControlKey::LockScreen,
        _ => return None,
    })
}

fn plain_key(name: &str) -> Option<u32> {
    if name.chars().count() == 1 {
        return name.chars().next().map(|character| character as u32);
    }
    let character = name.strip_prefix("VK_")?;
    if character.len() != 1 {
        return None;
    }
    let value = character.as_bytes()[0];
    match value {
        b'A'..=b'Z' => Some(u32::from(value + (b'a' - b'A'))),
        b'0'..=b'9' => Some(u32::from(value)),
        _ => None,
    }
}

fn is_key(key: &Option<ControlKey>, first: ControlKey, second: ControlKey) -> bool {
    matches!(key.as_ref(), Some(value) if value == &first || value == &second)
}

fn legacy_key_event(value: &serde_json::Value) -> Result<KeyEvent, String> {
    let name = value
        .get("name")
        .and_then(|field| field.as_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "sessionInputKey payload needs a key name".to_string())?;
    let down = value
        .get("down")
        .and_then(|field| field.as_bool())
        .ok_or_else(|| "sessionInputKey payload needs a boolean down".to_string())?;
    let press = value
        .get("press")
        .and_then(|field| field.as_bool())
        .unwrap_or(false);
    let key = control_key(name);
    let mut event = KeyEvent::new();
    if let Some(key) = key.clone() {
        event.set_control_key(key);
    } else if let Some(character) = plain_key(name) {
        event.set_chr(character);
    } else {
        return Err(format!(
            "sessionInputKey does not support key name {name:?}"
        ));
    }
    event.down = !press && down;
    event.press = press;
    if value
        .get("alt")
        .and_then(|field| field.as_bool())
        .unwrap_or(false)
        && !is_key(&key, ControlKey::Alt, ControlKey::RAlt)
    {
        event.modifiers.push(ControlKey::Alt.into());
    }
    if value
        .get("shift")
        .and_then(|field| field.as_bool())
        .unwrap_or(false)
        && !is_key(&key, ControlKey::Shift, ControlKey::RShift)
    {
        event.modifiers.push(ControlKey::Shift.into());
    }
    if value
        .get("ctrl")
        .and_then(|field| field.as_bool())
        .unwrap_or(false)
        && !is_key(&key, ControlKey::Control, ControlKey::RControl)
    {
        event.modifiers.push(ControlKey::Control.into());
    }
    if value
        .get("command")
        .and_then(|field| field.as_bool())
        .unwrap_or(false)
        && !is_key(&key, ControlKey::Meta, ControlKey::RWin)
    {
        event.modifiers.push(ControlKey::Meta.into());
    }
    event.mode = KeyboardMode::Legacy.into();
    Ok(event)
}

/// The running viewer a legacy key event belongs to.
///
/// The local policy is not read here: the engine holds it and refuses the event
/// itself, both when it is queued and again at the writer, so this layer cannot
/// become a second, drifting copy of the operator's decision.
fn active_keyboard_viewer(session_id: &str) -> Result<Arc<Viewer>, String> {
    with_sessions(|sessions| {
        let Some(record) = sessions.get(session_id) else {
            return Err("unknown session".to_string());
        };
        record
            .viewer
            .clone()
            .ok_or_else(|| "session has no running viewer".to_string())
    })
}

/// Sends a legacy keyboard event through the viewer's selected protocol adapter.
///
/// `input_generation` is the epoch the client is acting on and is required: the
/// engine admits the event only under the generation in force, refuses one named
/// with an epoch it has left, and answers a refusal with the generation its gate
/// holds now so the client can retire stale input state.
#[napi]
pub fn session_input_key(session_id: String, key_json: String, input_generation: f64) -> String {
    let value: serde_json::Value = match serde_json::from_str(&key_json) {
        Ok(value) => value,
        Err(_) => return error_json("sessionInputKey payload is not JSON"),
    };
    let generation = match expected_input_generation("sessionInputKey", input_generation) {
        Ok(generation) => generation,
        Err(message) => return error_json(&message),
    };
    let event = match legacy_key_event(&value) {
        Ok(event) => event,
        Err(message) => return error_json(&message),
    };
    match active_keyboard_viewer(&session_id) {
        Ok(viewer) => match viewer.send_rustdesk_key(event, generation) {
            Ok(admitted) => {
                serde_json::json!({ "ok": true, "input_generation": admitted }).to_string()
            }
            Err(error) => refusal_json(&format!("{error:?}"), viewer.input_generation()),
        },
        Err(message) => error_json(&message),
    }
}

/// Sends a text sequence without fabricating individual key transitions.
///
/// The generation contract is `session_input_key`'s: the epoch is required, a
/// stale one is refused, and the answer carries the generation the queued event
/// stamps or the one the gate holds now.
#[napi]
pub fn session_input_string(session_id: String, value: String, input_generation: f64) -> String {
    let generation = match expected_input_generation("sessionInputString", input_generation) {
        Ok(generation) => generation,
        Err(message) => return error_json(&message),
    };
    if value.is_empty() {
        return error_json("sessionInputString value is empty");
    }
    let mut event = KeyEvent::new();
    event.set_seq(value);
    match active_keyboard_viewer(&session_id) {
        Ok(viewer) => match viewer.send_rustdesk_key(event, generation) {
            Ok(admitted) => {
                serde_json::json!({ "ok": true, "input_generation": admitted }).to_string()
            }
            Err(error) => refusal_json(&format!("{error:?}"), viewer.input_generation()),
        },
        Err(message) => error_json(&message),
    }
}

/// Publishes the client's view-only policy for this session.
///
/// The engine enforces it, not this layer: the running viewer stops admitting
/// input, drops what is already queued under the previous policy, and releases
/// the keys and buttons its writer emitted through the same ordered writer. The
/// answer separates the admission change from that release, so a caller is never
/// told a release completed because the setter returned.
#[napi]
pub fn session_set_view_only(session_id: String, enabled: bool) -> String {
    with_sessions(|sessions| match sessions.get_mut(&session_id) {
        Some(record) => {
            if let Err(message) = mutable_snapshot(record) {
                return error_json(message);
            }
            record.input_policy.view_only = enabled;
            let policy = record.input_policy;
            let outcome = publish_input_policy(record, policy);
            policy_json("sessionSetViewOnly", policy, outcome)
        }
        None => error_json("unknown session"),
    })
}

/// Publishes this session's acceptance of a peer the handshake did not prove.
///
/// A RustDesk session whose wire is not encrypted, or whose peer identity was
/// not verified, admits no input until its own operator accepts it — the
/// engine refuses every event, pointer and key alike, until this call. The
/// acceptance belongs to the viewer that is running now: it is never taken from
/// registration options and never written to preferences, so the next session
/// starts unaccepted. Withdrawing it revokes input immediately and releases
/// what the writer already emitted.
#[napi]
pub fn session_set_unverified_input_accepted(session_id: String, accepted: bool) -> String {
    with_sessions(|sessions| match sessions.get_mut(&session_id) {
        Some(record) => {
            if let Err(message) = mutable_snapshot(record) {
                return error_json(message);
            }
            record.input_policy.unverified_accepted = accepted;
            let policy = record.input_policy;
            let outcome = publish_input_policy(record, policy);
            policy_json("sessionSetUnverifiedInputAccepted", policy, outcome)
        }
        None => error_json("unknown session"),
    })
}

/// Records a client option pair and answers what the engine does with it.
///
/// The engine acts on `view-only` (the running viewer's own policy, published
/// here, refuses input while it is on) and `fps` (the rate the next
/// `session_start` asks for). Every other key is kept on the record so the
/// client can be told it arrived, and answered as not acted on rather than
/// silently dropped.
#[napi]
pub fn session_set_common(session_id: String, key: String, value: String) -> String {
    with_sessions(|sessions| match sessions.get_mut(&session_id) {
        Some(record) => {
            if let Err(message) = mutable_snapshot(record) {
                return error_json(message);
            }
            record.common.insert(key.clone(), value.clone());
            let mut published: Option<InputPolicyOutcome> = None;
            let (acted, action_note) = match key.as_str() {
                "view-only" => {
                    record.input_policy.view_only =
                        matches!(value.trim(), "Y" | "y" | "true" | "1");
                    let policy = record.input_policy;
                    published = publish_input_policy(record, policy);
                    if record.input_policy.view_only {
                        (
                            true,
                            "view-only applied to the engine now: its writer admits no further input and releases what it already emitted".to_string(),
                        )
                    } else {
                        (
                            true,
                            "view-only cleared: the engine admits input again and replays nothing queued under the previous policy".to_string(),
                        )
                    }
                }
                "fps" => match value.trim().parse::<u32>() {
                    Ok(fps) if (1..=240).contains(&fps) => {
                        record.fps = fps;
                        (true, "rate applied to the next session_start; a running viewer keeps its rate".to_string())
                    }
                    _ => (
                        false,
                        "recorded, not acted on: fps takes a rate between 1 and 240".to_string(),
                    ),
                },
                _ => (
                    false,
                    format!("recorded, not acted on: the engine acts on {COMMON_ACTED_ON:?} only"),
                ),
            };
            let recorded_only: Vec<&str> = record
                .common
                .keys()
                .filter(|key| !COMMON_ACTED_ON.contains(&key.as_str()))
                .map(String::as_str)
                .collect();
            let retired = published.map_or(0, |outcome| outcome.releases_retired);
            let unreleased = published.map_or(0, |outcome| outcome.releases_unreleased);
            // A release this viewer still owes is what the client acts on, so it
            // is said in the same words a policy change uses; what this key did
            // is what an answer with nothing outstanding says.
            let note = release_note(retired, unreleased).map_or(action_note, str::to_owned);
            let mut answer = serde_json::json!({
                "ok": true,
                "key": key,
                "acted": acted,
                "acted_on": COMMON_ACTED_ON,
                "recorded_only": recorded_only,
                "view_only": record.input_policy.view_only,
                "unverified_input_accepted": record.input_policy.unverified_accepted,
                "admission_revoked": published.is_some_and(|outcome| outcome.revoked),
                "releases_owed": published.map_or(0, |outcome| outcome.releases_owed),
                "releases_retired": retired,
                "release_pending": retired > 0,
                "releases_unreleased": unreleased,
                "fps": record.fps,
                "note": note,
            });
            // Published only when a viewer is running: a session with none has
            // no gate to name.
            if let Some(outcome) = published {
                answer["input_generation"] = serde_json::json!(outcome.input_generation);
            }
            answer.to_string()
        }
        None => error_json("unknown session"),
    })
}

/// The engine takes the requested frame rate when the viewer starts, so this
/// records it for the next session_start instead of implying a running session
/// changed rate.
#[napi]
pub fn session_set_custom_fps(session_id: String, fps: u32) -> String {
    if fps == 0 || fps > 240 {
        return error_json("fps must be between 1 and 240");
    }
    with_sessions(|sessions| match sessions.get_mut(&session_id) {
        Some(record) => {
            if let Err(message) = mutable_snapshot(record) {
                return error_json(message);
            }
            record.fps = fps;
            serde_json::json!({
                "ok": true,
                "note": "applied to the next session_start; a running viewer keeps its rate",
            })
            .to_string()
        }
        None => error_json("unknown session"),
    })
}

/// Cumulative counters from `Viewer::snapshot`. The engine reports totals, not
/// window rates, so the client owns the sampling window; this never invents an
/// average it did not measure.
#[napi]
pub fn session_get_frame_rate_snapshot(session_id: String, _display: u32) -> String {
    let sample = with_sessions(|sessions| {
        sessions.get_mut(&session_id).map(|record| {
            let snapshot = observe_terminal_reclamation(record);
            (
                record.dials,
                record.fps,
                record.terminal_elapsed_ms.unwrap_or_else(|| {
                    u64::try_from(record.started.elapsed().as_millis()).unwrap_or(u64::MAX)
                }),
                snapshot,
            )
        })
    });
    match sample {
        Some((dials, fps, elapsed_ms, Some(value))) => serde_json::json!({
            "available": true,
            "source": "engine_viewer_snapshot",
            // Both identities change when the viewer is dialled again, which is
            // what makes the client start a fresh window, and every rate it
            // shows is computed from the cumulative counters below.
            "generation": dials.to_string(),
            "intentRevision": dials.to_string(),
            "desiredFps": fps,
            "safetyFpsCap": null,
            "elapsedMs": elapsed_ms,
            // The engine's own lifecycle phase, which is what a session that
            // has not reached media yet must report: a hardcoded media state
            // claimed streaming during capability and authentication.
            "status": value.phase,
            "qualityRecommendationApplied": false,
            "recommendation": null,
            "receivedPackets": value.received_units,
            "decodedFrames": value.pushed_units,
            "submittedFrames": value.render_submissions,
            "admittedUnits": null,
            "unavailableFrames": 0,
            "noBufferFrames": 0,
            // This path converts no colour and drives no separate target: the
            // surface takes the decoder's buffer as it comes. Zero calls is the
            // honest figure, not a placeholder.
            "conversionCalls": 0,
            "conversionNs": 0,
            "targetCalls": 0,
            "targetNs": 0,
            // Admission never waits for a slot: a full queue is refused rather
            // than queued behind, so no frame ever spends time waiting in one.
            "queueCalls": 0,
            "queueNs": 0,
            "busyFrames": 0,
            // The interval this path measures runs from taking a unit to the
            // submission of its picture: the round trip through the codec,
            // pipeline delay included, not the decode work itself. The client's
            // decode row means "measured decode work", so reporting this
            // interval there would put one measurement under two names and call
            // a latency a work figure. The hardware decoder exposes no decode
            // interval, so this layer reports none and that row stays empty
            // rather than wrong; `renderNs` below carries the real one.
            "decodeCalls": 0,
            "decodeNs": 0,
            "decodeTimingAvailable": false,
            // Keep the numeric schema: zero samples means no measured latency,
            // independently of the complete submission count above.
            "renderCalls": value.render_timing.map_or(0, |timing| timing.samples),
            "renderNs": value.render_timing.map_or(0, |timing| timing.total_ns),
            // The codec this session negotiated, by name. Rewriting this
            // snapshot dropped it, which is why the client's codec row read
            // "--" while the stream ran H265.
            "codec": value.codec,
            "renderPeakNs": value.render_timing.map_or(0, |timing| timing.peak_ns),
            "queuedUnits": value.queued_units,
            "queueLen": value.queued_units,
            "decodeCapacityFps": null,
        })
        .to_string(),
        Some((_, _, _, None)) => serde_json::json!({
            "available": false,
            "reason": "engine_viewer_not_started",
        })
        .to_string(),
        None => serde_json::json!({
            "available": false,
            "reason": "unknown_session",
        })
        .to_string(),
    }
}

/// The entry points this file defines, each paired with the name napi exports it
/// under (`session_add` is ArkTS `sessionAdd`).
///
/// `har_surface_manifest` reports this list as implemented and
/// `implemented_entry_points_exist` names every function in it, so the compiler
/// fails the build on a rename or a deletion instead of leaving the manifest to
/// claim an entry point the HAR no longer serves.
macro_rules! implemented_entry_points {
    ($(($exported:literal, $function:ident)),+ $(,)?) => {
        const IMPLEMENTED: &[&str] = &[$($exported),+];

        #[allow(dead_code)]
        fn implemented_entry_points_exist() {
            $(let _ = $function;)+
        }
    };
}

implemented_entry_points!(
    ("nativeVersion", native_version),
    ("harSurfaceManifest", har_surface_manifest),
    ("queryDecoderCapabilities", query_decoder_capabilities),
    ("runtimeGetDecoderCapabilities", runtime_get_decoder_capabilities),
    ("appSetLifecycle", app_set_lifecycle),
    ("appInit", app_init),
    ("validateServerProfile", validate_server_profile),
    ("lanScanStart", lan_scan_start),
    ("lanPeersQuery", lan_peers_query),
    ("lanScanStop", lan_scan_stop),
    ("lanPeerRemove", lan_peer_remove),
    ("sessionAdd", session_add),
    ("sessionStart", session_start),
    ("sessionLogin", session_login),
    ("sessionBindSurface", session_bind_surface),
    ("sessionClose", session_close),
    ("sessionAcknowledgeClose", session_acknowledge_close),
    ("sessionPollEvents", session_poll_events),
    ("sessionRefresh", session_refresh),
    ("sessionSetCommon", session_set_common),
    ("sessionSetCustomFps", session_set_custom_fps),
    ("sessionSetViewOnly", session_set_view_only),
    (
        "sessionSetUnverifiedInputAccepted",
        session_set_unverified_input_accepted
    ),
    ("sessionSendMouse", session_send_mouse),
    ("sessionInputKey", session_input_key),
    ("sessionInputString", session_input_string),
    (
        "sessionGetFrameRateSnapshot",
        session_get_frame_rate_snapshot
    ),
    ("xcomponentAttach", xcomponent_attach),
    ("xcomponentDetach", xcomponent_detach),
    (
        "xcomponentSetFrameRateRangeNative",
        xcomponent_set_frame_rate_range_native
    ),
);

/// Which of the client's expected entry points this build serves, and how.
///
/// `implemented` is derived from the entry points above, `pending` is the
/// current Resk import list minus those. Missing engine operations are not
/// advertised as implemented merely because another bridge accepts the name.
#[napi]
pub fn har_surface_manifest() -> String {
    // RustDeskNativeApi.ets imports, plus this bridge's explicit input-policy
    // export. A refused entry point remains pending, not implemented.
    let expected = [
        "backendSummary",
        "buildMarker",
        "healthcheck",
        "inputInterceptorPollEvents",
        "inputInterceptorStart",
        "inputInterceptorStop",
        "nativeVersion",
        "runtimeGetApiServer",
        "runtimeGetDecoderCapabilities",
        "runtimeGetServerConfig",
        "runtimeInit",
        "runtimeListFavorites",
        "runtimeListLanPeers",
        "runtimeListLocalDir",
        "runtimeListRecentPeers",
        "peerQueryOnline",
        "runtimeRemoveDiscoveredPeer",
        "runtimeScanLanPeers",
        "runtimeSetLifecycle",
        "runtimeSetRecordingDirectory",
        "runtimeSetServerConfig",
        "runtimeTestServerConfig",
        "sessionAcknowledgeClose",
        "sessionAdd",
        "sessionBindSurface",
        "sessionCancelJob",
        "sessionChangeResolution",
        "sessionClose",
        "sessionEnterOrLeave",
        "sessionGetConnToken",
        "sessionGetEnableTrustedDevices",
        "sessionGetFrameRateSnapshot",
        "sessionGetImageQuality",
        "sessionGetIsRecording",
        "sessionGetRemoteAudioState",
        "sessionGetRgbaSize",
        "sessionGetToggleOption",
        "sessionHandleFlutterKeyEvent",
        "sessionInputKey",
        "sessionInputString",
        "sessionLogin",
        "sessionNextRgba",
        "sessionOnWaitingForImageDialogShow",
        "sessionPollEvents",
        "sessionReadRemoteDir",
        "sessionRecordScreen",
        "sessionRefresh",
        "sessionSend2fa",
        "sessionSendClipboard",
        "sessionSendClipboardFiles",
        "sessionSendClipboardImage",
        "sessionSendFiles",
        "sessionSendMouse",
        "sessionSetClipboardFileRoot",
        "sessionSetCodecPreference",
        "sessionSetCommon",
        "sessionSetConfirmOverrideFile",
        "sessionSetCustomFps",
        "sessionSetCustomImageQuality",
        "sessionSetImageQuality",
        "sessionSetShowRemoteCursor",
        "sessionSetSize",
        "sessionSetVideoPaused",
        "sessionSetViewOnly",
        "sessionSetUnverifiedInputAccepted",
        "sessionStart",
        "sessionSurfaceDestroyed",
        "sessionSwitchDisplay",
        "sessionTakeClipboard",
        "sessionTakeClipboardImage",
        "sessionTakeRgbaFrame",
        "sessionToggleOption",
        "transferNextJobId",
        "xcomponentAttach",
        "xcomponentDetach",
        "xcomponentSetFrameRateRangeNative",
    ];
    // Kept separate on purpose: these accept the call but only touch local state.
    let registry_only: [&str; 0] = [];
    let pending: Vec<&str> = expected
        .into_iter()
        .filter(|name| !IMPLEMENTED.contains(name) && !registry_only.contains(name))
        .collect();
    serde_json::json!({
        "engine": "rd-engine",
        "version": env!("CARGO_PKG_VERSION"),
        "implemented": IMPLEMENTED,
        "registry_only": registry_only,
        "pending": pending,
        "refused_entry_points": ["sessionCancelJob"],
        "not_served": {
            "transfer_cancel": {
                "entry_points": ["sessionCancelJob"],
                "reason": "no transfer-job owner is wired to this bridge; cancellation is refused and never closes a viewer or ACKs its terminal receipt",
            },
            "rgba_pull": {
                "entry_points": ["sessionGetRgbaSize", "sessionNextRgba", "sessionTakeRgbaFrame"],
                "reason": "the engine presents each frame into the surface sessionBindSurface recorded and has no CPU-side RGBA pull path",
            },
            "viewer_controls": {
                "entry_points": [
                    "sessionSetSize", "sessionSwitchDisplay", "sessionSetVideoPaused",
                    "sessionChangeResolution", "sessionSetShowRemoteCursor",
                    "sessionSetCodecPreference", "sessionGetImageQuality",
                    "sessionSetImageQuality", "sessionSetCustomImageQuality",
                    "sessionGetToggleOption", "sessionToggleOption",
                ],
                "reason": "the shared Viewer has no backing operations for these contracts; received display metadata and recorded common options are not applied controls",
            },
            "viewer_state": {
                "entry_points": [
                    "sessionGetRemoteAudioState", "sessionGetConnToken",
                    "sessionGetEnableTrustedDevices",
                ],
                "reason": "the shared Viewer exposes no audio renderer state, connection token or trusted-device state; false, null and default objects would not be engine results",
            },
            "input_adapter": {
                "entry_points": ["sessionEnterOrLeave", "sessionHandleFlutterKeyEvent"],
                "reason": "no focus/grab owner or Flutter key translator is wired to the shared Viewer; existing input exports require an explicit input generation",
            },
            "server_config": {
                "entry_points": ["runtimeGetServerConfig", "runtimeSetServerConfig"],
                "reason": "approved profiles belong to the Resk explicit-save store; this bridge validates and captures a route at sessionAdd, not mutable global server configuration",
            },
            "presence": {
                "entry_points": ["peerQueryOnline"],
                "reason": "query_presence exists in the engine but is not wired to an approved-profile, app-owned cancellable async query; LAN discovery is not server presence",
            },
        },
        "note": "sessionStart uses the captured explicit-save route for RustDesk IDs or the unchanged direct protocol connector; appInit and LAN cache/completion work are asynchronous and consent/lifecycle fenced; runtimeGetDecoderCapabilities shares the advertised-metadata query without measured or recommended codec claims; pending entries are not implemented; presentation remains the bound Surface, not RGBA pull",
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        apply_terminal_reclamation, bind_surface, client_mouse_button_to_wire, error_json,
        expected_input_generation, parse_viewer_target, policy_json, refusal_json,
        record_terminal_reclamation, resolve_mouse_coordinates, session_acknowledge_close,
        session_add, session_cancel_job, session_poll_events, with_sessions, ApprovedRoute,
        CloseWork, InputPolicyOutcome, LoginFailure, PendingSurfaceLease, Reported,
        SurfaceBinding, SurfaceLease, ViewerInputPolicy, ViewerSnapshot, ViewerTarget,
        MAX_SAFE_INPUT_GENERATION,
    };
    use std::sync::Arc;

    /// A destination the bridge only needs an id from. These tests exercise the
    /// bridge's receipts and ownership rules, never a native holder or a decoder.
    struct TestLease(u64);

    unsafe impl SurfaceLease for TestLease {
        fn surface_id(&self) -> u64 {
            self.0
        }
    }

    /// Injects the facts a real `xcomponentAttach` + holder borrow would produce.
    /// This host build has no ArkUI environment, so no borrow can run here; the
    /// receipt, single-publish and release rules are what these tests check.
    fn inject_binding(id: &str, component_id: &str, surface_id: u64, token: u64) {
        with_sessions(|sessions| {
            let record = sessions.get_mut(id).expect("the record is registered");
            record
                .lease
                .publish(Arc::new(TestLease(surface_id)))
                .expect("this session has not published a destination yet");
            record.binding = Some(SurfaceBinding {
                token,
                component_id: component_id.to_owned(),
                surface_id,
                display: 0,
            });
        });
    }

    fn json(response: String) -> serde_json::Value {
        serde_json::from_str(&response).expect("the bridge returns JSON")
    }

    fn register_lifecycle_test(id: &str) -> String {
        let added = json(session_add(
            id.to_owned(),
            "127.0.0.1:21118".to_owned(),
            r#"{"password":"test-only"}"#.to_owned(),
        ));
        assert_eq!(added["ok"], true);
        assert_eq!(added["session"]["kind"], "rustdesk");
        assert_eq!(added["session"]["target"], "127.0.0.1:21118");
        let epoch = added["session"]["lifecycleEpoch"].as_str().unwrap();
        assert!(epoch.parse::<u64>().unwrap() > 0);
        epoch.to_owned()
    }

    #[test]
    fn native_epoch_and_binding_survive_close_until_ack_then_id_reuse_gets_a_new_epoch() {
        let id = "napi-test-neverstarted";
        let epoch = register_lifecycle_test(id);
        // A bare Surface id string is not a binding key any more: with no live
        // holder there is nothing to borrow, so the answer refuses and invents no
        // destination.
        let refused = json(bind_surface(None, id.into(), 0, "42".into(), epoch.clone()));
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["surfaces"], serde_json::json!([]));
        let token = 4242u64;
        inject_binding(id, "xcomponent:test", 42, token);
        // The same holder re-binds from what this record already holds: no second
        // borrow and no second destination.
        let rebound = json(bind_surface(
            None,
            id.into(),
            0,
            "xcomponent:test".into(),
            epoch.clone(),
        ));
        assert_eq!(rebound["ok"], true);
        assert_eq!(rebound["bound"], true);
        assert_eq!(rebound["surfaces"][0]["token"], token.to_string());
        assert_eq!(rebound["surfaces"][0]["released"], false);
        // One destination per session: another component may not replace it.
        let replaced = json(bind_surface(None, id.into(), 0, "99".into(), epoch.clone()));
        assert_eq!(replaced["ok"], false);
        assert!(replaced["message"]
            .as_str()
            .unwrap()
            .contains("single Surface"));
        for act_id in [0, 37] {
            assert_eq!(json(session_cancel_job(id.into(), act_id))["ok"], false);
        }
        assert_eq!(json(session_poll_events(id.into(), 10))["closed"], false);
        assert_eq!(json(session_acknowledge_close(id.into(), epoch.clone()))["ok"], false);

        let close = json(CloseWork::prepare(id.into()).run());
        assert_eq!(close["ok"], true);
        assert_eq!(close["released"], true);
        assert_eq!(close["settle"], "neverstarted");
        assert_eq!(close["session"]["lifecycleEpoch"], epoch);
        assert_eq!(close["surfaces"][0]["surfaceId"], "42");
        assert_eq!(close["surfaces"][0]["componentId"], "xcomponent:test");
        assert_eq!(close["surfaces"][0]["token"], token.to_string());
        assert_eq!(close["surfaces"][0]["sourceIdentity"], epoch);
        assert_eq!(close["surfaces"][0]["released"], true);
        assert!(close.get("input_generation").is_none());
        assert!(close.get("releases_unreleased").is_none());
        assert_eq!(json(CloseWork::prepare(id.into()).run()), close);
        // The confirmed close already emptied the loan; giving it back is
        // idempotent and still names what was released.
        let cleared = json(bind_surface(None, id.into(), 0, "".into(), epoch.clone()));
        assert_eq!(cleared["released"], true);
        assert_eq!(cleared["held"], false);
        assert_eq!(cleared["surfaces"][0]["surfaceId"], "42");
        assert_eq!(json(session_acknowledge_close(id.into(), epoch.clone()))["record_removed"], true);

        let next_epoch = register_lifecycle_test(id);
        assert_ne!(next_epoch, epoch);
        assert_eq!(json(session_acknowledge_close(id.into(), epoch.clone()))["ok"], false);
        assert_eq!(json(bind_surface(None, id.into(), 0, "43".into(), epoch))["ok"], false);
        let next_close = json(CloseWork::prepare(id.into()).run());
        assert_eq!(next_close["session"]["lifecycleEpoch"], next_epoch);
        assert_eq!(next_close["surfaces"], serde_json::json!([]));
        assert_eq!(json(session_acknowledge_close(id.into(), next_epoch))["ok"], true);
        let unknown = json(CloseWork::prepare(id.into()).run());
        assert_eq!(unknown["ok"], false);
        assert_eq!(unknown["released"], false, "empty surfaces is not release proof");
        assert_eq!(unknown["settle"], "unconfirmed");
    }

    #[test]
    fn reclaimed_auth_failure_keeps_terminal_evidence_and_requires_a_complete_receipt() {
        let id = "napi-test-terminal-evidence";
        let epoch = register_lifecycle_test(id);
        inject_binding(id, "xcomponent:test", 43, 4343);
        // Exercise the bridge's terminal transition with owner-supplied facts;
        // this is not a peer-authentication or native-decoder integration test.
        with_sessions(|sessions| {
            let record = sessions.get_mut(id).unwrap();
            record.dials = 1;
            let snapshot = ViewerSnapshot {
                phase: "failed".into(),
                error: Some("AuthenticationFailed".into()),
                login_failure: Some(LoginFailure::WrongPassword),
                closed: true,
                input_generation: 9,
                releases_unreleased: 2,
                received_units: 17,
                pushed_units: 16,
                render_submissions: 15,
                ..Default::default()
            };
            record_terminal_reclamation(record, &snapshot, Some(true));
            assert!(record.password.is_empty());
            assert_eq!(record.lease.published_surface_id(), 0);
            assert!(!record.terminal_receipt_constructed);
        });
        assert_eq!(json(session_acknowledge_close(id.into(), epoch.clone()))["ok"], false);
        let poll = json(session_poll_events(id.into(), 10));
        assert_eq!(poll["events"][0]["name"], "close");
        assert_eq!(poll["released"], true);
        assert_eq!(poll["settle"], "settled");
        assert_eq!(poll["session"]["phase"], "failed");
        assert_eq!(poll["session"]["inputGeneration"], "9");
        assert_eq!(poll["login_failure"], "wrong_password");
        assert_eq!(poll["releases_unreleased"], 2);
        assert_eq!(poll["render_submissions"], 15);
        let close = json(CloseWork::prepare(id.into()).run());
        assert_eq!(close["ok"], true, "remote failure is not reclamation failure");
        assert_eq!(close["error"], "AuthenticationFailed");
        assert_eq!(close["login_failure"], "wrong_password");
        assert_eq!(close["releases_unreleased"], 2);
        assert_eq!(close["surfaces"], poll["surfaces"]);
        let repeated = json(session_poll_events(id.into(), 10));
        assert_eq!(repeated["events"], serde_json::json!([]));
        assert_eq!(repeated["error"], poll["error"]);
        assert_eq!(repeated["received_units"], 17);
        assert_eq!(json(session_acknowledge_close(id.into(), epoch))["ok"], true);
    }

    #[test]
    fn unknown_or_failed_reclamation_never_authorizes_giveback_or_ack() {
        let id = "napi-test-quarantine";
        let epoch = register_lifecycle_test(id);
        inject_binding(id, "xcomponent:test", 44, 4444);
        let snapshot = ViewerSnapshot {
            phase: "failed".into(),
            error: Some("ReclamationUnconfirmed".into()),
            closed: true,
            input_generation: 3,
            releases_unreleased: 1,
            ..Default::default()
        };
        with_sessions(|sessions| {
            let record = sessions.get_mut(id).unwrap();
            record.dials = 1;
            record_terminal_reclamation(record, &snapshot, None);
            assert!(record.terminal_snapshot.is_none(), "unknown is observed again later");
            assert!(record.reclaimed.is_none());
        });
        let held = json(bind_surface(None, id.into(), 0, "".into(), epoch.clone()));
        assert_eq!(held["ok"], false);
        assert_eq!(held["held"], true);
        assert_eq!(held["released"], false);
        assert_eq!(json(session_acknowledge_close(id.into(), epoch.clone()))["ok"], false);

        with_sessions(|sessions| {
            record_terminal_reclamation(sessions.get_mut(id).unwrap(), &snapshot, Some(false));
        });
        let poll = json(session_poll_events(id.into(), 10));
        assert_eq!(poll["reclamation_known"], true);
        assert_eq!(poll["reclaimed"], false);
        assert_eq!(poll["released"], false);
        assert_eq!(poll["settle"], "unconfirmed");
        assert_eq!(poll["surfaces"][0]["quarantined"], true);
        assert_eq!(poll["surfaces"][0]["surfaceId"], "44");
        assert_eq!(poll["releases_unreleased"], 1);
        assert_eq!(json(session_cancel_job(id.into(), 37))["ok"], false);
        assert_eq!(json(session_acknowledge_close(id.into(), epoch))["ok"], false);
        with_sessions(|sessions| {
            let record = sessions.get(id).unwrap();
            assert_eq!(record.lease.published_surface_id(), 44);
            assert!(!record.terminal_receipt_constructed);
            assert_eq!(record.password, "test-only");
            // Remove only this synthetic test fixture: it has no native owner.
            // No production API is permitted to evict a quarantined record.
            sessions.remove(id);
        });
    }

    #[test]
    fn pending_host_approval_does_not_request_new_credentials() {
        let mut reported = Reported::default();
        let mut snapshot = ViewerSnapshot {
            phase: "awaiting_approval".to_owned(),
            ..Default::default()
        };
        assert!(reported.events(&snapshot).is_empty());
        snapshot.phase = "authenticated".to_owned();
        snapshot.authenticated = true;
        let events = reported.events(&snapshot);
        assert!(events
            .iter()
            .any(|event| event["name"] == "connection_ready"));
        assert!(!events.iter().any(|event| event["type"] == "input-password"));
        assert!(reported.events(&snapshot).is_empty());
    }

    /// A coordinate-less button borrows the last position the engine admitted,
    /// and resolving one is a pure decision: the record is written only after
    /// the engine admitted the event that carried it.
    #[test]
    fn mouse_button_reuses_the_last_admitted_absolute_position() {
        let admitted = Some((480, 270));
        assert_eq!(
            resolve_mouse_coordinates(0, Some(10), Some(20), admitted),
            Ok((10, 20)),
            "a move's own coordinates are its candidate position"
        );
        assert_eq!(
            resolve_mouse_coordinates(1, None, None, admitted),
            Ok((480, 270)),
            "a button without coordinates borrows the admitted position"
        );
        assert_eq!(
            resolve_mouse_coordinates(2, None, None, admitted),
            Ok((480, 270))
        );
        assert_eq!(
            resolve_mouse_coordinates(3, None, None, admitted),
            Ok((0, 0)),
            "a wheel event carries notches, never a position"
        );
    }

    #[test]
    fn absolute_mouse_requires_a_complete_or_admitted_position() {
        assert_eq!(
            resolve_mouse_coordinates(0, None, None, None),
            Err("absolute mouse movement needs both x and y".to_string())
        );
        assert_eq!(
            resolve_mouse_coordinates(1, Some(1), None, None),
            Err("absolute mouse input needs both x and y or neither".to_string())
        );
        assert_eq!(
            resolve_mouse_coordinates(2, None, None, None),
            Err("mouse button needs a prior absolute pointer position".to_string())
        );
    }

    /// An epoch crosses this bridge only as an exact positive safe integer. The
    /// engine compares it against its own generation, so a rounded, clamped or
    /// inferred value would decide admission under a boundary the client never
    /// saw.
    #[test]
    fn an_input_generation_must_be_a_positive_safe_integer() {
        assert_eq!(expected_input_generation("sessionSendMouse", 1.0), Ok(1));
        assert_eq!(
            expected_input_generation("sessionSendMouse", MAX_SAFE_INPUT_GENERATION),
            Ok(9_007_199_254_740_991)
        );
        for rejected in [
            0.0,
            -1.0,
            2.5,
            f64::NAN,
            f64::INFINITY,
            9_007_199_254_740_992.0,
        ] {
            assert!(
                expected_input_generation("sessionInputKey", rejected).is_err(),
                "{rejected} is not a positive safe integer"
            );
        }
    }

    /// A refusal from the engine names the generation its gate holds now, so a
    /// client can retire the input state it kept for an epoch the engine has
    /// left; an answer this layer refuses itself names none, because there is no
    /// gate to read.
    #[test]
    fn only_an_engine_refusal_names_the_current_generation() {
        let refused =
            serde_json::from_str::<serde_json::Value>(&refusal_json("StaleInputGeneration", 7))
                .expect("the answer is JSON");
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["message"], "StaleInputGeneration");
        assert_eq!(
            refused["input_generation"], 7,
            "a refusal names the epoch the client's state belongs to now"
        );

        let local = serde_json::from_str::<serde_json::Value>(&error_json("unknown session"))
            .expect("the answer is JSON");
        assert_eq!(local["ok"], false);
        assert!(
            local.get("input_generation").is_none(),
            "an answer with no running viewer to read names no epoch"
        );
        assert!(local.get("error").is_some(), "the reason is still carried");
    }

    #[test]
    fn client_mouse_button_codes_map_to_rustdesk_wire_bits() {
        assert_eq!(client_mouse_button_to_wire(1), Ok(1));
        assert_eq!(client_mouse_button_to_wire(2), Ok(2));
        assert_eq!(client_mouse_button_to_wire(3), Ok(4));
        assert_eq!(client_mouse_button_to_wire(4), Ok(8));
        assert_eq!(client_mouse_button_to_wire(5), Ok(16));
        assert!(client_mouse_button_to_wire(6).is_err());
    }

    /// The destination slot accepts exactly one lease: a second fill would swap
    /// the Surface under a running viewer, so it is refused instead of applied.
    #[test]
    fn a_session_destination_is_published_once_and_released_only_by_reclamation() {
        let lease = PendingSurfaceLease::new();
        assert_eq!(lease.published_surface_id(), 0);
        assert!(!lease.is_ready(), "an unpublished slot is not ready");
        lease
            .publish(Arc::new(TestLease(7)))
            .expect("the first publish is what fills the slot");
        assert!(lease.is_ready());
        assert_eq!(lease.published_surface_id(), 7);
        assert!(
            lease.publish(Arc::new(TestLease(8))).is_err(),
            "a second lease may not replace the running destination"
        );
        assert_eq!(lease.published_surface_id(), 7);
        lease.release();
        assert!(!lease.is_ready());
        assert_eq!(lease.published_surface_id(), 0);
    }

    #[test]
    fn unconfirmed_reclamation_keeps_the_surface_lease_bound() {
        let lease = PendingSurfaceLease::new();
        lease
            .publish(Arc::new(TestLease(42)))
            .expect("one publish per session");
        let mut closed = false;
        let mut closing = false;
        let mut reclaimed = None;

        apply_terminal_reclamation(
            &mut closed,
            &mut closing,
            &mut reclaimed,
            &lease,
            Some(false),
        );

        assert!(
            !closed,
            "a failed reclamation must not make the record reusable"
        );
        assert!(closing, "the record remains terminally unsafe");
        assert_eq!(reclaimed, Some(false));
        assert_eq!(
            lease.published_surface_id(),
            42,
            "the borrowed destination stays published"
        );
    }

    #[test]
    fn confirmed_reclamation_releases_the_surface_lease() {
        let lease = PendingSurfaceLease::new();
        lease
            .publish(Arc::new(TestLease(42)))
            .expect("one publish per session");
        let mut closed = false;
        let mut closing = true;
        let mut reclaimed = None;

        apply_terminal_reclamation(
            &mut closed,
            &mut closing,
            &mut reclaimed,
            &lease,
            Some(true),
        );

        assert!(closed, "only a confirmed release makes the record reusable");
        assert!(!closing);
        assert_eq!(reclaimed, Some(true));
        assert_eq!(
            lease.published_surface_id(),
            0,
            "the released loan is emptied"
        );
    }

    #[test]
    fn direct_protocol_targets_keep_their_protocol_driver() {
        let (vnc, _) = parse_viewer_target("vnc://10.0.0.8:5901", false).expect("valid VNC");
        assert!(matches!(vnc, ViewerTarget::Vnc(_)));

        let (rdp, _) = parse_viewer_target("rdp://operator@10.0.0.9:3389", false)
            .expect("valid RDP account and endpoint");
        assert!(matches!(rdp, ViewerTarget::Rdp(_)));
        assert!(parse_viewer_target("rdp://10.0.0.9:3389", false).is_err());

        let (peer_id, _) = parse_viewer_target("123456789", false).expect("parseable peer ID");
        assert!(ApprovedRoute::parse("123456789", None).is_err());
        assert!(matches!(peer_id, ViewerTarget::RustDesk { address: None }));

        let (claimed_ip, _) = parse_viewer_target("10.0.0.8", true).expect("opaque LAN claimed ID");
        assert!(matches!(
            claimed_ip,
            ViewerTarget::RustDesk { address: None }
        ));
        assert!(ApprovedRoute::parse("10.0.0.8", None).is_err());
        let (manual_ip, _) = parse_viewer_target("10.0.0.8", false).expect("manual direct address");
        assert!(matches!(
            manual_ip,
            ViewerTarget::RustDesk { address: Some(_) }
        ));
        assert!(parse_viewer_target("vnc://10.0.0.8", true).is_err());
        assert!(parse_viewer_target("rdp://operator@10.0.0.8", true).is_err());
    }

    /// The policy answer is the contract the ArkTS client reads, so the facts it
    /// keys on have to be there and have to agree with each other.
    ///
    /// A client that keeps input state of its own learns from
    /// `input_generation` that the engine invalidated what came before this
    /// answer, and settles a release it was told about from `release_pending` /
    /// `releases_unreleased` — a session with no viewer has neither, and says so
    /// by carrying no generation at all.
    #[test]
    fn a_policy_answer_names_the_generation_and_the_release_it_still_owes() {
        let read_only = ViewerInputPolicy::read_only();
        let answer = |owed: u64, retired: u64, unreleased: u64| {
            let outcome = InputPolicyOutcome {
                policy: read_only,
                input_generation: 4,
                // A repeated setter: this call revoked nothing of its own.
                revoked: false,
                releases_owed: owed,
                releases_retired: retired,
                releases_unreleased: unreleased,
            };
            serde_json::from_str::<serde_json::Value>(&policy_json(
                "sessionSetViewOnly",
                read_only,
                Some(outcome),
            ))
            .expect("the answer is JSON")
        };

        let settled = answer(0, 0, 0);
        assert_eq!(settled["input_generation"], 4);
        assert_eq!(settled["admission_revoked"], false);
        assert_eq!(settled["release_pending"], false);
        assert_eq!(settled["releases_unreleased"], 0);

        // A key the operator is holding is not a release the engine owes, so an
        // answer may not report it as one still on its way.
        let holding = answer(1, 0, 0);
        assert_eq!(holding["releases_owed"], 1, "the writer owns the hold");
        assert_eq!(
            holding["release_pending"], false,
            "nothing was retired, so nothing is pending"
        );

        let pending = answer(1, 1, 0);
        assert_eq!(pending["releases_retired"], 1);
        assert_eq!(pending["release_pending"], true);

        let lost = answer(0, 0, 1);
        assert_eq!(lost["release_pending"], false);
        assert_eq!(lost["releases_unreleased"], 1);

        let recorded = serde_json::from_str::<serde_json::Value>(&policy_json(
            "sessionSetViewOnly",
            read_only,
            None,
        ))
        .expect("the answer is JSON");
        assert!(
            recorded.get("input_generation").is_none(),
            "a session with no viewer has no gate to name"
        );
    }
}
