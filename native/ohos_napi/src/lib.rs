//! ArkTS-facing NAPI surface of rd-engine.
//!
//! This HarmonyOS-only kernel output serves the typed `rustdesk-ohrs` package.
//! Its manifest distinguishes real engine-backed exports from unsupported
//! legacy client capabilities; no entry point fabricates success or telemetry.
use base::message_proto::{ControlKey, KeyEvent, KeyboardMode};
use napi_derive_ohos::napi;
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
    sync::{Arc, Mutex},
};
mod app_context;
mod server_profile;
use app_context::{
    app_init, app_set_lifecycle, lan_peer_remove, lan_peers_query, lan_scan_start, lan_scan_stop,
};
use server_profile::{validate_server_profile, ApprovedRoute};
mod capabilities;
use capabilities::query_decoder_capabilities;

/// The ArkTS renderer owns the Surface; the engine only needs its identity and
/// the promise that it outlives the lease (see ohos_decoder.rs for the contract).
///
/// The id is shared rather than copied because the client binds its surface
/// after it asks for the session: the engine reads the lease when the first
/// frame opens the surface, so a binding that arrives before then is what it
/// presents into. A lease still without an id fails at that open instead of
/// presenting into nothing.
struct OhosSurfaceLease {
    surface_id: AtomicU64,
}

impl OhosSurfaceLease {
    fn new() -> Self {
        Self {
            surface_id: AtomicU64::new(0),
        }
    }

    fn bind(&self, surface_id: u64) {
        self.surface_id.store(surface_id, Ordering::Release);
    }
}

unsafe impl SurfaceLease for OhosSurfaceLease {
    fn surface_id(&self) -> u64 {
        self.surface_id.load(Ordering::Acquire)
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

struct SessionRecord {
    target: String,
    viewer_target: ViewerTarget,
    /// Explicit-save profile and local identity, owned at registration. Starts
    /// never read editable server settings or import trust from the target.
    id_route: Option<IdRoute>,
    /// A confirmed terminal record remains until poll consumption is ACKed.
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
    /// A constructed terminal poll response, independent of one-shot events.
    terminal_polled: bool,
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
    /// The surface this session presents into, held from the moment the session
    /// is registered: the client binds the surface id after it asks for the
    /// session, and the engine reads the lease when the first frame opens it.
    lease: Arc<OhosSurfaceLease>,
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
    lease: &OhosSurfaceLease,
    verdict: Option<bool>,
) {
    match verdict {
        Some(true) => {
            *closed = true;
            *closing = false;
            *reclaimed = Some(true);
            lease.bind(0);
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

/// Observes terminal ownership at every lifecycle entry, without consuming events.
/// Unknown/failed reclamation retains the Viewer, lease and registry record.
fn observe_terminal_reclamation(record: &mut SessionRecord) -> Option<ViewerSnapshot> {
    if let Some(snapshot) = &record.terminal_snapshot {
        return Some(snapshot.clone());
    }
    let viewer = record.viewer.as_ref()?;
    let snapshot = viewer.snapshot();
    if snapshot.closed {
        let verdict = viewer.reclamation_confirmed();
        if verdict == Some(true) {
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
            scrub_terminal_record(record);
        }
    }
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
    match &record.id_route {
        Some(route) => {
            Viewer::start_rendezvous(options, record.lease.clone(), route.profile.configuration())
        }
        None => Viewer::start(options, record.lease.clone()),
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
    let registered = with_sessions(|sessions| -> Result<(), String> {
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
        sessions.insert(
            session_id.clone(),
            SessionRecord {
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
                terminal_polled: false,
                lease: Arc::new(OhosSurfaceLease::new()),
                input_policy,
                cursor: None,
                common: HashMap::new(),
                reported: Reported::default(),
            },
        );
        Ok(())
    });
    match registered {
        Ok(()) => action_json(
            true,
            "session_add",
            &session_id,
            "registered",
            serde_json::json!({
                "routable": true,
                "fps": fps,
                "view_only": view_only,
                "note": format!("{route_note}; {credentials_note}"),
            }),
        ),
        Err(message) => error_json(&message),
    }
}

/// The response shape the ArkTS client reads.
///
/// `updateSessionState` takes the session id out of `response.session` and
/// leaves it untouched when that object is absent, so a session entry point that
/// answers without one loses the id the rest of the UI keys on. Every session
/// response therefore carries `ok`, `action` and that object, with the call's
/// own fields merged in beside them.
fn action_json(
    ok: bool,
    action: &str,
    session_id: &str,
    phase: &str,
    extra: serde_json::Value,
) -> String {
    let mut response = serde_json::json!({
        "ok": ok,
        "action": action,
        "session": {
            "sessionId": session_id,
            "coreSessionId": session_id,
            "phase": phase,
        },
    });
    if let (Some(target), serde_json::Value::Object(extra)) = (response.as_object_mut(), extra) {
        for (key, value) in extra {
            target.insert(key, value);
        }
    }
    response.to_string()
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
    let started = with_sessions(|sessions| -> Result<(Arc<Viewer>, bool), String> {
        let Some(record) = sessions.get_mut(&session_id) else {
            return Err("unknown session".to_string());
        };
        mutable_snapshot(record).map_err(str::to_owned)?;
        if let Some(viewer) = &record.viewer {
            return Ok((viewer.clone(), false));
        }
        let viewer = dial(record)?;
        record.viewer = Some(viewer.clone());
        record.reported = Reported::default();
        // A new viewer is a new peer session: the position the previous one
        // admitted says nothing about where this one's pointer is, so a
        // coordinate-less button waits for a move this viewer actually admitted.
        record.cursor = None;
        record.dials += 1;
        record.started = Instant::now();
        Ok((viewer, true))
    });
    match started {
        Ok((viewer, started)) => {
            let snapshot = viewer.snapshot();
            let surface_bound = with_sessions(|sessions| {
                sessions
                    .get(&session_id)
                    .is_some_and(|record| record.lease.surface_id() != 0)
            });
            serde_json::json!({
                "ok": true,
                "started": started,
                "phase": snapshot.phase,
                "protocol": snapshot.protocol,
                "route": snapshot.route,
                "surface_bound": surface_bound,
                "note": if started {
                    "viewer dialled; it presents into the surface the client binds, which it may bind after this call"
                } else {
                    "a viewer is already running for this session: session_start did not dial again"
                },
            })
            .to_string()
        }
        Err(message) => error_json(&message),
    }
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

/// Records the OHOS surface this session presents into.
///
/// A session may bind a surface while it has no viewer yet. Once a viewer is
/// running, replacing or clearing its Surface is refused: close it first and
/// wait for the terminal poll response that confirms native reclamation.
#[napi]
pub fn session_bind_surface(session_id: String, display: u32, surface_id: String) -> String {
    let surface_id = surface_id.trim();
    let bound = if surface_id.is_empty() {
        0
    } else {
        match surface_id.parse::<u64>() {
            Ok(value) if value != 0 => value,
            _ => return error_json("surface id must be the decimal u64 the XComponent reports"),
        }
    };
    with_sessions(|sessions| match sessions.get_mut(&session_id) {
        Some(record) => {
            let snapshot = match mutable_snapshot(record) {
                Ok(snapshot) => snapshot,
                Err(message) => return error_json(message),
            };
            let existing = record.lease.surface_id();
            if snapshot.is_some() {
                if bound == 0 {
                    return error_json(
                        "cannot clear a surface while a viewer is running; request close and wait for confirmed reclamation",
                    );
                }
                if existing != 0 && existing != bound {
                    return error_json(
                        "cannot replace a running viewer's surface; request close and wait for confirmed reclamation",
                    );
                }
            }
            record.lease.bind(bound);
            let phase = snapshot.map_or_else(|| "registered".to_owned(), |value| value.phase);
            action_json(
                true,
                "session_bind_surface",
                &session_id,
                &phase,
                serde_json::json!({
                    "bound": bound != 0,
                    "display": display,
                    "note": if bound != 0 {
                        format!("display {display} bound to this session's surface: the engine reads it when it opens the surface for the first frame")
                    } else {
                        "binding cleared before any viewer was started".to_owned()
                    },
                }),
            )
        }
        None => error_json("unknown session"),
    })
}

/// Requests teardown, retaining ownership until the actual reclamation verdict.
/// A confirmed close scrubs runtime ownership but never consumes or ACKs the
/// terminal receipt. The client must still poll before sessionCancelJob(…, 0).
#[napi]
pub fn session_close(session_id: String) -> String {
    with_sessions(|sessions| {
        let Some(record) = sessions.get_mut(&session_id) else {
            return error_json("unknown session");
        };
        observe_terminal_reclamation(record);
        if record.closed {
            return action_json(
                true,
                "session_close",
                &session_id,
                "closed",
                serde_json::json!({
                    "already_closed": true,
                    "reclamation_known": record.reclaimed.is_some(),
                    "reclaimed": record.reclaimed,
                    "note": "session was already terminal; poll and acknowledge its recorded receipt",
                }),
            );
        }
        if record.closing {
            let verdict = record.reclaimed;
            return action_json(
                true,
                "session_close",
                &session_id,
                if verdict.is_some() { "failed" } else { "closing" },
                serde_json::json!({
                    "already_closing": true,
                    "reclamation_known": verdict.is_some(),
                    "reclaimed": verdict,
                    "note": if verdict.is_some() {
                        "the viewer is terminal but native surface reclamation was not confirmed; do not replace or clear this Surface"
                    } else {
                        "close was already requested; keep the Surface alive and poll for its terminal verdict"
                    },
                }),
            );
        }
        if let Some(viewer) = &record.viewer {
            record.closing = true;
            viewer.request_close();
            return action_json(
                true,
                "session_close",
                &session_id,
                "closing",
                serde_json::json!({
                    "reclamation_known": false,
                    "reclaimed": serde_json::Value::Null,
                    "note": "close requested; keep the Surface alive and poll for confirmed reclamation before replacing or clearing it",
                }),
            );
        }
        // No Viewer ever existed for this registered record: no runtime input
        // generation or release counters are fabricated for its terminal poll.
        apply_terminal_reclamation(
            &mut record.closed,
            &mut record.closing,
            &mut record.reclaimed,
            record.lease.as_ref(),
            Some(true),
        );
        scrub_terminal_record(record);
        action_json(
            true,
            "session_close",
            &session_id,
            "closed",
            serde_json::json!({
                "reclamation_known": true,
                "reclaimed": true,
                "note": "no viewer owned this session's Surface; poll before acknowledging the receipt",
            }),
        )
    })
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

/// Live calls request whole-viewer cancellation, never a transfer-job action.
/// actId=0 also ACKs a confirmed, successfully polled terminal receipt. Only
/// that explicit ACK removes the record; unknown/unpolled/quarantined records
/// cannot be retired or relabelled as reclaimed by this call.
#[napi]
pub fn session_cancel_job(session_id: String, act_id: u32) -> String {
    with_sessions(|sessions| {
        let Some(record) = sessions.get_mut(&session_id) else {
            return error_json("unknown session");
        };
        let snapshot = observe_terminal_reclamation(record);
        if record.closed && record.reclaimed == Some(true) {
            if act_id != 0 {
                return error_json("terminal receipt acknowledgment requires actId 0");
            }
            if !record.terminal_polled {
                return error_json(
                    "terminal receipt has not been polled; call sessionPollEvents before retiring the record",
                );
            }
            let response = serde_json::json!({
                "ok": true,
                "record_removed": true,
                "closed": true,
                "reclamation_known": true,
                "reclaimed": record.reclaimed,
            })
            .to_string();
            sessions.remove(&session_id);
            return response;
        }
        if snapshot.as_ref().is_some_and(|value| value.closed) || record.reclaimed.is_some() {
            return error_json("native surface reclamation is unconfirmed; the terminal record must be retained");
        }
        let Some(viewer) = &record.viewer else {
            return error_json("session has no running viewer");
        };
        record.closing = true;
        viewer.request_close();
        serde_json::json!({
            "ok": true,
            "record_removed": false,
            "note": "close requested; keep the Surface alive and poll sessionPollEvents for its reclamation verdict",
        })
        .to_string()
    })
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
            return error_json("unknown session");
        };
        let Some(snapshot) = observe_terminal_reclamation(record) else {
            if record.closed {
                let events = if record.reported.finished {
                    Vec::new()
                } else {
                    vec![serde_json::json!({ "name": "close" })]
                };
                let response = serde_json::json!({
                    "ok": true,
                    "events": events,
                    "phase": "closed",
                    "error": null,
                    "login_failure": null,
                    "peer_close_reason": null,
                    "authenticated": false,
                    "closed": true,
                    "reclamation_known": record.reclaimed.is_some(),
                    "reclaimed": record.reclaimed,
                    "note": "no viewer owned this session's Surface; reclamation is confirmed",
                })
                .to_string();
                record.reported.finished = true;
                record.terminal_polled = record.reclaimed == Some(true);
                return response;
            }
            return serde_json::json!({
                "ok": true,
                "events": [],
                "phase": "registered",
                "target": record.target,
                "routable": true,
                "closed": false,
                "login_failure": null,
                "peer_close_reason": null,
                "reclamation_known": false,
                "reclaimed": serde_json::Value::Null,
                "note": poll_note("registered", None),
            })
            .to_string();
        };
        let reclaimed = record.reclaimed;
        // This is typed terminal metadata, never a replacement reclamation
        // verdict or a channel for arbitrary CloseReason text from the peer.
        let peer_close_reason = if snapshot.closed && reclaimed == Some(true) {
            peer_close_reason_name(snapshot.peer_close_reason)
        } else {
            None
        };
        let events = record.reported.events(&snapshot);
        let response = serde_json::json!({
            "ok": true,
            "events": events,
            "phase": snapshot.phase,
            "error": snapshot.error,
            "login_failure": login_failure_name(snapshot.login_failure),
            "peer_close_reason": peer_close_reason,
            "route": snapshot.route,
            "codec": snapshot.codec,
            "width": snapshot.width,
            "height": snapshot.height,
            "encrypted": snapshot.encrypted,
            "peer_verified": snapshot.peer_verified,
            "keyboard_allowed": snapshot.keyboard_allowed,
            // The generation the admission answer above was read under. It
            // advances on any local policy or peer-grant change, which is how a
            // client that keeps input state of its own learns that the engine
            // released what it had taken — including a change that leaves
            // `keyboard_allowed` exactly as it was.
            "input_generation": snapshot.input_generation,
            // The same counters a policy change answers with, sampled from the
            // gate beside the generation, so a client can settle a release it
            // was told about without inferring completion from the generation.
            // `releases_owed` is every hold the writer owns, the keys and
            // buttons being held right now included; `releases_retired` is the
            // part a change retired, which is the release a client waits for.
            "releases_owed": snapshot.releases_owed,
            "releases_retired": snapshot.releases_retired,
            "release_pending": snapshot.releases_retired > 0,
            "releases_unreleased": snapshot.releases_unreleased,
            "authenticated": snapshot.authenticated,
            "closed": snapshot.closed,
            "reclamation_known": reclaimed.is_some(),
            "reclaimed": reclaimed,
            "received_units": snapshot.received_units,
            "pushed_units": snapshot.pushed_units,
            "render_submissions": snapshot.render_submissions,
            // A release this viewer still owes is what the client acts on, so
            // it is said in the same words a policy change uses; the phase note
            // is what an answer with nothing outstanding falls back to.
            "note": release_note(snapshot.releases_retired, snapshot.releases_unreleased)
                .unwrap_or_else(|| poll_note(&snapshot.phase, snapshot.error.as_deref())),
        })
        .to_string();
        // Construct the complete successful response before allowing ACK. A
        // one-shot close event alone is not a consumed terminal receipt.
        if snapshot.closed && record.closed && record.reclaimed == Some(true) {
            record.terminal_polled = true;
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
    ("sessionPollEvents", session_poll_events),
    ("sessionRefresh", session_refresh),
    ("sessionCancelJob", session_cancel_job),
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
);

/// Which of the client's expected entry points this build serves, and how.
///
/// `implemented` is derived from the entry points above, `pending` is the
/// client's own list minus those, and the RGBA pull trio is named as not served
/// because presentation goes through the bound surface.
#[napi]
pub fn har_surface_manifest() -> String {
    // The client's list (docs/OHRS_SURFACE.md), kept as the baseline `pending`
    // is computed against: a call it makes that this HAR does not serve has to
    // show up there.
    let expected = [
        "sessionAdd",
        "sessionStart",
        "sessionLogin",
        "sessionPollEvents",
        "sessionClose",
        "sessionRefresh",
        "sessionCancelJob",
        "sessionSetCommon",
        "sessionSetCustomFps",
        "sessionSetSize",
        "sessionSetViewOnly",
        "sessionSetUnverifiedInputAccepted",
        "sessionSetVideoPaused",
        "sessionSetImageQuality",
        "sessionSetCustomImageQuality",
        "sessionSetClipboardFileRoot",
        "sessionSetConfirmOverrideFile",
        "sessionInputString",
        "sessionSend2fa",
        "sessionSwitchDisplay",
        "sessionSendFiles",
        "sessionReadRemoteDir",
        "transferNextJobId",
        "sessionSendClipboard",
        "sessionSendClipboardFiles",
        "sessionSendClipboardImage",
        "sessionTakeClipboard",
        "sessionTakeClipboardImage",
        "sessionToggleOption",
        "sessionGetToggleOption",
        "sessionGetImageQuality",
        "sessionGetConnToken",
        "sessionGetEnableTrustedDevices",
        "sessionGetRemoteAudioState",
        "sessionGetFrameRateSnapshot",
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
        "not_served": {
            "rgba_pull": {
                "entry_points": ["sessionGetRgbaSize", "sessionNextRgba", "sessionTakeRgbaFrame"],
                "reason": "the engine presents each frame into the surface sessionBindSurface recorded and has no CPU-side RGBA pull path",
            },
        },
        "note": "sessionStart uses the captured explicit-save route for RustDesk IDs or the unchanged direct protocol connector; appInit and LAN cache/completion work are asynchronous and consent/lifecycle fenced; pending entries are not served; presentation remains the bound Surface, not RGBA pull",
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        apply_terminal_reclamation, client_mouse_button_to_wire, error_json,
        expected_input_generation, parse_viewer_target, policy_json, refusal_json,
        resolve_mouse_coordinates, ApprovedRoute, InputPolicyOutcome, OhosSurfaceLease, Reported, SurfaceLease,
        ViewerInputPolicy, ViewerSnapshot, ViewerTarget, MAX_SAFE_INPUT_GENERATION,
    };

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

    #[test]
    fn unconfirmed_reclamation_keeps_the_surface_lease_bound() {
        let lease = OhosSurfaceLease::new();
        lease.bind(42);
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
        assert_eq!(lease.surface_id(), 42, "the Surface lease stays intact");
    }

    #[test]
    fn confirmed_reclamation_releases_the_surface_lease() {
        let lease = OhosSurfaceLease::new();
        lease.bind(42);
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
        assert_eq!(lease.surface_id(), 0, "the released lease is cleared");
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
