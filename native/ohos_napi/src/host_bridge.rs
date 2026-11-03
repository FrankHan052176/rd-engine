//! HarmonyOS host-service NAPI surface.
//!
//! This module only admits the app scope, converts typed JSON, and waits for the
//! engine's own host-service owner. It creates no Tokio runtime, no second
//! capture owner and no alternate listener: every fact it returns is read from
//! `rd_engine::host::service`.
//!
//! The approved server profile in the start request is the same v2 explicit-save
//! envelope `runtime_get_server_config` returns, validated by the same
//! `ApprovedRoute` owner the session path uses. It selects the endpoints this
//! run registers with; it is never taken from a LAN scan, a target string or an
//! ambient mutable configuration.
use super::{
    app_context::{AppScope, app_scope, hold_id_admission, id_admission},
    host_security::{admit_security, SecurityOp, SecurityWork},
    server_profile::ApprovedRoute,
};
use hbb_common::{config::Config, sodiumoxide::crypto::sign};
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task},
    Env,
};
use rd_engine::host::{
    security::HostSecurity,
    service::{
        request_id as request_token, HostService, HostServiceError, HostServiceOptions,
        HostServiceStatus, DEFAULT_BITRATE,
    },
    HostCaptureSnapshot, HostError, HostPeerSnapshot,
};
#[cfg(target_env = "ohos")]
use rd_engine::ohos_input::{
    authorization_status, cancel_injection_request, request_injection, AuthorizationAnswer,
    InjectionStatus, InputError,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, MutexGuard};

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_PEERS_PER_POLL: i32 = 256;
const MAX_PASSWORD_LENGTH: u32 = 128;
const HOST_PLATFORM: &str = "HarmonyOS";
const DEFAULT_DISPLAY_NAME: &str = "HarmonyOS";

#[derive(Clone, Copy)]
struct ScreenConfig {
    display_id: i32,
    width: i32,
    height: i32,
    fps: u32,
}

struct BridgeState {
    /// The current (or last) owner. Retained after a stop so a status read keeps
    /// reporting the real terminal facts instead of inventing "disabled".
    service: Option<Arc<HostService>>,
    /// Geometry supplied by the platform display owner, used by the next start.
    screen: Option<ScreenConfig>,
    /// Last local ID this bridge admitted, so a status read needs no Config I/O.
    local_id: String,
    /// Explicit injection request owned by the admitted app generation. Unlike
    /// a Host run epoch, this exists while the system dialog is still pending.
    input_authorization_request_id: Option<u64>,
}

static BRIDGE: Mutex<BridgeState> = Mutex::new(BridgeState {
    service: None,
    screen: None,
    local_id: String::new(),
    input_authorization_request_id: None,
});

fn bridge() -> MutexGuard<'static, BridgeState> {
    BRIDGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn number(value: &Value, name: &str) -> Result<i64, String> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{name} must be an integer"))
}

fn string_or_empty(value: &Value, name: &str) -> Result<String, String> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(format!("{name} must be a string")),
    }
}

fn boolean_or(value: &Value, name: &str, default: bool) -> Result<bool, String> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("{name} must be a boolean")),
    }
}

fn host_error_text(error: HostError) -> String {
    match error {
        HostError::InvalidOptions => "host options or connection handle are invalid".into(),
        HostError::NoRuntime => "engine runtime is unavailable".into(),
        HostError::NoHardwareCodec => "this device reported no usable hardware encoder".into(),
        HostError::ListenFailed => "the host listener/route admission never became ready".into(),
        HostError::TransportFailed => "the host connection transport failed".into(),
        HostError::AuthenticationFailed => "host authentication failed or expired".into(),
        HostError::ApprovalDenied => "the approval is denied, stale or already consumed".into(),
        HostError::NoCommonCodec => "controller and host share no codec".into(),
        HostError::InvalidFrameRate => "the controller requested an invalid frame rate".into(),
        HostError::CaptureFailed => "the platform screen capture failed".into(),
        HostError::InvalidAccessUnit => "the encoder produced an invalid access unit".into(),
        HostError::UnsupportedDisplay => "the display is unsupported or changed".into(),
        HostError::InputUnavailable => "remote input is not granted by this engine".into(),
        HostError::InputFailed => "remote input failed".into(),
        HostError::ReclamationUnconfirmed => {
            "a native capture/listener owner did not confirm reclamation".into()
        }
    }
}

pub(super) fn service_error_text(error: HostServiceError) -> String {
    match error {
        HostServiceError::Host(error) => host_error_text(error),
        other => other.to_string(),
    }
}

/// The system injection-authorization fact this bridge reports.
///
/// On a real HarmonyOS target this is read from the engine's own
/// `rd_engine::ohos_input` seam, which serializes request ownership with the SDK
/// fact. Every other build target has no multimodal-input SDK, so the only
/// honest answer there is `unsupported`: the bridge never fabricates a grant it
/// cannot hold, and no callback here hands Host a policy.
struct InputAuthorization {
    /// The request's real return code, or the QueryAuthorizedStatus code after
    /// status/cancel. Off-target unsupported has no SDK call and reports `0`.
    result_code: i32,
    /// `unauthorized` | `authorizing` | `authorized` | `unsupported` | `failed`.
    status: &'static str,
    /// Process request owner, never an authorization epoch or a Host run epoch.
    request_id: Option<u64>,
}

#[cfg(target_env = "ohos")]
fn input_authorization_answer(answer: AuthorizationAnswer) -> InputAuthorization {
    InputAuthorization {
        result_code: answer.result_code,
        status: injection_status_word(answer.status),
        request_id: answer.request_id,
    }
}

#[cfg(target_env = "ohos")]
fn injection_status_word(status: InjectionStatus) -> &'static str {
    match status {
        InjectionStatus::Unauthorized => "unauthorized",
        InjectionStatus::Authorizing => "authorizing",
        InjectionStatus::Authorized => "authorized",
        InjectionStatus::Unsupported => "unsupported",
        InjectionStatus::Failed(_) => "failed",
    }
}

/// Asks the system for injection authorization. Short and synchronous by
/// contract: it starts no polling thread, retries nothing and only runs when the
/// ArkTS application calls it from an explicit user action.
#[cfg(target_env = "ohos")]
fn request_input_authorization() -> InputAuthorization {
    input_authorization_answer(request_injection())
}

/// Reads status and its request owner in one engine registry snapshot. A status
/// query creates no owner; a late OS grant cannot revive a cancelled request.
#[cfg(target_env = "ohos")]
fn query_input_authorization() -> InputAuthorization {
    input_authorization_answer(authorization_status())
}

#[cfg(target_env = "ohos")]
fn cancel_input_authorization(request_id: u64) -> Result<InputAuthorization, String> {
    cancel_injection_request(request_id)
        .map(input_authorization_answer)
        .map_err(|error| match error {
            InputError::InvalidInput => {
                "the injection authorization requestId is stale or is not owned by this app".into()
            }
            InputError::Unsupported => {
                "a live host run or held input owns injection authorization; stop that exact run and await native cleanup before cancelling".into()
            }
            InputError::ReclamationUnconfirmed => {
                "native input reclamation is unconfirmed; the injection owner is retained".into()
            }
            other => format!("injection authorization cancellation failed: {other:?}"),
        })
}

/// No multimodal-input injection authorization exists off a HarmonyOS target.
/// Reporting `unsupported` with no return code is the whole answer; a fabricated
/// `authorized` here would be the fake grant this bridge must never produce.
#[cfg(not(target_env = "ohos"))]
fn request_input_authorization() -> InputAuthorization {
    InputAuthorization {
        result_code: 0,
        status: "unsupported",
        request_id: None,
    }
}

#[cfg(not(target_env = "ohos"))]
fn query_input_authorization() -> InputAuthorization {
    InputAuthorization {
        result_code: 0,
        status: "unsupported",
        request_id: None,
    }
}

#[cfg(not(target_env = "ohos"))]
fn cancel_input_authorization(_request_id: u64) -> Result<InputAuthorization, String> {
    Ok(query_input_authorization())
}

fn parse_input_authorization_request_id(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|request_id| *request_id != 0 && request_id.to_string() == value)
        .ok_or_else(|| {
            "input authorization requestId must be a canonical non-zero decimal u64 string".into()
        })
}

/// The app guard covers SDK request plus token publication, not the dialog's
/// lifetime. AppContext::retire holds the same guard before calling our closer.
/// Dropping a short request scope must not cancel the dialog it just opened.
fn request_scoped_input_authorization() -> Result<InputAuthorization, String> {
    let _scope = app_scope()?;
    let admission = id_admission()?;
    let _admission_guard = hold_id_admission(&admission)?;
    let mut state = bridge();
    let answer = request_input_authorization();
    state.input_authorization_request_id = answer.request_id;
    Ok(answer)
}

/// Cleanup deliberately needs no fresh foreground AppScope: a backgrounded or
/// detached app must still retire its original request. Both the bridge slot
/// and the engine compare the exact token; neither substitutes a current one.
fn cancel_owned_input_authorization(request_id: u64) -> Result<InputAuthorization, String> {
    let mut state = bridge();
    #[cfg(target_env = "ohos")]
    if state.input_authorization_request_id != Some(request_id) {
        return Err("the injection authorization requestId is stale or is not owned by this app".into());
    }
    let answer = cancel_input_authorization(request_id)?;
    state.input_authorization_request_id = answer.request_id;
    Ok(answer)
}

fn input_authorization_message(status: &str) -> &'static str {
    match status {
        "unauthorized" => {
            "the system does not authorize injection; only an explicit user action may request it"
        }
        "authorizing" => "the system injection authorization request is waiting for the user's decision",
        "authorized" => "the system reports injection authorization; remote input still requires a current request owner",
        "unsupported" => "this device or build has no multimodal input injection authorization",
        "failed" => "the system injection authorization call failed and reported its own result code",
        _ => "the injection authorization state is not one this bridge reports",
    }
}

/// `ok` only says the call produced a real fact, never "granted" or "the dialog
/// closed". In particular cancel returns the SDK's observed state after its
/// void CancelInjection call, not an invented unauthorized answer.
fn input_authorization_document(action: &str, authorization: InputAuthorization) -> Value {
    let message = if action == "input_authorization_cancel" && authorization.request_id.is_none() {
        match authorization.status {
            "unauthorized" => "this request owner is retired and the system reports injection unauthorized",
            "authorizing" => "this request owner is retired; the system still reports authorizing, so closing the authorization dialog is unconfirmed",
            "authorized" => "this request owner is retired; the system still reports authorized, so system authorization revocation is unconfirmed",
            _ => input_authorization_message(authorization.status),
        }
    } else {
        input_authorization_message(authorization.status)
    };
    json!({
        "ok": matches!(authorization.status, "unauthorized" | "authorizing" | "authorized"),
        "action": action,
        "resultCode": authorization.result_code,
        "status": authorization.status,
        "requestId": authorization.request_id.map(|request_id| request_id.to_string()).unwrap_or_default(),
        "message": message,
    })
}

fn input_authorization_failure(action: &str, error: &str) -> Value {
    json!({
        "ok": false,
        "action": action,
        "resultCode": 0,
        "status": "failed",
        "requestId": "",
        "message": error,
    })
}

/// Why an `enableInput` start was refused, in the same five words the status
/// exports use. A refused start never falls back to a view-only run that claims
/// input.
fn input_authorization_rejection(authorization: InputAuthorization) -> String {
    match authorization.status {
        "unauthorized" => {
            "remote input needs the system's injection authorization, which is currently unauthorized"
                .into()
        }
        "authorizing" => {
            "remote input needs the system's injection authorization, and the request is still waiting for the user's decision".into()
        }
        "unsupported" => "this device or build cannot inject remote input".into(),
        "failed" => format!(
            "the system injection authorization call failed with result code {}, so remote input cannot be admitted",
            authorization.result_code
        ),
        _ => "remote input is not granted by the system".into(),
    }
}

fn admit_input_authorization(
    request_id: u64,
    authorization: InputAuthorization,
) -> Result<u64, String> {
    if authorization.status != "authorized" {
        return Err(input_authorization_rejection(authorization));
    }
    if authorization.request_id != Some(request_id) {
        return Err("the input authorization requestId is stale or has no current owner".into());
    }
    Ok(request_id)
}

fn capture_value(capture: &HostCaptureSnapshot) -> Value {
    json!({
        "state": capture.state,
        "authorized": capture.authorized,
        "sdkStateCode": capture.sdk_state_code,
        "framesObserved": capture.frames,
        "encodedBytes": capture.bytes,
        "queuedUnits": capture.queued_units,
        "queuedBytes": capture.queued_bytes,
        "width": capture.width,
        "height": capture.height,
        "error": capture.error.as_ref().map(ToString::to_string),
    })
}

fn peer_value(run_epoch: u64, peer: &HostPeerSnapshot) -> Value {
    json!({
        "connId": peer.conn_id,
        "requestId": request_token(run_epoch, peer).unwrap_or_default(),
        "peerId": peer.peer_id,
        "peerName": peer.name,
        "authorized": peer.authorized,
        "disconnected": peer.disconnected,
        "phase": peer.phase,
        "keyboard": peer.keyboard,
        "approvalEpoch": peer.approval_epoch.map(|epoch| epoch.to_string()).unwrap_or_default(),
        "policyRevision": peer.policy_revision.to_string(),
        "capture": peer.capture.as_ref().map(capture_value),
    })
}

/// The capture owner this service currently has, preferring the one that really
/// reported consent. There is no aggregate claim when no publisher exists: a
/// listening host with no controller has no capture at all.
fn aggregate_capture(status: &HostServiceStatus) -> Option<&HostCaptureSnapshot> {
    status
        .peers
        .iter()
        .filter_map(|peer| peer.capture.as_ref())
        .find(|capture| capture.authorized)
        .or_else(|| status.peers.iter().find_map(|peer| peer.capture.as_ref()))
}

pub(super) fn current_service() -> Option<Arc<HostService>> {
    bridge().service.clone()
}

/// The directory of the one host security record under the app-private root.
const SECURITY_DIRECTORY: &str = "host-security";

/// The one app-private security record of this process.
///
/// It is opened once from the private root `app_scope` admitted and never
/// replaced: the password/2FA entry points and the live host-service run share
/// this `Arc`, so a change made through the panel is the state the host really
/// authenticates with, and there is never a second store or a second file.
static SECURITY: Mutex<Option<Arc<HostSecurity>>> = Mutex::new(None);

/// Hook A of `.build-deps/host-security-handoff/hooks.md` §3: the security owner
/// of this process, opened on first use.
///
/// The app scope is enforced before the private root is touched, so a revoked
/// generation or a changed root cannot hand out a record. A record that exists
/// but cannot be read is an error and never a fresh initial state: treating it as
/// empty would silently drop the operator's permanent verifier and second factor.
pub(super) fn security_store() -> Result<Arc<HostSecurity>, String> {
    let scope = app_scope()?;
    let mut slot = SECURITY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(store) = slot.as_ref() {
        return Ok(store.clone());
    }
    let store = HostSecurity::open(scope.root().join(SECURITY_DIRECTORY))
        .map_err(|error| format!("the host security record is unusable: {error}"))?;
    *slot = Some(store.clone());
    Ok(store)
}

/// Hook B of the same handoff §4: publish the record's current verifier set into
/// the live run, so the new set and its revision decide the next authentication.
///
/// With no run live this is not an error and claims nothing — the next start
/// reads this same record. While a run is live, a failed publish is returned so
/// the caller reports the change as unapplied instead of saved.
pub(super) fn republish_host_security(store: &Arc<HostSecurity>) -> Result<(), String> {
    match current_service() {
        Some(service) => service
            .apply_security_credentials(store)
            .map_err(service_error_text),
        None => Ok(()),
    }
}

/// App-lifecycle fence hook for the parent-owned app context.
///
/// `app_set_lifecycle` is the privacy/foreground boundary; a revocation must not
/// leave a viewed-host listener accepting. This only *requests* the close: the
/// owner still joins its own native cleanup through `stop`, so an unconfirmed
/// teardown is reported as such rather than claimed here.
pub(super) fn close_after_lifecycle_fence() {
    if let Some(service) = current_service() {
        HostService::request_close(&service);
    }
    // APP is already held by AppContext::retire. Request publication uses
    // APP -> BRIDGE -> engine registry in the same order, so no newer app
    // request can be cancelled by this fence.
    let request_id = bridge().input_authorization_request_id;
    if let Some(request_id) = request_id {
        if let Err(error) = cancel_owned_input_authorization(request_id) {
            // A live run/held input is not pre-run cancellation. Its real close
            // owner still owes cleanup; keep the token and report the refusal.
            hbb_common::log::warn!("app lifecycle injection cancellation refused: {error}");
        }
    }
}

pub(super) fn failure_document(action: &str, error: &str) -> Value {
    // No successful status was produced, so enabled input is only whatever the
    // retained owner still reports: false when this process never ran a host.
    let input_enabled = current_service().is_some_and(|service| service.status().input_enabled);
    let authorization = query_input_authorization();
    json!({
        "ok": false,
        "action": action,
        "state": "failed",
        "serverState": "failed",
        "serverRunning": false,
        "error": error,
        "message": error,
        "lastError": error,
        "audioEnabled": false,
        "audioSupported": false,
        "inputEnabled": input_enabled,
        "inputAuthorization": authorization.status,
        "clipboardEnabled": false,
    })
}

fn status_document(action: &str, status: Option<&HostServiceStatus>, my_id: &str) -> Value {
    let authorization = query_input_authorization();
    let mut document = json!({
        "ok": true,
        "action": action,
        "audioEnabled": false,
        "audioSupported": false,
        "inputEnabled": false,
        "inputAuthorization": authorization.status,
        "clipboardEnabled": false,
        "registration": "stopped",
        "registrationObserved": false,
        "runEpoch": "0",
        "myId": my_id,
        "peerCount": 0,
        "clientCount": 0,
        "captureActive": false,
        "systemCaptureConfirmed": false,
        "framesObserved": 0,
        "terminal": false,
        "teardownUnconfirmed": Value::Null,
        "peers": Vec::<Value>::new(),
    });
    let Some(status) = status else {
        document["state"] = json!("disabled");
        document["serverState"] = json!("disabled");
        document["serverRunning"] = json!(false);
        document["hostPhase"] = json!("disabled");
        document["message"] = json!("the host service has never been started in this process");
        return document;
    };
    document["state"] = json!(status.state);
    // The run's own advertised fact, never the request's `enableInput`.
    document["inputEnabled"] = json!(status.input_enabled);
    document["serverState"] = json!(status.state);
    document["serverRunning"] = json!(status.state == "listening");
    document["hostPhase"] = json!(status.host_phase);
    document["runEpoch"] = json!(status.run_epoch.to_string());
    document["myId"] = json!(status.id);
    document["registration"] = json!(status.registration.as_str());
    document["registrationObserved"] = json!(status.registration_observed);
    document["approveMode"] = json!(status.approve_mode);
    document["approveModeScoped"] = json!(status.approve_mode_scoped);
    document["localApprovalEnforced"] = json!(status.local_approval_enforced);
    document["width"] = json!(status.width);
    document["height"] = json!(status.height);
    document["peerCount"] = json!(status.peer_count);
    document["clientCount"] = json!(status.authorized_peers);
    document["teardownUnconfirmed"] = match status.teardown_unconfirmed {
        true => json!("a previous host owner did not confirm native reclamation"),
        false => Value::Null,
    };
    document["peers"] = Value::Array(
        status
            .peers
            .iter()
            .map(|peer| peer_value(status.run_epoch, peer))
            .collect(),
    );
    let capture = aggregate_capture(status);
    let terminal = capture.is_some_and(|capture| matches!(capture.state, "stopped" | "quarantined"));
    document["captureState"] = match capture {
        Some(capture) => json!(capture.state),
        None => Value::Null,
    };
    document["captureActive"] = json!(capture.is_some() && !terminal);
    document["systemCaptureConfirmed"] = json!(capture.is_some_and(|capture| capture.authorized));
    document["consentState"] = match capture {
        Some(capture) => json!(capture.state),
        None => Value::Null,
    };
    document["framesObserved"] = json!(capture.map_or(0, |capture| capture.frames));
    document["sdkStateCode"] = json!(capture.map_or(-1, |capture| capture.sdk_state_code));
    document["queuedUnits"] = json!(capture.map_or(0, |capture| capture.queued_units));
    document["queuedBytes"] = json!(capture.map_or(0, |capture| capture.queued_bytes));
    document["terminal"] = json!(terminal);
    document["terminalReason"] = match capture.and_then(|capture| capture.error.as_ref()) {
        Some(error) => json!(error.to_string()),
        None => Value::Null,
    };
    if let Some(error) = status.error {
        let text = service_error_text(error);
        document["error"] = json!(text);
        document["lastError"] = json!(text);
    }
    document
}

/// One admitted start. Everything here was converted before any worker ran: the
/// approved server route and the official local identity are the only sources of
/// the run.
struct PendingStart {
    route: ApprovedRoute,
    display_name: String,
    bitrate: i64,
    audio_requested: bool,
    /// The local grant admitted for this run: true only when the system's own
    /// injection authorization was `authorized` at admission.
    allow_input: bool,
    /// Frozen at admission, never replaced by a worker's newer system grant.
    input_authorization_request_id: Option<u64>,
    require_local_approval: bool,
    screen: ScreenConfig,
    id: String,
}

fn parse_screen(value: &Value) -> Result<ScreenConfig, String> {
    let display_id = number(value, "displayId").unwrap_or(0);
    let width = number(value, "width")?;
    let height = number(value, "height")?;
    let fps = number(value, "frameRate").unwrap_or(30);
    if !(0..=i64::from(i32::MAX)).contains(&display_id) {
        return Err("displayId must be a non-negative display identifier".into());
    }
    if !(1..=8192).contains(&width) || !(1..=8192).contains(&height) {
        return Err("the display width/height must be the real screen geometry".into());
    }
    if width * height > 33_554_432 {
        return Err("the display geometry exceeds this publisher's pixel budget".into());
    }
    if !(1..=60).contains(&fps) {
        return Err("frameRate must be 1..=60 for the platform screen source".into());
    }
    Ok(ScreenConfig {
        display_id: display_id as i32,
        width: width as i32,
        height: height as i32,
        fps: fps as u32,
    })
}

fn admit_start(options_json: &str, local_id: String) -> Result<PendingStart, String> {
    if options_json.len() > MAX_REQUEST_BYTES {
        return Err("host start options are larger than this layer accepts".into());
    }
    let value: Value = serde_json::from_str(options_json)
        .map_err(|_| "host start options must be a JSON object".to_string())?;
    if !value.is_object() {
        return Err("host start options must be a JSON object".into());
    }
    // A local-approval request must not become password-or-click. When false,
    // passwords still require verification; there is no anonymous auto-approve.
    let require_local_approval = boolean_or(&value, "requireLocalApproval", true)?;
    // Remote keyboard/pointer injection needs a real system injection grant on
    // this device and the caller's exact explicit request owner. Preserve that
    // token until native run registration rechecks it under the engine mutex.
    let allow_input = boolean_or(&value, "enableInput", false)?;
    let input_authorization_request_id = if allow_input {
        let token = value
            .get("inputAuthorizationRequestId")
            .and_then(Value::as_str)
            .ok_or_else(|| "inputAuthorizationRequestId must be a decimal string for enableInput".to_string())?;
        let request_id = parse_input_authorization_request_id(token)?;
        Some(admit_input_authorization(request_id, query_input_authorization())?)
    } else {
        None
    };
    // Clipboard transfer is still not implemented on this platform; a request
    // for it is refused rather than silently dropped.
    if boolean_or(&value, "enableClipboard", false)? {
        return Err("this engine has no remote clipboard transfer on HarmonyOS".into());
    }
    let audio_requested = boolean_or(&value, "enableAudio", false)?;
    let display_name = match string_or_empty(&value, "displayName")? {
        name if name.is_empty() => DEFAULT_DISPLAY_NAME.to_string(),
        name => name,
    };
    let bitrate = match value.get("bitrate") {
        None | Some(Value::Null) => DEFAULT_BITRATE,
        Some(_) => number(&value, "bitrate")?,
    };
    if !(100_000..=200_000_000).contains(&bitrate) {
        return Err("bitrate must be between 100000 and 200000000 bit/s".into());
    }
    let profile = value.get("approvedServerProfile").ok_or_else(|| {
        "a saved approved server profile is required to register this host".to_string()
    })?;
    let route = ApprovedRoute::parse(&local_id, Some(profile))?;
    let screen = bridge()
        .screen
        .ok_or_else(|| "the screen geometry has not been configured for this run".to_string())?;
    Ok(PendingStart {
        route,
        display_name,
        bitrate,
        audio_requested,
        allow_input,
        input_authorization_request_id,
        require_local_approval,
        screen,
        id: local_id,
    })
}

/// The official local identity, read through the same Config root the rest of
/// the application bootstrapped. The signing key never leaves the run.
fn local_identity() -> Result<(sign::SecretKey, sign::PublicKey, Vec<u8>), String> {
    hbb_common::sodiumoxide::init().map_err(|_| "crypto initialization failed".to_string())?;
    let (secret, public) = Config::get_key_pair();
    let signing_key = sign::SecretKey::from_slice(&secret)
        .ok_or_else(|| "the official local signing key is invalid".to_string())?;
    let public_key = sign::PublicKey::from_slice(&public)
        .ok_or_else(|| "the official local public key is invalid".to_string())?;
    let registration_uuid = hbb_common::get_uuid();
    if registration_uuid.is_empty() {
        return Err("the official device UUID is unavailable".to_string());
    }
    Ok((signing_key, public_key, registration_uuid))
}

enum HostStage {
    Start(Box<PendingStart>),
    Stop {
        epoch: Option<u64>,
        action: &'static str,
    },
}

enum HostResult {
    Started(Arc<HostService>, Value),
    Done(Value),
}

pub struct HostWork {
    stage: Option<HostStage>,
    scope: Option<AppScope>,
    result: Option<HostResult>,
}

impl HostWork {
    fn refused(error: String, action: &str) -> Self {
        Self {
            stage: None,
            scope: None,
            result: Some(HostResult::Done(failure_document(action, &error))),
        }
    }

    fn start(&mut self) -> HostResult {
        let Some(HostStage::Start(request)) = self.stage.take() else {
            return HostResult::Done(failure_document(
                "server_start",
                "the host start request was not admitted",
            ));
        };
        if let Some(error) = self.scope.as_ref().and_then(|scope| scope.check().err()) {
            return HostResult::Done(failure_document("server_start", &error));
        }
        if current_service().is_some_and(|service| service.is_running()) {
            return HostResult::Done(failure_document(
                "server_start",
                "another host service run is already active",
            ));
        }
        // The run authenticates with this process's one security record. Opened
        // here, on the worker, so the first record read never blocks the ArkTS
        // thread, and a corrupt record fails the start instead of silently
        // becoming a fresh initial state.
        let security = match security_store() {
            Ok(store) => store,
            Err(error) => return HostResult::Done(failure_document("server_start", &error)),
        };
        let (signing_key, public_key, registration_uuid) = match local_identity() {
            Ok(identity) => identity,
            Err(error) => return HostResult::Done(failure_document("server_start", &error)),
        };
        let route = request.route.configuration();
        let service = HostService::start(HostServiceOptions {
            id: request.id.clone(),
            display_name: request.display_name,
            public_key,
            signing_key,
            registration_uuid,
            rendezvous_server: route.rendezvous_server,
            relay_server: route.relay_server,
            licence_key: route.licence_key,
            width: request.screen.width,
            height: request.screen.height,
            bitrate: request.bitrate,
            platform: HOST_PLATFORM.to_string(),
            require_local_approval: request.require_local_approval,
            allow_input: request.allow_input,
            #[cfg(target_env = "ohos")]
            input_authorization_request_id: request.input_authorization_request_id,
            security,
        });
        let status = service.status();
        let mut document = status_document("server_start", Some(&status), &request.id);
        document["ok"] = json!(status.state == "listening");
        document["audioRequested"] = json!(request.audio_requested);
        if status.state == "listening" {
            document["message"] = json!(if request.audio_requested {
                // Reported, not swallowed: this engine captures no device audio,
                // so nothing is shared and nothing claims to be.
                "screen sharing is listening; device audio capture is not implemented in this engine and is not shared"
            } else {
                "the host service is listening"
            });
        } else {
            let text = status
                .error
                .map(service_error_text)
                .unwrap_or_else(|| "the host listener never became ready".to_string());
            document["error"] = json!(text);
            document["message"] = json!(text);
            document["lastError"] = json!(text);
        }
        {
            let mut state = bridge();
            state.service = Some(service.clone());
            state.local_id = request.id.clone();
        }
        // Publish first, then check the original scope. A fence before
        // publication is caught here; a fence after it sees this service in
        // close_after_lifecycle_fence. Cleanup does not depend on JS resolving.
        if let Some(error) = self.scope.as_ref().and_then(|scope| scope.check().err()) {
            HostService::request_close(&service);
            return HostResult::Done(failure_document("server_start", &error));
        }
        HostResult::Started(service, document)
    }

    fn stop(&mut self) -> HostResult {
        let Some(HostStage::Stop { epoch, action }) = self.stage.take() else {
            return HostResult::Done(failure_document(
                "server_stop",
                "the host stop request was not admitted",
            ));
        };
        let Some(service) = current_service() else {
            // Nothing is owned by this process. An idempotent stop is not an
            // error and it claims no teardown.
            let local_id = bridge().local_id.clone();
            return HostResult::Done(status_document(action, None, &local_id));
        };
        match service.stop(epoch) {
            Ok(status) => {
                let mut document = status_document(action, Some(&status), &status.id);
                if status.teardown_unconfirmed {
                    document["ok"] = json!(false);
                    document["error"] = json!("a native owner did not confirm reclamation");
                    document["lastError"] = document["error"].clone();
                    document["message"] = json!(
                        "the host service stopped but native reclamation is unconfirmed; it will not be reused"
                    );
                } else {
                    document["ok"] = json!(true);
                    document["message"] =
                        json!("the host service and its listener are stopped");
                }
                HostResult::Done(document)
            }
            Err(error) => HostResult::Done(failure_document(action, &service_error_text(error))),
        }
    }
}

impl Task for HostWork {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        // A refused admission already carries its own failure document.
        if let Some(HostResult::Done(document)) = self.result.take() {
            return Ok(document.to_string());
        }
        let starting = match &self.stage {
            Some(HostStage::Start(_)) => true,
            Some(HostStage::Stop { .. }) => false,
            None => {
                return Ok(
                    failure_document("host_service", "no host operation was admitted").to_string(),
                )
            }
        };
        let outcome = if starting { self.start() } else { self.stop() };
        let document = match outcome {
            HostResult::Started(service, document) => {
                self.result = Some(HostResult::Started(service, document.clone()));
                document
            }
            HostResult::Done(document) => {
                self.result = Some(HostResult::Done(document.clone()));
                document
            }
        };
        Ok(document.to_string())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi_ohos::Result<Self::JsValue> {
        let Some(HostResult::Started(service, document)) = self.result.take() else {
            return Ok(output);
        };
        // The start promise may only resolve while the app generation it was
        // admitted under is still current. A revoked generation closes the
        // service it created instead of reporting it ready.
        if let Some(error) = self.scope.as_ref().and_then(|scope| scope.check().err()) {
            HostService::request_close(&service);
            let text = format!("stale native app generation: {error}");
            return Ok(failure_document("server_start", &text).to_string());
        }
        Ok(document.to_string())
    }
}

/// Starts the host service: real listener/route admission, hbbs registration and
/// the temporary-credential owner. It resolves when the listener is ready, never
/// when a controller is connected or a capture consented.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_server_start(options_json: String) -> AsyncTask<HostWork> {
    let admitted = (|| -> Result<HostWork, String> {
        let scope = app_scope()?;
        let local_id = id_admission()?.local_id;
        let request = admit_start(&options_json, local_id)?;
        Ok(HostWork {
            stage: Some(HostStage::Start(Box::new(request))),
            scope: Some(scope),
            result: None,
        })
    })();
    AsyncTask::new(admitted.unwrap_or_else(|error| HostWork::refused(error, "server_start")))
}

fn stop_work(run_epoch: &str, action: &'static str) -> HostWork {
    let epoch = if run_epoch.is_empty() {
        Ok(None)
    } else {
        run_epoch
            .parse::<u64>()
            .map(Some)
            .map_err(|_| "runEpoch must be a decimal string".to_string())
    };
    match epoch {
        Ok(epoch) => HostWork {
            stage: Some(HostStage::Stop { epoch, action }),
            scope: None,
            result: None,
        },
        Err(error) => HostWork::refused(error, action),
    }
}

/// Stops the run this service owns and waits for the Host and the registration
/// worker to end. An empty epoch means the current run; a stale epoch is refused.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_server_stop(run_epoch: String) -> AsyncTask<HostWork> {
    AsyncTask::new(stop_work(&run_epoch, "server_stop"))
}

/// The same owner stop as `controlledServerStop`: screen sharing has no separate
/// capture singleton, so stopping it stops and joins the one host service.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_screen_capture_stop(run_epoch: String) -> AsyncTask<HostWork> {
    AsyncTask::new(stop_work(&run_epoch, "screen_capture_stop"))
}

fn sync_status(action: &str) -> String {
    let service = current_service();
    let status = service.as_ref().map(|service| service.status());
    let local_id = bridge().local_id.clone();
    status_document(action, status.as_ref(), &local_id).to_string()
}

/// The current host-service state, read from the live owners. No I/O and no
/// ownership change.
#[napi]
pub fn controlled_server_get_status() -> String {
    sync_status("server_status")
}

/// The capture projection of the same host-service owner. It is a read of the
/// real publisher stats, never a second capture owner.
#[napi(js_name = "controlledScreenCaptureGetStatus")]
pub fn controlled_screen_capture_status() -> String {
    sync_status("screen_capture_status")
}

/// Configures the display geometry the next run publishes.
///
/// The values must be the real display geometry the platform owner reports; a
/// run freezes them, and the native publisher still refuses a geometry change.
/// This starts no capture and grants no privacy consent.
#[napi]
pub fn controlled_screen_configure(config_json: String) -> String {
    let configured = (|| -> Result<(ScreenConfig, String), String> {
        let _scope = app_scope()?;
        let local_id = id_admission()?.local_id;
        if config_json.len() > MAX_REQUEST_BYTES {
            return Err("screen configuration is larger than this layer accepts".into());
        }
        let value: Value = serde_json::from_str(&config_json)
            .map_err(|_| "screen configuration must be a JSON object".to_string())?;
        if current_service().is_some_and(|service| service.is_running()) {
            return Err("screen geometry is frozen while the host service runs".into());
        }
        Ok((parse_screen(&value)?, local_id))
    })();
    match configured {
        Ok((screen, local_id)) => {
            let mut state = bridge();
            state.screen = Some(screen);
            state.local_id = local_id;
            json!({
                "ok": true,
                "action": "screen_configure",
                "displayId": screen.display_id,
                "width": screen.width,
                "height": screen.height,
                "frameRate": screen.fps,
                "frozen": false,
                "message": "the next host run publishes this geometry; the frame cadence follows the controller's signed request",
            })
            .to_string()
        }
        Err(error) => failure_document("screen_configure", &error).to_string(),
    }
}

/// Lists the connections of the current run. A request token is only present
/// while that connection is really awaiting a local decision.
#[napi]
pub fn controlled_incoming_poll(limit: i32) -> String {
    if !(0..=MAX_PEERS_PER_POLL).contains(&limit) {
        return failure_document("incoming_poll", "limit must be 0..=256").to_string();
    }
    let limit = limit as usize;
    let Some(service) = current_service() else {
        return json!({
            "ok": true,
            "action": "incoming_poll",
            "clients": Vec::<Value>::new(),
            "requests": Vec::<Value>::new(),
            "totalClients": 0,
            "totalRequests": 0,
            "truncated": false,
            "message": "the host service is not running",
        })
        .to_string();
    };
    let status = service.status();
    let mut requests = Vec::new();
    let mut clients = Vec::new();
    for peer in &status.peers {
        let value = peer_value(status.run_epoch, peer);
        if peer.authorized && !peer.disconnected {
            clients.push(value);
        } else if !peer.disconnected && peer.approval_epoch.is_some() {
            requests.push(value);
        }
    }
    let total_requests = requests.len();
    let total_clients = clients.len();
    requests.truncate(limit);
    clients.truncate(limit);
    json!({
        "ok": true,
        "action": "incoming_poll",
        "runEpoch": status.run_epoch.to_string(),
        "state": status.state,
        "serverRunning": status.state == "listening",
        "clients": clients,
        "requests": requests,
        "totalClients": total_clients,
        "totalRequests": total_requests,
        "truncated": total_requests > limit || total_clients > limit,
    })
    .to_string()
}

/// Latches one local decision for exactly the connection its token names.
#[napi]
pub fn controlled_incoming_resolve(request_id_value: String, allow: bool) -> String {
    let action = "incoming_resolve";
    let Some(service) = current_service() else {
        return failure_document(action, "the host service is not running").to_string();
    };
    match service.approve(&request_id_value, allow) {
        Ok(()) => json!({
            "ok": true,
            "action": action,
            "requestId": request_id_value,
            "accepted": allow,
            "message": if allow {
                "the connection is approved; the system capture prompt follows that session's own consent"
            } else {
                "the connection request is denied"
            },
        })
        .to_string(),
        Err(error) => failure_document(action, &service_error_text(error)).to_string(),
    }
}

/// Requests the system injection authorization for this app.
///
/// This is the one caller-triggered entry point: the ArkTS application decides
/// that an explicit user action exists, and this bridge starts no polling
/// thread, retries nothing and grants no Host policy from a callback. The
/// answer's `status` is the authorization fact; `ok` only says the call produced
/// one. It never starts a run or admits input on its own.
#[napi]
pub fn controlled_input_authorization_request() -> String {
    let action = "input_authorization_request";
    match request_scoped_input_authorization() {
        Ok(answer) => input_authorization_document(action, answer).to_string(),
        Err(error) => input_authorization_failure(action, &error).to_string(),
    }
}

/// The current system injection-authorization fact. A query requests nothing
/// and starts no run; it cannot create or revive an admission owner. Status,
/// resultCode and requestId come from the same engine registry snapshot.
#[napi]
pub fn controlled_input_authorization_status() -> String {
    let action = "input_authorization_status";
    if let Err(error) = app_scope() {
        return input_authorization_failure(action, &error).to_string();
    }
    input_authorization_document(action, query_input_authorization()).to_string()
}

/// Cancels only a named pre-run request. Cleanup is allowed after the app scope
/// is revoked, but a stale token and an owner held by a live Host are refused.
/// The system may keep reporting authorizing/authorized after its void cancel
/// call; neither this document nor `ok` confirms that the OS dialog closed.
#[napi]
pub fn controlled_input_authorization_cancel(request_id: String) -> String {
    let action = "input_authorization_cancel";
    let cancelled = parse_input_authorization_request_id(&request_id)
        .and_then(cancel_owned_input_authorization);
    match cancelled {
        Ok(answer) => input_authorization_document(action, answer).to_string(),
        Err(error) => input_authorization_failure(action, &error).to_string(),
    }
}

/// The password panel's view. Every fact here is read from the record the host
/// really checks and from this run's own state: the stored verification method,
/// whether a permanent verifier is stored, and the live run's temporary
/// plaintext while the stored method accepts one. Nothing is reported as
/// unimplemented and nothing defaults to an initial state.
pub(super) fn password_document(
    action: &str,
    store: &HostSecurity,
    listening: bool,
    temporary: Option<String>,
    message: &str,
) -> Value {
    let permanent = store.permanent_password_set();
    json!({
        "ok": true,
        "action": action,
        "state": if listening { "listening" } else { "disabled" },
        "temporaryPassword": temporary.unwrap_or_default(),
        "verificationMethod": store.verification_method().as_str(),
        "permanentPasswordSet": permanent,
        // This host keeps one local verifier set, so the official local/preset
        // password split is the same fact here.
        "localPermanentPasswordSet": permanent,
        // No configuration policy locks these in this engine.
        "verificationMethodFixed": false,
        "permanentPasswordChangeDisabled": false,
        "maxPasswordLength": MAX_PASSWORD_LENGTH,
        "passwordSettingsSupported": true,
        "message": message,
    })
}

/// The temporary password of the live run, held by the native owner, and the
/// stored permanent-password facts. There is no plaintext on disk and no
/// temporary value once the run ends.
///
/// The record is opened and read on the worker, never on the ArkTS thread: this
/// panel is usable before any host run starts, so it cannot borrow the start
/// call's worker to be off the UI thread.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_password_get() -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::PasswordGet)
}

/// Replaces the temporary verifier of the live run. The new revision closes
/// authentication for connections that had not authorized yet. A stored method
/// that accepts no temporary password is refused rather than answered with a
/// password that could never authenticate.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_password_refresh() -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::PasswordRefresh)
}

#[cfg(test)]
mod tests {
    use super::{
        admit_input_authorization, input_authorization_document, input_authorization_rejection,
        parse_input_authorization_request_id, InputAuthorization,
    };
    use serde_json::json;

    fn authorization(status: &'static str, result_code: i32) -> InputAuthorization {
        InputAuthorization {
            result_code,
            status,
            request_id: None,
        }
    }

    #[test]
    fn request_ids_are_strict_nonzero_decimal_u64_strings() {
        for token in ["1", "18446744073709551615"] {
            assert_eq!(
                parse_input_authorization_request_id(token).map(|id| id.to_string()),
                Ok(token.to_string())
            );
        }
        for token in ["", "0", "+1", "-1", "01", " 1", "1 ", "1.0", "１", "18446744073709551616"] {
            assert!(parse_input_authorization_request_id(token).is_err(), "{token:?}");
        }
    }

    #[test]
    fn a_new_grant_cannot_replace_the_admitted_start_request() {
        let granted = |request_id| InputAuthorization {
            result_code: 0,
            status: "authorized",
            request_id,
        };
        let original = admit_input_authorization(17, granted(Some(17))).unwrap();
        assert_eq!(original, 17);
        assert!(admit_input_authorization(original, granted(Some(18))).is_err());
        assert!(admit_input_authorization(original, granted(None)).is_err());
        assert!(admit_input_authorization(original, InputAuthorization {
            status: "authorizing",
            ..granted(Some(17))
        }).is_err());
        assert_eq!(
            admit_input_authorization(original, granted(Some(17))),
            Ok(original)
        );
    }

    /// The shared answer shape must never turn a status into a grant: `ok` only
    /// says the call produced a real fact, and the client reads `status`.
    #[test]
    fn a_status_answer_is_not_an_authorization() {
        for status in ["unauthorized", "authorizing", "authorized"] {
            let document = input_authorization_document(
                "input_authorization_status",
                InputAuthorization {
                    request_id: Some(u64::MAX),
                    ..authorization(status, 0)
                },
            );
            assert_eq!(document["status"], json!(status));
            assert_eq!(document["requestId"], json!("18446744073709551615"));
            assert_eq!(document["ok"], json!(true), "a real status is still a real answer");
            let cancelled = input_authorization_document(
                "input_authorization_cancel",
                authorization(status, 0),
            );
            assert_eq!(cancelled["status"], json!(status), "cancel preserves the observed OS state");
            assert_eq!(cancelled["requestId"], json!(""), "the cancelled owner is not revived");
        }
        for status in ["unsupported", "failed"] {
            let document = input_authorization_document(
                "input_authorization_status",
                authorization(status, 0),
            );
            assert_eq!(document["status"], json!(status));
            assert_eq!(document["ok"], json!(false), "no fact this bridge can hold");
        }
    }

    #[test]
    fn a_failed_query_keeps_the_system_result_code() {
        let document = input_authorization_document(
            "input_authorization_status",
            authorization("failed", 401),
        );
        assert_eq!(document["status"], json!("failed"));
        assert_eq!(document["resultCode"], json!(401));
        assert_eq!(document["requestId"], json!(""));
    }

    /// An `enableInput` start is refused for the real reason, and a failed
    /// system call keeps its own code in the refusal text.
    #[test]
    fn a_refused_start_names_the_real_authorization_state() {
        let refused: Vec<String> = ["unauthorized", "authorizing", "unsupported", "failed"]
            .into_iter()
            .map(|status| input_authorization_rejection(authorization(status, 401)))
            .collect();
        assert!(refused.iter().all(|text| !text.is_empty()));
        let mut distinct = refused.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            refused.len(),
            "each state refuses differently"
        );
        assert!(refused[3].contains("401"), "the real code is reported");
    }
}
