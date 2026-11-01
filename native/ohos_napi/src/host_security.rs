//! ArkTS-facing host security surface: the permanent password verifier, the
//! verification method, TOTP enrolment, trusted devices and the live password
//! panel.
//!
//! Every entry point here reads or mutates the one `HostSecurity` owner the host
//! service really authenticates with (`security_store`) and, where the primary
//! password set changed, asks the live host run to republish its credentials
//! (`republish_host_security`). This layer keeps no verifier, secret or device
//! list of its own, starts no runtime and owns no socket; a refused or
//! unpersisted change is answered as such.
//!
//! None of that I/O runs on the ArkTS thread. An exported function here only
//! captures this app generation's `AppScope` and hands one small `SecurityOp` to
//! a `Task`; the record is opened, read and written, the live run's credentials
//! are republished and its temporary verifier rotated inside `Task::compute`.
//! The captured scope is checked again on the worker before the store is touched
//! and once more when the promise resolves, so the facts — and the one-time
//! secrets — of an older generation are never handed to a newer panel.
//!
//! Two hooks this module requires from the parent-owned bridge are named in
//! `.build-deps/host-security-handoff/hooks.md`: `security_store` and
//! `republish_host_security`.
use super::{
    app_context::{AppScope, app_scope, id_admission},
    host_bridge::{
        current_service, failure_document, password_document as running_password_document,
        republish_host_security, security_store, service_error_text,
    },
    scrub_password,
};
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task},
    Env,
};
use rd_engine::host::security::{
    HostSecurity, MAX_HWID_BYTES, MAX_PERMANENT_PASSWORD_CHARS, TrustedDevice,
};
use serde_json::{json, Value};
use std::sync::Arc;

/// One request's worth of JSON. The device list is the largest thing admitted.
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// The bound the ArkTS password field displays.
const MAX_PASSWORD_LENGTH: u32 = MAX_PERMANENT_PASSWORD_CHARS as u32;

fn security() -> Result<Arc<HostSecurity>, String> {
    security_store()
}

/// A refused or impossible change. `ok: false` is what the client's
/// `requireSuccess` turns into an error instead of a saved state.
fn refusal(action: &str, error: &str) -> Value {
    json!({
        "ok": false,
        "action": action,
        "error": error,
        "message": error,
        "lastError": error,
    })
}

fn password_document(action: &str, store: &HostSecurity, message: &str) -> Value {
    let permanent = store.permanent_password_set();
    json!({
        "ok": true,
        "action": action,
        "verificationMethod": store.verification_method().as_str(),
        "permanentPasswordSet": permanent,
        // This host has one local verifier store, so the local/preset split of
        // the official client is the same fact here.
        "localPermanentPasswordSet": permanent,
        // No configuration policy locks these in this engine.
        "verificationMethodFixed": false,
        "permanentPasswordChangeDisabled": false,
        "maxPasswordLength": MAX_PASSWORD_LENGTH,
        "passwordSettingsSupported": true,
        "message": message,
    })
}

fn device_value(device: &TrustedDevice) -> Value {
    json!({
        // The ArkTS record carries the raw identifier as a byte array, and
        // `removal` sends the same shape back.
        "hwid": device.hwid,
        "time": device.time,
        "id": device.id,
        "name": device.name,
        "platform": device.platform,
    })
}

/// The 2FA panel's view. The TOTP secret and any pending enrolment URI are not
/// part of it: only `controlled_two_factor_begin` returns a URI, once.
fn two_factor_document(action: &str, store: &HostSecurity, message: &str) -> Value {
    let state = store.two_factor_state();
    let mut document = json!({
        "ok": true,
        "action": action,
        "enabled": state.enabled,
        "setupPending": state.setup_pending,
        "trustedDevicesEnabled": state.trusted_devices_enabled,
        "trustedDevicesFixed": false,
        "trustedDevices": state
            .trusted_devices
            .iter()
            .map(device_value)
            .collect::<Vec<_>>(),
        "message": message,
    });
    if let Some(error) = state.registration_error {
        // A verified code really did verify; only the device could not be
        // stored. Saying so is not a claim that the device is trusted.
        document["lastError"] = json!(error);
    }
    document
}

/// A credential admitted from ArkTS: the permanent password, or the six-digit
/// code of a pending enrolment.
///
/// The bytes are zeroed on every path this work can take — an admission refused
/// before a worker was queued, a task dropped without ever running, a worker
/// that finished or failed, and a promise that resolved — so no plaintext of
/// either outlives the operation that needed it.
pub(super) struct Secret(String);

impl Secret {
    fn new(value: String) -> Self {
        Self(value)
    }

    /// The only way out: the store's own verifier/check receives these bytes for
    /// this one call. Nothing formats them into an answer.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        scrub_password(&mut self.0);
    }
}

/// What one admitted operation is, in the terms its client already handles: the
/// action name every answer carries, the failure shape (the password panel's
/// answers belong to the host-service bridge), and whether it is a change rather
/// than a read.
#[derive(Clone, Copy)]
struct Shape {
    action: &'static str,
    host_service: bool,
    mutation: bool,
}

impl Shape {
    /// A refused call in the shape its client already handles. A refusal changed
    /// nothing and is never a saved state.
    fn failure(&self, error: &str) -> Value {
        if self.host_service {
            failure_document(self.action, error)
        } else {
            refusal(self.action, error)
        }
    }

    /// The answer of a call whose worker ran but whose app generation ended
    /// before the promise resolved.
    ///
    /// The facts are withheld: neither a record read nor a one-time secret (the
    /// enrolment URI, the live run's temporary password) may reach a panel newer
    /// than the call. A change whose worker already returned is in the owner the
    /// next generation reads, and this answer says so instead of claiming the
    /// change was never made.
    fn withheld(&self, error: &str) -> Value {
        let text = format!("stale native app generation: {error}");
        let message = if self.mutation {
            format!(
                "{text}; the worker had already completed this change, so the host owner holds it, \
                 while this generation's result and any one-time value are withheld"
            )
        } else {
            format!(
                "{text}; the worker completed this call, so its result and any one-time secret are \
                 withheld from this generation"
            )
        };
        let mut document = self.failure(&text);
        document["message"] = json!(message);
        document
    }
}

/// One security/password operation: the small set of things these entry points
/// do. The bounded request is already validated and the credential, if any, is
/// held by `Secret`; the store is only reached in `run`, on the worker.
pub(super) enum SecurityOp {
    PasswordGet,
    PasswordRefresh,
    PasswordSetPermanent(Secret),
    PasswordSetVerificationMethod(String),
    SettingSet {
        key: String,
        value: String,
    },
    TwoFactorBegin,
    TwoFactorVerify(Secret),
    TwoFactorDisable,
    TwoFactorGet,
    TwoFactorRemoveTrustedDevices(String),
    TwoFactorClearTrustedDevices,
}

impl SecurityOp {
    fn shape(&self) -> Shape {
        match self {
            Self::PasswordGet => Shape {
                action: "password_get",
                host_service: true,
                mutation: false,
            },
            Self::PasswordRefresh => Shape {
                action: "password_refresh",
                host_service: true,
                mutation: true,
            },
            Self::PasswordSetPermanent(_) => Shape {
                action: "password_set_permanent",
                host_service: false,
                mutation: true,
            },
            Self::PasswordSetVerificationMethod(_) => Shape {
                action: "password_set_verification_method",
                host_service: false,
                mutation: true,
            },
            Self::SettingSet { .. } => Shape {
                action: "setting_set",
                host_service: false,
                mutation: true,
            },
            Self::TwoFactorBegin => Shape {
                action: "two_factor_begin",
                host_service: false,
                mutation: false,
            },
            Self::TwoFactorVerify(_) => Shape {
                action: "two_factor_verify",
                host_service: false,
                mutation: true,
            },
            Self::TwoFactorDisable => Shape {
                action: "two_factor_disable",
                host_service: false,
                mutation: true,
            },
            Self::TwoFactorGet => Shape {
                action: "two_factor_get",
                host_service: false,
                mutation: false,
            },
            Self::TwoFactorRemoveTrustedDevices(_) => Shape {
                action: "two_factor_remove_trusted_devices",
                host_service: false,
                mutation: true,
            },
            Self::TwoFactorClearTrustedDevices => Shape {
                action: "two_factor_clear_trusted_devices",
                host_service: false,
                mutation: true,
            },
        }
    }

    /// The worker half of the call: the one record is opened, read, written and
    /// its verifier set republished here, and `rotate_temporary_password` runs
    /// against the live owner. A failed change keeps the last valid state.
    fn run(&self) -> Result<Value, String> {
        let shape = self.shape();
        match self {
            Self::PasswordGet => {
                let store = security()?;
                let service = current_service();
                let listening = service.as_ref().is_some_and(|service| service.is_running());
                let temporary = service.and_then(|service| service.temporary_password());
                let message = match (listening, temporary.is_some()) {
                    (false, _) => "no host service is running, so no password is in force",
                    (true, true) => {
                        "the temporary password of the running host service; the stored verification method decides which passwords are accepted"
                    }
                    (true, false) => {
                        "this run accepts no temporary password; the stored verification method accepts only the permanent one"
                    }
                };
                Ok(running_password_document(shape.action, &store, listening, temporary, message))
            }
            Self::PasswordRefresh => {
                let store = security()?;
                let Some(service) = current_service() else {
                    return Err("the host service is not running".to_string());
                };
                let password = service
                    .rotate_temporary_password()
                    .map_err(service_error_text)?;
                Ok(running_password_document(
                    shape.action,
                    &store,
                    service.is_running(),
                    Some(password),
                    "the temporary password was replaced; connections that had not authorized must use the new one",
                ))
            }
            Self::PasswordSetPermanent(password) => {
                let store = security()?;
                store
                    .set_permanent_password(password.expose())
                    .map_err(|error| error.to_string())?;
                republish_host_security(&store)?;
                let message = if store.permanent_password_set() {
                    "the permanent password verifier is stored; the plaintext was not kept"
                } else {
                    "the permanent password is cleared"
                };
                Ok(password_document(shape.action, &store, message))
            }
            Self::PasswordSetVerificationMethod(method) => {
                let store = security()?;
                store.set_verification_method(method).map_err(|error| error.to_string())?;
                republish_host_security(&store)?;
                Ok(password_document(
                    shape.action,
                    &store,
                    "the accepted password set is stored and published to this run",
                ))
            }
            Self::SettingSet { key, value } => {
                let store = security()?;
                let enabled = store.set_setting(key, value).map_err(|error| error.to_string())?;
                Ok(json!({
                    "ok": true,
                    "action": shape.action,
                    "key": key,
                    "value": if enabled { "true" } else { "false" },
                    "trustedDevicesEnabled": enabled,
                    "message": "the trusted-device policy is stored and is read at the next verification",
                }))
            }
            Self::TwoFactorBegin => {
                let store = security()?;
                let account = id_admission()?.local_id;
                let uri = store
                    .begin_two_factor(&account)
                    .map_err(|error| error.to_string())?;
                let mut document = two_factor_document(
                    shape.action,
                    &store,
                    "scan the URI, then enter the current six-digit code to enable 2FA",
                );
                document["uri"] = json!(uri);
                Ok(document)
            }
            Self::TwoFactorVerify(code) => {
                let store = security()?;
                store.verify_two_factor(code.expose()).map_err(|error| error.to_string())?;
                Ok(two_factor_document(
                    shape.action,
                    &store,
                    "two-factor authentication is enabled and its secret is stored",
                ))
            }
            Self::TwoFactorDisable => {
                let store = security()?;
                store.disable_two_factor().map_err(|error| error.to_string())?;
                Ok(two_factor_document(
                    shape.action,
                    &store,
                    "two-factor authentication is disabled and its trusted devices are revoked",
                ))
            }
            Self::TwoFactorGet => {
                let store = security()?;
                Ok(two_factor_document(
                    shape.action,
                    &store,
                    "two-factor state read from the host's own record",
                ))
            }
            Self::TwoFactorRemoveTrustedDevices(hwids_json) => {
                let store = security()?;
                let hwids = parse_hwids(hwids_json)?;
                store.remove_trusted_devices(&hwids).map_err(|error| error.to_string())?;
                Ok(two_factor_document(
                    shape.action,
                    &store,
                    "the named trusted devices are revoked",
                ))
            }
            Self::TwoFactorClearTrustedDevices => {
                let store = security()?;
                store.clear_trusted_devices().map_err(|error| error.to_string())?;
                Ok(two_factor_document(shape.action, &store, "every trusted device is revoked"))
            }
        }
    }
}

/// One admitted security/password call.
///
/// Admission is the bounded parameter check plus the captured `AppScope`; it
/// touches no store, no Config and no live run. The record is reached only by
/// `Task::compute`, on a worker thread.
pub struct SecurityWork {
    op: Option<SecurityOp>,
    shape: Shape,
    scope: Option<AppScope>,
    /// The admission's own refusal, already in this operation's failure shape.
    admitted_refusal: Option<String>,
    /// Whether the worker answered successfully. A refusal changed nothing and
    /// is never replaced by the withheld answer.
    succeeded: bool,
}

impl SecurityWork {
    fn admitted(op: SecurityOp, scope: AppScope) -> Self {
        Self {
            shape: op.shape(),
            op: Some(op),
            scope: Some(scope),
            admitted_refusal: None,
            succeeded: false,
        }
    }

    /// A call that never reached a worker: the app scope was refused. Nothing
    /// was read and nothing was written, and a credential it carried is scrubbed
    /// here rather than waiting for the task to be released.
    fn refused(op: SecurityOp, error: String) -> Self {
        let shape = op.shape();
        // Explicit: the credential must not outlive the refusal.
        drop(op);
        Self {
            op: None,
            shape,
            scope: None,
            admitted_refusal: Some(shape.failure(&error).to_string()),
            succeeded: false,
        }
    }
}

impl Task for SecurityWork {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        // A refused admission already carries its own failure document.
        let Some(op) = self.op.take() else {
            let shape = self.shape;
            let document = match self.admitted_refusal.take() {
                Some(document) => document,
                None => shape.failure("no security operation was admitted").to_string(),
            };
            return Ok(document);
        };
        // The generation this call was admitted under is checked before the
        // record or the live run is touched: an operation admitted by a
        // generation that has since ended can neither read nor change it.
        if let Some(error) = self.scope.as_ref().and_then(|scope| scope.check().err()) {
            return Ok(self.shape.withheld(&error).to_string());
        }
        // `op` (and with it the credential) is dropped when this call returns.
        match op.run() {
            Ok(document) => {
                self.succeeded = true;
                Ok(document.to_string())
            }
            Err(error) => Ok(self.shape.failure(&error).to_string()),
        }
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi_ohos::Result<Self::JsValue> {
        if !self.succeeded {
            return Ok(output);
        }
        // The panel this promise resolves into must still be the generation that
        // asked. A read's facts and a one-time secret of an older generation are
        // withheld, never rewritten into the refusing panel's state.
        let Some(error) = self.scope.as_ref().and_then(|scope| scope.check().err()) else {
            return Ok(output);
        };
        Ok(self.shape.withheld(&error).to_string())
    }
}

/// Admission for one operation: the bounded request is already validated and
/// this captures the generation it belongs to. The store itself is reached on
/// the worker only.
pub(super) fn admit_security(op: SecurityOp) -> AsyncTask<SecurityWork> {
    AsyncTask::new(match app_scope() {
        Ok(scope) => SecurityWork::admitted(op, scope),
        Err(error) => SecurityWork::refused(op, error),
    })
}

/// Stores the permanent password as a salted verifier and republishes this run's
/// primary credentials. The plaintext is never returned and never stored.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_password_set_permanent(password: String) -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::PasswordSetPermanent(Secret::new(password)))
}

/// Selects which verifiers the primary password check accepts.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_password_set_verification_method(method: String) -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::PasswordSetVerificationMethod(method))
}

/// Writes the host settings this engine really acts on. An unhandled key is
/// refused rather than answered as saved.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_setting_set(key: String, value: String) -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::SettingSet { key, value })
}

/// Generates a fresh TOTP secret and the otpauth URI that enrols it. Nothing is
/// enabled and nothing is written until one six-digit code proves the secret.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_two_factor_begin() -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::TwoFactorBegin)
}

/// Enables the second factor only when the code proves the pending secret; the
/// secret becomes durable in that same write.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_two_factor_verify(code: String) -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::TwoFactorVerify(Secret::new(code)))
}

/// Turns the second factor off, durably, and revokes the trusted devices it
/// enrolled.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_two_factor_disable() -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::TwoFactorDisable)
}

/// The stored 2FA state: enabled, the trusted-device policy and the live device
/// list. No secret and no enrolment URI.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_two_factor_get() -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::TwoFactorGet)
}

fn parse_hwids(value: &str) -> Result<Vec<Vec<u8>>, String> {
    if value.len() > MAX_REQUEST_BYTES {
        return Err("the trusted-device list is larger than this layer accepts".into());
    }
    let parsed: Value =
        serde_json::from_str(value).map_err(|_| "hwids must be a JSON array of byte arrays")?;
    let entries = parsed
        .as_array()
        .ok_or("hwids must be a JSON array of byte arrays")?;
    if entries.is_empty() {
        return Err("no trusted device was named".into());
    }
    let mut hwids = Vec::with_capacity(entries.len());
    for entry in entries {
        let bytes = entry
            .as_array()
            .ok_or("each hwid must be an array of bytes")?;
        if bytes.is_empty() || bytes.len() > MAX_HWID_BYTES {
            return Err("each hwid must be a non-empty byte array within bounds".into());
        }
        let mut hwid = Vec::with_capacity(bytes.len());
        for byte in bytes {
            let value = byte
                .as_u64()
                .filter(|value| *value <= u64::from(u8::MAX))
                .ok_or("hwid bytes must be integers 0..=255")?;
            hwid.push(value as u8);
        }
        hwids.push(hwid);
    }
    Ok(hwids)
}

/// Revokes the named trusted devices. An unreadable or empty list is refused,
/// never treated as "clear everything".
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_two_factor_remove_trusted_devices(hwids_json: String) -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::TwoFactorRemoveTrustedDevices(hwids_json))
}

/// Revokes every trusted device.
#[napi(ts_return_type = "Promise<string>")]
pub fn controlled_two_factor_clear_trusted_devices() -> AsyncTask<SecurityWork> {
    admit_security(SecurityOp::TwoFactorClearTrustedDevices)
}
