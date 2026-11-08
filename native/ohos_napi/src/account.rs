//! Worker-only OHOS adapter over the shared official-account service.
//!
//! `service` owns all public JSON, OIDC, credentials and cloud mutations. This
//! bridge only admits the environment/consent/private root, resolves the native
//! native-committed authority and dispatches the ten frozen JS entry points. No
//! credential-bearing snapshot or OIDC auth_body is requested or filtered here.
use super::{
    app_context::{account_admitted, admit_account, AccountGrant},
    app_profile::{load_saved_binding, SavedBinding},
    app_storage::store_dir,
};
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task},
    Env,
};
use rd_engine::official_account::service::{self, Admission};
use serde_json::{json, Map, Value};

const MAX_RECEIPT_BYTES: usize = 512;
const MAX_PROVIDER_BYTES: usize = 1024;
const MAX_BOOK_ID_BYTES: usize = 64;
const MAX_PROFILE_BYTES: usize = 16 * 1024;
const MAX_MUTATION_BYTES: usize = 256 * 1024;

/// Called with APP held only for withdrawn consent, detach or destroy. A normal
/// browser foreground/background transition keeps the admitted OAuth attempt.
pub(super) fn revoke_after_lifecycle_fence() {
    service::revoke_pending();
}

struct Failure {
    code: &'static str,
    message: String,
    sent: Option<bool>,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), sent: None }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid", message)
    }

    fn document(&self) -> String {
        let mut value = json!({ "ok": false, "code": self.code, "error": self.message });
        if let Some(sent) = self.sent { value["sent"] = json!(sent); }
        value.to_string()
    }
}

fn text(label: &str, value: String, max: usize) -> Result<String, Failure> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Failure::invalid(format!("{label} is empty, too large or has control characters")));
    }
    Ok(value)
}

fn opaque(label: &str, value: String) -> Result<String, Failure> {
    let value = text(label, value, MAX_RECEIPT_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(Failure::invalid(format!("{label} carries whitespace")));
    }
    Ok(value)
}

fn optional_string(map: &Map<String, Value>, key: &str) -> Result<Option<String>, Failure> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Failure::invalid(format!("{key} must be a string"))),
    }
}

struct Requested {
    mode: String,
    revision: u64,
    id_server: Option<String>,
    api_server: Option<String>,
}

fn parse_requested(approved: &str) -> Result<Option<Requested>, Failure> {
    if approved.is_empty() { return Ok(None); }
    if approved.len() > MAX_PROFILE_BYTES {
        return Err(Failure::invalid("The server profile is too large"));
    }
    let value: Value = serde_json::from_str(approved)
        .map_err(|_| Failure::invalid("The server profile is not valid JSON"))?;
    let map = value.as_object().ok_or_else(|| Failure::invalid("The server profile must be an object"))?;
    let mode = map.get("mode").and_then(Value::as_str)
        .ok_or_else(|| Failure::invalid("The server profile requires a string mode"))?.to_owned();
    let revision = match map.get("revision") {
        None => 0,
        Some(Value::Number(number)) => number.as_u64()
            .ok_or_else(|| Failure::invalid("The server profile revision is invalid"))?,
        Some(Value::String(decimal)) => decimal.parse::<u64>().ok()
            .filter(|revision| revision.to_string() == *decimal)
            .ok_or_else(|| Failure::invalid("The server profile revision is invalid"))?,
        Some(_) => return Err(Failure::invalid("The server profile revision is invalid")),
    };
    Ok(Some(Requested {
        mode, revision,
        id_server: optional_string(map, "idServer")?,
        api_server: optional_string(map, "apiServer")?,
    }))
}

/// A JS profile may only confirm the current native approval. It never supplies
/// a route. An unset custom API is forwarded as custom to the core, which fences
/// the old account and reports unsupported; it must not leave an official bind.
fn authoritative(saved: Option<SavedBinding>, requested: Option<Requested>) -> Result<String, Failure> {
    let Some(saved) = saved else {
        if requested.as_ref().is_some_and(|request| request.mode != "official" || request.revision != 0) {
            return Err(Failure::new("profile-unapproved", "No server profile has been saved natively"));
        }
        return Ok(String::new());
    };
    if let Some(request) = requested {
        if request.mode != saved.mode || request.revision != saved.revision
            || request.id_server.as_ref().is_some_and(|id| *id != saved.id_server)
            || request.api_server.as_ref().is_some_and(|api| *api != saved.api_server)
        {
            return Err(Failure::new("profile-mismatch", "The supplied profile is not the saved, approved profile"));
        }
    }
    Ok(json!({
        "mode": saved.mode, "profileRevision": saved.revision,
        "idServer": saved.id_server, "apiServer": saved.api_server, "key": saved.key,
        "keyKind": saved.key_kind,
    }).to_string())
}

fn bind(admitted: &Admitted, approved: &str) -> Result<String, Failure> {
    if !admitted.admission.is_current() {
        return Err(Failure::new("revoked", "The account work was revoked"));
    }
    let requested = parse_requested(approved)?;
    let dir = store_dir(&admitted.grant.store_scope()).map_err(|error| Failure::new("not-ready", error))?;
    // Read-only projection: public Key plus kind, never an Asset lookup or save.
    let saved = load_saved_binding(&dir).map_err(|error| Failure::new("profile-unreadable", error))?;
    let target = authoritative(saved, requested)?;
    Ok(service::bind_server(admitted.admission, &target))
}

enum Operation {
    Bind { approved: String },
    Snapshot,
    Providers,
    OidcStart { receipt: String, provider_id: String, remember_me: bool },
    OidcResult { attempt: String },
    OidcCancel { attempt: String },
    Logout { receipt: String },
    CloudList { receipt: String },
    CloudLoad { receipt: String, book_id: String },
    CloudMutate { receipt: String, book_id: String, mutation_json: String },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate { Data, Effect }

impl Operation {
    fn gate(&self) -> Gate {
        match self {
            Self::Bind { .. } | Self::OidcCancel { .. } | Self::Logout { .. }
                | Self::CloudMutate { .. } => Gate::Effect,
            _ => Gate::Data,
        }
    }
}

struct Admitted {
    grant: AccountGrant,
    admission: Admission,
}

fn run(admitted: &Admitted, operation: Operation) -> Result<String, Failure> {
    let admission = admitted.admission;
    Ok(match operation {
        Operation::Bind { approved } => return bind(admitted, &approved),
        Operation::Snapshot => service::snapshot(admission),
        Operation::Providers => service::providers(admission),
        Operation::OidcStart { receipt, provider_id, remember_me } =>
            service::oidc_start(admission, &receipt, &provider_id, remember_me),
        Operation::OidcResult { attempt } => service::oidc_result(admission, &attempt),
        Operation::OidcCancel { attempt } => service::oidc_cancel(&attempt),
        Operation::Logout { receipt } => service::logout(admission, &receipt),
        Operation::CloudList { receipt } => service::cloud_list(admission, &receipt),
        Operation::CloudLoad { receipt, book_id } => service::cloud_load(admission, &receipt, &book_id),
        Operation::CloudMutate { receipt, book_id, mutation_json } =>
            service::cloud_mutate(admission, &receipt, &book_id, &mutation_json),
    })
}

pub struct AccountTask {
    admitted: Option<Admitted>,
    operation: Option<Operation>,
    gate: Gate,
    error: Option<Failure>,
}

pub struct AccountOutput { document: String }

fn build(env: &Env, mutation: bool, parsed: Result<Operation, Failure>) -> AsyncTask<AccountTask> {
    let admitted = parsed.and_then(|operation| {
        admit_account(env.raw() as usize, Admission::capture)
            .map(|(grant, admission)| (Admitted { grant, admission }, operation))
            .map_err(|error| Failure::new("not-ready", error))
    });
    AsyncTask::new(match admitted {
        Ok((admitted, operation)) => AccountTask {
            gate: operation.gate(), admitted: Some(admitted), operation: Some(operation), error: None,
        },
        Err(mut error) => {
            if mutation { error.sent = Some(false); }
            AccountTask { admitted: None, operation: None, gate: Gate::Effect, error: Some(error) }
        }
    })
}

impl Task for AccountTask {
    type Output = AccountOutput;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<AccountOutput> {
        let outcome = match (self.admitted.as_ref(), self.operation.take()) {
            (Some(admitted), Some(operation)) => run(admitted, operation),
            _ => Err(self.error.take().unwrap_or_else(|| Failure::new("not-ready", "The account operation was not admitted"))),
        };
        Ok(AccountOutput { document: outcome.unwrap_or_else(|failure| failure.document()) })
    }

    fn resolve(&mut self, env: Env, output: AccountOutput) -> napi_ohos::Result<String> {
        if let (Some(admitted), Gate::Data) = (&self.admitted, self.gate) {
            if !admitted.admission.is_current() || account_admitted(env.raw() as usize).is_err() {
                return Ok(Failure::new("revoked", "The account answer was revoked before resolution").document());
            }
        }
        // Effects report what actually happened. Revocation cannot un-send a
        // mutation, and must not turn its sent=true into a false cancellation.
        Ok(output.document)
    }
}

/// Returns `{ok, mode, profileRevision:number, sessionRetained}`.
#[napi(ts_return_type = "Promise<string>")]
pub fn account_bind_server(env: Env, approved_profile_json: String) -> AsyncTask<AccountTask> {
    build(&env, false, Ok(Operation::Bind { approved: approved_profile_json }))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn account_snapshot(env: Env) -> AsyncTask<AccountTask> {
    build(&env, false, Ok(Operation::Snapshot))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn account_providers(env: Env) -> AsyncTask<AccountTask> {
    build(&env, false, Ok(Operation::Providers))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn account_oidc_start(env: Env, receipt: String, provider_id: String, remember_me: bool) -> AsyncTask<AccountTask> {
    let parsed = opaque("receipt", receipt).and_then(|receipt| Ok(Operation::OidcStart {
        receipt, provider_id: text("providerId", provider_id, MAX_PROVIDER_BYTES)?, remember_me,
    }));
    build(&env, false, parsed)
}

#[napi(ts_return_type = "Promise<string>")]
pub fn account_oidc_result(env: Env, attempt_receipt: String) -> AsyncTask<AccountTask> {
    build(&env, false, opaque("attemptReceipt", attempt_receipt).map(|attempt| Operation::OidcResult { attempt }))
}

/// Cancels only this attempt. Returns `{ok, cancelled, attemptReceipt}`.
#[napi(ts_return_type = "Promise<string>")]
pub fn account_oidc_cancel(env: Env, attempt_receipt: String) -> AsyncTask<AccountTask> {
    build(&env, false, opaque("attemptReceipt", attempt_receipt).map(|attempt| Operation::OidcCancel { attempt }))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn account_logout(env: Env, receipt: String) -> AsyncTask<AccountTask> {
    build(&env, false, opaque("receipt", receipt).map(|receipt| Operation::Logout { receipt }))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn cloud_address_book_list(env: Env, receipt: String) -> AsyncTask<AccountTask> {
    build(&env, false, opaque("receipt", receipt).map(|receipt| Operation::CloudList { receipt }))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn cloud_address_book_load(env: Env, receipt: String, book_id: String) -> AsyncTask<AccountTask> {
    let parsed = opaque("receipt", receipt).and_then(|receipt| Ok(Operation::CloudLoad {
        receipt, book_id: text("bookId", book_id, MAX_BOOK_ID_BYTES)?,
    }));
    build(&env, false, parsed)
}

#[napi(ts_return_type = "Promise<string>")]
pub fn cloud_address_book_mutate(env: Env, receipt: String, book_id: String, mutation_json: String) -> AsyncTask<AccountTask> {
    let parsed = opaque("receipt", receipt).and_then(|receipt| Ok(Operation::CloudMutate {
        receipt, book_id: text("bookId", book_id, MAX_BOOK_ID_BYTES)?,
        mutation_json: text("mutation", mutation_json, MAX_MUTATION_BYTES)?,
    }));
    build(&env, true, parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(api: &str) -> SavedBinding {
        SavedBinding { revision: 3, mode: "custom", id_server: "id.example.test:21116".to_owned(),
            api_server: api.to_owned(), key: "public-key".to_owned(), key_kind: "public" }
    }

    #[test]
    fn binding_uses_the_native_approval_not_the_supplied_route() {
        assert_eq!(authoritative(None, None).expect("official default"), "");
        let forged = parse_requested(r#"{"mode":"custom","revision":3,"apiServer":"https://other.example"}"#).expect("request");
        assert_eq!(authoritative(Some(saved("https://api.example")), forged).err().map(|failure| failure.code), Some("profile-mismatch"));
        let unapproved = parse_requested(r#"{"mode":"custom","revision":3}"#).expect("request");
        assert_eq!(authoritative(None, unapproved).err().map(|failure| failure.code), Some("profile-unapproved"));
    }

    #[test]
    fn custom_without_api_is_forwarded_as_custom_never_official() {
        let target: Value = serde_json::from_str(&authoritative(Some(saved("")), None).expect("native target")).expect("JSON");
        assert_eq!(target["mode"], "custom");
        assert_eq!(target["apiServer"], "");
        assert_eq!(target["profileRevision"], 3);
    }
}
