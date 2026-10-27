//! Private OHOS bootstrap and the app-scoped adapter over the official LAN owner.
//!
//! Export reception performs memory-only admission/cancellation. File access,
//! queries and completion waits run in napi AsyncTask workers, never under the
//! session registry or the app metadata lock. No scanner or Tokio runtime here.
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task},
    Env,
};
use rd_engine::lan::{self, LanCompletion, LanNotice, LanOwner, LanSnapshot};
use serde_json::{json, Value};
use std::{
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

#[derive(Clone, Copy)]
struct Ticket {
    environment: usize,
    epoch: u64,
}

#[derive(Clone)]
struct Discovery {
    owner: Arc<LanOwner>,
    revision: Arc<AtomicU64>,
    action: u64,
}

#[derive(Clone)]
struct Retirement {
    owner: Arc<LanOwner>,
    completion: LanCompletion,
}

struct AppContext {
    environment: Option<usize>,
    epoch: u64,
    privacy_accepted: bool,
    foreground: bool,
    // Reserved before any lazy Config access; never reset, including on failure
    // or environment teardown. Only EntryAbility.context.filesDir supplies it.
    root: Option<PathBuf>,
    local_id: Option<String>,
    discovery: Option<Discovery>,
    retiring: Option<Retirement>,
}

static APP: Mutex<AppContext> = Mutex::new(AppContext {
    environment: None,
    epoch: 1,
    privacy_accepted: false,
    foreground: false,
    root: None,
    local_id: None,
    discovery: None,
    retiring: None,
});

// Separate serialization boundary: may be held over bootstrap I/O, never over
// a join and never while holding APP. Same-root callers share its actual result.
static INITIALIZED: Mutex<Option<Result<String, String>>> = Mutex::new(None);

fn app() -> Result<MutexGuard<'static, AppContext>, String> {
    APP.lock()
        .map_err(|_| "native app metadata is unavailable".to_string())
}

impl AppContext {
    fn ticket(&self) -> Result<Ticket, String> {
        Ok(Ticket {
            environment: self
                .environment
                .ok_or_else(|| "native environment is not attached".to_string())?,
            epoch: self.epoch,
        })
    }

    fn check(&self, ticket: Ticket) -> Result<(), String> {
        if self.environment != Some(ticket.environment) || self.epoch != ticket.epoch {
            return Err("stale native app generation".to_string());
        }
        Ok(())
    }

    fn allowed(&self) -> bool {
        self.privacy_accepted && self.foreground && self.local_id.is_some()
    }

    fn require_allowed(&self) -> Result<(), String> {
        if !self.privacy_accepted {
            return Err("privacy consent is not current".to_string());
        }
        if !self.foreground {
            return Err(
                "application discovery/routing admission is not in the foreground".to_string(),
            );
        }
        if self.local_id.is_none() {
            return Err("native private storage is not ready".to_string());
        }
        Ok(())
    }

    fn advance(&mut self) -> Result<(), String> {
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| "native app generation exhausted".to_string())?;
        Ok(())
    }

    fn retire(&mut self) {
        if let Some(discovery) = self.discovery.take() {
            let completion = discovery.owner.request_close();
            self.retiring = Some(Retirement {
                owner: discovery.owner,
                completion,
            });
        }
    }
}

fn attach_environment(env: &Env, state: &mut AppContext) -> Result<(), String> {
    let environment = env.raw() as usize;
    match state.environment {
        Some(current) if current == environment => return Ok(()),
        Some(_) => return Err("another native environment owns the app lifecycle".to_string()),
        None => {}
    }
    // napi-ohos 1.2.0 Env::add_env_cleanup_hook / OHOS Node-API. The hook
    // cancels but never joins on the environment thread. The core owns its
    // retirement even if no JS promise survives to observe the receipt.
    env.add_env_cleanup_hook(environment, detach_environment)
        .map_err(|error| format!("cannot attach native environment cleanup: {error}"))?;
    state.advance()?;
    state.environment = Some(environment);
    Ok(())
}

fn detach_environment(environment: usize) {
    let mut state = APP.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if state.environment != Some(environment) {
        return;
    }
    state.privacy_accepted = false;
    state.foreground = false;
    // Clearing the environment is itself a fence even if the counter is spent.
    state.environment = None;
    let _ = state.advance();
    state.retire();
}

fn error_text(previous: Option<String>, next: String) -> String {
    match previous {
        Some(previous) if previous != next => format!("{previous}; {next}"),
        Some(previous) => previous,
        None => next,
    }
}

fn failed_lifecycle(error: String) -> Value {
    json!({ "ok": false, "ownerGeneration": "", "ready": false,
        "discoveryAllowed": false, "error": error })
}

fn lifecycle_reply(state: &AppContext, error: Option<String>) -> Value {
    let mut value = json!({
        "ok": error.is_none(),
        "ownerGeneration": state.discovery.as_ref()
            .map(|discovery| discovery.owner.generation().to_string()).unwrap_or_default(),
        "ready": state.local_id.is_some(),
        "discoveryAllowed": state.allowed() && state.discovery.is_some(),
    });
    if let Some(error) = error {
        value["error"] = Value::String(error);
    }
    value
}

fn fixed_root(files_dir: &str) -> Result<PathBuf, String> {
    let root = Path::new(files_dir);
    if !root.is_absolute()
        || files_dir.contains('\0')
        || !root
            .components()
            .any(|part| matches!(part, Component::Normal(_)))
        || root
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("filesDir must be the absolute private Context directory".to_string());
    }
    Ok(root.to_path_buf())
}

#[cfg(target_env = "ohos")]
fn initialize_private_root(root: &Path) -> Result<String, String> {
    use hbb_common::{
        config::{Config, APP_DIR, APP_HOME_DIR},
        sodiumoxide,
    };
    let canonical = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve filesDir: {error}"))?;
    if !canonical.is_dir() {
        return Err("filesDir is not a directory".to_string());
    }
    let config_dir = canonical.join("rustdesk");
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| format!("cannot prepare private RustDesk directory: {error}"))?;
    let config_dir = config_dir
        .canonicalize()
        .map_err(|error| format!("cannot resolve private RustDesk directory: {error}"))?;
    if config_dir.parent() != Some(canonical.as_path()) {
        return Err("RustDesk configuration directory leaves the fixed private root".to_string());
    }
    let home = canonical
        .to_str()
        .ok_or_else(|| "filesDir is not UTF-8".to_string())?;
    let config = config_dir
        .to_str()
        .ok_or_else(|| "configuration directory is not UTF-8".to_string())?;
    // Both globals are installed before the first lazy Config/get_id access.
    *APP_DIR
        .write()
        .map_err(|_| "Config path lock is unavailable".to_string())? = config.to_owned();
    *APP_HOME_DIR
        .write()
        .map_err(|_| "Config home lock is unavailable".to_string())? = home.to_owned();
    sodiumoxide::init().map_err(|_| "crypto initialization failed".to_string())?;
    let id = Config::get_id();
    if id.is_empty() {
        return Err("official Config did not produce a local ID".to_string());
    }
    // Official Config's store is void/log-only: this is an in-memory identity,
    // not proof of durable storage or of hbbs registration.
    Ok(id)
}

#[cfg(not(target_env = "ohos"))]
fn initialize_private_root(_root: &Path) -> Result<String, String> {
    // Do not accidentally initialize desktop Config paths when this OHOS-only
    // crate is inspected/compiled on a host platform.
    Err("private native bootstrap is supported only on HarmonyOS".to_string())
}

fn bootstrap_result(ticket: Ticket, root: Option<&Path>) -> Result<Option<String>, String> {
    let mut initialized = INITIALIZED
        .lock()
        .map_err(|_| "private initialization did not complete safely".to_string())?;
    {
        let state = app()?;
        state.check(ticket)?;
        if root.is_some() && (!state.privacy_accepted || !state.foreground) {
            return Err("private initialization requires current foreground consent".to_string());
        }
    }
    if initialized.is_none() {
        if let Some(root) = root {
            // One admitted initialization may finish after revocation. Its
            // result is retained, but only a current task may publish ready.
            *initialized = Some(
                std::panic::catch_unwind(|| initialize_private_root(root)).unwrap_or_else(|_| {
                    Err("official private Config initialization panicked".to_string())
                }),
            );
        }
    }
    match initialized.as_ref() {
        Some(Ok(id)) => Ok(Some(id.clone())),
        Some(Err(error)) => Err(error.clone()),
        None => Ok(None),
    }
}

fn finish_retirement(retirement: &Retirement) -> Result<(), String> {
    let result = retirement.completion.wait_blocking();
    // Never hold APP, SESSIONS or an initializer lock while joining.
    let mut state = match app() {
        Ok(state) => state,
        Err(error) => return Err(error_text(result.err(), error)),
    };
    if state
        .retiring
        .as_ref()
        .is_some_and(|current| current.owner.generation() == retirement.owner.generation())
    {
        state.retiring = None;
    }
    result
}

fn prepare_discovery(state: &mut AppContext) -> Result<(), String> {
    if !state.allowed() || state.discovery.is_some() {
        return Ok(());
    }
    if state.retiring.is_some() {
        return Err("previous discovery owner is still closing".to_string());
    }
    let id = state
        .local_id
        .as_ref()
        .ok_or_else(|| "local identity is not ready".to_string())?;
    let revision = Arc::new(AtomicU64::new(0));
    let notice_revision = revision.clone();
    // Lock-free invalidation only: this never queries, waits or calls into JS.
    let notifier: Arc<dyn Fn(LanNotice) + Send + Sync> = Arc::new(move |notice| {
        notice_revision.fetch_max(notice.cache_revision, Ordering::AcqRel);
    });
    let owner = lan::acquire_initialized_owner(id.clone(), Some(notifier))?;
    state.discovery = Some(Discovery {
        owner,
        revision,
        action: 1,
    });
    Ok(())
}

pub struct AppWork {
    ticket: Option<Ticket>,
    retirement: Option<Retirement>,
    root: Option<PathBuf>,
    error: Option<String>,
}

impl AppWork {
    fn refused(error: String) -> Self {
        Self {
            ticket: None,
            retirement: None,
            root: None,
            error: Some(error),
        }
    }

    fn run(&self) -> Value {
        let mut failure = self.error.clone();
        if let Some(retirement) = &self.retirement {
            if let Err(error) = finish_retirement(retirement) {
                failure = Some(error_text(failure, error));
            }
        }
        let Some(ticket) = self.ticket else {
            return failed_lifecycle(
                failure.unwrap_or_else(|| "native lifecycle was not admitted".to_string()),
            );
        };
        // Also waits for already-admitted bootstrap I/O to leave its private
        // serialization boundary. Revocation needs no consent to await cleanup.
        let initialized = match bootstrap_result(ticket, self.root.as_deref()) {
            Ok(id) => id,
            Err(error) => {
                failure = Some(error_text(failure, error));
                None
            }
        };
        let mut state = match app() {
            Ok(state) => state,
            Err(error) => return failed_lifecycle(error_text(failure, error)),
        };
        if let Err(error) = state.check(ticket) {
            return failed_lifecycle(error_text(failure, error));
        }
        if let Some(id) = initialized {
            state.local_id = Some(id);
        }
        if failure.is_none() {
            if let Err(error) = prepare_discovery(&mut state) {
                failure = Some(error);
            }
        }
        lifecycle_reply(&state, failure)
    }
}

impl Task for AppWork {
    type Output = Value;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<Value> {
        Ok(self.run())
    }

    fn resolve(&mut self, _env: Env, output: Value) -> napi_ohos::Result<String> {
        if self.ticket.is_none() {
            return Ok(output.to_string());
        }
        let checked = self
            .ticket
            .ok_or_else(|| "native lifecycle was not admitted".to_string())
            .and_then(|ticket| {
                let state = app()?;
                state.check(ticket)?;
                let current = state
                    .discovery
                    .as_ref()
                    .map(|discovery| discovery.owner.generation().to_string())
                    .unwrap_or_default();
                if output.get("ownerGeneration").and_then(Value::as_str) != Some(current.as_str()) {
                    return Err("stale discovery owner at lifecycle resolution".to_string());
                }
                Ok(())
            });
        if let Err(error) = checked {
            let previous = output
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned);
            return Ok(failed_lifecycle(error_text(previous, error)).to_string());
        }
        Ok(output.to_string())
    }
}

/// Every lifecycle update fences synchronously before its AsyncTask is queued,
/// including a same-state privacy reread. No previous owner/scan is adopted.
#[napi(ts_return_type = "Promise<string>")]
pub fn app_set_lifecycle(env: Env, privacy_accepted: bool, foreground: bool) -> AsyncTask<AppWork> {
    let admitted = (|| -> Result<AppWork, String> {
        let mut state = app()?;
        attach_environment(&env, &mut state)?;
        // Fence before changing facts or returning the promise. Even a repeated
        // true/true refresh has a fresh idle owner once retirement completes.
        state.privacy_accepted = false;
        state.foreground = false;
        state.advance()?;
        state.retire();
        state.privacy_accepted = privacy_accepted;
        state.foreground = foreground;
        Ok(AppWork {
            ticket: Some(state.ticket()?),
            retirement: state.retiring.clone(),
            root: None,
            error: None,
        })
    })();
    AsyncTask::new(admitted.unwrap_or_else(AppWork::refused))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn app_init(env: Env, files_dir: String) -> AsyncTask<AppWork> {
    let admitted = (|| -> Result<AppWork, String> {
        let root = fixed_root(&files_dir)?;
        let mut state = app()?;
        attach_environment(&env, &mut state)?;
        if !state.privacy_accepted || !state.foreground {
            return Err("private initialization requires current foreground consent".to_string());
        }
        match &state.root {
            Some(reserved) if reserved != &root => {
                return Err("native private root is already fixed".to_string())
            }
            Some(_) => {}
            None => state.root = Some(root.clone()),
        }
        Ok(AppWork {
            ticket: Some(state.ticket()?),
            retirement: state.retiring.clone(),
            root: Some(root),
            error: None,
        })
    })();
    AsyncTask::new(admitted.unwrap_or_else(AppWork::refused))
}

/// No Config I/O from sessionAdd/start. The ID is captured with the same app
/// generation as the approved immutable route, and cannot outlive revocation.
pub(super) struct IdAdmission {
    ticket: Ticket,
    pub(super) local_id: String,
}

pub(super) fn id_admission() -> Result<IdAdmission, String> {
    let state = app()?;
    state.require_allowed()?;
    Ok(IdAdmission {
        ticket: state.ticket()?,
        local_id: state
            .local_id
            .clone()
            .ok_or_else(|| "local ID is not ready".to_string())?,
    })
}

pub(super) struct IdAdmissionGuard {
    _state: MutexGuard<'static, AppContext>,
}

pub(super) fn hold_id_admission(admission: &IdAdmission) -> Result<IdAdmissionGuard, String> {
    let state = app()?;
    state.check(admission.ticket)?;
    state.require_allowed()?;
    // Held only while registering/starting an owned route, never while doing
    // Config/LanPeers I/O, waiting for cleanup or acquiring INITIALIZED.
    Ok(IdAdmissionGuard { _state: state })
}

struct LanTicket {
    app: Ticket,
    discovery: Discovery,
    scan: Option<u64>,
}

enum LanCommand {
    Start,
    Query,
    Stop,
    Remove(String),
}

pub struct LanWork {
    ticket: Option<LanTicket>,
    owner_generation: String,
    scan_id: String,
    completion: Option<LanCompletion>,
    error: Option<String>,
}

pub struct LanOutput {
    document: String,
    revision: u64,
    terminal: Option<String>,
    error: Option<String>,
}

fn token(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|number| *number != 0 && number.to_string() == value)
        .ok_or_else(|| "invalid decimal native generation/scan token".to_string())
}

fn scan_token(value: &str) -> Result<Option<u64>, String> {
    if value.is_empty() {
        Ok(None)
    } else {
        token(value).map(Some)
    }
}

impl LanWork {
    fn refused(owner_generation: String, scan_id: String, error: String) -> Self {
        Self {
            ticket: None,
            owner_generation,
            scan_id,
            completion: None,
            error: Some(error),
        }
    }

    fn failure(&self, error: String) -> Value {
        // Rejected admission MUST NOT query the cache to decorate an error.
        // This is a closed admission, not a successful empty discovery result.
        json!({ "ok": false, "ownerGeneration": self.owner_generation,
            "scanId": self.scan_id, "revision": "0", "state": "closed",
            "peers": [], "error": error })
    }

    fn check(&self) -> Result<&LanTicket, String> {
        let ticket = self
            .ticket
            .as_ref()
            .ok_or_else(|| "LAN command was not admitted".to_string())?;
        let state = app()?;
        state.check(ticket.app)?;
        state.require_allowed()?;
        let current = state
            .discovery
            .as_ref()
            .ok_or_else(|| "discovery owner is closed".to_string())?;
        if current.owner.generation() != ticket.discovery.owner.generation()
            || current.action != ticket.discovery.action
            || current.owner.scan_id() != ticket.scan
        {
            return Err("stale discovery owner/scan/command".to_string());
        }
        Ok(ticket)
    }

    fn run(&self) -> Value {
        let mut failure = self.error.clone();
        if let Some(completion) = &self.completion {
            // Already-admitted stop/remove cleanup continues even after a
            // lifecycle fence or after JS abandons this promise.
            if let Err(error) = completion.wait_blocking() {
                failure = Some(error_text(failure, error));
            }
        }
        let ticket = match self.check() {
            Ok(ticket) => ticket,
            Err(error) => return self.failure(error_text(failure, error)),
        };
        match ticket.discovery.owner.query_blocking() {
            Ok(snapshot) => self.snapshot(snapshot, failure),
            Err(error) => self.failure(error_text(failure, error)),
        }
    }

    fn snapshot(&self, snapshot: LanSnapshot, failure: Option<String>) -> Value {
        let Some(ticket) = &self.ticket else {
            return self.failure("LAN snapshot has no admitted owner".to_string());
        };
        let failure = match snapshot.error {
            Some(error) => Some(error_text(failure, error)),
            None => failure,
        };
        if snapshot.owner_generation != ticket.discovery.owner.generation()
            || snapshot.scan_id != ticket.scan
        {
            let mut value = self.failure(error_text(
                failure,
                "stale core snapshot identity".to_string(),
            ));
            if let Some(terminal) = snapshot.terminal {
                value["terminal"] = json!(terminal);
            }
            return value;
        }
        let mut value = json!({
            "ok": failure.is_none(),
            "ownerGeneration": snapshot.owner_generation.to_string(),
            "scanId": snapshot.scan_id.map(|scan| scan.to_string()).unwrap_or_default(),
            "revision": snapshot.cache_revision.to_string(),
            "state": snapshot.state,
            "peers": snapshot.peers,
        });
        if let Some(terminal) = snapshot.terminal {
            value["terminal"] = json!(terminal);
        }
        if let Some(error) = failure {
            value["error"] = json!(error);
        }
        value
    }
}

fn admit_lan(env: Env, owner_generation: String, scan_id: String, command: LanCommand) -> LanWork {
    let admitted = (|| -> Result<LanWork, String> {
        let generation = token(&owner_generation)?;
        let expected_scan = scan_token(&scan_id)?;
        let mut state = app()?;
        if state.environment != Some(env.raw() as usize) {
            return Err("native environment does not own discovery".to_string());
        }
        state.require_allowed()?;
        let app_ticket = state.ticket()?;
        let discovery = state
            .discovery
            .as_mut()
            .ok_or_else(|| "discovery owner is not ready".to_string())?;
        if discovery.owner.generation() != generation {
            return Err("stale discovery owner generation".to_string());
        }
        if !matches!(&command, LanCommand::Start) && discovery.owner.scan_id() != expected_scan {
            return Err("stale discovery scan token".to_string());
        }
        let next_action = discovery
            .action
            .checked_add(1)
            .ok_or_else(|| "discovery command generation exhausted".to_string())?;
        let mut completion = None;
        let mut error = None;
        let mut scan = discovery.owner.scan_id();
        match command {
            LanCommand::Start => match discovery.owner.start() {
                Ok(start) => {
                    scan = Some(start.scan_id);
                    if start.started {
                        discovery.action = next_action;
                    }
                }
                Err(failure) => error = Some(failure),
            },
            LanCommand::Query => {}
            LanCommand::Stop => {
                let scan = expected_scan.ok_or_else(|| "stop requires a scan token".to_string())?;
                match discovery.owner.request_stop(scan) {
                    Ok(receipt) => {
                        completion = Some(receipt);
                        discovery.action = next_action;
                    }
                    Err(failure) => error = Some(failure),
                }
            }
            LanCommand::Remove(id) => match discovery.owner.request_remove(expected_scan, id) {
                Ok(receipt) => {
                    completion = Some(receipt);
                    discovery.action = next_action;
                }
                Err(failure) => error = Some(failure),
            },
        }
        Ok(LanWork {
            ticket: Some(LanTicket {
                app: app_ticket,
                discovery: discovery.clone(),
                scan,
            }),
            owner_generation: owner_generation.clone(),
            scan_id: scan.map(|scan| scan.to_string()).unwrap_or_default(),
            completion,
            error,
        })
    })();
    admitted.unwrap_or_else(|error| LanWork::refused(owner_generation, scan_id, error))
}

impl Task for LanWork {
    type Output = LanOutput;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<LanOutput> {
        let output = self.run();
        // The official list is unbounded. Serialize and release its Value tree
        // on this worker; resolve only checks small immutable receipt metadata.
        Ok(LanOutput {
            revision: output
                .get("revision")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0),
            terminal: output
                .get("terminal")
                .and_then(Value::as_str)
                .map(str::to_owned),
            error: output
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned),
            document: output.to_string(),
        })
    }

    fn resolve(&mut self, _env: Env, output: LanOutput) -> napi_ohos::Result<String> {
        if self.ticket.is_none() {
            return Ok(output.document);
        }
        let checked = self.check().and_then(|ticket| {
            if output.revision < ticket.discovery.revision.load(Ordering::Acquire) {
                return Err("stale LAN cache revision at promise resolution".to_string());
            }
            Ok(())
        });
        if let Err(error) = checked {
            let mut refused = self.failure(error_text(output.error, error));
            if let Some(terminal) = output.terminal {
                refused["terminal"] = json!(terminal);
            }
            return Ok(refused.to_string());
        }
        Ok(output.document)
    }
}

#[napi(ts_return_type = "Promise<string>")]
pub fn lan_scan_start(env: Env, owner_generation: String) -> AsyncTask<LanWork> {
    AsyncTask::new(admit_lan(
        env,
        owner_generation,
        String::new(),
        LanCommand::Start,
    ))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn lan_peers_query(
    env: Env,
    owner_generation: String,
    expected_scan_id: String,
) -> AsyncTask<LanWork> {
    AsyncTask::new(admit_lan(
        env,
        owner_generation,
        expected_scan_id,
        LanCommand::Query,
    ))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn lan_scan_stop(env: Env, owner_generation: String, scan_id: String) -> AsyncTask<LanWork> {
    AsyncTask::new(admit_lan(env, owner_generation, scan_id, LanCommand::Stop))
}

#[napi(ts_return_type = "Promise<string>")]
pub fn lan_peer_remove(
    env: Env,
    owner_generation: String,
    expected_scan_id: String,
    claimed_id: String,
) -> AsyncTask<LanWork> {
    AsyncTask::new(admit_lan(
        env,
        owner_generation,
        expected_scan_id,
        LanCommand::Remove(claimed_id),
    ))
}
