//! Official Windows main/--cm adapter. The main process alone initializes the
//! engine controller; CM has only an authenticated, bounded IPC projection.
//! Client JSON/event vocabulary: pinned RustDesk 092a961b629d318fe290eeafac0cd214a1e9deeb
//! src/ui_cm_interface.rs::Client and src/flutter.rs::InvokeUiCM (AGPL-3.0-only).
//! No media/input owner, password generator, or second Tokio runtime lives here.
mod windows;

use anyhow::{bail, ensure, Context, Result};
use flutter_rust_bridge::StreamSink;
use hbb_common::{base64::{engine::general_purpose::STANDARD, Engine as _}, config::LocalConfig, futures::{channel::oneshot, executor::block_on, future::{select, Either}}, sodiumoxide::utils};
pub(crate) use rd_engine::host::control::HostCommand;
use rd_engine::host::control::{ActivitySnapshot, HostController, HostReply, PeerSnapshot, ServiceSnapshot};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{HashMap, HashSet}, process::{Child, Command, Stdio}, sync::{atomic::{AtomicBool, Ordering}, mpsc::{self, Receiver, SyncSender}, Arc, LazyLock, Mutex, MutexGuard}, thread::JoinHandle, time::{Duration, Instant}};
use windows::{Identity, Pipe};

// The owner-reservation pipe name stays stable across wire versions.
const VERSION: u32 = 3;
const QUEUE: usize = 16;
const MAX_REQUEST_FRAME: usize = 16 * 1024;
const MAX_PEERS: usize = 2048;
const COMMAND_TIMEOUT_MS: u64 = 45_000;
const COMMAND_TIMEOUT: Duration = Duration::from_millis(COMMAND_TIMEOUT_MS);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(200);
const MAX_AGE: Duration = Duration::from_secs(2);

fn new_cm_deadline() -> Result<u64> {
    windows::uptime_ms().checked_add(COMMAND_TIMEOUT_MS).context("CM command uptime deadline unavailable")
}
fn deadline_from_uptime(deadline_uptime_ms: u64) -> Result<Instant> {
    // Take the Instant first: preemption between these samples must not extend
    // the sender's budget. GetTickCount64 is shared by both local processes.
    let base = Instant::now();
    let remaining = deadline_uptime_ms.checked_sub(windows::uptime_ms()).context("CM command expired before admission")?;
    ensure!(remaining > 0 && remaining <= COMMAND_TIMEOUT_MS, "CM command expired or deadline exceeds its budget");
    base.checked_add(Duration::from_millis(remaining)).context("CM command monotonic deadline unavailable")
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> { value.lock().unwrap_or_else(|e| e.into_inner()) }
fn nonzero_nonce() -> u64 {
    loop {
        let mut bytes = [0u8; 8];
        hbb_common::sodiumoxide::randombytes::randombytes_into(&mut bytes);
        let value = u64::from_ne_bytes(bytes);
        if value != 0 { return value; }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessRole { Main, Cm, Other }
// This is the OS process role, frozen once, NOT a Dart isolate's app_type.
// Pinned desktop_multi_window 8b774a66671cbb9bcb2631af6ac28f9bdd469ce3
// windows/flutter_window.cc creates a FlutterViewController in the SAME process;
// its Dart-only `multi_window` arguments must not reset or bypass this owner.
static PROCESS_ROLE: LazyLock<ProcessRole> = LazyLock::new(|| {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--cm") { ProcessRole::Cm }
    else if args.iter().any(|arg| arg == "multi_window" || arg == "--install" || arg == "--server" || arg == "--service") { ProcessRole::Other }
    else { ProcessRole::Main }
});
pub(crate) fn is_cm() -> bool { *PROCESS_ROLE == ProcessRole::Cm }
pub(crate) fn uses_host_options() -> bool { *PROCESS_ROLE != ProcessRole::Other }

enum OwnerCommand { Control(HostCommand), Peer { binding: Binding, action: PeerAction } }
struct OwnerRequest { command: OwnerCommand, deadline: Instant, cancelled: oneshot::Receiver<()>, reply: SyncSender<Result<HostReply>> }
struct Owner {
    controller: Arc<HostController>,
    commands: SyncSender<OwnerRequest>,
    stopping: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
    child: Mutex<Option<Child>>,
    identity: Identity,
    preferences: Mutex<UiPreferences>,
}
// Explicit startup admission is required: getters never run these initializers.
static OWNER: LazyLock<Mutex<Option<std::result::Result<Arc<Owner>, String>>>> = LazyLock::new(|| Mutex::new(None));
static CM: LazyLock<Mutex<Option<std::result::Result<Arc<Cm>, String>>>> = LazyLock::new(|| Mutex::new(None));
static MAIN_INIT_STARTED: AtomicBool = AtomicBool::new(false);
static CM_INIT_STARTED: AtomicBool = AtomicBool::new(false);

// These are observation caches only. Losing the pipe marks an error WITHOUT
// clearing peer/native ownership or turning uncertain cleanup into success.
#[derive(Default)]
struct Projection {
    state: Option<ServiceSnapshot>,
    seen: Option<Instant>,
    failure: Option<String>,
    preferences: Option<UiPreferences>,
    preferences_seen: Option<Instant>,
    high_water: i32,
    sinks: HashMap<String, StreamSink<String>>,
}
static PROJECTION: LazyLock<Mutex<Projection>> = LazyLock::new(|| Mutex::new(Projection::default()));

// Read-only presentation metadata, never an arbitrary LocalConfig map or a CM
// write command. Its revision is independent of the engine's service revision.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiPreferences { theme: String, language: String, revision: u64 }
impl UiPreferences {
    fn initial() -> Result<Self> {
        let preferences = Self { theme: LocalConfig::get_option("theme"), language: LocalConfig::get_option("lang"), revision: 1 };
        preferences.validate()?;
        Ok(preferences)
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.revision != 0 && self.theme.len() <= 128 && self.language.len() <= 128, "invalid CM appearance bounds");
        Ok(())
    }
}
impl Projection {
    fn preferences(&self) -> Result<&UiPreferences> {
        if let Some(error) = &self.failure { bail!("{error}"); }
        ensure!(self.preferences_seen.is_some_and(|at| at.elapsed() <= MAX_AGE), "CM appearance is stale or unavailable");
        self.preferences.as_ref().context("CM appearance has not been synchronized")
    }
}
fn preference_events(sink: &StreamSink<String>, current: &UiPreferences, previous: Option<&UiPreferences>) {
    if previous.map(|value| value.theme.as_str()) != Some(current.theme.as_str()) {
        let _ = sink.add(json!({"name":"theme", "dark":current.theme}).to_string());
    }
    if previous.map(|value| value.language.as_str()) != Some(current.language.as_str()) {
        let _ = sink.add(json!({"name":"language", "lang":current.language}).to_string());
    }
}
fn publish_preferences(preferences: UiPreferences) -> Result<()> {
    preferences.validate()?;
    let mut projection = lock(&PROJECTION);
    if let Some(previous) = &projection.preferences {
        ensure!(preferences.revision >= previous.revision, "CM appearance revision regressed");
        if preferences.revision == previous.revision {
            ensure!(preferences == *previous, "CM appearance revision was reused");
            projection.preferences_seen = Some(Instant::now());
            return Ok(());
        }
    }
    let previous = projection.preferences.replace(preferences);
    projection.preferences_seen = Some(Instant::now());
    // Cache the complete preference revision before a Dart reload can read it.
    if let Some(current) = &projection.preferences {
        for sink in projection.sinks.values() { preference_events(sink, current, previous.as_ref()); }
    }
    Ok(())
}
pub(crate) fn cm_ui_preference(key: &str) -> Result<String> {
    ensure!(is_cm(), "CM appearance projection requires the dedicated process");
    let projection = lock(&PROJECTION);
    let preferences = projection.preferences()?;
    match key {
        "theme" => Ok(preferences.theme.clone()),
        "lang" => Ok(preferences.language.clone()),
        _ => bail!("unsupported CM appearance preference"),
    }
}
pub(crate) fn refresh_ui_preference(key: &str) -> Result<String> {
    let owner = owner()?;
    ensure!(matches!(key, "theme" | "lang"), "unsupported main appearance preference");
    // Main's existing setter remains the sole persistent preference writer.
    // The change notification's payload is not a configuration authority.
    let mut preferences = lock(&owner.preferences);
    let value = LocalConfig::get_option(key);
    ensure!(value.len() <= 128, "main appearance preference exceeds its bounds");
    let previous = if key == "theme" { &preferences.theme } else { &preferences.language };
    if previous != &value {
        let revision = preferences.revision.checked_add(1).context("main appearance revisions exhausted")?;
        if key == "theme" { preferences.theme = value.clone(); } else { preferences.language = value.clone(); }
        preferences.revision = revision;
    }
    Ok(value)
}

fn sanitized(mut state: ServiceSnapshot) -> Result<ServiceSnapshot> {
    ensure!(state.owner_epoch != 0 && state.peers.len() <= MAX_PEERS, "invalid host snapshot bounds");
    crate::configuration::strip_credential_options(&mut state.options);
    // These are not ordinary preferences, even if supplied by an older owner.
    for key in ["temporary-password", "permanent-password", "salt", "uuid", "private-key", "key-pair", "password-hash"] {
        if let Some(value) = state.options.remove(key) { let mut bytes = value.into_bytes(); utils::memzero(&mut bytes); }
    }
    Ok(state)
}
fn client(peer: &PeerSnapshot, owner: u64, revision: u64) -> Value {
    json!({ "id":peer.conn_id, "authorized":peer.authorized, "disconnected":peer.disconnected,
        "is_file_transfer":false, "is_terminal":false, "port_forward":"", "name":peer.name,
        "peer_id":peer.peer_id, "avatar":"", "keyboard":peer.keyboard, "clipboard":false,
        "audio":false, "file":false, "restart":false, "recording":false, "block_input":false,
        "privacy_mode":false, "from_switch":false, "phase":peer.phase, "error":peer.error,
        "owner_epoch":owner.to_string(), "run_epoch":peer.run_epoch.to_string(),
        "connection_token":peer.connection_token.to_string(), "approval_epoch":peer.approval_epoch.map(|x| x.to_string()),
        "policy_revision":peer.policy_revision.to_string(), "revision":revision.to_string() })
}
fn clients(state: &ServiceSnapshot) -> Vec<Value> {
    state.peers.iter().map(|peer| client(peer, state.owner_epoch, state.revision)).collect()
}
fn initial_events(sink: &StreamSink<String>, state: &ServiceSnapshot) {
    // The extra envelope supplies atomic snapshot/revision recovery. Official CM
    // receives its usual dialect as well; every same-ID update is a FULL Client.
    let _ = sink.add(json!({"name":"host_state", "owner_epoch":state.owner_epoch.to_string(), "revision":state.revision.to_string(), "phase":state.phase, "status_num":state.status_num, "error":state.error, "clients":clients(state)}).to_string());
    for peer in &state.peers {
        let _ = sink.add(json!({"name":"add_connection", "client":client(peer, state.owner_epoch, state.revision).to_string()}).to_string());
    }
}
fn publish(state: ServiceSnapshot) -> Result<()> {
    let state = sanitized(state)?;
    let mut projection = lock(&PROJECTION);
    if let Some(old) = &projection.state {
        ensure!(old.owner_epoch == state.owner_epoch, "host owner epoch changed; reopen CM");
        if state.revision < old.revision { return Ok(()); }
        if state.revision == old.revision {
            projection.seen = Some(Instant::now());
            return Ok(());
        }
    }
    let previous: HashMap<i32, (u64, u64, bool)> = projection.state.as_ref().map(|s| s.peers.iter().map(|p| (p.conn_id, (p.connection_token, p.run_epoch, p.disconnected))).collect()).unwrap_or_default();
    let mut ids = HashSet::new();
    let mut high_water = projection.high_water;
    for peer in &state.peers {
        ensure!(peer.conn_id > 0 && peer.connection_token != 0 && ids.insert(peer.conn_id), "invalid CM connection projection");
        if let Some(identity) = previous.get(&peer.conn_id) {
            ensure!((identity.0, identity.1) == (peer.connection_token, peer.run_epoch), "CM connection ID was reused");
        } else {
            ensure!(peer.conn_id > projection.high_water, "CM connection ID overflow or reuse");
        }
        high_water = high_water.max(peer.conn_id);
    }
    for sink in projection.sinks.values() {
        for removed in previous.keys().filter(|id| !ids.contains(*id)) {
            let _ = sink.add(json!({"name":"on_client_remove", "id":removed.to_string(), "close":"true"}).to_string());
        }
        for peer in &state.peers {
            if peer.disconnected && previous.get(&peer.conn_id).is_some_and(|old| !old.2) {
                let _ = sink.add(json!({"name":"on_client_remove", "id":peer.conn_id.to_string(), "close":"false"}).to_string());
            }
        }
        initial_events(sink, &state);
    }
    projection.high_water = high_water;
    projection.state = Some(state);
    projection.seen = Some(Instant::now());
    Ok(())
}
fn failed(message: String) {
    let mut projection = lock(&PROJECTION);
    if projection.failure.as_ref() != Some(&message) {
        for sink in projection.sinks.values() {
            let _ = sink.add(json!({"name":"host_error", "error":message}).to_string());
        }
    }
    projection.failure = Some(message);
}
pub(crate) fn subscribe(app_type: &str, sink: StreamSink<String>) -> Result<()> {
    if !matches!(app_type, "main" | "cm") { return Ok(()); }
    let mut projection = lock(&PROJECTION);
    if let Some(state) = &projection.state { initial_events(&sink, state); }
    if let Ok(preferences) = projection.preferences() { preference_events(&sink, preferences, None); }
    if let Some(error) = &projection.failure { let _ = sink.add(json!({"name":"host_error", "error":error}).to_string()); }
    projection.sinks.insert(app_type.to_owned(), sink);
    Ok(())
}
pub(crate) fn unsubscribe(app_type: &str) { lock(&PROJECTION).sinks.remove(app_type); }

impl Owner {
    fn create() -> Result<Arc<Self>> {
        ensure!(!is_cm() && uses_host_options(), "only the real main process may initialize Host");
        let identity = Identity::current()?;
        // Reserve BEFORE credentials/controller initialization; another main must
        // fail rather than starting a second registration/capture/input owner.
        let pipe = Pipe::reserve(&identity)?;
        let controller = HostController::initialize()?;
        let preferences = Mutex::new(UiPreferences::initial()?);
        let (commands, receive) = mpsc::sync_channel::<OwnerRequest>(QUEUE);
        let owner = Arc::new(Self { controller, commands, stopping: AtomicBool::new(false), threads: Mutex::new(Vec::new()), child: Mutex::new(None), identity, preferences });
        publish(owner.controller.snapshot())?;
        let control = owner.controller.clone();
        let worker = std::thread::Builder::new().name("rd-host-control-bridge".into()).spawn(move || {
            while let Ok(mut request) = receive.recv() {
                let result = if !matches!(request.cancelled.try_recv(), Ok(None)) || Instant::now() >= request.deadline {
                    drop(request.command); // HostCommand::drop scrubs credentials.
                    Err(anyhow::anyhow!("host caller released or command expired before admission"))
                } else {
                    // Binding validation and submission share the serialized
                    // bridge owner, so a queued configuration change cannot
                    // slip between a CM policy check and its core command.
                    let command = match request.command {
                        OwnerCommand::Control(command) => Ok(command),
                        OwnerCommand::Peer { binding, action } => peer_command(&control.snapshot(), binding, action),
                    };
                    command.and_then(|command| {
                        let operation = control.execute_with_deadline(command, request.deadline);
                        hbb_common::futures::pin_mut!(operation);
                        block_on(async {
                            // Cancellation wins if both futures are ready. Dropping
                            // execute closes its core reply receiver, so not-yet-
                            // admitted positive work is refused. It never aborts
                            // the actor's admitted native/file cleanup or rolls back.
                            match select(request.cancelled, operation).await {
                                Either::Left(_) => Err(anyhow::anyhow!("host caller released; outcome remains unconfirmed")),
                                Either::Right((reply, _)) => reply.map_err(Into::into),
                            }
                        })
                    })
                };
                // The engine owns admitted cleanup even when its caller times out.
                // HostReply::drop scrubs even a successfully buffered reply
                // whose receiver disappears before taking its password.
                let _ = request.reply.send(result);
            }
        })?;
        lock(&owner.threads).push(worker);
        let serving = owner.clone();
        let server = std::thread::Builder::new().name("rd-host-cm-pipe".into()).spawn(move || serve(pipe, serving))?;
        lock(&owner.threads).push(server);
        let observing = owner.clone();
        let watcher = std::thread::Builder::new().name("rd-host-ui-state".into()).spawn(move || {
            let mut states = observing.controller.subscribe_state();
            let mut last_spawn = 0;
            let mut initial = true;
            while !observing.stopping.load(Ordering::Acquire) {
                if !initial {
                    match states.has_changed() {
                        Ok(false) => { std::thread::park_timeout(POLL); continue; },
                        Ok(true) => {},
                        Err(_) => {
                            failed("host state owner was lost".into());
                            observing.stopping.store(true, Ordering::Release);
                            break;
                        },
                    }
                }
                initial = false;
                let state = states.borrow_and_update().clone();
                let newest = state.peers.iter().filter(|p| !p.disconnected).map(|p| p.conn_id).max().unwrap_or(0);
                if newest > last_spawn {
                    last_spawn = newest;
                    if let Err(error) = observing.show_cm() { failed(error.to_string()); }
                }
                if let Err(error) = publish(state) { failed(error.to_string()); }
                // A dedicated blocking observer, never an engine async worker.
                std::thread::park_timeout(POLL);
            }
        });
        let watcher = match watcher {
            Ok(watcher) => watcher,
            Err(error) => {
                owner.stopping.store(true, Ordering::Release);
                return Err(error.into());
            },
        };
        lock(&owner.threads).push(watcher);
        Ok(owner)
    }
    fn call(&self, command: HostCommand) -> Result<HostReply> {
        let deadline = Instant::now().checked_add(COMMAND_TIMEOUT).context("host command deadline unavailable")?;
        self.queued(OwnerCommand::Control(command), deadline)
    }
    fn queued(&self, command: OwnerCommand, deadline: Instant) -> Result<HostReply> {
        if self.stopping.load(Ordering::Acquire) {
            drop(command);
            bail!("host owner has retired");
        }
        ensure!(Instant::now() < deadline, "host command expired before admission");
        let (reply, result) = mpsc::sync_channel(1);
        // This sender is deliberately never signalled. Every return path drops
        // it and wakes the worker, including timeout/loss of the reply waiter.
        let (_cancel_on_return, cancelled) = oneshot::channel();
        let request = OwnerRequest { command, deadline, cancelled, reply };
        if let Err(error) = self.commands.try_send(request) {
            let request = match error { mpsc::TrySendError::Full(r) | mpsc::TrySendError::Disconnected(r) => r };
            drop(request.command);
            bail!("host control queue unavailable or full");
        }
        result.recv_timeout(deadline.saturating_duration_since(Instant::now())).context("host command timeout/loss; outcome remains unconfirmed")?
    }
    fn show_cm(&self) -> Result<()> {
        let mut child = lock(&self.child);
        if let Some(process) = child.as_mut() {
            if process.try_wait()?.is_none() { return Ok(()); }
            // try_wait has reaped the exited child before replacement.
        }
        *child = Some(Command::new(&self.identity.exe).arg("--cm").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().context("cannot launch packaged connection manager")?);
        Ok(())
    }
}
fn owner() -> Result<Arc<Owner>> {
    ensure!(!is_cm(), "CM cannot access main-process credentials or configuration commands");
    match lock(&OWNER).as_ref() {
        Some(Ok(owner)) => {
            ensure!(!owner.stopping.load(Ordering::Acquire), "host owner unavailable");
            Ok(owner.clone())
        },
        Some(Err(error)) => bail!("{error}"),
        None => bail!("host main process is not initialized"),
    }
}
pub(crate) fn main_init() -> Result<()> {
    if is_cm() { return cm_init(); }
    if !uses_host_options() { return Ok(()); }
    if lock(&OWNER).is_some() { return owner().map(|_| ()); }
    ensure!(MAIN_INIT_STARTED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok(), "host initialization is already in progress");
    // Never hold the cell lock over identity/disk/thread work: synchronous
    // getters must return not-ready, not wait on startup on the UI thread.
    let result = Owner::create().map_err(|e| e.to_string());
    if let Err(error) = &result { failed(error.clone()); }
    *lock(&OWNER) = Some(result);
    owner().map(|_| ())
}
pub(crate) fn execute(command: HostCommand) -> Result<HostReply> {
    match owner() { Ok(owner) => owner.call(command), Err(error) => { drop(command); Err(error) } }
}
pub(crate) fn acknowledge(command: HostCommand) -> Result<()> {
    match execute(command)? {
        HostReply::Acknowledged => { publish(owner()?.controller.snapshot())?; Ok(()) },
        _ => bail!("unexpected host reply"),
    }
}
pub(crate) fn temporary_password() -> Result<String> {
    let mut reply = execute(HostCommand::GetTemporaryPassword)?;
    match &mut reply { HostReply::TemporaryPassword(value) => Ok(std::mem::take(value)), _ => bail!("unexpected password reply") }
}
pub(crate) fn registration_uuid() -> Result<String> {
    ensure!(!is_cm(), "unsupported: connection manager cannot read the account UUID");
    let owner = owner()?;
    // Never retry machine UID discovery or initialize a fallback signing key.
    Ok(STANDARD.encode(owner.controller.registration_uuid()))
}
pub(crate) fn snapshot() -> Result<ServiceSnapshot> {
    if !is_cm() { return sanitized(owner()?.controller.snapshot()); }
    let projection = lock(&PROJECTION);
    if let Some(error) = &projection.failure { bail!("{error}"); }
    ensure!(projection.seen.is_some_and(|at| at.elapsed() <= MAX_AGE), "CM snapshot is stale or unavailable");
    projection.state.clone().context("CM is not attached")
}
pub(crate) fn last_error() -> String {
    if let Some(error) = &lock(&PROJECTION).failure { return error.clone(); }
    snapshot().map(|s| s.error.unwrap_or_default()).unwrap_or_else(|e| e.to_string())
}

// Deliberately no secret/general-option/start/stop variant. Serde rejects unknown
// variants/fields before dispatch, and no payload PID is accepted anywhere.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum CmCommand {
    Hello,
    Snapshot { after_revision: Option<u64> },
    Activity,
    Peer { binding: Binding, action: PeerAction },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding { conn_id: i32, connection_token: u64, run_epoch: u64, approval_epoch: Option<u64>, policy_revision: u64 }
impl From<&PeerSnapshot> for Binding {
    fn from(p: &PeerSnapshot) -> Self { Self { conn_id:p.conn_id, connection_token:p.connection_token, run_epoch:p.run_epoch, approval_epoch:p.approval_epoch, policy_revision:p.policy_revision } }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub(crate) enum PeerAction { Approve { allow: bool }, Disconnect, Remove, Keyboard { enabled: bool } }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { version: u32, owner_epoch: u64, channel_epoch: u64, request_id: u64, deadline_uptime_ms: u64, command: CmCommand }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response { version: u32, owner_epoch: u64, channel_epoch: u64, request_id: u64, result: std::result::Result<CmReply, String> }
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
enum CmReply {
    Snapshot { state: ServiceSnapshot, preferences: UiPreferences },
    Unchanged { revision: u64, preferences: UiPreferences },
    Activity(ActivitySnapshot),
    Acknowledged,
}

fn serve(mut pipe: Pipe, owner: Arc<Owner>) {
    let result = (|| -> Result<()> {
        while !owner.stopping.load(Ordering::Acquire) {
            if pipe.accept()? {
                // An unauthorized client gets neither handshake nor snapshot.
                if let Ok(peer) = pipe.authenticate(&owner.identity, true) {
                    // A failed client loses its channel, not the Host's native
                    // ownership. An authenticated new CM can open a new channel.
                    let _ = serve_connection(&mut pipe, &peer, &owner);
                }
            }
            pipe.disconnect()?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        failed(format!("host IPC endpoint failed: {error}"));
        // Keep the first-instance reservation while the core may still own live
        // peers. Dropping it here could admit a second main-process Host. Main
        // control remains available to perform the real checked Stop.
        let _reserved_endpoint = pipe;
        while !owner.stopping.load(Ordering::Acquire) { std::thread::park_timeout(Duration::from_secs(1)); }
    }
}
fn serve_connection(pipe: &mut Pipe, peer: &windows::Peer, owner: &Owner) -> Result<()> {
    let first: Request = pipe.receive(Instant::now() + IO_TIMEOUT, MAX_REQUEST_FRAME)?;
    ensure!(first.version == VERSION && first.owner_epoch == 0 && first.channel_epoch == 0 && first.request_id == 1 && matches!(first.command, CmCommand::Hello), "invalid CM handshake");
    deadline_from_uptime(first.deadline_uptime_ms)?;
    let epoch = owner.controller.snapshot().owner_epoch;
    // A fresh SERVER nonce prevents replay of a captured old Hello and request
    // sequence even while the same main-process owner is still running.
    let channel = nonzero_nonce();
    pipe.send(&Response { version:VERSION, owner_epoch:epoch, channel_epoch:channel, request_id:1, result:Ok(CmReply::Snapshot { state:sanitized(owner.controller.snapshot())?, preferences:lock(&owner.preferences).clone() }) }, Instant::now() + IO_TIMEOUT)?;
    let mut previous = 1u64;
    let mut window = Instant::now();
    let mut count = 0usize;
    while !owner.stopping.load(Ordering::Acquire) {
        let request: Request = pipe.receive(Instant::now() + IO_TIMEOUT, MAX_REQUEST_FRAME)?;
        peer.alive()?;
        ensure!(request.version == VERSION && request.owner_epoch == epoch && request.channel_epoch == channel && previous.checked_add(1) == Some(request.request_id), "stale or replayed CM command");
        previous = request.request_id;
        if window.elapsed() >= Duration::from_secs(1) { window = Instant::now(); count = 0; }
        count += 1;
        ensure!(count <= 64, "CM request rate exceeded");
        let result = deadline_from_uptime(request.deadline_uptime_ms)
            .and_then(|deadline| dispatch(owner, request.command, deadline)).map_err(|e| e.to_string());
        pipe.send(&Response { version:VERSION, owner_epoch:epoch, channel_epoch:channel, request_id:request.request_id, result }, Instant::now() + IO_TIMEOUT)?;
    }
    Ok(())
}
fn dispatch(owner: &Owner, command: CmCommand, deadline: Instant) -> Result<CmReply> {
    ensure!(Instant::now() < deadline, "CM command expired before dispatch");
    let command = match command {
        CmCommand::Hello => bail!("CM handshake cannot be repeated"),
        CmCommand::Snapshot { after_revision } => {
            let states = owner.controller.subscribe_state();
            let state = states.borrow();
            let preferences = lock(&owner.preferences).clone();
            return if after_revision == Some(state.revision) {
                Ok(CmReply::Unchanged { revision:state.revision, preferences })
            } else { Ok(CmReply::Snapshot { state:sanitized(state.clone())?, preferences }) };
        },
        CmCommand::Activity => OwnerCommand::Control(HostCommand::ReadActivity),
        CmCommand::Peer { binding, action } => OwnerCommand::Peer { binding, action },
    };
    match &owner.queued(command, deadline)? {
        HostReply::Acknowledged => Ok(CmReply::Acknowledged),
        HostReply::Activity(activity) => Ok(CmReply::Activity(activity.clone())),
        _ => bail!("non-CM reply refused"),
    }
}
fn peer_command(state: &ServiceSnapshot, binding: Binding, action: PeerAction) -> Result<HostCommand> {
    // OS process authentication is NOT evidence of a physical operator. The
    // core still rechecks live input activity and actual permission ceilings.
    let peer = state.peers.iter().find(|p| p.conn_id == binding.conn_id).context("unknown CM connection")?;
    ensure!(peer.conn_id > 0 && peer.connection_token == binding.connection_token && peer.run_epoch == binding.run_epoch && peer.approval_epoch == binding.approval_epoch && peer.policy_revision == binding.policy_revision, "stale CM peer/approval/policy epoch");
    Ok(match action {
        PeerAction::Approve { allow } => HostCommand::Approve { run_epoch:binding.run_epoch, conn_id:binding.conn_id, approval_epoch:binding.approval_epoch.context("connection has no pending approval")?, policy_revision:binding.policy_revision, allow },
        PeerAction::Disconnect => HostCommand::Disconnect { run_epoch:binding.run_epoch, conn_id:binding.conn_id },
        PeerAction::Remove => { ensure!(peer.disconnected, "cannot remove an active connection"); HostCommand::RemoveDisconnected { run_epoch:binding.run_epoch, conn_id:binding.conn_id } },
        PeerAction::Keyboard { enabled } => HostCommand::SetKeyboard { run_epoch:binding.run_epoch, conn_id:binding.conn_id, enabled },
    })
}

struct CmRequest { command: CmCommand, deadline_uptime_ms: u64, reply: SyncSender<Result<CmReply>> }
struct Cm { commands: SyncSender<CmRequest>, epoch: u64, alive: Arc<AtomicBool> }
struct Connection { pipe: Pipe, peer: windows::Peer, epoch: u64, channel: u64, request: u64, revision: u64 }
impl Connection {
    fn attach() -> Result<(Self, ServiceSnapshot, UiPreferences)> {
        let identity = Identity::current()?;
        let mut pipe = Pipe::connect(&identity)?;
        let peer = pipe.authenticate(&identity, false)?;
        let deadline_uptime_ms = new_cm_deadline()?;
        let deadline = Instant::now().checked_add(IO_TIMEOUT).context("CM handshake deadline unavailable")?;
        pipe.send(&Request { version:VERSION, owner_epoch:0, channel_epoch:0, request_id:1, deadline_uptime_ms, command:CmCommand::Hello }, deadline)?;
        let reply: Response = pipe.receive(deadline, windows::MAX_FRAME)?;
        ensure!(reply.version == VERSION && reply.owner_epoch != 0 && reply.channel_epoch != 0 && reply.request_id == 1, "invalid owner handshake");
        let channel = reply.channel_epoch;
        let epoch = reply.owner_epoch;
        let (state, preferences) = match reply.result.map_err(anyhow::Error::msg)? { CmReply::Snapshot { state, preferences } => (state, preferences), _ => bail!("missing initial host snapshot") };
        ensure!(state.owner_epoch == epoch, "snapshot owner mismatch");
        Ok((Self { pipe, peer, epoch, channel, request:1, revision:state.revision }, state, preferences))
    }
    fn call(&mut self, command: CmCommand, deadline_uptime_ms: u64) -> Result<CmReply> {
        let command_deadline = deadline_from_uptime(deadline_uptime_ms)?;
        self.peer.alive()?;
        self.request = self.request.checked_add(1).context("CM request IDs exhausted")?;
        // Three seconds is transport grace only; neither the request nor the
        // core operation receives another command budget at this queue hop.
        let reply_deadline = command_deadline.checked_add(IO_TIMEOUT).context("CM reply deadline unavailable")?;
        let send_deadline = Instant::now().checked_add(IO_TIMEOUT).context("CM send deadline unavailable")?.min(command_deadline);
        self.pipe.send(&Request { version:VERSION, owner_epoch:self.epoch, channel_epoch:self.channel, request_id:self.request, deadline_uptime_ms, command }, send_deadline)?;
        let reply: Response = self.pipe.receive(reply_deadline, windows::MAX_FRAME)?;
        ensure!(reply.version == VERSION && reply.owner_epoch == self.epoch && reply.channel_epoch == self.channel && reply.request_id == self.request, "stale or unrelated host reply");
        let result = reply.result.map_err(anyhow::Error::msg)?;
        match &result {
            CmReply::Snapshot { state, .. } => {
                ensure!(state.owner_epoch == self.epoch && state.revision >= self.revision, "host snapshot regressed");
                self.revision = state.revision;
            },
            CmReply::Unchanged { revision, .. } => ensure!(*revision == self.revision, "unrelated host revision acknowledgement"),
            _ => {},
        }
        Ok(result)
    }
}
impl Cm {
    fn create() -> Result<Arc<Self>> {
        ensure!(is_cm(), "cm_init requires the dedicated --cm process");
        let (mut connection, state, preferences) = Connection::attach()?;
        publish(state)?;
        publish_preferences(preferences)?;
        let (commands, receive) = mpsc::sync_channel::<CmRequest>(QUEUE);
        let alive = Arc::new(AtomicBool::new(true));
        let cm = Arc::new(Self { commands, epoch:connection.epoch, alive:alive.clone() });
        std::thread::Builder::new().name("rd-cm-host-link".into()).spawn(move || {
            let result = cm_worker(&mut connection, receive);
            alive.store(false, Ordering::Release);
            failed(result.err().map(|e| e.to_string()).unwrap_or_else(|| "CM host link closed".into()));
            // No reconnect. This CM belongs to exactly this authenticated owner
            // epoch; a fresh process must attach to a replacement owner.
        })?;
        Ok(cm)
    }
    fn call(&self, command: CmCommand) -> Result<CmReply> {
        ensure!(self.alive.load(Ordering::Acquire), "CM owner link lost; reopen CM");
        let deadline_uptime_ms = new_cm_deadline()?;
        let reply_deadline = deadline_from_uptime(deadline_uptime_ms)?.checked_add(IO_TIMEOUT).context("CM reply deadline unavailable")?;
        let (reply, result) = mpsc::sync_channel(1);
        self.commands.try_send(CmRequest { command, deadline_uptime_ms, reply }).map_err(|_| anyhow::anyhow!("CM command queue full or unavailable"))?;
        result.recv_timeout(reply_deadline.saturating_duration_since(Instant::now())).context("CM reply timeout; outcome remains unconfirmed")?
    }
}
fn cm_worker(connection: &mut Connection, receive: Receiver<CmRequest>) -> Result<()> {
    loop {
        match receive.recv_timeout(POLL) {
            Ok(request) => {
                // Native refusals are returned as Result errors. Transport/protocol
                // loss is detected by the subsequent authoritative snapshot too.
                let result = connection.call(request.command, request.deadline_uptime_ms);
                if let Ok(CmReply::Snapshot { state, preferences }) = &result {
                    publish_preferences(preferences.clone())?;
                    publish(state.clone())?;
                }
                let _ = request.reply.send(result);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        // Observation has its own fresh budget, never a replacement deadline
        // for a queued user command or a retry of an expired mutation.
        match connection.call(CmCommand::Snapshot { after_revision:Some(connection.revision) }, new_cm_deadline()?)? {
            CmReply::Snapshot { state, preferences } => { publish_preferences(preferences)?; publish(state)?; },
            CmReply::Unchanged { revision, preferences } => {
                publish_preferences(preferences)?;
                let mut projection = lock(&PROJECTION);
                ensure!(projection.state.as_ref().is_some_and(|state| state.owner_epoch == connection.epoch && state.revision == revision), "CM revision cache mismatch");
                projection.seen = Some(Instant::now());
            },
            _ => bail!("unexpected host snapshot reply"),
        }
    }
}
pub(crate) fn cm_init() -> Result<()> {
    if lock(&CM).is_some() { return cm().map(|_| ()); }
    ensure!(CM_INIT_STARTED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok(), "CM initialization is already in progress");
    let result = Cm::create().map_err(|e| e.to_string());
    if let Err(error) = &result { failed(error.clone()); }
    *lock(&CM) = Some(result);
    cm().map(|_| ())
}
fn cm() -> Result<Arc<Cm>> {
    match lock(&CM).as_ref() {
        Some(Ok(cm)) => { ensure!(cm.alive.load(Ordering::Acquire), "CM owner link lost; reopen CM"); Ok(cm.clone()) },
        Some(Err(error)) => bail!("{error}"),
        None => bail!("CM has not attached to Host"),
    }
}
fn client_snapshot() -> Result<ServiceSnapshot> {
    if !is_cm() {
        let state = snapshot()?;
        publish(state.clone())?;
        return Ok(state);
    }
    let cm = cm()?;
    let state = match cm.call(CmCommand::Snapshot { after_revision:None })? { CmReply::Snapshot { state, .. } => state, _ => bail!("unexpected client snapshot reply") };
    ensure!(state.owner_epoch == cm.epoch, "CM owner epoch changed");
    Ok(state)
}
pub(crate) fn clients_state() -> Result<String> {
    Ok(serde_json::to_string(&clients(&client_snapshot()?))?)
}
pub(crate) fn clients_length() -> Result<usize> {
    Ok(client_snapshot()?.peers.len())
}
pub(crate) fn check_clients_length(length: usize) -> Result<Option<String>> {
    let state = client_snapshot()?;
    if state.peers.len() == length { Ok(None) }
    else { Ok(Some(serde_json::to_string(&clients(&state))?)) }
}
pub(crate) fn peer_action(conn_id: i32, action: PeerAction) -> Result<()> {
    let binding = {
        let projection = lock(&PROJECTION);
        if let Some(error) = &projection.failure { bail!("{error}"); }
        if is_cm() { ensure!(projection.seen.is_some_and(|at| at.elapsed() <= MAX_AGE), "CM snapshot is stale"); }
        let state = projection.state.as_ref().context("CM has no published snapshot")?;
        let peer = state.peers.iter().find(|p| p.conn_id == conn_id).context("unknown published CM connection")?;
        Binding::from(peer)
    };
    let command = CmCommand::Peer { binding, action };
    let reply = if is_cm() { cm()?.call(command)? } else {
        let deadline = Instant::now().checked_add(COMMAND_TIMEOUT).context("host command deadline unavailable")?;
        dispatch(owner()?.as_ref(), command, deadline)?
    };
    ensure!(matches!(reply, CmReply::Acknowledged), "unexpected CM decision reply");
    // Acknowledgement is decision-recorded ONLY. Authorization/permissions are
    // never written here: they come from the owner's subsequent state edge.
    Ok(())
}
pub(crate) fn activity() -> Result<ActivitySnapshot> {
    let activity = if is_cm() {
        match cm()?.call(CmCommand::Activity)? { CmReply::Activity(value) => value, _ => bail!("unexpected activity reply") }
    } else {
        match &execute(HostCommand::ReadActivity)? { HostReply::Activity(value) => value.clone(), _ => bail!("unexpected activity reply") }
    };
    ensure!(!activity.uncertain, "remote input activity is uncertain");
    // JavaScript/Dart f64 must preserve wall-clock milliseconds exactly.
    ensure!(activity.click_wall_ms <= (1u64 << 53) && activity.mouse_wall_ms <= (1u64 << 53), "input activity timestamp exceeds exact UI range");
    Ok(activity)
}
pub(crate) fn cm_config(name: &str) -> Result<String> {
    let state = snapshot()?;
    match name {
        "hide_cm" => Ok((state.options.get("allow-hide-cm").is_some_and(|v| v == "Y") && state.options.get("verification-method").is_some_and(|v| v == "use-permanent-password") && state.options.get("approve-mode").is_some_and(|v| v == "password")).to_string()),
        "id" => Ok(state.id),
        _ => bail!("unsupported CM configuration key"),
    }
}
