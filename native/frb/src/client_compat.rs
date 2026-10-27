//! Limited-capability adapter for the pure official revision in UPSTREAM.txt.
//!
//! The engine owns sessions, input policy and native frame production; pinned
//! hbb_common supplies configuration. Unsupported features are refused, not
//! implemented by storing fictitious success. CLIENT_SURFACE.md records the
//! consumer callsites, remaining limits and verification still required.
//! Runner C exports live outside this single FRB input in c_entry_points.rs.

use crate::configuration;
use crate::frames::FrameStore;
use crate::keyboard::KeyboardState;
use crate::platform;
use anyhow::ensure;
use base::message_proto::{ControlKey, KeyEvent, KeyboardMode};
use flutter_rust_bridge::{StreamSink, SyncReturn};
use hbb_common::base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use hbb_common::config::{
    Config, LocalConfig, PeerConfig, UserDefaultConfig, BUILTIN_SETTINGS, ENCRYPT_MAX_LEN,
    HARD_SETTINGS, NEW_STORED_PEER_CONFIG, RS_PUB_KEY,
};
use hbb_common::log;
use hbb_common::sodiumoxide::crypto::sign;
use hbb_common::sodiumoxide::utils;
use rd_engine::lan::{self, LanCompletion, LanNotice, LanOwner, LanSnapshot};
use rd_engine::official_account::{self as account, CacheKind};
use rd_engine::protocol::rect::Rect;
use rd_engine::rendezvous::RendezvousConfig;
use rd_engine::session::PeerCloseReason;
use rd_engine::surface::FrameObserver;
use rd_engine::viewer::{
    direct_address, LoginFailure, SurfaceLease, Viewer, ViewerInputPolicy, ViewerOptions,
    ViewerSnapshot, ViewerTarget,
};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// The client's vocabulary
// ---------------------------------------------------------------------------

/// The id every session call carries. Same alias as the client's own bridge.
pub type SessionID = uuid::Uuid;

/// The client's result alias: flutter_rust_bridge 1.80 parses `Result` only when
/// the error converts to `anyhow::Error`, which is what this is.
pub type Result<T> = anyhow::Result<T>;

/// What a session's stream carries to Dart. The variant names and payloads are
/// the client's: its session loop matches on `EventToUI_Event`,
/// `EventToUI_Rgba` and `EventToUI_Texture`.
pub enum EventToUI {
    Event(String),
    Rgba(usize),
    Texture(usize, bool),
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The line every unimplemented entry leaves: it names itself and says who
/// refused. The engine has no behaviour behind it, so the answer is a refusal
/// rather than a fabricated value.
fn unsupported(name: &str) {
    log::error!("{name}: unsupported by rd-engine");
}

fn unsupported_text(name: &str) -> String {
    unsupported(name);
    format!("err=unsupported: {name}")
}

fn unsupported_result<T>(name: &str) -> Result<T> {
    unsupported(name);
    anyhow::bail!("unsupported: {name}")
}

/// A negative capability/action result where the official caller treats the
/// default as "unavailable" or "not applied", never as successful completion.
/// Synchronous FRB errors are possible; these particular callers instead need
/// their documented absence value, such as false for a cursor move not applied.
fn unsupported_absence<T: Default>(name: &str) -> T {
    unsupported(name);
    T::default()
}

/// For entries the engine answers with "this build has no such state": an
/// absence rather than a missing feature, so it is not logged as an error.
fn no_state(name: &str) {
    log::debug!("{name}: no such state in this engine");
}

/// The client's message-box event. One shape for a live session and for one
/// this bridge refused, so a refusal reads to the client exactly like any other
/// connection error and its Retry button follows the same `hasRetry` field.
fn msgbox_event(kind: &str, title: &str, text: &str, link: &str, retry: bool) -> serde_json::Value {
    json!({
        "name": "msgbox",
        "type": kind,
        "title": title,
        "text": text,
        "link": link,
        "hasRetry": if retry { "true" } else { "" },
    })
}

/// The client's app name. The bridge serves the client, so the name its window
/// title and its Windows runner ask for is the client's, not this crate's.
pub(crate) const APP_NAME: &str = "RustDesk";

/// The URI prefix the client shows for its own links.
pub(crate) const URI_PREFIX: &str = "rustdesk://";

/// The public rendezvous service, used when the client configured no server of
/// its own. The same default the engine's own rendezvous probe dials.
const DEFAULT_RENDEZVOUS_SERVER: &str = "rs-ny.rustdesk.com:21116";

/// The client's own waiting-for-image sentence (`kMsgboxTextWaitingForImage` in
/// `consts.dart`): the client keys its connected overlay off this exact text.
const WAITING_FOR_IMAGE: &str = "Connected, waiting for image...";

/// The engine's own spellings of the states this bridge has to tell apart. They
/// are local constants of `ViewerError`/`ViewerSnapshot`, written by the engine's
/// own `Display`, never a peer's text.
const ENGINE_AUTH_FAILED: &str = "AuthenticationFailed";
const ENGINE_SECOND_FACTOR_UNSUPPORTED: &str = "SecondFactorUnsupported";
const ENGINE_AWAITING_APPROVAL: &str = "awaiting_approval";

const DEFAULT_FPS: i32 = 30;
const DEFAULT_TRACKPAD_SPEED: i32 = 100;
const PUMP_POLL: Duration = Duration::from_millis(100);
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// App-wide state
// ---------------------------------------------------------------------------

/// Process-local runtime and UI state; persistent settings use hbb_common.
#[derive(Default)]
struct AppState {
    device_id: String,
    device_name: String,
    home_dir: String,
    app_dir: String,
    /// The session the client last focused, for `set_cur_session_id`.
    current_session: String,
    /// The last failure a session reported, for `main_get_error`.
    last_error: String,
    /// The `start_global_event_stream` sinks, by the app type the Dart passed.
    channels: HashMap<String, StreamSink<String>>,
    /// A registration identity, not a reusable app-type name. Old LAN work may
    /// not publish to a replacement main stream.
    lan_stream: Option<Arc<()>>,
    lan_owner: Option<Arc<LanOwner>>,
    lan_retirement: Option<(u64, LanCompletion)>,
    lan_published_revision: u64,
    lan_noticed_revision: u64,
    lan_query_pending: bool,
    logging: bool,
}

static APP: LazyLock<Mutex<AppState>> = LazyLock::new(|| Mutex::new(AppState::default()));
// Serializes bridge owner admission/retirement only. Never held during cache
// I/O or while waiting for completion, and never acquired by a core callback.
static LAN_LIFECYCLE: Mutex<()> = Mutex::new(());

/// Protected local identity is not hbbs registration or proof of reachability.
fn my_id() -> String {
    Config::get_id()
}

fn local_name() -> String {
    let app = lock(&APP);
    app.device_name.clone()
}

fn option(key: &str) -> String {
    Config::get_option(key)
}

fn local_option(key: &str) -> String {
    LocalConfig::get_option(key)
}

fn push_global_event(app_type: &str, event: String) {
    let app = lock(&APP);
    if let Some(sink) = app.channels.get(app_type) {
        let _ = sink.add(event);
    }
}

/// The client's `main_broadcast_message`: every window but the main and the
/// connection-manager one hears about a theme or language change.
fn broadcast_others(data: &serde_json::Value) {
    let app = lock(&APP);
    for (app_type, sink) in app.channels.iter() {
        if app_type == "main" || app_type == "cm" {
            continue;
        }
        let _ = sink.add(data.to_string());
    }
}

fn set_last_error(text: String) {
    lock(&APP).last_error = text;
}

fn lan_matches(app: &AppState, stream: &Arc<()>, owner: &Arc<LanOwner>) -> bool {
    app.lan_stream
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, stream))
        && app
            .lan_owner
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, owner))
}

/// Fence publication atomically with replacement/removal of the main sink.
fn invalidate_lan_owner(app: &mut AppState) -> Option<Arc<LanOwner>> {
    app.lan_stream = app.channels.contains_key("main").then(|| Arc::new(()));
    app.lan_published_revision = 0;
    app.lan_noticed_revision = 0;
    app.lan_query_pending = false;
    app.lan_owner.take()
}

/// Called with LAN_LIFECYCLE held, never APP. The core retains responsibility
/// for retirement even when this bridge no longer has a listener or caller.
fn retire_lan_owner(owner: Option<Arc<LanOwner>>) {
    if let Some(owner) = owner {
        let completion = owner.request_close();
        lock(&APP).lan_retirement = Some((owner.generation(), completion));
    }
}

/// Only normal FRB worker entries call this; acquiring an owner may wait for a
/// previous owner's real retirement, but no bridge/core metadata lock is held.
fn lan_context() -> Result<(Arc<()>, Arc<LanOwner>)> {
    let (stream, retirement) = {
        let _admission = lock(&LAN_LIFECYCLE);
        let app = lock(&APP);
        ensure!(
            app.logging && !app.app_dir.is_empty(),
            "LAN configuration is not initialized"
        );
        let stream = app
            .lan_stream
            .clone()
            .ok_or_else(|| anyhow::anyhow!("LAN discovery has no active main stream"))?;
        if let Some(owner) = &app.lan_owner {
            return Ok((stream, owner.clone()));
        }
        (stream, app.lan_retirement.clone())
    };
    if let Some((generation, retirement)) = retirement {
        let result = retirement.wait_blocking();
        {
            let _admission = lock(&LAN_LIFECYCLE);
            let mut app = lock(&APP);
            if app
                .lan_retirement
                .as_ref()
                .is_some_and(|(current, _)| *current == generation)
            {
                // Completion ends ownership even when the retired work failed.
                // Consume only this receipt, never a successor's retirement.
                app.lan_retirement = None;
            }
        }
        result.map_err(anyhow::Error::msg)?;
    }
    let _admission = lock(&LAN_LIFECYCLE);
    {
        let app = lock(&APP);
        ensure!(
            app.lan_stream
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &stream)),
            "LAN stream was replaced"
        );
        if let Some(owner) = &app.lan_owner {
            return Ok((stream, owner.clone()));
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let ping_id = my_id();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let ping_id = String::new();
    let notification_stream = stream.clone();
    let notifier = Arc::new(move |notice| lan_notice(notification_stream.clone(), notice));
    let owner =
        lan::acquire_initialized_owner(ping_id, Some(notifier)).map_err(anyhow::Error::msg)?;
    let mut app = lock(&APP);
    app.lan_owner = Some(owner.clone());
    app.lan_retirement = None;
    Ok((stream, owner))
}

fn lan_error(stream: &Arc<()>, owner: &Arc<LanOwner>, error: &str) {
    let mut app = lock(&APP);
    if lan_matches(&app, stream, owner) {
        app.last_error = format!("LAN discovery: {error}");
        log::error!("LAN discovery: {error}");
    }
}

fn publish_lan_snapshot(
    stream: &Arc<()>,
    owner: &Arc<LanOwner>,
    snapshot: LanSnapshot,
) -> Result<()> {
    let peers = serde_json::to_string(&snapshot.peers)?;
    let event = json!({ "name": "load_lan_peers", "peers": peers }).to_string();
    let mut app = lock(&APP);
    if !lan_matches(&app, stream, owner)
        || snapshot.owner_generation != owner.generation()
        || snapshot.cache_revision < app.lan_published_revision
    {
        return Ok(());
    }
    // Keep the ownership check and actual enqueue in one critical section.
    let published = app.channels.get("main").is_some_and(|sink| sink.add(event));
    ensure!(published, "LAN event stream is closed");
    app.lan_published_revision = snapshot.cache_revision;
    if let Some(error) = snapshot.error {
        app.last_error = format!("LAN discovery: {error}");
    }
    Ok(())
}

/// Core notifications run on the existing engine executor. Coalesce them into
/// one off-UI query worker, rather than doing file I/O in the callback or
/// spawning an unbounded collection of parallel cache reads.
fn lan_notice(stream: Arc<()>, notice: LanNotice) {
    let owner = {
        let mut app = lock(&APP);
        let Some(owner) = app.lan_owner.clone() else {
            return;
        };
        if !lan_matches(&app, &stream, &owner) || owner.generation() != notice.owner_generation {
            return;
        }
        app.lan_noticed_revision = app.lan_noticed_revision.max(notice.cache_revision);
        if app.lan_query_pending {
            return;
        }
        app.lan_query_pending = true;
        owner
    };
    hbb_common::tokio::task::spawn_blocking(move || loop {
        let result = owner
            .query_blocking()
            .map_err(anyhow::Error::msg)
            .and_then(|snapshot| publish_lan_snapshot(&stream, &owner, snapshot));
        if let Err(error) = &result {
            lan_error(&stream, &owner, &error.to_string());
            let _ = owner.request_close();
        }
        let mut app = lock(&APP);
        if !lan_matches(&app, &stream, &owner) {
            return;
        }
        if result.is_err() || app.lan_noticed_revision <= app.lan_published_revision {
            app.lan_query_pending = false;
            return;
        }
    });
}

// ---------------------------------------------------------------------------
// Boot: the global event stream, ids, logging
// ---------------------------------------------------------------------------

/// The client's app-level event stream. One sink per app type, exactly as the
/// core keeps it; the engine pushes what the client's own boot asks for (the
/// peer lists it reads from the shared store, theme and language changes).
pub fn start_global_event_stream(s: StreamSink<String>, app_type: String) -> Result<()> {
    #[cfg(target_os = "windows")]
    crate::host_bridge::subscribe(&app_type, s.clone())?;
    let _admission = lock(&LAN_LIFECYCLE);
    let main = app_type == "main";
    let retired = {
        let mut app = lock(&APP);
        app.channels.insert(app_type, s);
        if main {
            invalidate_lan_owner(&mut app)
        } else {
            None
        }
    };
    retire_lan_owner(retired);
    Ok(())
}

pub fn stop_global_event_stream(app_type: String) {
    #[cfg(target_os = "windows")]
    crate::host_bridge::unsubscribe(&app_type);
    let _admission = lock(&LAN_LIFECYCLE);
    let retired = {
        let mut app = lock(&APP);
        app.channels.remove(&app_type);
        if app_type == "main" {
            invalidate_lan_owner(&mut app)
        } else {
            None
        }
    };
    retire_lan_owner(retired);
}

/// Initialize the shared store's app directory and logging. Persistent settings
/// continue to use that store's platform-specific configuration paths.
pub fn main_init(app_dir: String, custom_client_config: String) -> Result<()> {
    ensure!(
        custom_client_config.is_empty(),
        "unsupported: custom client configuration is not accepted by this adapter"
    );
    let mut app = lock(&APP);
    app.app_dir = app_dir;
    if !app.logging {
        app.logging = true;
        *hbb_common::config::APP_DIR
            .write()
            .unwrap_or_else(|error| error.into_inner()) = app.app_dir.clone();
        hbb_common::init_log(false, "rustdesk-frb");
    }
    drop(app);
    #[cfg(target_os = "windows")]
    crate::host_bridge::main_init()?;
    Ok(())
}

pub fn main_get_home_dir() -> String {
    let home = lock(&APP).home_dir.clone();
    if home.is_empty() {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_default()
    } else {
        home
    }
}

pub fn main_set_home_dir(_home: String) {
    lock(&APP).home_dir = _home;
}

pub fn main_get_data_dir_ios(app_dir: String) -> SyncReturn<String> {
    lock(&APP).app_dir = app_dir;
    let data_dir = std::path::Path::new(&lock(&APP).app_dir).join("data");
    if let Err(error) = std::fs::create_dir_all(&data_dir) {
        log::warn!("main_get_data_dir_ios: cannot create {data_dir:?}: {error}");
    }
    SyncReturn(data_dir.to_string_lossy().to_string())
}

/// The pinned official consumer's product version for About, not the engine or
/// bridge crate artifact version. This identity does not promise runtime parity.
pub fn main_get_version() -> String {
    env!("RD_OFFICIAL_PRODUCT_VERSION").to_owned()
}

pub fn main_get_build_date() -> String {
    no_state("main_get_build_date");
    String::new()
}

pub fn main_get_app_name() -> String {
    APP_NAME.to_owned()
}

pub fn main_get_app_name_sync() -> SyncReturn<String> {
    SyncReturn(APP_NAME.to_owned())
}

pub fn main_uri_prefix_sync() -> SyncReturn<String> {
    SyncReturn(URI_PREFIX.to_owned())
}

pub fn main_get_my_id() -> Result<String> {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::uses_host_options() {
        return Ok(crate::host_bridge::snapshot()?.id);
    }
    Ok(my_id())
}

pub fn main_change_id(new_id: String) -> Result<()> {
    unsupported_result("main_change_id")
}

pub fn main_get_uuid() -> Result<String> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::registration_uuid(); }
    #[cfg(not(target_os = "windows"))]
    { Ok(STANDARD.encode(hbb_common::get_uuid())) }
}

pub fn main_device_id(id: String) {
    lock(&APP).device_id = id;
}

pub fn main_device_name(name: String) {
    account::api::set_device_name(name.clone());
    lock(&APP).device_name = name;
}

pub fn main_get_langs() -> Result<String> {
    Ok(serde_json::to_string(&crate::localization::langs())?)
}

pub fn translate(name: String, locale: String) -> Result<SyncReturn<String>> {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::is_cm() {
        let language = crate::host_bridge::cm_ui_preference("lang")?;
        return Ok(SyncReturn(crate::localization::translate_locale_with_preference(name, &locale, &language)));
    }
    Ok(SyncReturn(crate::localization::translate_locale(name, &locale)))
}

pub fn main_get_error() -> String {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::uses_host_options() {
        let error = crate::host_bridge::last_error();
        if !error.is_empty() { return error; }
    }
    lock(&APP).last_error.clone()
}

pub fn main_get_fingerprint() -> Result<String> {
    #[cfg(target_os = "windows")]
    { return Ok(crate::host_bridge::snapshot()?.fingerprint); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("main_get_fingerprint")
}

pub fn main_get_license() -> String {
    no_state("main_get_license");
    String::new()
}

pub fn main_get_buildin_option(key: String) -> SyncReturn<String> {
    // A built-in table can name `password` too, and this is a global option
    // reader like the ones below, so a credential key reads as absent here.
    if configuration::is_credential_key(&key) {
        no_state("main_get_buildin_option: credential value withheld");
        return SyncReturn(String::new());
    }
    SyncReturn(
        BUILTIN_SETTINGS
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(&key)
            .cloned()
            .unwrap_or_default(),
    )
}

pub fn main_get_hard_option(key: String) -> SyncReturn<String> {
    // `password` is one of hbb_common's hard settings, so this reader is the
    // other place a global store could hand a credential out.
    if configuration::is_credential_key(&key) {
        no_state("main_get_hard_option: credential value withheld");
        return SyncReturn(String::new());
    }
    SyncReturn(
        HARD_SETTINGS
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(&key)
            .cloned()
            .unwrap_or_default(),
    )
}

pub fn main_is_option_fixed(key: String) -> SyncReturn<bool> {
    SyncReturn(
        HARD_SETTINGS
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .contains_key(&key),
    )
}

/// CM is synchronized only after a fresh authenticated owner snapshot.
pub fn option_synced() -> bool {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::uses_host_options() {
        return crate::host_bridge::snapshot().is_ok();
    }
    true
}

// ---------------------------------------------------------------------------
// Boot: the option stores
// ---------------------------------------------------------------------------

/// The one rule a write of a credential key meets at every store below, and at
/// the local Flutter map and the user defaults too.
///
/// A credential value is never stored: a non-empty value is refused here, with
/// the refusal named in the log and in `main_get_error`, and the caller then
/// clears the key from the same store. Clearing is what the client's own logout
/// path does with an empty value anyway, and doing it for a refused write as
/// well is what keeps "refused" from meaning "already stored by an earlier
/// run": no credential survives an attempt to persist one.
fn refuse_credential_write(entry: &str, key: &str, value: &str) {
    if value.is_empty() {
        log::debug!("{entry}: clearing credential key {key}");
        return;
    }
    log::error!("{entry}: refused credential key {key}");
    set_last_error(format!("{entry}: credential persistence is disabled"));
}

pub fn main_get_option(key: String) -> Result<String> {
    if configuration::is_credential_key(&key) {
        return Ok(String::new());
    }
    #[cfg(target_os = "windows")]
    if crate::host_bridge::uses_host_options() {
        return Ok(crate::host_bridge::snapshot()?.options.get(&key).cloned().unwrap_or_default());
    }
    Ok(option(&key))
}

pub fn main_get_option_sync(key: String) -> Result<SyncReturn<String>> {
    main_get_option(key).map(SyncReturn)
}

pub fn main_set_option(key: String, value: String) -> Result<()> {
    if configuration::is_credential_key(&key) {
        refuse_credential_write("main_set_option", &key, &value);
        discard_credential(value);
        anyhow::bail!("unsupported: credentials require their dedicated account or session API");
    }
    #[cfg(target_os = "windows")]
    {
        return crate::host_bridge::acknowledge(crate::host_bridge::HostCommand::SetOption { key, value });
    }
    #[cfg(not(target_os = "windows"))]
    if matches!(
        key.as_str(),
        "api-server" | "custom-rendezvous-server" | "relay-server" | "key" | "allow-websocket"
    ) && Config::get_option(&key) != value
    {
        account::change_server_configuration(|| Config::set_option(key, value))
    } else {
        Config::set_option(key, value);
        Ok(())
    }
}

pub fn main_get_options() -> Result<String> {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::uses_host_options() {
        return Ok(serde_json::to_string(&crate::host_bridge::snapshot()?.options)?);
    }
    let mut options = Config::get_options();
    configuration::strip_credential_options(&mut options);
    Ok(serde_json::to_string(&options)?)
}

pub fn main_get_options_sync() -> Result<SyncReturn<String>> {
    main_get_options().map(SyncReturn)
}

pub fn main_set_options(json: String) -> Result<()> {
    let mut options = serde_json::from_str::<HashMap<String, String>>(&json)
        .map_err(|_| anyhow::anyhow!("invalid option JSON"))?;
    if options
        .keys()
        .any(|key| configuration::is_credential_key(key))
    {
        configuration::strip_credential_options(&mut options);
        anyhow::bail!("unsupported: credentials require their dedicated account or session API");
    }
    #[cfg(target_os = "windows")]
    {
        return crate::host_bridge::acknowledge(crate::host_bridge::HostCommand::SetOptions { options });
    }
    #[cfg(not(target_os = "windows"))]
    {
    let previous = Config::get_options();
    let changes_server = [
        "api-server",
        "custom-rendezvous-server",
        "relay-server",
        "key",
        "allow-websocket",
    ]
    .iter()
    .any(|key| previous.get(*key) != options.get(*key));
    if changes_server {
        account::change_server_configuration(|| Config::set_options(options))
    } else {
        Config::set_options(options);
        Ok(())
    }
    }
}

pub fn main_get_local_option(key: String) -> Result<SyncReturn<String>> {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::is_cm() && matches!(key.as_str(), "theme" | "lang") {
        return crate::host_bridge::cm_ui_preference(&key).map(SyncReturn);
    }
    #[cfg(target_os = "windows")]
    if key == "allow-remote-cm-modification" {
        return Ok(SyncReturn(crate::host_bridge::snapshot()?.options.get(&key).cloned().unwrap_or_default()));
    }
    if matches!(key.as_str(), "access_token" | "user_info") {
        return account::get_local_option(&key).map(SyncReturn);
    }
    if configuration::is_credential_key(&key) {
        no_state("main_get_local_option: credential value withheld");
        return Ok(SyncReturn(String::new()));
    }
    Ok(SyncReturn(local_option(&key)))
}

pub fn main_set_local_option(key: String, value: String) -> Result<()> {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::is_cm() && matches!(key.as_str(), "theme" | "lang") {
        anyhow::bail!("unsupported: connection manager appearance preferences are read-only");
    }
    #[cfg(target_os = "windows")]
    if key == "allow-remote-cm-modification" {
        return crate::host_bridge::acknowledge(crate::host_bridge::HostCommand::SetOption { key, value });
    }
    if matches!(key.as_str(), "access_token" | "user_info") {
        discard_credential(value);
        anyhow::bail!("account write requires a captured scope receipt");
    }
    if configuration::is_credential_key(&key) {
        refuse_credential_write("main_set_local_option", &key, &value);
        discard_credential(value);
        anyhow::bail!("unsupported: credentials require their dedicated account or session API");
    }
    LocalConfig::set_option(key, value);
    Ok(())
}

pub fn get_local_flutter_option(k: String) -> SyncReturn<String> {
    if configuration::is_credential_key(&k) {
        no_state("get_local_flutter_option: credential value withheld");
        return SyncReturn(String::new());
    }
    SyncReturn(LocalConfig::get_flutter_option(&k))
}

pub fn set_local_flutter_option(k: String, v: String) {
    if configuration::is_credential_key(&k) {
        refuse_credential_write("set_local_flutter_option", &k, &v);
        LocalConfig::set_flutter_option(k, String::new());
        return;
    }
    LocalConfig::set_flutter_option(k, v);
}

pub fn get_local_kb_layout_type() -> SyncReturn<String> {
    SyncReturn(LocalConfig::get_kb_layout_type())
}

pub fn set_local_kb_layout_type(kb_layout_type: String) {
    LocalConfig::set_kb_layout_type(kb_layout_type);
}

pub fn main_set_user_default_option(key: String, value: String) {
    if configuration::is_credential_key(&key) {
        refuse_credential_write("main_set_user_default_option", &key, &value);
        let mut config = UserDefaultConfig::load();
        config.set(key, String::new());
        return;
    }
    let mut config = UserDefaultConfig::load();
    config.set(key, value);
}

pub fn main_get_user_default_option(key: String) -> SyncReturn<String> {
    if configuration::is_credential_key(&key) {
        no_state("main_get_user_default_option: credential value withheld");
        return SyncReturn(String::new());
    }
    SyncReturn(UserDefaultConfig::load().get(&key))
}

pub fn main_get_env(key: String) -> SyncReturn<String> {
    SyncReturn(std::env::var(key).unwrap_or_default())
}

pub fn main_set_env(key: String, value: Option<String>) -> SyncReturn<()> {
    let is_valid_key = !key.is_empty() && !key.contains('=') && !key.contains('\0');
    if !is_valid_key {
        log::error!("main_set_env: invalid environment variable key {key:?}");
        return SyncReturn(());
    }
    match value {
        Some(value) if !value.contains('\0') => std::env::set_var(key, value),
        Some(_) => log::error!("main_set_env: invalid environment variable value"),
        None => std::env::remove_var(key),
    }
    SyncReturn(())
}

pub fn main_get_http_status(url: String) -> Result<Option<String>> {
    account::http::poll(&url)
}

// ---------------------------------------------------------------------------
// Boot: the peer store
// ---------------------------------------------------------------------------

/// The peer store is the shared, pinned implementation, so its records - and
/// the credential fields it decrypts while loading them - are what the client
/// reads here. The one policy this bridge adds is that no credential leaves it:
/// the serialized record is built by `configuration::sanitized_peer_json`,
/// which drops the peer password and the RDP/OS login fields.
pub fn main_get_peer_sync(id: String) -> SyncReturn<String> {
    match configuration::sanitized_peer_json(&id) {
        Ok(json) => SyncReturn(json),
        // Preserve upstream's empty-string result on serialization failure.
        Err(error) => {
            log::error!("main_get_peer_sync: {error}");
            SyncReturn(String::new())
        }
    }
}

pub fn main_get_peer_option(id: String, key: String) -> Result<String> {
    // A credential value is never handed out. The answer is the empty string,
    // which is what an unset option reads as: this bridge neither exposes a
    // stored credential nor pretends it has one.
    if configuration::is_credential_key(&key) {
        no_state("main_get_peer_option: credential value withheld");
        return Ok(String::new());
    }
    Ok(peer_option(&id, &key))
}

pub fn main_get_peer_option_sync(id: String, key: String) -> SyncReturn<String> {
    // Deliberately unexposed credentials read as absent, as in the async accessor.
    if configuration::is_credential_key(&key) {
        return SyncReturn(String::new());
    }
    SyncReturn(peer_option(&id, &key))
}

pub fn main_set_peer_option(id: String, key: String, value: String) -> Result<()> {
    // Every credential key, not just `password`: the shared store encrypts and
    // keeps `rdp_password` and the OS login fields beside it, so a write of one
    // is the same act as a write of the other.
    ensure!(
        !configuration::is_credential_key(&key),
        "unsupported: credential persistence is disabled"
    );
    let mut config = PeerConfig::load(&id);
    if value.is_empty() {
        config.options.remove(&key);
    } else {
        config.options.insert(key, value);
    }
    config.store(&id);
    Ok(())
}

pub fn main_set_peer_option_sync(id: String, key: String, value: String) -> SyncReturn<bool> {
    if configuration::is_credential_key(&key) {
        set_last_error("main_set_peer_option_sync: credential persistence is disabled".to_owned());
        log::error!("main_set_peer_option_sync: refused credential key {key}");
        return SyncReturn(false);
    }
    match main_set_peer_option(id, key, value) {
        Ok(()) => SyncReturn(true),
        Err(_) => SyncReturn(false),
    }
}

pub fn main_set_peer_alias(id: String, alias: String) -> Result<()> {
    main_set_peer_option(id, "alias".to_owned(), alias)
}

pub fn main_get_peer_flutter_option_sync(id: String, k: String) -> SyncReturn<String> {
    if configuration::is_credential_key(&k) {
        return SyncReturn(String::new());
    }
    SyncReturn(
        PeerConfig::load(&id)
            .ui_flutter
            .get(&k)
            .cloned()
            .unwrap_or_default(),
    )
}

pub fn main_set_peer_flutter_option_sync(id: String, k: String, v: String) -> SyncReturn<()> {
    if configuration::is_credential_key(&k) {
        log::error!("main_set_peer_flutter_option_sync: refused credential key {k}");
        return SyncReturn(());
    }
    let mut config = PeerConfig::load(&id);
    if v.is_empty() {
        config.ui_flutter.remove(&k);
    } else {
        config.ui_flutter.insert(k, v);
    }
    config.store(&id);
    SyncReturn(())
}

pub fn main_get_new_stored_peers() -> String {
    let peers: Vec<String> = lock(&NEW_STORED_PEER_CONFIG).drain().collect();
    serde_json::to_string(&peers).unwrap_or_default()
}

pub fn main_get_fav() -> Vec<String> {
    LocalConfig::get_fav()
}

pub fn main_store_fav(favs: Vec<String>) {
    LocalConfig::set_fav(favs);
}

pub fn main_peer_exists(id: String) -> bool {
    PeerConfig::exists(&id)
}

pub fn main_peer_has_password(id: String) -> Result<bool> {
    // Whether a credential is stored for this peer is not itself a secret and is
    // what the client uses to offer forgetting it, so this answers from the
    // shared store. The value is still never returned, and the credential keys
    // are the same ones every other entry refuses.
    let config = PeerConfig::load(&id);
    Ok(!config.password.is_empty()
        || config
            .options
            .iter()
            .any(|(key, value)| configuration::is_credential_key(key) && !value.is_empty()))
}

pub fn main_forget_password(_id: String) -> Result<()> {
    anyhow::bail!("unsupported: this bridge does not manage stored peer credentials")
}

pub fn main_remove_peer(id: String) {
    PeerConfig::remove(&id);
}

pub fn main_get_last_remote_id() -> String {
    LocalConfig::get_remote_id()
}

/// The core maps a peer id to the relay id its connection would use. This
/// bridge dials through rendezvous and takes the relay the answer offers, so
/// there is nothing here to rewrite.
pub fn main_handle_relay_id(id: String) -> String {
    no_state("main_handle_relay_id");
    id
}

fn peer_option(id: &str, key: &str) -> String {
    PeerConfig::load(id)
        .options
        .get(key)
        .cloned()
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Boot: the lists the client asks for at start-up
// ---------------------------------------------------------------------------

/// The client's recent-peer list, enumerated from the same store the client
/// itself writes through `main_set_peer_option` and the peer cards. A store
/// that cannot be read is logged and publishes nothing at all, rather than
/// replacing the client's list with a synthetic empty one.
pub fn main_load_recent_peers() {
    match configuration::recent_peers_json() {
        Ok(peers) => {
            let event = json!({ "name": "load_recent_peers", "peers": peers });
            push_global_event("main", event.to_string());
        }
        Err(error) => log::error!("main_load_recent_peers: {error}"),
    }
}

/// The list the address book asks for: the same records, narrowed to the ids
/// the client passed in the official filter JSON.
pub fn main_load_recent_peers_for_ab(filter: String) -> String {
    match configuration::recent_peers_for_ab(&filter) {
        Ok(peers) => peers,
        Err(error) => {
            log::error!("main_load_recent_peers_for_ab: {error}");
            String::new()
        }
    }
}

/// Official favourites include observed LAN metadata when no stored peer
/// record exists. Neither source exports a remembered password.
pub fn main_load_fav_peers() {
    let result = (|| -> Result<()> {
        let (stream, owner) = lan_context()?;
        let snapshot = owner.query_blocking().map_err(anyhow::Error::msg)?;
        let peers = configuration::favorite_peers_json(snapshot.peers)?;
        let event = json!({ "name": "load_fav_peers", "peers": peers }).to_string();
        let app = lock(&APP);
        if lan_matches(&app, &stream, &owner)
            && snapshot.cache_revision >= app.lan_published_revision
        {
            if let Some(sink) = app.channels.get("main") {
                let _ = sink.add(event);
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        log::error!("main_load_fav_peers: {error}");
    }
}

/// The official four-field LAN projection from the real shared cache. Reading
/// a remembered list never starts a scan or authenticates a discovered peer.
pub fn main_load_lan_peers() {
    let result = (|| -> Result<()> {
        let (stream, owner) = lan_context()?;
        let snapshot = owner.query_blocking().map_err(anyhow::Error::msg)?;
        publish_lan_snapshot(&stream, &owner, snapshot)
    })();
    if let Err(error) = result {
        log::error!("main_load_lan_peers: {error}");
    }
}

pub fn main_get_lan_peers() -> String {
    let result = (|| -> Result<String> {
        let (stream, owner) = lan_context()?;
        let snapshot = owner.query_blocking().map_err(anyhow::Error::msg)?;
        let peers = serde_json::to_string(&snapshot.peers)?;
        ensure!(
            lan_matches(&lock(&APP), &stream, &owner),
            "LAN stream was replaced"
        );
        Ok(peers)
    })();
    match result {
        Ok(peers) => peers,
        Err(error) => {
            log::error!("main_get_lan_peers: {error}");
            // Preserve the official String API's error sentinel, not a fake
            // successful empty discovery result.
            String::new()
        }
    }
}

pub fn main_change_theme(dark: String) -> Result<()> {
    #[cfg(target_os = "windows")]
    let dark = if crate::host_bridge::uses_host_options() { crate::host_bridge::refresh_ui_preference("theme")? } else { dark };
    let event = json!({ "name": "theme", "dark": dark });
    broadcast_others(&event);
    Ok(())
}

pub fn main_change_language(lang: String) -> Result<()> {
    #[cfg(target_os = "windows")]
    let lang = if crate::host_bridge::uses_host_options() { crate::host_bridge::refresh_ui_preference("lang")? } else { lang };
    let event = json!({ "name": "language", "lang": lang });
    broadcast_others(&event);
    Ok(())
}

pub fn main_get_connect_status() -> Result<String> {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::uses_host_options() {
        let state = crate::host_bridge::snapshot()?;
        let video_conn_count = state.peers.iter().filter(|peer| peer.authorized && !peer.disconnected).count();
        return Ok(json!({ "status_num":state.status_num, "phase":state.phase,
            "registration":state.registration, "ready":state.ready, "error":state.error,
            "video_conn_count":video_conn_count,
            "owner_epoch":state.owner_epoch.to_string(), "revision":state.revision.to_string() }).to_string());
    }
    Ok(json!({ "status_num":0 }).to_string())
}

pub fn main_check_connect_status() -> Result<()> {
    #[cfg(target_os = "windows")]
    if crate::host_bridge::uses_host_options() { crate::host_bridge::snapshot()?; }
    Ok(())
}

pub fn main_get_async_status() -> String {
    // The engine runs no async job queue, so no job is running.
    String::new()
}

pub fn main_get_common(key: String) -> Result<String> {
    #[cfg(target_os = "windows")]
    if matches!(key.as_str(), "permanent-password-set" | "local-permanent-password-set") {
        let state = crate::host_bridge::snapshot()?;
        return Ok(if key == "permanent-password-set" { state.permanent_password_set } else { state.local_permanent_password_set }.to_string());
    }
    let _ = key;
    Ok(String::new())
}

pub fn main_get_common_sync(key: String) -> Result<SyncReturn<String>> {
    main_get_common(key).map(SyncReturn)
}

pub fn main_set_common(_key: String, _value: String) -> Result<()> {
    unsupported_result("main_set_common")
}

pub fn main_is_using_public_server() -> bool {
    option("custom-rendezvous-server").is_empty()
}

pub fn main_get_api_server() -> String {
    account::api::server()
}

pub fn main_get_main_display() -> SyncReturn<String> {
    // This describes the displays of the machine being shared. This bridge
    // drives the viewer role, so there is no capture display to describe.
    SyncReturn("{}".to_owned())
}

pub fn main_get_displays() -> SyncReturn<String> {
    SyncReturn("[]".to_owned())
}

pub fn main_get_sound_inputs() -> Vec<String> {
    // The engine's login request disables audio, so it has no input devices to
    // enumerate.
    Vec::new()
}

pub fn main_audio_support_loopback() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn main_has_file_clipboard() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn main_has_hwcodec() -> SyncReturn<bool> {
    // Off OpenHarmony the engine decodes in software.
    SyncReturn(false)
}

pub fn main_has_vram() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn main_has_gpu_texture_render() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn main_supported_hwdecodings() -> SyncReturn<String> {
    SyncReturn(json!({ "h264": false, "h265": false }).to_string())
}

pub fn main_check_hwcodec() {
    no_state("main_check_hwcodec");
}

pub fn main_get_use_texture_render() -> SyncReturn<bool> {
    SyncReturn(false)
}

/// The input source names the client's own local option uses. Source 1 is the
/// native grab loop, source 2 the Flutter key path (`common.dart` sets
/// `isInputSourceFlutter` for exactly this string, and `input_model.dart`
/// dispatches desktop key events only when it is set).
const NATIVE_INPUT_SOURCE: &str = "Input source 1";
const FLUTTER_INPUT_SOURCE: &str = "Input source 2";
const FLUTTER_INPUT_SOURCE_TIP: &str = "input_source_2_tip";
const INPUT_SOURCE_OPTION: &str = "input-source";

pub fn main_get_input_source() -> SyncReturn<String> {
    // The Flutter source is the one this artifact enables in
    // `main_init_input_source` and the only one it can serve: there is no
    // native grab loop to hand events to. Reporting anything else would make
    // the client drop its desktop key events before they reach this bridge.
    SyncReturn(FLUTTER_INPUT_SOURCE.to_owned())
}

pub fn main_supported_input_source() -> SyncReturn<String> {
    // The pairs are [source, tip-key], and the list is what this build can
    // really take rather than what the upstream client offers with its native
    // grab available.
    SyncReturn(json!([[FLUTTER_INPUT_SOURCE, FLUTTER_INPUT_SOURCE_TIP]]).to_string())
}

pub fn main_default_privacy_mode_impl() -> SyncReturn<String> {
    SyncReturn(String::new())
}

pub fn main_supported_privacy_mode_impls() -> SyncReturn<String> {
    SyncReturn("[]".to_owned())
}

pub fn main_get_printer_names() -> SyncReturn<String> {
    // No printer service in this bridge.
    SyncReturn("[]".to_owned())
}

pub fn main_get_trusted_devices() -> String {
    "[]".to_owned()
}

pub fn main_remove_trusted_devices(json: String) -> Result<()> {
    unsupported_result("main_remove_trusted_devices")
}

pub fn main_clear_trusted_devices() -> Result<()> {
    unsupported_result("main_clear_trusted_devices")
}

pub fn main_get_login_device_info() -> Result<SyncReturn<String>> {
    account::api::device_info().map(SyncReturn)
}

/// The longest secret the shared configuration layer will encrypt or keep, which
/// is what the client's password fields bound themselves by. It is the same
/// value the upstream client returns, read from the same pinned implementation,
/// so the fields stay usable without this artifact inventing a limit.
pub fn main_max_encrypt_len() -> SyncReturn<usize> {
    SyncReturn(ENCRYPT_MAX_LEN)
}

pub fn main_video_save_directory(root: bool) -> Result<SyncReturn<String>> {
    unsupported_result("main_video_save_directory")
}

// ---------------------------------------------------------------------------
// Boot: flags about this build
// ---------------------------------------------------------------------------

/// Build capabilities, independent of registration/hardware readiness. Only the
/// integrated Windows artifact has the current-user controlled-host owner.
pub fn is_incoming_only() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn is_outgoing_only() -> SyncReturn<bool> {
    SyncReturn(!cfg!(target_os = "windows"))
}

pub fn is_custom_client() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn is_disable_settings() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn is_disable_ab() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn is_disable_account() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn is_disable_group_panel() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn is_disable_installation() -> SyncReturn<bool> {
    // There is no installer in this artifact: the client's install card would
    // offer an action this build cannot perform.
    SyncReturn(true)
}

pub fn is_preset_password() -> Result<bool> {
    #[cfg(target_os = "windows")]
    { return Ok(crate::host_bridge::snapshot()?.preset_password); }
    #[cfg(not(target_os = "windows"))]
    Ok(false)
}

pub fn is_preset_password_mobile_only() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn is_support_multi_ui_session(version: String) -> SyncReturn<bool> {
    let _ = version;
    // One window per session in this bridge.
    SyncReturn(false)
}

pub fn is_selinux_enforcing() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn main_is_root() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Boot: platform probes
// ---------------------------------------------------------------------------

pub fn main_current_is_wayland() -> SyncReturn<bool> {
    SyncReturn(is_wayland())
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn is_wayland() -> bool {
    std::env::var("XDG_SESSION_TYPE")
        .map(|session| !session.eq_ignore_ascii_case("x11"))
        .unwrap_or(false)
}

#[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
fn is_wayland() -> bool {
    false
}

pub fn main_is_login_wayland() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn main_hide_dock() -> SyncReturn<bool> {
    // The client calls this to hide its macOS dock icon; this bridge cannot
    // reach the platform, and the client's own core answers true either way.
    SyncReturn(true)
}

pub fn main_get_mouse_time() -> Result<f64> {
    #[cfg(target_os = "windows")]
    { return Ok(crate::host_bridge::activity()?.mouse_wall_ms as f64); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("main_get_mouse_time")
}

pub fn main_check_mouse_time() -> Result<()> {
    #[cfg(target_os = "windows")]
    { crate::host_bridge::activity()?; return Ok(()); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("main_check_mouse_time")
}

pub fn get_double_click_time() -> SyncReturn<i32> {
    // The platform's double-click interval. 500ms is the Windows default the
    // client's own input timing already assumes, and there is no platform query
    // in this bridge.
    SyncReturn(500)
}

pub fn version_to_number(v: String) -> SyncReturn<i64> {
    SyncReturn(hbb_common::get_version_number(&v))
}

static TEXTURE_KEY: AtomicI32 = AtomicI32::new(0);

pub fn get_next_texture_key() -> SyncReturn<i32> {
    SyncReturn(TEXTURE_KEY.fetch_add(1, Ordering::SeqCst) + 1)
}

pub fn host_stop_system_key_propagate(_stopped: bool) {
    // The client's host-side system-key hook; this bridge drives the viewer.
    no_state("host_stop_system_key_propagate");
}

pub fn query_onlines(ids: Vec<String>) -> Result<()> {
    unsupported_result("query_onlines")
}

// ---------------------------------------------------------------------------
// Boot: updates, installers, accounts
// ---------------------------------------------------------------------------

pub fn main_get_software_update_url() -> Result<()> {
    unsupported_result("main_get_software_update_url")
}

pub fn main_get_new_version() -> SyncReturn<String> {
    // No update check has run and none can run here, so there is no version to
    // name; the client calls this synchronously and treats "" as "unknown".
    SyncReturn(unsupported_absence("main_get_new_version"))
}

pub fn main_update_me() -> SyncReturn<bool> {
    // Nothing starts, so the answer is false.
    SyncReturn(unsupported_absence("main_update_me"))
}

pub fn main_goto_install() -> SyncReturn<bool> {
    // False tells the official caller that no installer was started.
    SyncReturn(unsupported_absence("main_goto_install"))
}

/// The build's real install state. The client calls this while it builds its
/// home page, its settings fields and its safety tab, so it must answer: on
/// Windows the shared platform helper reads the actual installation, and on a
/// platform with no installer to have run it is the true "not installed".
pub fn main_is_installed() -> SyncReturn<bool> {
    SyncReturn(platform::is_installed())
}

pub fn main_is_installed_lower_version() -> SyncReturn<bool> {
    // No installed version is recorded, so none of it is lower than this one.
    SyncReturn(false)
}

pub fn main_is_installed_daemon(prompt: bool) -> SyncReturn<bool> {
    let _ = prompt;
    // This artifact has no service/daemon component and nothing to prompt for.
    SyncReturn(false)
}

pub fn main_is_process_trusted(prompt: bool) -> SyncReturn<bool> {
    let _ = prompt;
    // The process holds no accessibility or input-capture trust, and asks for
    // none: it never grabs native input, the Flutter key path does not need it.
    SyncReturn(false)
}

pub fn main_is_can_screen_recording(prompt: bool) -> SyncReturn<bool> {
    let _ = prompt;
    // There is no screen-capture path in a viewer-only artifact, so the
    // capability is genuinely absent.
    SyncReturn(false)
}

pub fn main_is_can_input_monitoring(prompt: bool) -> SyncReturn<bool> {
    let _ = prompt;
    // Same absence: no native input monitoring is implemented here.
    SyncReturn(false)
}

pub fn main_is_share_rdp() -> SyncReturn<bool> {
    // Sharing this machine over RDP is a host capability this artifact has not
    // got.
    SyncReturn(false)
}

pub fn main_set_share_rdp(enable: bool) -> Result<()> {
    unsupported_result("main_set_share_rdp")
}

pub fn install_show_run_without_install() -> Result<SyncReturn<bool>> {
    unsupported_result("install_show_run_without_install")
}

pub fn install_run_without_install() -> Result<()> {
    unsupported_result("install_run_without_install")
}

pub fn install_install_me(options: String, path: String) -> Result<()> {
    unsupported_result("install_install_me")
}

pub fn install_install_path() -> Result<SyncReturn<String>> {
    unsupported_result("install_install_path")
}

pub fn install_install_options() -> Result<SyncReturn<String>> {
    unsupported_result("install_install_options")
}

pub fn main_start_service() -> Result<()> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::acknowledge(crate::host_bridge::HostCommand::Start); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("main_start_service")
}

pub fn main_stop_service() -> Result<()> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::acknowledge(crate::host_bridge::HostCommand::Stop); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("main_stop_service")
}

pub fn main_update_temporary_password() -> Result<()> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::acknowledge(crate::host_bridge::HostCommand::RotateTemporaryPassword); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("main_update_temporary_password")
}

pub fn main_check_super_user_permission() -> Result<bool> {
    unsupported_result("main_check_super_user_permission")
}

pub fn main_get_temporary_password() -> Result<String> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::temporary_password(); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("main_get_temporary_password")
}

pub fn main_set_permanent_password_with_result(password: String) -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        crate::host_bridge::acknowledge(crate::host_bridge::HostCommand::SetPermanentPassword { password })?;
        return Ok(true);
    }
    #[cfg(not(target_os = "windows"))]
    { discard_credential(password); unsupported_result("main_set_permanent_password_with_result") }
}

pub fn main_get_unlock_pin() -> SyncReturn<String> {
    // No unlock pin is ever set by this artifact, and the settings page reads
    // this while it builds, so the true answer is the empty pin.
    SyncReturn(String::new())
}

pub fn main_set_unlock_pin(pin: String) -> SyncReturn<String> {
    // This entry reports failure through its own string: setting a pin would
    // mean storing host lock state this artifact does not keep, so it answers
    // with the reason instead of claiming the pin was stored.
    let _ = pin;
    unsupported("main_set_unlock_pin");
    SyncReturn("Failed, this app does not keep a local unlock pin.".to_owned())
}

pub fn main_generate2fa() -> Result<String> {
    unsupported_result("main_generate2fa")
}

pub fn main_verify2fa(code: String) -> Result<bool> {
    unsupported_result("main_verify2fa")
}

pub fn main_has_valid_2fa_sync() -> SyncReturn<bool> {
    // No host 2FA secret is created or kept here, so no valid 2FA exists. The
    // safety page reads this while it builds.
    SyncReturn(false)
}

pub fn main_verify_bot(token: String) -> Result<String> {
    unsupported_result("main_verify_bot")
}

pub fn main_has_valid_bot_sync() -> SyncReturn<bool> {
    // Same real absence: this artifact has no bot credential.
    SyncReturn(false)
}

// Keep the pinned ABI's old signatures fail-closed. Its patched Dart consumer
// uses the additive scoped methods below; a late unscoped callback cannot be
// distinguished from fresh intent after another process changes the account.
pub fn main_account_auth(op: String, remember_me: bool) -> Result<()> {
    anyhow::bail!("account authentication requires a captured scope receipt")
}

pub fn main_account_auth_cancel() -> Result<()> {
    anyhow::bail!("account authentication cancellation requires its attempt receipt")
}

pub fn main_account_auth_result() -> Result<String> {
    anyhow::bail!("account authentication result requires its attempt receipt")
}

/// One protected view, dispatched on an FRB worker rather than the UI isolate.
/// The returned JSON is private business data, never diagnostic context.
pub fn main_account_snapshot() -> Result<String> {
    account::snapshot()
}

pub fn main_account_set_local_option(
    receipt: String,
    key: String,
    value: String,
) -> Result<String> {
    account::set_local_option_scoped(&receipt, &key, value)
}

/// Cache receipts also bind the selected kind's durable clear revision.
pub fn main_account_cache(
    receipt: String,
    kind: String,
    operation: String,
    value: Option<String>,
) -> Result<String> {
    let kind = match kind.as_str() {
        "ab" => CacheKind::AddressBook,
        "group" => CacheKind::Group,
        _ => {
            if let Some(value) = value {
                discard_credential(value);
            }
            anyhow::bail!("invalid account cache kind");
        }
    };
    account::access_cache_scoped(&receipt, kind, &operation, value)
}

pub fn main_account_auth_scoped(receipt: String, op: String, remember_me: bool) -> Result<String> {
    account::oidc::start(receipt, op, remember_me)
}

pub fn main_account_auth_cancel_scoped(attempt: String) -> Result<()> {
    account::oidc::cancel(&attempt)
}

pub fn main_account_auth_result_scoped(attempt: String) -> Result<String> {
    account::oidc::result(&attempt)
}

/// The client's own avatar rule over this bridge's own API server: a path the
/// account server owns gets the configured server in front of it, anything else
/// (empty, data URI, absolute URL) is returned as it came. The settings page
/// calls this while building, so it answers instead of refusing.
pub fn main_resolve_avatar_url(avatar: String) -> SyncReturn<String> {
    let avatar = avatar.trim().to_owned();
    if avatar.starts_with('/') {
        let api_server = main_get_api_server();
        if !api_server.is_empty() {
            return SyncReturn(format!("{}{}", api_server.trim_end_matches('/'), avatar));
        }
    }
    SyncReturn(avatar)
}

pub fn main_http_request(
    url: String,
    method: String,
    body: Option<String>,
    header: String,
) -> Result<()> {
    account::http::start(url, method, body, header)
}

pub fn main_test_if_valid_server(server: String, test_with_proxy: bool) -> Result<String> {
    Ok(hbb_common::socket_client::test_if_valid_server(
        &server,
        test_with_proxy,
    ))
}

pub fn main_deploy_device(token: String, id: String) -> Result<String> {
    unsupported_result("main_deploy_device")
}

pub fn main_set_socks(_proxy: String, _username: String, _password: String) -> Result<()> {
    anyhow::bail!("unsupported: proxy credentials are not handled by this artifact")
}

pub fn main_get_socks() -> Result<Vec<String>> {
    unsupported_result("main_get_socks")
}

pub fn main_get_proxy_status() -> Result<bool> {
    Ok(Config::get_socks().is_some())
}

pub fn main_save_ab(json: String) -> Result<()> {
    discard_credential(json);
    anyhow::bail!("account cache write requires a captured cache receipt")
}

pub fn main_clear_ab() -> Result<()> {
    anyhow::bail!("account cache clear requires a captured cache receipt")
}

pub fn main_load_ab() -> Result<String> {
    anyhow::bail!("account cache load requires a captured cache receipt")
}

pub fn main_save_group(json: String) -> Result<()> {
    discard_credential(json);
    anyhow::bail!("account cache write requires a captured cache receipt")
}

pub fn main_clear_group() -> Result<()> {
    anyhow::bail!("account cache clear requires a captured cache receipt")
}

pub fn main_load_group() -> Result<String> {
    anyhow::bail!("account cache load requires a captured cache receipt")
}

pub fn main_discover() -> Result<()> {
    let (stream, owner) = lan_context()?;
    let _admission = lock(&LAN_LIFECYCLE);
    ensure!(
        lan_matches(&lock(&APP), &stream, &owner),
        "LAN stream was replaced"
    );
    owner.start().map_err(anyhow::Error::msg)?;
    Ok(())
}

pub fn main_remove_discovered(id: String) -> Result<()> {
    let (stream, owner) = lan_context()?;
    let completion = {
        let _admission = lock(&LAN_LIFECYCLE);
        ensure!(
            lan_matches(&lock(&APP), &stream, &owner),
            "LAN stream was replaced"
        );
        owner
            .request_remove(owner.scan_id(), id)
            .map_err(anyhow::Error::msg)?
    };
    completion.wait_blocking().map_err(anyhow::Error::msg)?;
    // Upstream store is log-only: query the actual cache after its write
    // attempt instead of optimistically announcing permanent deletion.
    let snapshot = owner.query_blocking().map_err(anyhow::Error::msg)?;
    publish_lan_snapshot(&stream, &owner, snapshot)
}

pub fn main_wol(id: String) -> Result<()> {
    unsupported_result("main_wol")
}

/// Creates the shortcut through the real platform helper instead of reporting a
/// refusal the client would never see: its caller shows "Successful" right after
/// this call, so the only honest implementations are one that really creates it
/// or one that fails.
pub fn main_create_shortcut(id: String) -> Result<()> {
    platform::create_shortcut(&id)
}

pub fn main_on_main_window_close() -> Result<()> {
    {
        let _admission = lock(&LAN_LIFECYCLE);
        let retired = invalidate_lan_owner(&mut lock(&APP));
        retire_lan_owner(retired);
    }
    Ok(())
}

pub fn main_test_wallpaper(_second: u64) -> Result<()> {
    unsupported_result("main_test_wallpaper")
}

pub fn main_support_remove_wallpaper() -> Result<bool> {
    unsupported_result("main_support_remove_wallpaper")
}

pub fn main_start_dbus_server() {
    // The client starts this on Linux to receive its own uri links. This bridge
    // has no ipc server, so there is nothing to start.
    no_state("main_start_dbus_server");
}

pub fn main_start_ipc_url_server() {
    no_state("main_start_ipc_url_server");
}

pub fn send_url_scheme(_url: String) -> Result<()> {
    unsupported_result("send_url_scheme")
}

pub fn main_handle_wayland_screencast_restore_token(
    _key: String,
    _value: String,
) -> Result<String> {
    unsupported_result("main_handle_wayland_screencast_restore_token")
}

// ---------------------------------------------------------------------------
// Boot: the connection manager (the host role)
// ---------------------------------------------------------------------------

pub fn cm_init() -> Result<()> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::cm_init(); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_init")
}

pub fn cm_get_clients_state() -> Result<String> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::clients_state(); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_get_clients_state")
}

pub fn cm_get_clients_length() -> Result<usize> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::clients_length(); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_get_clients_length")
}

pub fn cm_check_clients_length(length: usize) -> Result<Option<String>> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::check_clients_length(length); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_check_clients_length")
}

pub fn cm_get_config(name: String) -> Result<String> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::cm_config(&name); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_get_config")
}

pub fn cm_login_res(conn_id: i32, res: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::peer_action(conn_id, crate::host_bridge::PeerAction::Approve { allow:res }); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_login_res")
}

pub fn cm_close_connection(conn_id: i32) -> Result<()> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::peer_action(conn_id, crate::host_bridge::PeerAction::Disconnect); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_close_connection")
}

pub fn cm_close_connection_window(conn_id: i32) -> Result<()> {
    // Windows window close still waits for the same checked peer reclamation.
    cm_close_connection(conn_id)
}

pub fn cm_remove_disconnected_connection(conn_id: i32) -> Result<()> {
    #[cfg(target_os = "windows")]
    { return crate::host_bridge::peer_action(conn_id, crate::host_bridge::PeerAction::Remove); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_remove_disconnected_connection")
}

pub fn cm_check_click_time(conn_id: i32) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        ensure!(crate::host_bridge::snapshot()?.peers.iter().any(|p| p.conn_id == conn_id), "unknown CM connection");
        crate::host_bridge::activity()?;
        return Ok(());
    }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_check_click_time")
}

pub fn cm_get_click_time() -> Result<f64> {
    #[cfg(target_os = "windows")]
    { return Ok(crate::host_bridge::activity()?.click_wall_ms as f64); }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_get_click_time")
}

pub fn cm_switch_permission(conn_id: i32, name: String, enabled: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        ensure!(name == "keyboard", "unsupported CM permission");
        return crate::host_bridge::peer_action(conn_id, crate::host_bridge::PeerAction::Keyboard { enabled });
    }
    #[cfg(not(target_os = "windows"))]
    unsupported_result("cm_switch_permission")
}

pub fn cm_can_elevate() -> SyncReturn<bool> {
    SyncReturn(false)
}

pub fn cm_elevate_portable(_conn_id: i32) -> Result<()> {
    unsupported_result("cm_elevate_portable")
}

pub fn cm_switch_back(_conn_id: i32) -> Result<()> {
    unsupported_result("cm_switch_back")
}

// ---------------------------------------------------------------------------
// Local pointer operations
// ---------------------------------------------------------------------------

/// The local cursor operations relative-mouse mode uses. This bridge never moves
/// or clips the operator's own cursor, so the answer is the same "not applied"
/// the client's own model already handles: it then stops trying to recenter and
/// does not try to release a clip that was never applied.
pub fn main_set_cursor_position(x: i32, y: i32) -> SyncReturn<bool> {
    let _ = (x, y);
    SyncReturn(unsupported_absence("main_set_cursor_position"))
}

pub fn main_clip_cursor(
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    enable: bool,
) -> SyncReturn<bool> {
    let _ = (left, top, right, bottom, enable);
    SyncReturn(unsupported_absence("main_clip_cursor"))
}

/// Setting the input source writes the same local option the client reads back,
/// and only for the source this build has. The native source is refused: there
/// is no grab loop behind it, so accepting it would stop the Flutter key events
/// the client dispatches on without anything taking their place.
pub fn main_set_input_source(session_id: SessionID, value: String) -> Result<()> {
    ensure!(session_record(session_id).is_some(), "unknown session");
    ensure!(
        value == FLUTTER_INPUT_SOURCE,
        "unsupported: no native input grab is implemented here ({NATIVE_INPUT_SOURCE})"
    );
    LocalConfig::set_option(INPUT_SOURCE_OPTION.to_owned(), value);
    Ok(())
}

pub fn main_init_input_source() -> SyncReturn<()> {
    // Boot reaches this before any window exists and its caller cannot handle an
    // error. It enables the one input source this artifact has in the client's
    // own local configuration - the same act upstream performs when its native
    // grab is unavailable - so the client's `isInputSourceFlutter` dispatch and
    // this bridge agree from the first window on.
    LocalConfig::set_option(
        INPUT_SOURCE_OPTION.to_owned(),
        FLUTTER_INPUT_SOURCE.to_owned(),
    );
    SyncReturn(())
}

// ---------------------------------------------------------------------------
// Sessions: the registry
// ---------------------------------------------------------------------------

static SESSIONS: LazyLock<Mutex<HashMap<SessionID, Arc<Session>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static SESSIONS_OF_PEER: LazyLock<Mutex<HashMap<String, Vec<SessionID>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Credential material is session-local only. It is never persisted, returned,
/// logged, or reused after `session_close`.
#[derive(Default)]
struct SessionCredential(Vec<u8>);

impl SessionCredential {
    fn replace(&mut self, value: String) {
        self.clear();
        self.0 = value.into_bytes();
    }

    fn copy_for_viewer(&self) -> String {
        // The bytes originated as a Rust `String`, so this preserved copy is UTF-8.
        unsafe { String::from_utf8_unchecked(self.0.clone()) }
    }

    /// Whether this attempt carries a password at all. The bytes themselves are
    /// never read out of the session for anything but the viewer that needs them.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn clear(&mut self) {
        utils::memzero(&mut self.0);
        self.0.clear();
    }
}

impl Drop for SessionCredential {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Wipes a password that was handed in and is not going to be kept. Consuming the
/// string into bytes keeps this safe: the buffer is zeroed, and no live `String`
/// points at it afterwards.
fn discard_credential(password: String) {
    let mut bytes = password.into_bytes();
    utils::memzero(&mut bytes);
}

/// Everything the bridge knows about one session. Dart holds the id, the engine
/// holds the viewer, and this is what joins the two.
struct Session {
    session_id: SessionID,
    /// Decoded raw peer and immutable route intent, fixed before any peer store.
    peer: String,
    rustdesk_id_only: bool,
    /// Authentication material for this one live session. It is zeroed on
    /// replacement and close and never reaches hbb_common persistence.
    credential: Mutex<SessionCredential>,
    remember: AtomicBool,
    /// The session's event stream, set by `session_start`.
    events: Mutex<Option<StreamSink<EventToUI>>>,
    viewer: Mutex<Option<Arc<Viewer>>>,
    pump: Mutex<Option<JoinHandle<()>>>,
    stop: Mutex<Option<Arc<AtomicBool>>>,
    frames: Arc<FrameStore>,
    delivery: Mutex<(i32, i32)>,
    /// `session_get_option`, `session_get_flutter_option`, the style entries
    /// and the quality/trackpad values: the session's own little store, which
    /// is where the client's core keeps them too.
    options: Mutex<HashMap<String, String>>,
    /// `session_get_toggle_option` and `session_toggle_option`.
    toggles: Mutex<HashMap<String, bool>>,
    /// The cadence the client asked for. The engine's own fps is a login-time
    /// parameter, so this gates what the bridge announces to Dart.
    custom_fps: AtomicI32,
    last_announce: Mutex<Option<Instant>>,
    /// What the peer reported about itself, for `session_get_platform`.
    peer_platform: Mutex<String>,
    /// Explicit, session-scoped acceptance of a RustDesk peer the handshake did
    /// not prove. It is reset whenever a new viewer is started, and it is the
    /// only thing besides the handshake's own verification that opens
    /// `announce_frame`'s publication gate: no path in this bridge sets it on its
    /// own, so an unverified peer is never accepted implicitly.
    unverified_accepted: AtomicBool,
    /// The official Flutter key contract translated into the engine's keyboard
    /// wire: HID or platform key codes, the down/up pairing and the character a
    /// key carries where the protocol wants one. One per session because the
    /// pairing belongs to the session, and cleared whenever a new viewer starts,
    /// whose peer-side key state begins empty.
    keyboard: Mutex<KeyboardState>,
}

impl Session {
    fn new(session_id: SessionID, peer: String, rustdesk_id_only: bool) -> Self {
        Self {
            session_id,
            peer,
            rustdesk_id_only,
            credential: Mutex::new(SessionCredential::default()),
            remember: AtomicBool::new(false),
            events: Mutex::new(None),
            viewer: Mutex::new(None),
            pump: Mutex::new(None),
            stop: Mutex::new(None),
            frames: Arc::new(FrameStore::default()),
            delivery: Mutex::new((0, 0)),
            options: Mutex::new(HashMap::from([(
                "custom-fps".to_owned(),
                DEFAULT_FPS.to_string(),
            )])),
            toggles: Mutex::new(HashMap::new()),
            custom_fps: AtomicI32::new(DEFAULT_FPS),
            last_announce: Mutex::new(None),
            peer_platform: Mutex::new(String::new()),
            unverified_accepted: AtomicBool::new(false),
            keyboard: Mutex::new(KeyboardState::default()),
        }
    }

    fn emit(&self, event: EventToUI) {
        let events = lock(&self.events);
        if let Some(sink) = events.as_ref() {
            if !sink.add(event) {
                // The Dart side closed the stream; the session keeps running,
                // exactly as the core treats a closed sink.
                log::debug!("{}: session stream closed", self.session_id);
            }
        }
    }

    fn emit_json(&self, event: serde_json::Value) {
        self.emit(EventToUI::Event(event.to_string()));
    }

    fn msgbox(&self, kind: &str, title: &str, text: &str, link: &str, retry: bool) {
        self.emit_json(msgbox_event(kind, title, text, link, retry));
    }

    fn fail(&self, error: &str) {
        set_last_error(format!("{}: {error}", self.session_id));
        log::error!("{}: {error}", self.session_id);
        self.msgbox("error", "Connection Error", error, "", true);
    }

    /// The fps gate for announcing a frame. The pixels are always published;
    /// only the announcement is dropped, so the client never reads a stale
    /// buffer, it just decodes fewer times.
    fn announce_allowed(&self) -> bool {
        let fps = self.custom_fps.load(Ordering::Relaxed).clamp(1, 240) as u64;
        let interval = Duration::from_micros(1_000_000 / fps);
        let now = Instant::now();
        let mut last = lock(&self.last_announce);
        if let Some(previous) = *last {
            if now.duration_since(previous) < interval {
                return false;
            }
        }
        *last = Some(now);
        true
    }

    fn option(&self, key: &str) -> Option<String> {
        Some(lock(&self.options).get(key).cloned().unwrap_or_default())
    }

    fn set_option(&self, key: &str, value: String) {
        lock(&self.options).insert(key.to_owned(), value);
    }

    /// The session's real input policy: the operator's read-only switch, which
    /// starts from the peer's own stored `view_only` (and the user default the
    /// shared store merges into it), plus this session's acceptance of a peer
    /// the handshake did not prove.
    fn input_policy(&self) -> ViewerInputPolicy {
        ViewerInputPolicy {
            view_only: lock(&self.toggles)
                .get("view-only")
                .copied()
                .unwrap_or(false),
            unverified_accepted: self.unverified_accepted.load(Ordering::SeqCst),
        }
    }

    /// Whether the attempt the engine just finished carried no password: the
    /// difference between a peer that asked for one and a password that was
    /// rejected. Credential material itself is never read out here.
    fn credential_is_empty(&self) -> bool {
        lock(&self.credential).is_empty()
    }

    /// The client's event for `Password Required`: the peer wants a password
    /// this attempt did not send. One shape for both paths that report it - the
    /// start of an attempt that carried none and a login the engine refused for
    /// that reason - so the client never sees two spellings of one reason.
    fn password_required(&self) {
        self.msgbox("input-password", "Password Required", "", "", false);
    }

    /// The client's event for `Wrong Password`: the peer refused the password
    /// this attempt sent.
    fn wrong_password(&self) {
        self.msgbox(
            "re-input-password",
            "Wrong Password",
            "Do you want to enter again?",
            "",
            false,
        );
    }

    /// The client's event for a login the peer refused for a reason neither
    /// password event names. No credential this client can hold would settle it,
    /// so it is reported as the connection error it is - asking for a password
    /// here would leave the operator in a loop against a refusal no secret can
    /// answer - and in this bridge's own words, because the engine keeps the
    /// peer's own out of every string.
    fn refused_login(&self) {
        self.fail("The remote peer refused this login, and no password can answer it.")
    }

    /// Reports the end of one viewer attempt with the event the official client
    /// has for exactly that outcome. The session's event stream stays open: a
    /// failed attempt ends this viewer, not the UI's session, and its Retry can
    /// only work while the stream it already listens to is still alive.
    ///
    /// A refused login is read from the engine's own category and not inferred
    /// here. `Viewer::finish` publishes `login_failure` beside the unchanged
    /// `error` string for exactly this choice: "a client that has to choose
    /// between a password form and another outcome reads this field instead of
    /// inferring a reason from its own state". This bridge is that client, so
    /// the category picks the event, all three of its categories are consumed,
    /// and the peer's own words stay out of every string.
    fn report_end(&self, snapshot: &ViewerSnapshot) {
        // The engine's category decides outright when there is one, and the match
        // over it is exhaustive so a category cannot be dropped silently: which
        // password event the client gets follows from the category, and the third
        // one is a refusal that no password can answer.
        if let Some(failure) = snapshot.login_failure {
            match failure {
                // `Empty Password`: the peer wants a password this attempt did
                // not send.
                LoginFailure::EmptyPassword => return self.password_required(),
                // `Wrong Password`: the peer refused the password this attempt
                // sent.
                LoginFailure::WrongPassword => return self.wrong_password(),
                // Neither: a policy, an allow-list, or a reason this engine does
                // not classify.
                LoginFailure::Refused => return self.refused_login(),
            }
        }

        // Only the engine's reclaimed terminal metadata disables retry here.
        // Neither a generic error nor arbitrary peer text selects this path.
        if let Some(reason) = snapshot.peer_close_reason {
            let text = match reason {
                PeerCloseReason::ManualRequest => "Closed manually by the peer",
            };
            set_last_error(format!("{}: {text}", self.session_id));
            return self.msgbox("error", "Connection Error", text, "", false);
        }

        // No category: an authentication failure the engine did not classify - the
        // RFB and RDP wires and the RustDesk handshake's own unclassified refusal
        // all report the same `AuthenticationFailed`. Nothing here can tell a
        // refused password from a refused connection, so the event follows from
        // what this session knows: whether the attempt carried a password at all.
        match snapshot.error.as_deref() {
            Some(ENGINE_AUTH_FAILED) if self.credential_is_empty() => self.password_required(),
            Some(ENGINE_AUTH_FAILED) => self.wrong_password(),
            // Two-factor authentication is a real refusal of this build, not a
            // password problem: reporting it as one would ask the user for a
            // secret that cannot help.
            Some(ENGINE_SECOND_FACTOR_UNSUPPORTED) => {
                let text = "The remote peer requires two-factor authentication, which this app does not support.";
                set_last_error(format!("{}: {text}", self.session_id));
                self.msgbox("error", "Connection Error", text, "", false);
            }
            Some(error) => self.fail(error),
            None => {
                // No error and a closed viewer: this attempt ended without one,
                // which is what a local stop looks like. Nothing is invented for
                // it, and the session is not ended for the client.
                log::debug!("{}: viewer finished without an error", self.session_id);
            }
        }
    }

    fn announce_frame(&self) {
        // Serialize geometry and frame events; never announce a new geometry
        // while Dart still holds pixels belonging to the previous one.
        let mut geometry = lock(&self.delivery);
        let Some(viewer) = lock(&self.viewer).clone() else {
            return;
        };
        let mut snapshot = viewer.snapshot();
        if !snapshot.authenticated {
            return;
        }
        // F5: a peer the handshake did not prove publishes nothing until this
        // session's operator accepts it. The gate sits before `publish`, so while
        // it is shut neither a peer_info nor an Rgba event leaves this bridge and
        // no frame bytes become readable either (`FrameStore::size` and `pointer`
        // stay empty until a publish). That is what keeps the client's own trust
        // dialog reachable: its `handlePeerInfo` and its first-frame handling both
        // dismiss the dialogs, and the acceptance `session_set_common` records is
        // the only thing that opens this gate - it is never set here.
        if !snapshot.peer_verified && !self.unverified_accepted.load(Ordering::SeqCst) {
            return;
        }
        // Publishing order, once the gate is open: geometry first, then the frame
        // event that makes the client read the pixels. The geometry is still
        // (0, 0) after an unverified connection, so the first publication of an
        // accepted session is its peer_info, immediately followed by its first
        // frame; a frame event never precedes the geometry it belongs to.
        if !self.announce_allowed() {
            return;
        }
        let Some((width, height)) = self.frames.publish() else {
            return;
        };
        if *geometry != (width, height) {
            let first_geometry = *geometry == (0, 0);
            snapshot.width = width;
            snapshot.height = height;
            self.emit_json(peer_info_event(&snapshot));
            if first_geometry {
                self.msgbox("success", "Successful", WAITING_FOR_IMAGE, "", false);
            }
            *geometry = (width, height);
        }
        self.emit(EventToUI::Rgba(0));
    }

    /// Stops the pump and closes the viewer. Used before a restart and by
    /// `session_close`. The keyboard translator is cleared with it: the next
    /// viewer starts against a peer whose key state is empty, so nothing this
    /// one had down may be carried over as if it were still held.
    ///
    /// The locks are taken in the `viewer` then `keyboard` order the input path
    /// also uses: the viewer is taken first and released before the pump is
    /// joined, and the translator is cleared last, once every event that had
    /// already captured this viewer has finished submitting to it. Taking this
    /// viewer is what tells the input path it is looking at the previous
    /// connection, and that path takes the translator lock while it still holds
    /// the viewer lock (`translated_input_target`), so an event that captured
    /// this viewer is inside its hold before this clear can run and its
    /// translation is wiped with the connection it belonged to. That is what
    /// makes the clear complete rather than racy - a translation held across a
    /// submit cannot outlive this call, and the state the next viewer starts from
    /// is empty.
    fn stop_viewer(&self) {
        self.frames.restart();
        if let Some(stop) = lock(&self.stop).take() {
            stop.store(true, Ordering::SeqCst);
        }
        if let Some(viewer) = lock(&self.viewer).take() {
            viewer.request_close();
        }
        if let Some(pump) = lock(&self.pump).take() {
            let _ = pump.join();
        }
        lock(&self.keyboard).clear();
    }
}

/// What the viewer installs on the memory sink it creates for this bridge.
struct BridgeLease {
    observer: Arc<dyn FrameObserver>,
}

// SAFETY: the trait wants an id that is stable for the lease's life, and the
// memory sink off OpenHarmony never reads one.
unsafe impl SurfaceLease for BridgeLease {
    fn surface_id(&self) -> u64 {
        0
    }

    /// This lease is ready without a Surface, because the observer below *is*
    /// its surface.
    ///
    /// The trait's default reads the id, and `0` is the value that says this
    /// bridge binds no Surface at all: off OpenHarmony the sink this lease opens
    /// is a memory buffer that publishes through `frame_observer` (`Sink::open`),
    /// so waiting for an id that never arrives would hold every rectangle
    /// session (RFB and RDP) in `awaiting_surface` until its timeout and then
    /// fail it with `UnsupportedPlatform`. Readiness is therefore named here as
    /// the observer's presence - the same condition `Sink::open` needs before it
    /// can publish anything - rather than answered as a bare `true`, and the
    /// override is on this bridge's own lease alone: a lease with no observer and
    /// no Surface keeps the trait's own answer instead of counting as ready, as
    /// the OpenHarmony Surface lease and the test lease do.
    fn is_ready(&self) -> bool {
        self.frame_observer().is_some()
    }

    fn frame_observer(&self) -> Option<Arc<dyn FrameObserver>> {
        Some(self.observer.clone())
    }
}

/// The engine's observer for one session. Weak on purpose: the viewer holds the
/// lease for as long as it runs, and a strong reference here would keep the
/// session record alive after Dart closed it.
struct SessionObserver {
    session: Weak<Session>,
    frames: Arc<FrameStore>,
    generation: u64,
}

impl FrameObserver for SessionObserver {
    fn frame(&self, width: i32, height: i32, stride: usize, bytes: &[u8], damage: Rect) {
        if !self
            .frames
            .present(self.generation, width, height, stride, bytes, damage)
        {
            return;
        }
        let session = match self.session.upgrade() {
            Some(session) => session,
            None => return,
        };
        session.announce_frame();
    }
}

fn session_record(session_id: SessionID) -> Option<Arc<Session>> {
    lock(&SESSIONS).get(&session_id).cloned()
}

// This registry outlives the session only while an actual Dart frame loan
// remains. Never evict a borrowed pointer on timeout or on close.
static FRAME_OWNERS: LazyLock<Mutex<HashMap<SessionID, Arc<FrameStore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A session id this bridge refused at creation, with the reason and - once the
/// client starts it anyway - the stream it is listening to.
///
/// The official client ignores `session_add_sync`'s answer and starts the
/// session regardless, so a refusal has to be a state rather than only a return
/// value: it holds no credential, no viewer and no frame store, it is not
/// counted as a live session, and both `session_start` and `session_reconnect`
/// refuse out of it. It cannot become a normal connection by being retried,
/// because the retry the client sends carries the same session id; only
/// `session_close` clears it.
struct RejectedSession {
    reason: String,
    events: Mutex<Option<StreamSink<EventToUI>>>,
}

static REJECTED: LazyLock<Mutex<HashMap<SessionID, Arc<RejectedSession>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn reject(session_id: SessionID, reason: String) -> Arc<RejectedSession> {
    let rejection = Arc::new(RejectedSession {
        reason,
        events: Mutex::new(None),
    });
    lock(&REJECTED).insert(session_id, rejection.clone());
    rejection
}

fn rejection_of(session_id: SessionID) -> Option<Arc<RejectedSession>> {
    lock(&REJECTED).get(&session_id).cloned()
}

/// The visible half of a refusal: the client shows the same message box it shows
/// for a connection error, without the retry, because retrying here would rebuild
/// the connection the refusal is about.
fn refuse_session(session_id: SessionID, rejection: &Arc<RejectedSession>) {
    log::error!("{session_id}: {}", rejection.reason);
    set_last_error(format!("{session_id}: {}", rejection.reason));
    let event = msgbox_event("error", "Connection Error", &rejection.reason, "", false);
    let events = lock(&rejection.events);
    if let Some(sink) = events.as_ref() {
        let _ = sink.add(EventToUI::Event(event.to_string()));
    }
}

fn session_get_or_insert(session_id: SessionID, peer: String, rustdesk_id_only: bool) -> Result<Arc<Session>> {
    let session = {
        let mut sessions = lock(&SESSIONS);
        match sessions.get(&session_id) {
            Some(session) => {
                ensure!(session.peer == peer && session.rustdesk_id_only == rustdesk_id_only,
                    "session identity or route intent changed; close it and use a fresh session ID");
                return Ok(session.clone());
            }
            None => {
                let mut owners = lock(&FRAME_OWNERS);
                if owners.contains_key(&session_id) {
                    anyhow::bail!("session ID still owns an unreleased frame; use a fresh UUID");
                }
                let session = Arc::new(Session::new(session_id, peer, rustdesk_id_only));
                owners.insert(session_id, session.frames.clone());
                sessions.insert(session_id, session.clone());
                session
            }
        }
    };
    let peer = &session.peer;
    // The peer's stored configuration is the one source of this session's
    // initial values, read once, using only the decoded raw peer. The pinned
    // PeerConfig::load merges the user's defaults with the stored peer values.
    // Unsupported image-quality/codec selections are deliberately not seeded.
    let config = PeerConfig::load(peer);
    // Seed the client's local canvas/window state before the typed preferences.
    for (key, value) in &config.ui_flutter {
        session.set_option(key, value.clone());
    }
    lock(&session.toggles).insert("view-only".to_owned(), config.view_only.v);
    session.set_option("view-style", config.view_style);
    session.set_option("scroll-style", config.scroll_style);
    session.set_option(
        "edge-scroll-edge-thickness",
        config.edge_scroll_edge_thickness.to_string(),
    );
    session.set_option("trackpad-speed", config.trackpad_speed.to_string());
    session.set_option("reverse-mouse-wheel", config.reverse_mouse_wheel);
    session.set_option(
        "displays-as-individual-windows",
        config.displays_as_individual_windows,
    );
    session.set_option(
        "use-all-my-displays-for-the-remote-session",
        config.use_all_my_displays_for_the_remote_session,
    );
    if let Some(fps) = config
        .options
        .get("custom-fps")
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|fps| (1..=240).contains(fps))
    {
        session.custom_fps.store(fps, Ordering::SeqCst);
        session.set_option("custom-fps", fps.to_string());
    }
    let mut peers = lock(&SESSIONS_OF_PEER);
    let entry = peers.entry(peer.clone()).or_default();
    if !entry.contains(&session_id) {
        entry.push(session_id);
    }
    Ok(session)
}

fn sessions_of_peer(peer: &str) -> usize {
    lock(&SESSIONS_OF_PEER)
        .get(peer)
        .map(|sessions| sessions.len())
        .unwrap_or(0)
}

/// The client's own counter: how many sessions this peer has open. One session
/// per window is what this bridge keeps, so a known peer answers with the
/// windows the client opened for it.
pub fn peer_get_sessions_count(id: String, conn_type: i32) -> SyncReturn<usize> {
    let _ = conn_type;
    SyncReturn(sessions_of_peer(&id))
}

// ---------------------------------------------------------------------------
// Sessions: lifecycle
// ---------------------------------------------------------------------------

/// Where a session dials. Only an explicit unmarked target can select direct;
/// discovery/cache-derived intent remains ID-only even when the ID looks like IP.
enum Route {
    Direct(SocketAddr),
    Rendezvous(RendezvousConfig),
}

const ID_ONLY_PREFIX: &str = "rd-engine-id-only-v1://";
const ID_ONLY_NAMESPACE: &str = "rd-engine-id-only";

fn decode_session_target(id: String) -> Result<(String, bool)> {
    let (peer, rustdesk_id_only) = if let Some(encoded) = id.strip_prefix(ID_ONLY_PREFIX) {
        // Same 512-byte peer bound as the existing route admission; limit the
        // envelope before allocation. This engine rejects padding/trailing bits.
        ensure!(!encoded.is_empty() && encoded.len() <= 4 * ((512 + 2) / 3), "invalid ID-only route envelope");
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| anyhow::anyhow!("invalid ID-only route encoding"))?;
        let peer = String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("ID-only route peer is not UTF-8"))?;
        (peer, true)
    } else {
        (id, false)
    };
    let raw = peer.trim();
    ensure!(!raw.is_empty() && raw.len() <= 512, "invalid peer id or direct address");
    ensure!(!raw.contains("://") && !raw.get(..ID_ONLY_NAMESPACE.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(ID_ONLY_NAMESPACE)),
        "unsupported, malformed or nested route envelope");
    Ok((peer, rustdesk_id_only))
}

fn resolve(session: &Session) -> Result<Route> {
    if !session.rustdesk_id_only {
        if let Some(address) = direct_address(&session.peer) {
            return Ok(Route::Direct(address));
        }
    }
    // Prepare the mandatory ID route once, before any existing viewer is retired.
    Ok(Route::Rendezvous(rendezvous_config(&session.peer)?))
}

fn rendezvous_config(peer: &str) -> Result<RendezvousConfig> {
    let rendezvous_server = Config::get_rendezvous_server();
    ensure!(
        !rendezvous_server.is_empty(),
        "rendezvous server is not configured"
    );
    let configured_key = Config::get_option("key");
    let licence_key = if configured_key.is_empty() {
        RS_PUB_KEY.to_owned()
    } else {
        configured_key
    };
    let decoded = STANDARD
        .decode(licence_key.as_bytes())
        .map_err(|_| anyhow::anyhow!("configured rendezvous key is not valid base64"))?;
    let server_key = sign::PublicKey::from_slice(&decoded)
        .ok_or_else(|| anyhow::anyhow!("configured rendezvous key is not a public key"))?;
    let relay = Config::get_option("relay-server");
    Ok(RendezvousConfig {
        id: peer.to_owned(),
        rendezvous_server,
        licence_key,
        server_key,
        relay_server: (!relay.is_empty()).then_some(relay),
        connect_timeout: RENDEZVOUS_TIMEOUT,
    })
}

/// Starts the viewer and the pump that reports it to Dart. Only after transport
/// admission may a login/reconnect close the existing viewer: the engine takes
/// its password and target when it starts.
fn start_viewer(session: &Arc<Session>) -> Result<()> {
    let peer = &session.peer;
    ensure!(!peer.is_empty(), "session has no peer id or direct address");
    ensure!(
        rejection_of(session.session_id).is_none(),
        "this session was refused at creation and cannot become a connection"
    );
    // Neither direct IP nor rendezvous implements the configured proxy/WS
    // transport. Do not silently dial raw TCP or dismantle an existing viewer.
    let proxy = Config::is_proxy();
    let websocket = hbb_common::config::use_ws();
    ensure!(
        !proxy && !websocket,
        "unsupported: configured proxy/WebSocket viewer transport is not supported; no new connection was started"
    );

    // Missing hbbs or malformed signing configuration is an admission refusal,
    // not a reason to dismantle the current viewer or restart its frame store.
    let route = resolve(session)?;
    let local_id = my_id();
    ensure!(
        !local_id.is_empty(),
        "persistent RustDesk identity is unavailable"
    );

    session.unverified_accepted.store(false, Ordering::SeqCst);
    session.stop_viewer();
    let generation = session.frames.restart();
    *lock(&session.delivery) = (0, 0);
    *lock(&session.last_announce) = None;

    let requested_fps = session.custom_fps.load(Ordering::Relaxed).clamp(1, 240) as u32;
    let target = match &route {
        Route::Direct(address) => ViewerTarget::RustDesk {
            address: Some(*address),
        },
        Route::Rendezvous(_) => ViewerTarget::RustDesk { address: None },
    };
    let password = lock(&session.credential).copy_for_viewer();
    let password_was_empty = password.is_empty();
    let options = ViewerOptions {
        target,
        username: peer.clone(),
        local_id,
        local_name: local_name(),
        password,
        requested_fps,
        input_policy: session.input_policy(),
    };
    let lease: Arc<dyn SurfaceLease> = Arc::new(BridgeLease {
        observer: Arc::new(SessionObserver {
            session: Arc::downgrade(session),
            frames: session.frames.clone(),
            generation,
        }),
    });
    let viewer = match route {
        Route::Direct(_) => Viewer::start(options, lease),
        Route::Rendezvous(config) => Viewer::start_rendezvous(options, lease, config),
    }
    .map_err(|error| anyhow::anyhow!("viewer start failed: {error}"))?;

    *lock(&session.viewer) = Some(viewer.clone());
    spawn_pump(session, viewer, password_was_empty);
    Ok(())
}

/// The task that turns the viewer's own state into the client's events. The
/// engine drives authentication inside `Viewer::start`, so the bridge polls the
/// snapshot instead of draining a stream: what the client needs is a
/// connection_ready when the session is authenticated, a peer_info when the
/// peer's geometry is known, and - for each attempt - the event that matches what
/// really happened: a password form, the peer's approval wait, the trust
/// question for a peer the handshake did not prove, or the failure the client's
/// Retry can act on.
fn spawn_pump(session: &Arc<Session>, viewer: Arc<Viewer>, password_was_empty: bool) {
    let stop = Arc::new(AtomicBool::new(false));
    *lock(&session.stop) = Some(stop.clone());
    let weak = Arc::downgrade(session);
    let result = std::thread::Builder::new()
        .name(format!("rd-engine-flutter-{}", session.session_id))
        .spawn(move || pump(weak, viewer, stop, password_was_empty));
    match result {
        Ok(handle) => *lock(&session.pump) = Some(handle),
        Err(error) => log::error!("{}: cannot start the pump: {error}", session.session_id),
    }
}

fn pump(weak: Weak<Session>, viewer: Arc<Viewer>, stop: Arc<AtomicBool>, password_was_empty: bool) {
    let mut announced_ready = false;
    let mut asked_for_password = false;
    let mut announced_approval = false;
    let mut announced_insecure = false;
    let mut last_error = String::new();
    while !stop.load(Ordering::SeqCst) {
        let Some(session) = weak.upgrade() else {
            return;
        };
        let snapshot = viewer.snapshot();
        if !snapshot.authenticated {
            // The official client asks for the password as soon as it logs in
            // without one - the peer's operator may still accept the request,
            // but this dialog is the only way the user can supply the secret.
            if password_was_empty && !asked_for_password {
                asked_for_password = true;
                session.password_required();
            }
            // The engine's own waiting state: the peer answered that it grants
            // no password access, so its operator has to accept this request.
            if snapshot.phase == ENGINE_AWAITING_APPROVAL && !announced_approval {
                announced_approval = true;
                session.msgbox(
                    "wait-remote-accept-nook",
                    "Prompt",
                    "Please wait for the remote side to accept your session request...",
                    "",
                    false,
                );
            }
        }
        if !announced_ready && snapshot.authenticated {
            announced_ready = true;
            session.emit_json(json!({
                "name": "connection_ready",
                "secure": snapshot.encrypted.to_string(),
                "direct": (snapshot.route != "relay").to_string(),
                "stream_type": "",
            }));
        }
        // Trust comes from the handshake's own evidence, and it is asked for once
        // per viewer: a peer this dial could not prove gets no input until this
        // session's operator accepts it, and that acceptance is never carried
        // into the next viewer.
        if snapshot.authenticated
            && snapshot.protocol == "rustdesk"
            && !snapshot.peer_verified
            && !announced_insecure
        {
            announced_insecure = true;
            session.msgbox(
                "insecure-connection-nocancel-hasclose",
                "Insecure Connection",
                "conn-e2ee-unavailable-tip",
                "",
                false,
            );
        }
        if !snapshot.platform.is_empty() {
            *lock(&session.peer_platform) = snapshot.platform.clone();
        }
        session.announce_frame();
        if let Some(error) = snapshot.error.as_ref() {
            if *error != last_error {
                last_error = error.clone();
                set_last_error(format!("{}: {error}", session.session_id));
            }
        }
        if snapshot.closed {
            session.report_end(&snapshot);
            // The stream stays open on purpose. This is the end of one viewer,
            // not of the client's session: its Retry calls `session_reconnect`,
            // which starts a new viewer into this same stream, and a `close`
            // event here would make the client drop every event of that retry.
            return;
        }
        drop(session);
        std::thread::sleep(PUMP_POLL);
    }
}

/// The peer_info the client's `handlePeerInfo` parses: numbers as numbers, JSON
/// blobs as strings, and displays as a JSON string of objects.
fn peer_info_event(snapshot: &ViewerSnapshot) -> serde_json::Value {
    let width = snapshot.width;
    let height = snapshot.height;
    let index = usize::try_from(snapshot.current_display).unwrap_or(0);
    let display = snapshot.displays.get(index);
    let original_width = display
        .map(|display| display.original_width)
        .filter(|width| *width > 0)
        .unwrap_or(width);
    let original_height = display
        .map(|display| display.original_height)
        .filter(|height| *height > 0)
        .unwrap_or(height);
    let cursor_embedded = display
        .map(|display| display.cursor_embedded)
        .unwrap_or(false);
    // The client decodes the frame at displays[0]'s size, so that entry is the
    // geometry the engine presents - one display, because one is what this
    // bridge publishes.
    let displays = json!([{
        "x": 0,
        "y": 0,
        "width": width,
        "height": height,
        "cursor_embedded": if cursor_embedded { 1 } else { 0 },
        "original_width": original_width,
        "original_height": original_height,
    }]);
    json!({
        "name": "peer_info",
        // The engine's snapshot carries the peer's platform, version and
        // geometry but not its user or host name, and this bridge will not
        // invent them.
        "username": "",
        "hostname": "",
        "platform": snapshot.platform,
        "sas_enabled": "false",
        "displays": displays.to_string(),
        "version": snapshot.version,
        "features": json!({ "privacy_mode": false }).to_string(),
        "current_display": "0",
        "resolutions": "[]",
        "platform_additions": "",
    })
}

/// The peer's own saved routing requirement, merged the way the pinned client
/// merges it: `force-always-relay` is the peer's decision and the caller's
/// `force_relay` is added to it, never a substitute for it.
fn peer_forces_relay(peer: &str) -> bool {
    let stored = PeerConfig::load(peer)
        .options
        .get("force-always-relay")
        .cloned()
        .unwrap_or_default();
    hbb_common::config::option2bool("force-always-relay", &stored)
}

/// The client's session creation. Every parameter this bridge can refuse is
/// checked before it touches a session record, the recent-peer id or the
/// credential, so a refusal cannot leave a runnable session, a stored secret or a
/// live-session count behind. The client ignores the returned error and starts
/// the session anyway, so the refusal is also recorded against that session id
/// and answered there.
pub fn session_add_sync(
    session_id: SessionID,
    id: String,
    is_file_transfer: bool,
    is_port_forward: bool,
    is_rdp: bool,
    is_terminal: bool,
    switch_uuid: String,
    force_relay: bool,
    password: String,
    is_shared_password: bool,
    conn_token: Option<String>,
) -> SyncReturn<String> {
    let _ = is_shared_password;
    let (id, rustdesk_id_only) = match decode_session_target(id) {
        Ok(target) => target,
        Err(error) => {
            let reason = error.to_string();
            discard_credential(password);
            if session_record(session_id).is_none() { reject(session_id, reason.clone()); }
            return SyncReturn(format!("err={reason}"));
        }
    };
    if let Some(session) = session_record(session_id) {
        if session.peer != id || session.rustdesk_id_only != rustdesk_id_only {
            discard_credential(password);
            return SyncReturn("err=session identity or route intent changed; close it and use a fresh session ID".to_owned());
        }
    }
    let kind = if is_file_transfer {
        Some("file transfer")
    } else if is_port_forward {
        Some("port forward")
    } else if is_rdp {
        Some("RDP")
    } else if is_terminal {
        Some("terminal")
    } else {
        None
    };
    // None of these is a label the client may ignore: switching sides and the
    // connection token carry real login semantics, and a forced relay is a
    // routing decision this engine cannot honour.
    let refusal = if let Some(kind) = kind {
        Some(format!("unsupported: {kind} session"))
    } else if !switch_uuid.is_empty() {
        Some("unsupported: switching sides is not implemented".to_owned())
    } else if conn_token.as_deref().is_some_and(|token| !token.is_empty()) {
        Some("unsupported: connection-token login is not implemented".to_owned())
    } else if force_relay || peer_forces_relay(&id) {
        Some("unsupported: forced relay is not implemented by this engine".to_owned())
    } else {
        None
    };
    match refusal {
        Some(reason) => {
            // The password this call carried is wiped and dropped with it: a
            // refused session keeps no credential, so a refused password does
            // not outlive the call that was refused.
            discard_credential(password);
            reject(session_id, reason.clone());
            unsupported("session_add_sync");
            SyncReturn(format!("err={reason}"))
        }
        None => {
            let session = match session_get_or_insert(session_id, id, rustdesk_id_only) {
                Ok(session) => session,
                Err(error) => {
                    let reason = error.to_string();
                    discard_credential(password);
                    if session_record(session_id).is_none() { reject(session_id, reason.clone()); }
                    return SyncReturn(format!("err={reason}"));
                }
            };
            // A creation with valid parameters is a new request for this id, so
            // any earlier refusal for it is over.
            lock(&REJECTED).remove(&session_id);
            LocalConfig::set_remote_id(&session.peer);
            lock(&session.credential).replace(password);
            SyncReturn(String::new())
        }
    }
}

/// Adopting a session that already exists into another window. One viewer per
/// session is what this bridge runs, and a second window would need a second
/// renderer for it, so this refuses. The refusal is the string result the
/// official caller checks (`model.dart` returns early on a non-empty answer)
/// rather than an error the synchronous call could not deliver.
pub fn session_add_existed_sync(
    id: String,
    session_id: SessionID,
    displays: Vec<i32>,
) -> SyncReturn<String> {
    let _ = (id, session_id, displays);
    unsupported("session_add_existed_sync");
    SyncReturn("err=unsupported: one window per session".to_owned())
}

pub fn session_start(
    events2ui: StreamSink<EventToUI>,
    session_id: SessionID,
    id: String,
) -> Result<()> {
    if let Some(rejection) = rejection_of(session_id) {
        // The client starts a session it was just refused. It gets a real
        // stream carrying that refusal and nothing else; the stream stays open
        // so the client's own Close still reaches `session_close` and ends the
        // record. No viewer, no credential and no peer record are created here.
        *lock(&rejection.events) = Some(events2ui);
        refuse_session(session_id, &rejection);
        return Ok(());
    }
    let (peer, rustdesk_id_only) = decode_session_target(id)?;
    let session = session_get_or_insert(session_id, peer, rustdesk_id_only)?;
    *lock(&session.events) = Some(events2ui);
    if let Err(error) = start_viewer(&session) {
        session.fail(&error.to_string());
    }
    // This Result acknowledges stream registration, not connection success.
    // A FRB Stream Err terminates Dart's listener and would break manual Retry.
    Ok(())
}

pub fn session_start_with_displays(
    events2ui: StreamSink<EventToUI>,
    session_id: SessionID,
    id: String,
    displays: Vec<i32>,
) -> Result<()> {
    ensure!(
        displays.iter().all(|display| *display == 0),
        "unsupported: only display 0 is published"
    );
    session_start(events2ui, session_id, id)
}

/// Login. The engine authenticates inside `Viewer::start` with the password it
/// was given, so a password that arrives after a failed attempt restarts the
/// viewer with it - the same outcome the client's own core reaches by retrying
/// the login on the connection it kept.
pub fn session_login(
    session_id: SessionID,
    os_username: String,
    os_password: String,
    password: String,
    remember: bool,
) -> Result<()> {
    ensure!(
        os_username.is_empty() && os_password.is_empty(),
        "unsupported: OS-credential login is not implemented"
    );
    ensure!(!remember, "unsupported: credential persistence is disabled");
    if let Some(rejection) = rejection_of(session_id) {
        anyhow::bail!("unsupported: {}", rejection.reason);
    }
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    session.remember.store(false, Ordering::SeqCst);
    lock(&session.credential).replace(password);
    start_viewer(&session).inspect_err(|error| session.fail(&error.to_string()))
}

pub fn session_close(session_id: SessionID) {
    // A refused session id ends with the session it was recorded for; there is
    // no other way to clear it, so a retry can never outlive the client's close.
    lock(&REJECTED).remove(&session_id);
    let session = lock(&SESSIONS).remove(&session_id);
    if let Some(session) = session {
        session.stop_viewer();
        lock(&session.credential).clear();
        let mut owners = lock(&FRAME_OWNERS);
        if session.frames.close() {
            owners.remove(&session_id);
        }
        *lock(&session.events) = None;
        let peer = &session.peer;
        let mut peers = lock(&SESSIONS_OF_PEER);
        if let Some(sessions) = peers.get_mut(peer) {
            sessions.retain(|id| *id != session_id);
            if sessions.is_empty() {
                peers.remove(peer);
            }
        }
    }
}

pub fn session_reconnect(session_id: SessionID, force_relay: bool) -> Result<()> {
    ensure!(!force_relay, "unsupported: forced relay is not implemented");
    if let Some(rejection) = rejection_of(session_id) {
        // A reconnect is not a way round the refusal: it carries the same
        // session id, and the client's Retry always sends it with
        // `force_relay=false`, which is not the user withdrawing the routing
        // requirement the refusal was about. The refusal is shown again and no
        // ordinary connection is built under it.
        refuse_session(session_id, &rejection);
        anyhow::bail!("unsupported: {}", rejection.reason);
    }
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    start_viewer(&session).inspect_err(|error| session.fail(&error.to_string()))
}

pub fn session_refresh(session_id: SessionID, display: usize) -> Result<()> {
    ensure!(display == 0, "unsupported display");
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let viewer = lock(&session.viewer)
        .clone()
        .ok_or_else(|| anyhow::anyhow!("viewer is not running"))?;
    viewer
        .request_keyframe()
        .map_err(|error| anyhow::anyhow!("keyframe request refused: {error}"))
}

/// Accept the client's local viewport notification. Presentation remains at the
/// peer's geometry; this does not resize the peer or create a second viewport.
pub fn session_set_size(
    session_id: SessionID,
    display: usize,
    width: usize,
    height: usize,
) -> Result<()> {
    ensure!(session_record(session_id).is_some(), "unknown session");
    ensure!(display == 0, "unsupported display");
    ensure!(width > 0 && height > 0, "invalid viewport size");
    // The engine renders at the peer's negotiated geometry. This is only the
    // official client's local layout notification; no remote geometry claim is
    // made and no encoder setting is altered.
    Ok(())
}

pub fn session_set_custom_fps(session_id: SessionID, fps: i32) -> Result<()> {
    ensure!(
        (1..=240).contains(&fps),
        "requested FPS must be between 1 and 240"
    );
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    session.custom_fps.store(fps, Ordering::SeqCst);
    // The engine takes fps as a login parameter, so the value the session
    // reports is the one the viewer really started with.
    session.set_option("custom-fps", fps.to_string());
    let running = lock(&session.viewer)
        .as_ref()
        .map(|viewer| !viewer.snapshot().closed)
        .unwrap_or(false);
    if running {
        start_viewer(&session)?;
    }
    Ok(())
}

/// The engine's encoder decision is its own and it exposes no way to change the
/// peer's image quality. The client shows a successful set as the new selection
/// and reads it back, so this refuses instead of recording a value the next
/// connection would not use.
pub fn session_set_image_quality(session_id: SessionID, value: String) -> Result<()> {
    ensure!(session_record(session_id).is_some(), "unknown session");
    let _ = value;
    unsupported_result("session_set_image_quality")
}

/// No quality setting is in force here: nothing was applied, so there is no
/// value to read back. The client takes the absence as "use the default" rather
/// than as a selection the user made.
pub fn session_get_image_quality(session_id: SessionID) -> Option<String> {
    let _ = session_record(session_id)?;
    no_state("session_get_image_quality");
    None
}

pub fn session_set_custom_image_quality(session_id: SessionID, value: i32) -> Result<()> {
    ensure!(session_record(session_id).is_some(), "unknown session");
    let _ = value;
    unsupported_result("session_set_custom_image_quality")
}

pub fn session_get_custom_image_quality(session_id: SessionID) -> Option<Vec<i32>> {
    let _ = session_record(session_id)?;
    no_state("session_get_custom_image_quality");
    None
}

pub fn session_get_trackpad_speed(session_id: SessionID) -> Option<i32> {
    let session = session_record(session_id)?;
    let speed = lock(&session.options)
        .get("trackpad-speed")
        .and_then(|value| value.parse::<i32>().ok());
    Some(speed.unwrap_or(DEFAULT_TRACKPAD_SPEED))
}

pub fn session_set_trackpad_speed(session_id: SessionID, value: i32) {
    if let Some(session) = session_record(session_id) {
        session.set_option("trackpad-speed", value.to_string());
    }
}

pub fn session_get_remember(session_id: SessionID) -> Option<bool> {
    let session = session_record(session_id)?;
    Some(session.remember.load(Ordering::SeqCst))
}

pub fn session_get_enable_trusted_devices(session_id: SessionID) -> SyncReturn<bool> {
    let _ = session_record(session_id);
    SyncReturn(false)
}

pub fn will_session_close_close_session(session_id: SessionID) -> SyncReturn<bool> {
    // One session per peer in this bridge, so closing it closes the peer.
    let _ = session_record(session_id);
    SyncReturn(true)
}

pub fn session_is_multi_ui_session(session_id: SessionID) -> SyncReturn<bool> {
    let _ = session_record(session_id);
    SyncReturn(false)
}

pub fn session_get_conn_token(session_id: SessionID) -> SyncReturn<Option<String>> {
    let _ = session_record(session_id);
    no_state("session_get_conn_token");
    SyncReturn(None)
}

pub fn session_get_conn_session_id(session_id: SessionID) -> SyncReturn<String> {
    SyncReturn(
        session_record(session_id)
            .map(|session| session.session_id.to_string())
            .unwrap_or_default(),
    )
}

pub fn session_get_platform(session_id: SessionID, is_remote: bool) -> String {
    let session = match session_record(session_id) {
        Some(session) => session,
        None => return String::new(),
    };
    if is_remote {
        lock(&session.peer_platform).clone()
    } else {
        std::env::consts::OS.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Sessions: options, styles and toggles the client stores per session
// ---------------------------------------------------------------------------

/// The client's session-scoped option read, on the synchronous side of the
/// bridge on purpose.
///
/// Every handwritten call site in the pinned client `await`s this answer
/// (`flutter/lib/models/model.dart:1408`, `flutter/lib/common/widgets/toolbar.dart:156`,
/// `flutter/lib/common/widgets/dialog.dart:1443`, `remote_toolbar.dart:532`,
/// `custom_scale_base.dart:112`), so a `SyncReturn` hands them exactly the value
/// they already read. What changes is the order: the answer no longer needs a
/// worker of the FRB pool, so the awaiting caller resumes on the microtask queue
/// rather than whenever a worker picks the task up. A session setting asked
/// while an event is being handled - a view style, a scroll style - is therefore
/// read within that handling instead of racing the next event of the stream,
/// which is the whole point of a synchronous getter here.
pub fn session_get_option(session_id: SessionID, arg: String) -> SyncReturn<Option<String>> {
    if configuration::is_credential_key(&arg) {
        // The same policy as every other option entry: a credential value is
        // never handed out, and absence is the honest answer for it.
        no_state("session_get_option: credential value withheld");
        return SyncReturn(Some(String::new()));
    }
    SyncReturn(session_record(session_id).and_then(|session| session.option(&arg)))
}

/// The client's session-scoped peer option. A credential key is refused here
/// like everywhere else, so the session store cannot become a second, obvious
/// place where a peer's RDP or OS password is kept.
pub fn session_peer_option(session_id: SessionID, name: String, value: String) -> Result<()> {
    ensure!(
        !configuration::is_credential_key(&name),
        "unsupported: credential persistence is disabled"
    );
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    session.set_option(&name, value);
    Ok(())
}

pub fn session_get_peer_option(session_id: SessionID, name: String) -> String {
    if configuration::is_credential_key(&name) {
        return String::new();
    }
    match session_record(session_id) {
        Some(session) => session.option(&name).unwrap_or_default(),
        None => String::new(),
    }
}

pub fn session_get_toggle_option(session_id: SessionID, arg: String) -> Option<bool> {
    let session = session_record(session_id)?;
    if arg == "view-only" {
        return Some(session.input_policy().view_only);
    }
    None
}

pub fn session_get_toggle_option_sync(session_id: SessionID, arg: String) -> SyncReturn<bool> {
    SyncReturn(session_get_toggle_option(session_id, arg).unwrap_or(false))
}

/// The client's toggle switches. `view-only` is the one the engine really
/// enforces, so flipping it here changes what the live viewer admits and writes
/// the same decision back to the peer's stored configuration - the source the
/// next session for this peer reads.
pub fn session_toggle_option(session_id: SessionID, value: String) -> Result<()> {
    ensure!(value == "view-only", "unsupported session toggle");
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let next = !session.input_policy().view_only;
    lock(&session.toggles).insert("view-only".to_owned(), next);
    let peer = &session.peer;
    if !peer.is_empty() {
        let mut config = PeerConfig::load(peer);
        config.view_only.v = next;
        config.store(peer);
    }
    if let Some(viewer) = lock(&session.viewer).clone() {
        let mut policy = viewer.input_policy();
        policy.view_only = next;
        viewer.set_input_policy(policy);
    }
    Ok(())
}

pub fn session_get_flutter_option(session_id: SessionID, k: String) -> Option<String> {
    let session = session_record(session_id)?;
    if configuration::is_credential_key(&k) {
        return Some(String::new());
    }
    session.option(&k)
}

pub fn session_set_flutter_option(session_id: SessionID, k: String, v: String) {
    if configuration::is_credential_key(&k) {
        log::error!("session_set_flutter_option: refused credential key {k}");
        return;
    }
    if let Some(session) = session_record(session_id) {
        session.set_option(&k, v);
    }
}

pub fn session_get_view_style(session_id: SessionID) -> Option<String> {
    let session = session_record(session_id)?;
    session.option("view-style")
}

pub fn session_set_view_style(session_id: SessionID, value: String) {
    if let Some(session) = session_record(session_id) {
        session.set_option("view-style", value);
    }
}

pub fn session_get_scroll_style(session_id: SessionID) -> Option<String> {
    let session = session_record(session_id)?;
    session.option("scroll-style")
}

pub fn session_set_scroll_style(session_id: SessionID, value: String) {
    if let Some(session) = session_record(session_id) {
        session.set_option("scroll-style", value);
    }
}

pub fn session_get_edge_scroll_edge_thickness(session_id: SessionID) -> Option<i32> {
    let session = session_record(session_id)?;
    let stored = lock(&session.options)
        .get("edge-scroll-edge-thickness")
        .and_then(|value| value.parse::<i32>().ok());
    Some(stored.unwrap_or(0))
}

pub fn session_set_edge_scroll_edge_thickness(session_id: SessionID, value: i32) {
    if let Some(session) = session_record(session_id) {
        session.set_option("edge-scroll-edge-thickness", value.to_string());
    }
}

pub fn session_get_reverse_mouse_wheel_sync(session_id: SessionID) -> SyncReturn<Option<String>> {
    let stored = match session_record(session_id) {
        Some(session) => session.option("reverse-mouse-wheel").unwrap_or_default(),
        None => String::new(),
    };
    SyncReturn(Some(stored))
}

pub fn session_set_reverse_mouse_wheel(session_id: SessionID, value: String) {
    if let Some(session) = session_record(session_id) {
        session.set_option("reverse-mouse-wheel", value);
    }
}

pub fn session_get_displays_as_individual_windows(
    session_id: SessionID,
) -> SyncReturn<Option<String>> {
    let stored = match session_record(session_id) {
        Some(session) => session
            .option("displays-as-individual-windows")
            .unwrap_or_default(),
        None => String::new(),
    };
    SyncReturn(Some(stored))
}

pub fn session_set_displays_as_individual_windows(session_id: SessionID, value: String) {
    if let Some(session) = session_record(session_id) {
        session.set_option("displays-as-individual-windows", value);
    }
}

pub fn session_get_use_all_my_displays_for_the_remote_session(
    session_id: SessionID,
) -> SyncReturn<Option<String>> {
    let stored = match session_record(session_id) {
        Some(session) => session
            .option("use-all-my-displays-for-the-remote-session")
            .unwrap_or_default(),
        None => String::new(),
    };
    SyncReturn(Some(stored))
}

pub fn session_set_use_all_my_displays_for_the_remote_session(
    session_id: SessionID,
    value: String,
) {
    if let Some(session) = session_record(session_id) {
        session.set_option("use-all-my-displays-for-the-remote-session", value);
    }
}

pub fn session_set_common(session_id: SessionID, key: String, value: String) -> Result<()> {
    ensure!(
        key == "continue-insecure-connection",
        "unsupported session setting"
    );
    ensure!(
        value == "Y" || value == "N",
        "invalid peer acceptance value"
    );
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let accepted = value == "Y";
    session
        .unverified_accepted
        .store(accepted, Ordering::SeqCst);
    if let Some(viewer) = lock(&session.viewer).clone() {
        let mut policy = viewer.input_policy();
        policy.unverified_accepted = accepted;
        viewer.set_input_policy(policy);
        if accepted {
            // The gate in `announce_frame` only publishes once the window
            // decodes a frame, and this session's window has been showing the
            // client nothing while it was shut. Asking for a keyframe is what
            // makes the release happen now instead of at the peer's next
            // damage: the peer answers with a full frame, the observer presents
            // and publishes it as this session's peer_info followed by its
            // first frame.
            if let Err(error) = viewer.request_keyframe() {
                log::warn!("{session_id}: keyframe request after acceptance refused: {error}");
            }
        }
    }
    Ok(())
}

pub fn session_get_common(session_id: SessionID, key: String, param: String) -> Option<String> {
    let _ = param;
    let session = session_record(session_id)?;
    (key == "continue-insecure-connection").then(|| {
        if session.unverified_accepted.load(Ordering::SeqCst) {
            "Y".to_owned()
        } else {
            "N".to_owned()
        }
    })
}

pub fn session_get_common_sync(
    session_id: SessionID,
    key: String,
    param: String,
) -> SyncReturn<Option<String>> {
    SyncReturn(session_get_common(session_id, key, param))
}

pub fn session_on_waiting_for_image_dialog_show(session_id: SessionID) {
    let _ = session_id;
    // The client tells the core its waiting-for-image dialog is up. This bridge
    // has no dialog state of its own, so there is nothing to record.
    no_state("session_on_waiting_for_image_dialog_show");
}

/// The client remembers which session is focused, so its input path knows which
/// one an event belongs to. One viewer per session here, so the record is the
/// whole of what the core does with it.
pub fn set_cur_session_id(session_id: SessionID) {
    if session_record(session_id).is_some() {
        lock(&APP).current_session = session_id.to_string();
    }
}

// ---------------------------------------------------------------------------
// Sessions: frames
// ---------------------------------------------------------------------------

pub fn session_get_rgba_size(session_id: SessionID, display: usize) -> SyncReturn<usize> {
    if display != 0 {
        return SyncReturn(0);
    }
    SyncReturn(
        lock(&FRAME_OWNERS)
            .get(&session_id)
            .map(|frames| frames.size())
            .unwrap_or(0),
    )
}

/// Actual release acknowledgement from the pinned consumer, after its async
/// decode completes. A close/reconnect does not stand in for this callback.
pub fn session_next_rgba(session_id: SessionID, display: usize) -> SyncReturn<()> {
    if display != 0 {
        return SyncReturn(());
    }
    {
        let mut owners = lock(&FRAME_OWNERS);
        if owners
            .get(&session_id)
            .map(|frames| frames.release())
            .unwrap_or(false)
        {
            owners.remove(&session_id);
        }
    }
    if let Some(session) = session_record(session_id) {
        session.announce_frame();
    }
    SyncReturn(())
}

pub fn session_register_pixelbuffer_texture(
    session_id: SessionID,
    display: usize,
    ptr: usize,
) -> Result<SyncReturn<()>> {
    unsupported_result("session_register_pixelbuffer_texture")
}

pub fn session_register_gpu_texture(
    session_id: SessionID,
    display: usize,
    ptr: usize,
) -> Result<SyncReturn<()>> {
    unsupported_result("session_register_gpu_texture")
}

/// The published RGBA frame for one display, for the `session_get_rgba` C
/// symbol in `c_entry_points`. The size call reserves the immutable allocation;
/// it survives geometry changes and close until the actual nextRgba callback.
pub(crate) fn rgba_pointer(session_id: &str, display: usize) -> *const u8 {
    let Ok(session_id) = uuid::Uuid::parse_str(session_id) else {
        return std::ptr::null();
    };
    if display != 0 {
        return std::ptr::null();
    }
    lock(&FRAME_OWNERS)
        .get(&session_id)
        .map(|frames| frames.pointer())
        .unwrap_or(std::ptr::null())
}

// ---------------------------------------------------------------------------
// Sessions: input
// ---------------------------------------------------------------------------

/// The connection one input event belongs to: the viewer, and the input
/// generation that viewer admits, captured together under one acquisition of the
/// session's viewer lock.
///
/// Both halves matter and neither may be resolved later. A stop, a reconnect or a
/// login replaces the session's viewer and moves its generation, so an event that
/// re-resolved the viewer by session id after the fact would be sent to whatever
/// connection happens to be there by then, carrying that connection's own
/// generation - the engine's staleness check could not tell it apart from real
/// input of the new connection. Submitting to the captured viewer with the
/// generation captured beside it is what makes that check mean something: an
/// event that outlived its connection is refused, not relabelled.
fn input_target(session: &Arc<Session>) -> Result<(Arc<Viewer>, u64)> {
    let guard = lock(&session.viewer);
    captured_input_target(&guard)
}

/// The same capture, for the paths whose event is translated through the
/// session's keyboard state.
///
/// The locks are taken in the `viewer` then `keyboard` order `stop_viewer` takes,
/// and the translator is held until the send built from it has returned. That is
/// what closes the window between the two locks: an event holds the translator
/// before it lets go of the viewer lock, and the clear a stop performs needs the
/// same translator, so the two can only be ordered one way - this event
/// translates and submits to the connection it captured, and the clear then wipes
/// that connection's state. The interleaving the clear exists to prevent is
/// excluded: a capture of the old viewer followed by a translation of the next
/// connection's fresh state, which would leave a hold the next connection never
/// sent and make the engine drop that key's real press as a duplicate.
fn translated_input_target<'a>(
    session: &'a Arc<Session>,
) -> Result<(Arc<Viewer>, u64, MutexGuard<'a, KeyboardState>)> {
    let guard = lock(&session.viewer);
    let (viewer, generation) = captured_input_target(&guard)?;
    let keyboard = lock(&session.keyboard);
    drop(guard);
    Ok((viewer, generation, keyboard))
}

/// The capture both of the above share, read out of the viewer lock the caller
/// holds. It is not for general use: releasing that lock before the caller has
/// taken everything else the event needs is what the two wrappers exist to
/// prevent.
fn captured_input_target(
    guard: &MutexGuard<'_, Option<Arc<Viewer>>>,
) -> Result<(Arc<Viewer>, u64)> {
    let viewer = guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("viewer is not running"))?;
    Ok((viewer.clone(), viewer.snapshot().input_generation))
}

fn send_legacy_key(viewer: &Arc<Viewer>, generation: u64, event: KeyEvent) -> Result<()> {
    viewer
        .send_rustdesk_key(event, generation)
        .map_err(|error| anyhow::anyhow!("keyboard input refused: {error}"))?;
    Ok(())
}

fn legacy_key_event(
    name: &str,
    down: bool,
    press: bool,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
) -> Result<KeyEvent> {
    let mut event = KeyEvent::new();
    event.mode = KeyboardMode::Legacy.into();
    if press {
        event.press = true;
    } else {
        event.down = down;
    }

    if name.chars().count() == 1 {
        event.set_chr(name.chars().next().expect("one character") as u32);
    } else if let Some(letter) = name.strip_prefix("VK_").and_then(|v| {
        (v.len() == 1)
            .then(|| v.as_bytes()[0])
            .filter(u8::is_ascii_alphanumeric)
    }) {
        event.set_chr(u32::from(letter.to_ascii_lowercase()));
    } else {
        let control = match name {
            "VK_BACK" => ControlKey::Backspace,
            "VK_TAB" => ControlKey::Tab,
            "VK_ENTER" | "VK_RETURN" => ControlKey::Return,
            "VK_ESCAPE" => ControlKey::Escape,
            "VK_SPACE" => ControlKey::Space,
            "VK_LEFT" => ControlKey::LeftArrow,
            "VK_RIGHT" => ControlKey::RightArrow,
            "VK_UP" => ControlKey::UpArrow,
            "VK_DOWN" => ControlKey::DownArrow,
            "VK_HOME" => ControlKey::Home,
            "VK_END" => ControlKey::End,
            "VK_PRIOR" => ControlKey::PageUp,
            "VK_NEXT" => ControlKey::PageDown,
            "VK_INSERT" => ControlKey::Insert,
            "VK_DELETE" => ControlKey::Delete,
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
            "VK_SHIFT" => ControlKey::Shift,
            "VK_CONTROL" => ControlKey::Control,
            "VK_MENU" => ControlKey::Alt,
            _ => anyhow::bail!("unsupported keyboard key name"),
        };
        event.set_control_key(control);
    }

    if alt {
        event.modifiers.push(ControlKey::Alt.into());
    }
    if ctrl {
        event.modifiers.push(ControlKey::Control.into());
    }
    if shift {
        event.modifiers.push(ControlKey::Shift.into());
    }
    if command {
        event.modifiers.push(ControlKey::Meta.into());
    }
    Ok(event)
}

// The engine's mouse kinds and button bits: `kind | (button << 3)` is the
// original wire's encoding, which is what `Viewer::send_mouse` takes.
const KIND_MOVE: u32 = 0;
const KIND_DOWN: u32 = 1;
const KIND_UP: u32 = 2;
const KIND_WHEEL: u32 = 3;
const KIND_TRACKPAD: u32 = 4;
const KIND_MOVE_RELATIVE: u32 = 5;
const BUTTON_NONE: u32 = 0;
const BUTTON_LEFT: u32 = 1;
const BUTTON_RIGHT: u32 = 2;
const BUTTON_WHEEL: u32 = 4;
const BUTTON_BACK: u32 = 8;
const BUTTON_FORWARD: u32 = 16;

/// The client's mouse path, in the message shape its Dart sends:
/// `{"type": "down"|"up"|"wheel"|"trackpad"|"move_relative", "buttons": ...,
/// "x": "...", "y": "...", "alt"/"ctrl"/"shift"/"command": present-or-absent}`.
///
/// Two messages carry `relative_mouse_mode` instead: the client sends
/// `{"relative_mouse_mode": "0"}` when it leaves relative mode, which is a local
/// notification and never forwarded, and an activation marker that goes on only
/// as the zero-displacement relative move it claims to be.
pub fn session_send_mouse(session_id: SessionID, msg: String) -> Result<()> {
    let fields: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&msg).map_err(|_| anyhow::anyhow!("invalid mouse event"))?;
    if let Some(marker) = fields.get("relative_mouse_mode") {
        let active = matches!(marker.as_str(), Some("1" | "Y" | "on"));
        if !active {
            // Local-only: the client is leaving relative mode. Its model keeps
            // that state, and the peer learns of it by no longer receiving
            // relative moves. Decoding this as a pointer event would move the
            // remote cursor wherever the absent coordinates default to.
            log::debug!("{session_id}: relative mouse mode deactivation consumed locally");
            return Ok(());
        }
        // An activation marker is forwarded only when it is the no-op it claims
        // to be, so a message missing its type, its coordinates or carrying a
        // button is dropped rather than defaulted into a real move at (0, 0).
        let coordinate = |name: &str| -> Option<i32> {
            match fields.get(name) {
                None => Some(0),
                Some(value) => value
                    .as_i64()
                    .and_then(|value| i32::try_from(value).ok())
                    .or_else(|| value.as_str().and_then(|value| value.parse().ok())),
            }
        };
        let is_no_op = fields.get("type").and_then(serde_json::Value::as_str)
            == Some("move_relative")
            && coordinate("x") == Some(0)
            && coordinate("y") == Some(0)
            && ["buttons", "alt", "ctrl", "shift", "command"]
                .iter()
                .all(|field| !fields.contains_key(*field));
        if !is_no_op {
            log::warn!(
                "{session_id}: relative mouse mode activation marker is not a zero-displacement move; dropped"
            );
            return Ok(());
        }
    }
    let kind = match fields.get("type").and_then(serde_json::Value::as_str) {
        None | Some("move") => KIND_MOVE,
        Some("down") => KIND_DOWN,
        Some("up") => KIND_UP,
        Some("wheel") => KIND_WHEEL,
        Some("trackpad") => KIND_TRACKPAD,
        Some("move_relative") => KIND_MOVE_RELATIVE,
        Some(_) => anyhow::bail!("unsupported pointer event"),
    };
    let button = match fields.get("buttons").and_then(serde_json::Value::as_str) {
        None | Some("") => BUTTON_NONE,
        Some("left") => BUTTON_LEFT,
        Some("right") => BUTTON_RIGHT,
        Some("wheel") => BUTTON_WHEEL,
        Some("back") => BUTTON_BACK,
        Some("forward") => BUTTON_FORWARD,
        Some(_) => anyhow::bail!("invalid mouse button"),
    };
    let number = |name: &str| -> Result<i32> {
        match fields.get(name) {
            None => Ok(0),
            Some(value) => value
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                .ok_or_else(|| anyhow::anyhow!("invalid mouse coordinate")),
        }
    };
    let x = number("x")?;
    let y = number("y")?;
    // Same capture as the keyboard path: this pointer event goes to the
    // connection it was decoded against, under that connection's generation.
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let (viewer, generation) = input_target(&session)?;
    viewer
        .send_mouse(kind, button, x, y, generation)
        .map_err(|error| anyhow::anyhow!("pointer input refused: {error}"))?;
    Ok(())
}

/// The touch path the client uses on phones and tablets:
/// `{"k": "touch", "v": {"t": <gesture>, "v": ...}}`. The engine's pointer wire
/// carries mouse kinds and the legacy key event only - it has no touch event -
/// so this refuses instead of falling through to a mouse decode in which the
/// missing `type` field would become a move to (0, 0) and the gesture would be
/// lost.
pub fn session_send_pointer(session_id: SessionID, msg: String) -> Result<()> {
    let _ = msg;
    ensure!(session_record(session_id).is_some(), "unknown session");
    unsupported_result("session_send_pointer: touch input is not implemented by this engine")
}

/// Sends what the session's keyboard translator produced, to the connection the
/// event was captured against. `None` is the upstream outcome for a key the wire
/// carries no event for at all - the lock keys' own press or release, a raw
/// payload without a nameable key, and the auto-repeat of a modifier that is
/// already held: the conversion completed, the hold is undisturbed, and nothing
/// is sent. A key the translator cannot name at all is an `Err` before this point
/// and never reaches here.
fn send_translated_key(
    viewer: &Arc<Viewer>,
    generation: u64,
    event: Option<KeyEvent>,
) -> Result<()> {
    match event {
        Some(event) => send_legacy_key(viewer, generation, event),
        None => Ok(()),
    }
}

/// Translate the official Flutter key shape through this session's keyboard
/// translator and send it to the connection this event was captured against.
///
/// Translation and submit are one serial operation: the viewer and its generation
/// are captured first, the keyboard lock is then held from the translation until
/// the submit has returned, and both happen under that hold. Two things follow,
/// and both are the point of the hold. A release cannot overtake the press it
/// belongs to - the translator is what pairs them, and releasing it before the
/// send would let two calls register and enqueue out of order, leaving the peer
/// holding a key the operator has already let go. And `stop_viewer`'s clear
/// cannot land between a translation and the send built from it, so a hold
/// recorded here is either sent to the connection it belongs to or
/// cleared with that connection's translator, never carried into the next one.
///
/// `Viewer::send_rustdesk_key` remains the policy gate: it refuses the key when
/// the session is view-only, when the peer has revoked keyboard admission, or
/// when the event names a generation that viewer has left.
pub fn session_handle_flutter_key_event(
    session_id: SessionID,
    character: String,
    usb_hid: i32,
    lock_modes: i32,
    down_or_up: bool,
) -> Result<()> {
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let (viewer, generation, mut keyboard) = translated_input_target(&session)?;
    let event = keyboard.flutter(&character, usb_hid, lock_modes, down_or_up)?;
    let sent = send_translated_key(&viewer, generation, event);
    drop(keyboard);
    sent
}

/// The raw Flutter key shape, translated and submitted under the same serial
/// hold as the character shape above.
pub fn session_handle_flutter_raw_key_event(
    session_id: SessionID,
    name: String,
    platform_code: i32,
    position_code: i32,
    lock_modes: i32,
    down_or_up: bool,
) -> Result<()> {
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let (viewer, generation, mut keyboard) = translated_input_target(&session)?;
    let event = keyboard.raw(&name, platform_code, position_code, lock_modes, down_or_up)?;
    let sent = send_translated_key(&viewer, generation, event);
    drop(keyboard);
    sent
}

pub fn session_input_key(
    session_id: SessionID,
    name: String,
    down: bool,
    press: bool,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
) -> Result<()> {
    // This shape carries no translator state, so there is nothing to pair and
    // nothing to hold: the event is built, then captured and sent as one step.
    let event = legacy_key_event(&name, down, press, alt, ctrl, shift, command)?;
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let (viewer, generation) = input_target(&session)?;
    send_legacy_key(&viewer, generation, event)
}

pub fn session_input_string(session_id: SessionID, value: String) -> Result<()> {
    ensure!(!value.is_empty(), "text input is empty");
    ensure!(
        value.encode_utf16().count() <= 2048,
        "text input is too long"
    );
    let mut event = KeyEvent::new();
    event.mode = KeyboardMode::Legacy.into();
    event.set_seq(value);
    let session = session_record(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
    let (viewer, generation) = input_target(&session)?;
    send_legacy_key(&viewer, generation, event)
}

pub fn session_input_os_password(_session_id: SessionID, _value: String) -> Result<()> {
    anyhow::bail!("unsupported: OS credentials are not handled by this artifact")
}

/// The client's keyboard-grab notification has no native grab on this side.
/// Input admission remains owned by the live viewer policy.
pub fn session_enter_or_leave(_session_id: SessionID, _enter: bool) -> SyncReturn<()> {
    SyncReturn(())
}

/// The viewer speaks the RustDesk legacy keyboard wire; this reports that real
/// protocol mode rather than a fabricated platform-specific capability.
pub fn session_get_keyboard_mode(session_id: SessionID) -> Option<String> {
    session_record(session_id).map(|_| "legacy".to_owned())
}

pub fn session_set_keyboard_mode(session_id: SessionID, value: String) -> Result<()> {
    ensure!(session_record(session_id).is_some(), "unknown session");
    ensure!(value == "legacy", "unsupported keyboard mode");
    Ok(())
}

pub fn session_is_keyboard_mode_supported(session_id: SessionID, mode: String) -> SyncReturn<bool> {
    SyncReturn(session_record(session_id).is_some() && mode == "legacy")
}

pub fn session_send_note(session_id: SessionID, note: String) -> Result<()> {
    unsupported_result("session_send_note")
}

// ---------------------------------------------------------------------------
// Sessions: screenshot, recording, privacy, displays and the other roles
// ---------------------------------------------------------------------------

pub fn session_handle_screenshot(session_id: SessionID, action: String) -> Result<String> {
    unsupported_result("session_handle_screenshot")
}

pub fn session_take_screenshot(session_id: SessionID, display: usize) -> Result<()> {
    unsupported_result("session_take_screenshot")
}

pub fn session_record_screen(session_id: SessionID, start: bool) -> Result<()> {
    unsupported_result("session_record_screen")
}

pub fn session_get_is_recording(session_id: SessionID) -> SyncReturn<bool> {
    let _ = session_id;
    SyncReturn(false)
}

pub fn session_toggle_privacy_mode(
    session_id: SessionID,
    impl_key: String,
    on: bool,
) -> Result<()> {
    unsupported_result("session_toggle_privacy_mode")
}

pub fn session_send2fa(session_id: SessionID, code: String, trust_this_device: bool) -> Result<()> {
    unsupported_result("session_send2fa")
}

pub fn session_lock_screen(session_id: SessionID) -> Result<()> {
    unsupported_result("session_lock_screen")
}

pub fn session_ctrl_alt_del(session_id: SessionID) -> Result<()> {
    unsupported_result("session_ctrl_alt_del")
}

pub fn session_switch_display(
    is_desktop: bool,
    session_id: SessionID,
    value: Vec<i32>,
) -> Result<()> {
    unsupported_result("session_switch_display")
}

pub fn session_change_resolution(
    session_id: SessionID,
    display: i32,
    width: i32,
    height: i32,
) -> Result<()> {
    unsupported_result("session_change_resolution")
}

pub fn session_request_new_display_init_msgs(session_id: SessionID, display: usize) -> Result<()> {
    unsupported_result("session_request_new_display_init_msgs")
}

pub fn session_toggle_virtual_display(session_id: SessionID, index: i32, on: bool) -> Result<()> {
    unsupported_result("session_toggle_virtual_display")
}

pub fn session_restart_remote_device(session_id: SessionID) -> Result<()> {
    unsupported_result("session_restart_remote_device")
}

pub fn session_switch_sides(session_id: SessionID) -> Result<()> {
    unsupported_result("session_switch_sides")
}

pub fn session_send_selected_session_id(session_id: SessionID, sid: String) -> Result<()> {
    unsupported_result("session_send_selected_session_id")
}

pub fn session_alternative_codecs(session_id: SessionID) -> Result<String> {
    unsupported_result("session_alternative_codecs")
}

pub fn session_change_prefer_codec(session_id: SessionID) -> Result<()> {
    unsupported_result("session_change_prefer_codec")
}

pub fn session_get_audit_server_sync(
    session_id: SessionID,
    typ: String,
) -> Result<SyncReturn<String>> {
    unsupported_result("session_get_audit_server_sync")
}

pub fn session_get_last_audit_note(session_id: SessionID) -> Result<SyncReturn<String>> {
    unsupported_result("session_get_last_audit_note")
}

pub fn session_set_audit_guid(session_id: SessionID, guid: String) -> Result<()> {
    unsupported_result("session_set_audit_guid")
}

pub fn session_get_audit_guid(session_id: SessionID) -> Result<SyncReturn<String>> {
    unsupported_result("session_get_audit_guid")
}

// ---------------------------------------------------------------------------
// Sessions: terminals, file transfer and port forwarding
// ---------------------------------------------------------------------------

pub fn session_open_terminal(
    session_id: SessionID,
    terminal_id: i32,
    rows: u32,
    cols: u32,
) -> Result<()> {
    unsupported_result("session_open_terminal")
}

pub fn session_send_terminal_input(
    session_id: SessionID,
    terminal_id: i32,
    data: String,
) -> Result<()> {
    unsupported_result("session_send_terminal_input")
}

pub fn session_resize_terminal(
    session_id: SessionID,
    terminal_id: i32,
    rows: u32,
    cols: u32,
) -> Result<()> {
    unsupported_result("session_resize_terminal")
}

pub fn session_close_terminal(session_id: SessionID, terminal_id: i32) -> Result<()> {
    unsupported_result("session_close_terminal")
}

pub fn session_read_remote_dir(
    session_id: SessionID,
    path: String,
    include_hidden: bool,
) -> Result<()> {
    unsupported_result("session_read_remote_dir")
}

pub fn session_send_files(
    session_id: SessionID,
    act_id: i32,
    path: String,
    to: String,
    file_num: i32,
    include_hidden: bool,
    is_remote: bool,
    _is_dir: bool,
) -> Result<()> {
    unsupported_result("session_send_files")
}

pub fn session_set_confirm_override_file(
    session_id: SessionID,
    act_id: i32,
    file_num: i32,
    need_override: bool,
    remember: bool,
    is_upload: bool,
) -> Result<()> {
    unsupported_result("session_set_confirm_override_file")
}

pub fn session_remove_file(
    session_id: SessionID,
    act_id: i32,
    path: String,
    file_num: i32,
    is_remote: bool,
) -> Result<()> {
    unsupported_result("session_remove_file")
}

pub fn session_read_dir_to_remove_recursive(
    session_id: SessionID,
    act_id: i32,
    path: String,
    is_remote: bool,
    show_hidden: bool,
) -> Result<()> {
    unsupported_result("session_read_dir_to_remove_recursive")
}

pub fn session_remove_all_empty_dirs(
    session_id: SessionID,
    act_id: i32,
    path: String,
    is_remote: bool,
) -> Result<()> {
    unsupported_result("session_remove_all_empty_dirs")
}

pub fn session_cancel_job(session_id: SessionID, act_id: i32) -> Result<()> {
    unsupported_result("session_cancel_job")
}

pub fn session_create_dir(
    session_id: SessionID,
    act_id: i32,
    path: String,
    is_remote: bool,
) -> Result<()> {
    unsupported_result("session_create_dir")
}

pub fn session_read_local_dir_sync(
    _session_id: SessionID,
    path: String,
    show_hidden: bool,
) -> Result<String> {
    unsupported_result("session_read_local_dir_sync")
}

pub fn session_read_local_empty_dirs_recursive_sync(
    _session_id: SessionID,
    path: String,
    include_hidden: bool,
) -> Result<String> {
    unsupported_result("session_read_local_empty_dirs_recursive_sync")
}

pub fn session_read_remote_empty_dirs_recursive_sync(
    session_id: SessionID,
    path: String,
    include_hidden: bool,
) -> Result<()> {
    unsupported_result("session_read_remote_empty_dirs_recursive_sync")
}

pub fn session_load_last_transfer_jobs(session_id: SessionID) -> Result<()> {
    unsupported_result("session_load_last_transfer_jobs")
}

pub fn session_add_job(
    session_id: SessionID,
    act_id: i32,
    path: String,
    to: String,
    file_num: i32,
    include_hidden: bool,
    is_remote: bool,
) -> Result<()> {
    unsupported_result("session_add_job")
}

pub fn session_resume_job(session_id: SessionID, act_id: i32, is_remote: bool) -> Result<()> {
    unsupported_result("session_resume_job")
}

pub fn session_rename_file(
    session_id: SessionID,
    act_id: i32,
    path: String,
    new_name: String,
    is_remote: bool,
) -> Result<()> {
    unsupported_result("session_rename_file")
}

pub fn session_elevate_direct(session_id: SessionID) -> Result<()> {
    unsupported_result("session_elevate_direct")
}

pub fn session_elevate_with_logon(
    _session_id: SessionID,
    _username: String,
    _password: String,
) -> Result<()> {
    anyhow::bail!("unsupported: elevation credentials are not handled by this artifact")
}

pub fn session_add_port_forward(
    session_id: SessionID,
    local_port: i32,
    remote_host: String,
    remote_port: i32,
) -> Result<()> {
    unsupported_result("session_add_port_forward")
}

pub fn session_remove_port_forward(session_id: SessionID, local_port: i32) -> Result<()> {
    unsupported_result("session_remove_port_forward")
}

pub fn session_new_rdp(session_id: SessionID) -> Result<()> {
    unsupported_result("session_new_rdp")
}

pub fn session_printer_response(
    session_id: SessionID,
    id: i32,
    path: String,
    printer_name: String,
) -> Result<()> {
    unsupported_result("session_printer_response")
}
