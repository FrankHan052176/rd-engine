//! Pinned official outbound LAN discovery with engine-owned retirement.
//!
//! Callers must initialize the immutable hbb_common configuration namespace first.
//! Admission methods perform no cache I/O. Blocking queries/receipts belong on a
//! bridge worker. Observations are untrusted; this module never selects a route.
//! The 256-record ingress bound is not a peer/cache/memory bound. The upstream
//! cache remains unbounded, and its void store API proves only a write attempt.
//! See UPSTREAM.json for the selected sources and the lifecycle adaptations.
mod discovery;
mod peer_id;

use hbb_common::config;
use std::{
    any::Any,
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{runtime::Runtime, sync::Notify};

/// Invalidation only; not a cache write acknowledgement or an authenticated peer.
#[derive(Clone)]
pub struct LanNotice {
    pub owner_generation: u64,
    pub scan_id: Option<u64>,
    pub cache_revision: u64,
}

pub struct LanStart {
    pub scan_id: u64,
    /// False coalesces with the same scan and never resets its admission deadline.
    pub started: bool,
}

pub struct LanSnapshot {
    pub owner_generation: u64,
    pub scan_id: Option<u64>,
    pub cache_revision: u64,
    pub state: &'static str,
    pub peers: Vec<HashMap<&'static str, String>>,
    pub terminal: Option<&'static str>,
    pub error: Option<String>,
}

/// Dropping this receipt does not cancel the work or release its namespace gate.
#[derive(Clone)]
pub struct LanCompletion {
    inner: Arc<CompletionState>,
}

struct CompletionState {
    result: Mutex<Option<Result<(), String>>>,
    ready: Condvar,
    changed: Notify,
}

impl LanCompletion {
    fn pending() -> Self {
        Self {
            inner: Arc::new(CompletionState {
                result: Mutex::new(None),
                ready: Condvar::new(),
                changed: Notify::new(),
            }),
        }
    }

    /// Success means owned work ended, never that the official cache is durable.
    pub fn wait_blocking(&self) -> Result<(), String> {
        let mut result = lock(&self.inner.result);
        loop {
            if let Some(result) = result.as_ref() {
                return result.clone();
            }
            result = self
                .inner
                .ready
                .wait(result)
                .unwrap_or_else(|e| e.into_inner());
        }
    }

    async fn wait(&self) -> Result<(), String> {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(result) = lock(&self.inner.result).as_ref() {
                return result.clone();
            }
            changed.await;
        }
    }

    fn finish(&self, result: Result<(), String>) {
        let mut slot = lock(&self.inner.result);
        if slot.is_none() {
            *slot = Some(result);
            self.inner.ready.notify_all();
            self.inner.changed.notify_waiters();
        }
    }
}

/// Only bridges own this outer Arc. Tasks and the namespace retain OwnerState,
/// never LanOwner, so the last bridge drop always requests real retirement.
pub struct LanOwner {
    inner: Arc<OwnerState>,
}

type Notifier = Arc<dyn Fn(LanNotice) + Send + Sync>;

struct Namespace {
    next_generation: u64,
    owner: Option<Arc<OwnerState>>,
}

static NAMESPACE: Mutex<Namespace> = Mutex::new(Namespace {
    next_generation: 0,
    owner: None,
});
// Every LAN cache load/query/write, including final writes and removal, uses
// this boundary. No metadata lock is held during I/O or any join.
static CACHE: Mutex<()> = Mutex::new(());
static CACHE_REVISION: AtomicU64 = AtomicU64::new(0);

struct OwnerState {
    generation: u64,
    ping_id: String,
    runtime: &'static Runtime,
    metadata: Mutex<Metadata>,
    closed: LanCompletion,
    notices_changed: Notify,
}

struct Metadata {
    phase: Phase,
    closing: bool,
    next_scan_id: u64,
    scan: Option<Arc<Scan>>,
    scan_running: bool,
    removal: Option<LanCompletion>,
    notifier: Option<Notifier>,
    notices: usize,
    terminal: Option<&'static str>,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Scanning,
    Stopping,
    Removing,
    Closed,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Scanning => "scanning",
            Self::Stopping => "stopping",
            Self::Removing => "removing",
            Self::Closed => "closed",
        }
    }
}

impl Metadata {
    fn require_open(&self) -> Result<(), String> {
        if self.closing || self.phase == Phase::Closed {
            Err("LAN owner is closing or closed".to_owned())
        } else {
            Ok(())
        }
    }

    fn scan_id(&self) -> Option<u64> {
        self.scan.as_ref().map(|scan| scan.id)
    }
}

struct Scan {
    id: u64,
    control: Arc<discovery::ScanControl>,
    done: LanCompletion,
}

/// Acquires the one already-initialized configuration namespace. The old owner
/// must finish retirement first; this call neither replaces it nor retries.
/// Supply the initialized local ID for mobile/OHOS; desktop pings stay empty.
pub fn acquire_initialized_owner(
    ping_id: String,
    notifier: Option<Arc<dyn Fn(LanNotice) + Send + Sync>>,
) -> Result<Arc<LanOwner>, String> {
    let runtime = crate::executor::runtime().map_err(|_| "LAN executor unavailable".to_owned())?;
    let mut namespace = lock(&NAMESPACE);
    if namespace.owner.is_some() {
        return Err("LAN namespace is busy; retire its owner first".to_owned());
    }
    let generation = namespace
        .next_generation
        .checked_add(1)
        .ok_or_else(|| "LAN owner generation exhausted".to_owned())?;
    let inner = Arc::new(OwnerState {
        generation,
        ping_id,
        runtime,
        metadata: Mutex::new(Metadata {
            phase: Phase::Idle,
            closing: false,
            next_scan_id: 0,
            scan: None,
            scan_running: false,
            removal: None,
            notifier,
            notices: 0,
            terminal: None,
            error: None,
        }),
        closed: LanCompletion::pending(),
        notices_changed: Notify::new(),
    });
    namespace.next_generation = generation;
    namespace.owner = Some(inner.clone());
    Ok(Arc::new(LanOwner { inner }))
}

impl LanOwner {
    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    pub fn scan_id(&self) -> Option<u64> {
        lock(&self.inner.metadata).scan_id()
    }

    pub fn start(&self) -> Result<LanStart, String> {
        let scan = {
            let mut metadata = lock(&self.inner.metadata);
            metadata.require_open()?;
            if metadata.phase == Phase::Scanning {
                if let Some(scan) = &metadata.scan {
                    return Ok(LanStart {
                        scan_id: scan.id,
                        started: false,
                    });
                }
            }
            if metadata.phase != Phase::Idle {
                return Err("LAN scan is stopping or a removal is in progress".to_owned());
            }
            let id = metadata
                .next_scan_id
                .checked_add(1)
                .ok_or_else(|| "LAN scan ticket exhausted".to_owned())?;
            let scan = Arc::new(Scan {
                id,
                // Captured at admission, not when a blocking worker eventually starts.
                control: Arc::new(discovery::ScanControl::new()),
                done: LanCompletion::pending(),
            });
            metadata.next_scan_id = id;
            metadata.phase = Phase::Scanning;
            metadata.scan = Some(scan.clone());
            metadata.scan_running = true;
            metadata.terminal = None;
            metadata.error = None;
            scan
        };
        let id = scan.id;
        let owner = self.inner.clone();
        self.inner.runtime.spawn(async move {
            let worker_owner = owner.clone();
            let worker_scan = scan.clone();
            let result = run_blocking(owner.runtime, move || {
                discovery::discover(worker_owner, worker_scan)
            })
            .await;
            if let Err(error) = result {
                scan.control.fail(error);
            }
            // This observer has now consumed the actual coordinator JoinHandle.
            // The coordinator's cleanup guard consumed every socket JoinHandle.
            {
                let mut metadata = lock(&owner.metadata);
                let error = scan.control.error();
                metadata.scan_running = false;
                metadata.terminal = Some(scan.control.terminal());
                metadata.error = error.clone();
                if metadata.phase != Phase::Removing {
                    metadata.phase = if metadata.closing {
                        Phase::Stopping
                    } else {
                        Phase::Idle
                    };
                }
                scan.done.finish(error.map_or(Ok(()), Err));
            }
            owner.notify();
        });
        self.inner.notify();
        Ok(LanStart {
            scan_id: id,
            started: true,
        })
    }

    pub fn query_blocking(&self) -> Result<LanSnapshot, String> {
        // Early rejection is not the I/O admission check: recheck after CACHE.
        lock(&self.inner.metadata).require_open()?;
        let _cache = lock(&CACHE);
        lock(&self.inner.metadata).require_open()?;
        let peers = catch_unwind(AssertUnwindSafe(get_lan_peers))
            .map_err(|panic| panic_error("LAN cache query", panic))?;
        let metadata = lock(&self.inner.metadata);
        metadata.require_open()?;
        Ok(LanSnapshot {
            owner_generation: self.inner.generation,
            scan_id: metadata.scan_id(),
            cache_revision: CACHE_REVISION.load(Ordering::Acquire),
            state: metadata.phase.name(),
            peers,
            terminal: metadata.terminal,
            error: metadata.error.clone(),
        })
    }

    pub fn request_stop(&self, scan_id: u64) -> Result<LanCompletion, String> {
        let receipt = {
            let mut metadata = lock(&self.inner.metadata);
            metadata.require_open()?;
            let scan = metadata
                .scan
                .as_ref()
                .filter(|scan| scan.id == scan_id)
                .ok_or_else(|| "Stale LAN scan ticket".to_owned())?
                .clone();
            if metadata.scan_running {
                scan.control.cancel();
                if metadata.phase != Phase::Removing {
                    metadata.phase = Phase::Stopping;
                }
            }
            scan.done.clone()
        };
        self.inner.notify();
        Ok(receipt)
    }

    pub fn request_remove(
        &self,
        expected_scan_id: Option<u64>,
        id: String,
    ) -> Result<LanCompletion, String> {
        let (scan, receipt) = {
            let mut metadata = lock(&self.inner.metadata);
            metadata.require_open()?;
            if metadata.scan_id() != expected_scan_id {
                return Err("Stale LAN scan ticket".to_owned());
            }
            if metadata.phase == Phase::Removing {
                return Err("LAN removal is already in progress".to_owned());
            }
            let receipt = LanCompletion::pending();
            metadata.phase = Phase::Removing;
            metadata.removal = Some(receipt.clone());
            if metadata.scan_running {
                if let Some(scan) = &metadata.scan {
                    scan.control.cancel();
                }
            }
            (metadata.scan.clone(), receipt)
        };
        let owner = self.inner.clone();
        let done = receipt.clone();
        self.inner.runtime.spawn(async move {
            let mut error = None;
            if let Some(scan) = scan {
                if let Err(failure) = scan.done.wait().await {
                    add_error(&mut error, failure);
                }
            }
            // The Removing gate is still held even if the bridge lost its receipt.
            if let Err(failure) = run_blocking(owner.runtime, move || {
                let _cache = lock(&CACHE);
                remove_discovered(id)
            })
            .await
            {
                add_error(&mut error, failure);
            }
            {
                let mut metadata = lock(&owner.metadata);
                metadata.removal = None;
                metadata.phase = if metadata.closing {
                    Phase::Stopping
                } else {
                    Phase::Idle
                };
                if error.is_some() {
                    metadata.error = error.clone();
                    metadata.terminal = Some("failed");
                }
                done.finish(error.map_or(Ok(()), Err));
            }
            owner.notify();
        });
        self.inner.notify();
        Ok(receipt)
    }

    pub fn request_close(&self) -> LanCompletion {
        self.inner.request_close()
    }
}

impl Drop for LanOwner {
    fn drop(&mut self) {
        self.inner.request_close();
    }
}

impl OwnerState {
    fn request_close(self: &Arc<Self>) -> LanCompletion {
        let (scan, removal, notifier) = {
            let mut metadata = lock(&self.metadata);
            if metadata.closing {
                return self.closed.clone();
            }
            metadata.closing = true;
            if metadata.phase != Phase::Removing {
                metadata.phase = Phase::Stopping;
            }
            if metadata.scan_running {
                if let Some(scan) = &metadata.scan {
                    scan.control.cancel();
                }
            }
            (
                metadata.scan.clone(),
                metadata.removal.clone(),
                metadata.notifier.take(),
            )
        };
        let owner = self.clone();
        self.runtime.spawn(async move {
            let mut error = None;
            // Admission only takes the callback out of metadata. Release its
            // caller-owned captures here, never under a bridge admission lock.
            if let Err(panic) = catch_unwind(AssertUnwindSafe(|| drop(notifier))) {
                add_error(&mut error, panic_error("LAN notifier release", panic));
            }
            if let Some(scan) = scan {
                if let Err(failure) = scan.done.wait().await {
                    add_error(&mut error, failure);
                }
            }
            if let Some(removal) = removal {
                if let Err(failure) = removal.wait().await {
                    add_error(&mut error, failure);
                }
            }
            // Joins above cover writes. This barrier also waits for any cache
            // query admitted before closing; late queries recheck and do no I/O.
            if let Err(failure) = run_blocking(owner.runtime, || {
                let _cache = lock(&CACHE);
                Ok(())
            })
            .await
            {
                add_error(&mut error, failure);
            }
            loop {
                let changed = owner.notices_changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if lock(&owner.metadata).notices == 0 {
                    break;
                }
                changed.await;
            }
            // Retire and publish completion under the namespace gate. A new
            // owner can be acquired only after all admitted work is observed.
            let mut namespace = lock(&NAMESPACE);
            {
                let mut metadata = lock(&owner.metadata);
                if let Some(failure) = metadata.error.as_ref() {
                    add_error(&mut error, failure.clone());
                }
                metadata.phase = Phase::Closed;
                if let Some(failure) = error.as_ref() {
                    metadata.error = Some(failure.clone());
                    metadata.terminal = Some("failed");
                }
            }
            owner.closed.finish(error.map_or(Ok(()), Err));
            if namespace
                .owner
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &owner))
            {
                namespace.owner = None;
            }
        });
        self.closed.clone()
    }

    fn stopping(self: &Arc<Self>, scan_id: u64) {
        {
            let mut metadata = lock(&self.metadata);
            if metadata.scan_id() != Some(scan_id) || metadata.phase != Phase::Scanning {
                return;
            }
            metadata.phase = Phase::Stopping;
        }
        self.notify();
    }

    fn load_peers(&self) -> Vec<config::DiscoveryPeer> {
        let _cache = lock(&CACHE);
        config::LanPeers::load().peers
    }

    fn store_peers(self: &Arc<Self>, peers: &[config::DiscoveryPeer]) -> Result<(), String> {
        {
            let _cache = lock(&CACHE);
            store_peers(peers)?;
        }
        self.notify();
        Ok(())
    }

    fn notify(self: &Arc<Self>) {
        let notice = {
            let mut metadata = lock(&self.metadata);
            if metadata.closing || metadata.notifier.is_none() {
                return;
            }
            metadata.notices += 1;
            LanNotice {
                owner_generation: self.generation,
                scan_id: metadata.scan_id(),
                cache_revision: CACHE_REVISION.load(Ordering::Acquire),
            }
        };
        let owner = self.clone();
        // Dispatch on a real existing-runtime async worker (not a socket thread
        // or spawn_blocking worker). Callbacks may use tokio::task::spawn_blocking.
        self.runtime.spawn(async move {
            let _guard = NoticeGuard(owner.clone());
            let notifier = {
                let metadata = lock(&owner.metadata);
                if metadata.closing {
                    None
                } else {
                    metadata.notifier.clone()
                }
            };
            if let Some(notifier) = notifier {
                if let Err(panic) = catch_unwind(AssertUnwindSafe(|| notifier(notice))) {
                    let failure = panic_error("LAN notifier", panic);
                    let retired_notifier = {
                        let mut metadata = lock(&owner.metadata);
                        metadata.error = Some(failure.clone());
                        metadata.terminal = Some("failed");
                        if metadata.scan_running {
                            if let Some(scan) = &metadata.scan {
                                scan.control.fail(failure);
                            }
                            if metadata.phase != Phase::Removing {
                                metadata.phase = Phase::Stopping;
                            }
                        }
                        metadata.notifier.take()
                    };
                    drop(retired_notifier);
                }
            }
        });
    }
}

struct NoticeGuard(Arc<OwnerState>);

impl Drop for NoticeGuard {
    fn drop(&mut self) {
        let mut metadata = lock(&self.0.metadata);
        metadata.notices -= 1;
        self.0.notices_changed.notify_waiters();
    }
}

// Pinned ui_interface.rs:809-830 projection/removal. CACHE is held by callers;
// the only added store wrapper advances the write-attempt revision, even when
// the upstream void/log-only persistence API does not save successfully.
#[inline]
fn get_lan_peers() -> Vec<HashMap<&'static str, String>> {
    config::LanPeers::load()
        .peers
        .iter()
        .map(|peer| {
            HashMap::<&str, String>::from_iter([
                ("id", peer.id.clone()),
                ("username", peer.username.clone()),
                ("hostname", peer.hostname.clone()),
                ("platform", peer.platform.clone()),
            ])
        })
        .collect()
}

#[inline]
fn remove_discovered(id: String) -> Result<(), String> {
    let mut peers = config::LanPeers::load().peers;
    peers.retain(|x| x.id != id);
    store_peers(&peers)
}

fn store_peers(peers: &[config::DiscoveryPeer]) -> Result<(), String> {
    let revision = CACHE_REVISION
        .load(Ordering::Relaxed)
        .checked_add(1)
        .ok_or_else(|| "LAN cache revision exhausted".to_owned())?;
    CACHE_REVISION.store(revision, Ordering::Release);
    config::LanPeers::store(peers);
    Ok(())
}

async fn run_blocking<F>(runtime: &'static Runtime, work: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    // A startup panic creates no unobserved coordinator. Once spawned, the
    // JoinHandle is always awaited here, including a worker unwind.
    let task = catch_unwind(AssertUnwindSafe(|| runtime.spawn_blocking(work)))
        .map_err(|panic| panic_error("LAN blocking task admission", panic))?;
    task.await
        .map_err(|error| format!("LAN blocking task failed: {error}"))?
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned metadata lock cannot be allowed to skip owned cleanup.
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn panic_error(context: &str, panic: Box<dyn Any + Send>) -> String {
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic");
    format!("{context} panicked: {message}")
}

fn add_error(error: &mut Option<String>, failure: String) {
    match error {
        Some(existing) if *existing == failure => {}
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&failure);
        }
        None => *error = Some(failure),
    }
}
