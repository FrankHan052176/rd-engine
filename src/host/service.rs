//! One owned host-service run: the real listener/route admission, the hbbs
//! registration worker and the controlled credential owner, fenced by one run
//! epoch.
//!
//! This is the HarmonyOS host container, not the Windows-only `HostController`:
//! it never reads or writes the official desktop configuration, never touches a
//! Win32 producer and never claims a capture fact on its own. Starting waits for
//! the Host's own listener/route admission only — a session with no controller
//! really is `listening` with no capture, and that is a normal, sustainable
//! state rather than a failed start.
use super::security::HostSecurity;
use super::*;
use crate::authentication::{Passwords, PrimaryPolicy};
use crate::rendezvous::{
    IncomingHostRoute, RegistrationConfig, RegistrationState, run_host_registration,
};
use hbb_common::sodiumoxide::randombytes;
use std::net::SocketAddr;

/// Default encoded bitrate offered to a controller. It is a real
/// `PublisherConfig` input, not a reported measurement.
pub const DEFAULT_BITRATE: i64 = 8_000_000;
/// The same registration run window the existing host owner uses.
const REGISTRATION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// Listener/route admission bound. A refused start leaves no owner behind.
const START_TIMEOUT: Duration = Duration::from_secs(20);
/// Native teardown bound. Exceeding it is an unconfirmed reclamation, never a
/// clean stop, and the owner is not reused afterwards.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);
const TEMPORARY_PASSWORD_LEN: usize = 10;
const TEMPORARY_PASSWORD_ALPHABET: &[u8] =
    b"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

/// Password-or-click mode, used only when the caller did not require a local
/// approval. A caller requiring approval gets ClickOnly for the entire run,
/// including credential rotations and security-setting updates.
pub const APPROVE_MODE: &str = "both";

fn primary_policy(require_local_approval: bool) -> PrimaryPolicy {
    if require_local_approval {
        PrimaryPolicy::ClickOnly
    } else {
        PrimaryPolicy::PasswordOrClick
    }
}

/// This process could not prove that an earlier host owner released its native
/// capture/listener ownership. Nothing may start on top of it.
static UNRECLAIMED: AtomicBool = AtomicBool::new(false);
/// Run epochs never restart, so a request from an earlier run can never match a
/// later one.
static NEXT_RUN: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostRegistration {
    Registering,
    AddressObserved,
    /// hbbs answered this run's own registration. An observation over the
    /// registration channel, not authenticated presence and not capture ready.
    Observed,
    Stale,
    Refused,
    Conflict,
    Failed,
    Stopped,
}
impl HostRegistration {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registering => "registering",
            Self::AddressObserved => "address_observed",
            Self::Observed => "observed",
            Self::Stale => "stale",
            Self::Refused => "refused",
            Self::Conflict => "conflict",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
        }
    }
    /// hbbs really observed this run's registration. It is not "online",
    /// "authenticated" or "capturing".
    pub fn observed(self) -> bool {
        matches!(self, Self::Observed)
    }
    fn from_state(state: RegistrationState) -> Self {
        match state {
            RegistrationState::Registering => Self::Registering,
            RegistrationState::AddressObserved => Self::AddressObserved,
            RegistrationState::Observed { .. } => Self::Observed,
            RegistrationState::Stale => Self::Stale,
            RegistrationState::Refused(_) => Self::Refused,
            RegistrationState::Conflict(_) => Self::Conflict,
            RegistrationState::Failed(_) => Self::Failed,
            RegistrationState::Stopped(_) => Self::Stopped,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostServiceError {
    InvalidOptions,
    NoRuntime,
    /// An earlier owner never proved reclamation; a new run is refused.
    OwnerUnconfirmed,
    NotRunning,
    /// The named run epoch is not this service's current run.
    StaleRun,
    /// The Host owner itself refused or failed (listener, transport, capture…).
    Host(HostError),
    /// hbbs registration could not even be configured; no acquisition ran.
    Registration,
    /// The stored verification method does not accept a temporary password, so a
    /// rotated one could never authenticate and is not produced.
    TemporaryPasswordDisabled,
}
impl fmt::Display for HostServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOptions => write!(f, "Invalid host service options"),
            Self::NoRuntime => write!(f, "Engine runtime unavailable"),
            Self::OwnerUnconfirmed => {
                write!(f, "A previous host owner did not confirm reclamation")
            }
            Self::NotRunning => write!(f, "The host service is not running"),
            Self::StaleRun => write!(f, "The request belongs to another host service run"),
            Self::Host(error) => write!(f, "Host owner failed: {error}"),
            Self::Registration => write!(f, "Host registration configuration is invalid"),
            Self::TemporaryPasswordDisabled => write!(
                f,
                "The stored verification method does not accept a temporary password"
            ),
        }
    }
}
impl std::error::Error for HostServiceError {}

/// Everything one run needs. Contains signing/identity material and the server
/// wire key, so it deliberately implements neither `Debug` nor `Clone`.
pub struct HostServiceOptions {
    /// The official local ID this device is already known by.
    pub id: String,
    /// Human-readable device name, not the signed identity or login target.
    pub display_name: String,
    pub public_key: sign::PublicKey,
    pub signing_key: sign::SecretKey,
    /// Stable registration UUID. Erased by the owning run when it ends.
    pub registration_uuid: Vec<u8>,
    pub rendezvous_server: String,
    pub relay_server: Option<String>,
    /// Exact licence/public key wire value. Never logged.
    pub licence_key: String,
    /// Current display geometry supplied by the platform display owner.
    pub width: i32,
    pub height: i32,
    pub bitrate: i64,
    pub platform: String,
    /// Direct-access listener this run binds, or `None` when every controller
    /// must arrive through this run's own hbbs registration. A bound listener
    /// is what makes the run reachable by `IP:port`, so it stays the caller's
    /// decision instead of being implied by `ready`.
    pub listen: Option<SocketAddr>,
    /// Whether the direct listener may serve the protocol's plain handshake.
    /// A controller that dialled an address holds no pinned peer key, so it
    /// cannot complete the signed exchange; direct IP access is that legacy
    /// path. Peers admitted through hbbs are unaffected: their routes always
    /// require encryption.
    pub allow_legacy_plain: bool,
    pub require_local_approval: bool,
    /// Explicit local keyboard/pointer grant. On OHOS the process must already
    /// have dialog injection authorization; starting never requests it.
    pub allow_input: bool,
    #[cfg(target_env = "ohos")]
    pub input_authorization_request_id: Option<u64>,
    /// The one app-private security record this run authenticates with. The run
    /// keeps this exact `Arc`: the password/2FA surface mutates the same owner,
    /// so a change is the state this host really checks, and a republish needs
    /// no second store and no second file.
    pub security: Arc<HostSecurity>,
}

/// The observable state of this service, derived from the owners themselves.
#[derive(Clone)]
pub struct HostServiceStatus {
    /// The current (or last attempted) run. Zero before the first start.
    pub run_epoch: u64,
    /// `disabled` | `starting` | `listening` | `stopping` | `failed`.
    pub state: &'static str,
    /// The Host's own phase, verbatim.
    pub host_phase: &'static str,
    pub registration: HostRegistration,
    pub registration_observed: bool,
    pub id: String,
    pub width: i32,
    pub height: i32,
    pub peers: Vec<HostPeerSnapshot>,
    pub peer_count: u32,
    pub authorized_peers: u32,
    /// The Host owner's live, admitted grant, not the requested configuration.
    pub input_enabled: bool,
    pub error: Option<HostServiceError>,
    pub teardown_unconfirmed: bool,
    /// This service's real local-approval policy, empty when no run is live.
    pub approve_mode: &'static str,
    /// The policy belongs to this service run and is released when it stops.
    pub approve_mode_scoped: bool,
    /// A correct password authorizes without a local click under `both`.
    pub local_approval_enforced: bool,
}

/// The request token a consumer answers. It names the run epoch, the peer, the
/// approval epoch and the credential revision together, so an old answer cannot
/// be applied to a later connection.
pub fn request_id(run_epoch: u64, peer: &HostPeerSnapshot) -> Option<String> {
    peer.approval_epoch.map(|approval| {
        format!(
            "{run_epoch}:{}:{approval}:{}",
            peer.conn_id, peer.policy_revision
        )
    })
}

fn parse_request_id(value: &str) -> Option<(u64, u64, u64, u64)> {
    let mut parts = value.split(':');
    let run = parts.next()?.parse::<u64>().ok()?;
    let conn = parts.next()?.parse::<u64>().ok()?;
    let approval = parts.next()?.parse::<u64>().ok()?;
    let revision = parts.next()?.parse::<u64>().ok()?;
    parts
        .next()
        .is_none()
        .then_some((run, conn, approval, revision))
}

#[derive(Clone, Copy)]
struct Facts {
    epoch: u64,
    state: &'static str,
    error: Option<HostServiceError>,
    teardown_unconfirmed: bool,
}
impl Default for Facts {
    fn default() -> Self {
        Self {
            epoch: 0,
            state: "disabled",
            error: None,
            teardown_unconfirmed: false,
        }
    }
}

/// One live run. Its owners are exactly the ones the close boundary joins.
struct Run {
    epoch: u64,
    require_local_approval: bool,
    host: Arc<Host>,
    /// Cancels the registration worker only; the Host keeps its own token.
    cancel: CancellationToken,
    registration: Option<tokio::task::JoinHandle<()>>,
    states: watch::Receiver<RegistrationState>,
    report: Arc<Mutex<HostRegistration>>,
    credentials: Arc<HostCredentials>,
    /// The same security record this run published its verifier set from. The
    /// salt, the accepted password set and the second factor are read live from
    /// it, so a change through the NAPI surface is this run's state.
    security: Arc<HostSecurity>,
    /// Plaintext temporary password, held by this owner for the explicit getter.
    temporary_password: String,
    id: String,
    width: i32,
    height: i32,
}

pub struct HostService {
    run: Mutex<Option<Run>>,
    facts: Mutex<Facts>,
    /// A run taken out of `run` still belongs to its in-flight teardown.
    closing: tokio::sync::Mutex<()>,
}

/// A freshly generated temporary password. This is only the plaintext the local
/// UI may show; what the Host keeps is the verifier
/// [`HostSecurity::verifier`] derives from it with the record's stable salt.
fn new_temporary_password() -> String {
    (0..TEMPORARY_PASSWORD_LEN)
        .map(|_| {
            let index = randombytes::randombytes_uniform(TEMPORARY_PASSWORD_ALPHABET.len() as u32);
            TEMPORARY_PASSWORD_ALPHABET[index as usize] as char
        })
        .collect()
}

/// The primary verifier set this run authenticates with, exactly as the stored
/// method decides it: the temporary verifier only while the method accepts a
/// temporary password, and the permanent verifier only while it accepts that.
///
/// Both are derived with the record's own salt because one `HostAuthConfig`
/// publishes exactly one salt per connection. A per-rotation random salt would
/// make the persisted permanent verifier — whose plaintext is never kept — fail
/// every challenge, so the salt belongs to the record, not to the rotation.
fn host_passwords(security: &HostSecurity, temporary_password: &str) -> Passwords {
    let temporary = security
        .accepts_temporary_password()
        .then(|| security.verifier(temporary_password.as_bytes()));
    Passwords::from_host(temporary, security.permanent_verifier())
}

impl HostService {
    fn new() -> Self {
        Self {
            run: Mutex::new(None),
            facts: Mutex::new(Facts::default()),
            closing: tokio::sync::Mutex::new(()),
        }
    }

    /// Starts one run and blocks until the Host's own listener/route admission
    /// resolves. It never waits for a capture consent or a first access unit.
    pub fn start(options: HostServiceOptions) -> Arc<Self> {
        let service = Arc::new(Self::new());
        let outcome = match crate::executor::runtime() {
            Ok(runtime) => runtime.block_on(service.launch(options)),
            Err(_) => Err(HostServiceError::NoRuntime),
        };
        if let Err(error) = outcome {
            let mut facts = lock(&service.facts);
            facts.state = "failed";
            facts.error = Some(error);
        }
        service
    }

    async fn launch(&self, options: HostServiceOptions) -> Result<(), HostServiceError> {
        if UNRECLAIMED.load(Ordering::Acquire) {
            return Err(HostServiceError::OwnerUnconfirmed);
        }
        if options.id.is_empty()
            || options.id.len() > 512
            || options.rendezvous_server.is_empty()
            || options.licence_key.is_empty()
            || options.registration_uuid.is_empty()
        {
            return Err(HostServiceError::InvalidOptions);
        }
        let epoch = NEXT_RUN
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| HostServiceError::InvalidOptions)?
            + 1;
        // The accepted primary set belongs to the record, not to this run: its
        // salt is stable, so the persisted permanent verifier keeps matching and
        // a stored method really decides which passwords are accepted.
        let temporary_password = new_temporary_password();
        let host_credentials = Arc::new(HostCredentials::new(
            1,
            options.security.salt(),
            host_passwords(&options.security, &temporary_password),
            primary_policy(options.require_local_approval),
        ));
        let (routes, route_rx) = mpsc::channel::<IncomingHostRoute>(8);
        let host_options = HostOptions {
            listen: options.listen,
            allow_legacy_plain: options.allow_legacy_plain,
            id: options.id.clone(),
            display_name: options.display_name,
            signing_key: options.signing_key,
            width: options.width,
            height: options.height,
            bitrate: options.bitrate,
            platform: options.platform,
            credentials: host_credentials.clone(),
            security: Some(options.security.clone()),
            publisher_backend: PublisherBackend::Auto,
            #[cfg(all(
                any(target_os = "windows", dsh_windows_typecheck),
                feature = "windows-modern-producer"
            ))]
            output_key: "0".into(),
            #[cfg(not(all(
                any(target_os = "windows", dsh_windows_typecheck),
                feature = "windows-modern-producer"
            )))]
            output_index: 0,
            allow_input: options.allow_input,
            #[cfg(target_env = "ohos")]
            input_authorization_request_id: options.input_authorization_request_id,
            codec_selection: CodecSelection::Auto,
        };
        let host =
            Arc::new(Host::start(host_options, Some(route_rx)).map_err(HostServiceError::Host)?);
        let cancel = CancellationToken::new();
        let (states, state_rx) = watch::channel(RegistrationState::Registering);
        let report = Arc::new(Mutex::new(HostRegistration::Registering));
        let registration = crate::executor::runtime()
            .map_err(|_| HostServiceError::NoRuntime)?
            .spawn(registration_worker(
                RegistrationConfig {
                    id: options.id.clone(),
                    registration_uuid: options.registration_uuid,
                    public_key: options.public_key,
                    rendezvous_server: options.rendezvous_server,
                    relay_server: options.relay_server,
                    licence_key: options.licence_key,
                    deadline: REGISTRATION_WINDOW,
                },
                cancel.clone(),
                states,
                report.clone(),
                routes,
            ));
        {
            let mut facts = lock(&self.facts);
            let teardown_unconfirmed = facts.teardown_unconfirmed;
            *facts = Facts {
                epoch,
                state: "starting",
                error: None,
                teardown_unconfirmed,
            };
        }
        {
            let mut slot = lock(&self.run);
            *slot = Some(Run {
                epoch,
                require_local_approval: options.require_local_approval,
                host: host.clone(),
                cancel: cancel.clone(),
                registration: Some(registration),
                states: state_rx,
                report,
                credentials: host_credentials,
                // The same record `security_store()` handed this process, so the
                // run's second factor and a NAPI password/2FA change are one
                // state, never two stores.
                security: options.security,
                temporary_password,
                id: options.id,
                width: options.width,
                height: options.height,
            });
        }
        // The real admission boundary: the Host's own listener/route hand-off.
        let ready = tokio::time::timeout(START_TIMEOUT, host.wait_ready()).await;
        // A concurrent stop may have taken this run; it owns the teardown then.
        if !lock(&self.run)
            .as_ref()
            .is_some_and(|run| run.epoch == epoch)
        {
            return Err(HostServiceError::StaleRun);
        }
        match ready {
            Ok(Ok(())) => {
                lock(&self.facts).state = "listening";
                Ok(())
            }
            Ok(Err(error)) => {
                self.close_owned(epoch, Some(error)).await;
                Err(HostServiceError::Host(error))
            }
            Err(_) => {
                self.close_owned(epoch, None).await;
                Err(HostServiceError::Host(HostError::ListenFailed))
            }
        }
    }

    /// Stops the named run and waits for every owner it holds. An empty epoch
    /// means "the run this service currently has"; a mismatched epoch is refused
    /// so an old stop can never terminate a later run.
    pub fn stop(&self, epoch: Option<u64>) -> Result<HostServiceStatus, HostServiceError> {
        match crate::executor::runtime() {
            Ok(runtime) => runtime.block_on(self.stop_async(epoch)),
            Err(_) => Err(HostServiceError::NoRuntime),
        }
    }

    async fn stop_async(&self, epoch: Option<u64>) -> Result<HostServiceStatus, HostServiceError> {
        // A concurrent close may already have taken the run. Wait for its real
        // join before reading an empty slot as an idempotently completed stop.
        let _closing = self.closing.lock().await;
        // Taking the run and validating the epoch happen under one lock, so a
        // stop can never terminate a run other than the one it names.
        let run = {
            let mut slot = lock(&self.run);
            if slot
                .as_ref()
                .is_some_and(|run| epoch.is_some_and(|asked| asked != run.epoch))
            {
                return Err(HostServiceError::StaleRun);
            }
            slot.take()
        };
        let Some(run) = run else {
            // Nothing is owned: an idempotent stop of a stale owner is a no-op,
            // but a stop naming a different, older run is still refused.
            if epoch.is_some_and(|epoch| epoch != lock(&self.facts).epoch) {
                return Err(HostServiceError::StaleRun);
            }
            return Ok(self.status());
        };
        {
            let mut facts = lock(&self.facts);
            facts.state = "stopping";
        }
        self.teardown(run).await;
        Ok(self.status())
    }

    /// Joins the run this service owns, if it was not taken by `stop`.
    async fn close_owned(&self, epoch: u64, error: Option<HostError>) {
        let _closing = self.closing.lock().await;
        let run = {
            let mut slot = lock(&self.run);
            if slot.as_ref().is_some_and(|run| run.epoch == epoch) {
                slot.take()
            } else {
                None
            }
        };
        if let Some(run) = run {
            self.teardown(run).await;
        }
        let mut facts = lock(&self.facts);
        facts.state = "failed";
        facts.error = error.map(HostServiceError::Host).or(facts.error);
    }

    /// The single close boundary: the run's own peers first get their terminal
    /// reason, then the Host and the registration worker are joined. A join this
    /// process cannot confirm latches the process-wide quarantine.
    async fn teardown(&self, run: Run) {
        // Best-effort manual reason; the absolute deadline bounds only the send,
        // never the joins below.
        let _ = tokio::time::timeout(STOP_TIMEOUT, run.host.notify_stop_service(None)).await;
        run.cancel.cancel();
        let closed = tokio::time::timeout(STOP_TIMEOUT, run.host.close()).await;
        let clean = matches!(closed, Ok(Ok(())));
        if let Some(registration) = run.registration {
            let _ = tokio::time::timeout(STOP_TIMEOUT, registration).await;
        }
        let mut facts = lock(&self.facts);
        facts.epoch = run.epoch;
        if clean {
            facts.state = "disabled";
            facts.error = None;
        } else {
            UNRECLAIMED.store(true, Ordering::Release);
            facts.state = "failed";
            facts.teardown_unconfirmed = true;
            facts.error = Some(HostServiceError::Host(HostError::ReclamationUnconfirmed));
        }
    }

    /// The current observable state. Every field is read from an owner: the Host
    /// (listener, peers, capture projections), the registration worker, or the
    /// facts this service itself recorded.
    pub fn status(&self) -> HostServiceStatus {
        let facts = *lock(&self.facts);
        let slot = lock(&self.run);
        let run = slot.as_ref();
        let mut state = facts.state;
        let mut error = facts.error;
        let mut host_phase = "disabled";
        let mut peers = Vec::new();
        let mut registration = HostRegistration::Stopped;
        let mut id = String::new();
        let mut width = 0;
        let mut height = 0;
        let mut input_enabled = false;
        if let Some(run) = run {
            id = run.id.clone();
            width = run.width;
            height = run.height;
            let snapshot = run.host.snapshot();
            input_enabled = snapshot.input_enabled;
            host_phase = snapshot.phase;
            // The Host's own terminal verdict owns the service state.
            if matches!(state, "starting" | "listening")
                && (snapshot.closed || snapshot.error.is_some())
            {
                state = "failed";
                error = snapshot.error.map(HostServiceError::Host).or(error);
            }
            peers = run.host.peers();
            registration = if matches!(*lock(&run.report), HostRegistration::Failed) {
                HostRegistration::Failed
            } else {
                HostRegistration::from_state(*run.states.borrow())
            };
        }
        let authorized = peers.iter().filter(|peer| peer.authorized).count() as u32;
        HostServiceStatus {
            run_epoch: facts.epoch,
            state,
            host_phase,
            registration,
            registration_observed: registration.observed(),
            id,
            width,
            height,
            peer_count: peers.len() as u32,
            authorized_peers: authorized,
            input_enabled,
            peers,
            error,
            teardown_unconfirmed: facts.teardown_unconfirmed,
            approve_mode: match run.as_ref() {
                Some(run) if run.require_local_approval => "click",
                Some(_) => APPROVE_MODE,
                None => "",
            },
            approve_mode_scoped: run.is_some(),
            local_approval_enforced: run.as_ref().is_some_and(|run| run.require_local_approval),
        }
    }

    pub fn is_running(&self) -> bool {
        lock(&self.run).is_some()
    }

    pub fn run_epoch(&self) -> u64 {
        lock(&self.run)
            .as_ref()
            .map(|run| run.epoch)
            .unwrap_or_else(|| lock(&self.facts).epoch)
    }

    /// The plaintext temporary password, only while this service really owns one
    /// and the record's method accepts it. A permanent-only method keeps the
    /// plaintext inside the run — a later method change re-derives the same
    /// verifier from it — but it is not a password in force, so it is not
    /// reported as one.
    pub fn temporary_password(&self) -> Option<String> {
        let slot = lock(&self.run);
        let run = slot.as_ref()?;
        run.security
            .accepts_temporary_password()
            .then(|| run.temporary_password.clone())
    }

    /// Replaces the temporary verifier of the live run. The Host republishes the
    /// new revision, which closes authentication for peers that had not
    /// authorized yet; a peer that already authorized keeps its session. A
    /// method that accepts no temporary password refuses instead of producing a
    /// password that could never authenticate.
    pub fn rotate_temporary_password(&self) -> Result<String, HostServiceError> {
        let mut slot = lock(&self.run);
        let run = slot.as_mut().ok_or(HostServiceError::NotRunning)?;
        if !run.security.accepts_temporary_password() {
            return Err(HostServiceError::TemporaryPasswordDisabled);
        }
        let password = new_temporary_password();
        let revised = Arc::new(HostCredentials::revised(
            run.credentials.revision.wrapping_add(1),
            run.security.salt(),
            host_passwords(&run.security, &password),
            primary_policy(run.require_local_approval),
            &run.credentials,
        ));
        run.host.update_credentials(revised.clone());
        run.credentials = revised;
        run.temporary_password = password.clone();
        Ok(password)
    }

    /// Rebuilds the live run's credentials from `security` — the same record the
    /// run started from — with the temporary plaintext it already holds, and
    /// publishes them under a new revision.
    ///
    /// This is what makes a security change real for authentication rather than
    /// only stored: `Host::update_credentials` closes every peer that had not
    /// authorized yet and moves the revision the approval path checks, so the
    /// next attempt is decided by the new verifier set while an already
    /// authorized session keeps its own. No live run is not an error — the next
    /// start reads the same record — and a live one reports what really happened.
    pub fn apply_security_credentials(
        &self,
        security: &Arc<HostSecurity>,
    ) -> Result<(), HostServiceError> {
        let mut slot = lock(&self.run);
        let Some(run) = slot.as_mut() else {
            return Ok(());
        };
        let revised = Arc::new(HostCredentials::revised(
            run.credentials.revision.wrapping_add(1),
            security.salt(),
            host_passwords(security, &run.temporary_password),
            primary_policy(run.require_local_approval),
            &run.credentials,
        ));
        run.host.update_credentials(revised.clone());
        run.credentials = revised;
        Ok(())
    }

    /// Latches this local decision for exactly the connection it names.
    pub fn approve(&self, request: &str, allow: bool) -> Result<(), HostServiceError> {
        let (run_epoch, conn_id, approval, revision) =
            parse_request_id(request).ok_or(HostServiceError::InvalidOptions)?;
        let conn_id = i32::try_from(conn_id).map_err(|_| HostServiceError::InvalidOptions)?;
        let slot = lock(&self.run);
        let run = slot.as_ref().ok_or(HostServiceError::NotRunning)?;
        if run.epoch != run_epoch {
            return Err(HostServiceError::StaleRun);
        }
        run.host
            .approve_peer(conn_id, approval, revision, allow)
            .map_err(HostServiceError::Host)
    }

    /// Synchronous fence for an app-lifecycle revocation: nothing new is accepted
    /// and every peer is asked to end. The joined cleanup still happens in the
    /// run's own stop, so no caller here claims reclamation.
    pub fn request_close(service: &Arc<Self>) {
        {
            let mut facts = lock(&service.facts);
            if !matches!(facts.state, "disabled" | "failed") {
                facts.state = "stopping";
            }
        }
        let host = lock(&service.run).as_ref().map(|run| run.host.clone());
        if let Some(host) = host {
            host.request_close();
        }
        if let Some(run) = lock(&service.run).as_ref() {
            run.cancel.cancel();
        }
        // Complete the joined teardown off the caller's thread. It still reports
        // an unconfirmed reclamation as such.
        let Ok(runtime) = crate::executor::runtime() else {
            return;
        };
        let service = service.clone();
        runtime.spawn(async move {
            let _ = service.stop_async(None).await;
        });
    }
}

impl Drop for HostService {
    fn drop(&mut self) {
        // A dropped service must not leave a listener accepting. The Host's
        // original serve task still owns checked release/join and its input
        // run share; neither this Drop nor runtime shutdown claims reclamation.
        if let Some(run) = lock(&self.run).as_ref() {
            run.host.request_close();
            run.cancel.cancel();
        }
    }
}

/// One registration window for this run. The worker owns its own acquisition
/// tasks; a failed start is latched so the observed state is never left showing
/// "registering" for a worker that already ended.
fn registration_worker(
    config: RegistrationConfig,
    cancel: CancellationToken,
    states: watch::Sender<RegistrationState>,
    report: Arc<Mutex<HostRegistration>>,
    routes: mpsc::Sender<IncomingHostRoute>,
) -> impl std::future::Future<Output = ()> {
    async move {
        let ended = run_host_registration(config, cancel, states, routes).await;
        if ended.is_err() {
            *lock(&report) = HostRegistration::Failed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::StopReason;

    #[test]
    fn a_request_token_names_its_own_run_connection_and_credentials() {
        let peer = HostPeerSnapshot {
            conn_id: 7,
            connection_token: 7,
            approval_epoch: Some(11),
            policy_revision: 3,
            peer_id: "865000001".into(),
            name: "controller".into(),
            authorized: false,
            disconnected: false,
            phase: "awaiting_approval",
            keyboard: false,
            error: None,
            capture: None,
        };
        let token = request_id(4, &peer).expect("an awaiting peer has a token");
        assert_eq!(token, "4:7:11:3");
        assert_eq!(parse_request_id(&token), Some((4, 7, 11, 3)));

        // A peer that is not awaiting a decision has nothing to answer, so an
        // old approval can never be replayed against it.
        let mut authorized = peer.clone();
        authorized.approval_epoch = None;
        assert_eq!(request_id(4, &authorized), None);

        // Malformed or extended tokens are refused, not partially parsed.
        for value in [
            "",
            "4",
            "4:7",
            "4:7:11",
            "4:7:11:3:9",
            "a:7:11:3",
            "4:-7:11:3",
        ] {
            assert_eq!(parse_request_id(value), None, "{value:?}");
        }
    }

    #[test]
    fn a_worker_that_ends_badly_is_never_reported_as_registering() {
        assert_eq!(
            HostRegistration::from_state(RegistrationState::Registering),
            HostRegistration::Registering
        );
        assert!(
            HostRegistration::from_state(RegistrationState::Observed { keep_alive_raw: 0 })
                .observed()
        );
        // An address observation is not the identity acknowledged by hbbs.
        assert!(!HostRegistration::from_state(RegistrationState::AddressObserved).observed());
        assert!(!HostRegistration::from_state(RegistrationState::Stale).observed());
        assert_eq!(
            HostRegistration::from_state(RegistrationState::Stopped(StopReason::Cancelled)),
            HostRegistration::Stopped
        );
        assert_eq!(HostRegistration::Failed.as_str(), "failed");
    }

    #[test]
    fn a_service_with_no_run_reports_no_capture_and_no_scoped_policy() {
        let service = HostService::new();
        let status = service.status();
        assert_eq!(status.state, "disabled");
        assert_eq!(status.run_epoch, 0);
        assert!(status.peers.is_empty());
        assert_eq!(status.peer_count, 0);
        assert!(!status.input_enabled);
        assert!(!status.teardown_unconfirmed);
        // A policy is only reported while this service really runs.
        assert_eq!(status.approve_mode, "");
        assert!(!status.approve_mode_scoped);
        assert!(!status.local_approval_enforced);
        assert_eq!(service.temporary_password(), None);
        assert_eq!(
            service.rotate_temporary_password(),
            Err(HostServiceError::NotRunning)
        );
        assert_eq!(
            service.approve("0:0:0:0", true),
            Err(HostServiceError::NotRunning)
        );
    }

    #[tokio::test]
    async fn a_repeated_stop_waits_for_the_teardown_that_already_took_the_run() {
        let service = HostService::new();
        // Model the interval after the first close took the run but before its
        // native joins completed. The second stop must not return "stopping"
        // from the now-empty slot as though it had confirmed reclamation.
        let closing = service.closing.lock().await;
        *lock(&service.facts) = Facts {
            epoch: 7,
            state: "stopping",
            ..Facts::default()
        };
        let pending = service.stop_async(Some(7));
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        lock(&service.facts).state = "disabled";
        drop(closing);
        let status = pending.await.expect("the same run's completed close");
        assert_eq!(status.run_epoch, 7);
        assert_eq!(status.state, "disabled");
        assert!(!status.teardown_unconfirmed);
    }
}
