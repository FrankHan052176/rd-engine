use super::{configuration as cfg, *};
use crate::{host::{Host, HostCredentials, HostError, HostPeerSnapshot}, rendezvous::{self as registration, RegistrationConfig, RegistrationState, StopReason}};
use hbb_common::{config::{CheckedHostConfig, Config}, sodiumoxide::{self, crypto::sign}};
use std::{sync::atomic::{AtomicBool, Ordering}, time::Duration};
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(super) fn initialize() -> Result<Arc<HostController>, ControlError> {
    if INITIALIZED.swap(true, Ordering::AcqRel) { return Err(ControlError("Host controller was already initialized")); }
    let config = Config::checked_host_initialize().map_err(|_| ControlError("Checked host identity or configuration could not be loaded"))?;
    cfg::validate(&config.options)?;
    if Config::no_register_device() { return Err(ControlError("Host registration is disabled by local deployment policy")); }
    if Config::is_proxy() { return Err(ControlError("Configured host proxy transport is unsupported")); }
    let temporary = cfg::temporary(&config.options);
    let credentials = cfg::credentials(&config, &temporary, 1, None);
    let mut random = [0u8; 8];
    sodiumoxide::randombytes::randombytes_into(&mut random);
    let owner_epoch = u64::from_le_bytes(random).max(1);
    let mut snapshot = ServiceSnapshot {
        owner_epoch, run_epoch: 0, revision: 1, policy_revision: 1, id: String::new(), fingerprint: String::new(),
        permanent_password_set: false, local_permanent_password_set: false, preset_password: false,
        phase: "stopped".into(), ready: false, registration: "stopped".into(), status_num: 0,
        error: None, options: HashMap::new(), peers: Vec::new(),
    };
    cfg::apply_metadata(&mut snapshot, &config);
    let (states, receiver) = watch::channel(snapshot.clone());
    let (commands, requests) = mpsc::channel(32);
    let controller = Arc::new(HostController { commands, states: receiver, registration_uuid: config.registration_uuid.clone() });
    let runtime = crate::executor::runtime().map_err(|_| ControlError("Engine runtime unavailable"))?;
    runtime.spawn(Owner {
        config, temporary, credentials, snapshot, states, run: None,
        wake: Arc::new(Notify::new()), quarantined: false, valid: true,
    }.drive(requests));
    Ok(controller)
}

struct Run {
    host: Arc<Host>,
    cancel: CancellationToken,
    registration: watch::Receiver<RegistrationState>,
    registration_done: watch::Receiver<Option<Result<(), ControlError>>>,
    registration_task: JoinHandle<Result<(), ControlError>>,
    observer: JoinHandle<()>,
}
struct Owner {
    config: CheckedHostConfig,
    temporary: cfg::Secret,
    credentials: Arc<HostCredentials>,
    snapshot: ServiceSnapshot,
    states: watch::Sender<ServiceSnapshot>,
    run: Option<Run>,
    wake: Arc<Notify>,
    quarantined: bool,
    valid: bool,
}

impl Owner {
    async fn drive(mut self, mut requests: mpsc::Receiver<Request>) {
        loop {
            tokio::select! {
                biased;
                request = requests.recv() => {
                    let Some(request) = request else { let _ = self.stop().await; break; };
                    let retiring = restrictive(&request.command);
                    // Cleanup already admitted to this owner is never abandoned.
                    if !retiring && (request.reply.is_closed() || check_deadline(request.deadline).is_err()) {
                        let _ = request.reply.send(Err(expired_command()));
                        continue;
                    }
                    let mut result = match self.apply_automatic_rotation().await {
                        Ok(()) => self.command(request.command, request.deadline).await,
                        Err(error) => Err(error),
                    };
                    if !retiring && result.is_ok() && check_deadline(request.deadline).is_err() {
                        result = Err(unconfirmed_command());
                    }
                    self.observe();
                    self.publish();
                    let _ = request.reply.send(result);
                }
                _ = self.wake.notified() => {
                    let _ = self.apply_automatic_rotation().await;
                    self.observe();
                    let terminal = self.run.as_ref().is_some_and(|run| {
                        run.registration_done.borrow().is_some() || run.host.state.finished.load(Ordering::Acquire)
                    });
                    if terminal {
                        let reason = self.snapshot.error.clone();
                        let result = self.stop().await;
                        if result.is_err() || reason.is_some() {
                            self.snapshot.phase = if self.quarantined { "quarantined" } else { "failed" }.into();
                            if self.snapshot.error.is_none() { self.snapshot.error = reason; }
                            self.snapshot.status_num = -1;
                        }
                    }
                    self.publish();
                }
            }
        }
    }

    fn publish(&mut self) {
        if *self.states.borrow() == self.snapshot { return; }
        if let Some(revision) = self.snapshot.revision.checked_add(1) {
            self.snapshot.revision = revision;
        } else {
            self.valid = false;
            self.snapshot.error = Some("Host state revision exhausted".into());
        }
        self.states.send_replace(self.snapshot.clone());
    }

    fn observe(&mut self) {
        let Some(run) = self.run.as_ref() else { return; };
        let host = run.host.snapshot();
        self.snapshot.ready = host.ready;
        self.snapshot.peers = run.host.peers().into_iter().map(|peer| peer_snapshot(self.snapshot.run_epoch, peer)).collect();
        if let Some(error) = host.error { self.snapshot.error = Some(host_error(error).to_string()); }
        let registration = *run.registration.borrow();
        self.snapshot.registration = registration_name(registration).into();
        let terminal_error = match registration {
            RegistrationState::Conflict(_) => Some("Registration identity conflict; existing identity was preserved"),
            RegistrationState::Failed(_) => Some("Host registration failed"),
            _ => None,
        };
        if let Some(error) = terminal_error { self.snapshot.error = Some(error.into()); }
        if let Some(Err(error)) = *run.registration_done.borrow() { self.snapshot.error = Some(error.to_string()); }
        if host.phase == "reclamation_unconfirmed" {
            self.quarantined = true;
            self.snapshot.phase = "quarantined".into();
        } else if !matches!(self.snapshot.phase.as_str(), "stopping" | "starting") {
            self.snapshot.phase = if host.ready { "running" } else { host.phase }.into();
        }
        self.snapshot.status_num = if matches!(registration, RegistrationState::Failed(_) | RegistrationState::Conflict(_))
            || self.quarantined || run.registration_done.borrow().is_some_and(|result| result.is_err()) {
            -1
        } else if host.ready && matches!(registration, RegistrationState::Observed { .. }) { 1 } else { 0 };
    }

    async fn start(&mut self, deadline: Instant) -> Result<(), ControlError> {
        check_deadline(deadline)?;
        if self.quarantined { return Err(ControlError("Native ownership remains quarantined; restart is refused")); }
        if !self.valid { return Err(ControlError("Host configuration requires a checked refresh")); }
        if cfg::enabled(&self.config.options, "stop-service") { return Ok(()); }
        if self.run.as_ref().is_some_and(|run| run.registration_done.borrow().is_some()
            || run.host.state.cancel.is_cancelled() || run.host.state.unreclaimed.load(Ordering::Acquire)
            || run.host.state.finished.load(Ordering::Acquire)) { self.stop().await?; }
        check_deadline(deadline)?;
        if self.run.is_some() { return Ok(()); }
        positive(deadline, false)?;
        self.snapshot.run_epoch = self.snapshot.run_epoch.checked_add(1).ok_or(ControlError("Host run generation exhausted"))?;
        self.snapshot.phase = "starting".into();
        self.snapshot.registration = "not_started".into();
        self.snapshot.ready = false;
        self.snapshot.status_num = 0;
        self.snapshot.error = None;
        self.snapshot.peers.clear();
        self.publish();
        let id = self.config.id.clone();
        let signing_key = self.config.secret_key.clone();
        let credentials = self.credentials.clone();
        let options = self.config.options.clone();
        let (routes, receiver) = mpsc::channel(16);
        // Do not detach native creation when its request expires. Its original
        // worker still returns the Host handle, which is retired below.
        let starting = tokio::task::spawn_blocking(move || {
            positive(deadline, false)?;
            let options = cfg::host_options(id, signing_key, credentials, options)?;
            positive(deadline, false)?;
            Host::start(options, Some(receiver)).map(Arc::new).map_err(host_error)
        }).await.unwrap_or_else(|_| Err(host_error(HostError::ReclamationUnconfirmed)));
        let host = match starting {
            Ok(host) => host,
            Err(error) => { self.fail(error); return Err(error); }
        };
        host.set_remote_cm_policy(cfg::enabled(&self.config.options, "allow-remote-cm-modification"));
        let ready = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Err(expired_command()),
            result = host.wait_ready() => result.map_err(host_error),
        }.and_then(|()| positive(deadline, false));
        if let Err(error) = ready {
            host.request_close();
            self.snapshot.phase = "stopping".into();
            self.publish();
            let cleanup = host.close().await;
            if cleanup == Err(HostError::ReclamationUnconfirmed) || error.0 == host_error(HostError::ReclamationUnconfirmed).0 { self.quarantined = true; }
            let error = if self.quarantined { host_error(HostError::ReclamationUnconfirmed) } else { error };
            self.fail(error);
            return Err(error);
        }
        // Registration is advertised only after the actual input/output checks,
        // codec discovery, optional bind and route receiver have become ready.
        let cancel = CancellationToken::new();
        let (states, registration) = watch::channel(RegistrationState::Registering);
        let (done, registration_done) = watch::channel(None);
        let id = self.config.id.clone();
        let uuid = self.config.registration_uuid.clone();
        let public_key = self.config.public_key;
        let rendezvous = self.config.rendezvous_server.clone();
        let relay = cfg::option(&self.config.options, "relay-server").to_owned();
        let configured_key = cfg::option(&self.config.options, "key");
        let key = if configured_key.is_empty() { hbb_common::config::RS_PUB_KEY } else { configured_key }.to_owned();
        let reg_cancel = cancel.clone();
        let wake = self.wake.clone();
        let registration_task = tokio::spawn(async move {
            // Scheduling the task is not permission to advertise it later.
            let result = match positive(deadline, false) {
                Ok(()) => registration_loop(id, uuid, public_key, rendezvous,
                    if relay.is_empty() { None } else { Some(relay) }, key, reg_cancel, states, routes).await,
                Err(error) => Err(error),
            };
            done.send_replace(Some(result));
            wake.notify_one();
            result
        });
        let mut host_changes = host.subscribe_changes();
        let mut registration_changes = registration.clone();
        let observer_cancel = cancel.clone();
        let wake = self.wake.clone();
        let observer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = observer_cancel.cancelled() => break,
                    value = host_changes.changed() => { if value.is_err() { break; } },
                    value = registration_changes.changed() => { if value.is_err() { break; } },
                }
                wake.notify_one();
            }
        });
        self.run = Some(Run { host, cancel, registration, registration_done, registration_task, observer });
        if let Err(error) = check_deadline(deadline) {
            self.stop().await?;
            return Err(error);
        }
        self.snapshot.phase = "running".into();
        self.observe();
        self.publish();
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ControlError> {
        let Some(run) = self.run.take() else {
            if self.quarantined { return Err(host_error(HostError::ReclamationUnconfirmed)); }
            self.snapshot.ready = false;
            self.snapshot.phase = "stopped".into();
            self.snapshot.registration = "stopped".into();
            self.snapshot.status_num = 0;
            return Ok(());
        };
        self.snapshot.phase = "stopping".into();
        self.snapshot.ready = false;
        self.snapshot.status_num = 0;
        self.publish();
        run.cancel.cancel();
        run.host.request_close();
        // Do not abort native peers or registration handoffs. The old run owns
        // every one until its original cleanup/close has actually completed.
        let (registration, host, observer) = tokio::join!(run.registration_task, run.host.close(), run.observer);
        self.snapshot.peers = run.host.peers().into_iter().map(|peer| peer_snapshot(self.snapshot.run_epoch, peer)).collect();
        if host == Err(HostError::ReclamationUnconfirmed) { self.quarantined = true; }
        let result = if self.quarantined { Err(host_error(HostError::ReclamationUnconfirmed)) }
            else if let Err(error) = host { Err(host_error(error)) }
            else if observer.is_err() { Err(ControlError("Host state observer failed during retirement")) }
            else { registration.unwrap_or_else(|_| Err(ControlError("Registration owner did not finish"))) };
        // Closing authorized peers requests rotation even during an explicit
        // whole-run stop. Coalesced close events still retire the old value.
        let rotation = if self.credentials.take_temporary_rotation() { self.rotate_temporary() } else { Ok(()) };
        if rotation.is_err() { self.valid = false; }
        let result = result.and(rotation);
        self.snapshot.registration = "stopped".into();
        self.snapshot.phase = if result.is_ok() { "stopped" } else if self.quarantined { "quarantined" } else { "failed" }.into();
        self.snapshot.status_num = if result.is_ok() { 0 } else { -1 };
        if let Err(error) = result { self.snapshot.error = Some(error.to_string()); }
        self.publish();
        result
    }

    // The send verdict and native retirement are separate facts. A failed
    // notification cannot skip a checked stop-service commit, but native
    // quarantine or a failed retirement always has the higher priority.
    async fn stop_service(&mut self, deadline: Option<Instant>) -> Result<Option<ControlError>, ControlError> {
        if self.run.is_some() {
            self.snapshot.phase = "stopping".into();
            self.snapshot.ready = false;
            self.snapshot.status_num = 0;
            self.publish();
        }
        let notification = match &self.run {
            Some(run) if !self.quarantined => run.host.notify_stop_service(deadline).await.err().map(host_error),
            _ => None,
        };
        self.stop().await?;
        Ok(notification)
    }

    fn report_notification(&mut self, notification: Option<ControlError>) -> Result<(), ControlError> {
        if let Some(error) = notification {
            self.fail(error);
            return Err(error);
        }
        Ok(())
    }

    fn fail(&mut self, error: ControlError) {
        if error.0 == host_error(HostError::ReclamationUnconfirmed).0 { self.quarantined = true; }
        let error = if self.quarantined { host_error(HostError::ReclamationUnconfirmed) } else { error };
        self.snapshot.phase = if self.quarantined { "quarantined" } else { "failed" }.into();
        self.snapshot.ready = false;
        self.snapshot.status_num = -1;
        self.snapshot.error = Some(error.to_string());
        self.publish();
    }

    fn current(&self, run_epoch: u64) -> Result<Arc<Host>, ControlError> {
        if run_epoch != self.snapshot.run_epoch { return Err(ControlError("Stale host run")); }
        self.run.as_ref().map(|run| run.host.clone()).ok_or(ControlError("Host run is not active"))
    }
    fn install_credentials(&mut self, revision: u64) {
        self.snapshot.policy_revision = revision;
        self.credentials = cfg::credentials(&self.config, &self.temporary, revision, Some(&self.credentials));
        if let Some(run) = &self.run {
            run.host.update_credentials(self.credentials.clone());
            run.host.set_remote_cm_policy(cfg::enabled(&self.config.options, "allow-remote-cm-modification"));
        }
    }
    fn advance_credentials(&mut self) -> Result<(), ControlError> {
        let revision = self.snapshot.policy_revision.checked_add(1).ok_or(ControlError("Credential policy generation exhausted"))?;
        self.install_credentials(revision);
        Ok(())
    }
    fn rotate_temporary(&mut self) -> Result<(), ControlError> {
        let revision = self.snapshot.policy_revision.checked_add(1).ok_or(ControlError("Credential policy generation exhausted"))?;
        let temporary = cfg::temporary(&self.config.options);
        if let Some(run) = &self.run { run.host.invalidate_authentication(); }
        self.temporary = temporary;
        self.credentials.reset_temporary_failures();
        self.install_credentials(revision);
        Ok(())
    }
    async fn apply_automatic_rotation(&mut self) -> Result<(), ControlError> {
        if !self.credentials.take_temporary_rotation() { return Ok(()); }
        if let Err(error) = self.rotate_temporary() {
            self.valid = false;
            let _ = self.stop().await;
            let error = if self.quarantined { host_error(HostError::ReclamationUnconfirmed) } else { error };
            self.fail(error);
            return Err(error);
        }
        Ok(())
    }

    // after_write is only used after a checked setter returned durable success.
    // Its cache/account reconciliation must finish even if the reply expires;
    // it is not a renewed permission to reopen host authentication or admission.
    async fn reload(&mut self, check_activity: bool, deadline: Instant, after_write: bool) -> Result<(), ControlError> {
        if !after_write { check_deadline(deadline)?; }
        if let Some(run) = &self.run { run.host.invalidate_authentication(); }
        let prepared = tokio::task::spawn_blocking(move || {
            if !after_write {
                if check_activity { positive(deadline, false)?; } else { check_deadline(deadline)?; }
            }
            Config::checked_host_prepare().map_err(|_| ControlError("Checked host configuration reload failed"))
        }).await.map_err(|_| ControlError("Checked configuration worker did not complete"))??;
        if !after_write { check_deadline(deadline)?; }
        let candidate = &prepared.config;
        if candidate.id != self.config.id || candidate.public_key != self.config.public_key
            || candidate.registration_uuid != self.config.registration_uuid {
            return Err(ControlError("Host identity changed externally; automatic identity replacement is refused"));
        }
        cfg::validate(&candidate.options)?;
        let server_change = candidate.rendezvous_server != self.config.rendezvous_server
            || cfg::server_changed(&self.config.options, &candidate.options);
        let restart = server_change || cfg::run_changed(&self.config.options, &candidate.options);
        let rotate = ["temporary-password-length", "allow-numeric-one-time-password"].iter()
            .any(|key| cfg::option(&candidate.options, key) != cfg::option(&self.config.options, key));
        let was_running = self.run.is_some();
        let notification = if check_deadline(deadline).is_err() {
            self.stop().await?;
            None
        } else if cfg::enabled(&candidate.options, "stop-service") {
            self.stop_service(Some(deadline)).await?
        } else if restart {
            self.stop().await?;
            None
        } else {
            None
        };
        if !after_write { check_deadline(deadline)?; }
        // No new global/account scope can be published while an old incoming
        // run exists. Validate counters before the irreversible publication.
        let scope_epoch = if server_change { Some(self.snapshot.run_epoch.checked_add(1).ok_or(ControlError("Host run generation exhausted"))?) } else { None };
        self.snapshot.policy_revision.checked_add(1).ok_or(ControlError("Credential policy generation exhausted"))?;
        let config = tokio::task::spawn_blocking(move || {
            if !after_write {
                if check_activity || server_change { positive(deadline, false)?; } else { check_deadline(deadline)?; }
            }
            if server_change {
                let mut committed = None;
                crate::official_account::change_server_configuration(|| {
                    let guard = if after_write { Ok(()) } else { positive(deadline, false) };
                    committed = Some(guard.and_then(|()| {
                        Config::checked_host_commit(prepared)
                            .map_err(|_| ControlError("Checked host configuration publication could not be confirmed"))
                    }));
                }).map_err(|_| ControlError("Account/server configuration transaction failed"))?;
                committed.ok_or(ControlError("Server configuration transaction did not publish"))?
            } else {
                Config::checked_host_commit(prepared).map_err(|_| ControlError("Checked host configuration publication could not be confirmed"))
            }
        }).await.map_err(|_| ControlError("Configuration publication worker did not complete"))??;
        if let Some(epoch) = scope_epoch {
            self.snapshot.run_epoch = epoch;
            self.snapshot.peers.clear();
        }
        self.config = config;
        cfg::apply_metadata(&mut self.snapshot, &self.config);
        // Preserve the checked published truth. The caller retires any remaining
        // run on refusal; no expired write is reported as rolled back or rearmed.
        if check_deadline(deadline).is_err() {
            return Err(ControlError("Checked configuration is published; command expired before reactivation"));
        }
        if (check_activity || server_change) && sensitive(false).is_err() {
            return Err(ControlError("Checked configuration is published; remote activity prevents reactivation"));
        }
        check_deadline(deadline)?;
        if rotate { self.rotate_temporary()?; } else { self.advance_credentials()?; }
        self.valid = true;
        if restart && was_running && !cfg::enabled(&self.config.options, "stop-service") { self.start(deadline).await?; }
        self.report_notification(notification)
    }

    async fn set_options(&mut self, mut options: HashMap<String, String>, preserve_redacted: bool, deadline: Instant) -> Result<(), ControlError> {
        check_deadline(deadline)?;
        // Redacted values absent from a UI's full snapshot are not deletions.
        for (key, value) in &self.config.options {
            if preserve_redacted && cfg::is_secret_option(key, value) && !options.contains_key(key) { options.insert(key.clone(), value.clone()); }
        }
        for key in ["id", "uuid", "salt", "password", "permanent-password", "key-pair"] {
            if options.contains_key(key) { return Err(ControlError("Identity or credentials require their dedicated checked owner API")); }
        }
        if options.get("allow-remote-cm-modification").is_some_and(|value| value != cfg::option(&self.config.options, "allow-remote-cm-modification")) {
            return Err(ControlError("Local remote CM policy requires its dedicated local option setter"));
        }
        cfg::validate(&options)?;
        let only_stop = cfg::enabled(&options, "stop-service") && options.iter().all(|(key, value)| key == "stop-service" || self.config.options.get(key) == Some(value))
            && self.config.options.keys().all(|key| key == "stop-service" || options.contains_key(key));
        if !only_stop { positive(deadline, false)?; }
        let restart = cfg::run_changed(&self.config.options, &options);
        let was_running = self.run.is_some();
        let enabling_service = cfg::enabled(&self.config.options, "stop-service") && !cfg::enabled(&options, "stop-service");
        let notification = if restart || cfg::enabled(&options, "stop-service") {
            if cfg::enabled(&options, "stop-service") && check_deadline(deadline).is_ok() {
                self.stop_service(Some(deadline)).await?
            } else {
                self.stop().await?;
                None
            }
        } else {
            None
        };
        check_deadline(deadline)?;
        // Invalidate old pending challenges before a possibly durable mutation.
        if let Some(run) = &self.run { run.host.invalidate_authentication(); }
        let result = tokio::task::spawn_blocking(move || {
            if !only_stop { positive(deadline, false)?; } else { check_deadline(deadline)?; }
            Config::checked_set_options(options, || check_deadline(deadline).map_err(Into::into))
                .map_err(|_| ControlError("Host option commit could not be confirmed; refresh is required"))
        }).await.unwrap_or_else(|_| Err(ControlError("Host configuration worker did not complete")));
        if let Err(error) = result { self.valid = false; let _ = self.stop().await; self.fail(error); return Err(error); }
        if let Err(error) = self.reload(!only_stop, deadline, true).await { self.valid = false; let _ = self.stop().await; self.fail(error); return Err(error); }
        if !cfg::enabled(&self.config.options, "stop-service") && (enabling_service || was_running && self.run.is_none()) { self.start(deadline).await?; }
        self.report_notification(notification)
    }

    async fn command(&mut self, mut command: HostCommand, deadline: Instant) -> Result<HostReply, ControlError> {
        if !restrictive(&command) { check_deadline(deadline)?; }
        match &mut command {
            HostCommand::Start => self.start(deadline).await?,
            HostCommand::Stop => {
                let notification = self.stop_service(None).await?;
                self.report_notification(notification)?;
            }
            HostCommand::ReadActivity => {
                let value = crate::windows_input::remote_activity_snapshot();
                return Ok(HostReply::Activity(ActivitySnapshot { sequence: value.sequence,
                    click_wall_ms: value.click_wall_ms, mouse_wall_ms: value.mouse_wall_ms, uncertain: value.uncertain }));
            }
            HostCommand::GetTemporaryPassword => return Ok(HostReply::TemporaryPassword(self.temporary.0.clone())),
            HostCommand::RotateTemporaryPassword => {
                positive(deadline, false)?;
                self.rotate_temporary()?;
            }
            HostCommand::SetPermanentPassword { password } => {
                let password = cfg::Secret(std::mem::take(password));
                positive(deadline, false)?;
                if let Some(run) = &self.run { run.host.invalidate_authentication(); }
                let result = tokio::task::spawn_blocking(move || {
                    positive(deadline, false)?;
                    Config::checked_set_permanent_password(&password.0, || check_deadline(deadline).map_err(Into::into))
                        .map_err(|_| ControlError("Permanent password commit could not be confirmed; refresh is required"))
                }).await.unwrap_or_else(|_| Err(ControlError("Credential worker did not complete")));
                if let Err(error) = result { self.valid = false; let _ = self.stop().await; self.fail(error); return Err(error); }
                if let Err(error) = self.reload(true, deadline, true).await { self.valid = false; let _ = self.stop().await; self.fail(error); return Err(error); }
            }
            HostCommand::SetOption { key, value } if key == "allow-remote-cm-modification" => {
                positive(deadline, false)?;
                let value = std::mem::take(value);
                let result = tokio::task::spawn_blocking(move || {
                    positive(deadline, false)?;
                    Config::checked_set_remote_cm_policy(value, || check_deadline(deadline).map_err(Into::into))
                        .map_err(|_| ControlError("Local remote CM policy commit could not be confirmed; refresh is required"))
                }).await.unwrap_or_else(|_| Err(ControlError("Local configuration worker did not complete")));
                if let Err(error) = result { self.valid = false; let _ = self.stop().await; self.fail(error); return Err(error); }
                if let Err(error) = self.reload(true, deadline, true).await { self.valid = false; let _ = self.stop().await; self.fail(error); return Err(error); }
            }
            HostCommand::SetOption { key, value } => {
                let mut options = self.config.options.clone();
                if value.is_empty() { options.remove(key); } else { options.insert(key.clone(), std::mem::take(value)); }
                self.set_options(options, false, deadline).await?;
            }
            HostCommand::SetOptions { options } => self.set_options(std::mem::take(options), true, deadline).await?,
            HostCommand::RefreshConfiguration => {
                positive(deadline, false)?;
                if let Err(error) = self.reload(true, deadline, false).await { self.valid = false; let _ = self.stop().await; self.fail(error); return Err(error); }
            }
            HostCommand::Approve { run_epoch, conn_id, approval_epoch, policy_revision, allow } => {
                let host = self.current(*run_epoch)?;
                if *allow { positive(deadline, cfg::enabled(&self.config.options, "allow-remote-cm-modification"))?; }
                host.approve_peer(*conn_id, *approval_epoch, *policy_revision, *allow).map_err(host_error)?;
                if *allow && check_deadline(deadline).is_err() { return Err(expire_peer(&host, *conn_id).await); }
            }
            HostCommand::Disconnect { run_epoch, conn_id } => self.current(*run_epoch)?.disconnect(*conn_id).await.map_err(host_error)?,
            HostCommand::SetKeyboard { run_epoch, conn_id, enabled } => {
                let host = self.current(*run_epoch)?;
                if *enabled {
                    positive(deadline, cfg::enabled(&self.config.options, "allow-remote-cm-modification"))?;
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                            return Err(expire_peer(&host, *conn_id).await);
                        }
                        result = host.set_keyboard(*conn_id, true, deadline) => result.map_err(host_error)?,
                    }
                    if check_deadline(deadline).is_err() { return Err(expire_peer(&host, *conn_id).await); }
                } else {
                    host.set_keyboard(*conn_id, false, deadline).await.map_err(host_error)?;
                }
            }
            HostCommand::RemoveDisconnected { run_epoch, conn_id } => {
                if *run_epoch != self.snapshot.run_epoch { return Err(ControlError("Stale host run")); }
                if let Some(run) = &self.run { run.host.remove_disconnected(*conn_id).map_err(host_error)?; }
                else {
                    let peer = self.snapshot.peers.iter().find(|peer| peer.conn_id == *conn_id).ok_or(ControlError("Unknown host connection"))?;
                    if !peer.disconnected || peer.phase == "quarantined" { return Err(ControlError("Connection cleanup is not confirmed")); }
                    self.snapshot.peers.retain(|peer| peer.conn_id != *conn_id);
                }
            }
        }
        Ok(HostReply::Acknowledged)
    }
}

fn restrictive(command: &HostCommand) -> bool {
    matches!(command, HostCommand::Stop | HostCommand::Disconnect { .. } | HostCommand::SetKeyboard { enabled: false, .. } | HostCommand::Approve { allow: false, .. })
}
fn expired_command() -> ControlError {
    ControlError("Host command expired before this stage")
}
fn unconfirmed_command() -> ControlError {
    ControlError("Host command reply deadline expired; completed effects were not rolled back")
}
fn check_deadline(deadline: Instant) -> Result<(), ControlError> {
    if Instant::now() >= deadline { Err(expired_command()) } else { Ok(()) }
}
fn positive(deadline: Instant, allow_remote_cm: bool) -> Result<(), ControlError> {
    check_deadline(deadline)?;
    sensitive(allow_remote_cm)?;
    check_deadline(deadline)
}
async fn expire_peer(host: &Host, conn_id: i32) -> ControlError {
    // The input reader and publisher retain ownership until actual close.
    match host.cancel_peer(conn_id).await { Ok(()) => unconfirmed_command(), Err(error) => host_error(error) }
}
fn sensitive(allow_remote_cm: bool) -> Result<(), ControlError> {
    let activity = crate::windows_input::remote_activity_snapshot();
    if activity.uncertain || (!allow_remote_cm && !crate::windows_input::remote_input_allows_sensitive_action()) {
        return Err(ControlError("Recent or uncertain remote input blocks this sensitive local action"));
    }
    Ok(())
}
fn peer_snapshot(run_epoch: u64, peer: HostPeerSnapshot) -> PeerSnapshot {
    PeerSnapshot { conn_id: peer.conn_id, connection_token: peer.connection_token, run_epoch,
        approval_epoch: peer.approval_epoch, policy_revision: peer.policy_revision, peer_id: peer.peer_id,
        name: peer.name, authorized: peer.authorized, disconnected: peer.disconnected,
        phase: peer.phase.into(), keyboard: peer.keyboard, error: peer.error.map(|error| host_error(error).to_string()) }
}
fn host_error(error: HostError) -> ControlError {
    ControlError(match error {
        HostError::InvalidOptions => "Invalid host options or connection handle",
        HostError::NoRuntime => "Engine runtime unavailable",
        HostError::NoHardwareCodec => "Selected desktop has no supported hardware encoder",
        HostError::ListenFailed => "Direct host listener could not bind",
        HostError::TransportFailed => "Host connection transport failed",
        HostError::AuthenticationFailed => "Host authentication failed or expired",
        HostError::ApprovalDenied => "Approval is denied, stale or already consumed",
        HostError::NoCommonCodec => "Controller and host have no common codec",
        HostError::InvalidFrameRate => "Controller requested an invalid frame rate",
        HostError::CaptureFailed => "Selected desktop capture failed",
        HostError::InvalidAccessUnit => "Host encoder produced an invalid access unit",
        HostError::UnsupportedDisplay => "Selected display is unsupported or changed",
        HostError::InputUnavailable => "Requested input permission is unavailable",
        HostError::InputFailed => "Remote input failed",
        HostError::ReclamationUnconfirmed => "Native reclamation is unconfirmed; host is quarantined",
    })
}
fn registration_name(state: RegistrationState) -> &'static str {
    match state {
        RegistrationState::Registering => "registering", RegistrationState::AddressObserved => "address_observed",
        RegistrationState::Observed { .. } => "observed", RegistrationState::Stale => "stale",
        RegistrationState::Refused(_) => "refused", RegistrationState::Conflict(_) => "conflict",
        RegistrationState::Failed(_) => "failed", RegistrationState::Stopped(StopReason::Deadline) => "renewing",
        RegistrationState::Stopped(_) => "stopped",
    }
}

async fn registration_loop(id: String, mut uuid: Vec<u8>, public_key: sign::PublicKey,
    rendezvous: String, relay: Option<String>, key: String, cancel: CancellationToken,
    states: watch::Sender<RegistrationState>, routes: mpsc::Sender<registration::IncomingHostRoute>) -> Result<(), ControlError> {
    struct Uuid(Vec<u8>);
    impl Drop for Uuid { fn drop(&mut self) { sodiumoxide::utils::memzero(&mut self.0); } }
    let uuid = Uuid(std::mem::take(&mut uuid));
    loop {
        if cancel.is_cancelled() { return Ok(()); }
        let config = RegistrationConfig { id: id.clone(), registration_uuid: uuid.0.clone(), public_key,
            rendezvous_server: rendezvous.clone(), relay_server: relay.clone(), licence_key: key.clone(),
            deadline: Duration::from_secs(24 * 60 * 60) };
        registration::run_host_registration(config, cancel.clone(), states.clone(), routes.clone()).await
            .map_err(|_| ControlError("Host registration configuration or transport failed"))?;
        if cancel.is_cancelled() { return Ok(()); }
        let terminal = *states.borrow();
        match terminal {
            // The worker has already cleaned up all acquisition tasks. The
            // same immutable identity/configuration and run cancellation fence
            // survive this bounded renewal; no detached old epoch can publish.
            RegistrationState::Stopped(StopReason::Deadline) => { states.send_replace(RegistrationState::Registering); }
            RegistrationState::Stopped(StopReason::Cancelled) => return Ok(()),
            RegistrationState::Conflict(_) => return Err(ControlError("Registration identity conflict; identity unchanged")),
            _ => return Err(ControlError("Host registration ended before retirement")),
        }
    }
}
