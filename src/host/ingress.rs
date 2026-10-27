//! Admission and authentication hand off the complete transport to the existing
//! peer owner. No socket extraction, alternate receiver or media task lives here.
use super::*;

// Pinned server/connection.rs SEND_TIMEOUT_VIDEO: the ordinary remote desktop
// path uses 12 seconds, including pre-login replies. transport::split carries
// this field into its sole WireWriter; no new timeout/cancellation owner is needed.
const HOST_SEND_TIMEOUT_MS: u64 = 12_000;

pub(super) async fn serve(
    state: Arc<State>, options: Arc<HostOptions>, display: DisplayBinding,
    mut routes: Option<mpsc::Receiver<IncomingHostRoute>>,
) -> Result<(), HostError> {
    let probe_options = options.clone();
    let probe_display = display.clone();
    // Native discovery is always joined, never cancelled halfway through an owner.
    let codecs = tokio::task::spawn_blocking(move || encoders(&probe_options, &probe_display))
        .await.map_err(|_| HostError::ReclamationUnconfirmed)??;
    if state.cancel.is_cancelled() { return Ok(()); }
    let listener = match options.listen {
        Some(address) => Some(TcpListener::bind(address).await.map_err(|_| HostError::ListenFailed)?),
        None => None,
    };
    let admission = Arc::new(Semaphore::new(MAX_PREAUTH));
    let mut peers: JoinSet<Result<(), HostError>> = JoinSet::new();
    let mut failure = None;
    let mut unconfirmed = false;
    state.progress(|s| { s.phase = "listening"; s.ready = true; });
    loop {
        let incoming = tokio::select! {
            biased;
            _ = state.cancel.cancelled() => break,
            joined = peers.join_next_with_id(), if !peers.is_empty() => {
                if let Some(joined) = joined {
                    if let Err(error) = retire_peer(&state, joined) {
                        state.progress(|s| s.error = Some(error));
                        if error == HostError::ReclamationUnconfirmed {
                            unconfirmed = true;
                            state.cancel.cancel();
                        }
                    }
                }
                continue;
            }
            route = async {
                match routes.as_mut() { Some(routes) => routes.recv().await, None => std::future::pending().await }
            } => {
                match route {
                    Some(route) => Ingress::routed(route),
                    None => { routes = None; if listener.is_none() { break; } continue; }
                }
            }
            accepted = async {
                match listener.as_ref() { Some(listener) => listener.accept().await, None => std::future::pending().await }
            } => {
                match accepted {
                    Ok((socket, peer)) => match Ingress::direct(socket, peer) {
                        Ok(value) => value, Err(_) => continue,
                    },
                    Err(_) => { failure = Some(HostError::TransportFailed); break; }
                }
            }
        };
        if state.cancel.is_cancelled() { break; }
        if !state.auth_admission.load(Ordering::Acquire) { continue; }
        let Ok(permit) = admission.clone().try_acquire_owned() else { continue; };
        {
            let mut records = lock(&state.controls);
            if records.len() >= MAX_PEER_RECORDS {
                // Keep a bounded oldest-first CM history without letting failed
                // preauth sockets permanently exhaust future host admission.
                let retired = records.iter().find_map(|(id, peer)| {
                    let snapshot = lock(&peer.snapshot);
                    (snapshot.disconnected && snapshot.error != Some(HostError::ReclamationUnconfirmed)).then_some(*id)
                });
                if let Some(id) = retired { records.remove(&id); } else { continue; }
            }
        }
        let token = match NEXT_CONNECTION.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| (n < i32::MAX as u64).then_some(n + 1)) {
            Ok(previous) => previous + 1,
            Err(_) => { failure = Some(HostError::InvalidOptions); break; }
        };
        let (commands, receiver) = mpsc::channel(8);
        let control = Arc::new(PeerControl {
            snapshot: Mutex::new(HostPeerSnapshot {
                conn_id: token as i32, connection_token: token, approval_epoch: None,
                policy_revision: lock(&state.credentials).revision,
                peer_id: String::new(), name: String::new(), authorized: false,
                disconnected: false, phase: "authenticating", keyboard: false, error: None,
            }),
            cancel: state.cancel.child_token(), commands, finished: watch::channel(None).0,
        });
        lock(&state.controls).insert(token as i32, control.clone());
        let record = Arc::new(PeerRecord { control: Some(control), ..Default::default() });
        let handle = peers.spawn(peer(state.clone(), options.clone(), codecs, incoming,
            display.clone(), record.clone(), receiver, permit));
        state.track_peer(handle.id(), record);
        state.changed();
    }
    // Closing actual admission also drops queued streams from the retiring run.
    drop(listener);
    drop(routes);
    state.request_close();
    while let Some(joined) = peers.join_next_with_id().await {
        if retire_peer(&state, joined) == Err(HostError::ReclamationUnconfirmed) { unconfirmed = true; }
    }
    lock(&state.peers).clear();
    state.publish_peers();
    if unconfirmed {
        state.unreclaimed.store(true, Ordering::Release);
        return Err(HostError::ReclamationUnconfirmed);
    }
    failure.map_or(Ok(()), Err)
}

pub(super) struct Ingress {
    stream: FramedStream,
    origin: String,
    direct_targets: Vec<String>,
    permissions: Option<u64>,
    secure: bool,
    unsupported: bool,
}
impl Ingress {
    fn routed(route: IncomingHostRoute) -> Self {
        Self {
            stream: route.stream, origin: route.peer.to_string(), direct_targets: Vec::new(),
            permissions: route.permissions, secure: route.requirements.secure,
            unsupported: route.requirements.token_present || route.requirements.switch_code_present
                || route.requirements.conn_audit_ref.is_some(),
        }
    }
    fn direct(socket: TcpStream, peer: SocketAddr) -> Result<Self, HostError> {
        socket.set_nodelay(true).map_err(|_| HostError::TransportFailed)?;
        let local = socket.local_addr().map_err(|_| HostError::TransportFailed)?;
        Ok(Self {
            stream: FramedStream::from(socket, local), origin: peer.to_string(),
            direct_targets: vec![local.ip().to_string(), local.to_string()],
            permissions: None, secure: false, unsupported: false,
        })
    }
}

// Pinned common::get_control_permission uses TWO bits per permission. 00/11 are
// unset, 01 disables, 10 never grants beyond local policy. Registration's explicit
// Some(0) is deliberately stricter than upstream's unspecified-zero behavior.
fn route_permissions(local: Permissions, mask: Option<u64>) -> Permissions {
    let allows = |position: u32| match mask {
        None => true,
        Some(0) => false,
        Some(mask) => ((mask >> (position * 2)) & 3) != 1,
    };
    local.intersect(Permissions {
        keyboard: allows(0), clipboard: allows(2), audio: allows(4), file: allows(3),
    })
}

fn retire_peer(state: &State, joined: Result<(Id, Result<(), HostError>), tokio::task::JoinError>) -> Result<(), HostError> {
    let id = match &joined { Ok((id, _)) => *id, Err(error) => error.id() };
    let record = lock(&state.peers).remove(&id);
    let native = record.as_ref().is_some_and(|record| record.native.load(Ordering::Acquire));
    let result = match joined {
        Err(_) if native => Err(HostError::ReclamationUnconfirmed),
        Err(_) => Err(HostError::TransportFailed),
        Ok((_, result)) => result,
    };
    if result == Err(HostError::ReclamationUnconfirmed) { state.unreclaimed.store(true, Ordering::Release); }
    if let Some(control) = record.and_then(|record| record.control.clone()) {
        let mut snapshot = lock(&control.snapshot);
        snapshot.disconnected = true;
        snapshot.keyboard = false;
        snapshot.approval_epoch = None;
        snapshot.phase = if result == Err(HostError::ReclamationUnconfirmed) { "quarantined" } else { "disconnected" };
        snapshot.error = result.err();
        let was_authorized = snapshot.authorized;
        drop(snapshot);
        if was_authorized { state.request_temporary_rotation(); }
        control.finished.send_replace(Some(result));
    }
    state.publish_peers();
    result
}

pub(super) async fn authenticate(
    state: Arc<State>, options: &HostOptions, codecs: Encoders, mut incoming: Ingress,
    record: Arc<PeerRecord>, control: &PeerControl,
) -> Result<AuthenticatedParts, HostError> {
    if !state.auth_admission.load(Ordering::Acquire) { return Err(HostError::AuthenticationFailed); }
    // Set this on the COMPLETE direct/routed stream before handshake or Hash.
    // Its framing buffers, cipher/nonce state and relay lease remain untouched.
    incoming.stream.set_send_timeout(HOST_SEND_TIMEOUT_MS);
    let epoch = NEXT_REQUEST.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .map_err(|_| HostError::AuthenticationFailed)? + 1;
    let _approval = ApprovalGuard { state: state.clone(), epoch, record };
    let credentials = lock(&state.credentials).clone();
    lock(&control.snapshot).policy_revision = credentials.revision;
    // One deadline covers handshake, Hash send, approval wait and login replies.
    tokio::time::timeout(Duration::from_secs(90), authenticate_epoch(state, options, codecs,
        incoming, epoch, credentials, control)).await.map_err(|_| HostError::AuthenticationFailed)?
}

async fn authenticate_epoch(
    state: Arc<State>, options: &HostOptions, codecs: Encoders, incoming: Ingress,
    epoch: u64, credentials: Arc<HostCredentials>, control: &PeerControl,
) -> Result<AuthenticatedParts, HostError> {
    if incoming.unsupported { return Err(HostError::AuthenticationFailed); }
    let require_encryption = incoming.secure || incoming.direct_targets.is_empty() || !options.allow_legacy_plain;
    let grant = route_permissions(local_permissions(options), incoming.permissions);
    let mut targets = incoming.direct_targets;
    targets.push(options.id.clone());
    let config = HostAuthConfig {
        accepted_targets: targets, salt: credentials.salt.clone(), passwords: credentials.passwords.shared(),
        policy: credentials.policy, ceiling: grant, password_permissions: grant,
        peer_info: peer_info(options, codecs),
        approval: Box::new(LocalApproval { state: state.clone(), epoch, grant }),
        second_factor: Box::new(NoSecondFactor), attempts: Box::new(SharedAttempts { state: state.clone(), revision: credentials.revision }),
    };
    // Official raw direct viewers wait for Hash, not SignedId. This sequence is
    // an explicit local compatibility opt-in, never a routed/signed downgrade.
    let identity = if !require_encryption { HostIdentity::LegacyPlain }
        else { HostIdentity::Signed { id: options.id.clone(), secret_key: options.signing_key.clone() } };
    let established = handshake::host(incoming.stream, identity, Duration::from_secs(90)).await
        .map_err(|_| HostError::AuthenticationFailed)?;
    // from_established sends Hash. Verify the ACTUAL result before that send.
    if require_encryption && !matches!(established.security(), Security::Encrypted { .. }) {
        return Err(HostError::AuthenticationFailed);
    }
    let mut session = HostSession::from_established(established, config, Duration::from_secs(90), Duration::from_secs(30))
        .await.map_err(|_| HostError::AuthenticationFailed)?;
    let mut request: Option<Arc<PendingApproval>> = None;
    for _ in 0..64 {
        let event = match request.as_ref() {
            Some(entry) => session.recv_with_approval(&entry.notify).await,
            None => session.recv().await,
        }.map_err(|_| HostError::AuthenticationFailed)?;
        if let Some(claims) = session.login_request() {
            let mut snapshot = lock(&control.snapshot);
            snapshot.peer_id = sanitize_claim(&claims.my_id);
            snapshot.name = sanitize_claim(&claims.my_name);
        }
        if lock(&state.credentials).revision != credentials.revision || control.cancel.is_cancelled()
            || !state.auth_admission.load(Ordering::Acquire) {
            return Err(HostError::AuthenticationFailed);
        }
        match event {
            HostEvent::AwaitApproval | HostEvent::LoginRejected(_) if session.state() == crate::authentication::HostAuthState::AwaitApproval => {
                request = Some(state.request_approval(epoch, &incoming.origin));
                let mut snapshot = lock(&control.snapshot);
                snapshot.approval_epoch = Some(epoch);
                snapshot.phase = "awaiting_approval";
                drop(snapshot);
                state.changed();
            }
            HostEvent::Authorized(_) => {
                // The final authorize and credential publication share the same
                // lock; no await separates checking and committing this grant.
                let current = lock(&state.credentials);
                if current.revision != credentials.revision || control.cancel.is_cancelled()
                    || !state.auth_admission.load(Ordering::Acquire) {
                    return Err(HostError::AuthenticationFailed);
                }
                let parts = session.into_authenticated_parts().map_err(|_| HostError::AuthenticationFailed)?;
                let mut snapshot = lock(&control.snapshot);
                snapshot.authorized = true;
                snapshot.keyboard = parts.context.permissions.keyboard;
                snapshot.phase = "authorized";
                drop(snapshot);
                drop(current);
                authentication_succeeded();
                state.changed();
                return Ok(parts);
            }
            HostEvent::Closed => return Err(HostError::ApprovalDenied),
            HostEvent::LoginRejected(_) if session.state() == crate::authentication::HostAuthState::Closed => {
                return Err(HostError::ApprovalDenied);
            }
            _ => {}
        }
    }
    Err(HostError::AuthenticationFailed)
}

fn sanitize_claim(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).take(256).collect()
}
