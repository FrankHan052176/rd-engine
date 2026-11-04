//! RustDesk authentication on the original session and its absolute deadline.
use super::{
    AuthAnswers, CLIENT_VERSION, Connector, LoginFailure, Password, PasswordGate, SecondFactorGate,
    State, ViewerError, ViewerOptions, ViewerTarget, discard_password, lock,
};
use crate::{
    conn_token::ConnToken,
    rendezvous::RouteKind,
    session::{
        AuthenticatedParts, LoginCredential, SessionMode, ViewerEvent, ViewerSession, ViewerState,
    },
};
use base::message_proto::{self as proto, LoginRequest, OptionMessage};
use std::time::Duration;
use tokio::sync::mpsc;

/// This engine's own platform, in the terms a peer receives it.
///
/// The official client sends `whoami::platform()`, and so does this one, with the
/// one exception the compiler can name: on HarmonyOS `target_os` is `linux` and
/// the pinned `whoami` has no HarmonyOS arm, so it would answer "Linux" for a
/// device that is not one. Everywhere else the answer comes from the platform
/// itself rather than from a literal.
fn my_platform() -> String {
    #[cfg(target_env = "ohos")]
    {
        "HarmonyOS".to_owned()
    }
    #[cfg(not(target_env = "ohos"))]
    {
        hbb_common::whoami::platform().to_string()
    }
}

fn login_request(options: &ViewerOptions, supported: proto::SupportedDecoding) -> LoginRequest {
    // Key handshake has initialized sodium before Challenge. Never reuse a
    // process-local counter as an original-peer reconnect session identifier.
    let mut session_bytes = [0u8; 8];
    hbb_common::sodiumoxide::randombytes::randombytes_into(&mut session_bytes);
    let mut request = LoginRequest {
        username: options.username.clone(),
        my_id: options.local_id.clone(),
        my_name: options.local_name.clone(),
        my_platform: my_platform(),
        version: CLIENT_VERSION.into(),
        session_id: u64::from_le_bytes(session_bytes).max(1),
        video_ack_required: false,
        option: (if options.mode == SessionMode::Desktop {
            Some(OptionMessage {
                custom_fps: options.requested_fps as i32,
                ..options.session_options.login_options(&supported)
            })
        } else {
            None
        })
        .into(),
        ..Default::default()
    };
    if options.mode == SessionMode::FileTransfer {
        request.set_file_transfer(proto::FileTransfer::default());
    }
    request
}

pub(super) async fn authenticate(
    state: &State,
    mut options: ViewerOptions,
    supported: proto::SupportedDecoding,
    connector: Connector,
) -> Result<AuthenticatedParts, ViewerError> {
    let mut password = Password(std::mem::take(&mut options.password).into_bytes());
    let conn_token = options.conn_token.take();
    let session = match connector {
        Connector::Direct(identity) => {
            state.phase("connecting");
            let ViewerTarget::RustDesk {
                address: Some(address),
            } = options.target
            else {
                return Err(ViewerError::InvalidOptions);
            };
            let session = ViewerSession::connect_direct(address, identity, Duration::from_secs(30))
                .await
                .map_err(|_| ViewerError::ConnectFailed)?;
            state.route("direct_tcp");
            session
        }
        Connector::Rendezvous(config) => {
            state.phase("rendezvous");
            let timeout = config.connect_timeout;
            let (established, evidence) =
                crate::rendezvous::connect_viewer_for(config, options.mode)
                    .await
                    .map_err(|_| ViewerError::RendezvousFailed)?;
            if !evidence.encrypted || !evidence.peer_verified {
                return Err(ViewerError::RendezvousFailed);
            }
            state.route(match evidence.route {
                RouteKind::TcpHolePunch => "tcp_hole_punch",
                RouteKind::Relay => "relay",
            });
            ViewerSession::from_established(established, timeout, Duration::from_secs(30))
        }
    };
    state.phase("authenticating");
    // The two channels a local answer travels on, each bounded to one
    // outstanding answer, and each whose sender is what makes the channel
    // outlive every wait it arms. The copies published in `state.second_factor`
    // and `state.password` exist only while the session is really waiting for
    // that secret, so nothing offered outside the step is kept for a later
    // attempt. The receivers clear anything still in them when this exchange
    // ends, including on cancellation.
    let (codes, answers) = mpsc::channel::<String>(1);
    let (passwords, password_answers) = mpsc::channel::<String>(1);
    let mut answers = AuthAnswers {
        codes: answers,
        passwords: password_answers,
    };
    let result = authenticate_loop(
        state,
        session,
        &options,
        &mut password,
        conn_token,
        supported,
        &codes,
        &passwords,
        &mut answers,
    )
    .await;
    // Whatever ended this authentication — acceptance, refusal or a broken wire
    // — the entry points end with it: a code or a password offered afterwards is
    // not this session's answer. A cancelling viewer never reaches this line,
    // but it is already closing, which the two entry points refuse before they
    // look at their gate at all.
    *lock(&state.second_factor) = SecondFactorGate::default();
    *lock(&state.password) = PasswordGate::default();
    result
}

/// What one authentication step is waiting on: the peer's own record, or an
/// answer this viewer's consumer submitted.
enum AuthStep {
    Code(String),
    Password(String),
    Event(Result<ViewerEvent, ViewerError>),
}

/// Arms the password step on this same session and publishes the demand.
///
/// `failure` names why the consumer is asked: the peer wants a password this
/// attempt did not send (`EmptyPassword`, also the state of a login that went
/// out with none and waits on the peer's operator) or refused the one it sent
/// (`WrongPassword`). Either way the login the session already holds is what an
/// answer resends, and any answer still queued for an earlier demand is
/// dropped with that demand.
fn demand_password(
    state: &State,
    answers: &mut AuthAnswers,
    passwords: &mpsc::Sender<String>,
    failure: LoginFailure,
) -> Result<(), ViewerError> {
    *lock(&state.password) = PasswordGate::default();
    *lock(&state.second_factor) = SecondFactorGate::default();
    answers.clear();
    let mut gate = lock(&state.password);
    let mut inner = lock(&state.inner);
    inner.snapshot.password_challenge = inner
        .snapshot
        .password_challenge
        .checked_add(1)
        .ok_or(ViewerError::AuthenticationFailed)?;
    inner.snapshot.phase = match failure {
        LoginFailure::EmptyPassword => "awaiting_password",
        _ => "password_rejected",
    }
    .into();
    inner.snapshot.password_failure = Some(failure);
    gate.password = Some(passwords.clone());
    gate.submitted = false;
    Ok(())
}

/// The authentication exchange, the peer's password and second-factor steps
/// included.
///
/// The wire read is the same `ViewerSession::recv` the rest of authentication
/// uses, so it inherits the original absolute deadline. `recv_for_auth` does
/// only framed reads and synchronous dispatch; probe replies, codes and
/// passwords are written serially outside the select. Cancelling an in-progress
/// write still destroys that wire, never restores or retries a partial record.
pub(super) async fn authenticate_loop(
    state: &State,
    mut session: ViewerSession,
    options: &ViewerOptions,
    password: &mut Password,
    mut conn_token: Option<ConnToken>,
    supported: proto::SupportedDecoding,
    codes: &mpsc::Sender<String>,
    passwords: &mpsc::Sender<String>,
    answers: &mut AuthAnswers,
) -> Result<AuthenticatedParts, ViewerError> {
    loop {
        // A secret is multiplexed beside the wire only while the session really
        // waits for it: a code in the peer's second-factor step, a password while
        // a demand this loop armed is still unanswered. The wire is polled
        // first, so a record the peer already sent — including its answer to what
        // this loop wrote — is dispatched before a submission it is holding.
        let awaiting_code = session.state() == ViewerState::Await2Fa;
        let awaiting_password = {
            let gate = lock(&state.password);
            // `submitted` prevents another admission, not consumption of the
            // already queued answer after a probe won the biased read.
            gate.password.is_some()
        };
        let step = if awaiting_code || awaiting_password {
            tokio::select! {
                biased;
                event = session.recv_for_auth() => AuthStep::Event(event.map_err(|_| ViewerError::TransportFailed)),
                code = answers.codes.recv(), if awaiting_code => match code {
                    Some(code) => AuthStep::Code(code),
                    // The senders above outlive this loop; a closed channel is
                    // not a state authentication waits in.
                    None => return Err(ViewerError::Closed),
                },
                password = answers.passwords.recv(), if awaiting_password => match password {
                    Some(password) => AuthStep::Password(password),
                    None => return Err(ViewerError::Closed),
                },
            }
        } else {
            AuthStep::Event(
                session
                    .recv_for_auth()
                    .await
                    .map_err(|_| ViewerError::TransportFailed),
            )
        };
        lock(&state.inner).snapshot.enable_trusted_devices = session.enable_trusted_devices();
        match step {
            // The session itself decides whether the code is still admissible:
            // it checks its own absolute deadline and that it is still waiting,
            // and it writes on the same wire a failed login would use.
            AuthStep::Code(code) => session
                .send_second_factor(code)
                .await
                .map_err(|_| ViewerError::TransportFailed)?,
            // The demand this loop armed is answered on the wire the session
            // already owns: the login the peer refused is resent with the new
            // password, so the target, controller identity, session id and role
            // it carried are the ones the peer reads again, and the session's
            // own absolute authentication deadline is unchanged. The answer's
            // bytes are cleared as soon as the write is done with them, whether
            // it was written or refused.
            AuthStep::Password(password) => {
                let Some(request) = session.login_request().cloned() else {
                    discard_password(password);
                    return Err(ViewerError::AuthenticationFailed);
                };
                // The guard also scrubs if cancellation drops this future
                // during the write; code after `.await` would not run then.
                let answer = Password(password.into_bytes());
                let written = session.login(request, Some(&answer.0)).await;
                drop(answer);
                written.map_err(|_| ViewerError::TransportFailed)?;
            }
            AuthStep::Event(event) => match event? {
                ViewerEvent::PreAuthProbe(probe) => {
                    session
                        .reply_auth_probe(probe)
                        .await
                        .map_err(|_| ViewerError::TransportFailed)?;
                }
                ViewerEvent::Challenge => {
                    let mut request = login_request(options, supported.clone());
                    let credential = match conn_token.take() {
                        Some(token) => {
                            if token.session_id() != 0 {
                                request.session_id = token.session_id();
                            }
                            LoginCredential::Reconnect(token)
                        }
                        None if password.0.is_empty() => LoginCredential::ManualApproval,
                        None => LoginCredential::Password(&password.0),
                    };
                    // A login that carries no material waits on the peer's
                    // operator, who may accept it. The official client raises
                    // its password step beside that wait (client.rs:4690), so a
                    // password typed meanwhile settles the same attempt; the
                    // peer may also say nothing at all while its operator
                    // decides, and without this step the consumer would have
                    // nothing to show or answer.
                    let offers_password = matches!(credential, LoginCredential::ManualApproval);
                    let written = session.login_with(request, credential).await;
                    hbb_common::sodiumoxide::utils::memzero(&mut password.0);
                    password.0.clear();
                    written
                        // The login could not be sent, which is the same
                        // transport outcome and not the peer's decision about
                        // the credential.
                        .map_err(|_| ViewerError::TransportFailed)?;
                    if offers_password {
                        demand_password(state, answers, passwords, LoginFailure::EmptyPassword)?;
                    }
                }
                ViewerEvent::Authorized(_) => {
                    let token = session.take_reconnect_credential();
                    let parts = session
                        .into_authenticated_parts()
                        .map_err(|_| ViewerError::AuthenticationFailed)?;
                    let mut inner = lock(&state.inner);
                    if !state.cancel.is_cancelled() {
                        inner.conn_token = token;
                    }
                    return Ok(parts);
                }
                ViewerEvent::LoginError(error) if error == "No Password Access" => {
                    // The peer's operator has to accept this request, so the
                    // credential question this attempt asked is over: a password
                    // typed at the form that was up can no longer settle
                    // anything, and one offered now is refused instead of held.
                    *lock(&state.password) = PasswordGate::default();
                    *lock(&state.second_factor) = SecondFactorGate::default();
                    answers.clear();
                    state.phase("awaiting_approval")
                }
                // The peer asked for a second factor, and the same session is
                // what answers it. `Wrong 2FA Code` is the peer's answer to the
                // code this loop sent, so the step is armed again for the retry
                // instead of ending a session the peer has not refused.
                ViewerEvent::LoginError(error)
                    if error == "2FA Required" || error == "Wrong 2FA Code" =>
                {
                    // A demand that did not leave the session waiting for a code
                    // — a peer refusing before any login, where `recv` already
                    // closed the session — has no step to answer, so nothing is
                    // armed and no code is accepted for it.
                    if session.state() != ViewerState::Await2Fa {
                        return Err(ViewerError::LoginFailed(LoginFailure::Refused));
                    }
                    // A login the peer accepted far enough to ask for a code is
                    // past the password step: the form that was up is closed, and
                    // a password offered from here on must not be written as
                    // another login into this step.
                    *lock(&state.password) = PasswordGate::default();
                    *lock(&state.second_factor) = SecondFactorGate::default();
                    answers.clear();
                    let mut gate = lock(&state.second_factor);
                    let mut inner = lock(&state.inner);
                    inner.snapshot.second_factor_challenge = inner
                        .snapshot
                        .second_factor_challenge
                        .checked_add(1)
                        .ok_or(ViewerError::AuthenticationFailed)?;
                    inner.snapshot.phase = if error == "Wrong 2FA Code" {
                        "second_factor_rejected"
                    } else {
                        "awaiting_second_factor"
                    }
                    .into();
                    gate.code = Some(codes.clone());
                    gate.submitted = false;
                }
                // The peer's password demand on this same, still-open session:
                // `Empty Password` is the peer wanting one this attempt did not
                // send, `Wrong Password` its refusal of the one it sent. Either
                // way the login this session already holds is what a retry
                // resends, so the step is armed for exactly that answer and the
                // attempt stays open instead of ending here — which is what lets
                // a desktop or file-transfer session reach the step that
                // follows. A demand that did not leave the session waiting for a
                // login — a peer refusing before any login, where `recv`
                // already closed the session — has no step to answer, so it
                // keeps its failure category.
                ViewerEvent::LoginError(error)
                    if error == "Empty Password" || error == "Wrong Password" =>
                {
                    let failure = LoginFailure::of(&error);
                    if session.state() != ViewerState::AwaitLogin {
                        return Err(ViewerError::LoginFailed(failure));
                    }
                    demand_password(state, answers, passwords, failure)?;
                }
                // Every other refusal keeps its category: the peer's text is
                // what the classification reads, and the category is what a
                // client decides with. A peer that reports its own second-factor
                // verification unsupported is one of them — no code can settle
                // it, so it is not a wait this engine enters.
                ViewerEvent::LoginError(error) => {
                    return Err(ViewerError::LoginFailed(LoginFailure::of(&error)));
                }
                ViewerEvent::Closed => {
                    lock(&state.inner).observed_peer_close_reason = session.peer_close_reason();
                    return Err(ViewerError::RemoteClosed);
                }
                ViewerEvent::Progress | ViewerEvent::PreAuthControl(_) => {}
                _ => return Err(ViewerError::AuthenticationFailed),
            },
        }
    }
}
