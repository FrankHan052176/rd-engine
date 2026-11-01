//! Direct TCP authentication slice and post-auth dispatch gates, not a media
//! runtime. Handshake/relay callers can both supply an Established connection.
//! Authorization is not media readiness. No decoder, capture, CPU pixel copy,
//! upload fallback, or synthetic video-success path exists in this module.
use crate::{
    authentication::{
        self, AuthAction, HostAuthConfig, HostAuthState, HostAuthentication, Permissions,
    },
    conn_token::{ConnToken, PasswordSource, H1_BYTES},
    handshake::{self, Established, HostIdentity, Security, ViewerIdentity},
    transport::{WireReader, WireWriter},
};
use base::message_proto::{
    Auth2FA, Hash, LoginRequest, LoginResponse, Message, Misc, OptionMessage, PeerInfo,
    PermissionInfo, TestDelay, message, misc, permission_info::Permission,
};
use hbb_common::{
    protobuf::Message as _,
    sodiumoxide::{crypto::secretbox, utils},
    tcp::FramedStream,
};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, time::Instant};

fn failure(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn login_error(error: &str) -> Message {
    let mut response = LoginResponse::new();
    response.set_error(error.to_owned());
    let mut message = Message::new();
    message.set_login_response(response);
    message
}
fn close_message() -> Message {
    let mut misc = Misc::new();
    misc.set_close_reason("".into());
    let mut message = Message::new();
    message.set_misc(misc);
    message
}
fn close_reason(message: &Message) -> Option<&str> {
    let Some(message::Union::Misc(m)) = &message.union else { return None; };
    match &m.union {
        Some(misc::Union::CloseReason(reason)) => Some(reason.as_str()),
        _ => None,
    }
}

/// Owns the single-use code through early refusal and cancelled writes too.
struct SecondFactorMessage(Message);
impl Drop for SecondFactorMessage {
    fn drop(&mut self) {
        if let Some(message::Union::Auth2fa(factor)) = self.0.union.as_mut() {
            let mut bytes = std::mem::take(&mut factor.code).into_bytes();
            utils::memzero(&mut bytes);
        }
    }
}

/// Authentication owns the original, unsplit, small-limit wire. Only the
/// Active-gated public handoff may turn this into full-duplex media transport.
struct SessionIo {
    wire: Option<FramedStream>,
    prefetched: Option<Message>,
}
impl SessionIo {
    fn new(mut wire: FramedStream, prefetched: Option<Message>) -> Self {
        wire.0
            .codec_mut()
            .set_max_packet_length(handshake::AUTH_MAX_RECORD_BYTES);
        Self {
            wire: Some(wire),
            prefetched,
        }
    }
    fn terminate(&mut self) {
        self.wire.take();
        self.prefetched.take();
    }
    async fn recv(&mut self) -> io::Result<Option<Message>> {
        if let Some(message) = self.prefetched.take() {
            return Ok(Some(message));
        }
        let result = match self.wire.as_mut() {
            Some(wire) => match wire.next().await {
                Some(Ok(bytes)) => Message::parse_from_bytes(&bytes)
                    .map(Some)
                    .map_err(|_| failure("Invalid authentication message")),
                Some(Err(error)) => Err(error),
                None => Ok(None),
            },
            None => return Ok(None),
        };
        if !matches!(result, Ok(Some(_))) {
            self.terminate();
        }
        result
    }
    async fn send(&mut self, message: &Message) -> io::Result<()> {
        let wire = self
            .wire
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "Session closed"))?;
        let overhead = if wire.2.is_some() {
            secretbox::MACBYTES
        } else {
            0
        };
        if message.compute_size() > (handshake::AUTH_MAX_RECORD_BYTES - overhead) as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Oversized authentication message",
            ));
        }
        // A cancelled/failed send may have advanced the nonce or partially
        // written a record. Own the wire across await: cancellation drops it,
        // leaving self.wire=None. Never restore a half-written byte stream.
        let mut wire = self.wire.take().ok_or_else(|| failure("Session closed"))?;
        wire.send(message)
            .await
            .map_err(|_| io::Error::other("Authentication write failed"))?;
        self.wire = Some(wire);
        Ok(())
    }

    fn take_parts(&mut self) -> io::Result<(WireReader, WireWriter)> {
        // A prefetched handshake record must pass authentication dispatch first.
        if self.prefetched.is_some() {
            return Err(failure("Undispatched handshake record"));
        }
        let wire = self.wire.take().ok_or_else(|| failure("Session closed"))?;
        Ok(crate::transport::split(wire))
    }
}

/// Sanitized routing/session claims. Controller ID/name are peer claims, not
/// cryptographic identities. No password, OS credential, hwid or key is retained.
pub struct SessionClaims {
    pub target: String,
    pub controller_id: String,
    pub controller_name: String,
    pub controller_platform: String,
    pub controller_version: String,
    pub session_id: u64,
    pub video_ack_required: bool,
    pub options: Option<OptionMessage>,
}
impl From<&LoginRequest> for SessionClaims {
    fn from(request: &LoginRequest) -> Self {
        Self {
            target: request.username.clone(),
            controller_id: request.my_id.clone(),
            controller_name: request.my_name.clone(),
            controller_platform: request.my_platform.clone(),
            controller_version: request.version.clone(),
            session_id: request.session_id,
            video_ack_required: request.video_ack_required,
            options: request.option.as_ref().cloned(),
        }
    }
}

/// Immutable protocol role, fixed before routing and authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SessionMode {
    #[default]
    Desktop,
    FileTransfer,
}

pub enum AuthenticatedSide {
    Viewer,
    Host,
}

// Original desktop hosts send only disabled permissions during Connection::start;
// original viewer initializes keyboard/file/clipboard as enabled (1.4.9
// src/flutter.rs / src/ui/remote.rs) and treats omitted remote permissions as
// allowed. These are REMOTE defaults, never a local host grant or codec claim.
// Keep Permissions::default() deny-all for local host authorization and expose
// this cached remote state only after LoginResponse.PeerInfo succeeds.
const VIEWER_REMOTE_DEFAULTS: Permissions = Permissions {
    keyboard: true,
    clipboard: true,
    audio: true,
    file: true,
};

pub struct AuthenticatedContext {
    pub side: AuthenticatedSide,
    /// Only Encrypted.peer_id=Some identifies a signature-verified host. A host
    /// must never relabel claims.controller_id as a signature-verified peer.
    pub security: Security,
    /// Host: local deny-by-default policy grant. Viewer: original remote defaults
    /// overlaid by received reports, applicable only after authentication.
    /// Runtime must additionally apply local policy, options and real capability
    /// gates; remote permission does not mean a local feature is implemented.
    pub permissions: Permissions,
    /// Exact known peer reports, preserving missing vs false. Viewer only.
    pub permission_reports: Vec<PermissionInfo>,
    pub claims: SessionClaims,
    /// Viewer only: peer-supplied metadata, not validated codec availability.
    pub peer_info: Option<PeerInfo>,
}

/// Consume the authentication driver and give the media runtime independent
/// ownership. No session select loop, echo task, lock, or hidden writer remains.
pub struct AuthenticatedParts {
    pub reader: WireReader,
    pub writer: WireWriter,
    pub context: AuthenticatedContext,
}

/// A recognized peer close request, never the peer's arbitrary wire text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCloseReason {
    ManualRequest,
}

impl PeerCloseReason {
    pub(crate) fn of(reason: &str) -> Option<Self> {
        match reason {
            "Closed manually by the peer" => Some(Self::ManualRequest),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerState {
    AwaitHash,
    AwaitLogin,
    AwaitApproval,
    Await2Fa,
    Active,
    Closed,
}
pub enum ViewerEvent {
    Challenge,
    LoginError(String),
    /// Peer accepted authentication. Media capability/zero-copy readiness must
    /// still be established by the media provider, never inferred from login.
    Authorized(PeerInfo),
    PermissionChanged(Permissions),
    /// Explicitly allowed peer negotiation/UI control BEFORE login success.
    /// Never an authorization grant and never a media/input payload.
    PreAuthControl(Message),
    /// A pre-authentication probe read without writing a response. The
    /// multiplexing authentication driver replies outside its read select.
    PreAuthProbe(TestDelay),
    /// Authenticated wire payload, not proof of decode/render completion.
    Payload(Message),
    Progress,
    Closed,
}

/// What one login attempt carries as its password material.
///
/// The two password forms are the same computation at two points of the official
/// protocol: the client keeps h1 = SHA256(clear_password || peer salt) and sends
/// SHA256(h1 || the peer's challenge). A password a user types becomes h1 on this
/// path; a reconnect credential arrives as an h1 that was already salted with this
/// peer's salt, so salting it again would send a response no peer can verify.
/// Which one it is stays the caller's statement — and a `Reconnect` material can
/// only come from the official token text, never from an invented one.
pub enum LoginCredential<'a> {
    /// The original manual-approval login: no password material at all.
    ManualApproval,
    /// A password the user typed, in the clear, for this attempt only.
    Password(&'a [u8]),
    /// The official reconnect material with the provenance it arrived with. It is
    /// owned because that provenance may be a shared password string, and the
    /// token is consumed so the secret is never copied.
    Reconnect(ConnToken),
}

/// Password-equivalent material kept only so an authenticated session can be
/// reconnected from.
///
/// It holds the same h1 a typed password produces, where that password came from
/// and the session id this attempt used. It exists only while the attempt does: a
/// refusal that judged the password itself, a termination, a close, a replacement
/// by another attempt or the session's own drop zeroes it.
struct ReconnectCandidate {
    h1: Vec<u8>,
    source: PasswordSource,
    session_id: u64,
}

impl ReconnectCandidate {
    /// Hands the material to the caller that asked for it, without a copy. The
    /// emptied candidate drops as a shell.
    fn into_token(mut self) -> Option<ConnToken> {
        let h1 = std::mem::take(&mut self.h1);
        let source = std::mem::replace(&mut self.source, PasswordSource::Undefined);
        ConnToken::from_h1(h1, source, self.session_id)
    }
}

impl Drop for ReconnectCandidate {
    fn drop(&mut self) {
        utils::memzero(&mut self.h1);
        self.h1.clear();
    }
}

pub struct ViewerSession {
    io: SessionIo,
    security: Security,
    state: ViewerState,
    peer_close_reason: Option<PeerCloseReason>,
    hash: Option<Hash>,
    request: Option<LoginRequest>,
    permissions: Permissions,
    permission_reports: Vec<PermissionInfo>,
    peer_info: Option<PeerInfo>,
    enable_trusted_devices: Option<bool>,
    /// The credential a reconnect of this attempt would reuse, while the attempt
    /// is still running. Never part of a snapshot: it is taken explicitly, and
    /// only from an authenticated session.
    reconnect: Option<ReconnectCandidate>,
    auth_deadline: Instant,
    idle_timeout: Duration,
}

impl ViewerSession {
    pub fn from_established(
        wire: Established,
        auth_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        let (wire, security, prefetched) = wire.into_unsplit();
        Self {
            io: SessionIo::new(wire, prefetched),
            security,
            state: ViewerState::AwaitHash,
            peer_close_reason: None,
            hash: None,
            request: None,
            permissions: VIEWER_REMOTE_DEFAULTS,
            permission_reports: Vec::new(),
            peer_info: None,
            enable_trusted_devices: None,
            reconnect: None,
            auth_deadline: Instant::now() + auth_timeout,
            idle_timeout,
        }
    }
    /// Address is only the TCP route. The caller supplies target username and
    /// stable-ID evidence separately when logging in / selecting handshake.
    pub async fn connect_direct(
        address: SocketAddr,
        identity: ViewerIdentity,
        timeout: Duration,
    ) -> io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;
        stream.set_nodelay(true)?;
        let local = stream.local_addr()?;
        Self::connect_over(FramedStream::from(stream, local), identity, timeout).await
    }

    /// Completes the viewer handshake over an already-connected record stream.
    ///
    /// This is what makes the transport interchangeable: `FramedStream` is
    /// built on a boxed `AsyncRead + AsyncWrite`, so
    /// `hbb_common::tcp::FramedStream::from` accepts a QUIC bidirectional
    /// stream ([`crate::net::quic::QuicStream`]) exactly as it accepts a
    /// `TcpStream`, and both then reach the same handshake, the same
    /// authentication actors and the same session state machine. Nothing above
    /// this line knows which transport it is on.
    pub async fn connect_over(
        wire: FramedStream,
        identity: ViewerIdentity,
        timeout: Duration,
    ) -> io::Result<Self> {
        let wire = handshake::viewer(wire, identity, timeout).await?;
        Ok(Self::from_established(
            wire,
            timeout,
            Duration::from_secs(30),
        ))
    }
    pub fn enable_trusted_devices(&self) -> Option<bool> {
        self.enable_trusted_devices
    }
    pub fn state(&self) -> ViewerState {
        self.state
    }
    /// The exact recognized close request, retained after session termination.
    pub fn peer_close_reason(&self) -> Option<PeerCloseReason> {
        self.peer_close_reason
    }
    pub fn security(&self) -> &Security {
        &self.security
    }
    pub fn permissions(&self) -> Permissions {
        if self.state == ViewerState::Active {
            self.permissions
        } else {
            Permissions::default()
        }
    }

    /// Fails closed (consumes/drops the session) unless LoginResponse.PeerInfo
    /// has been received. Call immediately on Authorized; independently schedule
    /// reads/writes and TestDelay responses in the new runtime thereafter.
    pub fn into_authenticated_parts(mut self) -> io::Result<AuthenticatedParts> {
        if self.state != ViewerState::Active {
            return Err(failure("Session is not authenticated"));
        }
        let claims = self
            .request
            .as_ref()
            .map(SessionClaims::from)
            .ok_or_else(|| failure("Missing authenticated request"))?;
        let (reader, writer) = self.io.take_parts()?;
        Ok(AuthenticatedParts {
            reader,
            writer,
            context: AuthenticatedContext {
                side: AuthenticatedSide::Viewer,
                security: self.security,
                permissions: self.permissions,
                permission_reports: self.permission_reports,
                claims,
                peer_info: self.peer_info,
            },
        })
    }

    fn record_permission(&mut self, info: &PermissionInfo) {
        let Ok(permission) = info.permission.enum_value() else {
            return;
        };
        match permission {
            Permission::Keyboard => self.permissions.keyboard = info.enabled,
            Permission::Clipboard => self.permissions.clipboard = info.enabled,
            Permission::Audio => self.permissions.audio = info.enabled,
            Permission::File => self.permissions.file = info.enabled,
            _ => {}
        }
        if let Some(old) = self
            .permission_reports
            .iter_mut()
            .find(|old| old.permission == info.permission)
        {
            *old = info.clone();
        } else {
            self.permission_reports.push(info.clone());
        }
    }

    fn terminate(&mut self) {
        self.state = ViewerState::Closed;
        // Keep the typed terminal observation for the owner's final snapshot.
        self.permissions = Permissions::default();
        self.hash = None;
        self.request = None;
        self.permission_reports.clear();
        self.peer_info = None;
        // A terminated session is not one a reconnect may be made from, so the
        // material kept for that is scrubbed here rather than left for its drop.
        self.reconnect = None;
        self.io.terminate();
    }

    /// Empty None credentials preserve the original manual-approval request.
    /// Some(empty password) is rejected rather than mistaken for stored h1.
    /// `request.option.supported_decoding` is passed through from the caller's
    /// real capability provider. No VP9/H265/default decoder is inserted here.
    /// Old peers may interpret an absent advertisement as their historical VP9
    /// baseline; that wire behavior does not create a local decoder or permit
    /// a CPU-copy compatibility exception.
    pub async fn login(
        &mut self,
        request: LoginRequest,
        password: Option<&[u8]>,
    ) -> io::Result<()> {
        let credential = match password {
            None => LoginCredential::ManualApproval,
            Some(password) => LoginCredential::Password(password),
        };
        self.login_with(request, credential).await
    }

    /// The one login path: it validates the request, answers this peer's
    /// challenge from whichever material it was given, writes the login on the
    /// open wire and keeps the material a reconnect would need.
    ///
    /// Target, controller identity, session id and role are still frozen after
    /// the first written login, the deadline still applies, and nothing here
    /// dials or resets it: a retry is this login again on this session.
    ///
    /// A typed `Password` also makes the provenance `Undefined`, as the official
    /// client does whenever the password came from the user (client.rs:4774-4778):
    /// an earlier address-book claim must not survive a password the user just
    /// typed.
    pub async fn login_with(
        &mut self,
        mut request: LoginRequest,
        credential: LoginCredential<'_>,
    ) -> io::Result<()> {
        if Instant::now() >= self.auth_deadline {
            self.terminate();
            return Err(failure("Authentication deadline expired"));
        }
        if !matches!(
            self.state,
            ViewerState::AwaitLogin | ViewerState::AwaitApproval | ViewerState::Await2Fa
        ) {
            return Err(failure("Login is not allowed in this state"));
        }
        if self.hash.is_none() {
            return Err(failure("No peer challenge"));
        }
        let mode = match &request.union {
            None => SessionMode::Desktop,
            Some(base::message_proto::login_request::Union::FileTransfer(_)) => SessionMode::FileTransfer,
            _ => return Err(failure("Unsupported login role")),
        };
        if request.username.is_empty() || request.my_id.is_empty() {
            return Err(failure(
                "Login requires an explicit target and controller identity",
            ));
        }
        if !request.os_login.username.is_empty() || !request.os_login.password.is_empty() {
            return Err(failure("OS login unsupported"));
        }
        if let Some(first) = &self.request {
            if first.username != request.username
                || first.my_id != request.my_id
                || first.session_id != request.session_id
                || first.has_file_transfer() != (mode == SessionMode::FileTransfer)
            {
                return Err(failure("Login retry cannot change identity/scope"));
            }
        }
        let (response, reconnect) = self.challenge_material(request.session_id, credential)?;
        request.password = response.into();
        let mut retained = request.clone();
        retained.password = Default::default();
        let mut message = Message::new();
        message.set_login_request(request);
        if let Err(error) = self.io.send(&message).await {
            self.terminate();
            return Err(error);
        }
        // Only a login that actually reached the wire keeps material. A failed or
        // cancelled write terminated the session, which scrubs what an earlier
        // attempt held; a written one replaces it.
        self.reconnect = reconnect;
        self.request = Some(retained);
        self.state = ViewerState::AwaitLogin;
        Ok(())
    }

    /// The bytes this login carries in `LoginRequest.password`, plus the material
    /// a reconnect of this attempt would need.
    ///
    /// This is the only place the challenge response is computed, for both kinds
    /// of material, so neither can drift from the other: the wire always gets
    /// `SHA256(h1 || challenge)` of this peer's own challenge. A typed password
    /// becomes h1 here with this peer's salt; a reconnect credential already is
    /// h1 and is hashed exactly once, never salted again. The retained h1 is
    /// zeroed here and lives on only in the returned candidate.
    fn challenge_material(
        &self,
        session_id: u64,
        credential: LoginCredential<'_>,
    ) -> io::Result<(Vec<u8>, Option<ReconnectCandidate>)> {
        let hash = self
            .hash
            .as_ref()
            .ok_or_else(|| failure("No peer challenge"))?;
        match credential {
            // The original manual-approval login: no wire password, and nothing a
            // reconnect could reuse. No material is invented for it.
            LoginCredential::ManualApproval => Ok((Vec::new(), None)),
            LoginCredential::Password(password) => {
                if password.is_empty() {
                    return Err(failure("Empty supplied password"));
                }
                if std::env::var_os("RD_LOG_CHALLENGE").is_some() {
                    // Both fields travel in the clear on this wire; the password
                    // and everything derived from it are never printed.
                    eprintln!(
                        "peer challenge: salt_len={} salt={:?} challenge_len={} challenge={:?}",
                        hash.salt.len(),
                        hash.salt,
                        hash.challenge.len(),
                        hash.challenge
                    );
                }
                let mut h1 = authentication::salted_password(password, &hash.salt);
                let response = authentication::password_response(&h1, &hash.challenge);
                let reconnect = ReconnectCandidate {
                    h1: h1.to_vec(),
                    source: PasswordSource::Undefined,
                    session_id,
                };
                utils::memzero(&mut h1);
                Ok((response.to_vec(), Some(reconnect)))
            }
            LoginCredential::Reconnect(token) => {
                // A token without a session id repeats the official reader's own
                // rule (client.rs:2934-2941): the caller supplies the fresh
                // nonzero id, because choosing it is the caller's step. A zero id
                // here is a caller that skipped it, not a token this session may
                // pretend was usable.
                if session_id == 0 {
                    return Err(failure("Reconnect requires a fresh nonzero session id"));
                }
                let token_session = token.session_id();
                if token_session != 0 && token_session != session_id {
                    return Err(failure("Reconnect credential belongs to another session"));
                }
                let (h1, source) = token.into_parts();
                let Ok(mut material) = <[u8; H1_BYTES]>::try_from(h1.as_slice()) else {
                    let mut h1 = h1;
                    utils::memzero(&mut h1);
                    return Err(failure("Reconnect credential is not a salted password"));
                };
                let response = authentication::password_response(&material, &hash.challenge);
                let reconnect = ReconnectCandidate {
                    h1,
                    source,
                    session_id,
                };
                utils::memzero(&mut material);
                Ok((response.to_vec(), Some(reconnect)))
            }
        }
    }

    /// The credential a reconnect of this authenticated session may be made with.
    ///
    /// Nothing is exported before the peer's own `PeerInfo` moved this session to
    /// [`ViewerState::Active`]: a demanded password, an approval wait or a second
    /// factor is not an authentication, and a credential handed out then would
    /// claim a session this engine never got. A session that carried no password
    /// material (manual approval) exports nothing rather than an invented one, and
    /// a closed or terminated one has already scrubbed what it held.
    ///
    /// Taking is explicit and once: the caller owns the token from here (the
    /// Viewer keeps it in a slot of its own, outside every snapshot), and a second
    /// call returns `None` instead of duplicating a password-equivalent secret.
    pub fn take_reconnect_credential(&mut self) -> Option<ConnToken> {
        if self.state != ViewerState::Active {
            return None;
        }
        self.reconnect.take()?.into_token()
    }

    /// The login this session already sent, with the identity and role it
    /// carries and without the password material.
    ///
    /// A retry the peer asks for is this login again: the same target, the same
    /// controller identity, the same session id and the same desktop-or-file
    /// role. Resending it is what makes a password answer a retry on the wire
    /// that is already open, instead of a new request the peer would read as
    /// another attempt.
    pub(crate) fn login_request(&self) -> Option<&LoginRequest> {
        self.request.as_ref()
    }

    /// Answers the peer's second-factor step on this same session and wire.
    ///
    /// The session is the one that decides whether a code is still admissible:
    /// it refuses one before the peer asked, after an answer moved it past that
    /// step, and after its own absolute authentication deadline, and it writes
    /// on the wire a failed login would use. No trusted-device enrollment or
    /// bypass is implemented here, so the `hwid` stays empty; a code is sent and
    /// then cleared, never kept.
    pub async fn send_second_factor(&mut self, code: String) -> io::Result<()> {
        let mut message = SecondFactorMessage(Message::new());
        message.0.set_auth_2fa(Auth2FA {
            code,
            ..Default::default()
        });
        if Instant::now() >= self.auth_deadline {
            self.terminate();
            return Err(failure("Authentication deadline expired"));
        }
        if self.state != ViewerState::Await2Fa {
            return Err(failure("Not awaiting second factor"));
        }
        let result = self.io.send(&message.0).await;
        if result.is_err() {
            self.terminate();
        }
        result
    }

    pub async fn recv(&mut self) -> io::Result<ViewerEvent> {
        match self.recv_for_auth().await? {
            ViewerEvent::PreAuthProbe(probe) => {
                self.reply_auth_probe(probe).await?;
                Ok(ViewerEvent::Progress)
            }
            event => Ok(event),
        }
    }

    /// Pure framed read plus synchronous dispatch, safe to multiplex with a
    /// local answer. In particular it never awaits a probe response write.
    pub(crate) async fn recv_for_auth(&mut self) -> io::Result<ViewerEvent> {
        let result = self.recv_inner().await;
        if result.is_err() || self.state == ViewerState::Closed {
            self.terminate();
        }
        result
    }

    pub(crate) async fn reply_auth_probe(&mut self, probe: TestDelay) -> io::Result<()> {
        if Instant::now() >= self.auth_deadline {
            self.terminate();
            return Err(failure("Authentication deadline expired"));
        }
        if self.state == ViewerState::Closed || self.state == ViewerState::Active {
            return Err(failure("Not in authentication"));
        }
        let mut response = Message::new();
        response.set_test_delay(probe);
        let result = self.io.send(&response).await;
        if result.is_err() {
            self.terminate();
        }
        result
    }

    async fn recv_inner(&mut self) -> io::Result<ViewerEvent> {
        if self.state == ViewerState::Closed {
            return Ok(ViewerEvent::Closed);
        }
        let deadline = if self.state == ViewerState::Active {
            Instant::now() + self.idle_timeout
        } else {
            self.auth_deadline
        };
        let result = tokio::time::timeout_at(deadline, self.io.recv()).await;
        let message = match result {
            Ok(Ok(Some(message))) => message,
            Ok(Ok(None)) => {
                self.state = ViewerState::Closed;
                return Ok(ViewerEvent::Closed);
            }
            Ok(Err(error)) => {
                self.state = ViewerState::Closed;
                return Err(error);
            }
            Err(_) => {
                self.state = ViewerState::Closed;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Session receive timeout",
                ));
            }
        };
        if let Some(reason) = close_reason(&message) {
            self.peer_close_reason = PeerCloseReason::of(reason);
            self.state = ViewerState::Closed;
            return Ok(ViewerEvent::Closed);
        }
        match &message.union {
            Some(message::Union::TestDelay(probe)) => {
                // Never write inside this read: the authentication driver may
                // cancel it when a local 2FA answer arrives. Writes retain the
                // wire across await and must be scheduled outside that select.
                if self.state == ViewerState::Active {
                    return Ok(ViewerEvent::Payload(message));
                }
                if !probe.from_client {
                    return Ok(ViewerEvent::PreAuthProbe(probe.clone()));
                }
                return Ok(ViewerEvent::Progress);
            }
            None => return Ok(ViewerEvent::Progress),
            // Original missing-key viewer can encounter the host's earlier
            // SignedId before Hash; it has already sent the empty compatibility M.
            Some(message::Union::SignedId(_))
                if self.state == ViewerState::AwaitHash
                    && matches!(self.security, Security::LegacyPlain { .. }) =>
            {
                return Ok(ViewerEvent::Progress);
            }
            Some(message::Union::Hash(hash)) if self.state == ViewerState::AwaitHash => {
                if hash.salt.is_empty() || hash.challenge.is_empty() {
                    self.state = ViewerState::Closed;
                    return Err(failure("Invalid authentication challenge"));
                }
                self.hash = Some(hash.clone());
                self.state = ViewerState::AwaitLogin;
                return Ok(ViewerEvent::Challenge);
            }
            Some(message::Union::LoginResponse(response)) if self.state != ViewerState::Active => {
                self.enable_trusted_devices = Some(response.enable_trusted_devices);
                match &response.union {
                    Some(base::message_proto::login_response::Union::Error(error)) => {
                        // The peer's verdict on the password itself is the one
                        // refusal that invalidates the material a reconnect would
                        // reuse. A second factor or an approval refusal comes
                        // after that password was accepted, so it must not throw
                        // it away, and neither must a rejection this engine cannot
                        // attribute to the password.
                        if error == authentication::WRONG_PASSWORD || error == "Empty Password" {
                            self.reconnect = None;
                        }
                        // Original on_open/whitelist policy can reject before
                        // Hash or any LoginRequest. Surface the refusal, never
                        // mistake it for an application payload or an auth grant.
                        if self.request.is_none() {
                            self.state = ViewerState::Closed;
                            return Ok(ViewerEvent::LoginError(error.clone()));
                        }
                        self.state = match error.as_str() {
                            "2FA Required" | "Wrong 2FA Code" | "2FA verification unsupported" => {
                                ViewerState::Await2Fa
                            }
                            "No Password Access" => ViewerState::AwaitApproval,
                            _ => ViewerState::AwaitLogin,
                        };
                        return Ok(ViewerEvent::LoginError(error.clone()));
                    }
                    Some(base::message_proto::login_response::Union::PeerInfo(info)) => {
                        if self.request.is_none() {
                            return Err(failure("Unsolicited login success"));
                        }
                        self.state = ViewerState::Active;
                        self.peer_info = Some(info.clone());
                        return Ok(ViewerEvent::Authorized(info.clone()));
                    }
                    _ => {
                        self.state = ViewerState::Closed;
                        return Err(failure("Empty login response"));
                    }
                }
            }
            _ => {}
        }
        // Verified against 1.4.9 Connection::start: Hash -> denied permissions
        // precedes the login loop. CM may send ChatMessage/SwitchPermission
        // before authorization; Wayland is_inited sends MessageBox before the
        // successful LoginResponse. These are reports/UI only, NOT auth success.
        if let Some(message::Union::Misc(m)) = &message.union {
            if let Some(misc::Union::PermissionInfo(info)) = &m.union {
                self.record_permission(info);
                return Ok(if self.state == ViewerState::Active {
                    ViewerEvent::PermissionChanged(self.permissions)
                } else {
                    ViewerEvent::PreAuthControl(message)
                });
            }
        }
        if self.state != ViewerState::Active
            && (matches!(&message.union, Some(message::Union::MessageBox(_)))
                || matches!(&message.union, Some(message::Union::Misc(m)) if matches!(m.union, Some(misc::Union::ChatMessage(_)))))
        {
            return Ok(ViewerEvent::PreAuthControl(message));
        }
        if self.state != ViewerState::Active {
            self.state = ViewerState::Closed;
            return Err(failure("Application payload before authentication"));
        }
        Ok(ViewerEvent::Payload(message))
    }
    pub async fn close(&mut self) -> io::Result<()> {
        if self.state == ViewerState::Closed {
            return Ok(());
        }
        let result = self.io.send(&close_message()).await;
        self.terminate();
        result
    }
}

pub enum HostEvent {
    Progress,
    AwaitApproval,
    LoginRejected(&'static str),
    /// Authentication grant only, not capture/codec/display readiness.
    Authorized(Permissions),
    Unsupported,
    Closed,
}

pub struct HostSession {
    io: SessionIo,
    auth: HostAuthentication,
    security: Security,
    permissions: Permissions,
    ready: bool,
    auth_deadline: Instant,
    idle_timeout: Duration,
}

impl HostSession {
    pub async fn from_established(
        wire: Established,
        config: HostAuthConfig,
        auth_timeout: Duration,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        let auth = HostAuthentication::new(config).map_err(failure)?;
        let (wire, security, prefetched) = wire.into_unsplit();
        let mut io = SessionIo::new(wire, prefetched);
        let mut message = Message::new();
        message.set_hash(auth.challenge().clone());
        io.send(&message).await?;
        Ok(Self {
            io,
            auth,
            security,
            permissions: Permissions::default(),
            ready: false,
            auth_deadline: Instant::now() + auth_timeout,
            idle_timeout,
        })
    }
    pub async fn accept_direct(
        stream: TcpStream,
        identity: HostIdentity,
        config: HostAuthConfig,
        timeout: Duration,
    ) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let local = stream.local_addr()?;
        let wire = handshake::host(FramedStream::from(stream, local), identity, timeout).await?;
        Self::from_established(wire, config, timeout, Duration::from_secs(30)).await
    }
    pub fn state(&self) -> HostAuthState {
        self.auth.state()
    }
    pub fn security(&self) -> &Security {
        &self.security
    }
    pub fn permissions(&self) -> Permissions {
        self.permissions
    }
    /// Sanitized, immutable pre-auth claims; contains no password/OS credentials.
    pub(crate) fn login_request(&self) -> Option<&LoginRequest> {
        self.auth.request()
    }

    /// Consumes the authenticated host driver after its success/permission
    /// records are flushed. Local auth providers/credentials are dropped here;
    /// runtime keeps only the grant and sanitized remote-desktop context.
    pub fn into_authenticated_parts(mut self) -> io::Result<AuthenticatedParts> {
        if self.auth.state() != HostAuthState::Authorized || !self.ready {
            return Err(failure("Session is not authenticated"));
        }
        let claims = self
            .auth
            .request()
            .map(SessionClaims::from)
            .ok_or_else(|| failure("Missing authenticated request"))?;
        let (reader, writer) = self.io.take_parts()?;
        Ok(AuthenticatedParts {
            reader,
            writer,
            context: AuthenticatedContext {
                side: AuthenticatedSide::Host,
                security: self.security,
                permissions: self.permissions,
                permission_reports: Vec::new(),
                claims,
                peer_info: None,
            },
        })
    }

    async fn apply(&mut self, action: AuthAction) -> io::Result<HostEvent> {
        let result = self.apply_inner(action).await;
        if result.is_err() || self.auth.state() == HostAuthState::Closed {
            self.auth.close();
            self.permissions = Permissions::default();
            self.io.terminate();
        }
        result
    }

    async fn apply_inner(&mut self, action: AuthAction) -> io::Result<HostEvent> {
        match action {
            AuthAction::Ignored => Ok(HostEvent::Progress),
            AuthAction::PendingApproval => {
                // Original pre-1.2.0 peers wait without this explanatory error.
                if self
                    .auth
                    .request()
                    .map(|v| {
                        hbb_common::get_version_number(&v.version)
                            >= hbb_common::get_version_number("1.2.0")
                    })
                    .unwrap_or(false)
                {
                    self.io.send(&login_error("No Password Access")).await?;
                }
                Ok(HostEvent::AwaitApproval)
            }
            AuthAction::Error {
                message,
                terminal: _,
            } => {
                self.io.send(&login_error(message)).await?;
                Ok(HostEvent::LoginRejected(message))
            }
            AuthAction::Authorized { info, permissions } => {
                let mut response = LoginResponse::new();
                response.set_peer_info(info);
                let mut message = Message::new();
                message.set_login_response(response);
                self.io.send(&message).await?;
                self.permissions = permissions;
                // Local capability providers authorize features, but this slice
                // has no feature adapters. It never executes those messages.
                for (permission, enabled) in [
                    (Permission::Keyboard, permissions.keyboard),
                    (Permission::Clipboard, permissions.clipboard),
                    (Permission::Audio, permissions.audio),
                    (Permission::File, permissions.file),
                    (Permission::Restart, false),
                    (Permission::Recording, false),
                    (Permission::BlockInput, false),
                    (Permission::PrivacyMode, false),
                ] {
                    let mut misc = Misc::new();
                    misc.set_permission_info(PermissionInfo {
                        permission: permission.into(),
                        enabled,
                        ..Default::default()
                    });
                    let mut message = Message::new();
                    message.set_misc(misc);
                    self.io.send(&message).await?;
                }
                self.ready = true;
                Ok(HostEvent::Authorized(permissions))
            }
        }
    }

    /// Call only when a trusted local approval provider has changed state.
    pub async fn poll_approval(&mut self) -> io::Result<HostEvent> {
        if Instant::now() >= self.auth_deadline && self.auth.state() != HostAuthState::Authorized {
            self.auth.close();
            self.io.terminate();
            return Err(failure("Authentication deadline expired"));
        }
        let action = self.auth.poll_approval();
        self.apply(action).await
    }

    pub async fn recv(&mut self) -> io::Result<HostEvent> {
        self.recv_notified(None).await
    }

    /// Multiplex local approval ONLY while waiting for a wire record. Once a
    /// record is read, dispatch and all its writes finish before approval can
    /// be polled. In particular, approval must not cancel a partially sent
    /// pre-auth reply (which intentionally makes SessionIo terminal).
    ///
    /// The provider must publish its decision before calling notify_one(), so
    /// a notification during dispatch is retained for the next receive boundary.
    /// Do not externally select this entire method against approval.notified().
    /// Deliberate connection cancellation remains allowed: it closes the wire.
    pub async fn recv_with_approval(
        &mut self,
        approval: &tokio::sync::Notify,
    ) -> io::Result<HostEvent> {
        self.recv_notified(Some(approval)).await
    }

    async fn recv_notified(
        &mut self,
        approval: Option<&tokio::sync::Notify>,
    ) -> io::Result<HostEvent> {
        let result = self.recv_inner(approval).await;
        if result.is_err() || self.auth.state() == HostAuthState::Closed {
            self.auth.close();
            self.permissions = Permissions::default();
            self.io.terminate();
        }
        result
    }

    async fn recv_inner(
        &mut self,
        approval: Option<&tokio::sync::Notify>,
    ) -> io::Result<HostEvent> {
        if self.auth.state() == HostAuthState::Closed {
            return Ok(HostEvent::Closed);
        }
        let deadline = if self.auth.state() == HostAuthState::Authorized {
            Instant::now() + self.idle_timeout
        } else {
            self.auth_deadline
        };
        // SessionIo.recv is cancel-safe: it only waits on FramedStream::next;
        // decrypt/parse and consuming the single prefetched record have no await
        // after consuming a frame. No send or auth dispatch occurs in this select.
        let incoming = if let Some(approval) = approval {
            tokio::select! {
                biased;
                _ = approval.notified() => None,
                incoming = tokio::time::timeout_at(deadline, self.io.recv()) => Some(incoming),
            }
        } else {
            Some(tokio::time::timeout_at(deadline, self.io.recv()).await)
        };
        let Some(incoming) = incoming else {
            // The receive future is already dropped here. Approval dispatch and
            // its success/permission writes are not raced against another wake.
            return self.poll_approval().await;
        };
        let message = match incoming {
            Ok(Ok(Some(message))) => message,
            Ok(Ok(None)) => {
                self.auth.close();
                return Ok(HostEvent::Closed);
            }
            Ok(Err(error)) => {
                self.auth.close();
                return Err(error);
            }
            Err(_) => {
                self.auth.close();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Session receive timeout",
                ));
            }
        };
        if close_reason(&message).is_some() {
            self.auth.close();
            return Ok(HostEvent::Closed);
        }
        match message.union {
            None => Ok(HostEvent::Progress),
            Some(message::Union::TestDelay(probe)) => {
                if probe.from_client {
                    let mut m = Message::new();
                    m.set_test_delay(probe);
                    self.io.send(&m).await?;
                }
                Ok(HostEvent::Progress)
            }
            Some(message::Union::LoginRequest(request)) => {
                let action = self.auth.login(request);
                self.apply(action).await
            }
            Some(message::Union::Auth2fa(code)) => {
                let action = self.auth.second_factor(code);
                self.apply(action).await
            }
            _ if self.auth.state() != HostAuthState::Authorized => {
                self.io.send(&login_error("Connection not allowed")).await?;
                self.auth.close();
                Err(failure("Application payload before authentication"))
            }
            // No input/media/file/clipboard adapter exists yet. Do not report
            // success or call a legacy runtime simply because auth succeeded.
            _ => Ok(HostEvent::Unsupported),
        }
    }
    pub async fn close(&mut self) -> io::Result<()> {
        if self.auth.state() == HostAuthState::Closed {
            return Ok(());
        }
        self.auth.close();
        self.permissions = Permissions::default();
        let result = self.io.send(&close_message()).await;
        self.io.terminate();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{LoginCredential, ViewerEvent, ViewerSession, ViewerState};
    use crate::{
        authentication,
        conn_token::{ConnToken, PasswordSource, PasswordSourceKind, H1_BYTES},
        handshake::{self, ViewerIdentity},
    };
    use base::message_proto::{Hash, LoginRequest, LoginResponse, Message, PeerInfo, message};
    use hbb_common::{protobuf::Message as _, tcp::FramedStream};
    use std::time::Duration;

    /// How long the fixture's own end of the wire waits for one record.
    const LIMIT: Duration = Duration::from_secs(5);

    /// One record read from the fixture's end of the wire.
    async fn fixture_recv(wire: &mut FramedStream) -> Message {
        let bytes = tokio::time::timeout(LIMIT, wire.next())
            .await
            .expect("the fixture never waits past its own limit")
            .expect("the wire is still open")
            .expect("the record was read");
        Message::parse_from_bytes(&bytes).expect("the record is a message")
    }

    /// The challenge this fixture's peer sends, and the salt it names.
    const SALT: &str = "fixture-salt";
    const CHALLENGE: &str = "fixture-challenge";

    fn request(session_id: u64) -> LoginRequest {
        LoginRequest {
            username: "fixture-target".into(),
            my_id: "fixture-controller".into(),
            my_name: "fixture".into(),
            version: "1.4.9".into(),
            session_id,
            ..Default::default()
        }
    }

    /// A viewer session that has already read this peer's challenge, plus the
    /// fixture's own end of the same wire.
    async fn challenged() -> (ViewerSession, FramedStream) {
        let address = "127.0.0.1:1".parse().unwrap();
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let established = handshake::viewer(
            FramedStream::from(client, address),
            ViewerIdentity::LegacyUnverified,
            LIMIT,
        )
        .await
        .expect("the legacy handshake needs no peer record");
        let mut fixture = FramedStream::from(peer, address);
        assert!(fixture_recv(&mut fixture).await.union.is_none());
        let mut session = ViewerSession::from_established(established, LIMIT, LIMIT);
        let mut challenge = Message::new();
        challenge.set_hash(Hash {
            salt: SALT.into(),
            challenge: CHALLENGE.into(),
            ..Default::default()
        });
        fixture
            .send(&challenge)
            .await
            .expect("the challenge is written");
        assert!(matches!(session.recv().await, Ok(ViewerEvent::Challenge)));
        (session, fixture)
    }

    /// The record the official client sends for this h1: SHA256(h1 || challenge),
    /// computed by the same helper the host verifies with.
    fn official_response(h1: &[u8; H1_BYTES]) -> Vec<u8> {
        authentication::password_response(h1, CHALLENGE).to_vec()
    }

    fn credential(h1: &[u8; H1_BYTES], source: PasswordSource, session_id: u64) -> ConnToken {
        ConnToken::from_h1(h1.to_vec(), source, session_id).expect("a real h1 is a token")
    }

    /// The login the session wrote, as the fixture read it.
    async fn written_login(fixture: &mut FramedStream) -> LoginRequest {
        match fixture_recv(fixture).await.union {
            Some(message::Union::LoginRequest(request)) => request,
            other => panic!("the fixture expects the viewer's login, not {other:?}"),
        }
    }

    async fn send_response(fixture: &mut FramedStream, response: LoginResponse) {
        let mut message = Message::new();
        message.set_login_response(response);
        fixture
            .send(&message)
            .await
            .expect("the response is written");
    }

    fn error_response(error: &str) -> LoginResponse {
        let mut response = LoginResponse::new();
        response.set_error(error.to_owned());
        response
    }

    fn authorized_response() -> LoginResponse {
        let mut response = LoginResponse::new();
        response.set_peer_info(PeerInfo::new());
        response
    }

    /// A reconnect credential is challenged exactly once. The token's h1 is what
    /// SHA256(clear password || salt) produces, and the wire carries
    /// SHA256(h1 || challenge) — the same record a freshly typed password
    /// produces. Salting h1 a second time would be a different, unverifiable
    /// response, so that is what this refuses.
    #[tokio::test]
    async fn a_reconnect_credential_is_challenged_once() {
        let clear = b"fixture-password";
        let h1 = authentication::salted_password(clear, SALT);
        let (mut session, mut fixture) = challenged().await;
        session
            .login_with(
                request(7),
                LoginCredential::Reconnect(credential(&h1, PasswordSource::Undefined, 7)),
            )
            .await
            .expect("the reconnect login is written");
        let sent = written_login(&mut fixture).await;
        assert_eq!(sent.password, official_response(&h1));
        assert_eq!(sent.session_id, 7);
        let twice = authentication::salted_password(&h1, SALT);
        assert_ne!(
            sent.password,
            official_response(&twice),
            "the imported h1 is not salted a second time"
        );

        // The same clear password, typed instead of imported, is the same record.
        let (mut typed, mut typed_fixture) = challenged().await;
        typed
            .login_with(request(7), LoginCredential::Password(clear))
            .await
            .expect("the typed login is written");
        assert_eq!(written_login(&mut typed_fixture).await.password, sent.password);
    }

    /// The credential is exported only after the peer's own success, carrying the
    /// session id and provenance this attempt used, and only once.
    #[tokio::test]
    async fn a_credential_is_exported_only_after_the_peer_authorizes() {
        let h1 = authentication::salted_password(b"fixture-password", SALT);
        let (mut session, mut fixture) = challenged().await;
        session
            .login_with(
                request(9),
                LoginCredential::Reconnect(credential(
                    &h1,
                    PasswordSource::SharedAb("shared-fixture".into()),
                    9,
                )),
            )
            .await
            .expect("the reconnect login is written");
        assert_eq!(written_login(&mut fixture).await.password, official_response(&h1));
        assert_eq!(session.state(), ViewerState::AwaitLogin);
        assert!(
            session.take_reconnect_credential().is_none(),
            "a written login is not an authentication"
        );

        send_response(&mut fixture, authorized_response()).await;
        assert!(matches!(session.recv().await, Ok(ViewerEvent::Authorized(_))));
        let exported = session
            .take_reconnect_credential()
            .expect("the peer authorized this attempt");
        assert_eq!(exported.session_id(), 9);
        assert_eq!(exported.source_kind(), PasswordSourceKind::SharedAb);
        assert_eq!(exported.h1(), h1.as_slice());
        assert!(
            session.take_reconnect_credential().is_none(),
            "the credential is handed over once, not duplicated"
        );
    }

    /// The peer's verdict on the password itself leaves nothing to reconnect
    /// with, even if a later record authorizes the session.
    #[tokio::test]
    async fn a_password_refusal_leaves_no_credential_to_export() {
        let (mut session, mut fixture) = challenged().await;
        session
            .login_with(request(7), LoginCredential::Password(b"wrong-fixture"))
            .await
            .expect("the login is written");
        let _ = written_login(&mut fixture).await;
        send_response(
            &mut fixture,
            error_response(authentication::WRONG_PASSWORD),
        )
        .await;
        assert!(matches!(
            session.recv().await,
            Ok(ViewerEvent::LoginError(error)) if error == authentication::WRONG_PASSWORD
        ));
        send_response(&mut fixture, authorized_response()).await;
        assert!(matches!(session.recv().await, Ok(ViewerEvent::Authorized(_))));
        assert!(session.take_reconnect_credential().is_none());
    }

    /// A refusal of the second factor is not a refusal of the password: the
    /// material stays, because the peer had already accepted it.
    #[tokio::test]
    async fn a_second_factor_refusal_keeps_the_password_credential() {
        let clear = b"fixture-password";
        let h1 = authentication::salted_password(clear, SALT);
        let (mut session, mut fixture) = challenged().await;
        session
            .login_with(request(7), LoginCredential::Password(clear))
            .await
            .expect("the login is written");
        let _ = written_login(&mut fixture).await;
        send_response(
            &mut fixture,
            error_response(authentication::TWO_FACTOR_REQUIRED),
        )
        .await;
        assert!(matches!(
            session.recv().await,
            Ok(ViewerEvent::LoginError(error)) if error == authentication::TWO_FACTOR_REQUIRED
        ));
        send_response(&mut fixture, error_response("Wrong 2FA Code")).await;
        assert!(matches!(
            session.recv().await,
            Ok(ViewerEvent::LoginError(error)) if error == "Wrong 2FA Code"
        ));
        send_response(&mut fixture, authorized_response()).await;
        assert!(matches!(session.recv().await, Ok(ViewerEvent::Authorized(_))));
        let exported = session
            .take_reconnect_credential()
            .expect("the password was never refused");
        assert_eq!(exported.h1(), h1.as_slice());
        assert_eq!(exported.source_kind(), PasswordSourceKind::Undefined);
    }

    /// A typed answer replaces the imported provenance, as the official client
    /// does whenever the password came from the user.
    #[tokio::test]
    async fn a_typed_password_replaces_the_imported_source() {
        let imported = authentication::salted_password(b"shared-fixture", SALT);
        let (mut session, mut fixture) = challenged().await;
        session
            .login_with(
                request(7),
                LoginCredential::Reconnect(credential(
                    &imported,
                    PasswordSource::SharedAb("shared-fixture".into()),
                    7,
                )),
            )
            .await
            .expect("the imported login is written");
        let _ = written_login(&mut fixture).await;
        send_response(
            &mut fixture,
            error_response(authentication::WRONG_PASSWORD),
        )
        .await;
        assert!(matches!(session.recv().await, Ok(ViewerEvent::LoginError(_))));

        let typed = b"typed-fixture";
        session
            .login_with(request(7), LoginCredential::Password(typed))
            .await
            .expect("the typed retry travels on the same request");
        let retried = written_login(&mut fixture).await;
        assert_eq!(
            retried.password,
            official_response(&authentication::salted_password(typed, SALT))
        );
        send_response(&mut fixture, authorized_response()).await;
        assert!(matches!(session.recv().await, Ok(ViewerEvent::Authorized(_))));
        let exported = session
            .take_reconnect_credential()
            .expect("the typed password was accepted");
        assert_eq!(exported.source_kind(), PasswordSourceKind::Undefined);
        assert_eq!(
            exported.h1(),
            authentication::salted_password(typed, SALT).as_slice()
        );
    }

    /// A session that is no longer authenticated exports nothing: closing it
    /// scrubs what it held.
    #[tokio::test]
    async fn a_closed_session_exports_no_credential() {
        let (mut session, mut fixture) = challenged().await;
        session
            .login_with(request(7), LoginCredential::Password(b"fixture-password"))
            .await
            .expect("the login is written");
        let _ = written_login(&mut fixture).await;
        send_response(&mut fixture, authorized_response()).await;
        assert!(matches!(session.recv().await, Ok(ViewerEvent::Authorized(_))));
        session.close().await.expect("the close is written");
        assert_eq!(session.state(), ViewerState::Closed);
        assert!(session.take_reconnect_credential().is_none());
    }

    /// A token that names its session is that session's credential and no other's,
    /// and one that names none takes the caller's fresh nonzero id — the same rule
    /// the official reader applies, without pretending a zero id was usable.
    #[tokio::test]
    async fn a_token_session_id_must_match_unless_it_is_absent() {
        let h1 = authentication::salted_password(b"fixture-password", SALT);
        let (mut session, mut fixture) = challenged().await;
        assert!(
            session
                .login_with(
                    request(9),
                    LoginCredential::Reconnect(credential(&h1, PasswordSource::Undefined, 7)),
                )
                .await
                .is_err(),
            "a token from another session is not this one's credential"
        );
        assert!(
            session
                .login_with(
                    request(0),
                    LoginCredential::Reconnect(credential(&h1, PasswordSource::Undefined, 0)),
                )
                .await
                .is_err(),
            "a zero session id is not the fresh nonzero id the caller must supply"
        );
        assert_eq!(session.state(), ViewerState::AwaitLogin);

        session
            .login_with(
                request(9),
                LoginCredential::Reconnect(credential(&h1, PasswordSource::Undefined, 0)),
            )
            .await
            .expect("a token without a session id takes the caller's fresh one");
        assert_eq!(written_login(&mut fixture).await.session_id, 9);
    }

    /// The peer's second factor is answered on the one session that asked for
    /// it: a wrong code keeps that session and admits a retry, and only the
    /// peer's own `PeerInfo` ends the login.
    ///
    /// The wire is a real framed stream owned by both ends here, so the records
    /// asserted are the ones the session actually wrote — not a restatement of
    /// the message the test built.
    #[tokio::test]
    async fn a_wrong_second_factor_code_keeps_the_session_and_admits_a_retry() {
        let address = "127.0.0.1:1".parse().unwrap();
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let established = handshake::viewer(
            FramedStream::from(client, address),
            ViewerIdentity::LegacyUnverified,
            LIMIT,
        )
        .await
        .expect("the legacy handshake needs no peer record");
        let mut fixture = FramedStream::from(peer, address);
        // The viewer's own handshake record, before any authentication state.
        assert!(fixture_recv(&mut fixture).await.union.is_none());

        let mut session = ViewerSession::from_established(established, LIMIT, LIMIT);
        let mut challenge = Message::new();
        challenge.set_hash(Hash {
            salt: "fixture-salt".into(),
            challenge: "fixture-challenge".into(),
            ..Default::default()
        });
        fixture
            .send(&challenge)
            .await
            .expect("the challenge is written");
        assert!(matches!(session.recv().await, Ok(ViewerEvent::Challenge)));
        session
            .login(
                LoginRequest {
                    username: "fixture-target".into(),
                    my_id: "fixture-controller".into(),
                    my_name: "fixture".into(),
                    version: "1.4.9".into(),
                    session_id: 7,
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("the login is written");
        let Some(message::Union::LoginRequest(_)) = fixture_recv(&mut fixture).await.union else {
            panic!("the fixture expects the viewer's login")
        };

        // A code offered before the peer asks is not this peer's second factor:
        // the session refuses it and nothing reaches the wire.
        assert!(session.send_second_factor("111111".into()).await.is_err());

        let mut response = LoginResponse::new();
        response.set_error("2FA Required".into());
        let mut demand = Message::new();
        demand.set_login_response(response);
        fixture.send(&demand).await.expect("the demand is written");
        assert!(matches!(
            session.recv().await,
            Ok(ViewerEvent::LoginError(error)) if error == "2FA Required"
        ));
        assert_eq!(session.state(), ViewerState::Await2Fa);

        session
            .send_second_factor("222222".into())
            .await
            .expect("a code is written while the peer waits for one");
        let Some(message::Union::Auth2fa(factor)) = fixture_recv(&mut fixture).await.union else {
            panic!("the fixture expects the viewer's code")
        };
        assert_eq!(factor.code, "222222");
        assert!(
            factor.hwid.is_empty(),
            "no trusted-device enrollment is claimed"
        );

        // The peer refused that code: the same session is still waiting, and the
        // retry travels on it.
        let mut response = LoginResponse::new();
        response.set_error("Wrong 2FA Code".into());
        let mut wrong = Message::new();
        wrong.set_login_response(response);
        fixture.send(&wrong).await.expect("the refusal is written");
        assert!(matches!(
            session.recv().await,
            Ok(ViewerEvent::LoginError(error)) if error == "Wrong 2FA Code"
        ));
        assert_eq!(session.state(), ViewerState::Await2Fa);
        session
            .send_second_factor("333333".into())
            .await
            .expect("the retry is written on the same wait");
        let Some(message::Union::Auth2fa(factor)) = fixture_recv(&mut fixture).await.union else {
            panic!("the fixture expects the retry")
        };
        assert_eq!(factor.code, "333333");

        // Only the peer's own evidence authorizes the session.
        let mut response = LoginResponse::new();
        response.set_peer_info(PeerInfo::new());
        let mut success = Message::new();
        success.set_login_response(response);
        fixture
            .send(&success)
            .await
            .expect("the peer info is written");
        assert!(matches!(
            session.recv().await,
            Ok(ViewerEvent::Authorized(_))
        ));
        assert_eq!(session.state(), ViewerState::Active);
        // Past that step a code is refused rather than written.
        assert!(session.send_second_factor("444444".into()).await.is_err());
    }
}
