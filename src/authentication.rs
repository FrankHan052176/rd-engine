//! Pure authentication state. Local providers supply policy and credentials;
//! no Config, stable identity inferred from IP, or legacy session objects.
use base::message_proto::{
    Auth2FA, Hash, LoginRequest, PeerInfo, login_request, option_message::BoolOption,
};
use hbb_common::sodiumoxide::{crypto::hash::sha256, randombytes, utils};

pub const WRONG_PASSWORD: &str = "Wrong Password";
pub const TWO_FACTOR_REQUIRED: &str = "2FA Required";

pub fn salted_password(password: &[u8], salt: &str) -> [u8; 32] {
    let mut hash = sha256::State::new();
    hash.update(password);
    hash.update(salt.as_bytes());
    hash.finalize().0
}

pub fn password_response(h1: &[u8; 32], challenge: &str) -> [u8; 32] {
    let mut hash = sha256::State::new();
    hash.update(h1);
    hash.update(challenge.as_bytes());
    hash.finalize().0
}

/// Deliberately not Debug/Clone. Stored h1 values are password-equivalent.
pub struct Passwords {
    values: std::sync::Arc<PasswordValues>,
}
struct PasswordValues { values: Vec<[u8; 32]>, temporary: Option<usize> }
impl Passwords {
    pub fn from_salted(values: Vec<[u8; 32]>) -> Self {
        Self { values: std::sync::Arc::new(PasswordValues { values, temporary: None }) }
    }
    /// The checked host owner identifies its temporary verifier explicitly;
    /// permanent/preset matches must never count as temporary failures.
    pub(crate) fn from_host(temporary: Option<[u8; 32]>, permanent: Option<[u8; 32]>) -> Self {
        let mut values = Vec::with_capacity(usize::from(temporary.is_some()) + usize::from(permanent.is_some()));
        let temporary_index = temporary.map(|h1| { values.push(h1); 0 });
        if let Some(h1) = permanent { values.push(h1); }
        Self { values: std::sync::Arc::new(PasswordValues { values, temporary: temporary_index }) }
    }
    /// Shares the zeroizing verifier owner, never copies password-equivalent bytes.
    pub(crate) fn shared(&self) -> Self {
        Self { values: self.values.clone() }
    }
    fn verify(&self, hash: &Hash, response: &[u8]) -> (bool, Option<bool>) {
        if response.len() != 32 { return (false, self.values.temporary.map(|_| false)); }
        let mut valid = false;
        let mut temporary_match = false;
        for (index, value) in self.values.values.iter().enumerate() {
            let mut expected = password_response(value, &hash.challenge);
            let matched = utils::memcmp(&expected, response);
            valid |= matched;
            temporary_match |= self.values.temporary == Some(index) && matched;
            utils::memzero(&mut expected);
        }
        let temporary_outcome = if temporary_match { Some(true) }
            else if !valid && self.values.temporary.is_some() { Some(false) } else { None };
        (valid, temporary_outcome)
    }
}
impl Drop for PasswordValues {
    fn drop(&mut self) {
        for value in &mut self.values {
            utils::memzero(value);
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Permissions {
    pub keyboard: bool,
    pub clipboard: bool,
    pub audio: bool,
    pub file: bool,
}
impl Permissions {
    pub fn intersect(self, other: Self) -> Self {
        Self {
            keyboard: self.keyboard && other.keyboard,
            clipboard: self.clipboard && other.clipboard,
            audio: self.audio && other.audio,
            file: self.file && other.file,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryPolicy {
    PasswordOnly,
    ClickOnly,
    PasswordOrClick,
}

/// A trusted local UI/provider must explicitly approve the latched request.
/// Pending is not success. This API is never populated from a wire bool.
pub trait ApprovalProvider: Send {
    fn check(&mut self, request: &LoginRequest) -> Approval;
}
pub enum Approval {
    Pending,
    Denied,
    Approved(Permissions),
}
pub struct PendingApproval;
impl ApprovalProvider for PendingApproval {
    fn check(&mut self, _: &LoginRequest) -> Approval {
        Approval::Pending
    }
}

/// The engine does not implement TOTP or trusted-device storage. A provider may
/// verify a code, but incoming hwid alone NEVER bypasses this state.
pub trait SecondFactorProvider: Send {
    fn required(&self) -> bool;
    fn verify(&mut self, response: &Auth2FA) -> FactorResult;
}
pub enum FactorResult {
    Verified,
    Wrong,
    Unsupported,
}
pub struct NoSecondFactor;
impl SecondFactorProvider for NoSecondFactor {
    fn required(&self) -> bool {
        false
    }
    fn verify(&mut self, _: &Auth2FA) -> FactorResult {
        FactorResult::Unsupported
    }
}
pub struct UnsupportedSecondFactor;
impl SecondFactorProvider for UnsupportedSecondFactor {
    fn required(&self) -> bool {
        true
    }
    fn verify(&mut self, _: &Auth2FA) -> FactorResult {
        FactorResult::Unsupported
    }
}

/// Shared rate/whitelist policy belongs outside one connection so reconnecting
/// cannot reset it. Implementations must not log the LoginRequest credentials.
pub trait AttemptPolicy: Send {
    fn allow(&mut self, second_factor: bool) -> Result<(), &'static str>;
    fn outcome(&mut self, second_factor: bool, accepted: bool);
    /// Only a real enabled temporary verifier match, or a complete primary
    /// mismatch after all enabled permanent/preset verifiers failed, reaches this.
    fn temporary_password_outcome(&mut self, _matched: bool) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAuthState {
    AwaitLogin,
    AwaitApproval,
    Await2Fa,
    Authorized,
    Closed,
}
pub enum AuthAction {
    Error {
        message: &'static str,
        terminal: bool,
    },
    PendingApproval,
    Authorized {
        info: PeerInfo,
        permissions: Permissions,
    },
    Ignored,
}

pub struct HostAuthConfig {
    /// Accepted target IDs/direct authorities, supplied by the listener/dialer.
    /// This is routing validation only, not viewer identity verification.
    pub accepted_targets: Vec<String>,
    pub salt: String,
    pub passwords: Passwords,
    pub policy: PrimaryPolicy,
    pub ceiling: Permissions,
    pub password_permissions: Permissions,
    /// Identity metadata and capabilities supplied by the local provider.
    /// `PeerInfo::default()` leaves encoding/displays absent; authentication
    /// never synthesizes VP9, H265, Main10, HDR, or a software-copy fallback.
    /// Only advertise codec/display capabilities backed by the eventual media
    /// provider's actual zero-copy path. A codec flag is not a bit-depth claim.
    pub peer_info: PeerInfo,
    pub approval: Box<dyn ApprovalProvider>,
    pub second_factor: Box<dyn SecondFactorProvider>,
    pub attempts: Box<dyn AttemptPolicy>,
}

pub struct HostAuthentication {
    config: HostAuthConfig,
    hash: Hash,
    state: HostAuthState,
    request: Option<LoginRequest>,
    grant: Permissions,
}

impl HostAuthentication {
    pub fn new(config: HostAuthConfig) -> Result<Self, &'static str> {
        hbb_common::sodiumoxide::init().map_err(|_| "Crypto initialization failed")?;
        if config.accepted_targets.is_empty() || config.salt.is_empty() {
            return Err("Missing explicit authentication configuration");
        }
        const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let challenge: String = (0..6)
            .map(|_| {
                ALPHABET[randombytes::randombytes_uniform(ALPHABET.len() as u32) as usize] as char
            })
            .collect();
        let hash = Hash {
            salt: config.salt.clone(),
            challenge,
            ..Default::default()
        };
        Ok(Self {
            config,
            hash,
            state: HostAuthState::AwaitLogin,
            request: None,
            grant: Permissions::default(),
        })
    }
    pub fn challenge(&self) -> &Hash {
        &self.hash
    }
    pub fn state(&self) -> HostAuthState {
        self.state
    }
    pub fn request(&self) -> Option<&LoginRequest> {
        self.request.as_ref()
    }
    pub fn close(&mut self) {
        self.state = HostAuthState::Closed;
        self.grant = Permissions::default();
        self.request = None;
    }

    fn error(&mut self, message: &'static str, terminal: bool) -> AuthAction {
        if terminal {
            self.close();
        }
        AuthAction::Error { message, terminal }
    }

    pub fn login(&mut self, mut request: LoginRequest) -> AuthAction {
        if self.state == HostAuthState::Closed {
            return AuthAction::Ignored;
        }
        if self.state == HostAuthState::Authorized {
            return AuthAction::Ignored;
        }
        if !self.config.accepted_targets.contains(&request.username) {
            return self.error("Offline", true);
        }
        // This slice is remote-desktop only. Never silently treat another role
        // as a desktop login, even with a correct password.
        if let Some(role) = &request.union {
            let error = match role {
                login_request::Union::FileTransfer(_) => "No permission of file transfer",
                login_request::Union::PortForward(_) => "No permission of IP tunneling",
                login_request::Union::ViewCamera(_) => "No permission of viewing camera",
                login_request::Union::Terminal(_) => "No permission of terminal",
                _ => "Unsupported session role",
            };
            return self.error(error, true);
        }
        if !request.os_login.username.is_empty() || !request.os_login.password.is_empty() {
            return self.error("OS login is unsupported for this session", true);
        }
        // Freeze every material claim shown to the local approver. A retry may
        // change only its challenge response, never identity, options or role.
        let response = std::mem::take(&mut request.password);
        request.os_login = Default::default();
        if self.request.as_ref().is_some_and(|first| first != &request) {
            return self.error("Connection request changed", true);
        }
        if request.my_id.is_empty() {
            return self.error("Connection not allowed", true);
        }
        self.state = HostAuthState::AwaitLogin;
        let nonempty = !response.is_empty();
        let valid = if self.config.policy != PrimaryPolicy::ClickOnly && nonempty {
            if let Err(error) = self.config.attempts.allow(false) {
                return self.error(error, false);
            }
            let (valid, temporary) = self.config.passwords.verify(&self.hash, &response);
            self.config.attempts.outcome(false, valid);
            if let Some(matched) = temporary { self.config.attempts.temporary_password_outcome(matched); }
            valid
        } else {
            false
        };
        self.request = Some(request);
        if valid {
            self.grant = self
                .config
                .password_permissions
                .intersect(self.config.ceiling);
            return self.after_primary();
        }
        if self.config.policy == PrimaryPolicy::PasswordOnly {
            return self.error(
                if nonempty {
                    WRONG_PASSWORD
                } else {
                    "Empty Password"
                },
                false,
            );
        }
        self.state = HostAuthState::AwaitApproval;
        match self.poll_approval() {
            AuthAction::PendingApproval
                if self.config.policy == PrimaryPolicy::PasswordOrClick && nonempty =>
            {
                self.error(WRONG_PASSWORD, false)
            }
            other => other,
        }
    }

    pub fn poll_approval(&mut self) -> AuthAction {
        if self.state != HostAuthState::AwaitApproval {
            return AuthAction::Ignored;
        }
        let Some(request) = self.request.as_ref() else {
            return AuthAction::Ignored;
        };
        match self.config.approval.check(request) {
            Approval::Pending => AuthAction::PendingApproval,
            Approval::Denied => self.error("Connection not allowed", true),
            Approval::Approved(grant) => {
                self.grant = grant.intersect(self.config.ceiling);
                self.after_primary()
            }
        }
    }

    fn after_primary(&mut self) -> AuthAction {
        if self.config.second_factor.required() {
            self.state = HostAuthState::Await2Fa;
            return self.error(TWO_FACTOR_REQUIRED, false);
        }
        self.authorize()
    }

    pub fn second_factor(&mut self, code: Auth2FA) -> AuthAction {
        if self.state != HostAuthState::Await2Fa {
            return AuthAction::Ignored;
        }
        if let Err(error) = self.config.attempts.allow(true) {
            return self.error(error, false);
        }
        match self.config.second_factor.verify(&code) {
            FactorResult::Verified => {
                self.config.attempts.outcome(true, true);
                self.authorize()
            }
            FactorResult::Wrong => {
                self.config.attempts.outcome(true, false);
                self.error("Wrong 2FA Code", false)
            }
            FactorResult::Unsupported => self.error("2FA verification unsupported", false),
        }
    }

    fn authorize(&mut self) -> AuthAction {
        // Keyboard is the local permission, not the viewer's mutable disable
        // preference. The peer's original reader combines both admission states.
        // Other unavailable adapters retain their existing preference ceiling.
        if let Some(options) = self.request.as_ref().and_then(|v| v.option.as_ref()) {
            if options.disable_clipboard.enum_value() == Ok(BoolOption::Yes) {
                self.grant.clipboard = false;
            }
            if options.disable_audio.enum_value() == Ok(BoolOption::Yes) {
                self.grant.audio = false;
            }
            if options.enable_file_transfer.enum_value() == Ok(BoolOption::No) {
                self.grant.file = false;
            }
        }
        self.state = HostAuthState::Authorized;
        AuthAction::Authorized {
            info: self.config.peer_info.clone(),
            permissions: self.grant,
        }
    }
}
