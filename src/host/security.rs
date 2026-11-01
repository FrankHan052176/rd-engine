//! The host's own durable security record: the permanent password verifier, the
//! verification method, TOTP enrolment and trusted devices.
//!
//! One app-private root owns one record. A missing record is the initial state
//! (no permanent password, no second factor, no trusted device); a damaged
//! record or a failed write is an error and the last valid state stays, so a
//! decode failure can never silently reset authentication policy.
//!
//! The permanent password is persisted only as
//! [`salted_password`](crate::authentication::salted_password) of the plaintext
//! with this record's stable salt - the same verifier the host's
//! challenge/response check consumes - so no plaintext password is stored,
//! returned, logged or repeated in an error message.
//!
//! TOTP enrolment keeps a freshly generated secret in memory until one six-digit
//! code proves it; only then does a single atomic write publish it as enabled.
//! A trusted device is recorded only from a code that just verified, and only
//! with the explicit non-empty `hwid` that code arrived with. The hwid is never
//! consulted before the primary password/approval step: [`HostSecondFactor`] is
//! asked only while `HostAuthentication` is already at `Await2Fa`.
use crate::authentication::{FactorResult, SecondFactorProvider, salted_password};
use base::message_proto::Auth2FA;
use hbb_common::{
    get_time,
    serde_json::{Value, json},
    sodiumoxide::{randombytes, utils},
};
use std::{
    fmt, fs, io,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

/// The one file this owner writes, directly under the app-private root it was
/// given. Nothing else in the engine reads or writes it.
pub const RECORD_FILE: &str = "host-security.json";
const RECORD_VERSION: u64 = 1;
/// One verifier, one TOTP seed and a bounded device list; a larger file is not a
/// record this owner wrote.
const MAX_RECORD_BYTES: u64 = 64 * 1024;
/// The bound the ArkTS password field reports as `maxPasswordLength`.
pub const MAX_PERMANENT_PASSWORD_CHARS: usize = 128;
/// 16 random bytes written as 32 hex characters, the length the official host
/// salt uses.
const SALT_BYTES: usize = 16;
/// RFC 4226 asks for at least 128 bits; 160 is what an authenticator app expects.
const TOTP_SECRET_BYTES: usize = 20;
const TOTP_DIGITS: u32 = 6;
const TOTP_STEP_SECONDS: u64 = 30;
/// One step either side: the window the official host verifies with.
const TOTP_WINDOW: u64 = 1;
const TOTP_ISSUER: &str = "RustDesk";
const TOTP_LABEL: &str = "Connection";
/// The official record's validity (`TrustedDevice::outdate`): 90 days.
const TRUSTED_DEVICE_LIFETIME_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const MAX_TRUSTED_DEVICES: usize = 64;
/// The largest `hwid` value this owner stores or accepts.
pub const MAX_HWID_BYTES: usize = 256;
/// The one host setting this engine acts on, under the name the ArkTS client
/// sends.
const SETTING_TRUSTED_DEVICES: &str = "trustedDevicesEnabled";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The primary verifier set this host accepts. The strings are the ones the
/// official option stores and the ArkTS client sends, so no layer invents a
/// fourth mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationMethod {
    Temporary,
    Permanent,
    Both,
}

impl VerificationMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Temporary => "use-temporary-password",
            Self::Permanent => "use-permanent-password",
            Self::Both => "use-both-passwords",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "use-temporary-password" => Some(Self::Temporary),
            "use-permanent-password" => Some(Self::Permanent),
            "use-both-passwords" => Some(Self::Both),
            _ => None,
        }
    }

    /// The temporary password is part of the accepted set.
    pub fn accepts_temporary(self) -> bool {
        self != Self::Permanent
    }

    /// The permanent verifier is part of the accepted set. `Both` with no stored
    /// verifier therefore accepts the temporary password only, which is what the
    /// official host does as well.
    pub fn accepts_permanent(self) -> bool {
        self != Self::Temporary
    }
}

#[derive(Debug)]
pub enum SecurityError {
    /// The private root or the record could not be used.
    Storage(io::Error),
    /// A record exists but is not one this owner wrote. It is never treated as
    /// the initial state.
    Corrupt(&'static str),
    /// A caller-supplied value was refused; nothing was persisted.
    Invalid(&'static str),
    TwoFactorAlreadyEnabled,
    NoSetupInProgress,
    WrongCode,
    /// The key is not one this engine acts on.
    UnsupportedSetting,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "host security storage failed: {error}"),
            Self::Corrupt(reason) => write!(f, "host security record is unusable: {reason}"),
            Self::Invalid(reason) => write!(f, "{reason}"),
            Self::TwoFactorAlreadyEnabled => {
                write!(f, "two-factor authentication is already enabled")
            }
            Self::NoSetupInProgress => write!(f, "no two-factor enrolment is in progress"),
            Self::WrongCode => write!(f, "wrong 2FA code"),
            Self::UnsupportedSetting => write!(f, "unsupported host setting"),
        }
    }
}

impl std::error::Error for SecurityError {}

impl From<io::Error> for SecurityError {
    fn from(error: io::Error) -> Self {
        Self::Storage(error)
    }
}

/// One trusted device. Identity is the `hwid` bytes alone; `id`/`name`/`platform`
/// are the peer's own claims for display and are never part of the decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedDevice {
    pub hwid: Vec<u8>,
    /// Registration time in milliseconds, the unit `hbb_common::get_time` uses.
    pub time: i64,
    pub id: String,
    pub name: String,
    pub platform: String,
}

impl TrustedDevice {
    /// The official record's validity: 90 days from registration.
    pub fn outdated(&self, now: i64) -> bool {
        self.time.saturating_add(TRUSTED_DEVICE_LIFETIME_MS) < now
    }
}

/// An enabled TOTP secret. Deliberately not `Debug`; zeroed on drop.
#[derive(Clone)]
struct Totp {
    secret: Vec<u8>,
    created_at: i64,
}

impl Drop for Totp {
    fn drop(&mut self) {
        utils::memzero(&mut self.secret);
    }
}

/// The whole durable record. Holds a password-equivalent verifier and the TOTP
/// seed, so it deliberately implements neither `Debug` nor a public `Clone`.
#[derive(Clone)]
struct Stored {
    salt: String,
    permanent: Option<[u8; 32]>,
    method: VerificationMethod,
    totp: Option<Totp>,
    trusted_devices_enabled: bool,
    devices: Vec<TrustedDevice>,
}

impl Stored {
    fn initial(salt: String) -> Self {
        Self {
            salt,
            permanent: None,
            method: VerificationMethod::Both,
            totp: None,
            // `enable-trusted-devices` is an `enable-` option: `option2bool`
            // reads an unset value as enabled and the client's own 2FA state
            // defaults it on. The list starts empty, so no device can be skipped
            // until one is enrolled by a verified code.
            trusted_devices_enabled: true,
            devices: Vec::new(),
        }
    }
}

impl Drop for Stored {
    fn drop(&mut self) {
        if let Some(verifier) = self.permanent.as_mut() {
            utils::memzero(verifier);
        }
    }
}

/// What the ArkTS 2FA panel is allowed to know. The secret and the pending
/// enrolment URI are not part of it.
#[derive(Clone, Debug)]
pub struct TwoFactorState {
    pub enabled: bool,
    pub setup_pending: bool,
    pub trusted_devices_enabled: bool,
    /// Live records only: an expired device is neither listed nor trusted.
    pub trusted_devices: Vec<TrustedDevice>,
    /// Why the last trusted-device registration could not be persisted. The
    /// verification it belonged to still succeeded; the device was not recorded.
    pub registration_error: Option<String>,
}

/// The host's durable security owner. One per app-private root.
pub struct HostSecurity {
    path: PathBuf,
    state: Mutex<Stored>,
    /// A `begin_two_factor` secret that is not enabled until a code proves it.
    /// In memory only: an unfinished enrolment does not survive the process.
    pending: Mutex<Option<Totp>>,
    registration_error: Mutex<Option<String>>,
}

impl HostSecurity {
    /// Opens the record under this app-private root. A missing file is the
    /// initial state and writes nothing; an unreadable or malformed file is an
    /// error, never a reset.
    pub fn open(root: impl Into<PathBuf>) -> Result<Arc<Self>, SecurityError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(SecurityError::Corrupt("the host security root is empty"));
        }
        let path = root.join(RECORD_FILE);
        let state = match read_record(&path)? {
            Some(state) => state,
            None => Stored::initial(random_hex(SALT_BYTES)),
        };
        Ok(Arc::new(Self {
            path,
            state: Mutex::new(state),
            pending: Mutex::new(None),
            registration_error: Mutex::new(None),
        }))
    }

    /// The stable salt every primary verifier (temporary and permanent) is
    /// derived with, because `HostAuthConfig` publishes exactly one salt per
    /// connection.
    pub fn salt(&self) -> String {
        lock(&self.state).salt.clone()
    }

    /// The verifier a plaintext password must hash to for this host: the same
    /// function, and the same salt, the host owner persists.
    pub fn verifier(&self, plaintext: &[u8]) -> [u8; 32] {
        let salt = self.salt();
        salted_password(plaintext, &salt)
    }

    /// Whether the run's temporary verifier belongs in the accepted set.
    pub fn accepts_temporary_password(&self) -> bool {
        lock(&self.state).method.accepts_temporary()
    }

    /// The stored permanent verifier, and only while the method accepts it.
    pub fn permanent_verifier(&self) -> Option<[u8; 32]> {
        let state = lock(&self.state);
        if !state.method.accepts_permanent() {
            return None;
        }
        state.permanent
    }

    pub fn verification_method(&self) -> VerificationMethod {
        lock(&self.state).method
    }

    pub fn permanent_password_set(&self) -> bool {
        lock(&self.state).permanent.is_some()
    }

    pub fn two_factor_enabled(&self) -> bool {
        lock(&self.state).totp.is_some()
    }

    pub fn trusted_devices_enabled(&self) -> bool {
        lock(&self.state).trusted_devices_enabled
    }

    /// Stores the permanent password as a salted verifier, or clears it. The
    /// plaintext is not kept anywhere.
    pub fn set_permanent_password(&self, password: &str) -> Result<(), SecurityError> {
        if password.chars().count() > MAX_PERMANENT_PASSWORD_CHARS {
            return Err(SecurityError::Invalid(
                "the permanent password is longer than this host accepts",
            ));
        }
        let mut current = lock(&self.state);
        let mut next = current.clone();
        if password.is_empty() {
            // Revocation: the verifier is gone, and a method that only accepted
            // it falls back to `both`, which then accepts the temporary password
            // alone. Nothing else about the record changes.
            next.permanent = None;
            if next.method == VerificationMethod::Permanent {
                next.method = VerificationMethod::Both;
            }
        } else {
            next.permanent = Some(salted_password(password.as_bytes(), &next.salt));
        }
        commit(&self.path, &mut current, next)
    }

    /// Selects which verifiers the primary password check accepts.
    pub fn set_verification_method(&self, method: &str) -> Result<(), SecurityError> {
        let method = VerificationMethod::parse(method)
            .ok_or(SecurityError::Invalid("unknown verification method"))?;
        let mut current = lock(&self.state);
        if method == VerificationMethod::Permanent && current.permanent.is_none() {
            return Err(SecurityError::Invalid(
                "a permanent password must be set before it can be the only method",
            ));
        }
        let mut next = current.clone();
        next.method = method;
        commit(&self.path, &mut current, next)
    }

    /// The settings this engine really acts on. An unhandled key is refused
    /// instead of reported as saved.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<bool, SecurityError> {
        if key != SETTING_TRUSTED_DEVICES {
            return Err(SecurityError::UnsupportedSetting);
        }
        let enabled = match value.trim() {
            "true" | "Y" | "1" => true,
            "false" | "N" | "0" => false,
            _ => return Err(SecurityError::UnsupportedSetting),
        };
        let mut current = lock(&self.state);
        let mut next = current.clone();
        next.trusted_devices_enabled = enabled;
        commit(&self.path, &mut current, next)?;
        Ok(enabled)
    }

    /// Generates a fresh secret and the otpauth URI that enrols it. The returned
    /// URI carries the secret once, to the operator who requested it; nothing is
    /// enabled and nothing is written until a code proves the secret.
    pub fn begin_two_factor(&self, account: &str) -> Result<String, SecurityError> {
        if account.trim().is_empty() {
            return Err(SecurityError::Invalid(
                "the two-factor account name is empty",
            ));
        }
        if self.two_factor_enabled() {
            return Err(SecurityError::TwoFactorAlreadyEnabled);
        }
        let secret = randombytes::randombytes(TOTP_SECRET_BYTES);
        let uri = otpauth_uri(&secret, account.trim());
        *lock(&self.pending) = Some(Totp {
            secret,
            created_at: get_time(),
        });
        Ok(uri)
    }

    /// Enables the second factor only after a six-digit code proves the pending
    /// secret; the secret and `enabled` are published by one atomic write.
    pub fn verify_two_factor(&self, code: &str) -> Result<(), SecurityError> {
        let code = code.trim();
        let guard = lock(&self.pending);
        let Some(pending) = guard.as_ref() else {
            return Err(SecurityError::NoSetupInProgress);
        };
        if !totp_matches(&pending.secret, code, get_time()) {
            return Err(SecurityError::WrongCode);
        }
        let mut current = lock(&self.state);
        let mut next = current.clone();
        next.totp = Some(Totp {
            secret: pending.secret.clone(),
            created_at: pending.created_at,
        });
        commit(&self.path, &mut current, next)?;
        drop(current);
        // Release the enrolment guard before clearing the slot it guards.
        drop(guard);
        *lock(&self.pending) = None;
        Ok(())
    }

    /// Disables the second factor durably. The trusted devices enrolled under it
    /// are revoked in the same write: a record must not survive into a later
    /// enrolment that never saw the code it was trusted from.
    pub fn disable_two_factor(&self) -> Result<(), SecurityError> {
        let mut pending = lock(&self.pending);
        let mut current = lock(&self.state);
        if current.totp.is_none() && current.devices.is_empty() {
            *pending = None;
            return Ok(());
        }
        let mut next = current.clone();
        next.totp = None;
        next.devices.clear();
        commit(&self.path, &mut current, next)?;
        *pending = None;
        Ok(())
    }

    /// What the operator may see: no secret, no pending URI, live devices only.
    pub fn two_factor_state(&self) -> TwoFactorState {
        let setup_pending = lock(&self.pending).is_some();
        let state = lock(&self.state);
        let now = get_time();
        TwoFactorState {
            enabled: state.totp.is_some(),
            setup_pending,
            trusted_devices_enabled: state.trusted_devices_enabled,
            trusted_devices: live_devices(&state.devices, now),
            registration_error: lock(&self.registration_error).clone(),
        }
    }

    /// Revokes the named devices. Nothing else in the list changes.
    pub fn remove_trusted_devices(&self, hwids: &[Vec<u8>]) -> Result<(), SecurityError> {
        if hwids.is_empty() || hwids.iter().any(Vec::is_empty) {
            return Err(SecurityError::Invalid("no trusted device was named"));
        }
        let mut current = lock(&self.state);
        let mut next = current.clone();
        next.devices
            .retain(|device| !hwids.iter().any(|hwid| hwid == &device.hwid));
        commit(&self.path, &mut current, next)
    }

    pub fn clear_trusted_devices(&self) -> Result<(), SecurityError> {
        let mut current = lock(&self.state);
        let mut next = current.clone();
        next.devices.clear();
        commit(&self.path, &mut current, next)
    }

    /// The Host's second factor. `response.hwid` is read only here, after
    /// `HostAuthentication` already accepted the primary password or a local
    /// approval, so an incoming hwid never bypasses primary authentication; with
    /// the second factor disabled this returns `Unsupported` and no device is
    /// consulted at all.
    pub fn verify_second_factor(&self, response: &Auth2FA) -> FactorResult {
        let code = response.code.trim();
        let hwid = response.hwid.as_ref();
        let state = lock(&self.state);
        let Some(totp) = state.totp.as_ref() else {
            return FactorResult::Unsupported;
        };
        let now = get_time();
        let enroll = state.trusted_devices_enabled;
        let trusted = enroll
            && !hwid.is_empty()
            && state
                .devices
                .iter()
                .any(|device| device.hwid == hwid && !device.outdated(now));
        if code.is_empty() {
            // A recorded device presenting its own hwid is the official skip-2FA
            // path; without a code and without a match there is nothing to verify.
            return if trusted {
                FactorResult::Verified
            } else {
                FactorResult::Wrong
            };
        }
        if !totp_matches(&totp.secret, code, now) {
            return FactorResult::Wrong;
        }
        drop(state);
        if enroll && !hwid.is_empty() {
            // Only a code that just verified may enroll, and only the explicit
            // non-empty hwid it arrived with. A failed write is reported here
            // instead of being reported with the authentication answer, which
            // stays true: the code did verify.
            match self.record_trusted_device(hwid) {
                Ok(()) => *lock(&self.registration_error) = None,
                Err(error) => *lock(&self.registration_error) = Some(error.to_string()),
            }
        }
        FactorResult::Verified
    }

    fn record_trusted_device(&self, hwid: &[u8]) -> Result<(), SecurityError> {
        if hwid.is_empty() || hwid.len() > MAX_HWID_BYTES {
            return Err(SecurityError::Invalid("the peer hwid is not storable"));
        }
        let mut current = lock(&self.state);
        if !current.trusted_devices_enabled {
            return Ok(());
        }
        let now = get_time();
        let mut next = current.clone();
        next.devices
            .retain(|device| device.hwid != hwid && !device.outdated(now));
        if next.devices.len() >= MAX_TRUSTED_DEVICES {
            return Err(SecurityError::Invalid("the trusted-device list is full"));
        }
        next.devices.push(TrustedDevice {
            hwid: hwid.to_vec(),
            time: now,
            // The peer's own display claims. They are not authentication
            // evidence, and this provider is not handed the login request.
            id: String::new(),
            name: String::new(),
            platform: String::new(),
        });
        commit(&self.path, &mut current, next)
    }
}

/// The real second factor the host authenticates with, in place of
/// `NoSecondFactor`.
pub struct HostSecondFactor {
    security: Arc<HostSecurity>,
}

impl HostSecondFactor {
    pub fn new(security: Arc<HostSecurity>) -> Self {
        Self { security }
    }
}

impl SecondFactorProvider for HostSecondFactor {
    fn required(&self) -> bool {
        self.security.two_factor_enabled()
    }

    fn verify(&mut self, response: &Auth2FA) -> FactorResult {
        self.security.verify_second_factor(response)
    }
}

fn live_devices(devices: &[TrustedDevice], now: i64) -> Vec<TrustedDevice> {
    devices
        .iter()
        .filter(|device| !device.outdated(now))
        .cloned()
        .collect()
}

/// Writes the new record, and only then publishes it. A failed write leaves the
/// previous state in force.
fn commit(
    path: &Path,
    current: &mut MutexGuard<'_, Stored>,
    next: Stored,
) -> Result<(), SecurityError> {
    write_record(path, &next)?;
    *current = next;
    Ok(())
}

fn encode(state: &Stored) -> Value {
    json!({
        "version": RECORD_VERSION,
        "salt": state.salt,
        "permanent": state.permanent.map(|verifier| hex(&verifier)),
        "method": state.method.as_str(),
        "totp": state.totp.as_ref().map(|totp| json!({
            "secret": hex(&totp.secret),
            "created_at": totp.created_at,
        })),
        "trusted_devices_enabled": state.trusted_devices_enabled,
        "trusted_devices": state.devices.iter().map(|device| json!({
            "hwid": hex(&device.hwid),
            "time": device.time,
            "id": device.id,
            "name": device.name,
            "platform": device.platform,
        })).collect::<Vec<_>>(),
    })
}

fn decode(value: &Value) -> Result<Stored, SecurityError> {
    let object = value
        .as_object()
        .ok_or(SecurityError::Corrupt("it is not a JSON object"))?;
    if object.get("version").and_then(Value::as_u64) != Some(RECORD_VERSION) {
        return Err(SecurityError::Corrupt("it has an unknown version"));
    }
    let salt = object
        .get("salt")
        .and_then(Value::as_str)
        .ok_or(SecurityError::Corrupt("it has no salt"))?;
    if salt.len() != SALT_BYTES * 2 || unhex(salt).is_none() {
        return Err(SecurityError::Corrupt("its salt is not a hex value"));
    }
    let permanent = match object.get("permanent") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let bytes = value
                .as_str()
                .and_then(unhex)
                .ok_or(SecurityError::Corrupt("its permanent verifier is unreadable"))?;
            Some(<[u8; 32]>::try_from(bytes).map_err(|_| {
                SecurityError::Corrupt("its permanent verifier is not 32 bytes")
            })?)
        }
    };
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .and_then(VerificationMethod::parse)
        .ok_or(SecurityError::Corrupt("it names no known verification method"))?;
    if method == VerificationMethod::Permanent && permanent.is_none() {
        return Err(SecurityError::Corrupt(
            "it requires a permanent password it does not hold",
        ));
    }
    let totp = match object.get("totp") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let secret = value
                .get("secret")
                .and_then(Value::as_str)
                .and_then(unhex)
                .ok_or(SecurityError::Corrupt("its TOTP secret is unreadable"))?;
            if secret.len() != TOTP_SECRET_BYTES {
                return Err(SecurityError::Corrupt("its TOTP secret is not 20 bytes"));
            }
            let created_at = value
                .get("created_at")
                .and_then(Value::as_i64)
                .ok_or(SecurityError::Corrupt("its TOTP enrolment has no time"))?;
            Some(Totp {
                secret,
                created_at,
            })
        }
    };
    let trusted_devices_enabled = object
        .get("trusted_devices_enabled")
        .and_then(Value::as_bool)
        .ok_or(SecurityError::Corrupt("it has no trusted-device policy"))?;
    let entries = object
        .get("trusted_devices")
        .and_then(Value::as_array)
        .ok_or(SecurityError::Corrupt("its trusted-device list is not a list"))?;
    if entries.len() > MAX_TRUSTED_DEVICES {
        return Err(SecurityError::Corrupt("its trusted-device list is too long"));
    }
    let mut devices = Vec::with_capacity(entries.len());
    for entry in entries {
        let hwid = entry
            .get("hwid")
            .and_then(Value::as_str)
            .and_then(unhex)
            .ok_or(SecurityError::Corrupt("a trusted device has no hwid"))?;
        if hwid.is_empty() || hwid.len() > MAX_HWID_BYTES {
            return Err(SecurityError::Corrupt(
                "a trusted device hwid is out of bounds",
            ));
        }
        let time = entry
            .get("time")
            .and_then(Value::as_i64)
            .ok_or(SecurityError::Corrupt("a trusted device has no time"))?;
        let text = |name: &str| -> Result<String, SecurityError> {
            entry
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(SecurityError::Corrupt(
                    "a trusted device claim is unreadable",
                ))
        };
        devices.push(TrustedDevice {
            hwid,
            time,
            id: text("id")?,
            name: text("name")?,
            platform: text("platform")?,
        });
    }
    Ok(Stored {
        salt: salt.to_owned(),
        permanent,
        method,
        totp,
        trusted_devices_enabled,
        devices,
    })
}

fn read_record(path: &Path) -> Result<Option<Stored>, SecurityError> {
    let Some(mut file) = open_existing(path)? else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_RECORD_BYTES {
        return Err(SecurityError::Corrupt("it is not a plausible record file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { hbb_common::libc::geteuid() } || metadata.mode() & 0o077 != 0
        {
            return Err(SecurityError::Corrupt("it is not private to the current user"));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(SecurityError::Corrupt("it grew past this owner's bound"));
    }
    let value: Value = hbb_common::serde_json::from_slice(&bytes)
        .map_err(|_| SecurityError::Corrupt("it is not valid JSON"))?;
    decode(&value).map(Some)
}

fn open_existing(path: &Path) -> Result<Option<fs::File>, SecurityError> {
    // A symlink is never this owner's record, and the private root is the only
    // place it is looked for.
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(SecurityError::Corrupt("it is not a regular file"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SecurityError::Storage(error)),
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    secure_open(&mut options);
    match options.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SecurityError::Storage(error)),
    }
}

/// A complete record is flushed to a private staging file in the same directory
/// and then renamed over the live one, so a reader never sees half a record and a
/// failed write leaves the previous record intact.
fn write_record(path: &Path, state: &Stored) -> Result<(), SecurityError> {
    let directory = path
        .parent()
        .ok_or(SecurityError::Invalid("the host security record has no directory"))?;
    fs::create_dir_all(directory)?;
    let bytes = hbb_common::serde_json::to_vec(&encode(state))
        .map_err(|_| SecurityError::Invalid("the host security record cannot be encoded"))?;
    let staging = directory.join(format!(".{RECORD_FILE}.{}.pending", random_hex(8)));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    secure_open(&mut options);
    let mut file = options.open(&staging)?;
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&staging);
        return Err(SecurityError::Storage(error));
    }
    if let Err(error) = replace_file(&staging, path) {
        let _ = fs::remove_file(&staging);
        return Err(SecurityError::Storage(error));
    }
    // Durability of the rename itself. A failure here cannot undo the published
    // record, so it is not reported as a failed write.
    #[cfg(not(windows))]
    if let Ok(directory) = fs::File::open(directory) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn secure_open(options: &mut fs::OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        // `O_NOFOLLOW` is not used on the HarmonyOS target, where the record lives
        // in the app sandbox and `open_existing` refuses a symlink entry before
        // the open; every other unix target gets the stronger flag.
        #[cfg(not(target_env = "ohos"))]
        options.custom_flags(hbb_common::libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself so a substituted symlink is detected
        // rather than followed.
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(not(any(unix, windows)))]
    let _ = options;
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // The complete record was flushed first. Request durable replacement; unlike
    // remove-then-rename this never leaves the record missing.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn random_hex(bytes: usize) -> String {
    hex(&randombytes::randombytes(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high as u8) << 4 | low as u8);
    }
    Some(out)
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, the encoding an authenticator's `secret`
/// parameter uses.
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// RFC 4226 HOTP over the one algorithm the protocol requires: HMAC-SHA1,
/// dynamically truncated to the last six decimal digits.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = ring::hmac::sign(&key, &counter.to_be_bytes());
    let digest = tag.as_ref();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    binary % 10u32.pow(TOTP_DIGITS)
}

fn totp_counter(unix_ms: i64) -> u64 {
    (unix_ms.max(0) as u64) / 1000 / TOTP_STEP_SECONDS
}

fn totp_code(secret: &[u8], unix_ms: i64) -> String {
    format!("{:06}", hotp(secret, totp_counter(unix_ms)))
}

/// A six-digit code is accepted at this step and one step either side. The
/// comparison is the constant-time one this crate already uses for passwords.
fn totp_matches(secret: &[u8], code: &str, unix_ms: i64) -> bool {
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let counter = totp_counter(unix_ms);
    let low = counter.saturating_sub(TOTP_WINDOW);
    let high = counter.saturating_add(TOTP_WINDOW);
    (low..=high).any(|counter| {
        let expected = format!("{:06}", hotp(secret, counter));
        utils::memcmp(expected.as_bytes(), code.as_bytes())
    })
}

fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The enrolment URI an authenticator scans: SHA1, six digits, thirty seconds -
/// exactly what [`totp_matches`] verifies.
fn otpauth_uri(secret: &[u8], account: &str) -> String {
    let issuer = format!("{TOTP_ISSUER} {TOTP_LABEL}");
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}",
        encode_component(&format!("{issuer}:{account}")),
        base32_encode(secret),
        encode_component(&issuer),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Auth2FA, HostSecurity, SecurityError, VerificationMethod, base32_encode, get_time, hotp,
        lock, random_hex, totp_code, totp_matches,
    };
    use crate::authentication::{FactorResult, SecondFactorProvider};
    use std::{fs, path::PathBuf, sync::Arc};

    /// The RFC 4226 secret: the ASCII bytes of "12345678901234567890".
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("rd-engine-security-{}", random_hex(8)));
            fs::create_dir_all(&path).expect("a temporary root");
            Self(path)
        }

        fn path(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn opened(root: &TempRoot) -> Arc<HostSecurity> {
        HostSecurity::open(root.path()).expect("the record opens")
    }

    fn record_path(root: &TempRoot) -> PathBuf {
        root.path().join(super::RECORD_FILE)
    }

    fn response(code: &str, hwid: &[u8]) -> Auth2FA {
        Auth2FA {
            code: code.to_owned(),
            hwid: hbb_common::bytes::Bytes::copy_from_slice(hwid),
            ..Default::default()
        }
    }

    fn pending_code(security: &HostSecurity) -> String {
        let pending = lock(&security.pending);
        let pending = pending.as_ref().expect("an enrolment is in progress");
        totp_code(&pending.secret, get_time())
    }

    fn enabled_secret(security: &HostSecurity) -> Vec<u8> {
        let state = lock(&security.state);
        state
            .totp
            .as_ref()
            .expect("the second factor is enabled")
            .secret
            .clone()
    }

    fn enable_two_factor(security: &HostSecurity) {
        security
            .begin_two_factor("865000001")
            .expect("a new enrolment");
        let code = pending_code(security);
        security
            .verify_two_factor(&code)
            .expect("the current code enables");
        assert!(security.two_factor_enabled());
    }

    #[test]
    fn the_hotp_vectors_of_rfc_4226_hold() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                format!("{:06}", hotp(RFC_SECRET, counter as u64)),
                *code,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn a_code_is_accepted_one_step_either_side_and_nothing_else() {
        let step = super::TOTP_STEP_SECONDS * 1000;
        let at_step_one = 30_000;
        let code = totp_code(RFC_SECRET, at_step_one);
        assert_eq!(code, "287082", "the RFC 6238 step-one code");
        assert!(totp_matches(RFC_SECRET, &code, at_step_one));
        // One step late and one step early are inside the window.
        assert!(totp_matches(RFC_SECRET, &code, at_step_one + step));
        assert!(totp_matches(RFC_SECRET, &code, at_step_one - step));
        // Two steps away is not.
        assert!(!totp_matches(RFC_SECRET, &code, at_step_one + 2 * step));
        assert!(!totp_matches(RFC_SECRET, &code, at_step_one + 3 * step));
        // Only six ASCII digits are a code at all.
        for rejected in ["28708", "2870821", "28708a", "", " 287082", "+28708"] {
            assert!(
                !totp_matches(RFC_SECRET, rejected, at_step_one),
                "{rejected:?}"
            );
        }
    }

    #[test]
    fn the_base32_encoder_matches_rfc_4648() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(
            base32_encode(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn a_missing_record_is_the_initial_state_and_writes_nothing() {
        let root = TempRoot::new();
        let nested = root.path().join("nested");
        let security = HostSecurity::open(&nested).expect("a missing record opens");
        assert!(!security.permanent_password_set());
        assert_eq!(security.verification_method(), VerificationMethod::Both);
        assert!(security.accepts_temporary_password());
        assert_eq!(security.permanent_verifier(), None);
        assert!(!security.two_factor_enabled());
        assert!(security.trusted_devices_enabled());
        assert_eq!(security.salt().len(), 32);
        let state = security.two_factor_state();
        assert!(!state.enabled);
        assert!(!state.setup_pending);
        assert!(state.trusted_devices.is_empty());
        // Opening the initial state is a read, not a write.
        assert!(!nested.exists());
    }

    #[test]
    fn the_permanent_password_is_persisted_only_as_a_verifier() {
        let root = TempRoot::new();
        let security = opened(&root);
        let password = "correct horse battery staple";
        security
            .set_permanent_password(password)
            .expect("it stores the verifier");
        let text = String::from_utf8(fs::read(record_path(&root)).expect("the record exists"))
            .expect("the record is JSON");
        assert!(
            !text.contains(password),
            "the plaintext password is not stored"
        );
        assert!(text.contains(&super::hex(&security.verifier(password.as_bytes()))));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(record_path(&root))
                .expect("the record exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "the record is private to this user");
        }
        // A fresh owner reads the same verifier without the plaintext.
        let reopened = opened(&root);
        assert!(reopened.permanent_password_set());
        assert_eq!(
            reopened.permanent_verifier(),
            Some(security.verifier(password.as_bytes()))
        );
        // Clearing it is a real revocation, durably.
        reopened.set_permanent_password("").expect("it clears");
        let cleared = opened(&root);
        assert!(!cleared.permanent_password_set());
        assert_eq!(cleared.permanent_verifier(), None);
    }

    #[test]
    fn the_verification_method_decides_the_primary_verifier_set() {
        let root = TempRoot::new();
        let security = opened(&root);
        security.set_permanent_password("permanent-password").unwrap();
        let permanent = security.verifier(b"permanent-password");
        assert_eq!(security.permanent_verifier(), Some(permanent));
        assert!(security.accepts_temporary_password());

        security
            .set_verification_method("use-permanent-password")
            .unwrap();
        assert!(!security.accepts_temporary_password());
        assert_eq!(security.permanent_verifier(), Some(permanent));
        assert_eq!(opened(&root).permanent_verifier(), Some(permanent));
        assert!(!opened(&root).accepts_temporary_password());

        security
            .set_verification_method("use-temporary-password")
            .unwrap();
        assert!(security.accepts_temporary_password());
        assert_eq!(security.permanent_verifier(), None);
        assert!(
            opened(&root).permanent_password_set(),
            "the verifier is kept but not accepted"
        );

        security.set_verification_method("use-both-passwords").unwrap();
        assert!(security.accepts_temporary_password());
        assert_eq!(security.permanent_verifier(), Some(permanent));

        // An unknown method is refused and changes nothing.
        assert!(security.set_verification_method("use-anything").is_err());
        assert_eq!(security.verification_method(), VerificationMethod::Both);

        // Permanent-only without a verifier is refused, and clearing the verifier
        // moves a permanent-only method back to `both`.
        security.set_permanent_password("").unwrap();
        assert!(
            security
                .set_verification_method("use-permanent-password")
                .is_err()
        );
        security.set_permanent_password("permanent-password").unwrap();
        security
            .set_verification_method("use-permanent-password")
            .unwrap();
        security.set_permanent_password("").unwrap();
        assert_eq!(security.verification_method(), VerificationMethod::Both);
        assert_eq!(
            opened(&root).verification_method(),
            VerificationMethod::Both
        );
    }

    #[test]
    fn a_damaged_record_is_refused_instead_of_reset() {
        let root = TempRoot::new();
        let path = record_path(&root);
        fs::write(&path, b"{ not a record").unwrap();
        assert!(matches!(
            HostSecurity::open(root.path()),
            Err(SecurityError::Corrupt(_))
        ));
        assert!(path.exists(), "the damaged record is left for the operator");
        // A record that claims a permanent-only method without holding a
        // verifier is equally unusable.
        let record = hbb_common::serde_json::json!({
            "version": 1,
            "salt": super::hex(&[0u8; 16]),
            "permanent": null,
            "method": "use-permanent-password",
            "totp": null,
            "trusted_devices_enabled": true,
            "trusted_devices": [],
        });
        fs::write(&path, record.to_string()).unwrap();
        assert!(matches!(
            HostSecurity::open(root.path()),
            Err(SecurityError::Corrupt(_))
        ));
    }

    #[test]
    fn a_failed_write_reports_the_error_and_keeps_the_valid_state() {
        let root = TempRoot::new();
        let directory = root.path().join("state");
        let security = HostSecurity::open(&directory).expect("a missing record opens");
        security
            .set_permanent_password("first-password")
            .expect("it stores");
        let verifier = security.verifier(b"first-password");
        // Make the record's directory unusable: the commit cannot be published.
        fs::remove_dir_all(&directory).unwrap();
        fs::write(&directory, b"not a directory").unwrap();
        let error = security
            .set_permanent_password("second-password")
            .expect_err("the write cannot succeed");
        assert!(matches!(error, SecurityError::Storage(_)), "{error:?}");
        assert_eq!(
            security.permanent_verifier(),
            Some(verifier),
            "the last valid verifier stays in force"
        );
        assert_eq!(security.verification_method(), VerificationMethod::Both);
        assert!(matches!(
            security.clear_trusted_devices(),
            Err(SecurityError::Storage(_))
        ));
    }

    #[test]
    fn totp_becomes_enabled_only_after_a_verified_code_is_persisted() {
        let root = TempRoot::new();
        let security = opened(&root);
        let uri = security
            .begin_two_factor("865000001")
            .expect("a new enrolment");
        assert!(uri.starts_with("otpauth://totp/"), "{uri}");
        assert!(uri.contains("algorithm=SHA1&digits=6&period=30"));
        assert!(uri.contains("secret="));
        assert!(!security.two_factor_enabled(), "begin only proposes");
        assert!(security.two_factor_state().setup_pending);
        // A wrong code is refused, enables nothing and writes nothing.
        let real = pending_code(&security);
        let wrong = if real == "000000" { "111111" } else { "000000" };
        assert!(matches!(
            security.verify_two_factor(wrong),
            Err(SecurityError::WrongCode)
        ));
        assert!(!security.two_factor_enabled());
        assert!(
            !record_path(&root).exists(),
            "a refused code persists nothing"
        );
        // The real code enables it, and the secret really is durable.
        security
            .verify_two_factor(&real)
            .expect("the current code enables");
        assert!(security.two_factor_enabled());
        assert!(!security.two_factor_state().setup_pending);
        assert!(opened(&root).two_factor_enabled());
        assert!(matches!(
            security.verify_two_factor(&real),
            Err(SecurityError::NoSetupInProgress)
        ));
        // Turning it off is durable as well.
        security.disable_two_factor().expect("it disables");
        assert!(!security.two_factor_enabled());
        assert!(!opened(&root).two_factor_enabled());
    }

    /// `FactorResult` deliberately has no `PartialEq`; each positive and
    /// negative expectation names the exact variant the provider returned.
    fn verdict(security: &HostSecurity, code: &str, hwid: &[u8]) -> FactorResult {
        security.verify_second_factor(&response(code, hwid))
    }

    #[test]
    fn a_trusted_device_is_recorded_only_from_a_verified_code_with_a_hwid() {
        let root = TempRoot::new();
        let security = opened(&root);
        enable_two_factor(&security);
        let hwid = b"peer-hwid-0001";

        // A verified code proves the factor; without an explicit hwid there is
        // nothing to record.
        let code = totp_code(&enabled_secret(&security), get_time());
        assert!(matches!(
            verdict(&security, &code, b""),
            FactorResult::Verified
        ));
        assert!(
            opened(&root).two_factor_state().trusted_devices.is_empty(),
            "no hwid, no record"
        );

        // The same verified code with an explicit hwid enrolls it, durably.
        let code = totp_code(&enabled_secret(&security), get_time());
        assert!(matches!(
            verdict(&security, &code, hwid),
            FactorResult::Verified
        ));
        let state = opened(&root).two_factor_state();
        assert_eq!(state.trusted_devices.len(), 1);
        assert_eq!(state.trusted_devices[0].hwid, hwid);
        assert!(state.registration_error.is_none());

        // The recorded device may skip the code, an unknown one may not.
        assert!(matches!(
            verdict(&security, "", hwid),
            FactorResult::Verified
        ));
        assert!(matches!(
            verdict(&security, "", b"other-hwid"),
            FactorResult::Wrong
        ));

        // The policy is a real switch, persisted under the key the client sends.
        assert!(!security.set_setting("trustedDevicesEnabled", "false").unwrap());
        assert!(!opened(&root).trusted_devices_enabled());
        assert!(matches!(
            verdict(&security, "", hwid),
            FactorResult::Wrong
        ));
        assert!(security.set_setting("trustedDevicesEnabled", "true").unwrap());
        assert!(matches!(
            verdict(&security, "", hwid),
            FactorResult::Verified
        ));
        // A key this engine does not act on is refused, not reported saved.
        assert!(matches!(
            security.set_setting("enable-os-login", "true"),
            Err(SecurityError::UnsupportedSetting)
        ));

        // Removal and clearing are durable.
        security.remove_trusted_devices(&[hwid.to_vec()]).unwrap();
        assert!(
            opened(&root)
                .two_factor_state()
                .trusted_devices
                .is_empty()
        );
        assert!(matches!(
            verdict(&security, "", hwid),
            FactorResult::Wrong
        ));

        // A device older than ninety days is neither listed nor trusted.
        let code = totp_code(&enabled_secret(&security), get_time());
        assert!(matches!(
            verdict(&security, &code, hwid),
            FactorResult::Verified
        ));
        {
            let mut current = lock(&security.state);
            let mut next = current.clone();
            next.devices[0].time = get_time() - super::TRUSTED_DEVICE_LIFETIME_MS - 1000;
            *current = next;
        }
        assert!(security.two_factor_state().trusted_devices.is_empty());
        assert!(matches!(
            verdict(&security, "", hwid),
            FactorResult::Wrong
        ));
        // The expired record is no longer worth trusting, and a fresh one
        // replaces it rather than joining it.
        let code = totp_code(&enabled_secret(&security), get_time());
        assert!(matches!(
            verdict(&security, &code, hwid),
            FactorResult::Verified
        ));
        assert_eq!(security.two_factor_state().trusted_devices.len(), 1);

        // Disabling the factor revokes the records it enrolled.
        security.disable_two_factor().unwrap();
        let state = opened(&root).two_factor_state();
        assert!(!state.enabled);
        assert!(state.trusted_devices.is_empty());
        assert!(matches!(
            verdict(&security, "", hwid),
            FactorResult::Unsupported
        ));
    }

    #[test]
    fn an_hwid_never_substitutes_for_the_primary_step() {
        let root = TempRoot::new();
        let security = opened(&root);
        // With no second factor the engine never asks it, and this provider has
        // no verified path at all - a claimed hwid or code included.
        assert!(matches!(
            verdict(&security, "", b"peer-hwid-0001"),
            FactorResult::Unsupported
        ));
        assert!(matches!(
            verdict(&security, "123456", b"peer-hwid-0001"),
            FactorResult::Unsupported
        ));
        let factor = super::HostSecondFactor::new(security.clone());
        assert!(!SecondFactorProvider::required(&factor));
        assert!(security.two_factor_state().trusted_devices.is_empty());
        // Nothing above wrote a record: no device can be skipped into existence.
        assert!(!record_path(&root).exists());
    }
}
