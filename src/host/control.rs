//! Windows main-process control owner. CM and bridge code observe this owner;
//! neither observations nor subscriptions initialize configuration or native work.
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, sync::Arc, time::{Duration, Instant}};
use tokio::sync::{mpsc, oneshot, watch};
mod owner;
mod configuration;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSnapshot {
    pub owner_epoch: u64,
    pub run_epoch: u64,
    pub revision: u64,
    pub policy_revision: u64,
    pub id: String,
    pub fingerprint: String,
    pub permanent_password_set: bool,
    pub local_permanent_password_set: bool,
    pub preset_password: bool,
    pub phase: String,
    pub ready: bool,
    pub registration: String,
    pub status_num: i32,
    pub error: Option<String>,
    pub options: HashMap<String, String>,
    pub peers: Vec<PeerSnapshot>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub conn_id: i32,
    pub connection_token: u64,
    pub run_epoch: u64,
    pub approval_epoch: Option<u64>,
    pub policy_revision: u64,
    pub peer_id: String,
    pub name: String,
    pub authorized: bool,
    pub disconnected: bool,
    pub phase: String,
    pub keyboard: bool,
    pub error: Option<String>,
}

// Deliberately no Debug: commands can contain plaintext credentials.
pub enum HostCommand {
    Start,
    Stop,
    RefreshConfiguration,
    RotateTemporaryPassword,
    GetTemporaryPassword,
    SetPermanentPassword { password: String },
    SetOption { key: String, value: String },
    SetOptions { options: HashMap<String, String> },
    Approve { run_epoch: u64, conn_id: i32, approval_epoch: u64, policy_revision: u64, allow: bool },
    Disconnect { run_epoch: u64, conn_id: i32 },
    SetKeyboard { run_epoch: u64, conn_id: i32, enabled: bool },
    RemoveDisconnected { run_epoch: u64, conn_id: i32 },
    ReadActivity,
}

impl Drop for HostCommand {
    fn drop(&mut self) {
        match self {
            Self::SetPermanentPassword { password } => configuration::wipe(password),
            Self::SetOption { value, .. } => configuration::wipe(value),
            Self::SetOptions { options } => { for value in options.values_mut() { configuration::wipe(value); } }
            _ => {}
        }
    }
}

pub enum HostReply {
    Acknowledged,
    TemporaryPassword(String),
    Activity(ActivitySnapshot),
}

// A receiver may disappear after a successful send. Keep the secret's cleanup
// on the value so both channel buffers and canceled futures scrub it as well.
impl Drop for HostReply {
    fn drop(&mut self) {
        if let Self::TemporaryPassword(value) = self { configuration::wipe(value); }
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct ActivitySnapshot {
    pub sequence: u64,
    pub click_wall_ms: u64,
    pub mouse_wall_ms: u64,
    pub uncertain: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ControlError(pub(crate) &'static str);
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.0) }
}
impl std::error::Error for ControlError {}

pub struct HostController {
    commands: mpsc::Sender<Request>,
    states: watch::Receiver<ServiceSnapshot>,
    registration_uuid: Vec<u8>,
}
struct Request {
    command: HostCommand,
    deadline: Instant,
    reply: oneshot::Sender<Result<HostReply, ControlError>>,
}

impl HostController {
    /// Only the real main-process startup calls this on its blocking worker.
    /// Observation APIs cannot initialize identity or native/network resources.
    pub fn initialize() -> Result<Arc<Self>, ControlError> {
        owner::initialize()
    }
    pub fn snapshot(&self) -> ServiceSnapshot { self.states.borrow().clone() }
    pub fn subscribe_state(&self) -> watch::Receiver<ServiceSnapshot> { self.states.clone() }
    /// Main-process native caller only; never included in snapshots or CM IPC.
    pub fn registration_uuid(&self) -> &[u8] { &self.registration_uuid }
    pub async fn execute(&self, command: HostCommand) -> Result<HostReply, ControlError> {
        let deadline = Instant::now().checked_add(Duration::from_secs(45))
            .ok_or(ControlError("Host command deadline is unavailable"))?;
        self.execute_with_deadline(command, deadline).await
    }
    /// Native bridge only: preserve the request's original monotonic deadline.
    /// Expiry never rolls back completed storage or abandons admitted cleanup.
    pub async fn execute_with_deadline(&self, command: HostCommand, deadline: Instant) -> Result<HostReply, ControlError> {
        let (reply, result) = oneshot::channel();
        self.commands.try_send(Request { command, deadline, reply })
            .map_err(|_| ControlError("Host control owner unavailable or busy"))?;
        result.await.map_err(|_| ControlError("Host control owner unavailable"))?
    }
}
