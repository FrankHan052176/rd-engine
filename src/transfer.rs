//! Session-owned RustDesk file transfer: one real job owner for a viewer's
//! `FileTransfer` role, built on the pinned `base::fs::TransferJob`.
//!
//! # Ownership
//!
//! The jobs live in the task that runs [`TransferOwner::run`]; the viewer's
//! reader and writer never see them. What leaves this module is [`Outbound`] —
//! one wire `Message` carrying the byte budget it holds — and what enters it is
//! [`Inbound`] (the peer's `FileAction`/`FileResponse`, once the viewer's single
//! reader has parsed it) plus [`TransferCommand`] from the client. This module
//! never takes the socket, the `WireWriter` or an `hbb_common::Stream`.
//!
//! The session's file permission is one more input the viewer's reader hands in
//! ([`TransferHandle::set_enabled`]). The owner acts on it at a pass boundary,
//! never inside a started disk read or write, and every effect
//! ([`Outbound::is_permitted`]) and every command carries the permission
//! generation it was issued under: an effect carries the generation of the pass
//! that queued it, fixed at that pass's own boundary, so one that waited for the
//! byte budget across a withdrawal is dropped rather than restamped by it. So
//! nothing a revocation reached is sent or run after a re-grant.
//!
//! The same seam carries the one write this module has to prove: an upload's last
//! record is confirmed back by the writer ([`Outbound::complete`]), so a job is
//! `Done` only once that record really was written — never because it was merely
//! queued, and never because the peer acknowledged anything.
//!
//! The two upstream helpers that do take a stream are replaced, not called:
//! `base::fs::handle_read_jobs`/`init_data_stream` are `async fn(.., &mut
//! Stream)`, so calling them would create a second writer with its own encryption
//! sequence. [`upload_step`] performs the same steps — `init_data_stream_for_cm`,
//! `read`, `new_error`/`new_digest`/`new_block`/`new_done`, one job per tick —
//! and hands every send to the session's one writer as an effect.
//!
//! # Provenance
//!
//! The algorithm is the pinned client's own, from `rustdesk/rustdesk` @
//! `092a961b629d318fe290eeafac0cd214a1e9deeb`
//! (`.build-deps/official-client`, read as a source candidate that is *not* this
//! product's tree): `src/client/io_loop.rs` for `FileResponse::{Dir,Digest,
//! Block,Done,Error}`, `FileAction::SendConfirm`, `Data::{SendFiles,
//! SetConfirmOverrideFile,CancelJob}`, the `handle_read_jobs` tick,
//! `cancel_transfer_job`, `update_jobs_status`; `src/common.rs` for
//! `is_support_file_transfer_resume`; `src/flutter.rs` and `src/common.rs` for
//! the client event shapes this module's [`TransferEvent`] mirrors. The job
//! algorithms themselves are the vendored `vendor/rustdesk/libs/base/src/fs.rs`.
//! Every place that was adapted rather than copied says so where it sits.
//!
//! # What is deliberately not here
//!
//! No printer job (`JobType::Generic` only), no resume/`AddJob` (a job carries
//! the serialized meta upstream persists; this owner keeps none), no directory
//! create/remove/rename, no host-side file service, and no second runtime.

use base::{
    fs::{self, DataSource, JobType, TransferJob},
    message_proto::{
        FileAction, FileDirectory, FileEntry, FileResponse, FileTransferBlock, FileTransferCancel,
        FileTransferDigest, FileTransferSendConfirmRequest, Message, ReadDir, file_action,
        file_response, file_transfer_send_confirm_request,
    },
};
use std::{
    collections::{HashMap, VecDeque},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Wire effects the writer may hold for this owner: one upstream block each
/// (the reader emits one `FileTransferBlock` per effect, `BUF_SIZE` = 128 KiB in
/// `base::fs`), plus the small control messages (`dir`, `digest`, `send_confirm`,
/// `done`, `error`, `cancel`). At most this many are buffered *and* one more may
/// be in the writer's hand, so the writer is never asked to drain an unbounded
/// queue into a biased control channel.
pub const TRANSFER_OUTBOUND_QUEUE: usize = 4;
/// The byte budget those effects share: a block's payload is reserved before the
/// effect is queued and released when the writer drops the effect after sending
/// it, so a payload being written counts against the budget too. Large enough
/// for one 128 KiB block at all times, small enough that transfer can never
/// starve input (`Viewer`'s writer rotates one bulk effect per pass).
pub const TRANSFER_BULK_BYTES: usize = 512 * 1024;
/// Commands the client may queue ahead of the owner.
pub const TRANSFER_COMMAND_QUEUE: usize = 16;
/// Peer messages the reader may queue ahead of the owner. The reader must wait
/// on this channel rather than drop a `FileResponse::Block`: a slow local disk
/// then applies real backpressure, which is what the pinned client's own session
/// loop does by awaiting `job.write` inline.
pub const TRANSFER_INBOUND_QUEUE: usize = 8;
/// Events the owner may hold for a client that has not taken them yet. A
/// progress sample is merged (or skipped as stale), and the owner starts a pass
/// only with room for the facts that pass can publish, so this bound is never
/// paid for by losing a listing, an overwrite question or a terminal state.
const TRANSFER_EVENTS_KEPT: usize = 64;
/// What one pass of the owner may publish: one coalesced progress sample and one
/// fact (a listing, an overwrite question, a terminal state). Starting a pass
/// only with this much room is what keeps the event queue exactly bounded
/// without dropping either.
const TRANSFER_EVENT_PASS_ROOM: usize = 2;
/// Job rows kept for the client's list, and with them the live jobs this session
/// admits: only terminal rows are dropped, and a command that would go past this
/// many live jobs is refused visibly instead of queueing work nobody can see.
const TRANSFER_ROWS_KEPT: usize = 64;
/// The one text a revocation reports. This engine's own constant, never peer
/// text, and the same reason [`TransferError::PermissionDenied`] carries.
const PERMISSION_REVOKED: &str = "the peer withdrew file transfer permission";
/// The one text an upload reports when this session's own writer did not write
/// its last record. It says exactly what is true — the `done` never reached the
/// wire — and claims nothing about the peer's own answer.
const UPLOAD_NOT_WRITTEN: &str = "the transfer writer did not write this upload's final record";
/// How often one job's progress is reported; upstream `update_jobs_status` uses
/// the same one-second window.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);

fn lock<T>(cell: &Mutex<T>) -> MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A refusal of this owner, decided from local constants only: never peer text
/// and never a filesystem diagnostic, so no path or peer string reaches a caller
/// through it. A job's own failure text is a [`TransferEvent::Failed`] and is
/// described there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferError {
    /// A job id that is not a positive integer.
    InvalidJob,
    /// This session already has a job with that id.
    DuplicateJob,
    /// No live job of this session has that id.
    UnknownJob,
    /// A job starting at a non-zero file index needs upstream's persisted job
    /// meta (`AddJob`/`ResumeJob`) and a serialized `.digest` sidecar, which this
    /// owner does not keep; starting it at file 0 would mislabel the transfer.
    ResumeUnsupported,
    /// No authorized local root was configured for this session.
    LocalRootUnset,
    /// The local path is empty, not absolute, escapes the authorized root, or
    /// carries a `..` component.
    LocalPathInvalid,
    /// A remote path is empty where it must name something, relative, or carries
    /// a `..` component.
    RemotePathInvalid,
    /// The owner's inbound or outbound channel is closed; the session is over.
    Closed,
    /// The viewer is cancelling, so no further effect is owed.
    Cancelled,
    /// The command queue is full: the client may retry once it has polled.
    Backpressure,
    /// This session already holds the maximum number of live transfer jobs.
    TooManyJobs,
    /// The peer has not granted (or has withdrawn) file transfer for this
    /// session.
    PermissionDenied,
    /// The peer's `FileResponse` carried a union variant this build does not
    /// know, so it can be read neither as a job fact nor as an answer this side
    /// owes: the owner ends rather than treating it as a peer success.
    UnsupportedMessage,
}

impl TransferError {
    /// The refusal as the local constant it already is.
    ///
    /// A caller that has to publish a `&'static str` — `ViewerError`'s own
    /// vocabulary — uses this instead of formatting, so no path or peer text can
    /// ever be built into an engine error string.
    pub fn static_reason(&self) -> &'static str {
        match self {
            Self::InvalidJob => "job id must be a positive integer",
            Self::DuplicateJob => "this session already has a job with that id",
            Self::UnknownJob => "no live job of this session has that id",
            Self::ResumeUnsupported => "resuming a job at a file offset is not implemented",
            Self::LocalRootUnset => "this session has no authorized local file root",
            Self::LocalPathInvalid => "local path is outside the authorized root",
            Self::RemotePathInvalid => "remote path is not an absolute path without traversal",
            Self::Closed => "the transfer channel is closed",
            Self::Cancelled => "the session is closing",
            Self::Backpressure => "the transfer command queue is full",
            Self::TooManyJobs => {
                "this session already holds the maximum number of live transfer jobs"
            }
            Self::PermissionDenied => PERMISSION_REVOKED,
            Self::UnsupportedMessage => "the peer sent a file message this session cannot answer",
        }
    }
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.static_reason())
    }
}

impl std::error::Error for TransferError {}

/// What a client may ask this session's transfer owner to do.
///
/// `remote` is always the path on the peer and `local` always the path here, so
/// the two directions cannot be swapped by accident. They map one-to-one onto the
/// pinned client's `Data::SendFiles`: `Download` is `is_remote: true` (the peer
/// owns the source), `Upload` is `is_remote: false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferCommand {
    /// Browse the peer's filesystem. An empty path is the peer's home directory,
    /// which is the one place upstream treats an empty path as valid.
    ReadDir { path: String, include_hidden: bool },
    /// Copy `remote` (on the peer) to `local` (under this session's root).
    Download {
        job: i32,
        remote: String,
        local: String,
        file_num: i32,
        include_hidden: bool,
    },
    /// Copy `local` (under this session's root) to `remote` (on the peer).
    Upload {
        job: i32,
        local: String,
        remote: String,
        file_num: i32,
        include_hidden: bool,
    },
    /// The operator answered an [`TransferEvent::Overwrite`]. `upload` selects the
    /// table exactly as upstream's `is_upload` does.
    ConfirmOverwrite {
        job: i32,
        file_num: i32,
        overwrite: bool,
        remember: bool,
        upload: bool,
    },
    /// Stop one job of this session. It never closes the viewer and never
    /// acknowledges a record.
    Cancel { job: i32 },
}

/// The job a command names, if it names one: what a refusal is reported against.
fn named_job(command: &TransferCommand) -> Option<i32> {
    match command {
        TransferCommand::ReadDir { .. } => None,
        TransferCommand::Download { job, .. }
        | TransferCommand::Upload { job, .. }
        | TransferCommand::ConfirmOverwrite { job, .. }
        | TransferCommand::Cancel { job } => Some(*job),
    }
}

/// One queued command with the permission generation it was submitted under. A
/// command the client issued before a revocation must not run after a re-grant,
/// so the owner drops a stamp that no longer matches instead of replaying it.
struct Issued {
    revision: u64,
    command: TransferCommand,
}

/// The session's file permission, as the peer's `PermissionInfo` reports it and
/// as the owner acts on it.
///
/// `revision` counts withdrawals: it moves on each enabled→disabled transition
/// and on nothing else, so a repeated `PermissionInfo` and a re-grant both fence
/// nothing off. Effects and commands carry the generation they were issued
/// under; what a revocation reached is neither sent nor run afterwards.
struct PermissionGate {
    enabled: AtomicBool,
    revision: AtomicU64,
    /// Wakes the owner, which may be waiting for a command, a peer message, room
    /// in the event queue, or nothing at all.
    changed: Notify,
}

impl PermissionGate {
    fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            revision: AtomicU64::new(0),
            changed: Notify::new(),
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Records the peer's answer. Only a real change wakes the owner, and only a
    /// withdrawal starts a new generation. `notify_one` rather than
    /// `notify_waiters`, so a change that lands between the owner's own check and
    /// its wait is kept instead of lost.
    fn set(&self, enabled: bool) {
        if self.enabled.swap(enabled, Ordering::AcqRel) == enabled {
            return;
        }
        if !enabled {
            self.revision.fetch_add(1, Ordering::AcqRel);
        }
        self.changed.notify_one();
    }
}

impl std::fmt::Debug for PermissionGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PermissionGate")
            .field("enabled", &self.is_enabled())
            .field("revision", &self.revision())
            .finish()
    }
}

/// One job's direction, in the terms the client's list shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

/// Where a job really is. `AwaitingOverwrite` means an
/// [`TransferEvent::Overwrite`] is outstanding; a sender waiting for the peer's
/// own confirmation is still `Running`, because that is not the operator's
/// decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferJobState {
    Queued,
    Running,
    AwaitingOverwrite,
    Done,
    Failed(String),
    Cancelled,
}

/// One job as the client may read it, including terminal jobs until the list is
/// pruned. `file_num` is the file being transferred (upstream's own
/// `job.file_num() - 1`), and the byte counters are the job's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRow {
    pub job: i32,
    pub direction: TransferDirection,
    pub state: TransferJobState,
    pub file_num: i32,
    pub total_size: u64,
    pub finished_size: u64,
    pub transferred: u64,
    pub remote: String,
    pub local: String,
}

/// What the client acts on, one variant per event name the pinned client reports
/// (`src/flutter.rs`), so a bridge maps them without inventing a vocabulary.
///
/// Non-progress events are retained until a consumer takes them; only `Progress`
/// is coalesced (one per job per second), which is what makes it safe to drop a
/// stale one.
#[derive(Debug, Clone, PartialEq)]
pub enum TransferEvent {
    /// `file_dir`: a listing. `id == 0` is the answer to a browse request; a job
    /// id is the file list that job will move.
    Directory(FileDirectory),
    /// `override_file_confirm`: the operator must decide about `read_path`.
    Overwrite {
        job: i32,
        file_num: i32,
        read_path: String,
        upload: bool,
        identical: bool,
    },
    /// `job_progress`.
    Progress {
        job: i32,
        file_num: i32,
        speed: f64,
        finished_size: u64,
    },
    /// `job_done`. For a download this is the peer's own terminal fact, and it is
    /// the only place a received file is made real. For an upload it means this
    /// session's own single writer reported that it wrote upstream's own `done`
    /// record ([`Outbound::complete`]); whether the peer accepted that `done` is
    /// not observable on this wire, so it is not claimed. A `done` the writer did
    /// not write is this job's `Failed`, never this event.
    Done { job: i32, file_num: i32 },
    /// `job_error`. `error` is either this engine's own constant or — for a job
    /// failure the peer reported — the peer's `FileTransferError.error`, which is
    /// what the pinned client shows its own operator. It never becomes a
    /// `ViewerError` or a snapshot string.
    Failed {
        job: i32,
        file_num: i32,
        error: String,
    },
    /// `job_error` with upstream's own `"skipped"` text: this file was not
    /// transferred because the peer or the operator declined the overwrite.
    Skipped { job: i32, file_num: i32 },
    /// `empty_dirs`.
    EmptyDirs {
        path: String,
        directories: Vec<FileDirectory>,
    },
}

/// The jobs the client may show and the events it has not consumed yet.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TransferSnapshot {
    pub jobs: Vec<TransferRow>,
    pub events: Vec<TransferEvent>,
}

/// What the owner reads once for the whole session.
///
/// `local_root` is the authorization for every local path a command names: the
/// client's own `startsWith` check is a UI convenience, not this boundary.
/// `peer_version` decides overwrite detection exactly as upstream's
/// `can_enable_overwrite_detection` does, and `peer_platform` decides whether an
/// inbound file list needs upstream's `transform_windows_path`.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    local_root: Option<PathBuf>,
    peer_platform: String,
    overwrite_detection: bool,
}

impl TransferConfig {
    pub fn new(
        local_root: Option<PathBuf>,
        peer_platform: impl Into<String>,
        peer_version: &str,
    ) -> Self {
        Self {
            local_root,
            peer_platform: peer_platform.into(),
            overwrite_detection: fs::can_enable_overwrite_detection(
                hbb_common::get_version_number(peer_version),
            ),
        }
    }

    fn root(&self) -> Result<&Path, TransferError> {
        self.local_root
            .as_deref()
            .ok_or(TransferError::LocalRootUnset)
    }
}

/// One peer message for the owner, already parsed once by the viewer's reader.
#[derive(Debug, Clone)]
pub enum Inbound {
    Action(FileAction),
    Response(FileResponse),
}

/// One wire message the session's single writer must send, with the byte budget
/// it holds and the permission generation it was queued under. Dropping it
/// (after the send, or instead of it) releases those bytes.
pub struct Outbound {
    message: Message,
    _permit: OwnedSemaphorePermit,
    permission: Arc<PermissionGate>,
    revision: u64,
    /// Where a final effect's write is reported back. Present only on the record
    /// whose writing the owner waits on (an upload's last `done`), so ordinary
    /// blocks stay one-way and the bounded queue is never a queue of ACKs.
    completion: Option<oneshot::Sender<bool>>,
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound")
            .field("message", &self.message)
            .field("revision", &self.revision)
            .field("completion", &self.completion.is_some())
            .finish()
    }
}

impl Outbound {
    /// The one message this effect carries. It carries nothing else: no socket,
    /// no runtime, and no promise that the peer consumed it.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Whether the session's file permission still stands for this effect.
    ///
    /// The writer checks this before sending: an effect stamped with a
    /// generation the session has since withdrawn is one the revocation already
    /// reached, so it is dropped (never sent, and never sent after a re-grant).
    /// A revocation's own cancels are stamped with the new generation — the one
    /// the pass that acts on the withdrawal began under — and therefore pass.
    pub fn is_permitted(&self) -> bool {
        self.permission.revision() == self.revision
    }

    /// Reports whether this effect was actually written, and releases it.
    ///
    /// This is how a written record is told apart from a queued one: the session's
    /// writer calls it after the one wire write it owns — `true` only when that
    /// write happened, `false` when it dropped this effect as stale or the write
    /// failed — and an owner waiting on that answer takes it. Dropping the effect
    /// without calling this closes the same answer without a `true`, so an unknown
    /// write is never read as a written one. Effects that carry no answer (every
    /// ordinary block) write nothing here.
    pub fn complete(self, written: bool) {
        if let Some(completion) = self.completion {
            // The owner may already have stopped waiting for it (the session was
            // cancelled); then the answer is owed to nobody.
            let _ = completion.send(written);
        }
    }
}

/// Why the owner stopped. The caller decides what that means for the session:
/// `Cancelled` is an ordinary close, the others mean nothing can be sent any
/// more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferExit {
    Cancelled,
    CommandClosed,
    InboundClosed,
    OutboundClosed,
}

/// The client's handle on a running owner: submit, read, allocate a job id.
pub struct TransferHandle {
    shared: Arc<TransferShared>,
    commands: mpsc::Sender<Issued>,
}

impl TransferHandle {
    /// Queues one command, refusing everything that can be refused without the
    /// wire (the session's file permission, path shape, root containment, job id
    /// shape, resume).
    ///
    /// Never blocks: this runs on the client's own thread, which is not the
    /// engine's runtime. A full queue is [`TransferError::Backpressure`], which
    /// the client may retry after polling. Refusals that need live job state
    /// (duplicate, unknown and over-the-limit ids) are reported to the client as
    /// [`TransferEvent::Failed`], because by then the command is this session's.
    pub fn submit(&self, command: TransferCommand) -> Result<(), TransferError> {
        // The generation is taken first, before anything else can be refused or
        // validated: it stamps what this command was really issued under. Read at
        // the end instead — after path and job validation — a withdrawal that
        // landed in between would be restamped as a command of the new era and
        // run after the re-grant.
        let revision = self.shared.permission.revision();
        if !self.shared.permission.is_enabled() {
            return Err(TransferError::PermissionDenied);
        }
        match &command {
            TransferCommand::ReadDir { path, .. } => validate_remote_path(path, true)?,
            TransferCommand::Download {
                job,
                remote,
                local,
                file_num,
                ..
            }
            | TransferCommand::Upload {
                job,
                local,
                remote,
                file_num,
                ..
            } => {
                validate_job(*job)?;
                if *file_num != 0 {
                    return Err(TransferError::ResumeUnsupported);
                }
                validate_local_path(self.shared.config.root()?, local)?;
                validate_remote_path(remote, false)?;
            }
            TransferCommand::ConfirmOverwrite { job, .. } | TransferCommand::Cancel { job } => {
                validate_job(*job)?
            }
        }
        self.commands
            .try_send(Issued { revision, command })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TransferError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => TransferError::Closed,
            })
    }

    /// Records the peer's file permission for this session, as its
    /// `PermissionInfo` reports it. `false` withdraws it: no further command is
    /// accepted, and the owner ends the jobs it still holds at its next pass
    /// boundary, before it starts any new disk read or write. Re-enabling admits
    /// new work but never replays what the revocation reached.
    pub fn set_enabled(&self, enabled: bool) {
        self.shared.permission.set(enabled);
    }

    /// Whether this session currently holds file transfer permission.
    pub fn is_enabled(&self) -> bool {
        self.shared.permission.is_enabled()
    }

    /// The job list plus every event not yet taken. Taking it consumes those
    /// events; the rows stay, including terminal ones.
    pub fn take_snapshot(&self) -> TransferSnapshot {
        self.shared.take_snapshot()
    }

    /// The job list plus at most `limit` of the oldest events not yet taken. The
    /// rest stay queued for the next poll, so a client that reports events under
    /// its own per-poll limit loses none of them.
    pub fn take_snapshot_limit(&self, limit: usize) -> TransferSnapshot {
        self.shared.take_snapshot_limit(limit)
    }

    /// The job list alone, without consuming events.
    pub fn jobs(&self) -> Vec<TransferRow> {
        lock(&self.shared.rows).clone()
    }

    /// The next session-owned job id, from the pinned client's own counter. An id
    /// allocated here is usable only by the owner that adopts it: a command naming
    /// an id this session does not hold is refused, so one viewer's job id can
    /// never address another viewer's job.
    pub fn next_job_id(&self) -> i32 {
        next_job_id()
    }
}

/// The next job id, from `base::fs`'s process-wide counter — the same one the
/// pinned client uses, so an id is never reused. Ownership is enforced by the
/// owner that adopts it, not by this counter.
pub fn next_job_id() -> i32 {
    fs::get_next_job_id()
}

/// What [`start`] hands the caller: the task to spawn, the client's handle, and
/// the two channel ends the viewer's reader and writer own.
pub struct TransferStart {
    pub owner: TransferOwner,
    pub handle: TransferHandle,
    pub inbound: mpsc::Sender<Inbound>,
    pub outbound: mpsc::Receiver<Outbound>,
}

/// Builds the owner and its channels. Nothing runs until the caller spawns
/// [`TransferOwner::run`] on the session's own executor, and no runtime is
/// created here.
pub fn start(config: TransferConfig, cancel: CancellationToken) -> TransferStart {
    let (commands_tx, commands_rx) = mpsc::channel(TRANSFER_COMMAND_QUEUE);
    let (inbound_tx, inbound_rx) = mpsc::channel(TRANSFER_INBOUND_QUEUE);
    let (outbound_tx, outbound_rx) = mpsc::channel(TRANSFER_OUTBOUND_QUEUE);
    // A fresh owner is permitted: the caller installs the peer's real answer (the
    // authenticated session's `Permission::File`) with `set_enabled`.
    let permission = Arc::new(PermissionGate::new(true));
    let shared = Arc::new(TransferShared {
        config,
        rows: Mutex::new(Vec::new()),
        events: Mutex::new(VecDeque::new()),
        events_room: Notify::new(),
        samples: Mutex::new(HashMap::new()),
        permission: Arc::clone(&permission),
    });
    TransferStart {
        owner: TransferOwner {
            shared: Arc::clone(&shared),
            commands: commands_rx,
            inbound: inbound_rx,
            wire: Wire {
                outbound: outbound_tx,
                bytes: Arc::new(Semaphore::new(TRANSFER_BULK_BYTES)),
                cancel: cancel.clone(),
                permission,
                // The first pass fixes it to the session's own generation before
                // it sends anything.
                revision: AtomicU64::new(0),
            },
            cancel,
            jobs: JobTables::default(),
            permission_revision: 0,
            revoking: false,
        },
        handle: TransferHandle {
            shared,
            commands: commands_tx,
        },
        inbound: inbound_tx,
        outbound: outbound_rx,
    }
}

/// The one local path a command may name: `root` itself or something under it.
///
/// Component-wise, so `root-other` is not `root`, and the resolved path is
/// rebuilt from the root and the relative tail, so no `..` can survive into the
/// filesystem operation even if one was sent. The remaining symlink and race
/// window belongs to the pinned `base::fs`, whose `join_validated_path`,
/// `set_files` and `write` refuse traversal and symlinked components on the
/// real path (see its `path_traversal_e2e_*` tests).
fn validate_local_path(root: &Path, named: &str) -> Result<PathBuf, TransferError> {
    if named.is_empty() || named.as_bytes().contains(&0) {
        return Err(TransferError::LocalPathInvalid);
    }
    let candidate = Path::new(named);
    if !candidate.is_absolute()
        || candidate
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(TransferError::LocalPathInvalid);
    }
    let relative = candidate
        .strip_prefix(root)
        .map_err(|_| TransferError::LocalPathInvalid)?;
    Ok(root.join(relative))
}

/// A remote path as the peer will resolve it: absolute, no null byte, and no
/// `..` segment. The peer owns its own confinement; this only refuses to ask it
/// for a path that leaves the directory the operator is looking at.
fn validate_remote_path(named: &str, allow_empty: bool) -> Result<(), TransferError> {
    if named.as_bytes().contains(&0) {
        return Err(TransferError::RemotePathInvalid);
    }
    if named.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(TransferError::RemotePathInvalid)
        };
    }
    if !named.starts_with('/') && !has_windows_drive_prefix(named) {
        return Err(TransferError::RemotePathInvalid);
    }
    if named.split(['/', '\\']).any(|segment| segment == "..") {
        return Err(TransferError::RemotePathInvalid);
    }
    Ok(())
}

/// `C:` or `c:`, the one non-`/` prefix the peer's own paths use.
fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_job(job: i32) -> Result<(), TransferError> {
    if job <= 0 {
        return Err(TransferError::InvalidJob);
    }
    Ok(())
}

/// `TransferJob::send_current_digest`'s message without its `Stream` argument:
/// the same `FileResponse::Digest`, carrying what `init_data_stream_for_cm`
/// reported for the file the job is about to read.
fn digest_message(
    id: i32,
    file_num: i32,
    last_modified: u64,
    file_size: u64,
    is_resume: bool,
) -> Message {
    let mut response = FileResponse::new();
    response.set_digest(FileTransferDigest {
        id,
        file_num,
        last_modified,
        file_size,
        is_resume,
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_file_response(response);
    message
}

/// `io_loop::cancel_transfer_job`'s message: one job, never the session.
fn cancel_message(id: i32) -> Message {
    let mut action = FileAction::new();
    action.set_cancel(FileTransferCancel {
        id,
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_file_action(action);
    message
}

/// `FileTransferSendConfirmRequest` with upstream's two answers.
fn confirm_request(
    id: i32,
    file_num: i32,
    overwrite: bool,
    offset: u32,
) -> FileTransferSendConfirmRequest {
    FileTransferSendConfirmRequest {
        id,
        file_num,
        union: Some(if overwrite {
            file_transfer_send_confirm_request::Union::OffsetBlk(offset)
        } else {
            file_transfer_send_confirm_request::Union::Skip(true)
        }),
        ..Default::default()
    }
}

impl TransferJobState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Failed(_) | Self::Cancelled)
    }
}

/// The effect channel, its byte budget and the session's cancellation: the only
/// three things this owner may do to the wire.
struct Wire {
    outbound: mpsc::Sender<Outbound>,
    bytes: Arc<Semaphore>,
    cancel: CancellationToken,
    /// The session's live file permission, as the writer reads it.
    permission: Arc<PermissionGate>,
    /// The generation of the pass this owner is in, fixed at the boundary where
    /// that pass began ([`TransferOwner::permission_step`]) and never read live:
    /// a send that waited for the byte budget or the writer's queue across a
    /// withdrawal keeps the stamp of the pass that read the data, so it is
    /// dropped instead of being replayed under the new epoch. The owner is the
    /// only writer of this cell and it is not updated inside a pass.
    revision: AtomicU64,
}

impl Wire {
    /// The generation the effects of the pass now being serviced carry.
    fn stamp(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Fixes the generation of the pass that is starting. Called only from the
    /// pass boundary that acts on a withdrawal, before it ends anything.
    fn set_revision(&self, revision: u64) {
        self.revision.store(revision, Ordering::Release);
    }

    /// Queues one wire message, holding `payload` bytes of the budget until the
    /// writer drops the effect. Cancellation is observed before and while
    /// waiting, so a closing session never blocks here, and a message this
    /// function does not hand over was never partially written.
    async fn send(&self, message: Message, payload: usize) -> Result<(), TransferError> {
        self.queue(message, payload, None).await
    }

    /// Queues one wire message and waits until this session's own writer reports
    /// whether it wrote it.
    ///
    /// `Ok(true)` is the only answer that makes the message a written record: a
    /// stale effect the writer dropped, a failed write and a writer that went
    /// away without answering (`Ok(false)`) are all "not written". It is not a
    /// peer acknowledgement — the peer's own answer is not on this wire — and it
    /// is used only for the one record whose completion the owner must prove,
    /// an upload's last `done`.
    async fn send_confirmed(
        &self,
        message: Message,
        payload: usize,
    ) -> Result<bool, TransferError> {
        let (written, confirmation) = oneshot::channel();
        self.queue(message, payload, Some(written)).await?;
        let observed = tokio::select! {
            biased;
            // A closing session owes no terminal fact: the wait ends here rather
            // than turning into a success or a job failure.
            _ = self.cancel.cancelled() => return Err(TransferError::Cancelled),
            observed = confirmation => observed,
        };
        Ok(matches!(observed, Ok(true)))
    }

    /// The one place an effect is built: the byte permit, the stamp and (only for
    /// [`Wire::send_confirmed`]) the write's answer.
    async fn queue(
        &self,
        message: Message,
        payload: usize,
        completion: Option<oneshot::Sender<bool>>,
    ) -> Result<(), TransferError> {
        // At least one permit each, so the same budget also bounds how many
        // small control messages the writer may be holding.
        let bytes = payload.clamp(1, u32::MAX as usize) as u32;
        let permit = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(TransferError::Cancelled),
            permit = Arc::clone(&self.bytes).acquire_many_owned(bytes) => {
                permit.map_err(|_| TransferError::Closed)?
            }
        };
        let effect = Outbound {
            message,
            _permit: permit,
            permission: Arc::clone(&self.permission),
            revision: self.stamp(),
            completion,
        };
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(TransferError::Cancelled),
            sent = self.outbound.send(effect) => sent.map_err(|_| TransferError::Closed),
        }
    }
}

/// The two upstream job tables, named by what they do to the wire: `read` jobs
/// read local files and send blocks (an upload), `write` jobs write blocks the
/// peer sends (a download).
#[derive(Default)]
struct JobTables {
    read: Vec<TransferJob>,
    write: Vec<TransferJob>,
}

impl JobTables {
    fn holds(&self, job: i32) -> bool {
        fs::get_job_immutable(job, &self.read).is_some()
            || fs::get_job_immutable(job, &self.write).is_some()
    }
}

/// One job's last progress sample, for the speed a report carries.
#[derive(Clone, Copy)]
struct Sample {
    transferred: u64,
    at: Instant,
}

/// What the client and the owner's own reports read: the job rows and the events
/// no consumer has taken yet.
struct TransferShared {
    config: TransferConfig,
    rows: Mutex<Vec<TransferRow>>,
    events: Mutex<VecDeque<TransferEvent>>,
    /// Wakes the owner when a poll has made room in `events`.
    events_room: Notify,
    samples: Mutex<HashMap<i32, Sample>>,
    permission: Arc<PermissionGate>,
}

impl TransferShared {
    fn push_row(&self, row: TransferRow) {
        let mut rows = lock(&self.rows);
        rows.push(row);
        // Pruning never removes what can still change: only a terminal row is
        // dropped, and the live ones are what the client is watching.
        while rows.len() > TRANSFER_ROWS_KEPT {
            match rows.iter().position(|row| row.state.is_terminal()) {
                Some(index) => {
                    rows.remove(index);
                }
                None => break,
            }
        }
    }

    fn set_row(&self, job: i32, change: impl FnOnce(&mut TransferRow)) {
        if let Some(row) = lock(&self.rows).iter_mut().find(|row| row.job == job) {
            change(row);
        }
    }

    /// Publishes one event, coalescing only `Progress`: one queued report per job
    /// is as informative as a hundred, while a directory listing, an overwrite
    /// question and a terminal fact are each owed to the consumer exactly once.
    ///
    /// A progress sample is the only event that may be left out: it replaces the
    /// one already queued for its job, and when the queue is full it is skipped
    /// because the job's row carries the same counters until the next sample. Any
    /// other event is always queued: the owner starts each pass with room for the
    /// facts it can publish (`make_room`), so the bound never costs one of them.
    fn push_event(&self, event: TransferEvent) {
        let mut events = lock(&self.events);
        let progress_job = match &event {
            TransferEvent::Progress { job, .. } => Some(*job),
            _ => None,
        };
        if let Some(job) = progress_job {
            let queued = events.iter().position(|queued| {
                matches!(queued, TransferEvent::Progress { job: queued_job, .. } if *queued_job == job)
            });
            match queued {
                Some(index) => {
                    events[index] = event;
                    return;
                }
                None if events.len() >= TRANSFER_EVENTS_KEPT => return,
                None => {}
            }
        }
        events.push_back(event);
    }

    /// The rows that can still change, which is what a new job would add to.
    fn live_rows(&self) -> usize {
        lock(&self.rows)
            .iter()
            .filter(|row| !row.state.is_terminal())
            .count()
    }

    fn decided(&self, job: i32) {
        self.set_row(job, |row| {
            if matches!(
                row.state,
                TransferJobState::Queued | TransferJobState::AwaitingOverwrite
            ) {
                row.state = TransferJobState::Running;
            }
        });
    }

    /// Reports one job's real counters, at most once per second per job
    /// (`update_jobs_status`' own window).
    fn progress(&self, job: &TransferJob) {
        let now = Instant::now();
        let transferred = job.transferred();
        let speed = {
            let mut samples = lock(&self.samples);
            let speed = match samples.get(&job.id()) {
                Some(sample) if now.duration_since(sample.at) < PROGRESS_INTERVAL => return,
                Some(sample) => {
                    let elapsed = now.duration_since(sample.at).as_secs_f64();
                    transferred.saturating_sub(sample.transferred) as f64 / elapsed
                }
                None => 0.0,
            };
            samples.insert(
                job.id(),
                Sample {
                    transferred,
                    at: now,
                },
            );
            speed
        };
        // Upstream reports `job.file_num() - 1`: `read` already moved to the next
        // file once the last block of one was handed over.
        let file_num = (job.file_num() - 1).max(0);
        let finished_size = job.finished_size();
        let total_size = job.total_size();
        self.set_row(job.id(), |row| {
            if matches!(row.state, TransferJobState::Queued) {
                row.state = TransferJobState::Running;
            }
            row.file_num = file_num;
            row.finished_size = finished_size;
            row.transferred = transferred;
            row.total_size = total_size;
        });
        self.push_event(TransferEvent::Progress {
            job: job.id(),
            file_num,
            speed,
            finished_size,
        });
    }

    /// Publishes a job's last state. `file_num` below zero keeps the row's own,
    /// which is what a cancellation knows about the file it interrupted.
    fn finish_row(&self, job: i32, state: TransferJobState, file_num: i32) {
        lock(&self.samples).remove(&job);
        self.set_row(job, |row| {
            row.state = state;
            if file_num >= 0 {
                row.file_num = file_num;
            }
        });
    }

    fn take_snapshot(&self) -> TransferSnapshot {
        self.take_snapshot_limit(usize::MAX)
    }

    /// Drains at most `limit` queued events, oldest first, and leaves the rest
    /// queued for the next poll: a caller's own per-poll limit decides how many
    /// events it takes now, never which facts survive. Rows are never consumed.
    fn take_snapshot_limit(&self, limit: usize) -> TransferSnapshot {
        let (events, taken) = {
            let mut events = lock(&self.events);
            let taken = limit.min(events.len());
            let drained: Vec<TransferEvent> = events.drain(..taken).collect();
            (drained, taken)
        };
        if taken > 0 {
            // The owner may be waiting for exactly this room.
            self.events_room.notify_one();
        }
        TransferSnapshot {
            jobs: lock(&self.rows).clone(),
            events,
        }
    }
}

/// One tick of the upstream reader loop, as `handle_read_jobs` returns it.
enum ReadTick {
    /// No unfinished upload job.
    Idle,
    /// The next job waits for the peer's or the operator's overwrite answer, so no
    /// block may be produced yet.
    Waiting,
    /// One block, digest or error reached the effect channel.
    Sent,
    /// The job reported its own last state and has left the table.
    Finished,
}

/// One upload tick: `base::fs::handle_read_jobs` with its two `Stream` sends
/// turned into effects.
///
/// The order is the pinned algorithm's: `init_data_stream_for_cm` (which opens
/// the file and yields the digest `send_current_digest` would have sent), then
/// one job's `read`, then exactly one of `new_block`, `new_error` or `new_done`,
/// handling one job per tick so a job waiting for a confirmation cannot be
/// overtaken.
///
/// The disk read is awaited directly, never inside a `select!`: a cancelled
/// session stops between blocks, and a read that already started is finished
/// rather than dropped and replayed.
///
/// The last `new_done` is also awaited for the session's own writer's answer: a
/// job is only `Done` once that record really was written. Its blocks stay
/// one-way so the pipeline stays bounded.
async fn upload_step(
    read: &mut Vec<TransferJob>,
    wire: &Wire,
    shared: &TransferShared,
) -> Result<ReadTick, TransferError> {
    // `init_jobs`: open each job's current file and, when overwrite detection is
    // on, ask the digest it carries. An error here is that job's one terminal
    // state (see `release_upload_job`): upstream keeps the job and re-runs the
    // same failing step on every tick, which here would spin on one file forever.
    for index in 0..read.len() {
        if read[index].is_last_job {
            continue;
        }
        let init = read[index].init_data_stream_for_cm().await;
        let id = read[index].id();
        let file_num = read[index].file_num();
        let is_resume = read[index].is_resume;
        match init {
            Ok(Some((last_modified, file_size))) => {
                wire.send(
                    digest_message(id, file_num, last_modified, file_size, is_resume),
                    1,
                )
                .await?;
            }
            // Nothing was owed this tick: the stream is already open and the
            // digest was already asked, or this file needs no question.
            Ok(None) => {}
            Err(error) => {
                let error = error.to_string();
                wire.send(fs::new_error(id, error.as_str(), file_num), 1)
                    .await?;
                release_upload_job(read, shared, id, file_num, error);
                return Ok(ReadTick::Finished);
            }
        }
    }
    let Some(index) = read.iter().position(|job| !job.is_last_job) else {
        return Ok(ReadTick::Idle);
    };
    let id = read[index].id();
    let result = read[index].read().await;
    match result {
        Err(error) => {
            let file_num = read[index].file_num();
            let error = error.to_string();
            // `read` already advanced to the next file, so the peer learns the
            // same file number upstream reports. The error is this job's one
            // terminal state, not a step to retry on the next tick.
            wire.send(fs::new_error(id, error.as_str(), file_num), 1)
                .await?;
            release_upload_job(read, shared, id, file_num, error);
            Ok(ReadTick::Finished)
        }
        Ok(Some(block)) => {
            let bytes = block.data.len();
            shared.progress(&read[index]);
            wire.send(fs::new_block(block), bytes).await?;
            Ok(ReadTick::Sent)
        }
        Ok(None) => {
            if !read[index].job_completed() {
                return Ok(ReadTick::Waiting);
            }
            let removed = fs::remove_job(id, read);
            let error = removed.as_ref().and_then(|job| job.job_error());
            let file_num = removed.as_ref().map_or(0, |job| job.file_num());
            match error {
                Some(error) => {
                    // `handle_read_jobs` sends the peer this error; upstream's own
                    // text for a single skipped file is "skipped".
                    wire.send(fs::new_error(id, error.as_str(), file_num), 1)
                        .await?;
                    if error == "skipped" {
                        shared.finish_row(id, TransferJobState::Done, file_num);
                        shared.push_event(TransferEvent::Skipped { job: id, file_num });
                    } else {
                        shared.finish_row(id, TransferJobState::Failed(error.clone()), file_num);
                        shared.push_event(TransferEvent::Failed {
                            job: id,
                            file_num,
                            error,
                        });
                    }
                }
                None => {
                    // The peer is owed upstream's own last record, and this job's
                    // completion is only real once this session's own writer has
                    // actually written it: an effect sitting in the queue is not a
                    // written record, and the peer's acceptance of the `done` is
                    // not observable on this wire, so it is not what is claimed.
                    // This one send is therefore confirmed; every block before it
                    // is not, which is what keeps `TRANSFER_OUTBOUND_QUEUE` and
                    // the byte budget a bounded pipeline instead of an ACK queue.
                    let written = wire.send_confirmed(fs::new_done(id, file_num), 1).await?;
                    if written {
                        shared.finish_row(id, TransferJobState::Done, file_num);
                        shared.push_event(TransferEvent::Done { job: id, file_num });
                    } else {
                        // The writer dropped it as stale, failed the write, or went
                        // away without answering. That is not a completion: the job
                        // gets the one terminal state it really reached, the peer
                        // is owed nothing further, and no other job or session is
                        // touched.
                        let error = UPLOAD_NOT_WRITTEN.to_owned();
                        shared.finish_row(id, TransferJobState::Failed(error.clone()), file_num);
                        shared.push_event(TransferEvent::Failed {
                            job: id,
                            file_num,
                            error,
                        });
                    }
                }
            }
            Ok(ReadTick::Finished)
        }
    }
}

/// An upload job that cannot produce its own bytes has no next step: upstream
/// keeps the job and re-sends the same error on every tick, which here would
/// spin on one unreadable file forever. The error is therefore this job's one
/// terminal state — the peer was told the real text once, the job leaves the
/// table so nothing can read it again, and the client gets one real `Failed`.
/// No other job and no session is closed.
fn release_upload_job(
    read: &mut Vec<TransferJob>,
    shared: &TransferShared,
    id: i32,
    file_num: i32,
    error: String,
) {
    fs::remove_job(id, read);
    shared.finish_row(id, TransferJobState::Failed(error.clone()), file_num);
    shared.push_event(TransferEvent::Failed {
        job: id,
        file_num,
        error,
    });
}

impl TransferConfig {
    fn peer_windows(&self) -> bool {
        self.peer_platform == "Windows"
    }
}

/// One session's transfer owner.
///
/// Nothing in it is shared with the viewer beyond the two channel ends and
/// [`TransferHandle`], which is what keeps the job tables off the session's
/// reader and writer and off any lock a control message could wait on.
pub struct TransferOwner {
    shared: Arc<TransferShared>,
    commands: mpsc::Receiver<Issued>,
    inbound: mpsc::Receiver<Inbound>,
    wire: Wire,
    cancel: CancellationToken,
    jobs: JobTables,
    /// The permission generation this owner has already acted on.
    permission_revision: u64,
    /// A revocation this owner is still ending, one job per pass.
    revoking: bool,
}

impl TransferOwner {
    /// Runs until the session closes, a channel end goes away, or the writer can
    /// no longer take an effect.
    ///
    /// One pass services one queued command, then one inbound peer message, then
    /// at most one upstream file block, so each pass ends at a wire-effect
    /// boundary: a cancel is observed between two real operations, never inside a
    /// file read or write, and an operation that already started is awaited to
    /// completion rather than dropped. The same boundary is where a revocation is
    /// acted on, and where a pass waits for room in the event queue.
    pub async fn run(mut self) -> TransferExit {
        loop {
            if self.cancel.is_cancelled() {
                return TransferExit::Cancelled;
            }
            if self.make_room().await.is_err() {
                return TransferExit::Cancelled;
            }
            match self.permission_step().await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(TransferError::Cancelled) => return TransferExit::Cancelled,
                Err(_) => return TransferExit::OutboundClosed,
            }
            match self.commands.try_recv() {
                Ok(issued) => {
                    if let Some(exit) = self.command(issued).await {
                        return exit;
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => return TransferExit::CommandClosed,
            }
            match self.inbound.try_recv() {
                Ok(inbound) => {
                    if let Some(exit) = self.received(inbound).await {
                        return exit;
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => return TransferExit::InboundClosed,
            }
            match upload_step(&mut self.jobs.read, &self.wire, &self.shared).await {
                Ok(ReadTick::Sent | ReadTick::Finished) => continue,
                Ok(ReadTick::Idle | ReadTick::Waiting) => {}
                Err(TransferError::Cancelled) => return TransferExit::Cancelled,
                Err(_) => return TransferExit::OutboundClosed,
            }
            if let Some(exit) = self.wait().await {
                return exit;
            }
        }
    }

    /// Waits until the event queue has room for one pass's events: one coalesced
    /// progress sample and one fact. A pass never starts without that room, which
    /// is what bounds the queue without dropping a listing, an overwrite question
    /// or a terminal state; a client that has not polled them yet is what makes
    /// the owner wait. Cancellation and a permission change are both observed
    /// while waiting, so neither is lost behind an unpolled client.
    async fn make_room(&self) -> Result<(), TransferError> {
        loop {
            if lock(&self.shared.events).len() + TRANSFER_EVENT_PASS_ROOM <= TRANSFER_EVENTS_KEPT {
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Err(TransferError::Cancelled),
                _ = self.wire.permission.changed.notified() => {}
                _ = self.shared.events_room.notified() => {}
            }
        }
    }

    /// Brings this owner in line with the session's file permission at a pass
    /// boundary, which is always between two real operations: a started disk read
    /// or write is awaited to completion, and only then is a revocation acted on.
    ///
    /// A withdrawal ends the jobs the owner still holds, one per pass — nothing
    /// alive at a revocation is resumed, because the effects it had queued (and
    /// the ones its pass went on to queue) carry the generation that pass began
    /// under and are dropped by their stamp. No pass that is ending those jobs
    /// services a command, so re-granted work is admitted only once the jobs the
    /// withdrawal reached are gone. Each job is a cancel to the peer, the job
    /// released (a download's partial file removed) and exactly one real `Failed`.
    /// The viewer itself is not closed, and a later re-grant only admits new work.
    ///
    /// `true` means a revocation pass ran, so this pass should not go on to
    /// ordinary work.
    async fn permission_step(&mut self) -> Result<bool, TransferError> {
        let revision = self.wire.permission.revision();
        if revision != self.permission_revision {
            // The boundary itself: the generation the pass starting here stamps
            // its effects with is the one the withdrawal created, because this is
            // the pass that acts on it. Everything an earlier pass queued keeps
            // its own stamp, so a block read before this point is dropped rather
            // than sent under the new epoch — and this pass's own cancels pass.
            self.permission_revision = revision;
            self.wire.set_revision(revision);
            self.revoking = true;
        }
        if !self.revoking {
            return Ok(false);
        }
        let job = self
            .jobs
            .read
            .first()
            .map(|job| job.id())
            .or_else(|| self.jobs.write.first().map(|job| job.id()));
        let Some(job) = job else {
            // Every job the revocation reached is gone; new work is refused by
            // `submit` until the peer grants the permission again.
            self.revoking = false;
            return Ok(true);
        };
        let error = PERMISSION_REVOKED.to_owned();
        match stop_job(
            job,
            &self.shared,
            &self.wire,
            &mut self.jobs,
            TransferJobState::Failed(error.clone()),
        )
        .await
        {
            Ok(()) => {
                self.shared.push_event(TransferEvent::Failed {
                    job,
                    file_num: -1,
                    error,
                });
                Ok(true)
            }
            // The job left the table between the selection and the cancel (an
            // inbound terminal fact for it): the next pass takes the rest.
            Err(TransferError::UnknownJob) => Ok(true),
            Err(error) => Err(error),
        }
    }

    /// Applies one command. A refusal is published for the job it named, so only a
    /// dead wire ends the owner.
    async fn command(&mut self, issued: Issued) -> Option<TransferExit> {
        let named = named_job(&issued.command);
        if issued.revision != self.wire.permission.revision() {
            // Issued under a permission generation that no longer holds. The
            // revocation itself owns what happened to the jobs it reached, so this
            // only reports that the command was not run: nothing a client queued
            // before a revocation is replayed after a re-grant.
            if let Some(job) = named {
                self.shared.push_event(TransferEvent::Failed {
                    job,
                    file_num: -1,
                    error: PERMISSION_REVOKED.to_owned(),
                });
            }
            return None;
        }
        let outcome = match issued.command {
            TransferCommand::ReadDir {
                path,
                include_hidden,
            } => read_directory(&path, include_hidden, &self.wire).await,
            TransferCommand::Download {
                job,
                remote,
                local,
                include_hidden,
                ..
            } => {
                download(
                    job,
                    &remote,
                    &local,
                    include_hidden,
                    &self.shared,
                    &self.wire,
                    &mut self.jobs,
                )
                .await
            }
            TransferCommand::Upload {
                job,
                local,
                remote,
                include_hidden,
                ..
            } => {
                upload(
                    job,
                    &local,
                    &remote,
                    include_hidden,
                    &self.shared,
                    &self.wire,
                    &mut self.jobs,
                )
                .await
            }
            TransferCommand::ConfirmOverwrite {
                job,
                file_num,
                overwrite,
                remember,
                upload,
            } => {
                confirm(
                    job,
                    file_num,
                    overwrite,
                    remember,
                    upload,
                    &self.shared,
                    &self.wire,
                    &mut self.jobs,
                )
                .await
            }
            TransferCommand::Cancel { job } => {
                cancel(job, &self.shared, &self.wire, &mut self.jobs).await
            }
        };
        match outcome {
            Ok(()) => None,
            Err(TransferError::Cancelled) => Some(TransferExit::Cancelled),
            Err(TransferError::Closed) => Some(TransferExit::OutboundClosed),
            Err(error) => {
                if let Some(job) = named {
                    let error = error.to_string();
                    self.shared
                        .finish_row(job, TransferJobState::Failed(error.clone()), -1);
                    self.shared.push_event(TransferEvent::Failed {
                        job,
                        file_num: -1,
                        error,
                    });
                }
                None
            }
        }
    }

    async fn received(&mut self, inbound: Inbound) -> Option<TransferExit> {
        let outcome = match inbound {
            Inbound::Action(action) => action_received(action, &self.shared, &mut self.jobs).await,
            Inbound::Response(response) => {
                response_received(response, &self.shared, &self.wire, &mut self.jobs).await
            }
        };
        match outcome {
            Ok(()) => None,
            Err(TransferError::Cancelled) => Some(TransferExit::Cancelled),
            // An inbound message that cannot be answered ends what it was for: the
            // wire it would answer on is gone.
            Err(_) => Some(TransferExit::OutboundClosed),
        }
    }

    /// Waits for the next command, peer message or permission change.
    /// `Some(exit)` means the owner must stop.
    async fn wait(&mut self) -> Option<TransferExit> {
        enum Ready {
            Command(Issued),
            Inbound(Inbound),
            Permission,
        }
        let ready = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Some(TransferExit::Cancelled),
            _ = self.wire.permission.changed.notified() => Ready::Permission,
            command = self.commands.recv() => match command {
                Some(command) => Ready::Command(command),
                None => return Some(TransferExit::CommandClosed),
            },
            inbound = self.inbound.recv() => match inbound {
                Some(inbound) => Ready::Inbound(inbound),
                None => return Some(TransferExit::InboundClosed),
            },
        };
        match ready {
            Ready::Command(issued) => self.command(issued).await,
            Ready::Inbound(inbound) => self.received(inbound).await,
            // The next pass acts on it, at its own boundary.
            Ready::Permission => None,
        }
    }
}

/// The peer browses its own filesystem: `ReadDir` carries no job id, and the
/// answer is a listing with `id == 0`.
async fn read_directory(
    path: &str,
    include_hidden: bool,
    wire: &Wire,
) -> Result<(), TransferError> {
    let mut action = FileAction::new();
    action.set_read_dir(ReadDir {
        path: path.to_owned(),
        include_hidden,
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_file_action(action);
    wire.send(message, 1).await
}

/// Whether one more job fits in what this session admits.
///
/// Upstream lets a client start as many jobs as it likes; here the client's own
/// row list is the bound, so queued work cannot grow behind a client that never
/// finishes it. The refusal is a real `Failed` for the job that named it (never a
/// `Queued` row, never a completion), published by the command path.
fn admit_job(shared: &TransferShared) -> Result<(), TransferError> {
    if shared.live_rows() >= TRANSFER_ROWS_KEPT {
        return Err(TransferError::TooManyJobs);
    }
    Ok(())
}

/// `Data::SendFiles` with `is_remote`: the peer owns the source, so this side
/// writes under the authorized root and asks the peer for its path.
#[allow(clippy::too_many_arguments)]
async fn download(
    job: i32,
    remote: &str,
    local: &str,
    include_hidden: bool,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    let path = validate_local_path(shared.config.root()?, local)?;
    validate_remote_path(remote, false)?;
    if jobs.holds(job) {
        return Err(TransferError::DuplicateJob);
    }
    admit_job(shared)?;
    let write = TransferJob::new_write(
        job,
        JobType::Generic,
        remote.to_owned(),
        DataSource::FilePath(path.clone()),
        0,
        include_hidden,
        true,
        shared.config.overwrite_detection,
    );
    shared.push_row(TransferRow {
        job,
        direction: TransferDirection::Download,
        state: TransferJobState::Queued,
        file_num: 0,
        // No file list yet: the peer's own `Dir` answer is what sizes this job.
        total_size: 0,
        finished_size: 0,
        transferred: 0,
        remote: remote.to_owned(),
        local: path.to_string_lossy().into_owned(),
    });
    jobs.write.push(write);
    wire.send(
        fs::new_send(job, JobType::Generic, remote.to_owned(), 0, include_hidden),
        1,
    )
    .await
}

/// `Data::SendFiles` without `is_remote`: the source is a local path under the
/// authorized root, and the peer is asked to receive the list this side will
/// stream.
#[allow(clippy::too_many_arguments)]
async fn upload(
    job: i32,
    local: &str,
    remote: &str,
    include_hidden: bool,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    let path = validate_local_path(shared.config.root()?, local)?;
    validate_remote_path(remote, false)?;
    if jobs.holds(job) {
        return Err(TransferError::DuplicateJob);
    }
    admit_job(shared)?;
    let read = match TransferJob::new_read(
        job,
        JobType::Generic,
        remote.to_owned(),
        DataSource::FilePath(path.clone()),
        0,
        include_hidden,
        false,
        shared.config.overwrite_detection,
    ) {
        Ok(read) => read,
        Err(error) => {
            // Upstream's `handle_job_status(id, -1, err)`: no job exists, and
            // nothing is owed to the peer.
            let error = error.to_string();
            shared.push_row(TransferRow {
                job,
                direction: TransferDirection::Upload,
                state: TransferJobState::Failed(error.clone()),
                file_num: -1,
                total_size: 0,
                finished_size: 0,
                transferred: 0,
                remote: remote.to_owned(),
                local: path.to_string_lossy().into_owned(),
            });
            shared.push_event(TransferEvent::Failed {
                job,
                file_num: -1,
                error,
            });
            return Ok(());
        }
    };
    let mut files = read.files().clone();
    if shared.config.peer_windows() {
        // Upstream: a Windows peer needs its own separator, which this side's
        // name validation would otherwise read as one long file name.
        fs::transform_windows_path(&mut files);
    }
    let file_num = read.file_num();
    let total_size = read.total_size();
    let request = fs::new_receive(job, remote.to_owned(), file_num, files, total_size);
    shared.push_row(TransferRow {
        job,
        direction: TransferDirection::Upload,
        state: TransferJobState::Queued,
        file_num,
        total_size,
        finished_size: 0,
        transferred: 0,
        remote: remote.to_owned(),
        local: path.to_string_lossy().into_owned(),
    });
    jobs.read.push(read);
    wire.send(request, 1).await
}

/// `Data::SetConfirmOverrideFile`: the operator's answer to one overwrite
/// question. `upload` selects the table exactly as upstream's `is_upload` does,
/// and with it whether the peer is answered here.
#[allow(clippy::too_many_arguments)]
async fn confirm(
    job: i32,
    file_num: i32,
    overwrite: bool,
    remember: bool,
    upload: bool,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    let request = confirm_request(job, file_num, overwrite, 0);
    if upload {
        let Some(named) = fs::get_job(job, &mut jobs.read) else {
            return Err(TransferError::UnknownJob);
        };
        if remember {
            named.set_overwrite_strategy(Some(overwrite));
        }
        named.confirm(&request).await;
        // Upstream sends nothing here: on the uploading side this answer only
        // releases its own reader, and what arrives next is what tells the peer.
        // Kept exactly as the pinned client does it.
        shared.decided(job);
    } else {
        let Some(named) = fs::get_job(job, &mut jobs.write) else {
            return Err(TransferError::UnknownJob);
        };
        if remember {
            named.set_overwrite_strategy(Some(overwrite));
        }
        named.confirm(&request).await;
        shared.decided(job);
        wire.send(fs::new_send_confirm(request), 1).await?;
    }
    Ok(())
}

/// `io_loop::cancel_transfer_job`: one job, one wire message, and the partial
/// download it leaves behind is removed. It never closes the viewer and never
/// acknowledges a record.
async fn cancel(
    job: i32,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    stop_job(job, shared, wire, jobs, TransferJobState::Cancelled).await
}

/// Ends one job of this session at a pass boundary: the peer is told to stop, the
/// job leaves its table, a partial download is removed, and the row gets the last
/// state the caller decided on. The only difference between an operator's cancel
/// and a revocation is that state.
async fn stop_job(
    job: i32,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
    state: TransferJobState,
) -> Result<(), TransferError> {
    if !jobs.holds(job) {
        return Err(TransferError::UnknownJob);
    }
    wire.send(cancel_message(job), 1).await?;
    if let Some(removed) = fs::remove_job(job, &mut jobs.write) {
        removed.remove_download_file();
    }
    fs::remove_job(job, &mut jobs.read);
    shared.finish_row(job, state, -1);
    Ok(())
}

/// The client-side `FileAction` the pinned session loop answers: the peer's
/// answer to a digest this side sent about an upload.
///
/// `ReadDir`/`Send`/`Receive`/`Cancel` are what a *host* answers a controller
/// with; this viewer is never the peer's file service, so none of them is
/// answered here.
async fn action_received(
    action: FileAction,
    shared: &TransferShared,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    if let Some(file_action::Union::SendConfirm(request)) = action.union {
        if let Some(named) = fs::get_job(request.id, &mut jobs.read) {
            named.confirm(&request).await;
            shared.decided(request.id);
        }
    }
    Ok(())
}

/// One peer `FileResponse`, dispatched exactly as the pinned client's session loop
/// dispatches it.
async fn response_received(
    response: FileResponse,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    match response.union {
        Some(file_response::Union::Dir(directory)) => {
            directory_received(directory, shared, wire, jobs).await
        }
        Some(file_response::Union::Digest(digest)) => {
            digest_received(digest, shared, wire, jobs).await
        }
        Some(file_response::Union::Block(block)) => block_received(block, shared, wire, jobs).await,
        Some(file_response::Union::Done(done)) => {
            // The peer's `Done` is what makes a received file real: rename the
            // `.download` beside it and restore its time, as upstream does. A
            // local write completing earlier is not this fact, and neither is a
            // `Done` for an id this session does not hold: a repeat, or a job that
            // already ended, cannot make a download real a second time, so it
            // publishes nothing at all.
            let Some(job) = fs::remove_job(done.id, &mut jobs.write) else {
                return Ok(());
            };
            job.modify_time();
            match job.job_error() {
                Some(error) => {
                    shared.finish_row(
                        done.id,
                        TransferJobState::Failed(error.clone()),
                        done.file_num,
                    );
                    shared.push_event(TransferEvent::Failed {
                        job: done.id,
                        file_num: done.file_num,
                        error,
                    });
                }
                None => {
                    shared.finish_row(done.id, TransferJobState::Done, done.file_num);
                    shared.push_event(TransferEvent::Done {
                        job: done.id,
                        file_num: done.file_num,
                    });
                }
            }
            Ok(())
        }
        Some(file_response::Union::Error(failure)) => {
            // The peer refused either this side's download or its upload. Only a
            // job this session still holds has a fact to report: an id no table
            // holds (a repeat, or one that already ended) gets no job event, so a
            // stray error can never look like a job of this session failing.
            let held = fs::remove_job(failure.id, &mut jobs.write)
                .or_else(|| fs::remove_job(failure.id, &mut jobs.read))
                .is_some();
            if !held {
                return Ok(());
            }
            // Upstream shows the peer's own text here; it stays a job diagnostic
            // and never becomes a viewer error or a snapshot string.
            shared.finish_row(
                failure.id,
                TransferJobState::Failed(failure.error.clone()),
                failure.file_num,
            );
            shared.push_event(TransferEvent::Failed {
                job: failure.id,
                file_num: failure.file_num,
                error: failure.error,
            });
            Ok(())
        }
        Some(file_response::Union::EmptyDirs(response)) => {
            shared.push_event(TransferEvent::EmptyDirs {
                path: response.path,
                directories: response.empty_dirs,
            });
            Ok(())
        }
        // A variant this build does not know is no fact of this session and has
        // no answer here: the owner ends instead of reading it as a success.
        Some(_) => Err(TransferError::UnsupportedMessage),
        None => Ok(()),
    }
}

/// What one inbound listing turned out to be.
enum Listing {
    /// No job is waiting for this id, so it is the operator's own browser.
    Browsed(FileDirectory),
    /// A download job accepted the peer's file list.
    Applied {
        job: i32,
        path: String,
        total_size: u64,
        file_num: i32,
        files: Vec<FileEntry>,
    },
    /// The pinned name validation refused the peer's list.
    Refused { job: i32, error: String },
}

async fn directory_received(
    directory: FileDirectory,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    let FileDirectory {
        id,
        path,
        mut entries,
        ..
    } = directory;
    if shared.config.peer_windows() {
        fs::transform_windows_path(&mut entries);
    }
    let listing = match fs::get_job(id, &mut jobs.write) {
        Some(named) => match named.set_files(entries.clone()) {
            Err(error) => Listing::Refused {
                job: id,
                error: error.to_string(),
            },
            Ok(()) => {
                named.set_finished_size_on_resume();
                Listing::Applied {
                    job: id,
                    path,
                    total_size: named.total_size(),
                    file_num: named.file_num(),
                    files: named.files().clone(),
                }
            }
        },
        None => Listing::Browsed(FileDirectory {
            id,
            path,
            entries,
            ..Default::default()
        }),
    };
    match listing {
        Listing::Browsed(directory) => shared.push_event(TransferEvent::Directory(directory)),
        Listing::Applied {
            job,
            path,
            total_size,
            file_num,
            files,
        } => {
            shared.set_row(job, |row| {
                row.total_size = total_size;
                row.file_num = file_num;
            });
            shared.decided(job);
            shared.push_event(TransferEvent::Directory(FileDirectory {
                id: job,
                path,
                entries: files,
                ..Default::default()
            }));
        }
        Listing::Refused { job, error } => {
            // A refused list is never half-applied: the job stops and the peer is
            // told, as upstream's `cancel_transfer_job` + `handle_job_status` do.
            cancel(job, shared, wire, jobs).await?;
            shared.finish_row(job, TransferJobState::Failed(error.clone()), -1);
            shared.push_event(TransferEvent::Failed {
                job,
                file_num: -1,
                error,
            });
        }
    }
    Ok(())
}

async fn digest_received(
    digest: FileTransferDigest,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    if digest.is_upload {
        // The peer asks about a file this side uploads: the question is whether to
        // replace what the peer already has.
        let decision = match fs::get_job_immutable(digest.id, &jobs.read) {
            Some(named) => match named.files().get(digest.file_num.max(0) as usize) {
                Some(file) => match &named.data_source {
                    DataSource::FilePath(base) => {
                        let read_path = fs::get_string(&TransferJob::join(base, &file.name));
                        let mut overwrite = named.default_overwrite_strategy();
                        let mut offset = 0;
                        if digest.is_identical && named.is_resume && digest.transferred_size > 0 {
                            overwrite = Some(true);
                            offset = digest.transferred_size as u32;
                        }
                        Some((read_path, overwrite, offset))
                    }
                    DataSource::MemoryCursor(_) => None,
                },
                None => None,
            },
            None => None,
        };
        let Some((read_path, overwrite, offset)) = decision else {
            return Ok(());
        };
        match overwrite {
            Some(overwrite) => {
                let request = confirm_request(digest.id, digest.file_num, overwrite, offset);
                if let Some(named) = fs::get_job(digest.id, &mut jobs.read) {
                    named.confirm(&request).await;
                }
                shared.decided(digest.id);
                wire.send(fs::new_send_confirm(request), 1).await?;
            }
            None => {
                shared.set_row(digest.id, |row| {
                    row.state = TransferJobState::AwaitingOverwrite
                });
                shared.push_event(TransferEvent::Overwrite {
                    job: digest.id,
                    file_num: digest.file_num,
                    read_path,
                    upload: true,
                    identical: digest.is_identical,
                });
            }
        }
        return Ok(());
    }
    // A download: the peer offers a file and this side decides from the real local
    // file, exactly as `is_write_need_confirmation` does.
    let decision = match fs::get_job_immutable(digest.id, &jobs.write) {
        Some(named) => match named.files().get(digest.file_num.max(0) as usize) {
            Some(file) => match &named.data_source {
                DataSource::FilePath(base) => Some((
                    fs::get_string(&TransferJob::join(base, &file.name)),
                    named.is_resume,
                    named.default_overwrite_strategy(),
                )),
                DataSource::MemoryCursor(_) => None,
            },
            None => None,
        },
        None => None,
    };
    let Some((write_path, is_resume, overwrite)) = decision else {
        return Ok(());
    };
    // Remembered on the job, which is where the `.digest` sidecar beside a resume
    // read comes from.
    if let Some(named) = fs::get_job(digest.id, &mut jobs.write) {
        named.set_digest(digest.file_size, digest.last_modified);
    }
    match fs::is_write_need_confirmation(is_resume, &write_path, &digest) {
        Ok(fs::DigestCheckResult::IsSame) => {
            let request = confirm_request(digest.id, digest.file_num, false, 0);
            answer_download_confirm(request, shared, wire, jobs).await?;
        }
        Ok(fs::DigestCheckResult::NeedConfirm(local)) => {
            let mut overwrite = overwrite;
            let mut offset = 0;
            if local.is_identical && is_resume && local.transferred_size > 0 {
                overwrite = Some(true);
                offset = local.transferred_size as u32;
            }
            match overwrite {
                Some(overwrite) => {
                    let request = confirm_request(digest.id, digest.file_num, overwrite, offset);
                    answer_download_confirm(request, shared, wire, jobs).await?;
                }
                None => {
                    shared.set_row(digest.id, |row| {
                        row.state = TransferJobState::AwaitingOverwrite
                    });
                    shared.push_event(TransferEvent::Overwrite {
                        job: digest.id,
                        file_num: digest.file_num,
                        read_path: write_path,
                        upload: false,
                        identical: local.is_identical,
                    });
                }
            }
        }
        Ok(fs::DigestCheckResult::NoSuchFile) => {
            let request = confirm_request(digest.id, digest.file_num, true, 0);
            answer_download_confirm(request, shared, wire, jobs).await?;
        }
        Err(error) => {
            // Upstream prints this and answers nothing, which leaves the peer
            // waiting for an answer that will never come; the job is stopped and
            // reported instead.
            let error = error.to_string();
            cancel(digest.id, shared, wire, jobs).await?;
            shared.finish_row(
                digest.id,
                TransferJobState::Failed(error.clone()),
                digest.file_num,
            );
            shared.push_event(TransferEvent::Failed {
                job: digest.id,
                file_num: digest.file_num,
                error,
            });
        }
    }
    Ok(())
}

/// Applies the local answer and then tells the peer, in that order, exactly as
/// upstream's download-side confirmation does.
async fn answer_download_confirm(
    request: FileTransferSendConfirmRequest,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    if let Some(named) = fs::get_job(request.id, &mut jobs.write) {
        named.confirm(&request).await;
    }
    shared.decided(request.id);
    wire.send(fs::new_send_confirm(request), 1).await
}

async fn block_received(
    block: FileTransferBlock,
    shared: &TransferShared,
    wire: &Wire,
    jobs: &mut JobTables,
) -> Result<(), TransferError> {
    let id = block.id;
    let written = match fs::get_job(id, &mut jobs.write) {
        Some(named) => {
            let result = named.write(block).await;
            if result.is_ok() {
                shared.progress(named);
            }
            Some(result)
        }
        None => None,
    };
    match written {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => {
            // Upstream leaves a `// to-do: add "skip"` here and keeps accepting
            // blocks after a failed write; a real disk error cannot be ignored, so
            // the peer is told to stop and the client is told why.
            let error = error.to_string();
            cancel(id, shared, wire, jobs).await?;
            shared.finish_row(id, TransferJobState::Failed(error.clone()), -1);
            shared.push_event(TransferEvent::Failed {
                job: id,
                file_num: -1,
                error,
            });
            Ok(())
        }
        // A block for a job this session does not hold is not this owner's to act
        // on; upstream ignores it too.
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::{
        FileTransferDone, FileTransferError, FileType, ReadEmptyDirsResponse, message,
    };
    use hbb_common::compress::decompress;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A directory the test owns from creation to removal.
    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new(prefix: &str) -> Self {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default();
            let path = std::env::temp_dir().join(format!(
                "rd_engine_transfer_{prefix}_{}_{}",
                std::process::id(),
                stamp
            ));
            std::fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.path.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::write(&path, contents).expect("write fixture");
            path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn entry(name: &str, size: u64) -> FileEntry {
        FileEntry {
            name: name.to_owned(),
            entry_type: FileType::File.into(),
            size,
            modified_time: 1,
            ..Default::default()
        }
    }

    /// Bytes that really are `len` long on the wire: a block pays for the byte
    /// budget with what it sends, and a compressible fixture would pay far less.
    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    fn action(wire: &Message) -> &FileAction {
        match wire.union.as_ref() {
            Some(message::Union::FileAction(action)) => action,
            other => panic!("expected a file action, got {other:?}"),
        }
    }

    fn response(wire: &Message) -> &FileResponse {
        match wire.union.as_ref() {
            Some(message::Union::FileResponse(response)) => response,
            other => panic!("expected a file response, got {other:?}"),
        }
    }

    /// One started session over the same seam the viewer uses: the owner task, the
    /// client's handle, and both channel ends.
    struct Session {
        handle: TransferHandle,
        inbound: mpsc::Sender<Inbound>,
        outbound: mpsc::Receiver<Outbound>,
        cancel: CancellationToken,
        task: tokio::task::JoinHandle<TransferExit>,
    }

    impl Session {
        fn start(root: &Path) -> Self {
            let cancel = CancellationToken::new();
            let TransferStart {
                owner,
                handle,
                inbound,
                outbound,
            } = start(
                TransferConfig::new(Some(root.to_path_buf()), "Linux", "1.4.9"),
                cancel.clone(),
            );
            Self {
                handle,
                inbound,
                outbound,
                cancel,
                task: tokio::spawn(owner.run()),
            }
        }

        async fn peer(&self, inbound: Inbound) {
            self.inbound.send(inbound).await.expect("peer message");
        }

        /// Queues `count` peer facts the client has not taken yet, one event each.
        async fn empty_dirs(&self, count: usize) {
            for index in 0..count {
                self.peer(Inbound::Response(FileResponse {
                    union: Some(file_response::Union::EmptyDirs(ReadEmptyDirsResponse {
                        path: format!("/sdcard/{index}"),
                        empty_dirs: Vec::new(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }))
                .await;
            }
        }

        /// The next wire effect the owner owes, still in the test's hand: what a
        /// test asserts about its stamp or its write before answering it.
        async fn effect_raw(&mut self) -> Outbound {
            tokio::time::timeout(Duration::from_secs(2), self.outbound.recv())
                .await
                .expect("an effect was owed")
                .expect("the owner is still running")
        }

        /// The next wire effect, reported to the owner as written — which is what
        /// the session's own writer does after the write it owns. Only an upload's
        /// last `done` waits for that answer; a block's is a no-op.
        async fn effect(&mut self) -> Message {
            let effect = self.effect_raw().await;
            let message = effect.message().clone();
            effect.complete(true);
            message
        }

        /// Asserts nothing is owed during a window: a job waiting for an answer
        /// must not stream.
        async fn quiet(&mut self) {
            if let Ok(Some(effect)) =
                tokio::time::timeout(Duration::from_millis(150), self.outbound.recv()).await
            {
                panic!("unexpected effect {:?}", effect.message());
            }
        }

        /// Takes events until one matches, returning everything seen.
        async fn events(&self, matches: impl Fn(&TransferEvent) -> bool) -> Vec<TransferEvent> {
            let mut seen = Vec::new();
            for _ in 0..300 {
                for event in self.handle.take_snapshot().events {
                    let hit = matches(&event);
                    seen.push(event);
                    if hit {
                        return seen;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("no matching transfer event; saw {seen:?}");
        }

        /// Starts one upload, answers the peer's own digest handshake, and returns
        /// the effect it last owed: the final `done`, whose write the owner waits
        /// for. Every effect before it is reported as written.
        async fn upload_to_final_done(&mut self, job: i32, source: &Path) -> Outbound {
            self.handle
                .submit(TransferCommand::Upload {
                    job,
                    local: source.to_string_lossy().into_owned(),
                    remote: "/sdcard".into(),
                    file_num: 0,
                    include_hidden: false,
                })
                .expect("accepted");
            let receive = self.effect().await;
            match action(&receive).union.as_ref() {
                Some(file_action::Union::Receive(request)) => assert_eq!(request.id, job),
                other => panic!("expected a receive request, got {other:?}"),
            }
            let digest = self.effect().await;
            match response(&digest).union.as_ref() {
                Some(file_response::Union::Digest(digest)) => assert_eq!(digest.id, job),
                other => panic!("expected a digest, got {other:?}"),
            }
            self.peer(Inbound::Action(FileAction {
                union: Some(file_action::Union::SendConfirm(
                    FileTransferSendConfirmRequest {
                        id: job,
                        file_num: 0,
                        union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }))
            .await;
            loop {
                let effect = self.effect_raw().await;
                let done = matches!(
                    response(effect.message()).union.as_ref(),
                    Some(file_response::Union::Done(_))
                );
                if done {
                    return effect;
                }
                effect.complete(true);
            }
        }

        async fn stop(self) {
            self.cancel.cancel();
            let exit = tokio::time::timeout(Duration::from_secs(2), self.task)
                .await
                .expect("the owner stops")
                .expect("the owner task did not panic");
            assert_eq!(exit, TransferExit::Cancelled);
        }
    }

    #[test]
    fn a_local_path_must_stay_under_the_authorized_root() {
        let root = Path::new("/storage/Users/currentUser/Download");
        assert_eq!(
            validate_local_path(root, "/storage/Users/currentUser/Download/a.txt"),
            Ok(root.join("a.txt"))
        );
        assert!(validate_local_path(root, "/storage/Users/currentUser/Download").is_ok());
        // A sibling directory that merely starts with the root's text is not the
        // root: the check is component-wise.
        for outside in [
            "/storage/Users/currentUser/Download-other/a.txt",
            "/storage/Users/currentUser/Download/../secret",
            "/storage/Users/currentUser/Download/./a.txt/../b",
            "Download/a.txt",
            "/etc/passwd",
            "",
            "/storage/Users/currentUser/Download/a\0b",
        ] {
            assert_eq!(
                validate_local_path(root, outside),
                Err(TransferError::LocalPathInvalid),
                "{outside}"
            );
        }
    }

    #[test]
    fn a_remote_path_must_be_absolute_and_without_traversal() {
        assert!(validate_remote_path("/sdcard", false).is_ok());
        assert!(validate_remote_path("C:\\Users", false).is_ok());
        // The one empty remote path: `ReadDir`'s own home-directory request.
        assert!(validate_remote_path("", true).is_ok());
        for bad in [
            "",
            "relative/path",
            "./x",
            "/sdcard/../secret",
            "/sdcard/\0",
        ] {
            assert_eq!(
                validate_remote_path(bad, false),
                Err(TransferError::RemotePathInvalid),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn a_command_that_cannot_work_is_refused_before_it_reaches_the_owner() {
        let temp = TempRoot::new("submit");
        let mut session = Session::start(temp.path());
        let inside = temp.path().join("a.txt").to_string_lossy().into_owned();
        assert_eq!(
            session.handle.submit(TransferCommand::Upload {
                job: 1,
                local: "/etc/passwd".into(),
                remote: "/sdcard".into(),
                file_num: 0,
                include_hidden: false,
            }),
            Err(TransferError::LocalPathInvalid)
        );
        assert_eq!(
            session.handle.submit(TransferCommand::Upload {
                job: 0,
                local: inside.clone(),
                remote: "/sdcard".into(),
                file_num: 0,
                include_hidden: false,
            }),
            Err(TransferError::InvalidJob)
        );
        // A resume this owner cannot honour is refused rather than started at file
        // zero as if it were a fresh transfer.
        assert_eq!(
            session.handle.submit(TransferCommand::Download {
                job: 3,
                remote: "/sdcard/a".into(),
                local: inside,
                file_num: 1,
                include_hidden: false,
            }),
            Err(TransferError::ResumeUnsupported)
        );
        assert_eq!(
            session.handle.submit(TransferCommand::ReadDir {
                path: "relative".into(),
                include_hidden: false,
            }),
            Err(TransferError::RemotePathInvalid)
        );
        assert_eq!(
            session.handle.submit(TransferCommand::Cancel { job: 0 }),
            Err(TransferError::InvalidJob)
        );
        // None of those reached the owner: nothing is owed on the wire and no row
        // mentions them.
        assert!(session.handle.jobs().is_empty());
        session.quiet().await;
        session.stop().await;
    }

    #[tokio::test]
    async fn a_peer_listing_reaches_the_client_as_a_directory_event() {
        let temp = TempRoot::new("listing");
        let mut session = Session::start(temp.path());
        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Dir(FileDirectory {
                    id: 0,
                    path: "/sdcard".to_owned(),
                    entries: vec![entry("note.txt", 5)],
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;
        let events = session
            .events(|event| matches!(event, TransferEvent::Directory(_)))
            .await;
        match events.last() {
            Some(TransferEvent::Directory(directory)) => {
                assert_eq!(directory.id, 0);
                assert_eq!(directory.path, "/sdcard");
                assert_eq!(directory.entries.len(), 1);
                assert_eq!(directory.entries[0].name, "note.txt");
                assert_eq!(directory.entries[0].size, 5);
            }
            other => panic!("expected a directory event, got {other:?}"),
        }
        // A listing is not a job.
        assert!(session.handle.jobs().is_empty());
        session.quiet().await;
        session.stop().await;
    }

    #[tokio::test]
    async fn a_download_writes_the_peers_bytes_and_ends_on_the_peers_done() {
        let temp = TempRoot::new("download");
        let mut session = Session::start(temp.path());
        let local = temp.path().join("out").join("file.txt");
        session
            .handle
            .submit(TransferCommand::Download {
                job: 7,
                remote: "/sdcard/file.txt".into(),
                local: local.to_string_lossy().into_owned(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("accepted");

        let send = session.effect().await;
        match action(&send).union.as_ref() {
            Some(file_action::Union::Send(request)) => {
                assert_eq!(request.id, 7);
                assert_eq!(request.path, "/sdcard/file.txt");
            }
            other => panic!("expected a send request, got {other:?}"),
        }

        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Dir(FileDirectory {
                    id: 7,
                    path: "/sdcard".to_owned(),
                    entries: vec![entry("", 6)],
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;
        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Digest(FileTransferDigest {
                    id: 7,
                    file_num: 0,
                    last_modified: 1,
                    file_size: 6,
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;

        // No local file exists yet, so the answer is upstream's "no such file"
        // offset rather than a question for the operator.
        let confirm = session.effect().await;
        match action(&confirm).union.as_ref() {
            Some(file_action::Union::SendConfirm(request)) => {
                assert_eq!(request.id, 7);
                assert_eq!(
                    request.union.as_ref(),
                    Some(&file_transfer_send_confirm_request::Union::OffsetBlk(0))
                );
            }
            other => panic!("expected a send confirm, got {other:?}"),
        }

        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Block(FileTransferBlock {
                    id: 7,
                    file_num: 0,
                    data: b"hello!".to_vec().into(),
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;

        // Real bytes landed, but the peer has not finished: a completed local write
        // is not a completed download.
        let before = session
            .events(|event| matches!(event, TransferEvent::Progress { .. }))
            .await;
        assert!(
            before
                .iter()
                .all(|event| !matches!(event, TransferEvent::Done { .. }))
        );
        assert!(!local.exists(), "a partial write is not the file");
        assert_eq!(
            std::fs::read(format!("{}.download", local.to_string_lossy()))
                .expect("the partial file"),
            b"hello!"
        );

        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Done(FileTransferDone {
                    id: 7,
                    file_num: 1,
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;

        let events = session
            .events(|event| matches!(event, TransferEvent::Done { .. }))
            .await;
        assert!(events.iter().any(|event| matches!(
            event,
            TransferEvent::Done {
                job: 7,
                file_num: 1
            }
        )));
        assert_eq!(std::fs::read(&local).expect("the received file"), b"hello!");
        let rows = session.handle.jobs();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, TransferJobState::Done);
        assert_eq!(rows[0].total_size, 6);
        assert_eq!(rows[0].finished_size, 6);
        session.stop().await;
    }

    #[tokio::test]
    async fn a_traversing_file_list_from_the_peer_is_refused_and_the_job_stops() {
        let temp = TempRoot::new("traversal");
        let mut session = Session::start(temp.path());
        session
            .handle
            .submit(TransferCommand::Download {
                job: 5,
                remote: "/sdcard/escape.txt".into(),
                local: temp
                    .path()
                    .join("escape.txt")
                    .to_string_lossy()
                    .into_owned(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("accepted");
        let _send = session.effect().await;
        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Dir(FileDirectory {
                    id: 5,
                    path: "/sdcard".to_owned(),
                    entries: vec![entry("../../../escape.txt", 4)],
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;
        // The refused list stops the job and tells the peer, upstream's own
        // `cancel_transfer_job` + `handle_job_status` pair.
        let cancel = session.effect().await;
        match action(&cancel).union.as_ref() {
            Some(file_action::Union::Cancel(request)) => assert_eq!(request.id, 5),
            other => panic!("expected a cancel, got {other:?}"),
        }
        let rows = session.handle.jobs();
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].state, TransferJobState::Failed(_)));
        assert_eq!(rows[0].total_size, 0, "the refused list was not applied");
        let events = session
            .events(|event| matches!(event, TransferEvent::Failed { job: 5, .. }))
            .await;
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TransferEvent::Failed { job: 5, .. }))
        );
        session.stop().await;
    }

    #[tokio::test]
    async fn an_upload_streams_only_after_the_peers_overwrite_answer() {
        let temp = TempRoot::new("upload");
        let mut session = Session::start(temp.path());
        let contents = vec![b'x'; 200];
        let source = temp.file("data.bin", &contents);
        session
            .handle
            .submit(TransferCommand::Upload {
                job: 9,
                local: source.to_string_lossy().into_owned(),
                remote: "/sdcard".into(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("accepted");

        let receive = session.effect().await;
        match action(&receive).union.as_ref() {
            Some(file_action::Union::Receive(request)) => {
                assert_eq!(request.id, 9);
                assert_eq!(request.path, "/sdcard");
                assert_eq!(request.files.len(), 1);
                assert_eq!(request.total_size, 200);
            }
            other => panic!("expected a receive request, got {other:?}"),
        }
        let digest = session.effect().await;
        match response(&digest).union.as_ref() {
            Some(file_response::Union::Digest(digest)) => {
                assert_eq!(digest.id, 9);
                assert_eq!(digest.file_size, 200);
            }
            other => panic!("expected a digest, got {other:?}"),
        }
        // Nothing streams while the peer's answer is outstanding.
        session.quiet().await;

        session
            .peer(Inbound::Action(FileAction {
                union: Some(file_action::Union::SendConfirm(
                    FileTransferSendConfirmRequest {
                        id: 9,
                        file_num: 0,
                        union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }))
            .await;

        let mut streamed = Vec::new();
        let done = loop {
            let message = session.effect().await;
            match response(&message).union.as_ref() {
                Some(file_response::Union::Block(block)) => {
                    if block.data.is_empty() {
                        continue;
                    }
                    streamed.extend(if block.compressed {
                        decompress(&block.data)
                    } else {
                        block.data.to_vec()
                    });
                }
                Some(file_response::Union::Done(done)) => break (*done).clone(),
                other => panic!("unexpected wire message {other:?}"),
            }
        };
        assert_eq!(streamed, contents);
        assert_eq!(done.id, 9);
        session
            .events(|event| matches!(event, TransferEvent::Done { job: 9, .. }))
            .await;
        session.stop().await;
    }

    #[tokio::test]
    async fn a_skipped_upload_reports_the_upstream_skip_and_stops_the_job() {
        let temp = TempRoot::new("skip");
        let mut session = Session::start(temp.path());
        let source = temp.file("data.bin", b"0123456789");
        session
            .handle
            .submit(TransferCommand::Upload {
                job: 9,
                local: source.to_string_lossy().into_owned(),
                remote: "/sdcard".into(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("accepted");
        let _receive = session.effect().await;
        let _digest = session.effect().await;
        session
            .peer(Inbound::Action(FileAction {
                union: Some(file_action::Union::SendConfirm(
                    FileTransferSendConfirmRequest {
                        id: 9,
                        file_num: 0,
                        union: Some(file_transfer_send_confirm_request::Union::Skip(true)),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }))
            .await;

        let error = session.effect().await;
        match response(&error).union.as_ref() {
            Some(file_response::Union::Error(failure)) => {
                assert_eq!(failure.id, 9);
                assert_eq!(failure.error, "skipped");
            }
            other => panic!("expected upstream's skip error, got {other:?}"),
        }
        session
            .events(|event| matches!(event, TransferEvent::Skipped { job: 9, .. }))
            .await;
        let rows = session.handle.jobs();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, TransferJobState::Done);
        session.stop().await;
    }

    #[tokio::test]
    async fn a_cancel_ends_only_the_job_it_names() {
        let temp = TempRoot::new("cancel");
        let mut session = Session::start(temp.path());
        for job in [11, 12] {
            session
                .handle
                .submit(TransferCommand::Download {
                    job,
                    remote: format!("/sdcard/{job}"),
                    local: temp
                        .path()
                        .join(format!("{job}.txt"))
                        .to_string_lossy()
                        .into_owned(),
                    file_num: 0,
                    include_hidden: false,
                })
                .expect("accepted");
        }
        for job in [11, 12] {
            let send = session.effect().await;
            match action(&send).union.as_ref() {
                Some(file_action::Union::Send(request)) => assert_eq!(request.id, job),
                other => panic!("expected a send request, got {other:?}"),
            }
        }
        session
            .handle
            .submit(TransferCommand::Cancel { job: 11 })
            .expect("accepted");
        let cancel = session.effect().await;
        match action(&cancel).union.as_ref() {
            Some(file_action::Union::Cancel(request)) => assert_eq!(request.id, 11),
            other => panic!("expected a cancel, got {other:?}"),
        }
        let rows = session.handle.jobs();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].state, TransferJobState::Cancelled);
        assert_eq!(rows[1].state, TransferJobState::Queued);

        // An id this session does not hold is refused and never reaches the peer.
        session
            .handle
            .submit(TransferCommand::Cancel { job: 999 })
            .expect("queued");
        session
            .events(|event| matches!(event, TransferEvent::Failed { job: 999, .. }))
            .await;
        session.quiet().await;
        session.stop().await;
    }

    #[test]
    fn progress_reports_coalesce_while_terminal_events_are_kept() {
        let shared = TransferShared {
            config: TransferConfig::new(None, "Linux", "1.4.9"),
            rows: Mutex::new(vec![TransferRow {
                job: 1,
                direction: TransferDirection::Download,
                state: TransferJobState::Running,
                file_num: 0,
                total_size: 10,
                finished_size: 0,
                transferred: 0,
                remote: "/sdcard/a".into(),
                local: "/root/a".into(),
            }]),
            events: Mutex::new(VecDeque::new()),
            events_room: Notify::new(),
            samples: Mutex::new(HashMap::new()),
            permission: Arc::new(PermissionGate::new(true)),
        };
        shared.push_event(TransferEvent::Progress {
            job: 1,
            file_num: 0,
            speed: 1.0,
            finished_size: 1,
        });
        shared.push_event(TransferEvent::Progress {
            job: 1,
            file_num: 0,
            speed: 2.0,
            finished_size: 2,
        });
        shared.push_event(TransferEvent::Overwrite {
            job: 1,
            file_num: 0,
            read_path: "/root/a".into(),
            upload: false,
            identical: false,
        });
        shared.push_event(TransferEvent::Done {
            job: 1,
            file_num: 1,
        });
        let snapshot = shared.take_snapshot();
        assert_eq!(snapshot.events.len(), 3);
        assert!(matches!(
            snapshot.events[0],
            TransferEvent::Progress { speed, .. } if speed == 2.0
        ));
        assert!(matches!(
            snapshot.events[1],
            TransferEvent::Overwrite { .. }
        ));
        assert!(matches!(snapshot.events[2], TransferEvent::Done { .. }));
        // Taking the snapshot consumed the events and kept the rows.
        assert!(shared.take_snapshot().events.is_empty());
        assert_eq!(shared.take_snapshot().jobs.len(), 1);
    }

    /// A `TransferShared` with no rows and no queued events.
    fn fresh_shared(root: Option<&Path>) -> TransferShared {
        TransferShared {
            config: TransferConfig::new(root.map(Path::to_path_buf), "Linux", "1.4.9"),
            rows: Mutex::new(Vec::new()),
            events: Mutex::new(VecDeque::new()),
            events_room: Notify::new(),
            samples: Mutex::new(HashMap::new()),
            permission: Arc::new(PermissionGate::new(true)),
        }
    }

    #[test]
    fn an_upload_job_that_cannot_stream_ends_once_and_leaves_the_table() {
        let temp = TempRoot::new("upload_error");
        temp.file("data.bin", b"0123456789");
        let mut read = vec![
            TransferJob::new_read(
                4,
                JobType::Generic,
                "/sdcard".into(),
                DataSource::FilePath(temp.path().to_path_buf()),
                0,
                false,
                false,
                false,
            )
            .expect("a job over the fixture"),
        ];
        let shared = fresh_shared(Some(temp.path()));
        shared.push_row(TransferRow {
            job: 4,
            direction: TransferDirection::Upload,
            state: TransferJobState::Queued,
            file_num: 0,
            total_size: 0,
            finished_size: 0,
            transferred: 0,
            remote: "/sdcard".into(),
            local: temp.path().to_string_lossy().into_owned(),
        });
        release_upload_job(&mut read, &shared, 4, 1, "read failed".into());
        // The job is released, so no tick can read that file again and report the
        // same failure a second time.
        assert!(fs::get_job(4, &mut read).is_none());
        let snapshot = shared.take_snapshot();
        assert_eq!(
            snapshot.jobs[0].state,
            TransferJobState::Failed("read failed".into())
        );
        assert_eq!(snapshot.events.len(), 1);
        assert!(matches!(
            &snapshot.events[0],
            TransferEvent::Failed { job: 4, file_num: 1, error } if error == "read failed"
        ));
    }

    #[test]
    fn a_limited_poll_takes_the_oldest_events_and_leaves_the_rest() {
        let shared = fresh_shared(None);
        for job in 1..=3 {
            shared.push_event(TransferEvent::Done { job, file_num: 1 });
        }
        assert_eq!(
            shared.take_snapshot_limit(1).events,
            vec![TransferEvent::Done {
                job: 1,
                file_num: 1
            }]
        );
        assert_eq!(
            shared.take_snapshot_limit(1).events,
            vec![TransferEvent::Done {
                job: 2,
                file_num: 1
            }]
        );
        // The rest stayed queued: the limit decided how many came now, not which
        // facts survived.
        assert_eq!(
            shared.take_snapshot().events,
            vec![TransferEvent::Done {
                job: 3,
                file_num: 1
            }]
        );
        assert!(shared.take_snapshot().events.is_empty());
    }

    #[tokio::test]
    async fn a_terminal_fact_for_an_id_no_table_holds_is_not_a_job_fact() {
        let temp = TempRoot::new("stray_terminal");
        let mut session = Session::start(temp.path());
        // A `Done` and an `Error` for ids this session never held: a repeat, or
        // something addressed elsewhere. Neither may become a job of this session.
        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Done(FileTransferDone {
                    id: 31,
                    file_num: 1,
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;
        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Error(FileTransferError {
                    id: 32,
                    file_num: 1,
                    error: "refused".into(),
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;
        // A listing is the next thing the owner owes, so its arrival proves both
        // messages above were already handled.
        session
            .peer(Inbound::Response(FileResponse {
                union: Some(file_response::Union::Dir(FileDirectory {
                    id: 0,
                    path: "/sdcard".to_owned(),
                    entries: Vec::new(),
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await;
        let events = session
            .events(|event| matches!(event, TransferEvent::Directory(_)))
            .await;
        assert!(
            events.iter().all(|event| !matches!(
                event,
                TransferEvent::Done { .. } | TransferEvent::Failed { .. }
            )),
            "a fact for an id this session does not hold: {events:?}"
        );
        assert!(session.handle.jobs().is_empty());
        session.stop().await;
    }

    #[tokio::test]
    async fn events_are_bounded_and_cancel_wakes_an_owner_waiting_for_room() {
        let temp = TempRoot::new("bounded_events");
        let mut session = Session::start(temp.path());
        session.empty_dirs(TRANSFER_EVENTS_KEPT).await;
        // The owner holds at most the bound while nobody polls, and polling takes
        // them in order without losing one.
        let mut seen = 0;
        let mut largest = 0;
        for _ in 0..500 {
            let events = session.handle.take_snapshot().events;
            largest = largest.max(events.len());
            seen += events.len();
            if seen == TRANSFER_EVENTS_KEPT {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(largest <= TRANSFER_EVENTS_KEPT, "held {largest} events");
        assert_eq!(seen, TRANSFER_EVENTS_KEPT, "a fact was lost to the bound");
        // Filling it again leaves the owner waiting for room; only the session's
        // own cancellation may end it then.
        session.empty_dirs(TRANSFER_EVENTS_KEPT).await;
        session.stop().await;
    }

    #[tokio::test]
    async fn a_job_past_the_live_bound_is_refused_visibly() {
        let temp = TempRoot::new("admission");
        let mut session = Session::start(temp.path());
        for job in 1..=TRANSFER_ROWS_KEPT as i32 {
            session
                .handle
                .submit(TransferCommand::Download {
                    job,
                    remote: format!("/sdcard/{job}"),
                    local: temp
                        .path()
                        .join(format!("{job}.txt"))
                        .to_string_lossy()
                        .into_owned(),
                    file_num: 0,
                    include_hidden: false,
                })
                .expect("accepted");
            let send = session.effect().await;
            match action(&send).union.as_ref() {
                Some(file_action::Union::Send(request)) => assert_eq!(request.id, job),
                other => panic!("expected a send request, got {other:?}"),
            }
        }
        assert_eq!(session.handle.jobs().len(), TRANSFER_ROWS_KEPT);
        // One more job does not fit: the refusal is a real, visible failure for
        // the job it named, not a row left queued and not a completion.
        session
            .handle
            .submit(TransferCommand::Download {
                job: 999,
                remote: "/sdcard/999".into(),
                local: temp.path().join("999.txt").to_string_lossy().into_owned(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("queued");
        session
            .events(|event| matches!(event, TransferEvent::Failed { job: 999, .. }))
            .await;
        let rows = session.handle.jobs();
        assert_eq!(rows.len(), TRANSFER_ROWS_KEPT);
        assert!(rows.iter().all(|row| row.job != 999));
        session.quiet().await;
        session.stop().await;
    }

    #[tokio::test]
    async fn a_revoked_permission_ends_the_live_job_once_and_admits_work_after() {
        let temp = TempRoot::new("revoke");
        let mut session = Session::start(temp.path());
        session
            .handle
            .submit(TransferCommand::Download {
                job: 41,
                remote: "/sdcard/a".into(),
                local: temp.path().join("a.txt").to_string_lossy().into_owned(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("accepted");
        let _send = session.effect().await;

        session.handle.set_enabled(false);
        assert!(!session.handle.is_enabled());
        // No new work is accepted while the permission is withdrawn.
        assert_eq!(
            session.handle.submit(TransferCommand::Download {
                job: 42,
                remote: "/sdcard/b".into(),
                local: temp.path().join("b.txt").to_string_lossy().into_owned(),
                file_num: 0,
                include_hidden: false,
            }),
            Err(TransferError::PermissionDenied)
        );

        // The job the revocation reached is stopped once: the peer is told, the
        // row keeps a real failure, and the client sees one fact for it.
        let cancel = session.effect().await;
        match action(&cancel).union.as_ref() {
            Some(file_action::Union::Cancel(request)) => assert_eq!(request.id, 41),
            other => panic!("expected a cancel, got {other:?}"),
        }
        let events = session
            .events(|event| matches!(event, TransferEvent::Failed { job: 41, .. }))
            .await;
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TransferEvent::Failed { job: 41, .. }))
                .count(),
            1
        );
        assert!(matches!(
            &session.handle.jobs()[0].state,
            TransferJobState::Failed(_)
        ));
        // The session is still alive: nothing else is owed.
        session.quiet().await;

        // A re-grant admits new work, and never replays what was refused.
        session.handle.set_enabled(true);
        session
            .handle
            .submit(TransferCommand::Download {
                job: 43,
                remote: "/sdcard/c".into(),
                local: temp.path().join("c.txt").to_string_lossy().into_owned(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("accepted");
        let send = session.effect().await;
        match action(&send).union.as_ref() {
            Some(file_action::Union::Send(request)) => assert_eq!(request.id, 43),
            other => panic!("expected a send request, got {other:?}"),
        }
        assert!(session.handle.jobs().iter().all(|row| row.job != 42));
        session.stop().await;
    }

    /// A block read under one permission generation that is still waiting for the
    /// byte budget when the peer withdraws and grants again keeps the generation
    /// it was read under: the writer drops it instead of sending old bytes under
    /// the new epoch, and only the revocation's own cancel — sent by the pass that
    /// began under the new generation — may pass.
    #[tokio::test]
    async fn a_block_waiting_for_the_byte_budget_is_not_restamped_by_a_regrant() {
        let temp = TempRoot::new("stale_block");
        let mut session = Session::start(temp.path());
        // Upstream's own block size, and one file that needs more than it: the
        // bytes held here are exactly the session's whole budget.
        const BLOCK: usize = 128 * 1024;
        let source = temp.file("big.bin", &noise(TRANSFER_BULK_BYTES + 1));
        session
            .handle
            .submit(TransferCommand::Upload {
                job: 21,
                local: source.to_string_lossy().into_owned(),
                remote: "/sdcard".into(),
                file_num: 0,
                include_hidden: false,
            })
            .expect("accepted");
        let _receive = session.effect().await;
        let _digest = session.effect().await;
        session
            .peer(Inbound::Action(FileAction {
                union: Some(file_action::Union::SendConfirm(
                    FileTransferSendConfirmRequest {
                        id: 21,
                        file_num: 0,
                        union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }))
            .await;

        // Hold every byte of the budget, so the next block is the one waiting.
        let mut held = Vec::new();
        for _ in 0..TRANSFER_BULK_BYTES / BLOCK {
            let effect = session.effect_raw().await;
            match response(effect.message()).union.as_ref() {
                Some(file_response::Union::Block(block)) => {
                    assert_eq!(
                        block.data.len(),
                        BLOCK,
                        "the fixture must pay for the budget"
                    )
                }
                other => panic!("expected a block, got {other:?}"),
            }
            held.push(effect);
        }
        // With the whole budget held the owner can read no further block.
        session.quiet().await;

        session.handle.set_enabled(false);
        session.handle.set_enabled(true);
        for effect in &held {
            assert!(
                !effect.is_permitted(),
                "a block read before the withdrawal was restamped"
            );
        }
        drop(held);

        // What the writer may still send is the revocation's own cancel; anything
        // from the pass that read before it is stale, whatever the permission says.
        loop {
            let effect = session.effect_raw().await;
            let cancels = matches!(
                effect.message().union.as_ref(),
                Some(message::Union::FileAction(action))
                    if matches!(action.union.as_ref(), Some(file_action::Union::Cancel(_)))
            );
            if cancels {
                assert!(
                    effect.is_permitted(),
                    "the revocation's own cancel was dropped"
                );
                effect.complete(true);
                break;
            }
            assert!(
                !effect.is_permitted(),
                "bytes read before the withdrawal were sent under the new epoch"
            );
            effect.complete(false);
        }
        // The job the revocation reached keeps its one real failure.
        session
            .events(|event| matches!(event, TransferEvent::Failed { job: 21, .. }))
            .await;
        assert!(matches!(
            &session.handle.jobs()[0].state,
            TransferJobState::Failed(_)
        ));
        session.stop().await;
    }

    /// An upload is done only once this session's own writer has written its last
    /// record: a `done` reported as not written, or one the writer went away with,
    /// is that job's one real failure — never a completion, and never a closed
    /// session.
    #[tokio::test]
    async fn an_upload_is_not_done_until_its_last_record_is_written() {
        let temp = TempRoot::new("final_record");
        let mut session = Session::start(temp.path());

        // No answer at all: the writer never reported a write.
        let unanswered = session
            .upload_to_final_done(31, &temp.file("a.bin", b"0123456789"))
            .await;
        drop(unanswered);

        // An answer that says it was not written.
        let refused = session
            .upload_to_final_done(32, &temp.file("b.bin", b"abcdefghij"))
            .await;
        refused.complete(false);

        let seen = session
            .events(|event| matches!(event, TransferEvent::Failed { job: 32, .. }))
            .await;
        for job in [31, 32] {
            assert_eq!(
                seen.iter()
                    .filter(|event| matches!(event, TransferEvent::Failed { job: reported, .. } if *reported == job))
                    .count(),
                1,
                "job {job} reports exactly one failure: {seen:?}"
            );
        }
        assert!(
            !seen
                .iter()
                .any(|event| matches!(event, TransferEvent::Done { .. })),
            "a record the writer did not write is not a completion: {seen:?}"
        );
        let rows = session.handle.jobs();
        for job in [31, 32] {
            let row = rows
                .iter()
                .find(|row| row.job == job)
                .expect("a row per job");
            assert!(
                matches!(&row.state, TransferJobState::Failed(_)),
                "job {job} ended as {:?}",
                row.state
            );
        }
        // The session is still alive and owes nothing else.
        session.quiet().await;
        session.stop().await;
    }
}
