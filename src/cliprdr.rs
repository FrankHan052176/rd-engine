//! The real RustDesk **file** clipboard: one session-owned Cliprdr owner that
//! both serves a local file offer and lands a peer's files on disk.
//!
//! This is upstream's `Message::Cliprdr` protocol, not the `FileAction` transfer
//! RPC and not a hand-rolled data channel. The message shapes, the file
//! descriptor layout, the flags, the size/range algorithm and the reply
//! vocabulary are the pinned client's own
//! (`rustdesk/rustdesk` @ `092a961b629d318fe290eeafac0cd214a1e9deeb`), read from
//! `.build-deps/cliprdr-upstream-pin/` (immutable blobs) and
//! `.build-deps/engine-feature-upstream-pin/libs/clipboard/src/lib.rs`:
//!
//! * `libs/clipboard/src/cliprdr.h` — every PDU's fields and the `CB_RESPONSE_*`
//!   / `FILECONTENTS_*` flag values.
//! * `libs/clipboard/src/platform/unix/filetype.rs` — `FileDescription::
//!   parse_file_descriptors`: the 4-byte count plus 592-byte records, the
//!   NUL-terminated 520-byte UTF-16LE name field, `FLAGS_FD_*` handling and
//!   `validate_file_name`.
//! * `libs/clipboard/src/platform/unix/local_file.rs` — `LocalFile::as_bin` (the
//!   exact 592-byte encode) and `construct_file_list` (recursing into a selected
//!   directory, descriptor names made relative to each root's parent).
//! * `libs/clipboard/src/platform/unix/serv_files.rs` — `sync_files`,
//!   `build_file_list_pdu`, `serve_file_contents` and `read_file_contents`: the
//!   `dw_flags` 1/2 split and `read_size = min(length, size - offset)`.
//! * `libs/clipboard/src/context_send.rs` — the 30 s response wait this module
//!   uses for its own unanswered requests.
//! * `src/clipboard_file.rs` in the same pin — `serve_clip_messages`, the real
//!   message flow: answer `FormatDataRequest` with the descriptor PDU, ask for
//!   the descriptors when a peer's `FormatList` carries `FileGroupDescriptorW`,
//!   answer `FileContentsRequest`, and treat a non-1 `msg_flags` as a failure.
//!
//! # What is deliberately not taken from upstream
//!
//! Upstream's file clipboard lives in a **process-wide** singleton: a
//! `VEC_MSG_CHANNEL` registry, a `CLIP_FILES` global cache, an unbounded channel
//! and — on Linux — a FUSE mount that is the only thing that ever issues
//! `FileContentsRequest`s. None of that is here. This owner belongs to one
//! viewer session, its channels are bounded, and it does the receiving half
//! itself: after a peer's descriptor list it asks for each file's size and then
//! its bytes in bounded chunks, writes them to a staging directory under the
//! root the client authorized, and publishes the paths only once the bytes are
//! flushed and finally named. Nothing is mounted, no OS clipboard is touched and
//! no second platform clipboard owner is created.
//!
//! # What leaves this module
//!
//! Exactly two kinds of value, and neither is a socket:
//!
//! * [`CliprdrEffect`] — one wire `Message` for the session's **one** existing
//!   writer, carrying the byte budget it holds and the permission generation it
//!   was queued under. Dropping it (after the write, or instead of it) releases
//!   those bytes. `complete(written)` reports whether that write really happened;
//!   it is never a peer acknowledgement, because this wire has none.
//! * [`CliprdrEvent`] — what the local client acts on: the paths a peer's files
//!   really became, a local offer that really reached the writer, and an explicit
//!   failure. Nothing here is published on the strength of a queued message.
//!
//! # Trust boundary
//!
//! An inbound descriptor list is peer input. Its count, its total length, each
//! record's length, the attributes flag, the name's NUL terminator and UTF-16
//! validity, the normalized relative shape of every name, duplicates and
//! file/directory conflicts are all checked before a byte is written. A name can
//! only ever create something **inside** this job's own staging directory under
//! the client's root: absolute paths, `..`, empty or `.` components, Windows
//! drive prefixes and symlinks are refused, and the source files this owner
//! serves are only ever the ones the client explicitly offered.
//!
//! # Blocking I/O
//!
//! `Cargo.toml` enables tokio without its `fs` feature, and this change owns no
//! Cargo file, so the file work is `std::fs` performed **inline in this owner's
//! own task** — the same precedent as the viewer's `clipboard_decode` task,
//! which also runs bounded blocking work in a spawned session task rather than a
//! second thread or runtime. Every step is bounded (a 64 KiB received chunk, at
//! most one 4 MiB served block, one descriptor PDU), and I/O is never placed
//! inside a `select!`: once a read or write starts it is awaited to completion,
//! so a close cannot drop an in-flight disk operation and replay it.

use base::message_proto::{self as proto, Cliprdr, Message};
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Wire effects the writer may hold: one upstream block each, plus the small
/// control messages (`ready`, `format_list`, `format_data_request/response`,
/// `file_contents_request/response`, `try_empty`). At most this many are
/// buffered *and* one more may be in the writer's hand, so the writer is never
/// asked to drain an unbounded queue.
pub const CLIPRDR_OUTBOUND_QUEUE: usize = 4;
/// The byte budget those effects share, released when the writer drops an effect
/// after sending it. It must be able to satisfy one single effect on its own:
/// the largest is a served range, capped at [`CLIPRDR_SERVE_BLOCK`]. One block
/// plus several control messages fit, so the queue is bounded in *bytes* as well
/// as in count — a queue of four maximum blocks is the worst case.
pub const CLIPRDR_OUTBOUND_BYTES: usize = (4 << 20) + (256 << 10);
/// Commands the client may queue ahead of the owner.
pub const CLIPRDR_COMMAND_QUEUE: usize = 16;
/// Peer messages the reader may queue. The reader must wait on this channel
/// rather than drop a `FileContentsRequest` or a `FormatList`: a slow local disk
/// then applies real backpressure, which is what the pinned client's own session
/// loop does by awaiting its clipboard handler inline.
pub const CLIPRDR_INBOUND_QUEUE: usize = 8;
/// Events the owner may hold for a client that has not taken them yet, and the
/// most it will ever hold. Reaching the bound is backpressure, not a reason to
/// lose a fact: a completed paste cannot be recreated from a later event, so the
/// owner waits for the applying consumer to take a batch instead of replacing
/// the oldest fact with a newer one.
pub const CLIPRDR_EVENTS_KEPT: usize = 64;
/// The range size this owner asks a peer for. Small enough that one received
/// chunk is a short, bounded disk write and a bounded outbound effect.
pub const CLIPRDR_CHUNK: u64 = 64 << 10;
/// The largest served range. This is upstream's own `BLOCK_SIZE`
/// (`libs/clipboard/src/platform/unix/mod.rs`), the request size its FUSE side
/// issues; a peer asking for more is refused with the protocol's own failure
/// answer rather than answered with a truncated file.
pub const CLIPRDR_SERVE_BLOCK: u64 = 4 << 20;
/// Descriptor records this owner accepts in one list, and entries one local offer
/// may expand to. Bounds the descriptor PDU at `4 + 592 * this` bytes (~606 KiB).
pub const MAX_CLIPRDR_FILES: usize = 1024;
/// Top-level paths one client offer may name: Resk's own `MAX_CLIPBOARD_FILES`.
pub const MAX_CLIPRDR_OFFER_ROOTS: usize = 64;
/// How deep the directory walk under one offered root may go.
pub const MAX_CLIPRDR_DEPTH: usize = 64;

/// `CliprdrFormat` id of the file descriptor list. Not a real Windows format id,
/// just the value upstream's unix side advertises (`FILEDESCRIPTOR_FORMAT_ID`).
pub const FILEDESCRIPTOR_FORMAT_ID: i32 = 49334;
/// The name upstream advertises for the descriptor list, matched by name when a
/// peer's `FormatList` is read — the id is only a convenience.
pub const FILEDESCRIPTORW_FORMAT_NAME: &str = "FileGroupDescriptorW";
/// `CliprdrFormat` id of a file's contents (`FILECONTENTS_FORMAT_ID`).
pub const FILECONTENTS_FORMAT_ID: i32 = 49267;
pub const FILECONTENTS_FORMAT_NAME: &str = "FileContents";

/// `CB_RESPONSE_OK`: the answer carries what was asked for.
pub const MSG_FLAGS_OK: i32 = 0x1;
/// `CB_RESPONSE_FAIL`: the answer is the peer's own failure report.
pub const MSG_FLAGS_FAIL: i32 = 0x2;
/// `FILECONTENTS_SIZE`: the request asks for an 8-byte little-endian size.
pub const FILECONTENTS_SIZE: i32 = 0x1;
/// `FILECONTENTS_RANGE`: the request asks for bytes at an offset.
pub const FILECONTENTS_RANGE: i32 = 0x2;

/// The descriptor record has valid attributes.
const FLAGS_FD_ATTRIBUTES: u32 = 0x04;
/// The descriptor record carries the file's unix mode in its reserved field.
const FLAGS_FD_UNIX_MODE: u32 = 0x08;
/// The descriptor record carries a last-write time.
const FLAGS_FD_LAST_WRITE: u32 = 0x20;
/// The descriptor record carries a size.
const FLAGS_FD_SIZE: u32 = 0x40;
/// A transfer with this flag shows progress upstream; carried for fidelity.
const FLAGS_FD_PROGRESSUI: u32 = 0x4000;
/// The flags this owner sets on every descriptor it encodes (`LocalFile::as_bin`).
const DESCRIPTOR_FLAGS: u32 = FLAGS_FD_SIZE
    | FLAGS_FD_LAST_WRITE
    | FLAGS_FD_ATTRIBUTES
    | FLAGS_FD_PROGRESSUI
    | FLAGS_FD_UNIX_MODE;

/// `FILEDESCRIPTORW::cFileName` capacity in UTF-16 code units, including the NUL.
const FILE_NAME_CODE_UNITS: usize = 260;
/// The same capacity in bytes: the fixed-size field inside one record.
const FILE_NAME_FIELD_SIZE: usize = FILE_NAME_CODE_UNITS * 2;
/// One `FILEDESCRIPTORW` record.
const FILE_DESCRIPTOR_SIZE: usize = 592;
/// 1601-01-01 + this many 100 ns ticks is 1970-01-01 (`LDAP_EPOCH_DELTA`).
const LDAP_EPOCH_DELTA: u64 = 116444772610000000;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// How long a request this owner sent may stay unanswered before the transfer it
/// belongs to is failed. The value is upstream's own
/// `CLIPBOARD_RESPONSE_WAIT_TIMEOUT_SECS` (`context_send.rs`). A descriptor
/// answer that never arrives cannot be disambiguated from a later one, so it is
/// reported rather than retried.
const CLIPRDR_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

fn lock<T>(cell: &Mutex<T>) -> MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Which filesystem operation failed. Part of a [`CliprdrError`] so a real disk
/// failure is reportable without ever carrying a path or peer text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskOp {
    CreateDir,
    Open,
    Read,
    Write,
    Flush,
    Rename,
    Metadata,
    SetPermissions,
    RemoveDir,
}

impl DiskOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::CreateDir => "create a directory",
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Rename => "rename",
            Self::Metadata => "read the metadata of",
            Self::SetPermissions => "set the permissions of",
            Self::RemoveDir => "remove the directory",
        }
    }
}

/// A refusal or failure of this owner.
///
/// Every variant is decided from local facts or from a protocol violation, and
/// none carries a path, a peer string or an OS message: what a caller publishes
/// is [`Self::static_reason`], plus a [`DiskOp`] and an `ErrorKind` for a real
/// disk failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliprdrError {
    /// This session may not exchange file clipboard content right now: the peer
    /// withdrew file or clipboard permission, the operator went read-only, the
    /// local clipboard is off, or the session is closing.
    ///
    /// Also the reason work admitted under a permission generation is dropped when
    /// that generation is replaced: a withdrawal and the re-grant that follows it
    /// both invalidate it, even though the fence is open again by the time the
    /// owner runs.
    PermissionDenied,
    /// No authorized clipboard file root was configured for this session.
    RootUnset,
    /// The root is not an absolute, non-symlinked, private directory.
    RootInvalid,
    /// A local offer named no paths.
    OfferEmpty,
    /// A local offer names more top-level paths than [`MAX_CLIPRDR_OFFER_ROOTS`],
    /// or expands to more entries than [`MAX_CLIPRDR_FILES`], or nests deeper
    /// than [`MAX_CLIPRDR_DEPTH`].
    OfferTooLarge,
    /// A local path cannot be offered: not absolute, a `..` component, missing,
    /// a symlink, or not representable as a descriptor name.
    OfferPathInvalid,
    /// A local file changed after it was offered. The descriptor this session
    /// announced no longer describes what would be read, and this owner never
    /// silently serves different bytes under the old descriptor.
    SourceChanged,
    /// The peer's descriptor list is malformed: bad count, bad length, missing
    /// attributes, or a contradictory entry set.
    DescriptorInvalid,
    /// A descriptor name is not a normalized relative path, is not
    /// NUL-terminated, is not valid UTF-16, or is too long for the field.
    FileNameInvalid,
    /// A `FileContentsRequest` this owner cannot serve: bad index, unknown flags,
    /// a negative or over-limit length, or an offset past the file's size.
    RequestInvalid,
    /// A `FileContentsResponse` does not answer the request in flight.
    StreamMismatch,
    /// This session has used every stream id the wire can carry.
    StreamExhausted,
    /// A `FormatDataResponse` arrived with no descriptor request in flight. It
    /// carries no request id, so attributing it to an offer would be a guess.
    DescriptorUnrequested,
    /// The peer reported a failure (`msg_flags` other than `CB_RESPONSE_OK`).
    PeerFailed,
    /// The peer's file clipboard is empty: it announced the file formats with no
    /// descriptors, so there is nothing to receive.
    PeerEmpty,
    /// The peer replaced its clipboard before the transfer it had started
    /// finished. Whatever was partially written by this owner was removed.
    PeerReplacedClipboard,
    /// The peer stopped answering a request this owner sent.
    TimedOut,
    /// The session writer did not write a message this owner needed written.
    NotWritten,
    /// The command queue is full: the client may retry once it has polled.
    Backpressure,
    /// The owner's channel is closed; the session is over.
    Closed,
    /// The viewer is cancelling, so no further effect is owed.
    Cancelled,
    /// A real filesystem failure on this device.
    Disk { operation: DiskOp, kind: std::io::ErrorKind },
}

impl CliprdrError {
    fn disk(operation: DiskOp, error: &std::io::Error) -> Self {
        Self::Disk {
            operation,
            kind: error.kind(),
        }
    }

    /// The refusal as a local constant, so no path or peer text can be built into
    /// a caller's event.
    pub fn static_reason(&self) -> &'static str {
        match self {
            Self::PermissionDenied => "this session may not exchange clipboard files",
            Self::RootUnset => "this session has no authorized clipboard file root",
            Self::RootInvalid => "the clipboard file root is not a private absolute directory",
            Self::OfferEmpty => "the local file list is empty",
            Self::OfferTooLarge => "the local file list is over the entry bound",
            Self::OfferPathInvalid => "a local path cannot be offered as a clipboard file",
            Self::SourceChanged => "a local clipboard file changed after it was offered",
            Self::DescriptorInvalid => "the peer's file descriptor list is malformed",
            Self::FileNameInvalid => "a clipboard file name is not a normalized relative path",
            Self::RequestInvalid => "a file contents request is not one this session can serve",
            Self::StreamMismatch => "a file contents response does not answer the request in flight",
            Self::StreamExhausted => "this session has used every file contents stream id",
            Self::DescriptorUnrequested => {
                "a file descriptor answer arrived with no descriptor request outstanding"
            }
            Self::PeerFailed => "the peer reported a file clipboard failure",
            Self::PeerEmpty => "the peer announced the file formats with no files",
            Self::PeerReplacedClipboard => {
                "the peer replaced its clipboard before the transfer finished"
            }
            Self::TimedOut => "the peer did not answer a file clipboard request in time",
            Self::NotWritten => "the session writer did not write this message",
            Self::Backpressure => "the cliprdr command queue is full",
            Self::Closed => "the cliprdr channel is closed",
            Self::Cancelled => "the session is closing",
            Self::Disk { .. } => "a clipboard file could not be handled on this device",
        }
    }
}

impl std::fmt::Display for CliprdrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disk { operation, kind } => {
                write!(f, "could not {} a clipboard file: {kind}", operation.as_str())
            }
            other => f.write_str(other.static_reason()),
        }
    }
}

impl std::error::Error for CliprdrError {}

/// What the client may ask this session's file clipboard to do.
///
/// Every variant only *enqueues*; what a command really achieved is a
/// [`CliprdrEvent`]. Paths are the client's own already-staged objects — this
/// owner never reads a pasteboard, never copies a file the client did not name,
/// and never invents a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliprdrCommand {
    /// The one directory under which a peer's files may be created. The client's
    /// own incoming root; everything this owner writes lives under it.
    SetRoot(PathBuf),
    /// Announce these local paths as this side's file clipboard. Replaces any
    /// previous offer, and drops every handle the previous one held.
    OfferFiles(Vec<PathBuf>),
    /// Withdraw the local offer. If one was announced, the peer is told the file
    /// clipboard is empty (`CliprdrTryEmpty`), exactly as upstream's
    /// `try_empty_clipboard_files` does.
    ClearLocalOffer,
}

/// One queued command with the request id the client was given for it.
struct Issued {
    request_id: u64,
    /// The generation in force when [`CliprdrHandle::submit`] admitted it. A
    /// command that outlives its generation is refused instead of run under the
    /// next one.
    revision: u64,
    command: CliprdrCommand,
}

/// The permission fence, and the generation every effect and command is stamped
/// with.
///
/// `allowed` is the AND the parent publishes: authenticated Desktop session, the
/// peer's clipboard grant, the peer's file grant, the local clipboard switch, not
/// read-only, and not closing. `revision` moves on every transition in either
/// direction, so work admitted under one era can never be sent or run in another:
/// a revocation and the re-grant that follows it both invalidate what the
/// previous answer admitted, and nothing is ever restamped.
struct Fence {
    state: Mutex<FenceState>,
    /// Wakes the owner, which may be waiting for a command, a peer message, room
    /// in the event queue, or nothing at all.
    changed: Notify,
}

struct FenceState {
    allowed: bool,
    revision: u64,
}

impl Fence {
    /// Closed, because nothing has published the facts yet.
    fn new() -> Self {
        Self {
            state: Mutex::new(FenceState { allowed: false, revision: 1 }),
            changed: Notify::new(),
        }
    }

    fn is_allowed(&self) -> bool {
        lock(&self.state).allowed
    }

    fn revision(&self) -> u64 {
        lock(&self.state).revision
    }

    fn permission(&self) -> (u64, bool) {
        let state = lock(&self.state);
        (state.revision, state.allowed)
    }

    fn permits(&self, revision: u64) -> bool {
        let state = lock(&self.state);
        state.allowed && state.revision == revision
    }

    /// Publishes the combined answer and returns the generation in force.
    ///
    /// A repeated value changes nothing, so a peer that re-sends a grant it
    /// already gave does not invalidate work in flight. `notify_one` rather than
    /// `notify_waiters`, so a change that lands between the owner's own check and
    /// its wait is kept instead of lost.
    fn set(&self, allowed: bool) -> u64 {
        let mut state = lock(&self.state);
        if state.allowed == allowed {
            return state.revision;
        }
        // The permission and its ticket are one publication. Two independent
        // atomics could expose the re-grant with the withdrawn era's ticket.
        state.allowed = allowed;
        state.revision += 1;
        let revision = state.revision;
        drop(state);
        self.changed.notify_one();
        revision
    }
}

impl std::fmt::Debug for Fence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fence")
            .field("allowed", &self.is_allowed())
            .field("revision", &self.revision())
            .finish()
    }
}

/// A byte cursor that refuses to read past its input, so a short peer record is
/// an error rather than a panic.
struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CliprdrError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(CliprdrError::DescriptorInvalid)?;
        let slice = self
            .data
            .get(self.offset..end)
            .ok_or(CliprdrError::DescriptorInvalid)?;
        self.offset = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, CliprdrError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, CliprdrError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }
}

/// A descriptor name is a normalized relative path, which is what makes every
/// created path stay inside this job's own directory.
///
/// The rules are `filetype::validate_file_name`: no Windows drive prefix, no
/// empty component, no `.` component, and `base::fs::
/// validate_file_name_no_traversal` on top (no NUL byte, no `..`). Two checks are
/// added here because the name is later joined onto a real directory: a name may
/// not start with `/`, and it may not be empty. `\` has already been normalized
/// to `/` by the caller, exactly as upstream does.
pub fn validate_descriptor_name(name: &str) -> Result<(), CliprdrError> {
    if name.is_empty() {
        return Err(CliprdrError::FileNameInvalid);
    }
    let bytes = name.as_bytes();
    if matches!(bytes, [letter, b':', b'/', ..] if letter.is_ascii_alphabetic()) {
        return Err(CliprdrError::FileNameInvalid);
    }
    if name.starts_with('/') {
        return Err(CliprdrError::FileNameInvalid);
    }
    if name
        .split('/')
        .any(|component| component.is_empty() || component == ".")
    {
        return Err(CliprdrError::FileNameInvalid);
    }
    base::fs::validate_file_name_no_traversal(name)
        .map_err(|_| CliprdrError::FileNameInvalid)?;
    Ok(())
}

/// Decodes one fixed-size name field: everything up to the first NUL code unit,
/// as UTF-16LE, with `\` normalized to `/`.
fn decode_name(field: &[u8]) -> Result<String, CliprdrError> {
    let terminator = field
        .chunks_exact(2)
        .position(|unit| unit == [0_u8, 0_u8])
        .ok_or(CliprdrError::FileNameInvalid)?;
    let mut text = String::new();
    for decoded in char::decode_utf16(
        field[..terminator * 2]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    ) {
        text.push(decoded.map_err(|_| CliprdrError::FileNameInvalid)?);
    }
    let name = text.replace('\\', "/");
    validate_descriptor_name(&name)?;
    Ok(name)
}

/// Encodes one descriptor name into its fixed 520-byte field.
fn name_field(name: &str) -> Result<[u8; FILE_NAME_FIELD_SIZE], CliprdrError> {
    validate_descriptor_name(name)?;
    let mut field = [0_u8; FILE_NAME_FIELD_SIZE];
    let mut units = 0;
    for encoded in name.encode_utf16() {
        // One code unit is kept for the terminator, so `units + 1` must fit.
        if units + 1 >= FILE_NAME_CODE_UNITS {
            return Err(CliprdrError::FileNameInvalid);
        }
        let offset = units * 2;
        field[offset..offset + 2].copy_from_slice(&encoded.to_le_bytes());
        units += 1;
    }
    Ok(field)
}

/// The MS-DOS attributes upstream's `LocalFile::as_bin` writes.
fn attributes_of(is_dir: bool, read_only: bool, hidden: bool) -> u32 {
    let normal = !(is_dir || read_only || hidden);
    let mut attributes = 0_u32;
    if read_only {
        attributes |= 0x1;
    }
    if hidden {
        attributes |= 0x2;
    }
    if is_dir {
        attributes |= ATTRIBUTE_DIRECTORY;
    }
    if normal {
        attributes |= 0x80;
    }
    attributes
}

/// A `SystemTime` in the 1601-epoch 100 ns ticks the record carries.
fn win32_time(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        / 100
        + LDAP_EPOCH_DELTA
}

/// One file of this side's offer, with the descriptor facts fixed at offer time.
///
/// The handle is opened lazily on the first served request and then kept for the
/// rest of the offer, so every range of one file is read from the same opened
/// object. If the file's size or kind changed before that first open, the offer
/// fails ([`CliprdrError::SourceChanged`]) instead of silently serving a
/// different file that happens to have the same name.
struct OfferedFile {
    path: PathBuf,
    /// The descriptor name: relative to the offered root's parent, `/`-separated.
    name: String,
    size: u64,
    is_dir: bool,
    /// The unix mode, already masked to `0o777` — the same bits a peer's
    /// `perm & 0o777` keeps.
    mode: u32,
    read_only: bool,
    modified: SystemTime,
    handle: Option<File>,
}

impl OfferedFile {
    /// The 592-byte `FILEDESCRIPTORW` record, exactly as `LocalFile::as_bin`
    /// lays it out: flags, 32 reserved bytes, attributes, 12 reserved bytes, the
    /// unix mode in the last 4 reserved bytes, the write time, size high/low, and
    /// the fixed-size name field.
    fn descriptor(&self) -> Result<Vec<u8>, CliprdrError> {
        let mut out = Vec::with_capacity(FILE_DESCRIPTOR_SIZE);
        out.extend_from_slice(&DESCRIPTOR_FLAGS.to_le_bytes());
        out.extend_from_slice(&[0_u8; 32]);
        let hidden = self
            .name
            .rsplit('/')
            .next()
            .is_some_and(|last| last.starts_with('.'));
        let attributes = attributes_of(self.is_dir, self.read_only, hidden);
        out.extend_from_slice(&attributes.to_le_bytes());
        out.extend_from_slice(&[0_u8; 12]);
        out.extend_from_slice(&self.mode.to_le_bytes());
        out.extend_from_slice(&win32_time(self.modified).to_le_bytes());
        out.extend_from_slice(&((self.size >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&((self.size & (u32::MAX as u64)) as u32).to_le_bytes());
        out.extend_from_slice(&name_field(&self.name)?);
        debug_assert_eq!(out.len(), FILE_DESCRIPTOR_SIZE);
        Ok(out)
    }

    /// The handle every range of this file is read from.
    fn handle(&mut self) -> Result<&File, CliprdrError> {
        if self.handle.is_none() {
            let handle = File::open(&self.path)
                .map_err(|error| CliprdrError::disk(DiskOp::Open, &error))?;
            let metadata = handle
                .metadata()
                .map_err(|error| CliprdrError::disk(DiskOp::Metadata, &error))?;
            // The opened object must still be the one the descriptor described.
            if metadata.is_dir() != self.is_dir || (!self.is_dir && metadata.len() != self.size) {
                return Err(CliprdrError::SourceChanged);
            }
            self.handle = Some(handle);
        }
        self.handle.as_ref().ok_or(CliprdrError::SourceChanged)
    }

    /// Reads `length` bytes at `offset` from the one opened source object.
    fn read_range(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, CliprdrError> {
        if length == 0 {
            // Upstream answers an empty range (an offset at the file's size) with
            // an empty successful response, without touching the handle.
            return Ok(Vec::new());
        }
        let handle = self.handle()?;
        let mut handle: &File = handle;
        handle
            .seek(SeekFrom::Start(offset))
            .map_err(|error| CliprdrError::disk(DiskOp::Read, &error))?;
        let mut buffer = vec![0_u8; length];
        handle
            .read_exact(&mut buffer)
            .map_err(|error| CliprdrError::disk(DiskOp::Read, &error))?;
        Ok(buffer)
    }
}

/// This side's announced file clipboard.
struct LocalOffer {
    /// The fence generation this offer was built under.
    revision: u64,
    files: Vec<OfferedFile>,
    /// The descriptor PDU for the whole list, built once at offer time.
    pdu: Vec<u8>,
    bytes: u64,
}

/// One record of a peer's descriptor list, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    /// Normalized relative name, `/`-separated.
    pub name: String,
    pub is_dir: bool,
    /// The size the descriptor stated. `0` means the peer did not state one; the
    /// size answer to the `FILECONTENTS_SIZE` request is what is actually used.
    pub declared: u64,
    /// The unix mode the peer described, if it sent one.
    pub perm: u16,
}

/// Parses a `FileGroupDescriptorW` PDU: a 4-byte count then that many 592-byte
/// records.
///
/// The checks are `FileDescription::parse_file_descriptors`': an exact total
/// length (`592 * count`), a valid-attributes flag, and the same name rules. One
/// bound is added — [`MAX_CLIPRDR_FILES`] — so a peer cannot make this allocate
/// an unbounded list before the length is even checked.
pub fn parse_descriptors(pdu: &[u8]) -> Result<Vec<RemoteEntry>, CliprdrError> {
    let mut cursor = Cursor::new(pdu);
    let count = cursor.u32()? as usize;
    if count > MAX_CLIPRDR_FILES {
        return Err(CliprdrError::DescriptorInvalid);
    }
    if count == 0 {
        return if cursor.remaining() == 0 {
            Ok(Vec::new())
        } else {
            Err(CliprdrError::DescriptorInvalid)
        };
    }
    if cursor.remaining() != FILE_DESCRIPTOR_SIZE * count {
        return Err(CliprdrError::DescriptorInvalid);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let flags = cursor.u32()?;
        cursor.take(32)?;
        let attributes = cursor.u32()?;
        cursor.take(12)?;
        let perm = cursor.u32()? as u16;
        // The last-write time is read for the record's length, then dropped: this
        // owner does not set it on a received file (see `finish_entry`).
        let _write_time = cursor.u64()?;
        let size_high = cursor.u32()?;
        let size_low = cursor.u32()?;
        let field = cursor.take(FILE_NAME_FIELD_SIZE)?;
        if flags & FLAGS_FD_ATTRIBUTES == 0 {
            return Err(CliprdrError::DescriptorInvalid);
        }
        // Upstream forces `valid_size = true` "for compatibility with Windows", so
        // the size fields are always read, even when `FLAGS_FD_SIZE` is unset.
        let declared = ((size_high as u64) << 32) | size_low as u64;
        entries.push(RemoteEntry {
            name: decode_name(field)?,
            is_dir: attributes & ATTRIBUTE_DIRECTORY != 0,
            declared,
            perm,
        });
    }
    Ok(entries)
}

/// Refuses a descriptor set whose names collide or whose parent is not a
/// directory: either would make two entries claim the same path.
fn validate_entries(entries: &[RemoteEntry]) -> Result<(), CliprdrError> {
    let mut kinds: HashMap<&str, bool> = HashMap::with_capacity(entries.len());
    for entry in entries {
        if kinds.insert(entry.name.as_str(), entry.is_dir).is_some() {
            return Err(CliprdrError::DescriptorInvalid);
        }
    }
    for entry in entries {
        let mut rest = entry.name.as_str();
        while let Some(index) = rest.rfind('/') {
            rest = &rest[..index];
            if let Some(is_dir) = kinds.get(rest) {
                if !*is_dir {
                    return Err(CliprdrError::DescriptorInvalid);
                }
            }
        }
    }
    Ok(())
}

/// One file of the peer's list as it is being received.
struct ReceivingFile {
    name: String,
    destination: PathBuf,
    /// This owner's own temporary name, in its own work directory.
    temporary: PathBuf,
    is_dir: bool,
    perm: u16,
    declared: u64,
    /// The size the peer answered, once it has.
    size: Option<u64>,
    written: u64,
    handle: Option<File>,
}

/// The request this job is waiting on. At most one is outstanding, which is what
/// makes a response's `stream_id` enough to attribute it.
#[derive(Debug, Clone, Copy)]
enum Awaiting {
    Size { stream: i32 },
    Range { stream: i32, offset: u64, requested: u64 },
}

impl Awaiting {
    fn stream(self) -> i32 {
        match self {
            Self::Size { stream } | Self::Range { stream, .. } => stream,
        }
    }
}

/// One peer file list being fetched, with the staging and work directories this
/// job alone owns.
struct ReceiveJob {
    request_id: u64,
    /// The fence generation that admitted this job. The bytes land on disk inside
    /// a pass that may outlive that generation (another thread can revoke while
    /// the blocking file work runs), so the generation travels with the job and is
    /// re-checked before anything of it is published.
    revision: u64,
    /// Where the finished entries are published from.
    dir: PathBuf,
    /// Where this job's temporary files live: a sibling of `dir`, so no name the
    /// peer can send can collide with one of ours.
    work: PathBuf,
    files: Vec<ReceivingFile>,
    next: usize,
    awaiting: Option<Awaiting>,
    bytes: u64,
}

impl ReceiveJob {
    fn current(&self) -> Option<usize> {
        (self.next < self.files.len()).then_some(self.next)
    }
}

/// The next thing a job needs, decided without borrowing the owner.
enum Step {
    /// Nothing more can be done without the peer's answer.
    Waiting,
    /// Every entry is on disk under this job's directory.
    Finished,
    /// The job must be aborted with this error.
    Failed(CliprdrError),
    /// Ask the peer for one file's size or one range of its bytes.
    Request { index: usize, kind: RequestKind },
}

#[derive(Debug, Clone, Copy)]
enum RequestKind {
    Size,
    Range { offset: u64, length: u64 },
}

/// One wire message the session's single writer must send, with the byte budget
/// it holds and the permission generation it was queued under. Dropping it
/// (after the send, or instead of it) releases those bytes.
pub struct CliprdrEffect {
    message: Message,
    fence: Arc<Fence>,
    revision: u64,
    _bytes: OwnedSemaphorePermit,
    /// Where a message whose writing the owner waits on reports back. Present
    /// only on the local offer's announcement, so ordinary answers stay one-way
    /// and the bounded queue is never a queue of ACKs.
    completion: Option<oneshot::Sender<bool>>,
}

impl std::fmt::Debug for CliprdrEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliprdrEffect")
            .field("message", &self.message)
            .field("revision", &self.revision)
            .field("completion", &self.completion.is_some())
            .finish()
    }
}

impl CliprdrEffect {
    /// The one message this effect carries. It carries nothing else: no socket,
    /// no runtime, and no promise that the peer consumed it.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Whether the fence still stands for this effect.
    ///
    /// The writer checks this before sending: an effect stamped with a generation
    /// the session has since left is one a revocation or a re-grant already
    /// reached, so it is dropped — never sent, and never sent under a later
    /// generation.
    pub fn is_permitted(&self) -> bool {
        self.fence.permits(self.revision)
    }

    /// Reports whether this effect was actually written, and releases it.
    ///
    /// This is how a written message is told apart from a queued one, and it is
    /// the *only* thing it means: this wire has no clipboard acknowledgement, so
    /// a written message is not a peer that applied anything. Dropping the effect
    /// without calling this closes the same answer without a `true`, so an
    /// unknown write is never read as a written one.
    pub fn complete(self, written: bool) {
        if let Some(completion) = self.completion {
            // The owner may already have stopped waiting (the session was
            // cancelled); then the answer is owed to nobody.
            let _ = completion.send(written);
        }
    }
}

/// What the local client acts on.
///
/// Every variant is a fact this session established, never a queued message: a
/// path here is a file whose bytes were flushed and finally named, an offer here
/// is one the session's writer reported writing, and a failure here is one the
/// owner decided. Nothing in this module is reported on the strength of being
/// put on a queue.
///
/// # Consumer contract: retained until taken
///
/// An event is **not** a one-shot fire-and-forget. It sits in the handle's
/// mailbox until a consumer takes it, and the mailbox is never drained by the
/// engine itself — not by a revocation, not by a close, not by a later event.
/// That is deliberate, because [`Self::Files`] is the only thing that tells the
/// client a peer's files are now real paths on this device: a poller that takes
/// events and ignores that variant would lose a completed paste for good.
///
/// So there are two shapes of caller and they use two different methods:
///
/// * A **notifier** (a background poll that only decides whether the foreground
///   should wake) asks [`CliprdrHandle::has_events`] or
///   [`CliprdrHandle::pending_events`]. Both are reads: the fact is still there
///   for whoever applies it next.
/// * The **one consumer that applies them** calls [`CliprdrHandle::take_events`]
///   or [`CliprdrHandle::take_events_limit`], and must act on every event it
///   receives — including forwarding [`Self::Files`] to the client's
///   `applyRemoteClipboard`-style path. A limit leaves the rest queued rather
///   than discarding them.
///
/// The mailbox holds at most [`CLIPRDR_EVENTS_KEPT`] facts, and reaching that
/// bound is backpressure rather than a reason to lose one: the owner waits for
/// the applying consumer to take a batch instead of replacing an older fact with
/// a newer one. A notifier that only ever looks therefore cannot be the session's
/// only reader — the engine keeps working only while its events are taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliprdrEvent {
    /// A peer's file list finished on disk. `paths` are this session's own final
    /// paths under the client's root — top-level entries of the peer's list, or
    /// every entry when the peer named only nested ones. `bytes` is what was
    /// really written.
    ///
    /// `revision` is the permission generation that admitted the job whose bytes
    /// these are. It is a fact about the past, not a claim about the present:
    /// events that were already queued keep it across a later withdrawal, and the
    /// applying consumer compares it with the live
    /// [`CliprdrHandle::revision`] before it treats the paths as the current
    /// clipboard. Files whose generation has been left are still real files — the
    /// event is how the consumer knows which ones to remove.
    Files {
        request_id: u64,
        revision: u64,
        paths: Vec<PathBuf>,
        bytes: u64,
    },
    /// This side's offer reached the session's one writer: the peer was told the
    /// formats this session carries. What the peer does with them is not
    /// observable here.
    Offered {
        request_id: u64,
        files: usize,
        bytes: u64,
    },
    /// A command or a transfer failed. `request_id` is the command's own id when
    /// one named it, and `None` when the failure belongs to no command (a stray
    /// peer answer).
    Failed {
        request_id: Option<u64>,
        error: CliprdrError,
    },
}

/// Why the owner stopped. The caller decides what that means for the session:
/// `Cancelled` is an ordinary close, the others mean nothing can be sent any
/// more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliprdrExit {
    Cancelled,
    CommandClosed,
    InboundClosed,
    OutboundClosed,
}

/// This owner's state that the client's handle reads: the fence, the request-id
/// counter and the events not yet taken.
struct Shared {
    fence: Arc<Fence>,
    next_request: AtomicU64,
    events: Mutex<VecDeque<CliprdrEvent>>,
    /// One permit per event in `events`: taken by [`Self::push`], returned by
    /// [`Self::take_events_limit`]. A full mailbox therefore makes the owner
    /// wait for the consumer instead of overwriting an older fact, and the count
    /// of events is bounded without ever dropping one.
    room: Semaphore,
    /// The session's cancel token, so a wait for room ends with the session
    /// rather than keeping the owner — and with it the caller's `JoinSet` — alive
    /// for a consumer that has gone.
    cancel: CancellationToken,
}

impl Shared {
    fn new(fence: Arc<Fence>, cancel: CancellationToken) -> Self {
        Self {
            fence,
            next_request: AtomicU64::new(0),
            events: Mutex::new(VecDeque::new()),
            room: Semaphore::new(CLIPRDR_EVENTS_KEPT),
            cancel,
        }
    }

    /// Request ids come from one monotonic counter, so a command's id and a
    /// receive this owner started for a peer's offer can never collide.
    fn next_request_id(&self) -> u64 {
        self.next_request.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Publishes one fact, waiting for room when the mailbox is full.
    ///
    /// A full mailbox means the applying consumer has not taken anything for a
    /// while, which is the same backpressure an ordinary bounded channel applies
    /// — not a licence to discard a completed paste. The wait ends when the
    /// consumer takes a batch, or with the session: `false` says the fact was not
    /// kept, and the only way to get it is a cancelled session, whose own
    /// shutdown reports nothing.
    async fn push(&self, event: CliprdrEvent) -> bool {
        let permit = match self.room.try_acquire() {
            Ok(permit) => permit,
            Err(_) => tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return false,
                permit = self.room.acquire() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return false,
                },
            },
        };
        lock(&self.events).push_back(event);
        // The permit now belongs to the queued fact, not to this call: taking the
        // fact returns it.
        permit.forget();
        true
    }

    fn take_events_limit(&self, limit: usize) -> Vec<CliprdrEvent> {
        let mut events = lock(&self.events);
        let count = events.len().min(limit);
        let taken: Vec<CliprdrEvent> = events.drain(..count).collect();
        drop(events);
        // Room for exactly what was taken; everything else stays queued.
        self.room.add_permits(count);
        taken
    }

    fn pending_events(&self) -> usize {
        lock(&self.events).len()
    }
}

/// The client's handle on a running owner.
pub struct CliprdrHandle {
    shared: Arc<Shared>,
    commands: mpsc::Sender<Issued>,
    /// Peer messages this session's reader has admitted, stamped with the
    /// generation they arrived in. Only [`Self::offer_inbound`] writes it.
    inbound: mpsc::Sender<CliprdrInbound>,
}

impl CliprdrHandle {
    /// Queues one command and answers the request id the client will see in this
    /// command's events.
    ///
    /// Never blocks: this runs on the client's own thread, which is not the
    /// engine's runtime. Only what can be decided without touching the
    /// filesystem is refused here (the fence, an empty or malformed path list);
    /// everything that needs a real directory — the root, whether an offered
    /// file exists, how far a directory expands — is discovered by the owner and
    /// reported as a [`CliprdrEvent::Failed`], never as a success receipt.
    pub fn submit(&self, command: CliprdrCommand) -> Result<u64, CliprdrError> {
        // The generation is taken first, so a withdrawal that lands while the
        // command is validated cannot be restamped as one of the new era.
        let revision = self.shared.fence.revision();
        let needs_permission = !matches!(&command, CliprdrCommand::ClearLocalOffer);
        if needs_permission && !self.shared.fence.is_allowed() {
            return Err(CliprdrError::PermissionDenied);
        }
        validate_command(&command)?;
        let request_id = self.shared.next_request_id();
        self.commands
            .try_send(Issued {
                request_id,
                revision,
                command,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => CliprdrError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => CliprdrError::Closed,
            })?;
        Ok(request_id)
    }

    /// Freezes one peer message at the generation in force when it arrived, then
    /// queues it for this session's owner.
    ///
    /// The viewer's reader calls this with everything it parsed out of a peer
    /// `Message::Cliprdr`. The stamp is read *before* room in the queue is
    /// awaited, so a message that arrives during a withdrawal or a re-grant keeps
    /// the era it really arrived in. The owner drops a message from an era it has
    /// left instead of applying it to the current one, and never restamps it. It
    /// waits when the owner's queue is full, which is the same backpressure the
    /// pinned client's session loop applies by awaiting its clipboard handler
    /// inline.
    pub async fn offer_inbound(&self, message: Cliprdr) -> Result<(), CliprdrError> {
        let revision = self.shared.fence.revision();
        self.inbound
            .send(CliprdrInbound { revision, message })
            .await
            .map_err(|_| CliprdrError::Closed)
    }

    /// Publishes the session's combined answer: authenticated Desktop, the peer's
    /// clipboard grant, the peer's file grant, the local clipboard switch, not
    /// read-only, not closing.
    ///
    /// Every transition in either direction moves the generation and drops what
    /// the previous answer held, so a re-grant never revives work a revocation
    /// reached.
    pub fn set_allowed(&self, allowed: bool) {
        self.shared.fence.set(allowed);
    }

    pub fn is_allowed(&self) -> bool {
        self.shared.fence.is_allowed()
    }

    /// Withdraws this session's permission: the peer revoked a grant, the
    /// operator went read-only, or the session is closing.
    pub fn revoke(&self) {
        self.shared.fence.set(false);
    }

    /// The generation every effect and command is stamped with.
    pub fn revision(&self) -> u64 {
        self.shared.fence.revision()
    }

    /// One coherent permission reading. Consumers must not combine a ticket
    /// from before a re-grant with the allowed flag from after it.
    pub fn permission(&self) -> (u64, bool) {
        self.shared.fence.permission()
    }

    /// Whether a fact is waiting. A read, never a hand-out: a notifier may ask
    /// this as often as it likes and the event is still there for the consumer
    /// that applies it.
    pub fn has_events(&self) -> bool {
        self.shared.pending_events() > 0
    }

    /// How many facts are waiting. A read, like [`Self::has_events`].
    pub fn pending_events(&self) -> usize {
        self.shared.pending_events()
    }

    /// Every event not yet taken, consuming them.
    ///
    /// This is the applying consumer's call, not a notifier's: see the consumer
    /// contract on [`CliprdrEvent`]. The caller must act on every event it
    /// receives, including [`CliprdrEvent::Files`].
    pub fn take_events(&self) -> Vec<CliprdrEvent> {
        self.take_events_limit(usize::MAX)
    }

    /// At most `limit` of the oldest events not yet taken; the rest stay queued,
    /// so a client that reports events under its own per-poll limit loses none.
    pub fn take_events_limit(&self, limit: usize) -> Vec<CliprdrEvent> {
        self.shared.take_events_limit(limit)
    }
}

impl std::fmt::Debug for CliprdrHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliprdrHandle")
            .field("fence", &self.shared.fence)
            .field("pending_events", &lock(&self.shared.events).len())
            .finish()
    }
}

/// One peer `Message::Cliprdr` as the viewer's reader admitted it.
///
/// The wrapper carries exactly one extra fact: the permission generation in force
/// when the message arrived. The owner may only reach the queue entry much later —
/// its own disk work and the writer's writes happen in between — and a withdrawal
/// and a re-grant can both land inside that window. Without the stamp a message
/// the peer sent before the withdrawal would be handled as traffic of the new era
/// and its effects would carry the new generation: work admitted by an older
/// ticket, restamped.
///
/// The fields are private on purpose: the only way to build one is
/// [`CliprdrHandle::offer_inbound`], which reads the generation before it waits
/// for room in a full queue.
pub struct CliprdrInbound {
    revision: u64,
    message: Cliprdr,
}

/// What [`start`] hands the caller: the task to spawn, the client's handle, and
/// the one channel end the viewer's writer owns.
///
/// There is no inbound sender here: the viewer's reader hands peer messages over
/// with [`CliprdrHandle::offer_inbound`], which is the only way to stamp them.
pub struct CliprdrStart {
    pub owner: CliprdrOwner,
    pub handle: Arc<CliprdrHandle>,
    /// The effects the viewer's one writer must send.
    pub outbound: mpsc::Receiver<CliprdrEffect>,
}

/// Builds the owner and its channels. Nothing runs until the caller spawns
/// [`CliprdrOwner::run`] on the session's own executor, and no runtime is created
/// here.
pub fn start(cancel: CancellationToken) -> CliprdrStart {
    let (commands_tx, commands_rx) = mpsc::channel(CLIPRDR_COMMAND_QUEUE);
    let (inbound_tx, inbound_rx) = mpsc::channel(CLIPRDR_INBOUND_QUEUE);
    let (outbound_tx, outbound_rx) = mpsc::channel(CLIPRDR_OUTBOUND_QUEUE);
    // The fence starts closed: the caller publishes the session's real facts with
    // `set_allowed` once it is authenticated and the peer's grants are known.
    let fence = Arc::new(Fence::new());
    let shared = Arc::new(Shared::new(Arc::clone(&fence), cancel.clone()));
    CliprdrStart {
        owner: CliprdrOwner {
            shared: Arc::clone(&shared),
            commands: commands_rx,
            inbound: inbound_rx,
            outbound: outbound_tx,
            bytes: Arc::new(Semaphore::new(CLIPRDR_OUTBOUND_BYTES)),
            cancel,
            revision: fence.revision(),
            root: None,
            offer: None,
            receive: None,
            pending_offer: None,
            descriptor_slot: None,
            answer_deadline: None,
            next_stream: 1,
        },
        handle: Arc::new(CliprdrHandle {
            shared,
            commands: commands_tx,
            inbound: inbound_tx,
        }),
        outbound: outbound_rx,
    }
}

/// One `Message::Cliprdr` carrying `union`.
fn cliprdr_message(union: proto::cliprdr::Union) -> Message {
    let mut message = Message::new();
    message.set_cliprdr(Cliprdr {
        union: Some(union),
        ..Default::default()
    });
    message
}

/// This side's file formats, in upstream's `unix_file_clip::get_format_list`
/// order: the descriptor list, then the contents.
fn format_list_message() -> Message {
    cliprdr_message(proto::cliprdr::Union::FormatList(
        proto::CliprdrServerFormatList {
            formats: vec![
                proto::CliprdrFormat {
                    id: FILEDESCRIPTOR_FORMAT_ID,
                    format: FILEDESCRIPTORW_FORMAT_NAME.to_owned(),
                    ..Default::default()
                },
                proto::CliprdrFormat {
                    id: FILECONTENTS_FORMAT_ID,
                    format: FILECONTENTS_FORMAT_NAME.to_owned(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    ))
}

/// "Send me the descriptor list carried under this format id."
fn format_data_request_message(requested_format_id: i32) -> Message {
    cliprdr_message(proto::cliprdr::Union::FormatDataRequest(
        proto::CliprdrServerFormatDataRequest {
            requested_format_id,
            ..Default::default()
        },
    ))
}

/// The descriptor PDU as a `FormatDataResponse`.
fn format_data_response_message(data: Vec<u8>) -> Message {
    cliprdr_message(proto::cliprdr::Union::FormatDataResponse(
        proto::CliprdrServerFormatDataResponse {
            msg_flags: MSG_FLAGS_OK,
            format_data: data.into(),
            ..Default::default()
        },
    ))
}

/// The same answer with the protocol's own failure flag, exactly as upstream's
/// `msg_resp_format_data_failure`.
fn format_data_failure_message() -> Message {
    cliprdr_message(proto::cliprdr::Union::FormatDataResponse(
        proto::CliprdrServerFormatDataResponse {
            msg_flags: MSG_FLAGS_FAIL,
            format_data: Vec::new().into(),
            ..Default::default()
        },
    ))
}

/// One `FileContentsRequest`: `FILECONTENTS_SIZE` asks for the size, and
/// `FILECONTENTS_RANGE` for bytes at an offset. The position is split into the
/// wire's two unsigned 32-bit halves.
fn file_contents_request_message(
    stream_id: i32,
    list_index: usize,
    kind: RequestKind,
) -> Message {
    let (dw_flags, offset, requested) = match kind {
        RequestKind::Size => (FILECONTENTS_SIZE, 0_u64, 0_i32),
        RequestKind::Range { offset, length } => {
            (FILECONTENTS_RANGE, offset, length.min(i32::MAX as u64) as i32)
        }
    };
    cliprdr_message(proto::cliprdr::Union::FileContentsRequest(
        proto::CliprdrFileContentsRequest {
            stream_id,
            list_index: list_index as i32,
            dw_flags,
            n_position_low: offset as u32 as i32,
            n_position_high: (offset >> 32) as u32 as i32,
            cb_requested: requested,
            // Windows' clipboard-data lock id is not used by this owner; upstream
            // ignores both fields on receipt too.
            have_clip_data_id: false,
            clip_data_id: 0,
            ..Default::default()
        },
    ))
}

/// One `FileContentsResponse` for the stream the peer asked on.
fn file_contents_response_message(
    msg_flags: i32,
    stream_id: i32,
    data: Vec<u8>,
) -> Message {
    cliprdr_message(proto::cliprdr::Union::FileContentsResponse(
        proto::CliprdrFileContentsResponse {
            msg_flags,
            stream_id,
            requested_data: data.into(),
            ..Default::default()
        },
    ))
}

/// "The shared file clipboard is empty": what upstream's
/// `try_empty_clipboard_files` tells a peer after the local file clipboard goes
/// away (see the comment on `CliprdrTryEmpty` in `message.proto`).
fn try_empty_message() -> Message {
    cliprdr_message(proto::cliprdr::Union::TryEmpty(
        proto::CliprdrTryEmpty::default(),
    ))
}

/// The id the peer advertised for its descriptor list, matched by name first
/// because the id is only a convention between implementations.
fn descriptor_format_id(formats: &proto::CliprdrServerFormatList) -> Option<i32> {
    let by_name = formats
        .formats
        .iter()
        .find(|format| format.format == FILEDESCRIPTORW_FORMAT_NAME)
        .map(|format| format.id);
    if by_name.is_some() {
        return by_name;
    }
    formats
        .formats
        .iter()
        .find(|format| format.id == FILEDESCRIPTOR_FORMAT_ID)
        .map(|format| format.id)
}

/// Whether a peer's `FormatList` is a file offer: it must carry the contents
/// format too, exactly as upstream's `serve_clip_messages` requires.
fn is_file_offer(formats: &proto::CliprdrServerFormatList) -> bool {
    let contents = formats
        .formats
        .iter()
        .any(|format| format.format == FILECONTENTS_FORMAT_NAME);
    contents && descriptor_format_id(formats).is_some()
}

/// Refuses what a command can be refused for without touching the filesystem.
fn validate_command(command: &CliprdrCommand) -> Result<(), CliprdrError> {
    match command {
        CliprdrCommand::SetRoot(root) => {
            if !root.is_absolute() || root.as_os_str().is_empty() {
                return Err(CliprdrError::RootInvalid);
            }
            if root.to_string_lossy().as_bytes().contains(&0) {
                return Err(CliprdrError::RootInvalid);
            }
            Ok(())
        }
        CliprdrCommand::OfferFiles(paths) => {
            if paths.is_empty() {
                return Err(CliprdrError::OfferEmpty);
            }
            if paths.len() > MAX_CLIPRDR_OFFER_ROOTS {
                return Err(CliprdrError::OfferTooLarge);
            }
            for path in paths {
                if !path.is_absolute() || path.as_os_str().is_empty() {
                    return Err(CliprdrError::OfferPathInvalid);
                }
                if path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
                {
                    return Err(CliprdrError::OfferPathInvalid);
                }
                if path.file_name().is_none() {
                    return Err(CliprdrError::OfferPathInvalid);
                }
            }
            Ok(())
        }
        CliprdrCommand::ClearLocalOffer => Ok(()),
    }
}

/// This session's one outstanding `FormatDataRequest`, as the wire can see it.
///
/// A `FormatDataResponse` carries **no request id**. The only thing that can tell
/// one answer from another is which request is outstanding, so the slot has to
/// outlive its own request: when a request ends any other way than by its answer,
/// a timeout, a permission generation that was replaced, the peer replacing its
/// list, or a close, the slot keeps a tombstone instead of being cleared. The one
/// untagged answer still owed to that request is then absorbed, and no new request
/// is admitted before it is. Clearing the slot instead is what would let a late
/// answer be attributed to the next request and file one offer's files under
/// another.
enum DescriptorSlot {
    /// Sent, and this session is waiting for its answer.
    InFlight { request_id: u64 },
    /// The request already ended (its end was reported) but its answer is still
    /// owed. The next `FormatDataResponse` drains this and is applied to nothing.
    Retired,
}

/// The session-owned file clipboard owner.
///
/// It runs as one task in the viewer's own `JoinSet`, next to the reader, the
/// writer, the clipboard decode and the transfer owner. It holds no socket, no
/// runtime and no second writer: everything it wants sent leaves as a
/// [`CliprdrEffect`], and everything it did leaves as a [`CliprdrEvent`].
pub struct CliprdrOwner {
    shared: Arc<Shared>,
    commands: mpsc::Receiver<Issued>,
    inbound: mpsc::Receiver<CliprdrInbound>,
    outbound: mpsc::Sender<CliprdrEffect>,
    bytes: Arc<Semaphore>,
    cancel: CancellationToken,
    /// The fence generation this pass acts under. Every effect and every peer
    /// answer this pass produces is stamped with it, so a change that lands
    /// mid-pass cannot be applied to work the previous answer admitted.
    revision: u64,
    root: Option<PathBuf>,
    offer: Option<LocalOffer>,
    receive: Option<ReceiveJob>,
    /// The newest peer offer that could not be asked about yet (its descriptor
    /// format id). Only the latest is kept: an older one describes a list the peer
    /// has already replaced.
    pending_offer: Option<i32>,
    /// This session's one outstanding descriptor request, or the tombstone of the
    /// last one until its untagged answer drains (see [`DescriptorSlot`]).
    descriptor_slot: Option<DescriptorSlot>,
    /// When the answer this owner is waiting for becomes a failure.
    answer_deadline: Option<Instant>,
    /// Stream ids are allocated monotonically and never reused, so a late answer
    /// can never be attributed to a later task.
    next_stream: i32,
}

impl CliprdrOwner {
    /// Runs the owner until the session ends.
    ///
    /// This is the task boundary the caller's `JoinSet` awaits, so a close waits
    /// for the owner and its in-flight disk work instead of aborting it and
    /// leaving handles behind. A cancel is observed between two real operations,
    /// never inside a started read or write, and a revocation is acted on at the
    /// same boundary.
    pub async fn run(mut self) -> CliprdrExit {
        loop {
            if self.cancel.is_cancelled() {
                self.shutdown();
                return CliprdrExit::Cancelled;
            }
            if self.outbound.is_closed() {
                // The one writer is gone: nothing this owner decided can reach the
                // peer any more.
                self.shutdown();
                return CliprdrExit::OutboundClosed;
            }
            self.adopt_fence().await;
            // A deadline is due at a *pass* boundary, not only where the loop
            // idles: `wait()` is never reached while a command or a peer message
            // is always ready, so a queue that is never empty would postpone this
            // owner's own 30 s answer timeout forever. Real traffic therefore
            // cannot invalidate it.
            if self.answer_due() {
                self.expire().await;
                continue;
            }
            match self.commands.try_recv() {
                Ok(issued) => {
                    self.command(issued).await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.shutdown();
                    return CliprdrExit::CommandClosed;
                }
            }
            match self.inbound.try_recv() {
                Ok(inbound) => {
                    self.receive_inbound(inbound).await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.shutdown();
                    return CliprdrExit::InboundClosed;
                }
            }
            if let Some(exit) = self.wait().await {
                self.shutdown();
                return exit;
            }
        }
    }

    /// Waits for the next command, peer message, fence change or expired answer.
    /// `Some(exit)` means the owner must stop.
    async fn wait(&mut self) -> Option<CliprdrExit> {
        enum Ready {
            Command(Issued),
            Inbound(CliprdrInbound),
            Fence,
            Expired,
        }
        // Read before the `select!`, so no branch borrows the owner while the
        // others poll its fields.
        let deadline = self.answer_deadline;
        let ready = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Some(CliprdrExit::Cancelled),
            _ = self.shared.fence.changed.notified() => Ready::Fence,
            command = self.commands.recv() => match command {
                Some(command) => Ready::Command(command),
                None => return Some(CliprdrExit::CommandClosed),
            },
            message = self.inbound.recv() => match message {
                Some(message) => Ready::Inbound(message),
                None => return Some(CliprdrExit::InboundClosed),
            },
            _ = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending::<()>().await,
                }
            } => Ready::Expired,
        };
        match ready {
            Ready::Command(issued) => self.command(issued).await,
            Ready::Inbound(inbound) => self.receive_inbound(inbound).await,
            // The next pass acts on it, at its own boundary.
            Ready::Fence => {}
            Ready::Expired => self.expire().await,
        }
        None
    }

    fn allowed(&self) -> bool {
        self.shared.fence.is_allowed()
    }

    /// Whether work admitted under `revision` may still take effect.
    ///
    /// Read from the live fence, never from this pass's snapshot: a pass that is
    /// inside blocking file work cannot observe a withdrawal until its next
    /// boundary, while another thread can publish one at any moment.
    fn admission(&self, revision: u64) -> Result<(), CliprdrError> {
        if self.cancel.is_cancelled() {
            return Err(CliprdrError::Cancelled);
        }
        if !self.shared.fence.is_allowed() || self.shared.fence.revision() != revision {
            return Err(CliprdrError::PermissionDenied);
        }
        Ok(())
    }

    /// Brings this owner in line with the fence at a pass boundary.
    ///
    /// Any change of the generation ends everything the owner still holds: the
    /// offer's handles are closed, a receive's own partial files are removed and
    /// reported, and the one outstanding descriptor request is retired. Nothing of
    /// it is ever given the new generation; a re-grant admits new work only.
    async fn adopt_fence(&mut self) {
        let revision = self.shared.fence.revision();
        if revision == self.revision {
            return;
        }
        self.revision = revision;
        // The change is acted on even when the fence reads open again: a
        // withdrawal and the re-grant that follows it can both land while this
        // owner is inside a disk operation or waiting on the writer, so `allowed`
        // now says nothing about whether the work still held was admitted by the
        // generation in force. It is dropped, never restamped.
        self.offer = None;
        self.drop_remote_state(CliprdrError::PermissionDenied).await;
    }

    /// Whether an answer this owner is waiting on has passed its deadline.
    ///
    /// Checked at every pass boundary so a ready queue cannot postpone it.
    fn answer_due(&self) -> bool {
        self.answer_deadline.is_some_and(|at| Instant::now() >= at)
    }

    /// One peer message the viewer's reader admitted, with the generation it
    /// arrived under.
    ///
    /// The era is adopted first: a message may have been stamped after a change
    /// this pass has not seen yet. A message from an era this owner has left is
    /// never restamped into the current one and never starts current-era work:
    ///
    /// * a `FormatDataResponse` still drains the tombstone of the request it was
    ///   owed to, and nothing from it is applied — dropping it would leave this
    ///   optional feature blocked on a request that can never be answered again;
    /// * everything else — a `FormatList` included — is dropped. A notification
    ///   the peer sent in an era this session has left describes the peer's
    ///   clipboard as it was then; acting on it now would start a new-era
    ///   transfer out of withdrawn traffic.
    async fn receive_inbound(&mut self, inbound: CliprdrInbound) {
        self.adopt_fence().await;
        if inbound.revision != self.revision {
            if matches!(
                &inbound.message.union,
                Some(proto::cliprdr::Union::FormatDataResponse(_))
            ) {
                self.drain_retired_descriptor_answer();
                // Only an offer that is already current-era work can be waiting
                // here: the era change above dropped everything older.
                self.resume_pending().await;
            }
            return;
        }
        self.received(inbound.message).await;
    }

    /// Ends the owner's own state without reporting anything: the session is over,
    /// so nobody is owed the fact. Only this owner's files are removed.
    fn shutdown(&mut self) {
        self.pending_offer = None;
        self.descriptor_slot = None;
        self.offer = None;
        self.answer_deadline = None;
        if let Some(mut job) = self.receive.take() {
            close_handles(&mut job);
            self.remove_job_files(&job);
        }
    }

    async fn command(&mut self, issued: Issued) {
        // A command is work admitted by the generation it was submitted under.
        // The era is adopted before it is compared, so a withdrawal and the
        // re-grant that follows it both reach it even though the fence reads open
        // again by the time this pass runs.
        self.adopt_fence().await;
        let request_id = issued.request_id;
        if issued.revision != self.revision {
            self.fail(Some(request_id), CliprdrError::PermissionDenied).await;
            return;
        }
        match issued.command {
            CliprdrCommand::SetRoot(path) => {
                if !self.allowed() {
                    self.fail(Some(request_id), CliprdrError::PermissionDenied).await;
                    return;
                }
                match adopt_root(&path) {
                    Ok(root) => self.root = Some(root),
                    Err(error) => self.fail(Some(request_id), error).await,
                }
            }
            CliprdrCommand::OfferFiles(paths) => {
                if !self.allowed() {
                    self.fail(Some(request_id), CliprdrError::PermissionDenied).await;
                    return;
                }
                // A new offer replaces the previous one, its handles included.
                self.offer = None;
                match build_offer(self.revision, &paths) {
                    Ok(offer) => {
                        let files = offer.files.len();
                        let bytes = offer.bytes;
                        self.offer = Some(offer);
                        self.announce_offer(request_id, files, bytes).await;
                    }
                    Err(error) => self.fail(Some(request_id), error).await,
                }
            }
            CliprdrCommand::ClearLocalOffer => self.clear_offer(request_id).await,
        }
    }

    /// Tells the peer which formats this side carries, and reports what really
    /// happened to the announcement.
    async fn announce_offer(&mut self, request_id: u64, files: usize, bytes: u64) {
        match self.announce(format_list_message(), 64).await {
            Ok(true) => {
                self.push(CliprdrEvent::Offered {
                    request_id,
                    files,
                    bytes,
                })
                .await;
            }
            Ok(false) => {
                // The writer took the effect but did not write it: either it was
                // stale by the time the writer reached it, or the write failed.
                // The offer is not announced, so it is not offered any more.
                self.offer = None;
                self.fail(Some(request_id), CliprdrError::NotWritten).await;
            }
            Err(error) => {
                self.offer = None;
                self.fail(Some(request_id), error).await;
            }
        }
    }

    /// Withdraws the local offer, and tells the peer the file clipboard is empty
    /// if one had been announced.
    async fn clear_offer(&mut self, request_id: u64) {
        if self.offer.take().is_none() {
            // Nothing was announced, so the peer's file clipboard never held
            // anything of this side: there is nothing to tell it.
            return;
        }
        // `CliprdrTryEmpty`, exactly as upstream's `try_empty_clipboard_files`
        // tells the other side after its own file clipboard goes away.
        if let Err(error) = self.queue(try_empty_message(), 64).await {
            self.fail(Some(request_id), error).await;
        }
    }

    async fn received(&mut self, clip: Cliprdr) {
        let Some(union) = clip.union else {
            // An empty union carries nothing to answer.
            return;
        };
        match union {
            // Informational in RustDesk's own implementation: `serve_clip_messages`
            // only logs it and sends nothing back, on either side.
            proto::cliprdr::Union::Ready(_) => {}
            proto::cliprdr::Union::FormatList(formats) => self.receive_format_list(formats).await,
            // RustDesk's own clipboard-file implementation never asks for one and
            // ignores it when it arrives; only the FreeRDP-derived Windows C
            // component sends it, and it carries no fact this side acts on.
            proto::cliprdr::Union::FormatListResponse(_) => {}
            proto::cliprdr::Union::FormatDataRequest(request) => {
                self.serve_descriptors(request.requested_format_id).await
            }
            proto::cliprdr::Union::FormatDataResponse(response) => {
                self.receive_descriptors(response).await
            }
            proto::cliprdr::Union::FileContentsRequest(request) => {
                self.serve_contents(request).await
            }
            proto::cliprdr::Union::FileContentsResponse(response) => {
                self.receive_contents(response).await
            }
            proto::cliprdr::Union::TryEmpty(_) => {
                // The peer emptied the shared file clipboard: this side's offer
                // goes with it, and so does anything it was still sending us.
                self.offer = None;
                self.drop_remote_state(CliprdrError::PeerReplacedClipboard).await;
            }
            // The audit-only variant: a summary for a peer's own record, never
            // content this session applies.
            proto::cliprdr::Union::Files(_) => {}
            // Generated protobuf oneofs are non-exhaustive. Unknown future
            // extensions carry no operation this owner can apply or acknowledge.
            _ => {}
        }
    }

    /// A peer's `FormatList`: either it is offering files, or it replaced its
    /// clipboard with something else.
    async fn receive_format_list(&mut self, formats: proto::CliprdrServerFormatList) {
        if !is_file_offer(&formats) {
            // The files this side was fetching describe a list the peer no longer
            // has; its indices are meaningless from now on.
            self.drop_remote_state(CliprdrError::PeerReplacedClipboard).await;
            return;
        }
        if !self.allowed() {
            return;
        }
        let Some(descriptor_id) = descriptor_format_id(&formats) else {
            return;
        };
        if self.descriptor_slot.is_some() {
            // One descriptor request at a time. A `FormatDataResponse` carries no
            // request id, so a second outstanding request could never be told
            // apart from the first's answer. Only the newest offer waits.
            self.pending_offer = Some(descriptor_id);
            return;
        }
        self.start_descriptor_request(descriptor_id).await;
    }

    /// Drops everything this side held for a peer's file list, reporting the one
    /// request that can no longer be answered.
    async fn drop_remote_state(&mut self, error: CliprdrError) {
        self.pending_offer = None;
        self.answer_deadline = None;
        if let Some(request_id) = self.retire_descriptor_request() {
            self.fail(Some(request_id), error.clone()).await;
        }
        if let Some(mut job) = self.receive.take() {
            close_handles(&mut job);
            self.abort_receive(job, error).await;
        }
    }

    /// Ends this session's descriptor request without freeing its slot: the one
    /// `FormatDataResponse` it is still owed carries no request id, so the slot
    /// keeps a tombstone until that answer is absorbed. Returns the request that
    /// was still in flight, if one was.
    fn retire_descriptor_request(&mut self) -> Option<u64> {
        if !matches!(self.descriptor_slot, Some(DescriptorSlot::InFlight { .. })) {
            return None;
        }
        match self.descriptor_slot.replace(DescriptorSlot::Retired) {
            Some(DescriptorSlot::InFlight { request_id }) => Some(request_id),
            _ => None,
        }
    }

    /// Drains the tombstone once the late answer to a retired request arrives. Its
    /// content is never applied; freeing the slot is the only effect.
    fn drain_retired_descriptor_answer(&mut self) {
        if matches!(self.descriptor_slot, Some(DescriptorSlot::Retired)) {
            self.descriptor_slot = None;
        }
    }

    /// Asks the peer for the descriptor list of its current offer.
    async fn start_descriptor_request(&mut self, descriptor_id: i32) {
        let request_id = self.shared.next_request_id();
        self.pending_offer = None;
        // A new file list replaces whatever was being fetched: the peer's
        // `list_index` refers to its *current* list, so the old indices can no
        // longer be used for anything.
        if let Some(mut job) = self.receive.take() {
            close_handles(&mut job);
            self.abort_receive(job, CliprdrError::PeerReplacedClipboard).await;
        }
        match self
            .queue(format_data_request_message(descriptor_id), 64)
            .await
        {
            Ok(()) => {
                self.descriptor_slot = Some(DescriptorSlot::InFlight { request_id });
                self.answer_deadline = Some(Instant::now() + CLIPRDR_RESPONSE_TIMEOUT);
            }
            Err(error) => self.fail(Some(request_id), error).await,
        }
    }

    /// Answers the peer's `FormatDataRequest` with this side's descriptor list.
    async fn serve_descriptors(&mut self, requested_format_id: i32) {
        if !self.allowed() {
            return;
        }
        // The clone ends the borrow before anything is awaited.
        let advertised = (requested_format_id == FILEDESCRIPTOR_FORMAT_ID)
            .then(|| self.offer.as_ref().map(|offer| offer.pdu.clone()))
            .flatten();
        match advertised {
            Some(data) => {
                let bytes = data.len();
                let _ = self
                    .queue(format_data_response_message(data), bytes + 64)
                    .await;
            }
            None => {
                // Nothing is offered under this format, so the protocol's own
                // failure answer is the honest answer (upstream's
                // `msg_resp_format_data_failure`). This is also stricter than
                // upstream, which answers the file list for whatever id was
                // asked for; answering a format this side never advertised would
                // be a wrong answer nobody notices.
                let _ = self.queue(format_data_failure_message(), 64).await;
            }
        }
    }

    /// The answer to this session's one outstanding descriptor request.
    async fn receive_descriptors(&mut self, response: proto::CliprdrServerFormatDataResponse) {
        let Some(slot) = self.descriptor_slot.take() else {
            // A `FormatDataResponse` carries no request id, so with nothing
            // outstanding there is no offer it could be attributed to. Guessing
            // would file one offer's files under another.
            self.fail(None, CliprdrError::DescriptorUnrequested).await;
            return;
        };
        let DescriptorSlot::InFlight { request_id } = slot else {
            // The answer this session is still owed to a request that already
            // ended is absorbed here, which is what frees the slot for the next
            // request. Nothing from it is applied.
            hbb_common::log::debug!("cliprdr: absorbing a retired descriptor answer");
            self.resume_pending().await;
            return;
        };
        self.answer_deadline = None;
        if response.msg_flags != MSG_FLAGS_OK {
            self.fail(Some(request_id), CliprdrError::PeerFailed).await;
            self.resume_pending().await;
            return;
        }
        let data: &[u8] = response.format_data.as_ref();
        if let Err(error) = self.begin_receive(request_id, data).await {
            self.fail(Some(request_id), error).await;
            self.resume_pending().await;
        }
    }

    /// Starts the newest offer that was waiting for the descriptor slot.
    async fn resume_pending(&mut self) {
        // One request at a time, tombstone included: while an untagged answer is
        // still owed, a second request could never be told apart from it.
        if self.descriptor_slot.is_some() {
            return;
        }
        if let Some(descriptor_id) = self.pending_offer.take() {
            self.start_descriptor_request(descriptor_id).await;
        }
    }

    /// Turns a peer's descriptor list into one receive job and starts it.
    async fn begin_receive(&mut self, request_id: u64, pdu: &[u8]) -> Result<(), CliprdrError> {
        let root = self.root.clone().ok_or(CliprdrError::RootUnset)?;
        let entries = parse_descriptors(pdu)?;
        if entries.is_empty() {
            return Err(CliprdrError::PeerEmpty);
        }
        validate_entries(&entries)?;
        // Every destination is built before any directory exists, so a name this
        // owner refuses leaves nothing behind.
        let dir = root.join(format!(".cliprdr-{request_id}"));
        let work = root.join(format!(".cliprdr-work-{request_id}"));
        let mut files = Vec::with_capacity(entries.len());
        for (index, entry) in entries.into_iter().enumerate() {
            let destination = join_descriptor_name(&dir, &entry.name)?;
            files.push(ReceivingFile {
                temporary: work.join(index.to_string()),
                destination,
                name: entry.name,
                is_dir: entry.is_dir,
                perm: entry.perm,
                declared: entry.declared,
                size: None,
                written: 0,
                handle: None,
            });
        }
        prepare_dir(&work)?;
        if let Err(error) = prepare_dir(&dir) {
            let _ = fs::remove_dir_all(&work);
            return Err(error);
        }
        self.receive = Some(ReceiveJob {
            request_id,
            revision: self.revision,
            dir,
            work,
            files,
            next: 0,
            awaiting: None,
            bytes: 0,
        });
        self.advance().await;
        Ok(())
    }

    /// Drives one receive job forward until it needs the peer's answer, finishes,
    /// or fails.
    ///
    /// The job is taken out of `self` for each decision so the step function never
    /// borrows the owner, and put back before anything is awaited: a started disk
    /// operation is always awaited to completion rather than dropped, which is
    /// what keeps a close from replaying it.
    async fn advance(&mut self) {
        loop {
            let Some(mut job) = self.receive.take() else {
                return;
            };
            match step(&mut job) {
                Step::Waiting => {
                    self.receive = Some(job);
                    return;
                }
                Step::Finished => {
                    self.finish_receive(job).await;
                    return;
                }
                Step::Failed(error) => {
                    self.abort_receive(job, error).await;
                    return;
                }
                Step::Request { index, kind } => {
                    let stream = self.next_stream;
                    if stream == i32::MAX {
                        // Stream ids are never reused, so the last one this wire
                        // can carry ends the transfer instead of wrapping into an
                        // id a peer has already seen.
                        self.abort_receive(job, CliprdrError::StreamExhausted).await;
                        return;
                    }
                    self.next_stream = stream + 1;
                    let message = file_contents_request_message(stream, index, kind);
                    job.awaiting = Some(match kind {
                        RequestKind::Size => Awaiting::Size { stream },
                        RequestKind::Range { offset, length } => Awaiting::Range {
                            stream,
                            offset,
                            requested: length,
                        },
                    });
                    self.receive = Some(job);
                    match self.queue(message, 64).await {
                        Ok(()) => {
                            self.answer_deadline =
                                Some(Instant::now() + CLIPRDR_RESPONSE_TIMEOUT);
                            return;
                        }
                        Err(error) => {
                            if let Some(mut job) = self.receive.take() {
                                close_handles(&mut job);
                                self.abort_receive(job, error).await;
                            }
                            return;
                        }
                    }
                }
            }
        }
    }

    /// One peer answer for the file contents request in flight.
    async fn receive_contents(&mut self, response: proto::CliprdrFileContentsResponse) {
        let Some(mut job) = self.receive.take() else {
            // Nothing is being fetched, so this answer belongs to no request this
            // session made. It is reported, never guessed at.
            self.fail(None, CliprdrError::StreamMismatch).await;
            return;
        };
        let Some(awaiting) = job.awaiting.take() else {
            self.receive = Some(job);
            self.fail(None, CliprdrError::StreamMismatch).await;
            return;
        };
        if response.stream_id != awaiting.stream() {
            if response.stream_id < awaiting.stream() {
                // A task this session already abandoned — its abort was reported —
                // is not written anywhere, and a later task must never receive it.
                // The request still in flight is left exactly as it was, *including
                // its deadline*: an answer to an older stream is not the answer the
                // live request is waiting for, so it cannot extend, cancel or
                // otherwise touch that wait.
                job.awaiting = Some(awaiting);
                self.receive = Some(job);
                return;
            }
            // A stream this owner never allocated: nothing can be attributed to it,
            // and the request in flight is not going to be answered, so the job is
            // ended rather than left waiting for an answer that has passed.
            self.abort_receive(job, CliprdrError::StreamMismatch).await;
            return;
        }
        // The answer the live request was waiting for: only now is that wait over.
        self.answer_deadline = None;
        if response.msg_flags != MSG_FLAGS_OK {
            self.abort_receive(job, CliprdrError::PeerFailed).await;
            return;
        }
        let data: &[u8] = response.requested_data.as_ref();
        let outcome = match awaiting {
            Awaiting::Size { .. } => size_answer(&mut job, data),
            Awaiting::Range {
                offset, requested, ..
            } => range_answer(&mut job, data, offset, requested),
        };
        if let Err(error) = outcome {
            self.abort_receive(job, error).await;
            return;
        }
        self.receive = Some(job);
        self.advance().await;
    }

    /// Publishes a batch that really is on disk under the generation that admitted
    /// it, and admits the next offer.
    ///
    /// The file work of a job happens inside one pass, and another thread can
    /// revoke while it runs, so the generation is re-read here — from the live
    /// fence, not from this pass's snapshot. Bytes that finished landing after the
    /// withdrawal are this job's own files to remove, never a new-era clipboard,
    /// and the failure is reported against the request that opened the job.
    async fn finish_receive(&mut self, job: ReceiveJob) {
        if let Err(error) = self.admission(job.revision) {
            self.abort_receive(job, error).await;
            return;
        }
        // The work directory only ever held this job's own temporaries; the final
        // entries stay where they were published.
        if let Err(error) = fs::remove_dir_all(&job.work) {
            if error.kind() != std::io::ErrorKind::NotFound {
                hbb_common::log::warn!(
                    "cliprdr: leaving {} in place: {}",
                    job.work.display(),
                    error
                );
            }
        }
        let paths = publish_paths(&job);
        let published = self
            .push(CliprdrEvent::Files {
                request_id: job.request_id,
                revision: job.revision,
                paths,
                bytes: job.bytes,
            })
            .await;
        if !published {
            // The session closed while this owner waited for mailbox room, so no
            // consumer will ever apply these paths. They were never handed out, so
            // they are removed instead of being left behind unreported.
            self.abort_receive(job, CliprdrError::Cancelled).await;
            return;
        }
        self.resume_pending().await;
    }

    /// Ends one receive job with a real error: only this job's own files are
    /// removed, and the failure is reported.
    async fn abort_receive(&mut self, job: ReceiveJob, error: CliprdrError) {
        // The job is over, so no answer is owed to it any more.
        self.answer_deadline = None;
        self.remove_job_files(&job);
        self.push(CliprdrEvent::Failed {
            request_id: Some(job.request_id),
            error,
        })
        .await;
    }

    /// Removes this job's staging and work directories — the only two paths this
    /// owner ever created, and never anything else under the client's root.
    fn remove_job_files(&self, job: &ReceiveJob) {
        for path in [&job.work, &job.dir] {
            match fs::remove_dir_all(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    // The failure this job owes the client is still the fact it
                    // needs; nothing else can be done about a leftover directory.
                    hbb_common::log::warn!(
                        "cliprdr: leaving {} in place: {}",
                        path.display(),
                        error
                    );
                }
            }
        }
    }

    /// Answers one of the peer's `FileContentsRequest`s.
    async fn serve_contents(&mut self, request: proto::CliprdrFileContentsRequest) {
        let stream_id = request.stream_id;
        if !self.allowed() {
            // After a withdrawal nothing is sent, not even a refusal: the fence's
            // own generation check at the writer would drop it anyway.
            return;
        }
        match self.file_contents(&request) {
            Ok(data) => {
                let bytes = data.len();
                let message = file_contents_response_message(MSG_FLAGS_OK, stream_id, data);
                let _ = self.queue(message, bytes + 64).await;
            }
            Err(_) => {
                // The protocol's own failure answer (`resp_file_contents_fail`),
                // so a peer waiting on this stream stops instead of timing out.
                let message = file_contents_response_message(MSG_FLAGS_FAIL, stream_id, Vec::new());
                let _ = self.queue(message, 64).await;
            }
        }
    }

    /// Serves one request from this side's offer, from the same opened source
    /// object every time.
    fn file_contents(
        &mut self,
        request: &proto::CliprdrFileContentsRequest,
    ) -> Result<Vec<u8>, CliprdrError> {
        let revision = self.revision;
        let Some(offer) = self.offer.as_mut() else {
            return Err(CliprdrError::OfferEmpty);
        };
        // A request that arrived under an older answer is refused rather than
        // answered from an offer that answer never admitted.
        if offer.revision != revision {
            return Err(CliprdrError::PermissionDenied);
        }
        let index = usize::try_from(request.list_index).map_err(|_| CliprdrError::RequestInvalid)?;
        let file = offer
            .files
            .get_mut(index)
            .ok_or(CliprdrError::RequestInvalid)?;
        if file.is_dir {
            // A directory has no contents stream; its children are their own
            // entries in the list.
            return Err(CliprdrError::RequestInvalid);
        }
        match request.dw_flags {
            FILECONTENTS_SIZE => Ok(file.size.to_le_bytes().to_vec()),
            FILECONTENTS_RANGE => {
                // The offset's two halves are unsigned 32-bit parts on the wire.
                // Upstream writes `(n_position_high as u64) << 32 | n_position_low
                // as u64`, which sign-extends a low half above 2 GiB; both halves
                // are read as u32 here so such an offset stays correct.
                let offset = ((request.n_position_high as u32 as u64) << 32)
                    | (request.n_position_low as u32 as u64);
                if request.cb_requested <= 0 {
                    return Err(CliprdrError::RequestInvalid);
                }
                let requested = request.cb_requested as u64;
                if requested > CLIPRDR_SERVE_BLOCK {
                    // Refused rather than answered with a truncated file: a short
                    // response reads as end-of-file to the requester, which would
                    // silently drop everything past this block.
                    return Err(CliprdrError::RequestInvalid);
                }
                if offset > file.size {
                    return Err(CliprdrError::RequestInvalid);
                }
                // Upstream's `read_size = min(length, size - offset)`.
                let length = (file.size - offset).min(requested);
                file.read_range(offset, length as usize)
            }
            _ => Err(CliprdrError::RequestInvalid),
        }
    }

    /// The answer this owner was waiting for never came.
    async fn expire(&mut self) {
        self.answer_deadline = None;
        if let Some(request_id) = self.retire_descriptor_request() {
            // A descriptor answer that never arrived cannot be told apart from one
            // that arrives later, so this request fails and its slot keeps a
            // tombstone: the late answer is absorbed there instead of being
            // attributed to the next request. An offer that is waiting stays in
            // `pending_offer` and starts a *new* request once that answer drains.
            // This optional feature is therefore truthfully blocked rather than
            // quietly attributed to the wrong offer.
            self.fail(Some(request_id), CliprdrError::TimedOut).await;
            return;
        }
        if let Some(mut job) = self.receive.take() {
            close_handles(&mut job);
            self.abort_receive(job, CliprdrError::TimedOut).await;
        }
    }

    /// Reserves `bytes` of the writer's budget, waiting for room rather than
    /// dropping an effect the owner already committed to.
    async fn reserve(&self, bytes: usize) -> Result<OwnedSemaphorePermit, CliprdrError> {
        let permits = u32::try_from(bytes)
            .unwrap_or(u32::MAX)
            .min(CLIPRDR_OUTBOUND_BYTES as u32);
        Arc::clone(&self.bytes)
            .acquire_many_owned(permits)
            .await
            .map_err(|_| CliprdrError::Closed)
    }

    /// Queues one message for the session's single writer.
    async fn queue(&mut self, message: Message, bytes: usize) -> Result<(), CliprdrError> {
        if self.cancel.is_cancelled() {
            return Err(CliprdrError::Cancelled);
        }
        if !self.allowed() {
            return Err(CliprdrError::PermissionDenied);
        }
        let permit = self.reserve(bytes).await?;
        let effect = CliprdrEffect {
            message,
            fence: Arc::clone(&self.shared.fence),
            revision: self.revision,
            _bytes: permit,
            completion: None,
        };
        self.outbound
            .send(effect)
            .await
            .map_err(|_| CliprdrError::Closed)
    }

    /// Queues one message whose writing this owner waits on, and answers whether
    /// it was really written. A writer that drops the effect without completing it
    /// closes the same answer without a `true`.
    async fn announce(&mut self, message: Message, bytes: usize) -> Result<bool, CliprdrError> {
        if self.cancel.is_cancelled() {
            return Err(CliprdrError::Cancelled);
        }
        if !self.allowed() {
            return Err(CliprdrError::PermissionDenied);
        }
        let permit = self.reserve(bytes).await?;
        let (completion, answer) = oneshot::channel();
        let effect = CliprdrEffect {
            message,
            fence: Arc::clone(&self.shared.fence),
            revision: self.revision,
            _bytes: permit,
            completion: Some(completion),
        };
        self.outbound
            .send(effect)
            .await
            .map_err(|_| CliprdrError::Closed)?;
        // Bounded: a writer that never reports back must not leave the owner (and
        // with it the session's `JoinSet`) waiting for an answer that is not
        // coming. An unanswered announcement is reported as not written.
        Ok(tokio::time::timeout(CLIPRDR_RESPONSE_TIMEOUT, answer)
            .await
            .ok()
            .and_then(|reported| reported.ok())
            .unwrap_or(false))
    }

    async fn fail(&mut self, request_id: Option<u64>, error: CliprdrError) {
        self.push(CliprdrEvent::Failed { request_id, error }).await;
    }

    /// Publishes one fact, waiting for the applying consumer if the mailbox is
    /// full. Answers whether it was kept: `false` only for a cancelled session,
    /// which is the one case where no consumer is owed anything and this owner
    /// must still be able to finish its own shutdown.
    async fn push(&self, event: CliprdrEvent) -> bool {
        self.shared.push(event).await
    }
}

/// One decision about a receive job's next step, taken without borrowing the
/// owner.
fn step(job: &mut ReceiveJob) -> Step {
    loop {
        if job.awaiting.is_some() {
            return Step::Waiting;
        }
        let Some(index) = job.current() else {
            return Step::Finished;
        };
        let destination = job.files[index].destination.clone();
        if job.files[index].is_dir {
            if let Err(error) = make_parent(&destination) {
                return Step::Failed(error);
            }
            if let Err(error) = fs::create_dir_all(&destination) {
                return Step::Failed(CliprdrError::disk(DiskOp::CreateDir, &error));
            }
            job.next = index + 1;
            continue;
        }
        if job.files[index].handle.is_none() {
            let temporary = job.files[index].temporary.clone();
            if let Err(error) = make_parent(&temporary) {
                return Step::Failed(error);
            }
            match File::create(&temporary) {
                Ok(handle) => job.files[index].handle = Some(handle),
                Err(error) => return Step::Failed(CliprdrError::disk(DiskOp::Write, &error)),
            }
        }
        let Some(size) = job.files[index].size else {
            return Step::Request {
                index,
                kind: RequestKind::Size,
            };
        };
        let written = job.files[index].written;
        if written < size {
            return Step::Request {
                index,
                kind: RequestKind::Range {
                    offset: written,
                    // Bounded chunks: one received write is small, and the
                    // outbound request effect it costs is small too.
                    length: (size - written).min(CLIPRDR_CHUNK),
                },
            };
        }
        if let Err(error) = finish_entry(&mut job.files[index]) {
            return Step::Failed(error);
        }
        job.bytes += size;
        job.next = index + 1;
        continue;
    }
}

/// Flushes one finished entry, gives it its final name, and applies the mode the
/// peer described. The temporary is renamed only after its bytes are durable, so
/// a published path always names complete content.
fn finish_entry(file: &mut ReceivingFile) -> Result<(), CliprdrError> {
    let Some(mut handle) = file.handle.take() else {
        return Err(CliprdrError::Disk {
            operation: DiskOp::Write,
            kind: std::io::ErrorKind::NotFound,
        });
    };
    // `File` is unbuffered, so `flush` would be a no-op: `sync_all` is the flush
    // this batch waits for before it names and publishes anything.
    handle
        .sync_all()
        .map_err(|error| CliprdrError::disk(DiskOp::Flush, &error))?;
    drop(handle);
    apply_mode(&file.temporary, file.perm)?;
    // A descriptor may name a nested file without separate directory records.
    // Its validated destination still needs its parent before the final rename.
    make_parent(&file.destination)?;
    fs::rename(&file.temporary, &file.destination)
        .map_err(|error| CliprdrError::disk(DiskOp::Rename, &error))
}

/// Closes every handle a job still holds, before its directories are removed: an
/// open handle blocks deletion on some platforms.
fn close_handles(job: &mut ReceiveJob) {
    for file in job.files.iter_mut() {
        file.handle = None;
    }
}

/// The 8-byte size answer to a `FILECONTENTS_SIZE` request.
fn size_answer(job: &mut ReceiveJob, data: &[u8]) -> Result<(), CliprdrError> {
    // Exactly what `serve_file_contents` answers with: `size.to_le_bytes()`.
    let bytes: [u8; 8] = data.try_into().map_err(|_| CliprdrError::RequestInvalid)?;
    let answered = u64::from_le_bytes(bytes);
    let index = job.current().ok_or(CliprdrError::RequestInvalid)?;
    let file = &mut job.files[index];
    if file.declared != 0 && file.declared != answered {
        // The peer contradicted the size in its own descriptor. Neither value is
        // silently preferred, and nothing is written on a guess.
        return Err(CliprdrError::DescriptorInvalid);
    }
    file.size = Some(answered);
    Ok(())
}

/// One `FILECONTENTS_RANGE` answer, written at the offset it was asked for.
fn range_answer(
    job: &mut ReceiveJob,
    data: &[u8],
    offset: u64,
    requested: u64,
) -> Result<(), CliprdrError> {
    let length = data.len() as u64;
    if length > requested {
        return Err(CliprdrError::RequestInvalid);
    }
    let index = job.current().ok_or(CliprdrError::RequestInvalid)?;
    let file = &mut job.files[index];
    if file.written != offset {
        return Err(CliprdrError::RequestInvalid);
    }
    let size = file.size.ok_or(CliprdrError::RequestInvalid)?;
    if offset + length > size {
        return Err(CliprdrError::RequestInvalid);
    }
    if length == 0 {
        // A nonzero request answered with no bytes cannot advance this file, and
        // asking again would be a silent replay of a request that already failed.
        return Err(CliprdrError::PeerFailed);
    }
    let Some(handle) = file.handle.as_mut() else {
        return Err(CliprdrError::Disk {
            operation: DiskOp::Write,
            kind: std::io::ErrorKind::NotFound,
        });
    };
    handle
        .write_all(data)
        .map_err(|error| CliprdrError::disk(DiskOp::Write, &error))?;
    file.written += length;
    Ok(())
}

/// The paths a finished batch publishes: the peer's top-level entries, or every
/// entry when the peer named only nested ones.
fn publish_paths(job: &ReceiveJob) -> Vec<PathBuf> {
    let top: Vec<PathBuf> = job
        .files
        .iter()
        .filter(|file| !file.name.contains('/'))
        .map(|file| file.destination.clone())
        .collect();
    if top.is_empty() {
        return job
            .files
            .iter()
            .map(|file| file.destination.clone())
            .collect();
    }
    top
}

/// Creates this owner's own directory, replacing a leftover of the same request
/// id so no previous transfer's files are mixed into this one.
fn prepare_dir(path: &Path) -> Result<(), CliprdrError> {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CliprdrError::disk(DiskOp::RemoveDir, &error)),
    }
    fs::create_dir_all(path).map_err(|error| CliprdrError::disk(DiskOp::CreateDir, &error))
}

/// Joins one validated descriptor name onto this job's own directory.
///
/// The name already passed [`validate_descriptor_name`], so this cannot leave
/// `dir`; the component walk is repeated anyway so the guarantee does not rest on
/// a caller elsewhere.
fn join_descriptor_name(dir: &Path, name: &str) -> Result<PathBuf, CliprdrError> {
    let mut path = dir.to_path_buf();
    for component in name.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(CliprdrError::FileNameInvalid);
        }
        path.push(component);
    }
    if path == dir {
        return Err(CliprdrError::FileNameInvalid);
    }
    Ok(path)
}

fn make_parent(path: &Path) -> Result<(), CliprdrError> {
    match path.parent() {
        Some(parent) => {
            fs::create_dir_all(parent).map_err(|error| CliprdrError::disk(DiskOp::CreateDir, &error))
        }
        None => Ok(()),
    }
}

/// Adopts the client's clipboard file root.
///
/// It must be absolute, must not itself be a symlink, and must be a directory —
/// created if it does not exist yet, which is the one place this owner creates
/// something outside its own staging directories. The canonical form is kept so
/// every joined path is inside the directory the client really named; resolving
/// *ancestors* is ordinary OS layout and is not treated as an escape.
fn adopt_root(named: &Path) -> Result<PathBuf, CliprdrError> {
    match fs::symlink_metadata(named) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CliprdrError::RootInvalid);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(named)
                .map_err(|error| CliprdrError::disk(DiskOp::CreateDir, &error))?;
            let metadata = fs::symlink_metadata(named)
                .map_err(|error| CliprdrError::disk(DiskOp::Metadata, &error))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CliprdrError::RootInvalid);
            }
        }
        Err(_) => return Err(CliprdrError::RootInvalid),
    }
    fs::canonicalize(named).map_err(|_| CliprdrError::RootInvalid)
}

/// Builds one local offer: the descriptor records and the PDU the peer will ask
/// for, with each entry's facts fixed now.
fn build_offer(revision: u64, paths: &[PathBuf]) -> Result<LocalOffer, CliprdrError> {
    let mut files = Vec::new();
    for path in paths {
        let Some(parent) = path.parent() else {
            return Err(CliprdrError::OfferPathInvalid);
        };
        collect_entries(parent, path, 0, &mut files)?;
    }
    if files.is_empty() {
        return Err(CliprdrError::OfferEmpty);
    }
    if files.len() > MAX_CLIPRDR_FILES {
        return Err(CliprdrError::OfferTooLarge);
    }
    let bytes = files
        .iter()
        .filter(|file| !file.is_dir)
        .map(|file| file.size)
        .sum();
    let mut pdu = Vec::with_capacity(4 + FILE_DESCRIPTOR_SIZE * files.len());
    pdu.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for file in &files {
        pdu.extend_from_slice(&file.descriptor()?);
    }
    Ok(LocalOffer {
        revision,
        files,
        pdu,
        bytes,
    })
}

/// Adds one selected path and, for a directory, everything under it to the offer,
/// in the order a peer will index them.
///
/// Each top-level path's descriptor name is relative to *its own* parent, which is
/// upstream's `construct_file_list`; a selected directory therefore arrives as
/// `dir` plus `dir/...` entries. A symlink is refused rather than followed, so
/// this walk can neither escape what the client named nor loop.
fn collect_entries(
    root: &Path,
    path: &Path,
    depth: usize,
    files: &mut Vec<OfferedFile>,
) -> Result<(), CliprdrError> {
    if files.len() >= MAX_CLIPRDR_FILES || depth > MAX_CLIPRDR_DEPTH {
        return Err(CliprdrError::OfferTooLarge);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| CliprdrError::OfferPathInvalid)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
        return Err(CliprdrError::OfferPathInvalid);
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| CliprdrError::OfferPathInvalid)?;
    let name = relative.to_string_lossy().replace('\\', "/");
    validate_descriptor_name(&name)?;
    let is_dir = file_type.is_dir();
    files.push(OfferedFile {
        path: path.to_path_buf(),
        name,
        size: metadata.len(),
        is_dir,
        mode: file_mode(&metadata),
        read_only: metadata.permissions().readonly(),
        modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        handle: None,
    });
    if !is_dir {
        return Ok(());
    }
    let entries = fs::read_dir(path).map_err(|_| CliprdrError::OfferPathInvalid)?;
    let mut children: Vec<PathBuf> = Vec::new();
    for entry in entries {
        children.push(entry.map_err(|_| CliprdrError::OfferPathInvalid)?.path());
    }
    // Sorted so the list's indices are stable between two offers of the same
    // directory: the peer addresses entries by index, not by name.
    children.sort();
    for child in children {
        collect_entries(root, &child, depth + 1, files)?;
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    // Only the permission bits: the descriptor's mode field is 16 bits wide on
    // receipt, and a peer's own `perm & 0o777` keeps exactly these.
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

#[cfg(unix)]
fn apply_mode(path: &Path, perm: u16) -> Result<(), CliprdrError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = u32::from(perm) & 0o777;
    if mode == 0 {
        // A peer that stated no mode leaves the platform default in place.
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| CliprdrError::disk(DiskOp::SetPermissions, &error))
}

#[cfg(not(unix))]
fn apply_mode(_path: &Path, _perm: u16) -> Result<(), CliprdrError> {
    // This platform has no unix mode to apply; the file keeps the default its
    // filesystem gave it.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::{self as wire, cliprdr::Union};

    /// A scratch directory that removes itself.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let mut dir = std::env::temp_dir();
            dir.push(format!("rd-cliprdr-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&dir).expect("a scratch directory");
            Self(dir)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The cliprdr union inside one effect's message.
    fn union(message: &Message) -> &Union {
        match &message.union {
            Some(wire::message::Union::Cliprdr(cliprdr)) => {
                cliprdr.union.as_ref().expect("a cliprdr union")
            }
            other => panic!("not a cliprdr message: {other:?}"),
        }
    }

    fn inbound_cliprdr(union: Union) -> Cliprdr {
        Cliprdr {
            union: Some(union),
            ..Default::default()
        }
    }

    /// A peer that carries both file formats, which is what makes a `FormatList`
    /// a file offer.
    fn peer_format_list() -> Cliprdr {
        inbound_cliprdr(Union::FormatList(wire::CliprdrServerFormatList {
            formats: vec![
                wire::CliprdrFormat {
                    id: FILEDESCRIPTOR_FORMAT_ID,
                    format: FILEDESCRIPTORW_FORMAT_NAME.to_owned(),
                    ..Default::default()
                },
                wire::CliprdrFormat {
                    id: FILECONTENTS_FORMAT_ID,
                    format: FILECONTENTS_FORMAT_NAME.to_owned(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }))
    }

    fn peer_format_data_response(msg_flags: i32, data: Vec<u8>) -> Cliprdr {
        inbound_cliprdr(Union::FormatDataResponse(
            wire::CliprdrServerFormatDataResponse {
                msg_flags,
                format_data: data.into(),
                ..Default::default()
            },
        ))
    }

    fn peer_file_contents_response(msg_flags: i32, stream_id: i32, data: Vec<u8>) -> Cliprdr {
        inbound_cliprdr(Union::FileContentsResponse(
            wire::CliprdrFileContentsResponse {
                msg_flags,
                stream_id,
                requested_data: data.into(),
                ..Default::default()
            },
        ))
    }

    fn format_data_request(requested_format_id: i32) -> Cliprdr {
        inbound_cliprdr(Union::FormatDataRequest(
            wire::CliprdrServerFormatDataRequest {
                requested_format_id,
                ..Default::default()
            },
        ))
    }

    fn file_contents_request(
        stream: i32,
        index: usize,
        flags: i32,
        offset: u64,
        requested: i32,
    ) -> Cliprdr {
        inbound_cliprdr(Union::FileContentsRequest(wire::CliprdrFileContentsRequest {
            stream_id: stream,
            list_index: index as i32,
            dw_flags: flags,
            n_position_low: offset as u32 as i32,
            n_position_high: (offset >> 32) as u32 as i32,
            cb_requested: requested,
            have_clip_data_id: false,
            clip_data_id: 0,
            ..Default::default()
        }))
    }

    /// One raw `FILEDESCRIPTORW` record, built without this module's own name
    /// checks so the *parse* side is what is under test.
    fn raw_descriptor(name: &str, size: u64, is_dir: bool) -> Vec<u8> {
        let mut record = Vec::with_capacity(FILE_DESCRIPTOR_SIZE);
        record.extend_from_slice(&DESCRIPTOR_FLAGS.to_le_bytes());
        record.extend_from_slice(&[0_u8; 32]);
        let attributes = if is_dir { 0x10_u32 } else { 0x80 };
        record.extend_from_slice(&attributes.to_le_bytes());
        record.extend_from_slice(&[0_u8; 12]);
        record.extend_from_slice(&0o644_u32.to_le_bytes());
        record.extend_from_slice(&0_u64.to_le_bytes());
        record.extend_from_slice(&((size >> 32) as u32).to_le_bytes());
        record.extend_from_slice(&((size & 0xffff_ffff) as u32).to_le_bytes());
        let mut field = [0_u8; FILE_NAME_FIELD_SIZE];
        for (index, unit) in name.encode_utf16().enumerate() {
            let offset = index * 2;
            field[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        record.extend_from_slice(&field);
        assert_eq!(record.len(), FILE_DESCRIPTOR_SIZE);
        record
    }

    fn raw_pdu(entries: &[(&str, u64, bool)]) -> Vec<u8> {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (name, size, is_dir) in entries {
            pdu.extend_from_slice(&raw_descriptor(name, *size, *is_dir));
        }
        pdu
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("a readable directory")
            .map(|entry| entry.expect("an entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Waits for the next event the owner published. The mailbox keeps an event
    /// until it is taken, so this is a wait on the owner's progress and not on a
    /// race.
    async fn next_event(handle: &CliprdrHandle) -> CliprdrEvent {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(event) = handle.take_events().into_iter().next() {
                return event;
            }
            assert!(Instant::now() < deadline, "the owner published no event");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// A running owner with its channels, as the viewer will hold them.
    struct Harness {
        handle: Arc<CliprdrHandle>,
        outbound: mpsc::Receiver<CliprdrEffect>,
        cancel: CancellationToken,
        owner: tokio::task::JoinHandle<CliprdrExit>,
    }

    impl Harness {
        fn start() -> Self {
            let cancel = CancellationToken::new();
            let start = start(cancel.clone());
            let handle = Arc::clone(&start.handle);
            handle.set_allowed(true);
            Self {
                handle,
                outbound: start.outbound,
                cancel,
                owner: tokio::spawn(start.owner.run()),
            }
        }

        async fn close(self) -> CliprdrExit {
            self.cancel.cancel();
            self.owner.await.expect("the owner task")
        }
    }

    #[tokio::test]
    async fn offered_files_are_served_as_real_bytes() {
        let scratch = Scratch::new("serve");
        let source = scratch.join("note.txt");
        fs::write(&source, b"hello cliprdr").expect("a source file");
        let mut harness = Harness::start();

        harness
            .handle
            .submit(CliprdrCommand::OfferFiles(vec![source]))
            .expect("the offer is queued");

        // The peer is told which formats this side carries.
        let effect = harness.outbound.recv().await.expect("the format list");
        assert!(effect.is_permitted());
        match union(effect.message()) {
            Union::FormatList(list) => {
                let names: Vec<&str> = list
                    .formats
                    .iter()
                    .map(|format| format.format.as_str())
                    .collect();
                assert_eq!(
                    names,
                    vec![FILEDESCRIPTORW_FORMAT_NAME, FILECONTENTS_FORMAT_NAME]
                );
                assert_eq!(list.formats[0].id, FILEDESCRIPTOR_FORMAT_ID);
                assert_eq!(list.formats[1].id, FILECONTENTS_FORMAT_ID);
            }
            other => panic!("not a format list: {other:?}"),
        }
        effect.complete(true);
        // The announcement's own write is the only thing `Offered` claims.
        assert!(matches!(
            next_event(&harness.handle).await,
            CliprdrEvent::Offered {
                files: 1,
                bytes: 13,
                ..
            }
        ));

        // The peer asks for the descriptor list and gets the real record.
        harness
            .handle
            .offer_inbound(format_data_request(FILEDESCRIPTOR_FORMAT_ID))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("the descriptor list");
        let entries = match union(effect.message()) {
            Union::FormatDataResponse(response) => {
                assert_eq!(response.msg_flags, MSG_FLAGS_OK);
                parse_descriptors(response.format_data.as_ref()).expect("a parsed list")
            }
            other => panic!("not a data response: {other:?}"),
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "note.txt");
        assert_eq!(entries[0].declared, 13);
        assert!(!entries[0].is_dir);
        effect.complete(true);

        // The size request is answered with the file's real length.
        harness
            .handle
            .offer_inbound(file_contents_request(7, 0, FILECONTENTS_SIZE, 0, 0))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("the size");
        let size = match union(effect.message()) {
            Union::FileContentsResponse(response) => {
                assert_eq!(response.msg_flags, MSG_FLAGS_OK);
                assert_eq!(response.stream_id, 7);
                response.requested_data.as_ref().to_vec()
            }
            other => panic!("not a contents response: {other:?}"),
        };
        assert_eq!(size, 13_u64.to_le_bytes().to_vec());
        effect.complete(true);

        // The range request is answered with the file's real bytes.
        harness
            .handle
            .offer_inbound(file_contents_request(8, 0, FILECONTENTS_RANGE, 0, 13))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("the bytes");
        let data = match union(effect.message()) {
            Union::FileContentsResponse(response) => {
                assert_eq!(response.msg_flags, MSG_FLAGS_OK);
                response.requested_data.as_ref().to_vec()
            }
            other => panic!("not a contents response: {other:?}"),
        };
        assert_eq!(data, b"hello cliprdr".to_vec());
        effect.complete(true);

        // A range past the end is clamped to what the file really has, exactly as
        // upstream's `read_size = min(length, size - offset)`.
        harness
            .handle
            .offer_inbound(file_contents_request(9, 0, FILECONTENTS_RANGE, 0, 4096))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("the clamped bytes");
        let data = match union(effect.message()) {
            Union::FileContentsResponse(response) => {
                assert_eq!(response.msg_flags, MSG_FLAGS_OK);
                response.requested_data.as_ref().to_vec()
            }
            other => panic!("not a contents response: {other:?}"),
        };
        assert_eq!(data, b"hello cliprdr".to_vec());
        effect.complete(true);

        // An index this offer does not have is the protocol's own failure answer,
        // never someone else's bytes.
        harness
            .handle
            .offer_inbound(file_contents_request(10, 9, FILECONTENTS_RANGE, 0, 4))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("the refusal");
        match union(effect.message()) {
            Union::FileContentsResponse(response) => {
                assert_eq!(response.msg_flags, MSG_FLAGS_FAIL);
                assert_eq!(response.stream_id, 10);
                assert!(response.requested_data.is_empty());
            }
            other => panic!("not a contents response: {other:?}"),
        }
        effect.complete(true);

        // A format this side never advertised is a failure answer too.
        harness
            .handle
            .offer_inbound(format_data_request(FILECONTENTS_FORMAT_ID))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("the format refusal");
        match union(effect.message()) {
            Union::FormatDataResponse(response) => assert_eq!(response.msg_flags, MSG_FLAGS_FAIL),
            other => panic!("not a data response: {other:?}"),
        }
        effect.complete(true);

        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    #[tokio::test]
    async fn peer_files_land_on_disk_and_are_published_once() {
        let scratch = Scratch::new("receive");
        let root = scratch.join("inbox");
        fs::create_dir_all(&root).expect("the root");
        let root = fs::canonicalize(&root).expect("a canonical root");
        let mut harness = Harness::start();
        harness
            .handle
            .submit(CliprdrCommand::SetRoot(root.clone()))
            .expect("the root is queued");

        // The peer announces files, and this side asks for their descriptors.
        harness
            .handle
            .offer_inbound(peer_format_list())
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a descriptor request");
        match union(effect.message()) {
            Union::FormatDataRequest(request) => {
                assert_eq!(request.requested_format_id, FILEDESCRIPTOR_FORMAT_ID);
            }
            other => panic!("not a data request: {other:?}"),
        }
        effect.complete(true);

        // Its list names one nested file and declares no size.
        harness
            .handle
            .offer_inbound(peer_format_data_response(
                MSG_FLAGS_OK,
                raw_pdu(&[("dir/a.txt", 0, false)]),
            ))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a size request");
        let size_stream = match union(effect.message()) {
            Union::FileContentsRequest(request) => {
                assert_eq!(request.list_index, 0);
                assert_eq!(request.dw_flags, FILECONTENTS_SIZE);
                request.stream_id
            }
            other => panic!("not a contents request: {other:?}"),
        };
        effect.complete(true);

        // The size answer is authoritative when no size was declared.
        harness
            .handle
            .offer_inbound(peer_file_contents_response(
                MSG_FLAGS_OK,
                size_stream,
                5_u64.to_le_bytes().to_vec(),
            ))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a range request");
        let (range_stream, offset, length) = match union(effect.message()) {
            Union::FileContentsRequest(request) => (
                request.stream_id,
                ((request.n_position_high as u32 as u64) << 32)
                    | (request.n_position_low as u32 as u64),
                request.cb_requested,
            ),
            other => panic!("not a contents request: {other:?}"),
        };
        assert_eq!(request_dw_flags(&effect), FILECONTENTS_RANGE);
        assert_eq!((offset, length), (0, 5));
        assert!(
            range_stream > size_stream,
            "stream ids are allocated monotonically and never reused"
        );
        effect.complete(true);

        // Only a complete, flushed, finally named file is published.
        harness
            .handle
            .offer_inbound(peer_file_contents_response(
                MSG_FLAGS_OK,
                range_stream,
                b"hello".to_vec(),
            ))
            .await
            .expect("sent");
        let paths = match next_event(&harness.handle).await {
            CliprdrEvent::Files { paths, bytes, .. } => {
                assert_eq!(bytes, 5);
                paths
            }
            other => panic!("not a files event: {other:?}"),
        };
        assert_eq!(paths.len(), 1);
        assert!(paths[0].starts_with(&root), "inside the authorized root");
        assert_eq!(
            fs::read(&paths[0]).expect("the received file"),
            b"hello".to_vec()
        );
        // The work directory is gone; only this job's published directory remains.
        let leftovers = entries(&root);
        assert_eq!(leftovers.len(), 1, "only this job: {leftovers:?}");
        assert!(leftovers[0].starts_with(".cliprdr-"));

        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    fn request_dw_flags(effect: &CliprdrEffect) -> i32 {
        match union(effect.message()) {
            Union::FileContentsRequest(request) => request.dw_flags,
            other => panic!("not a contents request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_failed_transfer_removes_only_its_own_partial_files() {
        let scratch = Scratch::new("failed");
        let root = scratch.join("inbox");
        fs::create_dir_all(&root).expect("the root");
        let keep = root.join("keep.txt");
        fs::write(&keep, b"not the peer's").expect("a local file");
        let root = fs::canonicalize(&root).expect("a canonical root");
        let mut harness = Harness::start();
        harness
            .handle
            .submit(CliprdrCommand::SetRoot(root.clone()))
            .expect("the root is queued");

        harness
            .handle
            .offer_inbound(peer_format_list())
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a descriptor request");
        effect.complete(true);
        harness
            .handle
            .offer_inbound(peer_format_data_response(
                MSG_FLAGS_OK,
                raw_pdu(&[("a.txt", 0, false), ("b.txt", 0, false)]),
            ))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a size request");
        let stream = match union(effect.message()) {
            Union::FileContentsRequest(request) => request.stream_id,
            other => panic!("not a contents request: {other:?}"),
        };
        effect.complete(true);

        // The peer reports its own failure for that request.
        harness
            .handle
            .offer_inbound(peer_file_contents_response(MSG_FLAGS_FAIL, stream, Vec::new()))
            .await
            .expect("sent");
        match next_event(&harness.handle).await {
            CliprdrEvent::Failed { error, .. } => assert_eq!(error, CliprdrError::PeerFailed),
            other => panic!("not a failure: {other:?}"),
        }
        // The client's own file is untouched, and nothing of this job survives.
        assert_eq!(
            fs::read(&keep).expect("the local file"),
            b"not the peer's".to_vec()
        );
        assert_eq!(entries(&root), vec!["keep.txt".to_owned()]);

        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    #[tokio::test]
    async fn a_traversal_name_is_refused_before_anything_is_written() {
        let scratch = Scratch::new("traversal");
        let root = scratch.join("inbox");
        fs::create_dir_all(&root).expect("the root");
        let root = fs::canonicalize(&root).expect("a canonical root");
        let mut harness = Harness::start();
        harness
            .handle
            .submit(CliprdrCommand::SetRoot(root.clone()))
            .expect("the root is queued");

        harness
            .handle
            .offer_inbound(peer_format_list())
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a descriptor request");
        effect.complete(true);
        harness
            .handle
            .offer_inbound(peer_format_data_response(
                MSG_FLAGS_OK,
                raw_pdu(&[("../escape.txt", 0, false)]),
            ))
            .await
            .expect("sent");
        match next_event(&harness.handle).await {
            CliprdrEvent::Failed { error, .. } => assert_eq!(error, CliprdrError::FileNameInvalid),
            other => panic!("not a failure: {other:?}"),
        }
        // Nothing was created and no contents were ever asked for.
        assert!(entries(&root).is_empty(), "nothing is written");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), harness.outbound.recv())
                .await
                .is_err(),
            "a refused descriptor list must not produce a contents request"
        );

        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    #[tokio::test]
    async fn a_withdrawal_fences_queued_work_and_never_restamps_it() {
        let scratch = Scratch::new("fence");
        let source = scratch.join("note.txt");
        fs::write(&source, b"x").expect("a source file");
        let mut harness = Harness::start();
        harness
            .handle
            .submit(CliprdrCommand::OfferFiles(vec![source.clone()]))
            .expect("the offer is queued");
        let effect = harness.outbound.recv().await.expect("the format list");
        assert!(effect.is_permitted());

        // The answer that admitted this effect is withdrawn.
        harness.handle.set_allowed(false);
        assert!(!effect.is_permitted(), "a revocation reached queued work");
        // A re-grant admits new work only: it never restamps what it did not admit.
        harness.handle.set_allowed(true);
        assert!(!effect.is_permitted(), "a re-grant must not revive it");

        // While the fence is closed no command that needs it is accepted.
        harness.handle.set_allowed(false);
        assert_eq!(
            harness
                .handle
                .submit(CliprdrCommand::OfferFiles(vec![source])),
            Err(CliprdrError::PermissionDenied)
        );

        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    #[tokio::test]
    async fn a_second_offer_waits_for_the_descriptor_answer_in_flight() {
        let mut harness = Harness::start();
        harness
            .handle
            .offer_inbound(peer_format_list())
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a descriptor request");
        effect.complete(true);

        // A second offer while the first is unanswered must not become a second
        // request: a `FormatDataResponse` carries no request id, so two
        // outstanding requests could not be told apart.
        harness
            .handle
            .offer_inbound(peer_format_list())
            .await
            .expect("sent");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), harness.outbound.recv())
                .await
                .is_err(),
            "a second descriptor request was sent while one was outstanding"
        );

        // Once the first is consumed, the newest offer is asked about — new
        // request, and the failed one is still reported.
        harness
            .handle
            .offer_inbound(peer_format_data_response(MSG_FLAGS_FAIL, Vec::new()))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("the next request");
        assert!(matches!(union(effect.message()), Union::FormatDataRequest(_)));
        effect.complete(true);
        match next_event(&harness.handle).await {
            CliprdrEvent::Failed { error, .. } => assert_eq!(error, CliprdrError::PeerFailed),
            other => panic!("not a failure: {other:?}"),
        }

        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    #[tokio::test]
    async fn a_stray_descriptor_answer_is_reported_and_attributed_to_nothing() {
        let harness = Harness::start();
        harness
            .handle
            .offer_inbound(peer_format_data_response(MSG_FLAGS_OK, raw_pdu(&[])))
            .await
            .expect("sent");
        match next_event(&harness.handle).await {
            CliprdrEvent::Failed { request_id, error } => {
                assert_eq!(error, CliprdrError::DescriptorUnrequested);
                assert_eq!(request_id, None);
            }
            other => panic!("not a failure: {other:?}"),
        }
        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    /// Drives one peer offer of a single file through to the event that published
    /// its paths.
    async fn fetch_one_file(harness: &mut Harness, name: &str, contents: &[u8]) {
        harness
            .handle
            .offer_inbound(peer_format_list())
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a descriptor request");
        effect.complete(true);
        harness
            .handle
            .offer_inbound(peer_format_data_response(
                MSG_FLAGS_OK,
                raw_pdu(&[(name, contents.len() as u64, false)]),
            ))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a size request");
        let stream = match union(effect.message()) {
            Union::FileContentsRequest(request) => request.stream_id,
            other => panic!("not a contents request: {other:?}"),
        };
        effect.complete(true);
        harness
            .handle
            .offer_inbound(peer_file_contents_response(
                MSG_FLAGS_OK,
                stream,
                (contents.len() as u64).to_le_bytes().to_vec(),
            ))
            .await
            .expect("sent");
        let effect = harness.outbound.recv().await.expect("a range request");
        let stream = match union(effect.message()) {
            Union::FileContentsRequest(request) => request.stream_id,
            other => panic!("not a contents request: {other:?}"),
        };
        effect.complete(true);
        harness
            .handle
            .offer_inbound(peer_file_contents_response(
                MSG_FLAGS_OK,
                stream,
                contents.to_vec(),
            ))
            .await
            .expect("sent");
        // Wait without taking the fact: the caller is testing its retention.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !harness.handle.has_events() {
            assert!(Instant::now() < deadline, "the owner published no event");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// The event mailbox keeps a fact until a consumer takes it, and a read does
    /// not consume anything: a background poll that only looks cannot swallow the
    /// completed paste the foreground has to apply.
    #[tokio::test]
    async fn a_published_batch_stays_until_it_is_taken() {
        let scratch = Scratch::new("retained");
        let root = scratch.join("inbox");
        fs::create_dir_all(&root).expect("the root");
        let root = fs::canonicalize(&root).expect("a canonical root");
        let mut harness = Harness::start();
        harness
            .handle
            .submit(CliprdrCommand::SetRoot(root))
            .expect("the root is queued");
        fetch_one_file(&mut harness, "note.txt", b"kept").await;

        // Reading is not taking: a notifier may look as often as it likes.
        assert!(harness.handle.has_events());
        assert_eq!(harness.handle.pending_events(), 1);
        assert!(harness.handle.has_events());
        assert_eq!(harness.handle.pending_events(), 1);
        // The applying consumer takes it exactly once.
        let taken = harness.handle.take_events();
        assert_eq!(taken.len(), 1);
        let paths = match &taken[0] {
            CliprdrEvent::Files {
                paths, revision, ..
            } => {
                // The batch carries the generation that admitted the job whose
                // bytes these are, so a consumer can tell an old-era batch from a
                // current one after a withdrawal.
                assert_eq!(*revision, harness.handle.revision());
                paths.clone()
            }
            other => panic!("not a files event: {other:?}"),
        };
        assert_eq!(
            fs::read(&paths[0]).expect("the received file"),
            b"kept".to_vec()
        );

        assert!(!harness.handle.has_events());
        assert!(harness.handle.take_events().is_empty());

        assert_eq!(harness.close().await, CliprdrExit::Cancelled);
    }

    /// The withdraw-then-regrant that the owner only sees as "still allowed".
    #[tokio::test]
    async fn a_collapsed_withdrawal_and_regrant_never_restamps_admitted_work() {
        let scratch = Scratch::new("collapse");
        let source = scratch.join("note.txt");
        fs::write(&source, b"x").expect("a source file");
        let start = start(CancellationToken::new());
        let handle = Arc::clone(&start.handle);
        let mut owner = start.owner;
        let mut outbound = start.outbound;
        handle.set_allowed(true);
        let era = handle.revision();

        // Two pieces of work were admitted under this era: one descriptor request
        // this side sent, and this side's own announced offer.
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_list(),
            })
            .await;
        let request = outbound.try_recv().expect("a descriptor request");
        assert!(matches!(union(request.message()), Union::FormatDataRequest(_)));
        assert_eq!(request.revision, era);
        owner.offer = Some(build_offer(era, &[source]).expect("an offer"));

        // A withdrawal and the re-grant that follows it both land while the owner
        // is busy, so it only ever sees the fence open again.
        handle.set_allowed(false);
        handle.set_allowed(true);
        assert!(handle.is_allowed());
        assert!(handle.revision() > era);

        // The next pass adopts the new era. What the old one admitted does not
        // survive it, even though the fence reads open now.
        let new_era = handle.revision();
        owner
            .receive_inbound(CliprdrInbound {
                revision: new_era,
                message: inbound_cliprdr(Union::FormatListResponse(Default::default())),
            })
            .await;
        let events = handle.take_events();
        assert_eq!(events.len(), 1, "{events:?}");
        assert!(matches!(
            &events[0],
            CliprdrEvent::Failed {
                request_id: Some(_),
                error: CliprdrError::PermissionDenied
            }
        ));
        assert!(owner.offer.is_none(), "the withdrawn offer survived");
        assert!(
            matches!(owner.descriptor_slot, Some(DescriptorSlot::Retired)),
            "the request of the old era must leave a tombstone"
        );

        // The peer asking for this side's list now gets the protocol's own failure
        // answer, never the list the withdrawn era admitted.
        owner
            .receive_inbound(CliprdrInbound {
                revision: new_era,
                message: format_data_request(FILEDESCRIPTOR_FORMAT_ID),
            })
            .await;
        match union(outbound.try_recv().expect("an answer").message()) {
            Union::FormatDataResponse(response) => assert_eq!(response.msg_flags, MSG_FLAGS_FAIL),
            other => panic!("not a data response: {other:?}"),
        }

        // The answer admitted under the old era is not applied either: it drains
        // the tombstone and starts nothing.
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_data_response(MSG_FLAGS_OK, raw_pdu(&[("a.txt", 0, false)])),
            })
            .await;
        assert!(
            outbound.try_recv().is_err(),
            "old-era traffic produced a contents request"
        );
        assert!(owner.receive.is_none(), "a stale answer started a receive");
        assert!(owner.descriptor_slot.is_none(), "the tombstone drained");
    }

    /// A command is admitted under the era it was submitted in, not the one that
    /// happens to be open when the owner finally runs it.
    #[tokio::test]
    async fn a_command_admitted_before_a_collapsed_regrant_is_refused() {
        let scratch = Scratch::new("command-era");
        let source = scratch.join("note.txt");
        fs::write(&source, b"x").expect("a source file");
        let start = start(CancellationToken::new());
        let handle = Arc::clone(&start.handle);
        let mut owner = start.owner;
        let mut outbound = start.outbound;
        handle.set_allowed(true);
        let era = handle.revision();
        let request_id = handle
            .submit(CliprdrCommand::OfferFiles(vec![source]))
            .expect("the command is queued");
        handle.set_allowed(false);
        handle.set_allowed(true);

        let issued = owner.commands.recv().await.expect("the queued command");
        assert_eq!(issued.revision, era);
        owner.command(issued).await;
        assert!(matches!(
            handle.take_events().as_slice(),
            [CliprdrEvent::Failed {
                request_id: Some(failed),
                error: CliprdrError::PermissionDenied
            }] if *failed == request_id
        ));
        assert!(owner.offer.is_none());
        assert!(
            outbound.try_recv().is_err(),
            "a command of an older era announced itself"
        );
    }

    /// A timed-out descriptor request keeps its slot until its untagged answer
    /// drains, so the next request can never claim that answer.
    #[tokio::test]
    async fn a_late_untagged_answer_after_a_timeout_is_absorbed_by_its_own_request() {
        let start = start(CancellationToken::new());
        let handle = Arc::clone(&start.handle);
        let mut owner = start.owner;
        let mut outbound = start.outbound;
        handle.set_allowed(true);
        let era = handle.revision();

        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_list(),
            })
            .await;
        let first = outbound.try_recv().expect("a descriptor request");
        assert!(matches!(union(first.message()), Union::FormatDataRequest(_)));

        // The answer never arrives within the pinned client's own wait.
        owner.answer_deadline = Some(Instant::now());
        assert!(owner.answer_due());
        owner.expire().await;
        assert!(matches!(
            handle.take_events().as_slice(),
            [CliprdrEvent::Failed {
                error: CliprdrError::TimedOut,
                ..
            }]
        ));
        assert!(matches!(
            owner.descriptor_slot,
            Some(DescriptorSlot::Retired)
        ));

        // A later offer arrives while that answer is still owed. It must not
        // become a second request the late answer could be attributed to.
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_list(),
            })
            .await;
        assert!(
            outbound.try_recv().is_err(),
            "a second request was sent while an answer was still owed"
        );
        assert_eq!(owner.pending_offer, Some(FILEDESCRIPTOR_FORMAT_ID));

        // The dead request's answer finally arrives: absorbed, applied to nothing.
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_data_response(MSG_FLAGS_OK, raw_pdu(&[("a.txt", 0, false)])),
            })
            .await;
        assert!(owner.receive.is_none(), "a late answer started a receive");
        assert!(
            matches!(owner.descriptor_slot, Some(DescriptorSlot::InFlight { .. })),
            "the drained tombstone was replaced by the waiting offer's request"
        );
        assert!(owner.pending_offer.is_none());

        // Draining frees the slot for the offer that waited: a new request.
        let second = outbound.try_recv().expect("the waiting offer's own request");
        assert!(matches!(union(second.message()), Union::FormatDataRequest(_)));
    }

    /// The 30 s answer timeout is acted on at a pass boundary, so a queue that is
    /// never empty cannot postpone it forever.
    #[tokio::test]
    async fn a_due_answer_deadline_is_acted_on_while_the_pass_never_idles() {
        let cancel = CancellationToken::new();
        let start = start(cancel.clone());
        let handle = Arc::clone(&start.handle);
        let mut owner = start.owner;
        let outbound = start.outbound;
        handle.set_allowed(true);
        let era = handle.revision();
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_list(),
            })
            .await;
        owner.answer_deadline = Some(Instant::now());

        // Every one of these is answered with an effect, and the writer's queue is
        // never drained here: the owner therefore blocks inside a pass instead of
        // reaching `wait()`, which is where the pre-fix loop could only notice the
        // deadline.
        for _ in 0..CLIPRDR_INBOUND_QUEUE {
            handle
                .offer_inbound(format_data_request(FILECONTENTS_FORMAT_ID))
                .await
                .expect("queued");
        }
        let owner = tokio::spawn(owner.run());
        match next_event(&handle).await {
            CliprdrEvent::Failed { error, .. } => assert_eq!(error, CliprdrError::TimedOut),
            other => panic!("not a failure: {other:?}"),
        }
        drop(outbound);
        cancel.cancel();
        let exit = owner.await.expect("the owner task");
        assert!(
            matches!(exit, CliprdrExit::Cancelled | CliprdrExit::OutboundClosed),
            "{exit:?}"
        );
    }

    /// A peer notification admitted before a withdrawal is never current-era
    /// work: it may not become the descriptor request of the era the session is
    /// in now.
    #[tokio::test]
    async fn an_old_era_format_list_cannot_start_a_current_era_transfer() {
        let start = start(CancellationToken::new());
        let handle = Arc::clone(&start.handle);
        let mut owner = start.owner;
        let mut outbound = start.outbound;
        handle.set_allowed(true);
        let old_era = handle.revision();

        // The peer offered files in that era, and the session then left it.
        handle.set_allowed(false);
        handle.set_allowed(true);

        owner
            .receive_inbound(CliprdrInbound {
                revision: old_era,
                message: peer_format_list(),
            })
            .await;
        assert!(
            outbound.try_recv().is_err(),
            "an offer of a left era started a new-era descriptor request"
        );
        assert!(
            owner.pending_offer.is_none(),
            "the old offer was kept as work of the current era"
        );
        assert!(owner.descriptor_slot.is_none());
        assert!(
            !handle.has_events(),
            "dropping an old-era notification is not a failure of the current era"
        );

        // The same notification under the era this owner is in does start the
        // request it always did: the drop is about the era, not about the variant.
        let era = handle.revision();
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_list(),
            })
            .await;
        assert!(matches!(
            union(outbound.try_recv().expect("a descriptor request").message()),
            Union::FormatDataRequest(_)
        ));
    }

    /// An answer to a stream below the live one leaves the live request's wait —
    /// deadline included — exactly as it was.
    #[tokio::test]
    async fn a_reply_for_a_lower_stream_cannot_move_the_live_request_deadline() {
        let scratch = Scratch::new("lower-stream");
        let root = scratch.join("inbox");
        fs::create_dir_all(&root).expect("the root");
        let root = fs::canonicalize(&root).expect("a canonical root");
        let start = start(CancellationToken::new());
        let handle = Arc::clone(&start.handle);
        let mut owner = start.owner;
        let mut outbound = start.outbound;
        handle.set_allowed(true);
        let era = handle.revision();

        owner
            .command(Issued {
                request_id: 1,
                revision: era,
                command: CliprdrCommand::SetRoot(root),
            })
            .await;
        assert!(owner.root.is_some(), "the root was not adopted");

        // One peer offer, answered, starts fetching a file: the size request this
        // owner has in flight is the live request.
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_list(),
            })
            .await;
        assert!(matches!(
            union(outbound.try_recv().expect("a descriptor request").message()),
            Union::FormatDataRequest(_)
        ));
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_data_response(MSG_FLAGS_OK, raw_pdu(&[("a.txt", 5, false)])),
            })
            .await;
        let live = outbound.try_recv().expect("a size request");
        let stream = match union(live.message()) {
            Union::FileContentsRequest(request) => request.stream_id,
            other => panic!("not a contents request: {other:?}"),
        };
        let deadline = owner
            .answer_deadline
            .expect("the request in flight has a deadline");

        // Stream ids are taken monotonically and never reused, so an id below the
        // live one belongs to a request this session already ended. Its answer is
        // not the answer the live request waits for: it is dropped and the wait —
        // deadline included — is untouched.
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_file_contents_response(
                    MSG_FLAGS_OK,
                    stream - 1,
                    4_u64.to_le_bytes().to_vec(),
                ),
            })
            .await;
        assert_eq!(
            owner.answer_deadline,
            Some(deadline),
            "an answer to an ended stream moved the live request's deadline"
        );
        assert!(
            matches!(
                owner.receive.as_ref().and_then(|job| job.awaiting.as_ref()),
                Some(Awaiting::Size { stream: live_stream }) if *live_stream == stream
            ),
            "the live request is no longer the one being waited on"
        );
        assert!(
            !handle.has_events(),
            "an ended stream's answer was reported as a failure of the live request"
        );

        // The matching answer does end that wait: the job asks for the bytes next,
        // under a wait of its own.
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_file_contents_response(
                    MSG_FLAGS_OK,
                    stream,
                    5_u64.to_le_bytes().to_vec(),
                ),
            })
            .await;
        assert!(
            owner.answer_deadline.expect("the next request's wait") > deadline,
            "the answered request's own deadline was not cleared"
        );
        assert!(matches!(
            owner.receive.as_ref().and_then(|job| job.awaiting),
            Some(Awaiting::Range { .. })
        ));
    }

    /// Bytes can finish landing after the generation that admitted them ended: the
    /// job's own files are then removed and reported, never published as a
    /// current-era clipboard.
    #[tokio::test]
    async fn a_completed_transfer_is_not_published_after_its_generation_ended() {
        let scratch = Scratch::new("late-finish");
        let root = scratch.join("inbox");
        fs::create_dir_all(&root).expect("the root");
        let root = fs::canonicalize(&root).expect("a canonical root");
        let start = start(CancellationToken::new());
        let handle = Arc::clone(&start.handle);
        let mut owner = start.owner;
        let mut outbound = start.outbound;
        handle.set_allowed(true);
        let era = handle.revision();

        owner
            .command(Issued {
                request_id: 1,
                revision: era,
                command: CliprdrCommand::SetRoot(root.clone()),
            })
            .await;
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_list(),
            })
            .await;
        assert!(matches!(
            union(outbound.try_recv().expect("a descriptor request").message()),
            Union::FormatDataRequest(_)
        ));
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_format_data_response(MSG_FLAGS_OK, raw_pdu(&[("a.txt", 5, false)])),
            })
            .await;
        let size = outbound.try_recv().expect("a size request");
        let size_stream = match union(size.message()) {
            Union::FileContentsRequest(request) => request.stream_id,
            other => panic!("not a contents request: {other:?}"),
        };
        owner
            .receive_inbound(CliprdrInbound {
                revision: era,
                message: peer_file_contents_response(
                    MSG_FLAGS_OK,
                    size_stream,
                    5_u64.to_le_bytes().to_vec(),
                ),
            })
            .await;
        let range = outbound.try_recv().expect("a range request");
        let range_stream = match union(range.message()) {
            Union::FileContentsRequest(request) => request.stream_id,
            other => panic!("not a contents request: {other:?}"),
        };

        // Another thread withdraws the grant while this pass is inside the job's
        // own file work, so the owner has not reached a pass boundary and cannot
        // have adopted it yet.
        handle.revoke();

        // The last answer completes the block on disk. Publishing it now would
        // give finished work the standing of a grant that no longer exists.
        owner
            .receive_contents(wire::CliprdrFileContentsResponse {
                msg_flags: MSG_FLAGS_OK,
                stream_id: range_stream,
                requested_data: b"hello".to_vec().into(),
                ..Default::default()
            })
            .await;

        let events = handle.take_events();
        match events.as_slice() {
            [CliprdrEvent::Failed {
                error: CliprdrError::PermissionDenied,
                ..
            }] => {}
            other => panic!("not the withdrawal's own failure: {other:?}"),
        }
        // The withdrawn job's real files are gone: nothing of the peer's was left
        // under the client's root as an unreported paste.
        assert!(entries(&root).is_empty(), "the job's files were left behind");
        assert!(owner.receive.is_none(), "the withdrawn job is still held");
    }

    /// A full event mailbox is backpressure, not a lost fact: a completed paste
    /// waits for the applying consumer instead of being replaced by a newer event,
    /// and a closing session still lets the owner go.
    #[tokio::test]
    async fn a_full_mailbox_keeps_every_fact_and_a_close_still_lets_the_owner_go() {
        let cancel = CancellationToken::new();
        let shared = Arc::new(Shared::new(Arc::new(Fence::new()), cancel.clone()));
        fn event(request_id: u64) -> CliprdrEvent {
            CliprdrEvent::Failed {
                request_id: Some(request_id),
                error: CliprdrError::Closed,
            }
        }
        for request_id in 1..=CLIPRDR_EVENTS_KEPT as u64 {
            assert!(shared.push(event(request_id)).await);
        }
        assert_eq!(shared.pending_events(), CLIPRDR_EVENTS_KEPT);

        // The next fact does not replace the oldest one; it waits for room.
        let waiting = Arc::clone(&shared);
        let blocked = tokio::spawn(async move {
            waiting.push(event(CLIPRDR_EVENTS_KEPT as u64 + 1)).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!blocked.is_finished(), "a full mailbox swallowed a fact");
        assert_eq!(shared.pending_events(), CLIPRDR_EVENTS_KEPT);

        // A bounded take makes exactly one slot, and the waiting fact lands in it.
        assert_eq!(shared.take_events_limit(1).len(), 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), blocked)
                .await
                .expect("the waiting fact was never given room")
                .expect("the waiting push panicked")
        );
        assert_eq!(shared.pending_events(), CLIPRDR_EVENTS_KEPT);

        // Nothing that was visible was replaced: the oldest fact is still first and
        // the newest is the one that waited.
        let kept = shared.take_events_limit(usize::MAX);
        assert_eq!(kept.len(), CLIPRDR_EVENTS_KEPT);
        assert!(matches!(
            &kept[0],
            CliprdrEvent::Failed {
                request_id: Some(2),
                ..
            }
        ));
        assert!(matches!(
            &kept[CLIPRDR_EVENTS_KEPT - 1],
            CliprdrEvent::Failed { request_id: Some(id), .. }
                if *id == CLIPRDR_EVENTS_KEPT as u64 + 1
        ));

        // A closing session must not leave the owner waiting for a consumer that is
        // gone: the wait ends and nothing already kept is lost.
        for request_id in 1..=CLIPRDR_EVENTS_KEPT as u64 {
            assert!(shared.push(event(request_id)).await);
        }
        let waiting = Arc::clone(&shared);
        let blocked = tokio::spawn(async move { waiting.push(event(999)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!blocked.is_finished());
        cancel.cancel();
        assert!(
            !tokio::time::timeout(Duration::from_secs(5), blocked)
                .await
                .expect("a cancelled session kept the owner waiting for a consumer")
                .expect("the cancelled push panicked"),
            "a cancelled session kept a fact no consumer can read"
        );
        assert_eq!(shared.pending_events(), CLIPRDR_EVENTS_KEPT);
    }
}
