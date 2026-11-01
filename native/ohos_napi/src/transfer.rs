//! Typed conversion between the ArkTS file-transfer entry points and the
//! engine's session-owned transfer owner.
//!
//! This module converts and serializes only. It owns no job, holds no registry
//! lock and performs no file or platform I/O: the caller passes the current
//! session's `Viewer` methods in, and every refusal the engine makes stays the
//! engine's own answer.
//!
//! The event shapes below are the pinned client's (`src/flutter.rs` and
//! `common::_make_fd_to_json` in `rustdesk/rustdesk` @ `092a961b…`), including
//! their numeric-as-text fields: the Resk consumer parses `id`, `file_num`,
//! `speed` and `finished_size` with `Number(text)` and checks `.trim()` first,
//! so a JSON number here would break it.

use base::message_proto::{FileDirectory, FileEntry};
use rd_engine::transfer::{self, TransferCommand, TransferEvent};
use serde_json::json;

/// One NAPI integer as a job id: positive and inside the engine's `i32` space.
///
/// The client allocates the id itself (`transferNextJobId`), so this only checks
/// the value it hands back; ownership of the id is the engine's own check.
fn job_id(value: i64) -> Result<i32, &'static str> {
    let value = i32::try_from(value).map_err(|_| "job id is out of range")?;
    if value <= 0 {
        return Err("job id must be a positive integer");
    }
    Ok(value)
}

/// `sessionSendFiles`: the client's `isRemote` means "the source is on the peer",
/// which is the engine's `Download`; the other direction is `Upload`.
///
/// `path` is the source and `to` the destination in both directions, exactly as
/// the client's own call names them. `file_num` is refused when it is not zero:
/// this owner keeps no serialized job meta, so it cannot resume one.
pub fn send_files_command(
    job: i64,
    path: String,
    to: String,
    file_num: i64,
    include_hidden: bool,
    is_remote: bool,
) -> Result<TransferCommand, &'static str> {
    let job = job_id(job)?;
    let file_num = i32::try_from(file_num).map_err(|_| "file number is out of range")?;
    Ok(if is_remote {
        TransferCommand::Download {
            job,
            remote: path,
            local: to,
            file_num,
            include_hidden,
        }
    } else {
        TransferCommand::Upload {
            job,
            local: path,
            remote: to,
            file_num,
            include_hidden,
        }
    })
}

/// `sessionReadRemoteDir`. An empty path is the peer's home directory, which is
/// the one place the protocol allows one.
pub fn read_dir_command(path: String, include_hidden: bool) -> TransferCommand {
    TransferCommand::ReadDir {
        path,
        include_hidden,
    }
}

/// `sessionSetConfirmOverrideFile`: the operator's answer to one job's overwrite
/// question. `is_upload` is the client's own direction flag and selects the same
/// table the engine's `Upload`/`Download` use.
pub fn confirm_command(
    job: i64,
    file_num: i64,
    need_override: bool,
    remember: bool,
    is_upload: bool,
) -> Result<TransferCommand, &'static str> {
    Ok(TransferCommand::ConfirmOverwrite {
        job: job_id(job)?,
        file_num: i32::try_from(file_num).map_err(|_| "file number is out of range")?,
        overwrite: need_override,
        remember,
        upload: is_upload,
    })
}

/// `sessionCancelJob`: one job, never a viewer close and never a record ACK.
pub fn cancel_command(job: i64) -> Result<TransferCommand, &'static str> {
    Ok(TransferCommand::Cancel { job: job_id(job)? })
}

/// `transferNextJobId`: the engine's own counter, so an id is never reused. The
/// id is usable only by the session that adopts it.
pub fn next_job_id() -> i32 {
    transfer::next_job_id()
}

/// One directory as the pinned client serializes it: the same keys, the same
/// `entry_type` number and no derived field.
fn directory_json(directory: &FileDirectory) -> String {
    let entries: Vec<serde_json::Value> = directory
        .entries
        .iter()
        .map(entry_json)
        .collect();
    json!({
        "id": directory.id,
        "path": directory.path,
        "entries": entries,
    })
    .to_string()
}

fn entry_json(entry: &FileEntry) -> serde_json::Value {
    json!({
        "entry_type": entry.entry_type.value(),
        "name": entry.name,
        "size": entry.size,
        "modified_time": entry.modified_time,
    })
}

/// The engine's transfer events as the client's own event shapes.
///
/// Every numeric and boolean field is text, because that is the shape the client
/// parses; `job_error` with `err: "skipped"` is upstream's own spelling for a
/// file the operator or the peer declined.
pub fn events(events: &[TransferEvent]) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|event| match event {
            TransferEvent::Directory(directory) => json!({
                "name": "file_dir",
                "is_local": "false",
                "value": directory_json(directory),
            }),
            TransferEvent::Overwrite {
                job,
                file_num,
                read_path,
                upload,
                identical,
            } => json!({
                "name": "override_file_confirm",
                "id": job.to_string(),
                "file_num": file_num.to_string(),
                "read_path": read_path,
                "is_upload": upload.to_string(),
                "is_identical": identical.to_string(),
            }),
            TransferEvent::Progress {
                job,
                file_num,
                speed,
                finished_size,
            } => json!({
                "name": "job_progress",
                "id": job.to_string(),
                "file_num": file_num.to_string(),
                "speed": speed.to_string(),
                "finished_size": finished_size.to_string(),
            }),
            TransferEvent::Done { job, file_num } => json!({
                "name": "job_done",
                "id": job.to_string(),
                "file_num": file_num.to_string(),
            }),
            TransferEvent::Failed {
                job,
                file_num,
                error,
            } => json!({
                "name": "job_error",
                "id": job.to_string(),
                "err": error,
                "file_num": file_num.to_string(),
            }),
            TransferEvent::Skipped { job, file_num } => json!({
                "name": "job_error",
                "id": job.to_string(),
                "err": "skipped",
                "file_num": file_num.to_string(),
            }),
            TransferEvent::EmptyDirs { path, directories } => {
                let directories: Vec<serde_json::Value> = directories
                    .iter()
                    .map(|directory| {
                        json!({
                            "id": directory.id,
                            "path": directory.path,
                            "entries": directory
                                .entries
                                .iter()
                                .map(entry_json)
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                json!({
                    "name": "empty_dirs",
                    "is_local": "false",
                    "value": json!({
                        "path": path,
                        "empty_dirs": directories,
                    })
                    .to_string(),
                })
            }
        })
        .collect()
}

/// The action was accepted by the engine's own admission, which is not a promise
/// that the peer received anything.
pub fn ok_response(action: &str) -> String {
    json!({
        "ok": true,
        "action": action,
    })
    .to_string()
}

/// The action was refused before it could be queued. `message` is the engine's
/// own local constant, never peer text.
pub fn error_response(action: &str, message: &str) -> String {
    json!({
        "ok": false,
        "action": action,
        "record_removed": false,
        "error": message,
        "message": message,
    })
    .to_string()
}
