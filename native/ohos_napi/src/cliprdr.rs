//! The file clipboard entry points Resk's `RustDeskNativeApi.ets` imports.
//!
//! `sessionSendClipboardFiles` and `sessionSetClipboardFileRoot` keep the
//! signatures the client declares today, so no ArkTS consumer changes for a real
//! wire implementation to arrive behind them. Neither of them touches a
//! pasteboard, copies a file or transfers anything: a call only enqueues one
//! command on the running viewer's own [`rd_engine::cliprdr`] owner, and the
//! answer says exactly that.
//!
//! # What a receipt claims
//!
//! `queued: true` means the command entered that owner's queue. It never means
//! the peer was told anything, that a descriptor list was written, or that a
//! byte reached a disk — those are stated by the engine's own events, which the
//! viewer publishes later ([`rd_engine::cliprdr::CliprdrEvent::Offered`] for the
//! announcement that really was written, and
//! [`rd_engine::cliprdr::CliprdrEvent::Files`] for a peer's files that really
//! became paths on this device). `applied: false` says that in every receipt,
//! including the successful one.
//!
//! A refusal is `ok: false` with `queued: false` and a `reason`: an unknown
//! session, a session with no cliprdr owner, a closed or full queue, or a
//! command this engine will not enqueue. Local shapes that need a real directory
//! to judge — whether an offered file exists, whether the root is a usable
//! private directory, how far a directory expands — are **not** judged here:
//! they are discovered by the owner and reported as a later `Failed` event, so a
//! receipt is never an `ok: true` for something that did not happen.
//!
//! The viewer's one reader admits peer messages; its one writer completes
//! effects. Polling only reports pending facts. The foreground applying consumer
//! explicitly takes events, then rechecks the live generation before applying
//! file paths to the system clipboard.

use napi_derive_ohos::napi;
use rd_engine::cliprdr::{CliprdrCommand, CliprdrError, CliprdrEvent};
use rd_engine::viewer::Viewer;

const SEND_FILES_ACTION: &str = "session_send_clipboard_files";
const SET_ROOT_ACTION: &str = "session_set_clipboard_file_root";

/// Bound on the JSON array this layer will parse.
///
/// The engine bounds how many roots one offer may name and refuses more; this
/// bound is about the bytes that arrive from ArkTS before any of that runs, so an
/// accidentally huge string is refused instead of being parsed into a list. A
/// real paste of 64 staged paths is far below it.
const MAX_PATHS_JSON_BYTES: usize = 32 << 10;

/// The running viewer for one session.
///
/// This is the same registry lookup the input and clipboard entry points use: it
/// refuses an unknown session and a session with no running viewer, and never
/// dials a new one. The permission decision is not made here — the engine's owner
/// holds the fence and answers with its own refusal, both when a command is
/// submitted and again at the writer, so this layer cannot become a second,
/// drifting copy of it.
fn active_viewer(session_id: &str) -> Result<std::sync::Arc<Viewer>, String> {
    crate::active_keyboard_viewer(session_id)
}

/// A shared (B→C) view has no file clipboard.
///
/// B's forward host serves one encoded display and nothing else, so neither a
/// file offer nor an incoming-root command has an owner there to receive it.
fn shared_refusal(action: &str) -> String {
    refused(
        action,
        "not_allowed",
        "a shared view has no file clipboard: the peer behind B is a forward host, not a desktop session",
    )
}

/// The receipt for a command that really entered the owner's queue.
fn queued(action: &str, request_id: u64) -> String {
    serde_json::json!({
        "ok": true,
        "queued": true,
        "applied": false,
        "action": action,
        "request_id": request_id,
    })
    .to_string()
}

/// The receipt for a command that was not queued, with a reason a client can act
/// on and the engine's own typed message.
fn refused(action: &str, reason: &'static str, error: &str) -> String {
    serde_json::json!({
        "ok": false,
        "queued": false,
        "applied": false,
        "action": action,
        "reason": reason,
        "error": error,
        "message": error,
    })
    .to_string()
}

/// The refusal category: what a caller would do differently.
fn reason(error: &CliprdrError) -> &'static str {
    match error {
        CliprdrError::PermissionDenied => "not_allowed",
        CliprdrError::RootUnset => "root_unset",
        CliprdrError::RootInvalid => "invalid_root",
        CliprdrError::OfferEmpty => "empty",
        CliprdrError::OfferTooLarge => "too_many_files",
        CliprdrError::OfferPathInvalid | CliprdrError::FileNameInvalid => "invalid_path",
        CliprdrError::Backpressure => "backpressure",
        CliprdrError::Closed | CliprdrError::Cancelled => "closed",
        _ => "failed",
    }
}

/// Announces this side's already-staged local files as its file clipboard.
///
/// `paths_json` is the JSON array of **absolute** paths the client itself staged
/// (it copies the local files or directories first and passes the real staged
/// paths), at most `MAX_CLIPRDR_OFFER_ROOTS` of them. A path that is relative, or
/// that names something unreadable, is refused by the engine and surfaces as a
/// later failure event; nothing here pretends it happened.
#[napi]
pub fn session_send_clipboard_files(session_id: String, paths_json: String) -> String {
    if crate::is_shared_session(&session_id) {
        return shared_refusal(SEND_FILES_ACTION);
    }
    if paths_json.len() > MAX_PATHS_JSON_BYTES {
        return refused(
            SEND_FILES_ACTION,
            "too_large",
            "sessionSendClipboardFiles paths are over the input bound",
        );
    }
    let paths: Vec<String> = match serde_json::from_str(&paths_json) {
        Ok(paths) => paths,
        Err(_) => {
            return refused(
                SEND_FILES_ACTION,
                "invalid_json",
                "sessionSendClipboardFiles paths are not a JSON array of strings",
            )
        }
    };
    let viewer = match active_viewer(&session_id) {
        Ok(viewer) => viewer,
        Err(message) => return refused(SEND_FILES_ACTION, "unknown_session", &message),
    };
    let Some(handle) = viewer.cliprdr_handle() else {
        return refused(
            SEND_FILES_ACTION,
            "cliprdr_unavailable",
            "this session has no file clipboard owner",
        );
    };
    let paths: Vec<std::path::PathBuf> = paths.into_iter().map(std::path::PathBuf::from).collect();
    match handle.submit(CliprdrCommand::OfferFiles(paths)) {
        Ok(request_id) => queued(SEND_FILES_ACTION, request_id),
        Err(error) => refused(SEND_FILES_ACTION, reason(&error), &error.to_string()),
    }
}

/// Sets the one private directory a peer's files may be created under.
///
/// The client passes its own incoming root. This only enqueues: whether the path
/// is an absolute, non-symlinked, usable directory — and creating it if it does
/// not exist yet — is decided by the owner, and a path it cannot adopt is
/// reported as a later failure event rather than as a successful receipt.
#[napi]
pub fn session_set_clipboard_file_root(session_id: String, root: String) -> String {
    if crate::is_shared_session(&session_id) {
        return shared_refusal(SET_ROOT_ACTION);
    }
    let viewer = match active_viewer(&session_id) {
        Ok(viewer) => viewer,
        Err(message) => return refused(SET_ROOT_ACTION, "unknown_session", &message),
    };
    let Some(handle) = viewer.cliprdr_handle() else {
        return refused(
            SET_ROOT_ACTION,
            "cliprdr_unavailable",
            "this session has no file clipboard owner",
        );
    };
    match handle.submit(CliprdrCommand::SetRoot(std::path::PathBuf::from(root))) {
        Ok(request_id) => queued(SET_ROOT_ACTION, request_id),
        Err(error) => refused(SET_ROOT_ACTION, reason(&error), &error.to_string()),
    }
}

fn file_event(event: CliprdrEvent) -> serde_json::Value {
    match event {
        CliprdrEvent::Files { request_id, revision, paths, bytes } => serde_json::json!({
            "kind": "files",
            "request_id": request_id,
            "revision": revision.to_string(),
            "paths": paths,
            "bytes": bytes,
        }),
        CliprdrEvent::Offered { request_id, files, bytes } => serde_json::json!({
            "kind": "offered",
            "request_id": request_id,
            "files": files,
            "bytes": bytes,
        }),
        CliprdrEvent::Failed { request_id, error } => serde_json::json!({
            "kind": "failed",
            "request_id": request_id,
            "reason": reason(&error),
            "error": error.to_string(),
        }),
    }
}

/// A notifier's non-consuming view. No file paths or clipboard bytes leave the
/// owner here, and a background poll never steals the applying consumer's facts.
#[napi]
pub fn session_get_clipboard_file_state(session_id: String) -> String {
    let action = "session_get_clipboard_file_state";
    if crate::is_shared_session(&session_id) {
        return shared_refusal(action);
    }
    let viewer = match active_viewer(&session_id) {
        Ok(viewer) => viewer,
        Err(message) => return refused(action, "unknown_session", &message),
    };
    let Some(handle) = viewer.cliprdr_handle() else {
        return refused(action, "cliprdr_unavailable", "this session has no file clipboard owner");
    };
    let (revision, allowed) = handle.permission();
    serde_json::json!({
        "ok": true,
        "action": action,
        "revision": revision.to_string(),
        "allowed": allowed,
        "pending": handle.pending_events(),
    }).to_string()
}

/// Only the foreground applying consumer calls this. It must process every
/// returned fact; Files retain their original ticket, even after revocation.
/// Taking one bounded batch leaves all remaining facts in the owner's mailbox.
#[napi]
pub fn session_take_clipboard_file_events(session_id: String) -> String {
    let action = "session_take_clipboard_file_events";
    if crate::is_shared_session(&session_id) {
        return shared_refusal(action);
    }
    let viewer = match active_viewer(&session_id) {
        Ok(viewer) => viewer,
        Err(message) => return refused(action, "unknown_session", &message),
    };
    let Some(handle) = viewer.cliprdr_handle() else {
        return refused(action, "cliprdr_unavailable", "this session has no file clipboard owner");
    };
    let events: Vec<_> = handle.take_events_limit(8).into_iter().map(file_event).collect();
    let (revision, allowed) = handle.permission();
    serde_json::json!({
        "ok": true,
        "action": action,
        "revision": revision.to_string(),
        "allowed": allowed,
        "events": events,
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_queued_receipt_never_claims_the_peer_applied_anything() {
        let receipt: serde_json::Value =
            serde_json::from_str(&queued(SEND_FILES_ACTION, 7)).expect("a JSON receipt");
        assert_eq!(receipt["ok"], true);
        assert_eq!(receipt["queued"], true);
        assert_eq!(receipt["applied"], false);
        assert_eq!(receipt["action"], SEND_FILES_ACTION);
        assert_eq!(receipt["request_id"], 7);
        // A queued receipt says nothing about the peer or about a disk.
        assert!(receipt.get("error").is_none());
        assert!(receipt.get("reason").is_none());
    }

    #[test]
    fn a_refusal_is_never_ok_and_names_its_reason() {
        let receipt: serde_json::Value = serde_json::from_str(&refused(
            SEND_FILES_ACTION,
            reason(&CliprdrError::PermissionDenied),
            "the fence is closed",
        ))
        .expect("a JSON receipt");
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["queued"], false);
        assert_eq!(receipt["applied"], false);
        assert_eq!(receipt["reason"], "not_allowed");
        assert!(receipt.get("request_id").is_none());
    }

    #[test]
    fn the_input_bound_is_refused_before_any_parsing() {
        let oversized = "x".repeat(MAX_PATHS_JSON_BYTES + 1);
        let receipt: serde_json::Value = serde_json::from_str(&session_send_clipboard_files(
            "no-such-session".to_owned(),
            oversized,
        ))
        .expect("a JSON receipt");
        // Refused for its size, and not for the session it never looked up.
        assert_eq!(receipt["reason"], "too_large");
        assert_eq!(receipt["queued"], false);
    }

    #[test]
    fn a_malformed_paths_document_is_refused_not_parsed_hopefully() {
        let receipt: serde_json::Value =
            serde_json::from_str(&session_send_clipboard_files(
                "no-such-session".to_owned(),
                "{\"not\":\"an array\"}".to_owned(),
            ))
            .expect("a JSON receipt");
        assert_eq!(receipt["reason"], "invalid_json");
    }
}
