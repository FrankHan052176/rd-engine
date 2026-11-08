//! The clipboard entry points Resk's `RustDeskNativeApi.ets` imports.
//!
//! `sessionSendClipboard`, `sessionSendClipboardImage`, `sessionTakeClipboard`
//! and `sessionTakeClipboardImage` keep the signatures the client declares
//! today, so no ArkTS consumer changes for a real wire implementation to arrive
//! behind them. None of them touches a pasteboard: text and PNG bytes go to the
//! viewer as a typed [`ClipboardPayload`], and the metadata/bytes pair the
//! client reads back is handed out from that viewer's own mailbox, which is
//! where the permission generation and the image reservation live.
//!
//! Two receipts are deliberately different shapes:
//!
//! * A send answers whether the payload was *queued into the session's one
//!   writer*, with the clipboard generation it was queued under. It never claims
//!   the peer applied it: the original wire has no clipboard acknowledgement, and
//!   upstream applies what it receives without answering. A refusal is `ok:false`
//!   with `queued:false` and a `reason`, never `ok:true` for something that was
//!   not put on the queue — a peer that is owed nothing for this payload
//!   (`not_deliverable`) is one of those refusals.
//! * A take hands out one real pending update. No update is `ok:false` with
//!   `reason:no_pending_update`, not a clipboard clear. Missing formats are
//!   omitted rather than JSON null, matching the ArkTS optional-field contract.
//!
//! The two-call read shape is the client's, and it is also the one place a
//! clipboard race could hide: `sessionTakeClipboard` hands out a descriptor and
//! `sessionTakeClipboardImage` hands out the bytes. They are not two independent
//! getters here — the descriptor reserves exactly one accepted update inside the
//! mailbox, so the bytes are from that same update or there are none, and a
//! withdrawal between the calls withholds them.

use napi_derive_ohos::napi;
use napi_ohos::bindgen_prelude::Uint8Array;
use rd_engine::clipboard::{
    ClipboardError, ClipboardMetadata, ClipboardPayload, MAX_CLIPBOARD_IMAGE_BYTES,
};
use rd_engine::viewer::{Viewer, ViewerError};

const SEND_TEXT_ACTION: &str = "session_send_clipboard";
const SEND_IMAGE_ACTION: &str = "session_send_clipboard_image";
const TAKE_ACTION: &str = "session_take_clipboard";

/// The running viewer for one session.
///
/// This is the same registry lookup the input entry points use; it refuses an
/// unknown session and a session that has no running viewer, and never dials a
/// new one. The local clipboard policy is not read here: the engine holds it and
/// refuses the payload itself, both when it is queued and again at the writer, so
/// this layer cannot become a second, drifting copy of that decision.
fn active_viewer(session_id: &str) -> Result<std::sync::Arc<Viewer>, String> {
    crate::active_keyboard_viewer(session_id)
}

/// A shared (B→C) view has no clipboard in either direction.
///
/// Neither the peer's updates nor this side's payloads are part of what a share
/// grants, and the refusal is made before any session lookup so no mailbox,
/// reservation or writer queue is touched.
fn shared_refusal(action: &str) -> String {
    refused_message(
        action,
        "not_allowed",
        "a shared view has no clipboard: neither direction is part of what the share grants",
    )
}

/// Sends one format set through the viewer, and answers with what was queued.
///
/// The engine decides whether this peer can receive it at all: a peer without
/// `MultiClipboards` is sent the text format only, and a payload with no text is
/// not sent to such a peer. That last case is a refusal here rather than a quiet
/// `ok:true`, because nothing was queued.
fn send(viewer: &Viewer, payload: ClipboardPayload, action: &str) -> String {
    let formats: Vec<&'static str> = payload.items().iter().map(|item| item.name()).collect();
    match viewer.clipboard_send(payload) {
        Ok(revision) => queued(action, revision, formats),
        Err(error) => refused(action, &error),
    }
}

/// The receipt for a payload that really entered the writer's queue.
///
/// `queued` is the whole claim. The wire carries no clipboard acknowledgement, so
/// `applied` is stated as false instead of being left to a reader's assumption,
/// and `clipboard_revision` is the permission generation the writer will check
/// again before it writes.
fn queued(action: &str, revision: u64, formats: Vec<&'static str>) -> String {
    serde_json::json!({
        "ok": true,
        "queued": true,
        "applied": false,
        "action": action,
        "clipboard_revision": revision,
        "formats": formats,
    })
    .to_string()
}

/// The receipt for a payload that was not queued, with a reason a client can act
/// on and the engine's own typed message.
fn refused(action: &str, error: &ViewerError) -> String {
    serde_json::json!({
        "ok": false,
        "queued": false,
        "applied": false,
        "action": action,
        "reason": reason(error),
        "error": error.to_string(),
    })
    .to_string()
}

/// The refusal category: what a caller would do differently.
fn reason(error: &ViewerError) -> &'static str {
    match error {
        ViewerError::Clipboard(ClipboardError::NotDeliverable) => "not_deliverable",
        ViewerError::Clipboard(ClipboardError::TooLarge { .. })
        | ViewerError::Clipboard(ClipboardError::InflatedTooLarge { .. }) => "too_large",
        ViewerError::Clipboard(ClipboardError::Corrupt { .. }) => "corrupt",
        ViewerError::Clipboard(ClipboardError::InvalidImage { .. }) => "invalid_image",
        ViewerError::Clipboard(ClipboardError::NotAccepted) => "not_accepted",
        ViewerError::Clipboard(ClipboardError::StaleGeneration) => "stale_generation",
        ViewerError::Clipboard(ClipboardError::Refused { .. }) => "refused",
        ViewerError::InputNotAllowed => "not_allowed",
        ViewerError::Backpressure => "backpressure",
        ViewerError::Closed => "closed",
        _ => "failed",
    }
}

/// Refuses a call before a session lookup, with the same receipt shape.
fn refused_message(action: &str, reason: &'static str, message: &str) -> String {
    serde_json::json!({
        "ok": false,
        "queued": false,
        "applied": false,
        "action": action,
        "reason": reason,
        "error": message,
    })
    .to_string()
}

/// Sends a plain-text copy.
///
/// An empty `content` is the wire's clear, not an error: the canonical client
/// applies an empty `Text` clipboard as a cleared clipboard, and this is how that
/// update is produced.
#[napi]
pub fn session_send_clipboard(session_id: String, content: String) -> String {
    if crate::is_shared_session(&session_id) {
        return shared_refusal(SEND_TEXT_ACTION);
    }
    let viewer = match active_viewer(&session_id) {
        Ok(viewer) => viewer,
        Err(message) => return refused_message(SEND_TEXT_ACTION, "unknown_session", &message),
    };
    send(&viewer, ClipboardPayload::text(content), SEND_TEXT_ACTION)
}

/// Sends an encoded PNG, exactly as the client's own image packer produced it.
///
/// The bytes are handed on as an encoded image; nothing here decodes them into
/// pixels it would then have to re-encode. The bound is checked against the typed
/// array's own length *before* any copy, so an oversized buffer is refused
/// without this layer allocating it first; the engine checks it again on the
/// wire.
#[napi]
pub fn session_send_clipboard_image(session_id: String, image: Uint8Array) -> String {
    let length = image.len();
    if length == 0 {
        return refused_message(
            SEND_IMAGE_ACTION,
            "empty_image",
            "sessionSendClipboardImage image is empty",
        );
    }
    if length > MAX_CLIPBOARD_IMAGE_BYTES {
        return refused_message(
            SEND_IMAGE_ACTION,
            "too_large",
            "sessionSendClipboardImage image is over the clipboard bound",
        );
    }
    if crate::is_shared_session(&session_id) {
        return shared_refusal(SEND_IMAGE_ACTION);
    }
    let viewer = match active_viewer(&session_id) {
        Ok(viewer) => viewer,
        Err(message) => return refused_message(SEND_IMAGE_ACTION, "unknown_session", &message),
    };
    send(&viewer, ClipboardPayload::png(image.to_vec()), SEND_IMAGE_ACTION)
}

/// Hands out the next clipboard update's metadata, and reserves its image.
///
/// The document is `{ ok, queued, applied, action, revision, text, html, image,
/// formats }`. `queued` and `applied` are false because this is not a send: it
/// reports what the peer's own update was, not anything this side wrote.
/// `revision` is the permission generation the update was accepted under;
/// `text: ""` is the clear. A missing format is omitted, never JSON null.
/// `image` is `{ format, width, height, byteLength }`, and `width`/`height` are
/// `0` for an encoded PNG/SVG, whose own header carries the size. `formats`
/// names every format the update carried, so an RTF or special format with no
/// pasteboard mapping is reported rather than silently dropped.
#[napi]
pub fn session_take_clipboard(session_id: String) -> String {
    if crate::is_shared_session(&session_id) {
        return shared_refusal(TAKE_ACTION);
    }
    let viewer = match active_viewer(&session_id) {
        Ok(viewer) => viewer,
        Err(message) => return refused_message(TAKE_ACTION, "unknown_session", &message),
    };
    let metadata = viewer.clipboard_take_metadata();
    describe(metadata.as_ref()).to_string()
}

/// Hands out the image bytes `sessionTakeClipboard` described.
///
/// An empty array means there are no bytes to apply: no image was described, or
/// the acceptance that described it was withdrawn before this call. The client
/// compares the length it was told against the length it received, so a refusal
/// here is visible to it instead of becoming a pasteboard write of the wrong
/// image.
#[napi]
pub fn session_take_clipboard_image(session_id: String) -> Uint8Array {
    // A shared view reserves nothing, so there is nothing to hand out: the empty
    // array is the same answer this call already gives for an unheld image.
    let Ok(viewer) = active_viewer(&session_id) else {
        return Uint8Array::new(Vec::new());
    };
    match viewer.clipboard_take_image() {
        Some(image) => Uint8Array::new(image.bytes),
        None => Uint8Array::new(Vec::new()),
    }
}

/// Optional formats stay absent: ArkTS checks `!== undefined`, not `!= null`.
fn describe(metadata: Option<&ClipboardMetadata>) -> serde_json::Value {
    let Some(metadata) = metadata else {
        return serde_json::json!({
            "ok": false,
            "queued": false,
            "applied": false,
            "action": TAKE_ACTION,
            "reason": "no_pending_update",
        });
    };
    let mut answer = serde_json::json!({
        "ok": true,
        "queued": false,
        "applied": false,
        "action": TAKE_ACTION,
        "revision": metadata.revision,
        "formats": metadata.formats,
    });
    if let Some(text) = &metadata.text {
        answer["text"] = serde_json::json!(text);
    }
    if let Some(html) = &metadata.html {
        answer["html"] = serde_json::json!(html);
    }
    if let Some(descriptor) = metadata.image {
        answer["image"] = serde_json::json!({
            "format": descriptor.format.as_str(),
            "width": descriptor.width,
            "height": descriptor.height,
            "byteLength": descriptor.byte_length,
        });
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use rd_engine::clipboard::{ClipboardImageDescriptor, ClipboardImageFormat};

    #[test]
    fn no_pending_update_is_not_a_clear_and_absent_formats_are_omitted() {
        let absent = describe(None);
        assert_eq!(absent["ok"], false);
        assert_eq!(absent["reason"], "no_pending_update");
        assert!(absent.get("text").is_none());
        let mut metadata = ClipboardMetadata {
            revision: 7,
            text: Some(String::new()),
            html: None,
            image: None,
            formats: vec!["text"],
        };
        let clear = describe(Some(&metadata));
        assert_eq!(clear["ok"], true);
        assert_eq!(clear["text"], "");
        assert!(clear.get("html").is_none());
        assert!(clear.get("image").is_none());
        metadata.text = None;
        metadata.formats = vec!["png"];
        metadata.image = Some(ClipboardImageDescriptor {
            format: ClipboardImageFormat::Png,
            width: 0,
            height: 0,
            byte_length: 24,
        });
        let image = describe(Some(&metadata));
        assert!(image.get("text").is_none());
        assert!(image.get("html").is_none());
        assert_eq!(image["image"]["byteLength"], 24);
    }
}
