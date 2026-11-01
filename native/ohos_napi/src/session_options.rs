//! ArkTS-facing session-option entry points, over `rd_engine::session_options`.
//!
//! This module is the bridge half of the typed RustDesk option store: it maps the
//! client's own spelling onto `SessionOptionChange` variants, hands the change to
//! the session that owns the wire, and answers with the *requested* state. It
//! never builds a message itself and never claims the peer applied anything.
//!
//! Two paths, kept separate on purpose:
//!
//!  * a session with a running viewer hands the change to
//!    `Viewer::set_session_option`, which prepares it against the peer's real
//!    version, the decoding this session advertised and the displays the peer
//!    reported, and queues the resulting control records on the session's one
//!    writer;
//!  * a session that has not dialled yet can only hold the values its login
//!    advertisement carries, so `SessionOptions::request` records them for the
//!    next `session_start`. A display switch or a resolution change is refused
//!    there instead of being recorded and never sent.
//!
//! What this module needs from `lib.rs` (each is a required hook, not an
//! assumption): `pub mod session_options;` in the engine crate, a
//! `SessionRecord::session_options: SessionOptions` field, the
//! `ViewerError::SessionOption(OptionError)` variant, and the
//! `Viewer::set_session_option` / `Viewer::session_options_snapshot` methods.
//! The exact hunks ship in `.build-deps/session-options-handoff/HANDOFF.md`.
//!
//! Not served here, deliberately: `sessionSetSize` takes the local renderer's
//! size and has no wire message, so it must not be answered as a remote
//! resolution change; and this engine has no audio renderer, so
//! `sessionGetRemoteAudioState` reports the option state and states that no
//! frame is played rather than reporting a renderer that does not exist.
use super::{error_json, mutable_snapshot, with_sessions};
use base::message_proto::{supported_decoding::PreferCodec, ImageQuality};
use napi_derive_ohos::napi;
use rd_engine::session_options::{SessionOptionChange, SessionOptions};
use rd_engine::viewer::ViewerError;
use serde_json::{json, Value};

/// Which session the answer is about: the one running now, or the next dial.
#[derive(Clone, Copy)]
enum OptionScope {
    /// A viewer is running; the change was queued for its single writer.
    Session,
    /// No viewer is running; the change is held for the next `session_start`.
    NextSession,
}

impl OptionScope {
    fn name(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::NextSession => "next_session",
        }
    }

    fn note(self) -> &'static str {
        match self {
            Self::Session => {
                "queued for this session's single writer; the peer's application is not \
                 confirmed, and a quality level has no peer echo so the answer is the requested one"
            }
            Self::NextSession => {
                "recorded for the next session_start: no viewer is running, so nothing has \
                 reached the wire"
            }
        }
    }
}

/// The requested state, in the terms the client's own settings use.
///
/// `image_quality` is the pinned client's config spelling (`low`, `balanced`,
/// `best`, `custom`, or empty for "nothing asked"), `codec_preference` is this
/// product's settings spelling, and `requested_resolution` is the resolution
/// this session asked the peer for on the display it asked to show.
fn requested_json(options: &SessionOptions) -> Value {
    json!({
        "image_quality": options.image_quality_name(),
        "custom_image_quality": options.custom_image_quality(),
        "codec_preference": options.codec_preference_name(),
        "clipboard_enabled": options.clipboard_enabled(),
        "audio_enabled": options.audio_enabled(),
        "show_remote_cursor": options.show_remote_cursor(),
        "display": options.display(),
        "requested_resolution": options
            .requested_resolution(options.display())
            .map(|(width, height)| json!({ "width": width, "height": height })),
    })
}

fn options_answer(action: &str, requested: &SessionOptions, scope: OptionScope) -> String {
    json!({
        "ok": true,
        "action": action,
        // This is the requested state, never a reading of what the peer did.
        "applied": false,
        "scope": scope.name(),
        "requested": requested_json(requested),
        "note": scope.note(),
    })
    .to_string()
}

/// Applies one typed change to the session the caller named.
///
/// The change is computed from the requested state the session holds now, so a
/// toggle flips what this session asked for rather than assuming the peer's
/// default. A closed or closing record is refused before anything is prepared,
/// and a refusal never leaves half of a change in force: the session's own state
/// is replaced only after the change was accepted.
fn apply(
    session_id: &str,
    action: &str,
    change: impl FnOnce(&SessionOptions) -> Result<SessionOptionChange, String>,
) -> String {
    with_sessions(|sessions| {
        let Some(record) = sessions.get_mut(session_id) else {
            return error_json("unknown session");
        };
        if let Err(message) = mutable_snapshot(record) {
            return error_json(message);
        }
        let viewer = record.viewer.clone();
        let current = match viewer.as_ref() {
            Some(viewer) => viewer.session_options_snapshot(),
            None => record.session_options.clone(),
        };
        let change = match change(&current) {
            Ok(change) => change,
            Err(message) => return error_json(&message),
        };
        match viewer {
            Some(viewer) => match viewer.set_session_option(change) {
                Ok(()) => {
                    let requested = viewer.session_options_snapshot();
                    record.session_options = requested.clone();
                    options_answer(action, &requested, OptionScope::Session)
                }
                Err(ViewerError::SessionOption(error)) => {
                    error_json(&format!("{action} refused: {error}"))
                }
                Err(error) => error_json(&format!("{action} refused: {error:?}")),
            },
            None => match record.session_options.request(change) {
                Ok(next) => {
                    record.session_options = next.clone();
                    options_answer(action, &next, OptionScope::NextSession)
                }
                Err(error) => error_json(&format!("{action} refused: {error}")),
            },
        }
    })
}

/// The named quality presets the pinned client's config understands.
///
/// `custom` is not a level: it means "use the custom percentage", which this
/// engine takes through `sessionSetCustomImageQuality`, so a client that wants a
/// percentage is told which call to use instead of having its request answered
/// as if a level had been chosen.
fn named_quality(name: &str) -> Result<ImageQuality, String> {
    match name.trim() {
        "low" => Ok(ImageQuality::Low),
        "balanced" => Ok(ImageQuality::Balanced),
        "best" => Ok(ImageQuality::Best),
        "custom" => Err(
            "sessionSetImageQuality takes a named level; sessionSetCustomImageQuality takes \
             the custom percentage"
                .to_string(),
        ),
        other => Err(format!(
            "sessionSetImageQuality has no level {other:?}: low, balanced or best"
        )),
    }
}

fn preferred_codec(name: &str) -> Result<PreferCodec, String> {
    match name.trim() {
        "auto" => Ok(PreferCodec::Auto),
        "h264" => Ok(PreferCodec::H264),
        "h265" => Ok(PreferCodec::H265),
        "vp8" => Ok(PreferCodec::VP8),
        "vp9" => Ok(PreferCodec::VP9),
        "av1" => Ok(PreferCodec::AV1),
        other => Err(format!(
            "sessionSetCodecPreference has no codec {other:?}: auto, h264, h265, vp8, vp9 or av1"
        )),
    }
}

/// The first display index of the legacy array the client sends.
///
/// The client's own entry point takes a `Vec<i32>` and uses its first element; an
/// array is never a request for several displays, and an empty one names none.
fn first_display(displays_json: &str) -> Result<i32, String> {
    let value: Vec<i32> = serde_json::from_str(displays_json).map_err(|_| {
        "sessionSwitchDisplay takes a JSON array of display indices, such as [0]".to_string()
    })?;
    value
        .first()
        .copied()
        .ok_or_else(|| "sessionSwitchDisplay needs one display index".to_string())
}

/// The state of an option this bridge acts on.
///
/// A toggle's name follows the client's own `get_toggle_option` vocabulary. Only
/// the three options this engine really acts on are answered: for any other name
/// this bridge has nothing to report, and `sessionToggleOption` refuses it rather
/// than recording a value nothing reads.
fn toggle_state(options: &SessionOptions, option: &str) -> bool {
    match option {
        "disable-audio" => !options.audio_enabled(),
        "disable-clipboard" => !options.clipboard_enabled(),
        "show-remote-cursor" => options.show_remote_cursor(),
        _ => false,
    }
}

fn flipped(options: &SessionOptions, option: &str) -> Result<SessionOptionChange, String> {
    match option {
        "disable-audio" => Ok(SessionOptionChange::AudioEnabled(!options.audio_enabled())),
        "disable-clipboard" => {
            Ok(SessionOptionChange::ClipboardEnabled(!options.clipboard_enabled()))
        }
        "show-remote-cursor" => Ok(SessionOptionChange::ShowRemoteCursor(
            !options.show_remote_cursor(),
        )),
        other => Err(format!(
            "sessionToggleOption has no option {other:?}: this engine acts on disable-audio, \
             disable-clipboard and show-remote-cursor only"
        )),
    }
}

#[napi]
pub fn session_set_image_quality(session_id: String, quality: String) -> String {
    match named_quality(&quality) {
        Ok(quality) => apply(&session_id, "sessionSetImageQuality", move |_| {
            Ok(SessionOptionChange::ImageQuality(quality))
        }),
        Err(message) => error_json(&message),
    }
}

#[napi]
pub fn session_set_custom_image_quality(session_id: String, quality: i32) -> String {
    apply(&session_id, "sessionSetCustomImageQuality", move |_| {
        Ok(SessionOptionChange::CustomImageQuality(quality))
    })
}

#[napi]
pub fn session_set_codec_preference(session_id: String, codec: String) -> String {
    match preferred_codec(&codec) {
        Ok(prefer) => apply(&session_id, "sessionSetCodecPreference", move |_| {
            Ok(SessionOptionChange::CodecPreference(prefer))
        }),
        Err(message) => error_json(&message),
    }
}

#[napi]
pub fn session_set_show_remote_cursor(session_id: String, enabled: bool) -> String {
    apply(&session_id, "sessionSetShowRemoteCursor", move |_| {
        Ok(SessionOptionChange::ShowRemoteCursor(enabled))
    })
}

#[napi]
pub fn session_switch_display(session_id: String, displays_json: String) -> String {
    match first_display(&displays_json) {
        Ok(display) => apply(&session_id, "sessionSwitchDisplay", move |_| {
            Ok(SessionOptionChange::SwitchDisplay(display))
        }),
        Err(message) => error_json(&message),
    }
}

/// Asks the peer to change one display's resolution.
///
/// This is the peer's own resolution request. The local renderer's size is a
/// different fact and has no wire message, so `sessionSetSize` is not answered
/// here and must not be turned into one.
#[napi]
pub fn session_change_resolution(
    session_id: String,
    display: i32,
    width: i32,
    height: i32,
) -> String {
    apply(&session_id, "sessionChangeResolution", move |_| {
        Ok(SessionOptionChange::ChangeResolution {
            display,
            width,
            height,
        })
    })
}

/// The requested quality in the pinned client's config spelling.
///
/// Empty means this session asked for nothing, so the peer's default applies. The
/// peer echoes no quality back, so there is no applied level to report and none
/// is invented.
#[napi]
pub fn session_get_image_quality(session_id: String) -> String {
    with_sessions(|sessions| match sessions.get(&session_id) {
        Some(record) => match record.viewer.as_ref() {
            Some(viewer) => viewer.session_options_snapshot().image_quality_name().to_string(),
            None => record.session_options.image_quality_name().to_string(),
        },
        None => String::new(),
    })
}

#[napi]
pub fn session_get_toggle_option(session_id: String, option: String) -> bool {
    with_sessions(|sessions| match sessions.get(&session_id) {
        Some(record) => {
            let requested = match record.viewer.as_ref() {
                Some(viewer) => viewer.session_options_snapshot(),
                None => record.session_options.clone(),
            };
            toggle_state(&requested, &option)
        }
        None => false,
    })
}

#[napi]
pub fn session_toggle_option(session_id: String, option: String) -> String {
    let named = option.trim().to_string();
    apply(&session_id, "sessionToggleOption", move |requested| {
        flipped(requested, &named)
    })
}

/// The audio option this session asked for, without claiming a renderer.
///
/// `available` and `rendererActive` are false because this engine really has no
/// desktop audio output; `muted` is the requested disable-audio state, which is a
/// real wire option. A client that reads this sees the option it set and the
/// reason no sound follows, rather than a renderer that does not exist.
#[napi]
pub fn session_get_remote_audio_state(session_id: String) -> String {
    with_sessions(|sessions| match sessions.get(&session_id) {
        Some(record) => {
            let requested = match record.viewer.as_ref() {
                Some(viewer) => viewer.session_options_snapshot(),
                None => record.session_options.clone(),
            };
            json!({
                "ok": true,
                "action": "sessionGetRemoteAudioState",
                "audio": {
                    "available": false,
                    "muted": !requested.audio_enabled(),
                    "rendererActive": false,
                    "errorText": "this engine has no desktop audio renderer: the option tells \
                                  the peer whether to send audio, and no frame is played",
                },
                "requested": requested_json(&requested),
            })
            .to_string()
        }
        None => error_json("unknown session"),
    })
}
