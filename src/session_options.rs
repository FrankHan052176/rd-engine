//! Typed RustDesk session options: what this viewer asks the peer for, and the
//! exact control messages that carry it.
//!
//! This module is deliberately small and owns no connection state. It holds the
//! *requested* configuration of one desktop session, turns a typed change into
//! the finite set of control messages the pinned RustDesk wire uses, and rejects
//! a change whose preconditions this session cannot meet. Sending is not part of
//! it: the caller's single writer sends what [`PreparedOption::messages`] holds,
//! which is why nothing here claims the peer applied anything.
//!
//! Three facts stay separate on purpose:
//!
//!  * **requested** — what [`SessionOptions`] holds and what
//!    [`SessionOptions::prepare`] returns as `next`;
//!  * **sent** — a message this module built reached the writer. Only the caller
//!    can see that, so this module never reports it;
//!  * **observed** — what the peer itself reported. Nothing here invents it, and
//!    a quality level has no peer echo at all, so the answer to "which quality"
//!    is always the requested level rather than a made-up applied one.
//!
//! Wire provenance: the message shapes below are the pinned official client's
//! own encoders, not paraphrase. They come from `rustdesk/rustdesk` at
//! `092a961b629d318fe290eeafac0cd214a1e9deeb`:
//!
//!  * `src/client.rs` — `get_option_message` / `save_image_quality` /
//!    `save_custom_image_quality` / `update_supported_decodings` (the
//!    `OptionMessage` shape, `custom_image_quality`'s `<< 8` encoding and the
//!    codec-preference message), and `get_custom_resolution` (the remembered
//!    per-display resolution a display switch repeats);
//!  * `src/ui_session_interface.rs` — `switch_display` (a `SwitchDisplay` whose
//!    width/height are the remembered custom resolution, `(0, 0)` when none) and
//!    `do_change_resolution` (a display-qualified `change_display_resolution` for
//!    a peer that understands one, the legacy unqualified `change_resolution`
//!    before that);
//!  * `src/common.rs` — `MIN_VER_MULTI_UI_SESSION = "1.2.4"` with
//!    `is_support_multi_ui_session_num`, the exact version gate the resolution
//!    choice uses;
//!  * `vendor/rustdesk/libs/base/protos/message.proto` — the field numbers and
//!    enum values themselves.
//!
//! Two upstream behaviors are deliberately *not* reproduced here because they
//! are client configuration policy, not wire: the public-server clamp that
//! replaces a custom quality above 100 with 50, and the config writes that keep
//! a choice across sessions. The caller owns its own configuration; this module
//! only states the wire's own domain and refuses anything outside it.

use crate::protocol::Protocol;
use crate::viewer::PeerDisplayInfo;
use base::message_proto::{
    DisplayResolution, ImageQuality, Message, Misc, OptionMessage, Resolution, SupportedDecoding,
    SwitchDisplay, option_message::BoolOption, supported_decoding::PreferCodec,
};
use std::collections::BTreeMap;
use std::fmt;

/// The peer version that first understood a display-qualified resolution change.
///
/// Taken from the pinned client's `MIN_VER_MULTI_UI_SESSION`: before it a peer
/// has no way to name a display in a resolution change, so the request can only
/// mean its current display.
const DISPLAY_RESOLUTION_SINCE: &str = "1.2.4";

/// The custom-quality domain the pinned client's own slider offers.
///
/// `10..=100` is the standard range and "More" extends it to `2000` for a direct
/// or private server. The extended values are accepted here because they are a
/// real wire value; deciding whether *this* server may receive one is the
/// caller's server policy, which this module has no view of.
const MIN_CUSTOM_QUALITY: i32 = 1;
const MAX_CUSTOM_QUALITY: i32 = 2000;

/// One typed request to change what this session asks the peer for.
///
/// It is an enum rather than a string key precisely so an unknown request cannot
/// be accepted: a bridge maps the client's own spelling onto these variants, and
/// anything it cannot map never becomes a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOptionChange {
    /// A named quality preset: `Low`, `Balanced` or `Best`.
    ImageQuality(ImageQuality),
    /// The custom quality percentage (`1..=2000`) the pinned client's slider
    /// produces; the wire carries it shifted by eight bits.
    CustomImageQuality(i32),
    /// Which decodable codec this session prefers. Only a codec this session
    /// actually advertised may be preferred.
    CodecPreference(PreferCodec),
    /// Whether the peer may exchange clipboard content with this session.
    ClipboardEnabled(bool),
    /// Whether this session asks the peer to send desktop audio and plays it.
    ///
    /// It is this viewer's own switch, not a grant: the audio owner plays only
    /// the AND of this option, the peer's own audio grant and the live desktop
    /// session, so asking for audio here cannot make a peer that withheld it
    /// heard.
    AudioEnabled(bool),
    /// Subscribe to the peer's separate cursor image and position messages.
    /// This does not ask the peer to embed cursor pixels in its video.
    ShowRemoteCursor(bool),
    /// Show another of the peer's displays, by its own index.
    SwitchDisplay(i32),
    /// Ask the peer to change the resolution of one of its displays.
    ChangeResolution {
        display: i32,
        width: i32,
        height: i32,
    },
}

/// What one change was checked against.
///
/// Every field is a fact the session already has, so nothing here is queried,
/// guessed or derived: the wire this session speaks, the peer's own version, the
/// decoding this session advertised at login, and the displays the peer
/// reported. `current_display` is the peer's display being shown now, which is
/// what a peer too old to name a display in a resolution change can be asked
/// about.
pub struct OptionContext<'a> {
    pub protocol: Protocol,
    /// The peer's own version string, as its login response carried it.
    pub peer_version: &'a str,
    /// The `supported_decoding` this session sent at login.
    pub advertised_decoding: &'a SupportedDecoding,
    /// The peer's displays at their own indices, as its handshake reported them.
    pub displays: &'a [PeerDisplayInfo],
    /// The peer's display this session is showing now.
    pub current_display: i32,
}

impl OptionContext<'_> {
    /// Refuses an index the peer never reported.
    ///
    /// The list is the handshake's, so a display the peer adds mid-session is
    /// refused here until something reports it; this engine does not track the
    /// peer's later display list, and inventing an index range would be worse
    /// than saying the display is not known.
    fn addressable(&self, display: i32) -> Result<(), OptionError> {
        let reported = i32::try_from(self.displays.len()).unwrap_or(i32::MAX);
        if display < 0 || display >= reported {
            return Err(OptionError::UnknownDisplay(display));
        }
        Ok(())
    }
}

/// One accepted change: the messages to send, and the requested state after it.
///
/// The messages are a bounded set of control records — one per change today —
/// and they carry no socket, runtime, task or media resource, so a caller hands
/// them to whatever already owns the wire. `next` is the *requested* state; it is
/// not a reading of what the peer did with the request.
#[derive(Debug, Clone)]
pub struct PreparedOption {
    /// The control messages this change produces, in the order they must travel.
    pub messages: Vec<Message>,
    /// The requested state after this change, to keep as the session's own
    /// answer to "what did we ask for".
    pub next: SessionOptions,
}

/// Why a change was refused before anything reached the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionError {
    /// These are the RustDesk wire's own controls; another wire has none.
    UnsupportedProtocol,
    /// `NotSet` is the absence of a request, not a quality to ask for.
    InvalidImageQuality,
    /// The custom quality is outside the pinned client's own domain.
    InvalidCustomQuality(i32),
    /// This session never advertised a decoder for the preferred codec, so
    /// preferring it would ask the peer for something it cannot decode.
    CodecUnavailable(PreferCodec),
    /// The peer reported no such display.
    UnknownDisplay(i32),
    /// A width or height that cannot describe a display.
    InvalidResolution { width: i32, height: i32 },
    /// The peer's version is unknown, so the resolution message shape is not.
    UnknownPeerVersion,
    /// This peer predates display-qualified resolution changes, so a request for
    /// a display other than the one being shown cannot be expressed.
    DisplayNotAddressable(i32),
    /// A display switch or resolution change needs the peer's own report; the
    /// session has not dialled yet, so it could only be recorded, never sent.
    SessionNotStarted,
}

impl fmt::Display for OptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocol => {
                write!(f, "session options exist only on the RustDesk wire")
            }
            Self::InvalidImageQuality => {
                write!(f, "a named quality must be Low, Balanced or Best")
            }
            Self::InvalidCustomQuality(value) => write!(
                f,
                "custom image quality {value} is outside {MIN_CUSTOM_QUALITY}..={MAX_CUSTOM_QUALITY}"
            ),
            Self::CodecUnavailable(codec) => write!(
                f,
                "codec {} is not one this session advertised a decoder for",
                prefer_name(*codec)
            ),
            Self::UnknownDisplay(display) => {
                write!(f, "the peer reported no display {display}")
            }
            Self::InvalidResolution { width, height } => {
                write!(f, "{width}x{height} is not a display resolution")
            }
            Self::UnknownPeerVersion => {
                write!(f, "the peer's version is not known yet")
            }
            Self::DisplayNotAddressable(display) => write!(
                f,
                "this peer's version cannot address display {display}; only the display being shown can be resized"
            ),
            Self::SessionNotStarted => {
                write!(
                    f,
                    "this change needs a running session and the peer's own report"
                )
            }
        }
    }
}

impl std::error::Error for OptionError {}

/// The requested configuration of one desktop session.
///
/// This is what a change produces and what a login advertises, so the same value
/// can be frozen into a session's start options and later replaced by the answer
/// the running session gives. Its default is this engine's own desktop default,
/// which now matches the official viewer's own: no quality request, clipboard
/// enabled, audio on (the operator's switch turns it off), no remote cursor,
/// display 0, and no remembered custom resolution. Clipboard admission still
/// requires the live authenticated desktop, the peer grant and a non-view-only
/// local policy; audio playback likewise requires the peer's own audio grant
/// beside this option, so a peer that withholds audio is never heard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOptions {
    /// The named preset asked for, if any.
    image_quality: Option<ImageQuality>,
    /// The custom quality percentage asked for, if any. It is the client-side
    /// percentage; the wire value is that shifted by eight bits.
    custom_image_quality: Option<i32>,
    codec_preference: PreferCodec,
    clipboard_enabled: bool,
    audio_enabled: bool,
    show_remote_cursor: bool,
    /// The display this session asked to show. It is the request, not the peer's
    /// confirmation of it.
    display: i32,
    /// The resolution this session asked the peer for, per display index. A
    /// display switch repeats it, exactly as the pinned client repeats the
    /// resolution it remembers for the display it switches to.
    requested_resolutions: BTreeMap<i32, (i32, i32)>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            image_quality: None,
            custom_image_quality: None,
            codec_preference: PreferCodec::Auto,
            clipboard_enabled: true,
            // The official viewer's own default: a desktop session receives the
            // peer's audio unless the operator turns it off. Playback still
            // needs the peer's own audio grant on a live authenticated session,
            // and this switch never starts a microphone or loopback capture.
            audio_enabled: true,
            show_remote_cursor: false,
            display: 0,
            requested_resolutions: BTreeMap::new(),
        }
    }
}

impl SessionOptions {
    /// The named preset this session asked for.
    pub fn image_quality(&self) -> Option<ImageQuality> {
        self.image_quality
    }

    /// The custom quality percentage this session asked for.
    pub fn custom_image_quality(&self) -> Option<i32> {
        self.custom_image_quality
    }

    /// The requested quality in the pinned client's own config spelling.
    ///
    /// `"low"`, `"balanced"`, `"best"` and `"custom"` are the values its
    /// `get_image_quality_enum` accepts, and the empty string means this session
    /// asked for nothing and the peer's default applies. It is the *requested*
    /// level: the peer echoes no quality back, so reporting an applied one would
    /// be invented.
    pub fn image_quality_name(&self) -> &'static str {
        match (self.image_quality, self.custom_image_quality) {
            (_, Some(_)) => "custom",
            (Some(ImageQuality::Low), None) => "low",
            (Some(ImageQuality::Balanced), None) => "balanced",
            (Some(ImageQuality::Best), None) => "best",
            (Some(ImageQuality::NotSet), None) | (None, None) => "",
        }
    }

    /// The codec this session prefers.
    pub fn codec_preference(&self) -> PreferCodec {
        self.codec_preference
    }

    /// The preferred codec in the spelling this product's settings use.
    pub fn codec_preference_name(&self) -> &'static str {
        prefer_name(self.codec_preference)
    }

    /// Whether the peer may exchange clipboard content with this session.
    pub fn clipboard_enabled(&self) -> bool {
        self.clipboard_enabled
    }

    /// Whether this session asks the peer to send desktop audio.
    ///
    /// The switch this viewer holds, not the answer to "did something play":
    /// the running session's own snapshot reports the audio owner's real state
    /// (format, whether the device is active, packets and samples), and a peer
    /// that withheld its audio grant plays nothing however this option is set.
    /// It is on by default, which is the official viewer's own desktop default;
    /// only an explicit off states `disable_audio` to the peer.
    pub fn audio_enabled(&self) -> bool {
        self.audio_enabled
    }

    /// Whether the peer was asked to embed its own cursor in the video.
    pub fn show_remote_cursor(&self) -> bool {
        self.show_remote_cursor
    }

    /// The display this session asked to show.
    pub fn display(&self) -> i32 {
        self.display
    }

    /// The resolution this session asked the peer for on `display`, if any.
    pub fn requested_resolution(&self, display: i32) -> Option<(i32, i32)> {
        self.requested_resolutions.get(&display).copied()
    }

    /// The `OptionMessage` a desktop login carries for this configuration.
    ///
    /// `advertised` is the decoding this build really has, exactly as
    /// [`crate::video::Decoders::supported_decoding`] states it; the requested
    /// preference is set inside it, which is the shape the pinned client's
    /// `get_supported_decoding` fills in. The frame rate is not here: this module
    /// does not own it, so the caller composes `custom_fps` from its own rate as
    /// it did before.
    ///
    /// The disable flags follow the pinned client's own login habit: a flag is
    /// stated when it is on, and left `NotSet` when it is off, so "off" means the
    /// peer's default rather than an argument with it. Audio is therefore left
    /// `NotSet` while this session asks for it — the pinned client sends
    /// `disable_audio: Yes` only when its own config has audio off
    /// (`src/client.rs:3386`) — and becomes `Yes` as soon as the operator turns
    /// the switch off. `enable_file_transfer`
    /// enables the Desktop's real file clipboard owner; it does not select the
    /// separate FileTransfer login role or grant a permission the peer withheld.
    /// Camera viewing remains explicitly disabled.
    pub fn validate_advertisement(
        &self,
        advertised_decoding: &SupportedDecoding,
    ) -> Result<(), OptionError> {
        if advertised(advertised_decoding, self.codec_preference) {
            Ok(())
        } else {
            Err(OptionError::CodecUnavailable(self.codec_preference))
        }
    }

    pub fn login_options(&self, advertised: &SupportedDecoding) -> OptionMessage {
        OptionMessage {
            image_quality: self.image_quality.unwrap_or(ImageQuality::NotSet).into(),
            custom_image_quality: self.custom_image_quality.map_or(0, |quality| quality << 8),
            disable_audio: login_disable(!self.audio_enabled).into(),
            disable_clipboard: login_disable(!self.clipboard_enabled).into(),
            show_remote_cursor: login_disable(self.show_remote_cursor).into(),
            supported_decoding: Some(SupportedDecoding {
                prefer: self.codec_preference.into(),
                ..advertised.clone()
            })
            .into(),
            // This engine sends no keyboard request other than "allowed"; the
            // local input policy is what stops input, and a read-only switch that
            // is turned off again must not wait for a grant the peer was told
            // never to send.
            disable_keyboard: BoolOption::No.into(),
            enable_file_transfer: BoolOption::Yes.into(),
            disable_camera: BoolOption::Yes.into(),
            ..Default::default()
        }
    }

    /// Records a change this session may be given before it dials.
    ///
    /// This is the pre-start half of [`Self::prepare`]: the values the login
    /// advertisement itself carries can be set while no peer is connected, and
    /// they take effect when the next session starts with this configuration. A
    /// display switch or a resolution change is refused here rather than recorded
    /// and quietly dropped: neither exists in the login message, and this engine
    /// has no post-login replay of a remembered resolution, so accepting one would
    /// be a request that could never reach the wire.
    pub fn request(&self, change: SessionOptionChange) -> Result<Self, OptionError> {
        match change {
            SessionOptionChange::ImageQuality(quality) => self.with_image_quality(quality),
            SessionOptionChange::CustomImageQuality(quality) => {
                self.with_custom_image_quality(quality)
            }
            SessionOptionChange::CodecPreference(prefer) => {
                let mut next = self.clone();
                next.codec_preference = prefer;
                Ok(next)
            }
            SessionOptionChange::ClipboardEnabled(enabled) => {
                let mut next = self.clone();
                next.clipboard_enabled = enabled;
                Ok(next)
            }
            SessionOptionChange::AudioEnabled(enabled) => {
                let mut next = self.clone();
                next.audio_enabled = enabled;
                Ok(next)
            }
            SessionOptionChange::ShowRemoteCursor(enabled) => {
                let mut next = self.clone();
                next.show_remote_cursor = enabled;
                Ok(next)
            }
            SessionOptionChange::SwitchDisplay(_)
            | SessionOptionChange::ChangeResolution { .. } => Err(OptionError::SessionNotStarted),
        }
    }

    /// Turns one change into the control messages that carry it.
    ///
    /// A change is refused when this session cannot make it real: another wire has
    /// no such options, a codec this build never advertised cannot be preferred, a
    /// display the peer never reported cannot be addressed, a resolution must be a
    /// real size, and a peer too old to name a display can only be asked about the
    /// display it is showing. Everything else becomes exactly one control message
    /// of the pinned wire's own shape.
    pub fn prepare(
        &self,
        change: SessionOptionChange,
        context: &OptionContext<'_>,
    ) -> Result<PreparedOption, OptionError> {
        if context.protocol != Protocol::RustDesk {
            return Err(OptionError::UnsupportedProtocol);
        }
        match change {
            SessionOptionChange::ImageQuality(quality) => {
                let next = self.with_image_quality(quality)?;
                Ok(PreparedOption {
                    messages: vec![option_message(OptionMessage {
                        image_quality: quality.into(),
                        ..Default::default()
                    })],
                    next,
                })
            }
            SessionOptionChange::CustomImageQuality(quality) => {
                let next = self.with_custom_image_quality(quality)?;
                Ok(PreparedOption {
                    messages: vec![option_message(OptionMessage {
                        // The pinned client's own encoding: `quality << 8`.
                        custom_image_quality: quality << 8,
                        ..Default::default()
                    })],
                    next,
                })
            }
            SessionOptionChange::CodecPreference(prefer) => {
                if !advertised(context.advertised_decoding, prefer) {
                    return Err(OptionError::CodecUnavailable(prefer));
                }
                let mut next = self.clone();
                next.codec_preference = prefer;
                Ok(PreparedOption {
                    messages: vec![option_message(OptionMessage {
                        // The pinned client's own codec-preference message: the
                        // decoding it advertised, with the preference set.
                        supported_decoding: Some(SupportedDecoding {
                            prefer: prefer.into(),
                            ..context.advertised_decoding.clone()
                        })
                        .into(),
                        ..Default::default()
                    })],
                    next,
                })
            }
            SessionOptionChange::ClipboardEnabled(enabled) => {
                let mut next = self.clone();
                next.clipboard_enabled = enabled;
                Ok(PreparedOption {
                    messages: vec![option_message(OptionMessage {
                        disable_clipboard: change_flag(!enabled).into(),
                        ..Default::default()
                    })],
                    next,
                })
            }
            SessionOptionChange::AudioEnabled(enabled) => {
                let mut next = self.clone();
                next.audio_enabled = enabled;
                Ok(PreparedOption {
                    messages: vec![option_message(OptionMessage {
                        disable_audio: change_flag(!enabled).into(),
                        ..Default::default()
                    })],
                    next,
                })
            }
            SessionOptionChange::ShowRemoteCursor(enabled) => {
                let mut next = self.clone();
                next.show_remote_cursor = enabled;
                Ok(PreparedOption {
                    messages: vec![option_message(OptionMessage {
                        show_remote_cursor: change_flag(enabled).into(),
                        ..Default::default()
                    })],
                    next,
                })
            }
            SessionOptionChange::SwitchDisplay(display) => {
                context.addressable(display)?;
                let (width, height) = self
                    .requested_resolutions
                    .get(&display)
                    .copied()
                    .unwrap_or((0, 0));
                let mut next = self.clone();
                next.display = display;
                let mut misc = Misc::new();
                // The pinned client's own shape: the display, plus the custom
                // resolution it remembers for that display and `(0, 0)` when it
                // remembers none. Nothing is claimed about the display's geometry
                // here — that is the peer's to report.
                //
                // The client's non-texture-render follow-up (`CaptureDisplays`
                // with `set: [display]`) is not sent: this engine presents one
                // bound native Surface, which is the texture-render case that
                // sends `switch_display` alone. Sending a capture instruction the
                // engine does not run would be a second, unverified display owner.
                misc.set_switch_display(SwitchDisplay {
                    display,
                    width,
                    height,
                    ..Default::default()
                });
                Ok(PreparedOption {
                    messages: vec![misc_message(misc)],
                    next,
                })
            }
            SessionOptionChange::ChangeResolution {
                display,
                width,
                height,
            } => {
                if width <= 0 || height <= 0 {
                    return Err(OptionError::InvalidResolution { width, height });
                }
                context.addressable(display)?;
                let version = hbb_common::get_version_number(context.peer_version);
                if version <= 0 {
                    return Err(OptionError::UnknownPeerVersion);
                }
                let mut misc = Misc::new();
                if version >= display_resolution_version() {
                    misc.set_change_display_resolution(DisplayResolution {
                        display,
                        resolution: Some(Resolution {
                            width,
                            height,
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    });
                } else {
                    // A peer without display-qualified resolution changes can only
                    // resize the display it is showing; asking it about another
                    // display would resize the wrong one.
                    if display != context.current_display {
                        return Err(OptionError::DisplayNotAddressable(display));
                    }
                    misc.set_change_resolution(Resolution {
                        width,
                        height,
                        ..Default::default()
                    });
                }
                let mut next = self.clone();
                next.requested_resolutions.insert(display, (width, height));
                Ok(PreparedOption {
                    messages: vec![misc_message(misc)],
                    next,
                })
            }
        }
    }

    fn with_image_quality(&self, quality: ImageQuality) -> Result<Self, OptionError> {
        // `NotSet` is the proto's "no request", which is the absence of a message
        // rather than a level: accepting it would let a caller clear the request
        // by sending one the peer ignores.
        if quality == ImageQuality::NotSet {
            return Err(OptionError::InvalidImageQuality);
        }
        let mut next = self.clone();
        next.image_quality = Some(quality);
        // Asking for a named level replaces a custom one, exactly as the pinned
        // client's config does: only one of the two is in force.
        next.custom_image_quality = None;
        Ok(next)
    }

    fn with_custom_image_quality(&self, quality: i32) -> Result<Self, OptionError> {
        if !(MIN_CUSTOM_QUALITY..=MAX_CUSTOM_QUALITY).contains(&quality) {
            return Err(OptionError::InvalidCustomQuality(quality));
        }
        let mut next = self.clone();
        next.custom_image_quality = Some(quality);
        next.image_quality = None;
        Ok(next)
    }
}

/// The version number a display-qualified resolution change needs.
fn display_resolution_version() -> i64 {
    hbb_common::get_version_number(DISPLAY_RESOLUTION_SINCE)
}

/// Whether this session advertised a decoder for `prefer`.
///
/// The answer is read from the advertisement the session actually sent, so an
/// ability this build does not have cannot be preferred: AV1, for one, is
/// advertised as zero everywhere in this engine and is therefore refused here
/// without a hard-coded exception.
fn advertised(decoding: &SupportedDecoding, prefer: PreferCodec) -> bool {
    match prefer {
        // No preference among the codecs the peer was offered is always valid.
        PreferCodec::Auto => true,
        PreferCodec::VP9 => decoding.ability_vp9 > 0,
        PreferCodec::H264 => decoding.ability_h264 > 0,
        PreferCodec::H265 => decoding.ability_h265 > 0,
        PreferCodec::VP8 => decoding.ability_vp8 > 0,
        PreferCodec::AV1 => decoding.ability_av1 > 0,
    }
}

/// The pinned client's own config spelling for a codec preference.
fn prefer_name(prefer: PreferCodec) -> &'static str {
    match prefer {
        PreferCodec::Auto => "auto",
        PreferCodec::VP9 => "vp9",
        PreferCodec::H264 => "h264",
        PreferCodec::H265 => "h265",
        PreferCodec::VP8 => "vp8",
        PreferCodec::AV1 => "av1",
    }
}

/// The login shape of a flag: stated only when it is on.
fn login_disable(on: bool) -> BoolOption {
    if on {
        BoolOption::Yes
    } else {
        BoolOption::NotSet
    }
}

/// The change shape of a flag: an explicit yes or no, because leaving it unset
/// would leave whatever the peer last heard in force.
fn change_flag(value: bool) -> BoolOption {
    if value {
        BoolOption::Yes
    } else {
        BoolOption::No
    }
}

/// One `Misc` carrying one `OptionMessage`, which is the shape every option
/// change on this wire takes.
fn option_message(option: OptionMessage) -> Message {
    let mut misc = Misc::new();
    misc.set_option(option);
    misc_message(misc)
}

fn misc_message(misc: Misc) -> Message {
    let mut message = Message::new();
    message.set_misc(misc);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::{message, misc};

    fn decoding(h264: bool, h265: bool, vp8: bool, vp9: bool) -> SupportedDecoding {
        SupportedDecoding {
            ability_h264: i32::from(h264),
            ability_h265: i32::from(h265),
            ability_vp8: i32::from(vp8),
            ability_vp9: i32::from(vp9),
            ability_av1: 0,
            prefer: PreferCodec::Auto.into(),
            ..Default::default()
        }
    }

    fn displays(count: usize) -> Vec<PeerDisplayInfo> {
        (0..count).map(|_| PeerDisplayInfo::default()).collect()
    }

    fn context<'a>(
        peer_version: &'a str,
        advertised_decoding: &'a SupportedDecoding,
        displays: &'a [PeerDisplayInfo],
        current_display: i32,
    ) -> OptionContext<'a> {
        OptionContext {
            protocol: Protocol::RustDesk,
            peer_version,
            advertised_decoding,
            displays,
            current_display,
        }
    }

    /// The one `OptionMessage` a change produced.
    fn sent_option(prepared: &PreparedOption) -> OptionMessage {
        assert_eq!(prepared.messages.len(), 1, "one change, one message");
        match prepared.messages[0].union.as_ref() {
            Some(message::Union::Misc(misc)) => match misc.union.as_ref() {
                Some(misc::Union::Option(option)) => option.clone(),
                other => panic!("change did not carry an option: {other:?}"),
            },
            other => panic!("change did not carry misc: {other:?}"),
        }
    }

    /// The one `Misc` union a change produced, for the non-option messages.
    fn sent_misc(prepared: &PreparedOption) -> misc::Union {
        assert_eq!(prepared.messages.len(), 1, "one change, one message");
        match prepared.messages[0].union.as_ref() {
            Some(message::Union::Misc(misc)) => misc
                .union
                .clone()
                .expect("every option change sets one misc field"),
            other => panic!("change did not carry misc: {other:?}"),
        }
    }

    #[test]
    fn login_advertises_only_the_controls_this_default_holds() {
        let advertised = decoding(true, false, false, false);
        let option = SessionOptions::default().login_options(&advertised);
        // Audio is asked for by default, which is the pinned client's own
        // desktop default: it states `disable_audio: Yes` only when its config
        // has audio off, so an enabled session leaves the flag unset and the
        // peer's own default decides. The peer's audio grant still bounds
        // playback, so asking here never overrides a peer that withheld it.
        assert_eq!(
            option.disable_audio.enum_value().unwrap(),
            BoolOption::NotSet,
            "the default desktop session asks for the peer's audio"
        );
        // Only this session's own switch can state the flag.
        let muted = SessionOptions::default()
            .request(SessionOptionChange::AudioEnabled(false))
            .expect("audio can be turned off")
            .login_options(&advertised);
        assert_eq!(
            muted.disable_audio.enum_value().unwrap(),
            BoolOption::Yes,
            "an explicit off is stated to the peer at login too"
        );
        assert_eq!(
            option.disable_clipboard.enum_value().unwrap(),
            BoolOption::NotSet,
            "the default clipboard request follows the peer default; the owner enforces its live grants"
        );
        assert_eq!(
            option.show_remote_cursor.enum_value().unwrap(),
            BoolOption::NotSet,
            "an off flag is left to the peer's default at login"
        );
        assert_eq!(
            option.enable_file_transfer.enum_value().unwrap(),
            BoolOption::Yes,
            "Desktop enables its file clipboard without changing the login role"
        );
        assert_eq!(
            option.disable_camera.enum_value().unwrap(),
            BoolOption::Yes,
            "camera viewing is excluded from this product"
        );
        assert_eq!(option.custom_fps, 0, "the caller owns the frame rate");
        let decoding = option
            .supported_decoding
            .as_ref()
            .expect("login states the decoding it advertised");
        assert_eq!(decoding.ability_h264, 1);
        assert_eq!(decoding.ability_vp9, 0);
        assert_eq!(decoding.prefer.enum_value().unwrap(), PreferCodec::Auto);
    }

    #[test]
    fn named_quality_is_one_option_message() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(1);
        let context = context("1.4.9", &advertised, &displays, 0);
        let prepared = SessionOptions::default()
            .prepare(
                SessionOptionChange::ImageQuality(ImageQuality::Best),
                &context,
            )
            .expect("Best is a request the peer understands");
        let option = sent_option(&prepared);
        assert_eq!(
            option.image_quality.enum_value().unwrap(),
            ImageQuality::Best
        );
        assert_eq!(option.custom_image_quality, 0);
        assert_eq!(prepared.next.image_quality(), Some(ImageQuality::Best));
        assert_eq!(prepared.next.image_quality_name(), "best");
    }

    #[test]
    fn not_set_is_not_a_quality_request() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(1);
        let context = context("1.4.9", &advertised, &displays, 0);
        assert_eq!(
            SessionOptions::default()
                .prepare(
                    SessionOptionChange::ImageQuality(ImageQuality::NotSet),
                    &context
                )
                .unwrap_err(),
            OptionError::InvalidImageQuality
        );
    }

    #[test]
    fn custom_quality_is_shifted_by_eight_and_replaces_the_named_preset() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(1);
        let context = context("1.4.9", &advertised, &displays, 0);
        let preset = SessionOptions::default()
            .prepare(
                SessionOptionChange::ImageQuality(ImageQuality::Low),
                &context,
            )
            .expect("Low is a request the peer understands");
        let prepared = preset
            .next
            .prepare(SessionOptionChange::CustomImageQuality(60), &context)
            .expect("60 is inside the pinned client's own domain");
        let option = sent_option(&prepared);
        assert_eq!(option.custom_image_quality, 60 << 8);
        assert_eq!(
            option.image_quality.enum_value().unwrap(),
            ImageQuality::NotSet,
            "only one of the two presets is in force"
        );
        assert_eq!(prepared.next.image_quality(), None);
        assert_eq!(prepared.next.image_quality_name(), "custom");
        assert_eq!(
            SessionOptions::default()
                .prepare(SessionOptionChange::CustomImageQuality(0), &context)
                .unwrap_err(),
            OptionError::InvalidCustomQuality(0)
        );
    }

    #[test]
    fn codec_preference_needs_the_decoding_this_login_advertised() {
        let without_vp9 = decoding(true, false, false, false);
        let displays = displays(1);
        let context_without = context("1.4.9", &without_vp9, &displays, 0);
        assert_eq!(
            SessionOptions::default()
                .prepare(
                    SessionOptionChange::CodecPreference(PreferCodec::VP9),
                    &context_without
                )
                .unwrap_err(),
            OptionError::CodecUnavailable(PreferCodec::VP9)
        );
        // AV1 is advertised as zero by this engine, so preferring it is refused
        // by the same evidence check rather than by a separate exception.
        assert_eq!(
            SessionOptions::default()
                .prepare(
                    SessionOptionChange::CodecPreference(PreferCodec::AV1),
                    &context_without
                )
                .unwrap_err(),
            OptionError::CodecUnavailable(PreferCodec::AV1)
        );

        let with_vp9 = decoding(true, true, false, true);
        let context_with = context("1.4.9", &with_vp9, &displays, 0);
        let prepared = SessionOptions::default()
            .prepare(
                SessionOptionChange::CodecPreference(PreferCodec::VP9),
                &context_with,
            )
            .expect("VP9 was advertised, so it may be preferred");
        let option = sent_option(&prepared);
        let decoding = option
            .supported_decoding
            .as_ref()
            .expect("a preference restates the advertisement");
        assert_eq!(decoding.prefer.enum_value().unwrap(), PreferCodec::VP9);
        assert_eq!(decoding.ability_vp9, 1);
        assert_eq!(decoding.ability_h264, 1);
        assert_eq!(prepared.next.codec_preference(), PreferCodec::VP9);
        assert_eq!(prepared.next.codec_preference_name(), "vp9");
    }

    #[test]
    fn clipboard_and_audio_are_real_disable_flags() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(1);
        let context = context("1.4.9", &advertised, &displays, 0);
        let enabled = SessionOptions::default()
            .prepare(SessionOptionChange::ClipboardEnabled(true), &context)
            .expect("clipboard can be asked for");
        assert_eq!(
            sent_option(&enabled)
                .disable_clipboard
                .enum_value()
                .unwrap(),
            BoolOption::No,
            "enabling clipboard states No rather than an unset flag"
        );
        assert!(enabled.next.clipboard_enabled());

        let disabled = enabled
            .next
            .prepare(SessionOptionChange::AudioEnabled(false), &context)
            .expect("audio can be withdrawn");
        assert_eq!(
            sent_option(&disabled).disable_audio.enum_value().unwrap(),
            BoolOption::Yes
        );
        assert!(!disabled.next.audio_enabled());

        let cursor = disabled
            .next
            .prepare(SessionOptionChange::ShowRemoteCursor(true), &context)
            .expect("the remote cursor is a real option");
        assert_eq!(
            sent_option(&cursor)
                .show_remote_cursor
                .enum_value()
                .unwrap(),
            BoolOption::Yes
        );
        assert!(cursor.next.show_remote_cursor());
    }

    #[test]
    fn switch_display_addresses_a_reported_display_and_repeats_its_resolution() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(2);
        let context = context("1.4.9", &advertised, &displays, 0);
        let switched = SessionOptions::default()
            .prepare(SessionOptionChange::SwitchDisplay(1), &context)
            .expect("the peer reported display 1");
        match sent_misc(&switched) {
            misc::Union::SwitchDisplay(display) => {
                assert_eq!(display.display, 1);
                assert_eq!(
                    (display.width, display.height),
                    (0, 0),
                    "no custom resolution was requested yet"
                );
            }
            other => panic!("switch_display built another message: {other:?}"),
        }
        assert_eq!(switched.next.display(), 1);
        assert_eq!(
            SessionOptions::default()
                .prepare(SessionOptionChange::SwitchDisplay(2), &context)
                .unwrap_err(),
            OptionError::UnknownDisplay(2)
        );

        let resized = switched
            .next
            .prepare(
                SessionOptionChange::ChangeResolution {
                    display: 1,
                    width: 1280,
                    height: 720,
                },
                &context,
            )
            .expect("1280x720 is a real size");
        let repeated = resized
            .next
            .prepare(SessionOptionChange::SwitchDisplay(1), &context)
            .expect("display 1 stays addressable");
        match sent_misc(&repeated) {
            misc::Union::SwitchDisplay(display) => {
                assert_eq!(
                    (display.width, display.height),
                    (1280, 720),
                    "the pinned client repeats the resolution it asked for"
                );
            }
            other => panic!("switch_display built another message: {other:?}"),
        }
    }

    #[test]
    fn resolution_change_follows_the_peer_version_it_was_given() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(2);

        let modern = context("1.4.9", &advertised, &displays, 0);
        let prepared = SessionOptions::default()
            .prepare(
                SessionOptionChange::ChangeResolution {
                    display: 1,
                    width: 1920,
                    height: 1080,
                },
                &modern,
            )
            .expect("a peer at or after 1.2.4 understands a display-qualified change");
        match sent_misc(&prepared) {
            misc::Union::ChangeDisplayResolution(change) => {
                assert_eq!(change.display, 1);
                let resolution = change.resolution.as_ref().expect("a resolution");
                assert_eq!((resolution.width, resolution.height), (1920, 1080));
            }
            other => panic!("resolution change built another message: {other:?}"),
        }
        assert_eq!(prepared.next.requested_resolution(1), Some((1920, 1080)));

        let legacy = context("1.2.3", &advertised, &displays, 1);
        let prepared = SessionOptions::default()
            .prepare(
                SessionOptionChange::ChangeResolution {
                    display: 1,
                    width: 1024,
                    height: 768,
                },
                &legacy,
            )
            .expect("display 1 is the one being shown");
        match sent_misc(&prepared) {
            misc::Union::ChangeResolution(resolution) => {
                assert_eq!((resolution.width, resolution.height), (1024, 768));
            }
            other => panic!("a legacy peer gets the unqualified message: {other:?}"),
        }
        assert_eq!(
            SessionOptions::default()
                .prepare(
                    SessionOptionChange::ChangeResolution {
                        display: 0,
                        width: 1024,
                        height: 768,
                    },
                    &legacy
                )
                .unwrap_err(),
            OptionError::DisplayNotAddressable(0),
            "a legacy peer cannot be asked about a display it is not showing"
        );

        let unknown = context("", &advertised, &displays, 0);
        assert_eq!(
            SessionOptions::default()
                .prepare(
                    SessionOptionChange::ChangeResolution {
                        display: 0,
                        width: 800,
                        height: 600,
                    },
                    &unknown
                )
                .unwrap_err(),
            OptionError::UnknownPeerVersion
        );
    }

    #[test]
    fn a_resolution_must_describe_a_display() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(1);
        let context = context("1.4.9", &advertised, &displays, 0);
        for (width, height) in [(0, 720), (1280, 0), (-1, 720)] {
            assert_eq!(
                SessionOptions::default()
                    .prepare(
                        SessionOptionChange::ChangeResolution {
                            display: 0,
                            width,
                            height,
                        },
                        &context
                    )
                    .unwrap_err(),
                OptionError::InvalidResolution { width, height }
            );
        }
    }

    #[test]
    fn another_wire_has_no_session_options() {
        let advertised = decoding(true, false, false, false);
        let displays = displays(1);
        for protocol in [Protocol::Vnc, Protocol::Rdp] {
            let context = OptionContext {
                protocol,
                peer_version: "1.4.9",
                advertised_decoding: &advertised,
                displays: &displays,
                current_display: 0,
            };
            assert_eq!(
                SessionOptions::default()
                    .prepare(SessionOptionChange::AudioEnabled(false), &context)
                    .unwrap_err(),
                OptionError::UnsupportedProtocol
            );
        }
    }

    #[test]
    fn a_prestart_request_refuses_what_it_could_never_send() {
        // The login advertisement carries the preset, preference and flags, so
        // they may be set before dialling.
        let prestart = SessionOptions::default()
            .request(SessionOptionChange::ImageQuality(ImageQuality::Balanced))
            .expect("a quality preset is in the login message")
            .request(SessionOptionChange::CodecPreference(PreferCodec::H264))
            .expect("a codec preference is in the login message")
            .request(SessionOptionChange::ClipboardEnabled(true))
            .expect("the clipboard flag is in the login message");
        assert_eq!(prestart.image_quality(), Some(ImageQuality::Balanced));
        assert_eq!(prestart.codec_preference(), PreferCodec::H264);
        assert!(prestart.clipboard_enabled());

        // A display switch and a resolution change are not in the login message
        // and this engine replays neither after login, so recording one would be
        // a request that could never reach the wire.
        assert_eq!(
            SessionOptions::default()
                .request(SessionOptionChange::SwitchDisplay(1))
                .unwrap_err(),
            OptionError::SessionNotStarted
        );
        assert_eq!(
            SessionOptions::default()
                .request(SessionOptionChange::ChangeResolution {
                    display: 0,
                    width: 1280,
                    height: 720,
                })
                .unwrap_err(),
            OptionError::SessionNotStarted
        );
    }
}
