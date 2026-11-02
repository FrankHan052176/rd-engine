//! The original RustDesk text/HTML/image clipboard's wire contract, and the
//! bounded per-viewer mailbox a platform clipboard owner takes from.
//!
//! The wire facts here are upstream's, not this module's invention. Encoding,
//! compression choice, the special-format vocabulary and the version/platform
//! rule for `MultiClipboards` restate RustDesk's own `src/clipboard.rs` at commit
//! `092a961b629d318fe290eeafac0cd214a1e9deeb` (`plain_to_proto`,
//! `image_to_proto`, `special_to_proto`, `create_multi_clipboards`,
//! `from_clipboard`, `get_msg_if_not_support_multi_clip`,
//! `is_support_multi_clipboard`, `valid_rgba_dimensions`).
//!
//! What this module deliberately does not take from upstream is the OS clipboard
//! itself: there is no `arboard` context, no clipboard listener thread and no
//! `ClipboardData`. A payload is a typed value and a mailbox holds it; the
//! platform's own clipboard owner — Resk's `RustDeskClipboardController` — stays
//! the only thing that reads or writes a pasteboard, keeps the read permission,
//! stages files and coalesces late writes. Nothing here spawns a thread, holds a
//! socket or reads an environment.
//!
//! Clearing is a real update: an empty `Text` clipboard is what the canonical
//! client applies when it receives `Clipboard::new()` (format `Text`, empty
//! content), so [`decode_clipboard`] answers `Some` with an empty text and never
//! `None`. A payload that cannot be interpreted is an error, never an empty
//! clipboard, and a compressed frame that inflates past its format's bound is
//! refused while it is being inflated rather than after (see
//! `decompress_within`).
//!
//! Decompression does not go through `hbb_common::compress::decompress`: that
//! helper is the same bounded reader with a fixed 256 MiB frame limit, so a
//! 1 KiB frame could inflate to 256 MiB before this module saw a byte and
//! refused it, and it leaves the window the frame header declares at zstd's own
//! default ceiling of 128 MiB. `decompress_within` is that reader with this
//! module's two bounds — output and back-reference window — which is why it
//! names `zstd` directly.

use base::message_proto::{self as proto, Clipboard, Message, MultiClipboards};
use hbb_common::compress::compress;
use std::{
    fmt,
    io::Read,
    sync::{Mutex, MutexGuard},
};

/// Bound for every text-like payload (text, RTF, HTML, special and SVG), measured
/// after decompression. Upstream has no such bound of its own (its shared
/// decompressor caps a frame at 256 MiB); this is the boundary one pasteboard
/// write can actually take on the phone that has to apply it. A real browser or
/// word-processor HTML fragment is orders of magnitude below it.
pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 4 << 20;

/// Bound for an encoded image (PNG or SVG) or for decoded RGBA pixels. It is the
/// same bound Resk's platform clipboard owner already enforces
/// (`MAX_CLIPBOARD_IMAGE_BYTES` in `RustDeskClipboardController.ets`), so a
/// payload this module accepts is one that owner can still build a `PixelMap`
/// from.
pub const MAX_CLIPBOARD_IMAGE_BYTES: usize = 64 << 20;

/// Largest RGBA width or height: the platform owner's own
/// `MAX_CLIPBOARD_IMAGE_DIMENSION`, which also keeps a 4096-pixel square
/// (4096 * 4096 * 4 = 64 MiB) inside [`MAX_CLIPBOARD_IMAGE_BYTES`].
pub const MAX_CLIPBOARD_IMAGE_DIMENSION: u32 = 16_384;

/// How many formats one `MultiClipboards` list may carry. A real clipboard
/// offers a handful (text, RTF, HTML, an image, a couple of special formats);
/// this only stops a peer from making the decoder walk an unbounded list.
pub const MAX_CLIPBOARD_ITEMS: usize = 16;

/// `MultiClipboards` arrived in 1.3.0 (upstream `is_support_multi_clipboard`).
pub const MULTI_CLIPBOARD_MIN_PEER_VERSION: &str = "1.3.0";

/// Android learned it in 1.3.3.
pub const MULTI_CLIPBOARD_MIN_ANDROID_VERSION: &str = "1.3.3";

/// Upstream's local ownership marker. It is a flag about which side wrote the
/// system clipboard, never content: upstream filters it out before encoding and
/// appends it only to what it writes locally, so it must not cross the wire and
/// must never be handed to a platform owner as pasteboard data.
const CLIPBOARD_OWNER_FORMAT: &str = "dyn.com.rustdesk.owner";

/// What a peer can be offered, derived from the peer's own reported version and
/// platform (upstream `is_support_multi_clipboard`).
///
/// Both values come from the authenticated `PeerInfo` the viewer already
/// publishes in its snapshot, so an encoder never guesses a capability from the
/// wire it is speaking or from this build's own features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerClipboardSupport {
    /// Whether a `MultiClipboards` message may be sent instead of one `Clipboard`.
    pub multi: bool,
}

impl PeerClipboardSupport {
    /// Classifies a peer from its reported version and platform.
    ///
    /// The comparison is upstream's: numeric version, no multi below 1.3.0, no
    /// multi for an empty platform or iOS, and Android only from 1.3.3. An
    /// unparsable version sorts as older than everything, exactly as
    /// `hbb_common::get_version_number` already treats it.
    pub fn of(version: &str, platform: &str) -> Self {
        let number = hbb_common::get_version_number(version);
        let multi = number >= hbb_common::get_version_number(MULTI_CLIPBOARD_MIN_PEER_VERSION)
            && !matches!(platform, "" | "iOS")
            && !(platform == "Android"
                && number < hbb_common::get_version_number(MULTI_CLIPBOARD_MIN_ANDROID_VERSION));
        Self { multi }
    }
}

/// The encoding of an image on the wire. The wire format id says which one this
/// is; nothing here decodes or re-encodes image data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardImageFormat {
    /// Raw RGBA pixels, with `width`/`height` beside them on the wire.
    Rgba,
    /// A PNG exactly as the sender encoded it.
    Png,
    /// An SVG document.
    Svg,
}

impl ClipboardImageFormat {
    /// The spelling the ArkTS clipboard owner compares against
    /// (`remoteImage.format === 'png'`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rgba => "rgba",
            Self::Png => "png",
            Self::Svg => "svg",
        }
    }
}

/// One image as it travels on the wire.
///
/// `bytes` is never reinterpreted: a PNG stays the encoded file the receiving
/// image SDK decodes, and only RGBA carries pixels this side could have drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardImage {
    pub format: ClipboardImageFormat,
    /// Encoded bytes for PNG/SVG, raw pixels for RGBA.
    pub bytes: Vec<u8>,
    /// RGBA only; `0` for PNG/SVG, whose own headers carry the size.
    pub width: u32,
    pub height: u32,
    /// RGBA only: always `width * 4`. The wire carries no row padding, so
    /// [`encode`] refuses a strided buffer instead of sending it misshapen.
    pub stride: u32,
}

impl ClipboardImage {
    /// The size-only view a platform owner needs before it asks for bytes.
    pub fn descriptor(&self) -> ClipboardImageDescriptor {
        ClipboardImageDescriptor {
            format: self.format,
            width: self.width,
            height: self.height,
            byte_length: self.bytes.len(),
        }
    }
}

/// An image's format and size without its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardImageDescriptor {
    pub format: ClipboardImageFormat,
    pub width: u32,
    pub height: u32,
    pub byte_length: usize,
}

/// One format's content, typed by the wire's own ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardFormatData {
    /// Plain text. An empty string is a clear, and it is a real update.
    Text(String),
    /// RTF, carried for fidelity; no HarmonyOS pasteboard record maps it today.
    Rtf(String),
    /// HTML.
    Html(String),
    Image(ClipboardImage),
    /// A named platform format, opaque to this module.
    Special {
        name: String,
        bytes: Vec<u8>,
    },
}

impl ClipboardFormatData {
    /// The format's own name, for a receipt or a test.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Rtf(_) => "rtf",
            Self::Html(_) => "html",
            Self::Image(image) => image.format.as_str(),
            Self::Special { .. } => "special",
        }
    }
}

/// What one side's clipboard currently holds, in wire terms.
///
/// It is a list because the original protocol carries a format set: a copy from
/// a browser offers Text and HTML together, and upstream reads and writes them
/// as one clipboard. Order is preserved on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClipboardPayload {
    items: Vec<ClipboardFormatData>,
}

impl ClipboardPayload {
    /// A payload of the formats one copy produced.
    pub fn from_items(items: Vec<ClipboardFormatData>) -> Self {
        Self { items }
    }

    /// Plain text. An empty string is the wire's clear.
    pub fn text(text: impl Into<String>) -> Self {
        Self::from_items(vec![ClipboardFormatData::Text(text.into())])
    }

    /// The clear the canonical client applies when it receives an empty `Text`
    /// clipboard.
    pub fn clear() -> Self {
        Self::text(String::new())
    }

    /// HTML along with the plain text that goes beside it.
    pub fn html(html: impl Into<String>, text: impl Into<String>) -> Self {
        Self::from_items(vec![
            ClipboardFormatData::Text(text.into()),
            ClipboardFormatData::Html(html.into()),
        ])
    }

    /// Encoded PNG bytes, handed on exactly as they came from the platform's
    /// encoder.
    pub fn png(bytes: Vec<u8>) -> Self {
        Self::from_items(vec![ClipboardFormatData::Image(ClipboardImage {
            format: ClipboardImageFormat::Png,
            bytes,
            width: 0,
            height: 0,
            stride: 0,
        })])
    }

    /// Raw RGBA pixels and the shape they claim. `stride` is checked by
    /// [`encode`], which refuses the padding this wire cannot carry.
    pub fn rgba(width: u32, height: u32, stride: u32, bytes: Vec<u8>) -> Self {
        Self::from_items(vec![ClipboardFormatData::Image(ClipboardImage {
            format: ClipboardImageFormat::Rgba,
            bytes,
            width,
            height,
            stride,
        })])
    }

    /// An SVG document.
    pub fn svg(svg: impl Into<String>) -> Self {
        Self::from_items(vec![ClipboardFormatData::Image(ClipboardImage {
            format: ClipboardImageFormat::Svg,
            bytes: svg.into().into_bytes(),
            width: 0,
            height: 0,
            stride: 0,
        })])
    }

    /// The formats this payload carries, in wire order.
    pub fn items(&self) -> &[ClipboardFormatData] {
        &self.items
    }

    /// Whether nothing at all is carried. Such a payload is refused by
    /// [`encode`]: an empty format list is not the same thing as a clear.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn text_content(&self) -> Option<&str> {
        self.items.iter().find_map(|item| match item {
            ClipboardFormatData::Text(text) => Some(text.as_str()),
            _ => None,
        })
    }

    fn html_content(&self) -> Option<&str> {
        self.items.iter().find_map(|item| match item {
            ClipboardFormatData::Html(html) => Some(html.as_str()),
            _ => None,
        })
    }

    fn image(&self) -> Option<&ClipboardImage> {
        self.items.iter().find_map(|item| match item {
            ClipboardFormatData::Image(image) => Some(image),
            _ => None,
        })
    }
}

/// Why this module refused or could not interpret a clipboard message.
///
/// Every variant is a local diagnosis built from local constants and this
/// message's own sizes: no peer text and no I/O diagnostics. A refusal and an
/// unreadable message are different answers, and neither is an empty clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    /// A payload — or its decompressed form — is over the format's own bound.
    TooLarge {
        format: &'static str,
        limit: usize,
        actual: usize,
    },
    /// A compressed frame that inflates past its format's bound.
    ///
    /// Kept apart from [`Self::TooLarge`] because that one measures what
    /// arrived: this one is refused while it is being inflated, so the size it
    /// would have reached is unknown and none is claimed.
    InflatedTooLarge { format: &'static str, limit: usize },
    /// A real format whose bytes cannot be interpreted as that format.
    Corrupt { format: &'static str },
    /// An image whose dimensions, stride or bytes do not describe each other.
    InvalidImage { reason: &'static str },
    /// Delivery is not accepted right now: the peer withdrew the clipboard
    /// permission, the operator did, or the session is closing.
    NotAccepted,
    /// A decoded message arrived under a permission generation this viewer has
    /// already left. It is dropped rather than applied to the new generation.
    StaleGeneration,
    /// This peer is owed nothing for this payload, so nothing was sent.
    ///
    /// Upstream's `get_msg_if_not_support_multi_clip` sends nothing at all when
    /// a peer without `MultiClipboards` is handed a payload that carries no
    /// text — an image-only copy is not deliverable to a 1.2.x peer. That is
    /// neither a queued send nor a broken message, and it is stated as its own
    /// refusal rather than being reported as one.
    NotDeliverable,
    /// A payload this module will not put on the wire at all.
    Refused { reason: &'static str },
}

impl fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                format,
                limit,
                actual,
            } => write!(
                f,
                "clipboard {format} payload is {actual} bytes, over the {limit}-byte bound"
            ),
            Self::Corrupt { format } => write!(f, "clipboard {format} payload cannot be decoded"),
            Self::InflatedTooLarge { format, limit } => write!(
                f,
                "clipboard {format} payload exceeds its {limit}-byte bound while decompressing"
            ),
            Self::InvalidImage { reason } => write!(f, "clipboard image is invalid: {reason}"),
            Self::NotAccepted => write!(f, "clipboard delivery is not accepted"),
            Self::StaleGeneration => {
                write!(
                    f,
                    "clipboard update belongs to a generation this viewer has left"
                )
            }
            Self::NotDeliverable => write!(
                f,
                "this peer accepts no format this payload carries, so nothing was sent"
            ),
            Self::Refused { reason } => write!(f, "clipboard payload refused: {reason}"),
        }
    }
}

impl std::error::Error for ClipboardError {}

/// One clipboard update as a mailbox hands it out: the permission generation it
/// was accepted under and the content that arrived with it.
///
/// The two travel together in one value on purpose. A caller never reads a
/// revision from one place and bytes from another, so the metadata it shows and
/// the bytes it applies are guaranteed to be from the same accepted update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardUpdate {
    pub revision: u64,
    pub payload: ClipboardPayload,
}

/// What a platform clipboard owner needs to apply an update, without its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardMetadata {
    /// The generation this update was accepted under.
    pub revision: u64,
    /// Present when the update carried text; `Some("")` is a clear.
    pub text: Option<String>,
    pub html: Option<String>,
    pub image: Option<ClipboardImageDescriptor>,
    /// Every format the update carried, so a format with no pasteboard mapping
    /// (RTF, a special format) is reported instead of vanishing silently.
    pub formats: Vec<&'static str>,
}

/// Encodes one payload for one peer.
///
/// `Ok(None)` means this peer is owed nothing for this payload: an older peer
/// without `MultiClipboards` can only be sent a `Text` clipboard, and upstream's
/// `get_msg_if_not_support_multi_clip` sends nothing at all when the payload has
/// no text — an image-only copy is simply not deliverable to 1.2.x. That is not
/// an error here, and it is never replaced by a private image encoding.
///
/// The payload is taken by value so a large image is encoded into the message
/// instead of being copied into it.
pub fn encode(
    payload: ClipboardPayload,
    peer: PeerClipboardSupport,
) -> Result<Option<Message>, ClipboardError> {
    if payload.items.is_empty() {
        return Err(ClipboardError::Refused {
            reason: "a payload with no formats is not a clipboard update",
        });
    }
    if payload.items.len() > MAX_CLIPBOARD_ITEMS {
        return Err(ClipboardError::TooLarge {
            format: "multi-clipboards",
            limit: MAX_CLIPBOARD_ITEMS,
            actual: payload.items.len(),
        });
    }
    // The index of the text format, taken before the items are consumed: it is
    // the one format a peer without MultiClipboards can still receive.
    let text = payload
        .items
        .iter()
        .position(|item| matches!(item, ClipboardFormatData::Text(_)));
    let mut clipboards = payload
        .items
        .into_iter()
        .map(encode_item)
        .collect::<Result<Vec<_>, _>>()?;
    let mut message = Message::new();
    if peer.multi {
        message.set_multi_clipboards(MultiClipboards {
            clipboards: clipboards.into_iter().collect(),
            ..Default::default()
        });
        return Ok(Some(message));
    }
    match text {
        Some(index) => {
            message.set_clipboard(clipboards.swap_remove(index));
            Ok(Some(message))
        }
        None => Ok(None),
    }
}

/// Decodes one `Clipboard` message (the single-format arm of the wire).
///
/// `Ok(None)` means this client has nothing to apply: the message names a format
/// this build does not know (a newer peer's id), or it is the local ownership
/// marker. `Err` means the message named a format this module does know and its
/// content is not that format — an unreadable message is never reported as an
/// empty clipboard.
pub fn decode_clipboard(clipboard: Clipboard) -> Result<Option<ClipboardPayload>, ClipboardError> {
    match decode_item(clipboard)? {
        Some(item) => Ok(Some(ClipboardPayload::from_items(vec![item]))),
        None => Ok(None),
    }
}

/// Decodes one `MultiClipboards` message, preserving the wire's format order.
pub fn decode_multi_clipboards(
    multi: MultiClipboards,
) -> Result<Option<ClipboardPayload>, ClipboardError> {
    if multi.clipboards.len() > MAX_CLIPBOARD_ITEMS {
        return Err(ClipboardError::TooLarge {
            format: "multi-clipboards",
            limit: MAX_CLIPBOARD_ITEMS,
            actual: multi.clipboards.len(),
        });
    }
    let mut items = Vec::with_capacity(multi.clipboards.len());
    for clipboard in multi.clipboards {
        if let Some(item) = decode_item(clipboard)? {
            items.push(item);
        }
    }
    if items.is_empty() {
        return Ok(None);
    }
    Ok(Some(ClipboardPayload::from_items(items)))
}

fn encode_item(item: ClipboardFormatData) -> Result<Clipboard, ClipboardError> {
    match item {
        ClipboardFormatData::Text(text) => {
            encode_text_like(&text, proto::ClipboardFormat::Text, "text")
        }
        ClipboardFormatData::Rtf(rtf) => encode_text_like(&rtf, proto::ClipboardFormat::Rtf, "rtf"),
        ClipboardFormatData::Html(html) => {
            encode_text_like(&html, proto::ClipboardFormat::Html, "html")
        }
        ClipboardFormatData::Image(image) => encode_image(image),
        ClipboardFormatData::Special { name, bytes } => {
            if name == CLIPBOARD_OWNER_FORMAT {
                return Err(ClipboardError::Refused {
                    reason: "the clipboard ownership marker is local state, not content",
                });
            }
            check_size("special", bytes.len(), MAX_CLIPBOARD_TEXT_BYTES)?;
            let mut clipboard = plain_clipboard(&bytes, proto::ClipboardFormat::Special);
            clipboard.special_name = name;
            Ok(clipboard)
        }
    }
}

fn encode_text_like(
    text: &str,
    format: proto::ClipboardFormat,
    name: &'static str,
) -> Result<Clipboard, ClipboardError> {
    check_size(name, text.len(), MAX_CLIPBOARD_TEXT_BYTES)?;
    Ok(plain_clipboard(text.as_bytes(), format))
}

fn encode_image(image: ClipboardImage) -> Result<Clipboard, ClipboardError> {
    let actual = image.bytes.len();
    check_size("image", actual, MAX_CLIPBOARD_IMAGE_BYTES)?;
    if actual == 0 {
        return Err(ClipboardError::InvalidImage {
            reason: "an image clipboard carries no bytes",
        });
    }
    match image.format {
        ClipboardImageFormat::Rgba => {
            let (width, height) = rgba_shape(image.width, image.height, actual)?;
            if image.stride != width * 4 {
                return Err(ClipboardError::InvalidImage {
                    reason: "RGBA stride must be width * 4; this wire carries no row padding",
                });
            }
            // Upstream compresses RGBA pixels exactly as it compresses text.
            let raw = image.bytes;
            let compressed = compress(&raw);
            let (compress_flag, content) = if !compressed.is_empty() && compressed.len() < raw.len()
            {
                (true, compressed)
            } else {
                (false, raw)
            };
            Ok(Clipboard {
                compress: compress_flag,
                content: content.into(),
                width: width as i32,
                height: height as i32,
                format: proto::ClipboardFormat::ImageRgba.into(),
                ..Default::default()
            })
        }
        // Upstream never recompresses an encoded PNG: the flag stays false and
        // the file travels as it was packed.
        ClipboardImageFormat::Png => Ok(Clipboard {
            compress: false,
            content: image.bytes.into(),
            format: proto::ClipboardFormat::ImagePng.into(),
            ..Default::default()
        }),
        ClipboardImageFormat::Svg => {
            std::str::from_utf8(&image.bytes).map_err(|_| ClipboardError::InvalidImage {
                reason: "an SVG clipboard is not UTF-8 text",
            })?;
            Ok(plain_clipboard(
                &image.bytes,
                proto::ClipboardFormat::ImageSvg,
            ))
        }
    }
}

/// Upstream `plain_to_proto`: compress only when the frame is strictly smaller
/// than the content, and say so on the wire.
fn plain_clipboard(raw: &[u8], format: proto::ClipboardFormat) -> Clipboard {
    let compressed = compress(raw);
    // `hbb_common::compress::compress` reports its own failure as an empty `Vec`.
    // Upstream's `compressed.len() < raw.len()` would then claim `compress: true`
    // with no content; an empty frame is treated as "not compressed" here.
    let (compress_flag, content) = if !compressed.is_empty() && compressed.len() < raw.len() {
        (true, compressed)
    } else {
        (false, raw.to_vec())
    };
    Clipboard {
        compress: compress_flag,
        content: content.into(),
        format: format.into(),
        ..Default::default()
    }
}

fn decode_item(clipboard: Clipboard) -> Result<Option<ClipboardFormatData>, ClipboardError> {
    let Clipboard {
        compress: compressed,
        content,
        width,
        height,
        format,
        special_name,
        ..
    } = clipboard;
    let Ok(format) = format.enum_value() else {
        // An id this build does not know is a newer peer's format, not a broken
        // message: upstream drops it with `filter_map` and so does this.
        return Ok(None);
    };
    let name = format_name(format);
    let bytes = decode_content(compressed, content, name, limit_for(format))?;
    match format {
        proto::ClipboardFormat::Text => Ok(Some(ClipboardFormatData::Text(utf8(&bytes, name)?))),
        proto::ClipboardFormat::Rtf => Ok(Some(ClipboardFormatData::Rtf(utf8(&bytes, name)?))),
        proto::ClipboardFormat::Html => Ok(Some(ClipboardFormatData::Html(utf8(&bytes, name)?))),
        proto::ClipboardFormat::ImageRgba => {
            let (width, height) = rgba_shape(
                positive_dimension(width)?,
                positive_dimension(height)?,
                bytes.len(),
            )?;
            Ok(Some(ClipboardFormatData::Image(ClipboardImage {
                format: ClipboardImageFormat::Rgba,
                bytes,
                width,
                height,
                stride: width * 4,
            })))
        }
        proto::ClipboardFormat::ImagePng => Ok(Some(ClipboardFormatData::Image(ClipboardImage {
            format: ClipboardImageFormat::Png,
            bytes,
            width: 0,
            height: 0,
            stride: 0,
        }))),
        proto::ClipboardFormat::ImageSvg => {
            std::str::from_utf8(&bytes).map_err(|_| ClipboardError::Corrupt { format: name })?;
            Ok(Some(ClipboardFormatData::Image(ClipboardImage {
                format: ClipboardImageFormat::Svg,
                bytes,
                width: 0,
                height: 0,
                stride: 0,
            })))
        }
        proto::ClipboardFormat::Special => {
            if special_name == CLIPBOARD_OWNER_FORMAT {
                // Upstream's own marker: a statement about which side wrote the
                // system clipboard, never pasteboard content.
                return Ok(None);
            }
            Ok(Some(ClipboardFormatData::Special {
                name: special_name,
                bytes,
            }))
        }
    }
}

/// The content bytes of one wire clipboard, decompressed when it says so.
///
/// The bound is applied to what arrived *before* any zstd work and, by
/// [`decompress_within`], twice more while the frame is inflated — once to its
/// output and once to the window it declares — so an oversized message costs no
/// decompression at all, and a frame that inflates past the bound is stopped
/// there instead of after it has grown.
fn decode_content(
    compressed: bool,
    content: bytes::Bytes,
    name: &'static str,
    limit: usize,
) -> Result<Vec<u8>, ClipboardError> {
    check_size(name, content.len(), limit)?;
    if !compressed {
        return Ok(content.to_vec());
    }
    let decoded = decompress_within(&content, limit).map_err(|error| match error {
        InflateError::Corrupt => ClipboardError::Corrupt { format: name },
        InflateError::TooLarge => ClipboardError::InflatedTooLarge {
            format: name,
            limit,
        },
    })?;
    if decoded.is_empty() {
        // Upstream sets the flag only for a frame that is strictly smaller than
        // real, non-empty content, so a compressed frame that inflates to
        // nothing breaks that contract: it is never the clear an empty text is.
        return Err(ClipboardError::Corrupt { format: name });
    }
    Ok(decoded)
}

/// Why one compressed frame was not inflated.
///
/// The two are kept apart because a caller acts on them differently — a broken
/// frame is a peer sending nonsense, an oversized one is a peer sending more
/// than this module takes — and because neither may be reported as the other.
enum InflateError {
    Corrupt,
    TooLarge,
}

/// Decompresses one zstd frame inside two bounds: how long its output may get
/// and how far back inside itself it may refer.
///
/// This is the shape of the vendored `hbb_common::compress::decompress_with_limit`
/// — the library's own `zstd::Decoder` behind `Read::take` — applied with this
/// module's bounds instead of the shared 256 MiB one. `Read::take` only bounds
/// the bytes handed back: the window a frame header declares is allocated by the
/// decoder before any output exists, and zstd's own default ceiling for it is
/// 2^27 = 128 MiB. So both are bounded here, and the window bound is a
/// precondition rather than a best effort. Nothing here parses a frame of its
/// own: the zstd library still reads the header and enforces both bounds while
/// inflating.
fn decompress_within(data: &[u8], limit: usize) -> Result<Vec<u8>, InflateError> {
    let mut decoder = zstd::Decoder::new(data).map_err(|_| InflateError::Corrupt)?;
    decoder
        .window_log_max(window_log_within(limit))
        // Not a best effort: a decoder that could not be capped is not used at
        // all, and the frame is refused rather than read under zstd's own
        // 128 MiB default ceiling.
        .map_err(|_| InflateError::Corrupt)?;
    let mut output = Vec::new();
    decoder
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| InflateError::Corrupt)?;
    if output.len() > limit {
        return Err(InflateError::TooLarge);
    }
    Ok(output)
}

/// The largest back-reference window, as a log2, that a frame this module accepts
/// can legitimately declare.
///
/// Every frame handed to [`decompress_within`] was produced by the vendored
/// `hbb_common::compress::compress`, which compresses with a *pledged* source
/// size. zstd then either writes single-segment, where the frame's window is
/// exactly its content size, or a window smaller than that content, so such a
/// frame never refers back further than the content it expands to. An accepted
/// frame expands to at most `limit` bytes (a longer one is stopped by
/// `Read::take`), which makes the smallest power of two that holds `limit` the
/// whole window it can need. A frame declaring more is refused: since its
/// content is within `limit`, exceeding this declaration means asking for a
/// window bigger than the entire payload, which is exactly the allocation this
/// bound exists to stop.
fn window_log_within(limit: usize) -> u32 {
    // ceil(log2(limit)): a frame that expands to `limit` bytes needs at most the
    // power of two that holds them.
    usize::BITS - limit.saturating_sub(1).leading_zeros()
}

fn limit_for(format: proto::ClipboardFormat) -> usize {
    match format {
        proto::ClipboardFormat::ImageRgba
        | proto::ClipboardFormat::ImagePng
        | proto::ClipboardFormat::ImageSvg => MAX_CLIPBOARD_IMAGE_BYTES,
        _ => MAX_CLIPBOARD_TEXT_BYTES,
    }
}

fn format_name(format: proto::ClipboardFormat) -> &'static str {
    match format {
        proto::ClipboardFormat::Text => "text",
        proto::ClipboardFormat::Rtf => "rtf",
        proto::ClipboardFormat::Html => "html",
        proto::ClipboardFormat::ImageRgba => "rgba",
        proto::ClipboardFormat::ImagePng => "png",
        proto::ClipboardFormat::ImageSvg => "svg",
        proto::ClipboardFormat::Special => "special",
    }
}

fn check_size(format: &'static str, actual: usize, limit: usize) -> Result<(), ClipboardError> {
    if actual > limit {
        return Err(ClipboardError::TooLarge {
            format,
            limit,
            actual,
        });
    }
    Ok(())
}

fn utf8(bytes: &[u8], format: &'static str) -> Result<String, ClipboardError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| ClipboardError::Corrupt { format })
}

fn positive_dimension(value: i32) -> Result<u32, ClipboardError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ClipboardError::InvalidImage {
            reason: "RGBA dimensions must be positive",
        })
}

/// Upstream `valid_rgba_dimensions`, with this module's two bounds added: a
/// dimension fits inside [`MAX_CLIPBOARD_IMAGE_DIMENSION`], and the pixels it
/// describes fit inside [`MAX_CLIPBOARD_IMAGE_BYTES`].
fn rgba_shape(width: u32, height: u32, len: usize) -> Result<(u32, u32), ClipboardError> {
    if width == 0
        || height == 0
        || width > MAX_CLIPBOARD_IMAGE_DIMENSION
        || height > MAX_CLIPBOARD_IMAGE_DIMENSION
    {
        return Err(ClipboardError::InvalidImage {
            reason: "RGBA dimensions are outside the display bound",
        });
    }
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(ClipboardError::InvalidImage {
            reason: "RGBA dimensions overflow the pixel count",
        })?;
    if expected != len {
        return Err(ClipboardError::InvalidImage {
            reason: "RGBA content length is not width * height * 4",
        });
    }
    Ok((width, height))
}

struct Mailbox {
    /// Advances on every acceptance change and on every revocation. A decode
    /// that captured the previous value can never enter the mailbox again.
    revision: u64,
    accepted: bool,
    /// Newest-only: a newer update replaces the one that has not been taken, and
    /// nothing ever waits for space. A clipboard is a value, not a queue, so the
    /// bound is what keeps a slow consumer from growing it.
    latest: Option<ClipboardUpdate>,
    /// The update an already-handed-out descriptor described, kept only for the
    /// image bytes the caller has not asked for yet. A newer accepted update
    /// never rewrites it (the descriptor the caller holds still names it);
    /// `revoke` and `set_accepted` drop it.
    reserved: Option<ClipboardUpdate>,
}

/// One viewer's clipboard mailbox: the only place a decoded peer update waits,
/// and the permission fence it waits behind.
///
/// It is per viewer and owned by that viewer's session state. Nothing here holds
/// a socket, a runtime or a spawned task, so a decode can run on the session's
/// own bounded blocking worker and this is what decides whether its result is
/// still wanted when it returns.
pub struct ClipboardState {
    inner: Mutex<Mailbox>,
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self::new()
    }
}

impl ClipboardState {
    /// A mailbox that accepts updates until something withdraws acceptance.
    ///
    /// Upstream's viewer treats an omitted remote clipboard permission as
    /// allowed (`VIEWER_REMOTE_DEFAULTS`), so the fence starts open and at
    /// generation 1 rather than 0: a caller always has a real generation to name.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Mailbox {
                revision: 1,
                accepted: true,
                latest: None,
                reserved: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Mailbox> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The generation a decode must name to enter this mailbox, and the one every
    /// hand-out is stamped with.
    pub fn revision(&self) -> u64 {
        self.lock().revision
    }

    /// Whether an accepted peer update may enter the mailbox right now.
    pub fn is_accepted(&self) -> bool {
        self.lock().accepted
    }

    /// Whether an accepted peer update is waiting to be taken.
    ///
    /// This is the one question a notifier may ask, and it is a read of the
    /// mailbox rather than a hand-out: an update this answers `true` for is
    /// still there for the platform owner that takes it next. It stops answering
    /// `true` when [`Self::take`] or [`Self::take_metadata`] hands the update
    /// out, and also when [`Self::set_accepted`] or [`Self::revoke`] empties the
    /// mailbox, so a notifier built on it never claims content that is gone.
    pub fn has_pending(&self) -> bool {
        self.lock().latest.is_some()
    }

    /// Whether a payload queued under `generation` may still be written.
    ///
    /// This is the writer's own question, answered by one read under one lock:
    /// delivery is still accepted *and* the generation that admitted the write
    /// is still the one in force. A payload queued before a withdrawal, a close
    /// or a fresh grant can therefore never be written after it — and asking
    /// both facts together is what stops a change from landing between a
    /// permission check and a separate generation read.
    pub fn admits(&self, generation: u64) -> bool {
        let mailbox = self.lock();
        mailbox.accepted && mailbox.revision == generation
    }

    /// Publishes whether clipboard delivery is accepted, and returns the
    /// generation in force afterwards.
    ///
    /// The caller drives this from the facts that decide it — the peer's
    /// `Permission::Clipboard` report, the operator's read-only switch, a
    /// locally disabled clipboard — and the transition, in either direction,
    /// advances the fence and drops whatever was still waiting: a withdrawal
    /// empties the mailbox and invalidates late decodes, and a fresh grant never
    /// inherits the previous one's content. A repeated value changes nothing, so
    /// a peer that re-sends its permission does not refuse a decode in flight.
    pub fn set_accepted(&self, accepted: bool) -> u64 {
        let mut mailbox = self.lock();
        if mailbox.accepted == accepted {
            return mailbox.revision;
        }
        mailbox.accepted = accepted;
        mailbox.latest = None;
        mailbox.reserved = None;
        mailbox.revision = mailbox.revision.saturating_add(1);
        mailbox.revision
    }

    /// Withdraws acceptance for this session: the peer revoked the clipboard
    /// permission, the operator did, or the session is closing.
    ///
    /// Unlike [`Self::set_accepted`], this always moves the fence and empties the
    /// mailbox, so a close that follows a withdrawal is still a boundary of its
    /// own: a decode that started before it cannot deliver into it.
    pub fn revoke(&self) -> u64 {
        let mut mailbox = self.lock();
        mailbox.accepted = false;
        mailbox.latest = None;
        mailbox.reserved = None;
        mailbox.revision = mailbox.revision.saturating_add(1);
        mailbox.revision
    }

    /// Offers one decoded peer update, stamped with the generation it arrived
    /// under.
    ///
    /// `generation` is the value [`Self::revision`] answered *before* the decode
    /// ran. A decode that outlived a withdrawal or a close names a generation
    /// this mailbox has left and is refused instead of being applied to the
    /// current one.
    pub fn accept_peer(
        &self,
        generation: u64,
        payload: ClipboardPayload,
    ) -> Result<(), ClipboardError> {
        let mut mailbox = self.lock();
        if !mailbox.accepted {
            return Err(ClipboardError::NotAccepted);
        }
        if generation != mailbox.revision {
            return Err(ClipboardError::StaleGeneration);
        }
        mailbox.latest = Some(ClipboardUpdate {
            revision: mailbox.revision,
            payload,
        });
        Ok(())
    }

    /// Takes the newest update with its bytes, as one value.
    ///
    /// This is the whole snapshot: the revision and the content are read under
    /// one lock, so a caller that keeps metadata beside bytes cannot end up with
    /// them from different updates.
    pub fn take(&self) -> Option<ClipboardUpdate> {
        self.lock().latest.take()
    }

    /// Takes the newest update's metadata and reserves its image, if it had one,
    /// for [`Self::take_image`].
    ///
    /// This is the shape a platform owner that receives metadata and bytes
    /// through two separate calls uses. The reservation is the accepted update
    /// itself, so the descriptor handed out here and the bytes handed out next
    /// are guaranteed to come from the same message.
    pub fn take_metadata(&self) -> Option<ClipboardMetadata> {
        let mut mailbox = self.lock();
        let update = mailbox.latest.take()?;
        let metadata = ClipboardMetadata {
            revision: update.revision,
            text: update.payload.text_content().map(str::to_owned),
            html: update.payload.html_content().map(str::to_owned),
            image: update.payload.image().map(ClipboardImage::descriptor),
            formats: update
                .payload
                .items()
                .iter()
                .map(ClipboardFormatData::name)
                .collect(),
        };
        if metadata.image.is_some() {
            mailbox.reserved = Some(update);
        }
        Some(metadata)
    }

    /// Hands out the image reserved by [`Self::take_metadata`].
    ///
    /// The reservation *is* the fence, so no token is needed: it holds the
    /// accepted update the descriptor described, and only `revoke`,
    /// `set_accepted` or another metadata hand-out can take it away. A
    /// withdrawal or a close between the two calls therefore drops it, and the
    /// bytes are withheld rather than written to a pasteboard after the
    /// permission that allowed them is gone. The descriptor's
    /// [`ClipboardMetadata::revision`] is still published for a caller that wants
    /// to check which generation it is applying.
    pub fn take_image(&self) -> Option<ClipboardImage> {
        let mut mailbox = self.lock();
        let image = mailbox.reserved.as_ref()?.payload.image()?.clone();
        mailbox.reserved = None;
        Some(image)
    }
}

impl fmt::Debug for ClipboardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mailbox = self.lock();
        f.debug_struct("ClipboardState")
            .field("revision", &mailbox.revision)
            .field("accepted", &mailbox.accepted)
            .field("pending", &mailbox.latest.is_some())
            .field("reserved", &mailbox.reserved.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn message(payload: ClipboardPayload, peer: PeerClipboardSupport) -> Message {
        encode(payload, peer)
            .expect("the payload is encodable")
            .expect("this peer is owed a message")
    }

    fn single(message: Message) -> Clipboard {
        match message.union {
            Some(proto::message::Union::Clipboard(clipboard)) => clipboard,
            Some(proto::message::Union::MultiClipboards(mut clipboards)) => {
                assert_eq!(clipboards.clipboards.len(), 1);
                clipboards.clipboards.remove(0)
            }
            other => panic!("expected one clipboard, got {other:?}"),
        }
    }

    fn wire(compress: bool, content: Vec<u8>, format: proto::ClipboardFormat) -> Clipboard {
        Clipboard {
            compress,
            content: content.into(),
            format: format.into(),
            ..Default::default()
        }
    }

    #[test]
    fn text_keeps_the_wire_compression_choice_and_round_trips() {
        let plain = single(message(
            ClipboardPayload::text("hello"),
            PeerClipboardSupport { multi: false },
        ));
        assert!(
            !plain.compress,
            "a frame that saves nothing is not compressed"
        );
        assert_eq!(plain.content.as_ref(), b"hello".as_slice());
        assert_eq!(plain.format.enum_value(), Ok(proto::ClipboardFormat::Text));

        let repeated = "a".repeat(4096);
        let compressed = single(message(
            ClipboardPayload::text(repeated.clone()),
            PeerClipboardSupport { multi: false },
        ));
        assert!(compressed.compress);
        assert!(compressed.content.len() < repeated.len());
        assert_eq!(
            decode_clipboard(compressed).unwrap(),
            Some(ClipboardPayload::text(repeated))
        );
    }

    #[test]
    fn an_empty_text_is_a_real_clear_and_not_an_empty_result() {
        let clear = single(message(
            ClipboardPayload::clear(),
            PeerClipboardSupport { multi: true },
        ));
        assert_eq!(clear.format.enum_value(), Ok(proto::ClipboardFormat::Text));
        assert!(!clear.compress);
        assert!(clear.content.is_empty());
        // The canonical client applies exactly this message as a cleared
        // clipboard, so it has to decode to a payload and never to `None`.
        assert_eq!(
            decode_clipboard(clear).unwrap(),
            Some(ClipboardPayload::clear())
        );
    }

    #[test]
    fn a_corrupt_compressed_payload_is_an_error_rather_than_a_clear() {
        let corrupt = wire(true, vec![0x00, 0x01, 0x02], proto::ClipboardFormat::Text);
        assert_eq!(
            decode_clipboard(corrupt),
            Err(ClipboardError::Corrupt { format: "text" })
        );
    }

    #[test]
    fn an_oversized_payload_is_refused_before_it_is_decompressed() {
        let plain = wire(
            false,
            vec![0u8; MAX_CLIPBOARD_TEXT_BYTES + 1],
            proto::ClipboardFormat::Text,
        );
        assert!(matches!(
            decode_clipboard(plain),
            Err(ClipboardError::TooLarge { format: "text", .. })
        ));
        // A compressed frame that is itself over the bound is refused without
        // inflating it.
        let frame = wire(
            true,
            vec![0u8; MAX_CLIPBOARD_TEXT_BYTES + 1],
            proto::ClipboardFormat::Html,
        );
        assert!(matches!(
            decode_clipboard(frame),
            Err(ClipboardError::TooLarge { format: "html", .. })
        ));
        // A real copy over the bound is refused on the way out as well.
        assert!(matches!(
            encode(
                ClipboardPayload::text("a".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1)),
                PeerClipboardSupport { multi: true }
            ),
            Err(ClipboardError::TooLarge { format: "text", .. })
        ));
    }

    #[test]
    fn rgba_dimensions_and_stride_describe_its_own_bytes() {
        let pixels = vec![7u8; 64 * 64 * 4];
        let payload = ClipboardPayload::rgba(64, 64, 256, pixels.clone());
        let encoded = single(message(
            payload.clone(),
            PeerClipboardSupport { multi: true },
        ));
        assert_eq!((encoded.width, encoded.height), (64, 64));
        assert!(
            encoded.compress,
            "RGBA pixels are zstd-compressed on the wire"
        );
        assert_eq!(decode_clipboard(encoded).unwrap(), Some(payload));

        // Four pixels claimed, three carried.
        let mut mismatched = wire(false, vec![0u8; 3], proto::ClipboardFormat::ImageRgba);
        mismatched.width = 2;
        mismatched.height = 2;
        assert!(matches!(
            decode_clipboard(mismatched),
            Err(ClipboardError::InvalidImage { .. })
        ));

        // A padded row buffer cannot be put on this wire at all: the format has
        // no stride field, so sending it would describe the wrong rows.
        assert!(matches!(
            encode(
                ClipboardPayload::rgba(2, 2, 12, vec![0u8; 24]),
                PeerClipboardSupport { multi: true }
            ),
            Err(ClipboardError::InvalidImage { .. })
        ));
        // Neither can a dimension past the platform owner's own bound.
        assert!(matches!(
            encode(
                ClipboardPayload::rgba(20_000, 1, 80_000, vec![0u8; 80_000]),
                PeerClipboardSupport { multi: true }
            ),
            Err(ClipboardError::InvalidImage { .. })
        ));
    }

    #[test]
    fn png_bytes_travel_encoded_and_never_stand_in_for_decoded_pixels() {
        let png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3];
        let encoded = single(message(
            ClipboardPayload::png(png.clone()),
            PeerClipboardSupport { multi: true },
        ));
        assert!(
            !encoded.compress,
            "upstream never recompresses an encoded PNG"
        );
        assert_eq!(encoded.content.as_ref(), png.as_slice());
        assert_eq!(
            encoded.format.enum_value(),
            Ok(proto::ClipboardFormat::ImagePng)
        );
        let decoded = decode_clipboard(encoded)
            .unwrap()
            .expect("a PNG clipboard decodes to a payload");
        let image = decoded.image().expect("the decoded image");
        assert_eq!(image.format, ClipboardImageFormat::Png);
        // Still encoded: the receiving image SDK decodes it. This module never
        // pretends to have parsed pixels it has not parsed.
        assert_eq!(image.bytes, png);
        assert_eq!((image.width, image.height), (0, 0));
        assert_eq!(image.descriptor().byte_length, png.len());
    }

    #[test]
    fn multi_clipboards_follow_the_peers_own_version_and_platform_rule() {
        assert!(PeerClipboardSupport::of("1.3.0", "Linux").multi);
        assert!(PeerClipboardSupport::of("1.4.9", "Windows").multi);
        assert!(!PeerClipboardSupport::of("1.2.9", "Windows").multi);
        assert!(!PeerClipboardSupport::of("1.4.0", "iOS").multi);
        assert!(!PeerClipboardSupport::of("1.4.0", "").multi);
        assert!(!PeerClipboardSupport::of("1.3.2", "Android").multi);
        assert!(PeerClipboardSupport::of("1.3.3", "Android").multi);
        // An unparsable version sorts as older than everything, which is what
        // `hbb_common::get_version_number` already makes of it.
        assert!(!PeerClipboardSupport::of("", "Windows").multi);
    }

    #[test]
    fn an_older_peer_receives_only_the_first_text_and_nothing_else() {
        let payload = ClipboardPayload::from_items(vec![
            ClipboardFormatData::Html("<b>hi</b>".to_owned()),
            ClipboardFormatData::Text("hi".to_owned()),
        ]);
        let encoded = single(message(
            payload.clone(),
            PeerClipboardSupport { multi: false },
        ));
        assert_eq!(
            encoded.format.enum_value(),
            Ok(proto::ClipboardFormat::Text)
        );
        assert_eq!(
            decode_clipboard(encoded).unwrap(),
            Some(ClipboardPayload::text("hi"))
        );

        // Upstream `get_msg_if_not_support_multi_clip` sends nothing at all when
        // the payload carries no text: this is neither an error nor a privately
        // invented single-image encoding.
        assert!(
            encode(
                ClipboardPayload::png(vec![1, 2, 3]),
                PeerClipboardSupport { multi: false }
            )
            .unwrap()
            .is_none()
        );

        // A peer that does support multi receives every format, in wire order.
        match message(payload, PeerClipboardSupport::of("1.4.9", "Linux")).union {
            Some(proto::message::Union::MultiClipboards(multi)) => {
                assert_eq!(multi.clipboards.len(), 2);
                assert_eq!(
                    multi.clipboards[0].format.enum_value(),
                    Ok(proto::ClipboardFormat::Html)
                );
            }
            other => panic!("expected multi clipboards, got {other:?}"),
        }
    }

    #[test]
    fn formats_this_client_cannot_apply_are_skipped_but_a_broken_one_is_an_error() {
        let unknown = Clipboard {
            format: hbb_common::protobuf::EnumOrUnknown::from_i32(99),
            ..Default::default()
        };
        assert!(
            decode_multi_clipboards(MultiClipboards {
                clipboards: vec![unknown].into(),
                ..Default::default()
            })
            .unwrap()
            .is_none()
        );

        // The ownership marker is local state, never content: it is dropped on
        // the way in and cannot be put on the wire.
        let marker = Clipboard {
            format: proto::ClipboardFormat::Special.into(),
            special_name: CLIPBOARD_OWNER_FORMAT.to_owned(),
            content: vec![1].into(),
            ..Default::default()
        };
        assert!(
            decode_clipboard(marker).unwrap().is_none(),
            "the ownership marker is not pasteboard content"
        );
        assert!(matches!(
            encode(
                ClipboardPayload::from_items(vec![ClipboardFormatData::Special {
                    name: CLIPBOARD_OWNER_FORMAT.to_owned(),
                    bytes: vec![1],
                }]),
                PeerClipboardSupport { multi: true }
            ),
            Err(ClipboardError::Refused { .. })
        ));

        // A real special format keeps its own name and bytes.
        let special = Clipboard {
            format: proto::ClipboardFormat::Special.into(),
            special_name: "XML Spreadsheet".to_owned(),
            content: b"<xml/>".to_vec().into(),
            ..Default::default()
        };
        assert_eq!(
            decode_clipboard(special).unwrap(),
            Some(ClipboardPayload::from_items(vec![
                ClipboardFormatData::Special {
                    name: "XML Spreadsheet".to_owned(),
                    bytes: b"<xml/>".to_vec(),
                }
            ]))
        );

        // A payload with no formats at all is refused rather than sent as an
        // empty message that the peer would apply as something.
        assert!(matches!(
            encode(
                ClipboardPayload::from_items(Vec::new()),
                PeerClipboardSupport { multi: true }
            ),
            Err(ClipboardError::Refused { .. })
        ));
    }

    #[test]
    fn a_withdrawn_grant_empties_the_mailbox_and_moves_the_fence() {
        let clipboard = ClipboardState::new();
        let revision = clipboard.revision();
        clipboard
            .accept_peer(revision, ClipboardPayload::text("before"))
            .unwrap();
        // A consumer can observe that there is something to take without taking
        // it, and the observation does not consume it.
        assert!(clipboard.has_pending());
        assert!(clipboard.has_pending());
        assert_eq!(
            clipboard.take().map(|update| update.payload),
            Some(ClipboardPayload::text("before"))
        );
        assert!(
            !clipboard.has_pending(),
            "a hand-out is not a waiting update"
        );

        clipboard
            .accept_peer(revision, ClipboardPayload::text("stale"))
            .unwrap();
        assert!(clipboard.has_pending());
        let revoked = clipboard.revoke();
        assert!(revoked > revision);
        assert!(!clipboard.is_accepted());
        assert!(
            !clipboard.has_pending(),
            "a withdrawal stops the report as well as the hand-out"
        );
        assert!(
            clipboard.take().is_none(),
            "withdrawal drops what was already waiting"
        );
        // A decode that captured the generation before the withdrawal cannot
        // enter the mailbox it has left behind.
        assert_eq!(
            clipboard.accept_peer(revision, ClipboardPayload::text("late")),
            Err(ClipboardError::NotAccepted)
        );
        assert_eq!(
            clipboard.accept_peer(revoked, ClipboardPayload::text("late")),
            Err(ClipboardError::NotAccepted)
        );
        assert!(clipboard.take().is_none());

        let regranted = clipboard.set_accepted(true);
        assert!(regranted > revoked);
        assert_eq!(
            clipboard.accept_peer(revision, ClipboardPayload::text("late")),
            Err(ClipboardError::StaleGeneration),
            "a new grant does not admit a decode from the withdrawn generation"
        );
        clipboard
            .accept_peer(regranted, ClipboardPayload::text("after"))
            .unwrap();
        assert!(
            clipboard.has_pending(),
            "a fresh grant reports its own update"
        );
        assert_eq!(
            clipboard.take().map(|update| update.payload),
            Some(ClipboardPayload::text("after"))
        );
    }

    #[test]
    fn a_repeated_grant_report_does_not_invalidate_a_decode_in_flight() {
        let clipboard = ClipboardState::new();
        let revision = clipboard.revision();
        // The peer re-sends the permission it already granted.
        assert_eq!(clipboard.set_accepted(true), revision);
        clipboard
            .accept_peer(revision, ClipboardPayload::text("kept"))
            .expect("an unchanged grant keeps the generation");
        assert!(clipboard.take().is_some());
    }

    #[test]
    fn metadata_and_bytes_come_from_the_update_the_descriptor_described() {
        let clipboard = ClipboardState::new();
        let revision = clipboard.revision();
        let pixels = vec![9u8; 2 * 2 * 4];
        clipboard
            .accept_peer(revision, ClipboardPayload::rgba(2, 2, 8, pixels.clone()))
            .unwrap();

        let metadata = clipboard.take_metadata().expect("a hand-out");
        assert_eq!(metadata.revision, revision);
        assert!(
            !clipboard.has_pending(),
            "the metadata hand-out is the take a notifier waits for"
        );
        assert_eq!(metadata.formats, vec!["rgba"]);
        assert!(metadata.text.is_none());
        let descriptor = metadata.image.expect("an image descriptor");
        assert_eq!((descriptor.width, descriptor.height), (2, 2));
        assert_eq!(descriptor.byte_length, pixels.len());

        // A newer update arrives before the caller asks for bytes. The
        // descriptor it holds still names the update the engine reserved for it,
        // so the two calls cannot be paired with different content.
        clipboard
            .accept_peer(revision, ClipboardPayload::png(vec![1, 2, 3]))
            .unwrap();

        let image = clipboard.take_image().expect("the reserved bytes");
        assert_eq!(image.format, ClipboardImageFormat::Rgba);
        assert_eq!(image.bytes, pixels);
        // Bytes are handed out once.
        assert!(clipboard.take_image().is_none());
        assert_eq!(
            clipboard.take().map(|update| update.payload),
            Some(ClipboardPayload::png(vec![1, 2, 3]))
        );
    }

    #[test]
    fn a_withdrawal_between_the_descriptor_and_the_bytes_withholds_them() {
        let clipboard = ClipboardState::new();
        let revision = clipboard.revision();
        clipboard
            .accept_peer(revision, ClipboardPayload::png(vec![1, 2, 3]))
            .unwrap();
        assert!(clipboard.take_metadata().is_some());
        clipboard.revoke();
        assert!(
            clipboard.take_image().is_none(),
            "the permission that allowed these bytes is gone"
        );
    }

    #[test]
    fn a_text_update_carries_no_reserved_image() {
        let clipboard = ClipboardState::new();
        let revision = clipboard.revision();
        clipboard
            .accept_peer(revision, ClipboardPayload::html("<b>x</b>", "x"))
            .unwrap();
        let metadata = clipboard.take_metadata().expect("a hand-out");
        assert_eq!(metadata.text.as_deref(), Some("x"));
        assert_eq!(metadata.html.as_deref(), Some("<b>x</b>"));
        assert!(metadata.image.is_none());
        assert_eq!(metadata.formats, vec!["text", "html"]);
        assert!(clipboard.take_image().is_none());
    }

    /// A compressed frame is stopped while it inflates, not after.
    ///
    /// This is the difference between this module's bound and the shared
    /// `hbb_common::compress::decompress`: the shared helper materialises all
    /// 8 MiB and only then refuses it, so a few-KiB frame could cost a quarter
    /// of a gigabyte on the phone that has to apply it.
    #[test]
    fn a_compressed_frame_that_inflates_past_the_bound_is_stopped_while_inflating() {
        let inflated = vec![b'a'; 8 << 20];
        let frame = compress(&inflated);
        assert!(
            frame.len() < 64 << 10,
            "a near-empty frame carries the whole 8 MiB"
        );

        // Inflating past the text bound is its own refusal, never a corrupt
        // frame and never an empty clipboard.
        assert_eq!(
            decode_clipboard(wire(true, frame.clone(), proto::ClipboardFormat::Text)),
            Err(ClipboardError::InflatedTooLarge {
                format: "text",
                limit: MAX_CLIPBOARD_TEXT_BYTES
            })
        );
        // The same content uncompressed is refused by the arrival bound before
        // any inflation at all.
        assert!(matches!(
            decode_clipboard(wire(false, inflated.clone(), proto::ClipboardFormat::Text)),
            Err(ClipboardError::TooLarge { format: "text", .. })
        ));
        // The same frame inside its own bound still decodes to exactly the
        // content that produced it, so the bound is not a blanket refusal.
        assert_eq!(
            decompress_within(&frame, inflated.len()).ok(),
            Some(inflated)
        );
    }

    /// A frame's declared window is bounded too, not only what it expands to.
    ///
    /// `Read::take` stops the bytes this module is handed back; it says nothing
    /// about the back-reference window a frame header makes the decoder
    /// allocate before any of those bytes exists. This is a genuine zstd frame —
    /// it decodes under the library's own defaults — whose header declares an
    /// 8 MiB window, twice the text bound, so it is refused instead of being
    /// given that window. `hbb_common::compress` cannot produce such a frame (a
    /// pledged source size keeps the window inside the content), which is what
    /// makes the content bound a window bound as well.
    #[test]
    fn a_frame_that_declares_a_window_beyond_the_bound_is_refused() {
        let mut encoder = zstd::Encoder::new(Vec::<u8>::new(), 3).expect("an encoder");
        encoder.window_log(23).expect("an 8 MiB window to declare");
        encoder.write_all(b"tiny").expect("writing the content");
        let frame = encoder.finish().expect("the frame");
        assert_eq!(
            zstd::decode_all(frame.as_slice()).expect("a valid zstd frame"),
            b"tiny".to_vec()
        );

        assert_eq!(
            decode_clipboard(wire(true, frame, proto::ClipboardFormat::Text)),
            Err(ClipboardError::Corrupt { format: "text" })
        );
    }
}
