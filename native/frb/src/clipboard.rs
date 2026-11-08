//! The platform clipboard owner for the non-HarmonyOS official-client adapter.
//!
//! ## Why this module exists: the pinned consumer has no bridge call at all
//!
//! At the pinned revision (`native/frb/UPSTREAM.txt`,
//! `092a961b629d318fe290eeafac0cd214a1e9deeb`) the official client exchanges the
//! *ordinary* clipboard inside its native half, never through flutter_rust_bridge:
//!
//! * local → remote: `Client::try_start_clipboard` (`src/client.rs:1860`) owns one
//!   clipboard loop that reads the system clipboard every `CLIPBOARD_INTERVAL`
//!   (`src/clipboard.rs`) and sends what it read from
//!   `ClientClipboardHandler::check_clipboard` (`src/client.rs:2002`);
//! * remote → local: `src/client/io_loop.rs:1541` hands the received payload to
//!   `clipboard::update_clipboard`, which writes the system clipboard itself;
//! * the Dart half only *consumes* a `"clipboard"` event
//!   (`flutter/lib/models/model.dart:366`), and upstream emits that event on iOS
//!   alone (`src/client/io_loop.rs:1546`).
//!
//! So there is no `session_*`/`main_*` entry for Dart to call, and adding one
//! would produce a function the pinned client never calls. What the pinned
//! client's native half does, this adapter has to do in its place - with the
//! shared engine as the only wire owner ([`rd_engine::clipboard`] encodes,
//! decodes, bounds and fences; [`rd_engine::viewer::Viewer`] owns the session and
//! its writer) and this module as the only platform clipboard owner.
//!
//! ## What is exchanged, and in which direction
//!
//! Desktop (Windows, macOS, Linux) gets the pin's own native exchange through
//! `arboard`, the crate the pinned client itself depends on
//! (`.build-deps/official-client/Cargo.toml`, the `rustdesk-org` fork):
//!
//! * remote → local: `Viewer::clipboard_take` gives one accepted update, and its
//!   typed formats are written to the system pasteboard as Text, RTF, HTML, an
//!   image (`ImageRgba` pixels, `ImagePng` file bytes, `ImageSvg` document) or
//!   the named special format the peer sent. Nothing is re-encoded: a PNG stays
//!   the PNG the sender packed, and only RGBA carries pixels.
//! * local → remote: the system pasteboard is read for those same formats and
//!   handed to `Viewer::clipboard_send` as a [`ClipboardPayload`]. Whether that
//!   send is admitted - the peer's grant, the operator's read-only switch, the
//!   local `disable-clipboard` option, the session still being open - is the
//!   engine's decision, never this module's.
//!
//! Anti-echo is the pin's own mechanism, not an invented acknowledgement: a
//! pasteboard this bridge wrote carries `dyn.com.rustdesk.owner`
//! (upstream `RUSTDESK_CLIPBOARD_OWNER_FORMAT`), and a read that finds it is a
//! copy that came *from* a peer, so it is not sent back. That is also what keeps
//! two windows on one machine from bouncing content between their peers.
//!
//! Change detection is this thread's own, because there is no platform
//! clipboard event source here: upstream's client clipboard loop is woken by
//! `clipboard_listener` and reads the pasteboard only when the platform reports
//! a change, while this owner polls. A cycle therefore keeps the one payload it
//! last got *queued* and does not send that same value again. That memory is one
//! payload and never a history, it is written only after a send was really
//! queued, and it stops covering anything once the permission generation that
//! admitted that send is gone - so a withdrawal or a fresh grant forgets it, and
//! a new connection synchronises whatever the pasteboard holds at that moment. A
//! peer update this thread writes to the pasteboard forgets it too: from then on
//! the pasteboard holds the peer's content, so a user copying the previously
//! sent value again is making a new copy rather than repeating the old one
//! (anti-echo stays the owner marker's job, exactly as it is upstream).
//!
//! ## Mobile
//!
//! Android and iOS have no `arboard`: the official client reads those
//! pasteboards through `scrap`'s JNI clipboard manager (Android) or needs a user
//! paste gesture (iOS), and writes them through the Java clipboard manager or the
//! `"clipboard"` event. This artifact has neither `scrap` nor a Java bridge, so
//! the only clipboard sink it really has there is the event the pinned Dart
//! consumer applies itself - and only for text. An update that carries no text
//! is named as unsupported rather than reported as applied, and there is no
//! local → remote direction on those targets.
//!
//! ## What is not here
//!
//! * The file clipboard. `main_has_file_clipboard` stays `false`
//!   (`client_compat.rs`) and `Cliprdr`/OS file-list work is a separate owner, so
//!   `FileUrl` is not read here at all. A file copy that also offers text is
//!   exchanged as that text, like any other text, and the engine's own
//!   `Viewer::clipboard_send` then retires the local file offer that value
//!   replaces.
//! * Any storage. Nothing is persisted, no clipboard content is logged, and the
//!   mailbox holds one update at a time because that is what the engine's
//!   mailbox already is - it is never extended into a queue here.
//! * Any second reader, writer or runtime. One thread per live viewer, started
//!   with the viewer and joined with it (see [`Owner`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use hbb_common::log;
use rd_engine::viewer::Viewer;
use serde_json::Value;

/// Publishing one event to the client's session stream.
///
/// Signed as a closure rather than the adapter's session record so this module
/// stays the clipboard owner and not a second view of session state: only the
/// mobile arm below needs it, because there the pinned consumer's own
/// `"clipboard"` event is the pasteboard sink.
pub type EventSink = Arc<dyn Fn(Value) + Send + Sync>;

/// Upstream's clipboard poll interval (`CLIPBOARD_INTERVAL` in the pinned
/// `src/clipboard.rs`), which is also the timeout its clipboard listener waits
/// with. Polling is the pin's own mechanism (there is no listener thread here to
/// depend on a platform event source), and it bounds one cycle's work.
const POLL: Duration = Duration::from_millis(333);

/// One live platform clipboard owner: a thread and the flag that retires it.
///
/// It is created by [`start`] and owned by the session record that started the
/// viewer, so `Session::stop_viewer` retires it exactly like the frame pump:
/// [`Owner::stop_and_join`] is how the session consumes it, and the drop
/// implementation below applies the same cancellation to any path that drops the
/// record instead of joining it.
pub struct Owner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Owner {
    /// Stops the owner and waits for it to finish.
    ///
    /// Called before the session's viewer is closed, so once this returns no
    /// pasteboard read or write is running or can start for that session, and no
    /// thread outlives it. A clipboard call already inside the platform API is
    /// bounded by that API's own return, exactly as it is upstream.
    pub fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                log::error!("clipboard owner stopped abnormally");
            }
        }
    }
}

impl Drop for Owner {
    /// A dropped owner still cancels its thread.
    ///
    /// Every real retirement goes through [`Owner::stop_and_join`], which is what
    /// the session calls; this is the same cancellation for a path that drops the
    /// record instead, so no clipboard reader can keep running behind a closed
    /// session. The flag is the only thing the loop waits on, so the thread leaves
    /// within one poll interval; a join is deliberately not done here, because a
    /// destructor must not block an arbitrary thread.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Starts the one clipboard owner for one live viewer.
///
/// `viewer` is that viewer itself: its mailbox is the only place a decoded peer
/// update waits, and its writer is the only way a local copy reaches the wire.
pub fn start(viewer: Arc<Viewer>, emit: EventSink) -> Owner {
    let stop = Arc::new(AtomicBool::new(false));
    let spawn = {
        let stop = stop.clone();
        std::thread::Builder::new()
            .name("rd-engine-clipboard".to_owned())
            .spawn(move || platform::run(viewer, stop, emit))
    };
    let handle = match spawn {
        Ok(handle) => Some(handle),
        Err(error) => {
            // No thread was created, so there is nothing to join; the failure is
            // reported instead of leaving a session that silently has no
            // clipboard owner.
            log::error!("cannot start the clipboard owner: {error}");
            None
        }
    };
    Owner { stop, handle }
}

// ---------------------------------------------------------------------------
// Desktop: the pinned client's own native clipboard, over `arboard`
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
mod platform {
    use super::*;
    use arboard::{Clipboard, ClipboardData, ClipboardFormat, ImageData};
    use rd_engine::clipboard::{
        ClipboardFormatData, ClipboardImage, ClipboardImageFormat, ClipboardPayload,
    };
    use rd_engine::viewer::ViewerError;

    /// Upstream `RUSTDESK_CLIPBOARD_OWNER_FORMAT`: the flag this bridge leaves on
    /// a pasteboard it wrote. It is ownership state, never content, so it is read
    /// to recognise our own write and is never handed to the engine as a payload
    /// (the engine refuses it by name).
    const OWNER_FORMAT: &str = "dyn.com.rustdesk.owner";

    /// Upstream `ClipboardSide::Client`'s `get_owner_data()`, the one byte a
    /// client-side write leaves behind.
    const OWNER_DATA: [u8; 1] = [0b10];

    /// Upstream `ClipboardSide::is_owner`: any low bit set means a RustDesk side
    /// wrote this pasteboard - the host's `0b01` as well as the client's `0b10`,
    /// because either way the content came from a peer and must not go back.
    const OWNER_MASK: u8 = 0b11;

    /// Upstream `CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET`: the one named special
    /// format its supported list passes through, so an Excel copy keeps the
    /// flavour it was packed with.
    const CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET: &str = "XML Spreadsheet";

    /// Upstream `SUPPORTED_FORMATS`, minus `FileUrl`: the file clipboard is a
    /// different message with its own owner, and `main_has_file_clipboard` stays
    /// false. `Special(OWNER_FORMAT)` is requested only to recognise our own
    /// write.
    const SUPPORTED: &[ClipboardFormat] = &[
        ClipboardFormat::Text,
        ClipboardFormat::Html,
        ClipboardFormat::Rtf,
        ClipboardFormat::ImageRgba,
        ClipboardFormat::ImagePng,
        ClipboardFormat::ImageSvg,
        ClipboardFormat::Special(CLIPBOARD_FORMAT_EXCEL_XML_SPREADSHEET),
        ClipboardFormat::Special(OWNER_FORMAT),
    ];

    /// Upstream `ClipboardContext::get_formats` retry: another process holding
    /// the pasteboard open is a normal, transient condition - upstream's own
    /// comment names rustdesk#9263 and #9222 - and is retried there three times
    /// `CLIPBOARD_GET_RETRY_INTERVAL_DUR` apart instead of being reported as a
    /// refusal of the content.
    const READ_ATTEMPTS: usize = 3;
    const READ_RETRY_INTERVAL: Duration = Duration::from_millis(33);

    pub(super) fn run(viewer: Arc<Viewer>, stop: Arc<AtomicBool>, _emit: EventSink) {
        // The pasteboard handle is created here and dropped with this thread:
        // `arboard` contexts are thread-affine, and one per live viewer is what
        // lets this owner be joined by the session that owns it.
        let mut pasteboard = Pasteboard::default();
        while !stop.load(Ordering::Acquire) {
            if apply_remote(&viewer, &stop, &mut pasteboard) {
                // The pasteboard now holds the peer's content, so the value this
                // thread last sent is no longer what the pasteboard says: a user
                // copying that same content again is making a new copy, and it
                // has to reach the peer instead of being taken for the one
                // already sent.
                pasteboard.last_queued = None;
            }
            send_local(&viewer, &stop, &mut pasteboard);
            std::thread::sleep(POLL);
        }
        log::debug!("clipboard owner stopped");
    }

    /// One live pasteboard, with the bookkeeping this thread keeps about it.
    ///
    /// The handle is thread-affine - `arboard` contexts are, which is why
    /// [`Owner`] joins the thread that opened it - so it lives beside the two
    /// facts the loop holds about the same pasteboard: whether it has already
    /// reported that no pasteboard can be opened at all, and the one payload it
    /// last got queued, which is what keeps a poll from re-sending an unchanged
    /// pasteboard (see [`LastQueued`]).
    #[derive(Default)]
    struct Pasteboard {
        handle: Option<Clipboard>,
        unavailable_reported: bool,
        last_queued: Option<LastQueued>,
    }

    impl Pasteboard {
        /// The thread's one pasteboard handle, created on first use.
        ///
        /// A target where no pasteboard can be opened at all - a headless Linux
        /// session with no display server, say - is reported once and then
        /// retried quietly: at three cycles a second a repeated error would be
        /// the only thing this thread ever produced.
        fn handle(&mut self) -> Option<&mut Clipboard> {
            if self.handle.is_none() {
                match Clipboard::new() {
                    Ok(context) => {
                        self.handle = Some(context);
                        self.unavailable_reported = false;
                    }
                    Err(error) => {
                        if !self.unavailable_reported {
                            self.unavailable_reported = true;
                            log::warn!("clipboard: no system pasteboard is available: {error}");
                        }
                        return None;
                    }
                }
            }
            self.handle.as_mut()
        }
    }

    /// The one payload this thread last got queued, with the generation that
    /// admitted it.
    ///
    /// Polling has to decide for itself whether the pasteboard changed, because
    /// this artifact has no platform clipboard event source: upstream's client
    /// loop is woken by `clipboard_listener` and reads the pasteboard only when
    /// the platform reports a change, while this owner asks every [`POLL`].
    /// Without this memory an unchanged Text or RGBA pasteboard would be
    /// compressed and sent again on every cycle for the whole life of the
    /// session, and the file owner's local offer would be retired again with it.
    ///
    /// It is one payload and never a history, it is written only after a send
    /// was really queued - the generation [`Viewer::clipboard_send`] returned,
    /// which is the writer's queue and not the peer's application of it, because
    /// the original wire has no clipboard acknowledgement - and it stops
    /// covering anything as soon as that generation is no longer in force. A
    /// withdrawal or a fresh grant therefore forgets it, and a new connection or
    /// a new permission synchronises what the pasteboard holds at that moment.
    struct LastQueued {
        generation: u64,
        payload: ClipboardPayload,
    }

    impl LastQueued {
        /// Whether `payload` is the content already queued for this viewer: the
        /// same value, under the generation that is still in force.
        fn covers(&self, viewer: &Viewer, payload: &ClipboardPayload) -> bool {
            self.payload == *payload && viewer.clipboard_admits(self.generation)
        }
    }

    /// Writes one accepted peer update to the system pasteboard.
    ///
    /// The update is taken as one value, so the formats named here and the bytes
    /// they carry are from the same accepted generation. A withdrawal or a close
    /// empties the mailbox, which is why a session that ends while this thread is
    /// mid-cycle cannot pick up content nobody permits any more.
    ///
    /// Returns whether the pasteboard now holds the peer's content: `false` for
    /// no update at all, for one that was not admitted at the commit, and for a
    /// write this platform refused.
    fn apply_remote(viewer: &Viewer, stop: &AtomicBool, pasteboard: &mut Pasteboard) -> bool {
        let Some(update) = viewer.clipboard_take() else {
            return false;
        };
        let mut data = Vec::with_capacity(update.payload.items().len() + 1);
        for item in update.payload.items() {
            match item {
                ClipboardFormatData::Text(text) => data.push(ClipboardData::Text(text.clone())),
                ClipboardFormatData::Rtf(rtf) => data.push(ClipboardData::Rtf(rtf.clone())),
                ClipboardFormatData::Html(html) => data.push(ClipboardData::Html(html.clone())),
                ClipboardFormatData::Image(image) => match image_data(image) {
                    Some(image) => data.push(ClipboardData::Image(image)),
                    // The one image shape this pasteboard cannot be handed: a
                    // document that is not UTF-8 text. The update is still
                    // applied for its other formats.
                    None => log::debug!("clipboard: the SVG in this update is not UTF-8 text"),
                },
                ClipboardFormatData::Special { name, bytes } => {
                    data.push(ClipboardData::Special((name.clone(), bytes.clone())))
                }
            }
        }
        if data.is_empty() {
            return false;
        }
        data.push(owner_marker());
        let Some(handle) = pasteboard.handle() else {
            return false;
        };
        // The update was taken before the pasteboard handle was opened, and this
        // platform write is the last moment it can still be withheld: a
        // withdrawal or a close that landed in between has advanced the fence,
        // and the revision this content arrived under is then no longer
        // admitted. Nothing is written onto a newer generation, so withdrawn
        // content is never stamped with a permission it never had.
        if stop.load(Ordering::Acquire) || !viewer.clipboard_admits(update.revision) {
            log::debug!(
                "clipboard: revision {} is no longer admitted, so it is not applied",
                update.revision
            );
            return false;
        }
        match handle.set_formats(&data) {
            Ok(()) => {
                log::debug!("clipboard: applied revision {}", update.revision);
                true
            }
            // The pasteboard refused the write. Nothing is claimed about it and
            // the update is not retried: it belonged to a moment that has passed,
            // and the next peer update starts a new one.
            Err(error) => {
                log::debug!("clipboard: this platform refused the update: {error}");
                false
            }
        }
    }

    /// Sends what the local user copied, if anything new is there.
    fn send_local(viewer: &Viewer, stop: &AtomicBool, pasteboard: &mut Pasteboard) {
        // A pasteboard is not read at all for a viewer that may not exchange
        // clipboard content right now: not before the peer's grant, not while
        // the operator or a local option has the clipboard turned off, not after
        // a close. Reading it and then discarding the value would still be this
        // side touching the user's clipboard on a permission it does not have.
        if stop.load(Ordering::Acquire) || !viewer.clipboard_enabled() {
            return;
        }
        let Some(handle) = pasteboard.handle() else {
            return;
        };
        let Some(data) = read_formats(handle) else {
            return;
        };
        if data.iter().any(is_owner_marker) {
            // Upstream `ClipboardContext::get_formats_filter`: what a RustDesk
            // side put here came from a peer (or from another window's peer), so
            // it is not sent back.
            return;
        }
        let items: Vec<ClipboardFormatData> = data.into_iter().filter_map(format_data).collect();
        if items.is_empty() {
            return;
        }
        let payload = ClipboardPayload::from_items(items);
        // Not a change: this is the content this thread already got queued for
        // this viewer, so nothing is compressed and nothing is queued again.
        if let Some(queued) = pasteboard.last_queued.as_ref() {
            if queued.covers(viewer, &payload) {
                return;
            }
        }
        // The read above may have waited through its own retries, and any
        // platform call can take long enough for a withdrawal, a re-grant or a
        // close to land: the stop flag and the permission are asked again right
        // before a payload read under the old answer would be encoded and queued.
        if stop.load(Ordering::Acquire) || !viewer.clipboard_enabled() {
            return;
        }
        // The send consumes the payload, so the copy that a later cycle compares
        // against is taken first, and it is only remembered once the send was
        // really queued.
        match viewer.clipboard_send(payload.clone()) {
            Ok(revision) => {
                pasteboard.last_queued = Some(LastQueued {
                    generation: revision,
                    payload,
                });
                log::debug!("clipboard: local content queued under revision {revision}");
            }
            // Not admitted right now: no peer grant, the operator's read-only
            // switch, a locally disabled clipboard, or a closing session. Nothing
            // was sent and nothing more is claimed; the next cycle asks again.
            Err(ViewerError::InputNotAllowed) | Err(ViewerError::Closed) => {}
            // A real refusal of this payload - an oversized or unencodable
            // format, a peer owed nothing for it, a full writer queue, or the
            // file clipboard owner refusing to retire its local offer before this
            // value replaces it (`ViewerError::FileClipboard`) - is named with its
            // typed reason instead of being counted as a send.
            Err(error) => log::debug!("clipboard: local content was not sent: {error}"),
        }
    }

    /// Reads the supported formats off the system pasteboard.
    fn read_formats(pasteboard: &mut Clipboard) -> Option<Vec<ClipboardData>> {
        for attempt in 0..READ_ATTEMPTS {
            match pasteboard.get_formats(SUPPORTED) {
                Ok(data) => {
                    return Some(
                        data.into_iter()
                            // Upstream drops `None` entries: a format it asked
                            // for and could not read is not content.
                            .filter(|item| !matches!(item, ClipboardData::None))
                            .collect(),
                    )
                }
                Err(arboard::Error::ClipboardOccupied) if attempt + 1 < READ_ATTEMPTS => {
                    std::thread::sleep(READ_RETRY_INTERVAL);
                }
                Err(error) => {
                    log::debug!("clipboard: this platform refused a read: {error}");
                    return None;
                }
            }
        }
        None
    }

    /// One system format as the engine's typed payload item.
    fn format_data(data: ClipboardData) -> Option<ClipboardFormatData> {
        match data {
            // An empty text is a real update, not a missing one: on the wire an
            // empty `Text` is the clear the canonical client applies
            // (`ClipboardPayload::clear`, `src/clipboard.rs`), so it is carried
            // as that clear. `None` - a format this platform does not offer at
            // all - is what means "no update".
            ClipboardData::Text(text) => Some(ClipboardFormatData::Text(text)),
            ClipboardData::Rtf(rtf) => Some(ClipboardFormatData::Rtf(rtf)),
            ClipboardData::Html(html) => Some(ClipboardFormatData::Html(html)),
            ClipboardData::Image(image) => {
                let bytes = image.bytes().to_vec();
                let (format, width, height) = match &image {
                    ImageData::Rgba(rgba) => (
                        ClipboardImageFormat::Rgba,
                        rgba.width as u32,
                        rgba.height as u32,
                    ),
                    ImageData::Png(_) => (ClipboardImageFormat::Png, 0, 0),
                    ImageData::Svg(_) => (ClipboardImageFormat::Svg, 0, 0),
                };
                Some(ClipboardFormatData::Image(ClipboardImage {
                    format,
                    bytes,
                    width,
                    height,
                    // The wire carries no row padding, and `arboard` hands RGBA
                    // back tightly packed, so the stride is the width it reports.
                    stride: match format {
                        ClipboardImageFormat::Rgba => width.saturating_mul(4),
                        ClipboardImageFormat::Png | ClipboardImageFormat::Svg => 0,
                    },
                }))
            }
            ClipboardData::Special((name, bytes)) => {
                Some(ClipboardFormatData::Special { name, bytes })
            }
            // Anything else this platform offers (`FileUrl`, or a fork-only
            // variant) is not a format this bridge carries, so it is not put on
            // the wire as one.
            _ => None,
        }
    }

    /// One engine payload item as a system pasteboard format.
    fn image_data(image: &ClipboardImage) -> Option<ImageData<'static>> {
        match image.format {
            // The engine guarantees `width * height * 4` bytes with an unpadded
            // stride before an image reaches this point.
            ClipboardImageFormat::Rgba => Some(ImageData::rgba(
                usize::try_from(image.width).ok()?,
                usize::try_from(image.height).ok()?,
                image.bytes.clone().into(),
            )),
            ClipboardImageFormat::Png => Some(ImageData::png(image.bytes.clone().into())),
            ClipboardImageFormat::Svg => {
                Some(ImageData::svg(std::str::from_utf8(&image.bytes).ok()?))
            }
        }
    }

    /// The marker byte pair upstream appends to every write it makes.
    fn owner_marker() -> ClipboardData {
        ClipboardData::Special((OWNER_FORMAT.to_owned(), OWNER_DATA.to_vec()))
    }

    fn is_owner_marker(data: &ClipboardData) -> bool {
        matches!(
            data,
            ClipboardData::Special((name, bytes))
                if name.as_str() == OWNER_FORMAT
                    && bytes.first().is_some_and(|owner| owner & OWNER_MASK != 0)
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn an_empty_text_is_the_wires_clear_rather_than_a_missing_format() {
            assert_eq!(
                format_data(ClipboardData::Text("hello".to_owned())),
                Some(ClipboardFormatData::Text("hello".to_owned()))
            );
            // The core's wire contract is that empty text *is* the clear
            // (`an_empty_text_is_a_real_clear_and_not_an_empty_result` in
            // `src/clipboard.rs`), so dropping it here would lose a real copy.
            assert_eq!(
                format_data(ClipboardData::Text(String::new())),
                Some(ClipboardFormatData::Text(String::new()))
            );
        }

        #[test]
        fn png_bytes_stay_png_and_rgba_keeps_its_shape() {
            let png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
            let mapped = format_data(ClipboardData::Image(ImageData::png(
                png.clone().into(),
            )))
            .expect("a PNG pasteboard is content");
            let ClipboardFormatData::Image(image) = mapped else {
                panic!("expected an image");
            };
            assert_eq!(image.format, ClipboardImageFormat::Png);
            assert_eq!(image.bytes, png, "an encoded PNG is never reinterpreted");
            assert_eq!((image.width, image.height, image.stride), (0, 0, 0));

            let pixels = vec![0u8; 2 * 3 * 4];
            let mapped = format_data(ClipboardData::Image(ImageData::rgba(
                2,
                3,
                pixels.clone().into(),
            )))
            .expect("an RGBA pasteboard is content");
            let ClipboardFormatData::Image(image) = mapped else {
                panic!("expected an image");
            };
            assert_eq!(image.format, ClipboardImageFormat::Rgba);
            assert_eq!(image.bytes, pixels);
            assert_eq!((image.width, image.height), (2, 3));
            assert_eq!(image.stride, 8, "stride is width * 4 with no padding");
        }

        #[test]
        fn an_engine_image_keeps_its_wire_format() {
            let rgba = ClipboardImage {
                format: ClipboardImageFormat::Rgba,
                bytes: vec![0u8; 4],
                width: 1,
                height: 1,
                stride: 4,
            };
            let Some(ImageData::Rgba(image)) = image_data(&rgba) else {
                panic!("an RGBA payload is handed on as RGBA pixels");
            };
            assert_eq!((image.width, image.height), (1, 1));
            assert_eq!(image.bytes.to_vec(), vec![0u8; 4]);

            // A PNG is handed on as the file it is, never as bare pixels.
            let png = ClipboardImage {
                format: ClipboardImageFormat::Png,
                bytes: vec![1, 2, 3],
                width: 0,
                height: 0,
                stride: 0,
            };
            assert!(matches!(image_data(&png), Some(ImageData::Png(_))));
        }

        #[test]
        fn the_owner_marker_is_recognised_by_the_pins_test() {
            assert!(is_owner_marker(&owner_marker()));
            // Upstream also treats a host-side marker as "a peer wrote this".
            assert!(is_owner_marker(&ClipboardData::Special((
                OWNER_FORMAT.to_owned(),
                vec![0b01],
            ))));
            // A zero marker is not an owner, and neither is another format.
            assert!(!is_owner_marker(&ClipboardData::Special((
                OWNER_FORMAT.to_owned(),
                vec![0],
            ))));
            assert!(!is_owner_marker(&ClipboardData::Special((
                "custom-format".to_owned(),
                vec![0b10],
            ))));
            assert!(!is_owner_marker(&ClipboardData::Text("hi".to_owned())));
        }
    }
}

// ---------------------------------------------------------------------------
// Android and iOS: the pinned consumer's own text event is the only sink
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;
    use rd_engine::clipboard::ClipboardFormatData;

    /// Publishes a remote text clipboard through the pinned consumer's own sink.
    ///
    /// On these targets the official client writes a remote clipboard through the
    /// Java clipboard manager from `scrap` (Android) or through the `"clipboard"`
    /// event (iOS, `src/client/io_loop.rs:1546`); this artifact has neither
    /// `scrap` nor a Java bridge. Dart's `Clipboard.setData` behind that event is
    /// the same pasteboard write, and the pinned `FfiModel` applies it itself
    /// (`flutter/lib/models/model.dart:366`), so text is a real exchange here.
    ///
    /// Nothing else is claimed. An update that carries no text has no sink, so it
    /// is named as unsupported instead of being reported as applied, and the
    /// local → remote direction does not exist: reading this side's pasteboard
    /// needs the Java clipboard manager or a user paste gesture, not a call this
    /// crate can make.
    pub(super) fn run(viewer: Arc<Viewer>, stop: Arc<AtomicBool>, emit: EventSink) {
        log::info!(
            "clipboard: text from the peer is applied through the client's own event; \
             this platform has no local reader in this artifact"
        );
        while !stop.load(Ordering::Acquire) {
            if let Some(update) = viewer.clipboard_take() {
                let text = update.payload.items().iter().find_map(|item| match item {
                    ClipboardFormatData::Text(text) => Some(text.as_str()),
                    _ => None,
                });
                // Publishing the event *is* the platform write on these targets,
                // so the revision that admitted the update is rechecked right
                // here: a withdrawal or a close that landed after the hand-out
                // must not reach the consumer's pasteboard.
                if stop.load(Ordering::Acquire) || !viewer.clipboard_admits(update.revision) {
                    log::debug!(
                        "clipboard: revision {} is no longer admitted, so it is not applied",
                        update.revision
                    );
                } else if let Some(text) = text {
                    emit(serde_json::json!({
                        "name": "clipboard",
                        "content": text,
                    }));
                } else {
                    log::debug!(
                        "clipboard: this platform's only sink carries text, and the update had none"
                    );
                }
            }
            std::thread::sleep(POLL);
        }
    }
}
