//! The RustDesk-wire video pipeline: admission of encoded records, the ordered
//! feeder, and the native decoder's lifecycle.
//!
//! It is the one path encoded video takes into a Surface, whichever session owns
//! the connection. The engine's own `Viewer` owns one after its handshake, and a
//! session that keeps the pinned RustDesk connection, authentication and
//! companion services can own one the same way: it implements [`VideoOwner`],
//! calls [`pipeline`], feeds every `VideoFrame` the peer sends to
//! [`VideoAdmission::admit`] and drives [`VideoFeed::run`] to completion. The
//! bounds, cancellation and reclamation rules below therefore hold for both.
//!
//! Rectangle protocols never enter it: LibVNCClient owns RFB request pacing and
//! IronRDP owns its decoded image, so their damage is presented without a
//! compressed-record queue.

use crate::viewer::{
    decoder::{
        AccessUnit, AccessUnitKind, CleanupVerdict, DecoderConfig, DecoderError, DecoderObserver,
        DecoderProjection, SurfaceDecoder, SurfaceLease, VideoCodec,
    },
    ViewerError, SURFACE_POLL, SURFACE_WAIT,
};
#[cfg(target_env = "ohos")]
use crate::media_capability::{self, AdvertisedCodec, CapabilityError};
use base::message_proto::{
    self as proto, supported_decoding::PreferCodec, video_frame, EncodedVideoFrame, PeerInfo,
    SupportedDecoding, SwitchDisplay, VideoFrame,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

// End-to-end low-latency budget: one record may be feeding while one waits.
// Larger queues preserve throughput by displaying increasingly stale frames.
//
// This depth is the floor for inter-coded video, and it is deliberate rather
// than a queue in the sense the latency budget forbids:
//
//  * It cannot be 1. Admission would then block the reader for the whole time
//    the feeder spends decoding, so the next frame could not even be received
//    while the current one was in the decoder — that raises latency for every
//    frame, which is the opposite of the goal.
//  * It must not grow. A deeper queue does not make the picture fresher, it
//    only makes it older: the displayed frame would be N records behind the
//    newest one already on the machine.
//  * Frames here cannot be dropped to make the queue "look short". An H264 or
//    H265 record is a dependency chain, so discarding an arbitrary record
//    corrupts every frame that references it. MODERN_RUNTIME.md forbids it.
const VIDEO_RECORDS: usize = 2;
const VIDEO_BYTES: usize = 32 * 1024 * 1024;
const MAX_UNITS_PER_RECORD: usize = 256;

/// The display a record belongs to and the picture size its decoder opens at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub display: i32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl Geometry {
    /// The peer's current display, as its handshake reported it.
    pub fn of_peer(info: &PeerInfo) -> Result<Self, ViewerError> {
        let index =
            usize::try_from(info.current_display).map_err(|_| ViewerError::InvalidPeerGeometry)?;
        let display = info
            .displays
            .get(index)
            .ok_or(ViewerError::InvalidPeerGeometry)?;
        if display.width <= 0 || display.height <= 0 {
            return Err(ViewerError::InvalidPeerGeometry);
        }
        Ok(Self {
            display: info.current_display,
            x: display.x,
            y: display.y,
            width: display.width,
            height: display.height,
        })
    }
}

/// The codecs this build may ask a peer for, and the evidence behind each.
///
/// A codec is advertised only where a decoder for it is actually in the build,
/// because the advertisement is a promise that the record which follows is
/// decodable. `Decoders` is therefore built from evidence by [`capabilities`],
/// never from a capability list, and its flags cannot be set by a caller.
#[derive(Clone, Copy)]
pub struct Decoders {
    h264: bool,
    h265: bool,
    /// The software VP8/VP9 backend's own runtime probe, one flag per codec: a
    /// process that can initialize a VP8 context is evidence for VP8 and not for
    /// VP9, so each flag is the answer to its own probe and is never filled in
    /// from the other. False without the feature, without a linked library, and
    /// on every target whose build has no hardware decoder to contribute either.
    vp8: bool,
    vp9: bool,
}

impl Decoders {
    /// Whether this build's evidence covers `codec`.
    ///
    /// It is the same answer the record path's gates use, read as one field, so a
    /// feeder decision about which backend will serve a record cannot disagree
    /// with the admission that delivered it.
    pub fn covers(self, codec: VideoCodec) -> bool {
        match codec {
            VideoCodec::H264 => self.h264,
            VideoCodec::H265 => self.h265,
            VideoCodec::Vp8 => self.vp8,
            VideoCodec::Vp9 => self.vp9,
        }
    }

    /// The login advertisement that promises exactly these codecs.
    pub fn supported_decoding(self) -> SupportedDecoding {
        SupportedDecoding {
            ability_h264: i32::from(self.h264),
            ability_h265: i32::from(self.h265),
            // VP8 and VP9 each follow the evidence the record path checks — the
            // software backend's own probe, one codec at a time — so an
            // advertisement can never outrun the decoder that has to accept the
            // record. AV1 stays zero: no backend for it is in this build, and a
            // zero is how that absence is stated.
            ability_vp9: i32::from(self.vp9),
            ability_vp8: i32::from(self.vp8),
            ability_av1: 0,
            // Auto: this client states no preference among the codecs it
            // advertised, and the peer's own priority (h265 over h264 over vp9)
            // decides.
            prefer: PreferCodec::Auto.into(),
            prefer_chroma: proto::Chroma::I420.into(),
            ..Default::default()
        }
    }
}

/// Whether one platform metadata answer is decoder evidence a peer may be given.
///
/// OpenHarmony is the only platform whose backend serves the two hardware
/// categories, so it is the only place this query exists: it reports a codec this
/// build can open, or nothing.
#[cfg(target_env = "ohos")]
fn advertised(value: &Result<AdvertisedCodec, CapabilityError>) -> bool {
    value.as_ref().is_ok_and(|v| {
        v.hardware
            && !v.codec_name.is_empty()
            && v.native_buffer_formats
                .as_ref()
                .is_ok_and(|f| !f.is_empty())
    })
}

/// What this build can actually decode on the platform it is running on.
///
/// Every flag is the answer to its own evidence and never a cross-codec
/// inference: OpenHarmony answers for H264/H265 out of its own decoder metadata,
/// VP8 and VP9 come from the software backend's runtime probe alone
/// (`SurfaceDecoder::serves_software_vpx`), and H264/H265 are false on every
/// target whose build has no hardware decoder for them.
///
/// The platform queries may be IPC: call it from a blocking worker.
pub fn capabilities() -> Result<Decoders, ViewerError> {
    #[cfg(target_env = "ohos")]
    {
        let h264 = media_capability::query_h264_hardware_decoder();
        let h265 = media_capability::query_hevc_hardware_capabilities().decoder;
        if matches!(&h264, Err(CapabilityError::UnsupportedPlatform))
            && matches!(&h265, Err(CapabilityError::UnsupportedPlatform))
        {
            return Err(ViewerError::UnsupportedPlatform);
        }
        let result = Decoders {
            h264: advertised(&h264),
            h265: advertised(&h265),
            // The software backend's own probe, the same evidence every target
            // uses. OpenHarmony's build links no host libvpx (`build.rs` refuses
            // that target outright), so both answer false here; they are read
            // from the probe rather than asserted, so an advertisement can only
            // ever follow evidence.
            vp8: SurfaceDecoder::serves_software_vpx(VideoCodec::Vp8),
            vp9: SurfaceDecoder::serves_software_vpx(VideoCodec::Vp9),
        };
        if !result.h264 && !result.h265 && !result.vp8 && !result.vp9 {
            return Err(ViewerError::NoHardwareCodec);
        }
        Ok(result)
    }
    #[cfg(not(target_env = "ohos"))]
    {
        // The software VP8/VP9 backend is the only decoder this target can
        // carry, so its own probe is the whole capability answer here. H264/H265
        // have no backend on this target and stay false, exactly as they do on
        // every build without a hardware decoder: neither is derived from a probe
        // that answers for another codec.
        let vp8 = SurfaceDecoder::software_vpx_refusal(VideoCodec::Vp8);
        let vp9 = SurfaceDecoder::software_vpx_refusal(VideoCodec::Vp9);
        // A build that can serve neither codec has nothing to decode for a peer,
        // so the session is refused here with the backend's own reason — which
        // feature, link or runtime gate refused — instead of being started for a
        // stream whose first record would already have no decoder.
        if let (Some(vp8), Some(vp9)) = (&vp8, &vp9) {
            return Err(ViewerError::NoSoftwareVpx(format!("VP8: {vp8}; VP9: {vp9}")));
        }
        Ok(Decoders {
            h264: false,
            h265: false,
            vp8: vp8.is_none(),
            vp9: vp9.is_none(),
        })
    }
}

/// The wire codec's own name, never an alias of another codec.
pub fn codec_name(codec: VideoCodec) -> &'static str {
    match codec {
        VideoCodec::H264 => "H264",
        VideoCodec::H265 => "H265",
        VideoCodec::Vp8 => "VP8",
        VideoCodec::Vp9 => "VP9",
    }
}

/// The session a pipeline belongs to.
///
/// The pipeline owns the queue, the decoder and the reclamation decision; the
/// session owns cancellation and whatever it reports to its own UI. Every
/// callback is a short, non-blocking update.
pub trait VideoOwner: Send + Sync + 'static {
    /// The session's cancellation. The pipeline stops when it fires.
    fn cancellation(&self) -> &CancellationToken;
    /// Set before a native decoder is created and cleared only by confirmed
    /// destruction or an open that allocated nothing. While it is set the
    /// session must keep its Surface lease: a decoder may still present into it.
    fn reclamation_unconfirmed(&self) -> &AtomicBool;
    /// Lifecycle progress: `opening_decoder` or `awaiting_surface`.
    fn video_phase(&self, phase: &'static str);
    /// Compressed units received from the peer, counted before admission.
    fn video_received(&self, units: u64);
    /// A decoder opened for `codec` at `geometry`; the session is now decoding.
    fn video_decoder_opened(
        &self,
        codec: VideoCodec,
        geometry: Geometry,
        observer: DecoderObserver,
    );
    /// The decoder is gone; `projection` holds its final counters when readable.
    fn video_decoder_closed(&self, projection: Option<DecoderProjection>);
    /// The feeder failed. Stop the session now; decoder teardown still follows,
    /// because network or UI cancellation must not wait for a blocking SDK
    /// teardown.
    fn video_failed(&self);
}

struct VideoRecord {
    codec: VideoCodec,
    geometry: Geometry,
    frames: Vec<EncodedVideoFrame>,
    // Held until the ordered feeder finishes this group, not released by recv.
    _slot: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}

/// What one `VideoFrame` became.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// Handed to the feeder under its slot and byte permits.
    Queued,
    /// The record carried no units; nothing was queued.
    Empty,
    /// The session was cancelled while the record waited; stop reading.
    Cancelled,
}

/// Creates one display's pipeline for a session.
///
/// `caps` must be the decoders this session advertised at login and `source`
/// the display the peer is sending. The two halves run on separate tasks: the
/// reader admits records, and [`VideoFeed::run`] feeds them.
pub fn pipeline<H: VideoOwner>(
    owner: Arc<H>,
    caps: Decoders,
    source: Geometry,
) -> (VideoAdmission<H>, VideoFeed<H>) {
    let (video, feed) = mpsc::channel(VIDEO_RECORDS);
    (
        VideoAdmission {
            owner: owner.clone(),
            caps,
            source,
            video,
            slots: Arc::new(Semaphore::new(VIDEO_RECORDS)),
            bytes: Arc::new(Semaphore::new(VIDEO_BYTES)),
        },
        VideoFeed { owner, video: feed, caps },
    )
}

/// The reader's half: turns the peer's `VideoFrame` messages into bounded records.
pub struct VideoAdmission<H: VideoOwner> {
    owner: Arc<H>,
    caps: Decoders,
    source: Geometry,
    video: mpsc::Sender<VideoRecord>,
    slots: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}

impl<H: VideoOwner> VideoAdmission<H> {
    /// Admits one record, waiting while the pipeline is full.
    ///
    /// The encoded units move into the record; nothing is copied here. A codec
    /// this session did not advertise, a record from another display, or a
    /// malformed or oversized record ends the session with its error.
    pub async fn admit(&mut self, frame: VideoFrame) -> Result<Admitted, ViewerError> {
        if frame.display != self.source.display {
            return Err(ViewerError::InvalidPeerGeometry);
        }
        let caps = self.caps;
        let (codec, frames) = match frame.union {
            Some(video_frame::Union::H264s(frames)) if caps.h264 => {
                (VideoCodec::H264, frames.frames)
            }
            Some(video_frame::Union::H265s(frames)) if caps.h265 => {
                (VideoCodec::H265, frames.frames)
            }
            // Each VPx record travels only under the evidence that advertised
            // that codec: the software backend's own probe, one codec at a time.
            // A codec the probe did not answer for falls to the named refusal
            // below instead of reaching a decoder that cannot take it, so a host
            // that sends VP8 to a viewer that advertised only VP9 is refused as
            // VP8.
            Some(video_frame::Union::Vp8s(frames)) if caps.vp8 => {
                (VideoCodec::Vp8, frames.frames)
            }
            Some(video_frame::Union::Vp9s(frames)) if caps.vp9 => {
                (VideoCodec::Vp9, frames.frames)
            }
            // Named instead of left to the catch-all, so a VPx record is refused
            // as VPx and can never be mistaken for a codec this viewer
            // advertised.
            Some(video_frame::Union::Vp8s(_)) | Some(video_frame::Union::Vp9s(_)) => {
                return Err(ViewerError::UnsupportedCodec)
            }
            _ => return Err(ViewerError::UnsupportedCodec),
        };
        if frames.is_empty() {
            return Ok(Admitted::Empty);
        }
        if frames.len() > MAX_UNITS_PER_RECORD || frames.iter().any(|f| f.data.is_empty()) {
            return Err(ViewerError::InvalidVideoRecord);
        }
        let length = frames
            .iter()
            .try_fold(0usize, |n, f| n.checked_add(f.data.len()))
            .ok_or(ViewerError::VideoRecordTooLarge)?;
        if length > VIDEO_BYTES {
            return Err(ViewerError::VideoRecordTooLarge);
        }
        self.owner.video_received(frames.len() as u64);
        let cancel = self.owner.cancellation();
        // Transport itself bounds the one not-yet-admitted RX record. Admitted
        // records INCLUDING the feeder's are byte+slot bound.
        let record = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(Admitted::Cancelled),
            admitted = async {
                let slot = self.slots.clone().acquire_owned().await.map_err(|_| ViewerError::Closed)?;
                let permit = self.bytes.clone().acquire_many_owned(length as u32).await.map_err(|_| ViewerError::Closed)?;
                Ok::<_, ViewerError>(VideoRecord { codec, geometry: self.source, frames, _slot: slot, _bytes: permit })
            } => admitted?,
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(Admitted::Cancelled),
            sent = self.video.send(record) => sent.map_err(|_| ViewerError::Closed)?,
        }
        Ok(Admitted::Queued)
    }

    /// Follows the peer to another display. Records already admitted keep the
    /// geometry they were admitted under, so the feeder reopens its decoder at
    /// the first record of the new display.
    pub fn switch_display(&mut self, display: &SwitchDisplay) -> Result<(), ViewerError> {
        if display.width <= 0 || display.height <= 0 || display.display < 0 {
            return Err(ViewerError::InvalidPeerGeometry);
        }
        self.source = Geometry {
            display: display.display,
            x: display.x,
            y: display.y,
            width: display.width,
            height: display.height,
        };
        Ok(())
    }
}

/// The feeder's half: the only owner of the native decoder.
pub struct VideoFeed<H: VideoOwner> {
    owner: Arc<H>,
    video: mpsc::Receiver<VideoRecord>,
    caps: Decoders,
}

impl<H: VideoOwner> VideoFeed<H> {
    /// Feeds admitted records into the decoder until the session ends.
    ///
    /// Drive it to completion and never abort it: it owns the native decoder,
    /// and its blocking teardown is what confirms the Surface may be released.
    pub async fn run(self, lease: Arc<dyn SurfaceLease>) -> Result<(), ViewerError> {
        let Self {
            owner,
            mut video,
            caps,
        } = self;
        let mut current = None;
        let result = feed_loop(&*owner, &mut video, lease, &mut current, caps).await;
        if result.is_err() {
            owner.video_failed();
        }
        let teardown = close_decoder(&*owner, &mut current).await;
        teardown?;
        result
    }
}

async fn close_decoder<H: VideoOwner>(
    owner: &H,
    current: &mut Option<SurfaceDecoder>,
) -> Result<(), ViewerError> {
    let Some(decoder) = current.take() else {
        return Ok(());
    };
    let observer = decoder.observer();
    let closed = tokio::task::spawn_blocking(move || decoder.close())
        .await
        .map_err(|_| ViewerError::TaskFailed);
    let stats = observer.stats();
    if stats
        .as_ref()
        .is_ok_and(|stats| stats.cleanup() == CleanupVerdict::Confirmed)
    {
        // close() can carry an earlier codec/Stop error even though Destroy
        // succeeded. The worker's final ownership state is the reclamation proof,
        // and the seam states it as one verdict rather than as a pair of fields a
        // caller re-reads.
        owner.reclamation_unconfirmed().store(false, Ordering::Release);
    }
    owner.video_decoder_closed(stats.ok());
    closed?.map(|_| ()).map_err(ViewerError::Decoder)
}

async fn feed_loop<H: VideoOwner>(
    owner: &H,
    video: &mut mpsc::Receiver<VideoRecord>,
    lease: Arc<dyn SurfaceLease>,
    current: &mut Option<SurfaceDecoder>,
    caps: Decoders,
) -> Result<(), ViewerError> {
    let cancel = owner.cancellation();
    let mut contract = None;
    loop {
        let observer = current.as_ref().map(SurfaceDecoder::observer);
        let record = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            stopped = async {
                match observer { Some(observer) => observer.wait_stopped().await, None => std::future::pending().await }
            } => return Err(ViewerError::Decoder(stopped.err().unwrap_or(DecoderError::Closed))),
            record = video.recv() => match record { Some(record) => record, None => return Ok(()) },
        };
        let next = (record.codec, record.geometry);
        if contract != Some(next) {
            close_decoder(owner, current).await?;
            if cancel.is_cancelled() {
                return Ok(());
            }
            owner.video_phase("opening_decoder");
            // The client may not have bound its surface yet: on OpenHarmony the
            // UI creates it after it asks for the session, and the first frame
            // can arrive before that. Waiting here is what keeps a correct
            // client from losing its session to a race it cannot see, and the
            // open below still refuses a lease that never gets an id.
            //
            // A software VP8/VP9 decoder is the one path that does not hold for.
            // It has no Surface to be bound — a memory sink reports id 0 and
            // never changes it — and it decodes only because this process's
            // capability probe answered for that codec and the lease carries the
            // frame observer its pixels are published to. Exactly that pair skips
            // the wait, decided from the same evidence that admitted the record.
            // Every surface-backed backend — the hardware categories and a VPx
            // lease with no observer, which `open` refuses as `InvalidConfig` —
            // keeps the F1 rule and the wait unchanged.
            let software_into_observer = matches!(next.0, VideoCodec::Vp8 | VideoCodec::Vp9)
                && caps.covers(next.0)
                && lease.frame_observer().is_some();
            if !software_into_observer && !lease.is_ready() {
                owner.video_phase("awaiting_surface");
                let waiting = async {
                    while !lease.is_ready() {
                        if cancel.is_cancelled() {
                            return false;
                        }
                        tokio::time::sleep(SURFACE_POLL).await;
                    }
                    true
                };
                if tokio::time::timeout(SURFACE_WAIT, waiting).await != Ok(true) {
                    owner.reclamation_unconfirmed().store(false, Ordering::Release);
                    return Err(ViewerError::Decoder(DecoderError::InvalidConfig));
                }
                owner.video_phase("opening_decoder");
            }
            let lease = lease.clone();
            owner.reclamation_unconfirmed().store(true, Ordering::Release);
            let opened = tokio::task::spawn_blocking(move || {
                SurfaceDecoder::open(
                    DecoderConfig {
                        codec: next.0,
                        width: next.1.width,
                        height: next.1.height,
                        // One AU may be inside PushInputBuffer while one waits
                        // for an input callback; do not build a stale decode tail.
                        max_queued_units: 2,
                        max_queued_bytes: VIDEO_BYTES,
                    },
                    lease,
                )
            })
            .await
            .map_err(|_| ViewerError::TaskFailed)?;
            let decoder = match opened {
                Ok(decoder) => decoder,
                Err(failure) => {
                    // The backend's own verdict, read as one field instead of
                    // re-deciding from its error variants: `Confirmed` means this
                    // open left nothing behind, so the Surface stays releasable,
                    // while `Unconfirmed` keeps the flag set because a
                    // quarantining teardown or a worker that did not return may
                    // still own the codec, its buffers and the lease.
                    if failure.cleanup == CleanupVerdict::Confirmed {
                        owner.reclamation_unconfirmed().store(false, Ordering::Release);
                    }
                    return Err(ViewerError::Decoder(failure.error));
                }
            };
            // Keep ownership even if close arrived during the blocking open; the
            // outer feeder will always run blocking teardown, never drop on IO.
            let observer = decoder.observer();
            *current = Some(decoder);
            owner.video_decoder_opened(next.0, next.1, observer);
            contract = Some(next);
        }
        let decoder = current.as_ref().ok_or(ViewerError::Closed)?;
        // Keep both record permits until its complete FIFO group has crossed
        // decoder admission. Each AU also retains decoder in-progress quota.
        for frame in record.frames {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let pts_us = frame
                .pts
                .checked_mul(1000)
                .ok_or(ViewerError::TimestampOverflow)?;
            let unit = AccessUnit {
                bytes: frame.data.to_vec(),
                pts_us,
                kind: AccessUnitKind::Frame { key: frame.key },
            };
            if let Err(rejected) = decoder.submit_cancellable(unit, cancel).await {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                return Err(ViewerError::Decoder(rejected.reason));
            }
        }
    }
}
