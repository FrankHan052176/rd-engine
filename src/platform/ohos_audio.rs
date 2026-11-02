//! OHOS audio output sink: an `OH_AudioRenderer` that pulls PCM through its
//! write-data callback.
//!
//! This module owns exactly one thing — the platform end of desktop remote
//! audio playback: a native renderer is created and started in
//! [`AudioRenderer::new`], bounded interleaved float PCM is admitted with
//! [`AudioRenderer::push`], and the native callback thread drains that queue into
//! the buffer the system hands it. Opus, the transport, the Viewer and both
//! bridges are elsewhere; so are capture, voice and camera audio, which this
//! sink neither opens nor touches.
//!
//! # Format
//!
//! The stream is configured as `AUDIOSTREAM_SAMPLE_S16LE` + raw PCM at the rate
//! and channel count the caller names (1 or 2), and the core hands over
//! interleaved `f32` samples that are converted with saturation on admission.
//! `AUDIOSTREAM_SAMPLE_F32LE` exists but only since API 17 (see
//! `native_audiostream_base.h`), while `S16LE` is API 10, so this sink does not
//! depend on an API 17 device. The callback setter used here
//! (`OH_AudioStreamBuilder_SetRendererWriteDataCallback`) is API 12 and current;
//! the deprecated `OH_AudioRenderer_Callbacks` struct is not bound.
//!
//! Once the native stream exists, its real sampling rate and channel count are
//! read back and must equal the requested ones. A stream the device
//! re-configured would play at the wrong pitch, and this sink does no
//! resampling, so such a stream is refused at creation instead.
//!
//! # Queue and backpressure
//!
//! The queue holds 200 ms of interleaved samples for the actual rate and channel
//! count and is allocated once, when the renderer is created. `push` admits a
//! whole chunk or nothing: a chunk that does not fit is answered with
//! [`RendererError::Backpressure`] and counted, so a caller cannot mistake a full
//! queue for queued audio. Nothing grows, nothing is dropped silently, and
//! admission never waits on the device. Queued means queued — [`AudioRenderer::stats`]
//! counts admitted samples and samples the native callback really consumed apart.
//!
//! The callback never allocates and never waits: it clears the native buffer,
//! then `try_lock`s the queue. If the producer happens to hold it for its
//! bounded copy, the callback plays silence and counts a starved callback. A
//! buffer the queue cannot fill is zero-filled past the queued samples — normal
//! renderer silence, not evidence that anything was decoded.
//!
//! # Ownership and failure
//!
//! The native callback's user data is one `Arc<Shared>` payload, kept alive by
//! the renderer until `OH_AudioRenderer_Release` returns success. Only then can
//! the native side no longer reach it. `close` stops and releases synchronously
//! and reports what the native calls actually returned:
//!
//! * release succeeded — the stream is reclaimed and the callback state is
//!   dropped here; a failing `OH_AudioRenderer_Stop` is reported as its own
//!   native error rather than folded into that answer;
//! * release failed — the stream object and the callback state are both
//!   retained for the life of the process, because a failed release proves
//!   nothing about further callbacks. That answer is
//!   [`RendererError::ReleaseUnconfirmed`], so the caller must not report the
//!   sink as released. Every later `close` of that renderer repeats the same
//!   answer: nothing is retried, and a repeated call cannot turn an unconfirmed
//!   reclamation into a success.
//!
//! The first unconfirmed release also closes creation for the rest of the
//! process ([`RendererError::CreationGateClosed`]): a sink that cannot reclaim
//! one stream must not keep building more of them, which is what an unlimited
//! create/fail/destroy loop would do. What stays retained is therefore one
//! callback state per renderer that was already open when the gate closed —
//! not a fixed number — and a stream that was open then still has its own state
//! kept if its release fails too.
//!
//! A failure while creating, configuring, verifying or starting the stream
//! destroys the builder it owns and releases the renderer it already has. An
//! unconfirmed release from that cleanup is the answer `new` returns, because
//! the caller has to know that a native stream may still reach its callback
//! state; only when the cleanup reclaimed everything is the original cause
//! reported.
//!
//! Off device (no `target_env = "ohos"`) nothing is fabricated: `new` returns
//! [`RendererError::UnsupportedPlatform`] and no instance can exist.

#[cfg(any(target_env = "ohos", test))]
use std::sync::{
    Arc, Mutex, TryLockError,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Queue depth, in milliseconds of interleaved PCM.
#[cfg(any(target_env = "ohos", test))]
const QUEUE_MILLIS: u32 = 200;
/// Channel counts this sink configures: mono and stereo share one interleaved
/// layout, anything wider needs a channel layout that is not set here.
#[cfg(any(target_env = "ohos", test))]
const MAX_CHANNELS: u16 = 2;
/// Highest sample rate a queue is sized for. The SDK documents no upper bound,
/// so this only refuses values no Opus stream and no device reports.
#[cfg(any(target_env = "ohos", test))]
const MAX_RATE: u32 = 384_000;
/// Scale used to convert `f32` to `i16`: full scale maps to `±32767`, so `-1.0`
/// is `-32767` rather than the asymmetric `-32768`.
#[cfg(any(target_env = "ohos", test))]
const S16_SCALE: f32 = 32_767.0;

/// Why the sink refused, or which native call failed.
///
/// Every variant that names a native `api` carries the code that call returned;
/// no code is invented and no failure is folded into a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendererError {
    /// Built for a platform without the `ohaudio` sink.
    UnsupportedPlatform,
    /// The requested rate or channel count is outside what this sink converts.
    InvalidFormat,
    /// The queue for that rate and channel count could not be allocated.
    OutOfMemory,
    /// The native stream runs at a format this sink did not ask for, so playing
    /// it would mean resampling.
    FormatMismatch {
        requested_rate: u32,
        requested_channels: u16,
        actual_rate: i32,
        actual_channels: i32,
    },
    /// The bounded queue has no room for the whole chunk; nothing was admitted.
    Backpressure,
    /// This renderer was already closed, so nothing accepts PCM any more.
    Closed,
    /// A native call reported failure. `code` is its `OH_AudioStream_Result`.
    Native { api: &'static str, code: i32 },
    /// A native call returned success but no object, which its contract forbids.
    NullHandle { api: &'static str },
    /// Teardown was attempted but reclamation is unconfirmed: the stream and the
    /// callback state are retained, and the caller must not report the sink as
    /// released.
    ReleaseUnconfirmed { api: &'static str, code: i32 },
    /// An earlier teardown is still unconfirmed, so this sink refuses to create
    /// another stream. `api` and `code` are the native call whose failure keeps a
    /// stream and its callback state alive; a new stream could not be reclaimed
    /// either.
    CreationGateClosed { api: &'static str, code: i32 },
}

impl std::fmt::Display for RendererError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "this platform has no OHOS audio renderer sink")
            }
            Self::InvalidFormat => write!(
                f,
                "sample rate or channel count outside the 1..=2 channel OHOS sink range"
            ),
            Self::OutOfMemory => write!(f, "the PCM queue could not be allocated"),
            Self::FormatMismatch {
                requested_rate,
                requested_channels,
                actual_rate,
                actual_channels,
            } => write!(
                f,
                "OHOS created a {actual_rate} Hz/{actual_channels} ch stream for the requested \
                 {requested_rate} Hz/{requested_channels} ch one"
            ),
            Self::Backpressure => write!(f, "the OHOS audio queue is full"),
            Self::Closed => write!(f, "the OHOS audio renderer is closed"),
            Self::Native { api, code } => write!(f, "{api} failed with OHOS code {code}"),
            Self::NullHandle { api } => write!(f, "{api} succeeded without returning an object"),
            Self::ReleaseUnconfirmed { api, code } => write!(
                f,
                "{api} failed with OHOS code {code}; the stream and its callback state are \
                 retained and reclamation is unconfirmed"
            ),
            Self::CreationGateClosed { api, code } => write!(
                f,
                "no OHOS audio stream is created after {api} failed with OHOS code {code}: a \
                 retained stream may still reach its callback state"
            ),
        }
    }
}

impl std::error::Error for RendererError {}

/// What the sink counted, kept apart on purpose: admitted PCM is not played PCM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RendererStats {
    /// Interleaved samples admitted by `push`.
    pub queued_samples: u64,
    /// Samples a native callback actually copied into its buffer.
    pub played_samples: u64,
    /// Callbacks that ran short of queued PCM (or could not take the queue) and
    /// therefore emitted silence past the queued samples.
    pub starved_callbacks: u64,
    /// `push` calls answered with `Backpressure`.
    pub rejected_pushes: u64,
}

/// Interleaved S16 ring buffer with a fixed capacity.
///
/// Allocated once and never resized: the callback only moves samples.
#[cfg(any(target_env = "ohos", test))]
struct Queue {
    samples: Vec<i16>,
    head: usize,
    len: usize,
}

#[cfg(any(target_env = "ohos", test))]
impl Queue {
    fn new(rate: u32, channels: u16) -> Result<Self, RendererError> {
        // 200 ms of frames, then the interleaved samples those frames carry.
        let frames = (u64::from(rate) * u64::from(QUEUE_MILLIS) / 1000) as usize;
        let capacity = frames * usize::from(channels);
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(capacity)
            .map_err(|_| RendererError::OutOfMemory)?;
        samples.resize(capacity, 0);
        Ok(Self {
            samples,
            head: 0,
            len: 0,
        })
    }

    fn capacity(&self) -> usize {
        self.samples.len()
    }

    fn space(&self) -> usize {
        self.capacity() - self.len
    }

    /// Admits `pcm` entirely or not at all: a partially admitted chunk would be
    /// audio the caller believes it queued whole.
    fn admit(&mut self, pcm: &[f32]) -> bool {
        if pcm.len() > self.space() {
            return false;
        }
        let capacity = self.capacity();
        let mut tail = self.head + self.len;
        if tail >= capacity {
            tail -= capacity;
        }
        for &sample in pcm {
            self.samples[tail] = to_s16(sample);
            tail += 1;
            if tail == capacity {
                tail = 0;
            }
        }
        self.len += pcm.len();
        true
    }

    /// Copies the queued prefix into `out` and returns how many samples that
    /// was; the rest of `out` is left for the caller to fill.
    fn drain_into(&mut self, out: &mut [i16]) -> usize {
        let taken = out.len().min(self.len);
        let capacity = self.capacity();
        let head_run = taken.min(capacity - self.head);
        out[..head_run].copy_from_slice(&self.samples[self.head..self.head + head_run]);
        let wrapped = taken - head_run;
        if wrapped > 0 {
            out[head_run..taken].copy_from_slice(&self.samples[..wrapped]);
            self.head = wrapped;
        } else {
            self.head += head_run;
            if self.head == capacity {
                self.head = 0;
            }
        }
        self.len -= taken;
        taken
    }
}

/// Converts one interleaved sample with saturation instead of wrap-around.
/// A NaN has no ordering, so it lands on silence rather than an invented value.
#[cfg(any(target_env = "ohos", test))]
fn to_s16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * S16_SCALE) as i16
}

#[cfg(any(target_env = "ohos", test))]
fn validate_format(rate: u32, channels: u16) -> Result<(), RendererError> {
    if rate < 8_000 || rate > MAX_RATE || channels == 0 || channels > MAX_CHANNELS {
        return Err(RendererError::InvalidFormat);
    }
    Ok(())
}

/// The answer for an `open` that failed while it already owned something native:
/// a cleanup that could not reclaim what it owned outranks `cause`, because the
/// caller has to know that a native object may still be reachable. A cleanup
/// that reclaimed everything leaves `cause` — the reason the stream was refused
/// — as the answer.
#[cfg(any(target_env = "ohos", test))]
fn open_failure(cleanup: Result<(), RendererError>, cause: RendererError) -> RendererError {
    match cleanup {
        Err(error @ RendererError::ReleaseUnconfirmed { .. }) => error,
        _ if matches!(&cause, RendererError::ReleaseUnconfirmed { .. }) => cause,
        Err(error) => error,
        Ok(()) => cause,
    }
}

/// The state the native callback thread and the producer thread share.
///
/// Only this allocation escapes to C, and only as an opaque user-data pointer;
/// every callback access goes through it, never through the renderer.
#[cfg(any(target_env = "ohos", test))]
struct Shared {
    queue: Mutex<Queue>,
    queued: AtomicU64,
    played: AtomicU64,
    starved: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicBool,
}

#[cfg(any(target_env = "ohos", test))]
impl Shared {
    fn new(rate: u32, channels: u16) -> Result<Arc<Self>, RendererError> {
        Ok(Arc::new(Self {
            queue: Mutex::new(Queue::new(rate, channels)?),
            queued: AtomicU64::new(0),
            played: AtomicU64::new(0),
            starved: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }))
    }

    /// Bounded admission. The lock is held for one conversion pass over the
    /// chunk and never while waiting on the device, so this cannot stall
    /// playback.
    fn admit(&self, pcm: &[f32]) -> Result<(), RendererError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(RendererError::Closed);
        }
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !queue.admit(pcm) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RendererError::Backpressure);
        }
        self.queued.fetch_add(pcm.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Fills `out` from the queue, or leaves it untouched when the producer is
    /// inside its bounded copy. Never blocks, never allocates.
    fn callback_fill(&self, out: &mut [i16]) -> usize {
        let filled = match self.queue.try_lock() {
            Ok(mut queue) => queue.drain_into(out),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().drain_into(out),
            Err(TryLockError::WouldBlock) => {
                self.starved.fetch_add(1, Ordering::Relaxed);
                return 0;
            }
        };
        if filled < out.len() {
            self.starved.fetch_add(1, Ordering::Relaxed);
        }
        self.played.fetch_add(filled as u64, Ordering::Relaxed);
        filled
    }

    fn stats(&self) -> RendererStats {
        RendererStats {
            queued_samples: self
                .queued
                .load(Ordering::Relaxed)
                .saturating_sub(self.played.load(Ordering::Relaxed)),
            played_samples: self.played.load(Ordering::Relaxed),
            starved_callbacks: self.starved.load(Ordering::Relaxed),
            rejected_pushes: self.rejected.load(Ordering::Relaxed),
        }
    }

    /// Refuses further PCM before the native stream is taken down, so a caller
    /// racing the close cannot hand over samples nothing will ever play.
    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

/// One OHOS audio output stream.
///
/// Created started. `Send` because the whole renderer moves to the one thread
/// that owns playback; not `Sync`, because the native stream is used through
/// `&self`/`&mut self` on that owner while the callback thread touches nothing
/// but its own queue.
pub struct AudioRenderer {
    #[cfg(target_env = "ohos")]
    inner: native::Renderer,
}

impl AudioRenderer {
    /// Creates and starts a real native renderer for interleaved PCM at
    /// `sample_rate` Hz and `channels` channels.
    pub fn new(sample_rate: u32, channels: u16) -> Result<Self, RendererError> {
        #[cfg(target_env = "ohos")]
        {
            native::Renderer::open(sample_rate, channels).map(|inner| Self { inner })
        }
        #[cfg(not(target_env = "ohos"))]
        {
            let _ = (sample_rate, channels);
            Err(RendererError::UnsupportedPlatform)
        }
    }

    /// Admits one chunk of interleaved `f32` samples. `Ok` means queued, not
    /// played; a chunk that does not fit the bounded queue is refused whole.
    pub fn push(&self, pcm: &[f32]) -> Result<(), RendererError> {
        #[cfg(target_env = "ohos")]
        {
            self.inner.push(pcm)
        }
        #[cfg(not(target_env = "ohos"))]
        {
            let _ = pcm;
            Err(RendererError::UnsupportedPlatform)
        }
    }

    /// True while the native stream is in `AUDIOSTREAM_STATE_RUNNING`, read back
    /// from the system rather than remembered from `Start`.
    pub fn is_active(&self) -> Result<bool, RendererError> {
        #[cfg(target_env = "ohos")]
        {
            self.inner.is_active()
        }
        #[cfg(not(target_env = "ohos"))]
        {
            Err(RendererError::UnsupportedPlatform)
        }
    }

    /// Admitted and consumed sample counts, starved callbacks and refused pushes.
    pub fn stats(&self) -> Result<RendererStats, RendererError> {
        #[cfg(target_env = "ohos")]
        {
            Ok(self.inner.stats())
        }
        #[cfg(not(target_env = "ohos"))]
        {
            Err(RendererError::UnsupportedPlatform)
        }
    }

    /// Stops and releases the native stream now. Call it from a blocking worker:
    /// the native stop waits for the stream. A second call repeats the first
    /// answer — an unconfirmed reclamation stays unconfirmed — and never retries
    /// `Stop` or `Release`.
    pub fn close(&mut self) -> Result<(), RendererError> {
        #[cfg(target_env = "ohos")]
        {
            self.inner.close()
        }
        #[cfg(not(target_env = "ohos"))]
        {
            Err(RendererError::UnsupportedPlatform)
        }
    }
}

#[cfg(target_env = "ohos")]
mod native {
    use std::{
        ffi::c_void,
        ptr, slice,
        sync::{Arc, LazyLock, Mutex},
    };

    use super::{RendererError, RendererStats, Shared};

    /// `AUDIOSTREAM_SUCCESS`.
    const SUCCESS: i32 = 0;
    /// `AUDIOSTREAM_TYPE_RENDERER`.
    const TYPE_RENDERER: i32 = 1;
    /// `AUDIOSTREAM_SAMPLE_S16LE` (since API 10; `F32LE` is API 17).
    const SAMPLE_S16LE: i32 = 1;
    /// `AUDIOSTREAM_ENCODING_TYPE_RAW`.
    const ENCODING_RAW: i32 = 0;
    /// `AUDIOSTREAM_USAGE_MUSIC`: remote desktop audio is media playback, not a
    /// call or a voice message.
    const USAGE_MUSIC: i32 = 1;
    /// `AUDIOSTREAM_LATENCY_MODE_NORMAL`: the mode that needs no fast-path
    /// device support.
    const LATENCY_NORMAL: i32 = 0;
    /// `AUDIOSTREAM_STATE_RUNNING`.
    const STATE_RUNNING: i32 = 2;
    /// `AUDIOSTREAM_STATE_INVALID`.
    const STATE_INVALID: i32 = -1;
    /// `AUDIO_DATA_CALLBACK_RESULT_VALID`: the filled buffer is played.
    const CALLBACK_VALID: i32 = 0;
    /// `AUDIO_DATA_CALLBACK_RESULT_INVALID`: the buffer content is dropped.
    const CALLBACK_INVALID: i32 = -1;

    /// `OH_AudioRendererStruct`: opaque in the SDK.
    #[repr(C)]
    struct Stream {
        _opaque: [u8; 0],
    }

    /// `OH_AudioStreamBuilderStruct`: opaque in the SDK.
    #[repr(C)]
    struct StreamBuilder {
        _opaque: [u8; 0],
    }

    /// `OH_AudioRenderer_OnWriteDataCallback`. The SDK's C enum result is an
    /// `int32_t`; `VALID` keeps the filled buffer, `INVALID` discards it.
    type WriteDataCallback =
        unsafe extern "C" fn(*mut Stream, *mut c_void, *mut c_void, i32) -> i32;

    // Signatures and result codes are from the installed
    // ohaudio/native_audiostream_base.h, native_audiostreambuilder.h and
    // native_audiorenderer.h; only APIs the target API level provides are bound.
    #[link(name = "ohaudio")]
    unsafe extern "C" {
        fn OH_AudioStreamBuilder_Create(builder: *mut *mut StreamBuilder, kind: i32) -> i32;
        fn OH_AudioStreamBuilder_Destroy(builder: *mut StreamBuilder) -> i32;
        fn OH_AudioStreamBuilder_SetSamplingRate(builder: *mut StreamBuilder, rate: i32) -> i32;
        fn OH_AudioStreamBuilder_SetChannelCount(
            builder: *mut StreamBuilder,
            channel_count: i32,
        ) -> i32;
        fn OH_AudioStreamBuilder_SetSampleFormat(builder: *mut StreamBuilder, format: i32) -> i32;
        fn OH_AudioStreamBuilder_SetEncodingType(
            builder: *mut StreamBuilder,
            encoding_type: i32,
        ) -> i32;
        fn OH_AudioStreamBuilder_SetLatencyMode(
            builder: *mut StreamBuilder,
            latency_mode: i32,
        ) -> i32;
        fn OH_AudioStreamBuilder_SetRendererInfo(builder: *mut StreamBuilder, usage: i32) -> i32;
        fn OH_AudioStreamBuilder_SetRendererWriteDataCallback(
            builder: *mut StreamBuilder,
            callback: Option<WriteDataCallback>,
            user_data: *mut c_void,
        ) -> i32;
        fn OH_AudioStreamBuilder_GenerateRenderer(
            builder: *mut StreamBuilder,
            renderer: *mut *mut Stream,
        ) -> i32;
        fn OH_AudioRenderer_Start(renderer: *mut Stream) -> i32;
        fn OH_AudioRenderer_Stop(renderer: *mut Stream) -> i32;
        fn OH_AudioRenderer_Release(renderer: *mut Stream) -> i32;
        fn OH_AudioRenderer_GetCurrentState(renderer: *mut Stream, state: *mut i32) -> i32;
        fn OH_AudioRenderer_GetSamplingRate(renderer: *mut Stream, rate: *mut i32) -> i32;
        fn OH_AudioRenderer_GetChannelCount(renderer: *mut Stream, channel_count: *mut i32) -> i32;
    }

    fn check(api: &'static str, code: i32) -> Result<(), RendererError> {
        if code == SUCCESS {
            Ok(())
        } else {
            Err(RendererError::Native { api, code })
        }
    }

    /// Callback states whose native release failed, plus the reason creation was
    /// closed for the rest of the process.
    ///
    /// A failed `Release` proves nothing about further callbacks, so the `Arc`
    /// backing that stream's user data is kept instead of freed: the native side
    /// may still call into it. The first failure also closes creation for good,
    /// because a sink that cannot reclaim one stream must not keep building new
    /// ones — that is what an unlimited create/fail/destroy loop would do. The
    /// retained set is therefore bounded by the renderers that were already open
    /// when the gate closed, not by a fixed cap.
    struct Retained {
        /// The native call and result code that closed creation, set once.
        closed_by: Option<(&'static str, i32)>,
        /// One `Arc` per failed release, held only so the callback state outlives
        /// a reclamation that never succeeded. Nothing reads it.
        _unreclaimed: Vec<Arc<Shared>>,
    }

    static RETAINED: LazyLock<Mutex<Retained>> = LazyLock::new(|| {
        Mutex::new(Retained {
            closed_by: None,
            _unreclaimed: Vec::new(),
        })
    });

    fn lock_retained() -> std::sync::MutexGuard<'static, Retained> {
        RETAINED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The admission gate every new stream passes: once one teardown is
    /// unconfirmed, no further renderer is built.
    ///
    /// The check runs under the retained state's lock, so a failure that lands
    /// after it can only come from a stream that was already open — after the
    /// gate closes, no attempt adds to the retained set.
    fn admission() -> Result<(), RendererError> {
        match lock_retained().closed_by {
            None => Ok(()),
            Some((api, code)) => Err(RendererError::CreationGateClosed { api, code }),
        }
    }

    /// Keeps `shared` for the rest of the process and closes creation, recording
    /// the native failure that made its stream unreclaimable.
    fn retain_unreclaimed(api: &'static str, code: i32, shared: &Arc<Shared>) {
        let mut retained = lock_retained();
        retained.closed_by.get_or_insert((api, code));
        retained._unreclaimed.push(Arc::clone(shared));
    }

    /// Stops and releases one native stream and reports what happened to the
    /// callback state that went with it.
    ///
    /// The caller's own `Arc` is dropped after this returns; on a failed release
    /// a clone is retained process-wide, so the user-data allocation outlives the
    /// call. Nothing is retried.
    fn teardown(handle: *mut Stream, shared: &Arc<Shared>) -> Result<(), RendererError> {
        let stopped = unsafe { OH_AudioRenderer_Stop(handle) };
        let released = unsafe { OH_AudioRenderer_Release(handle) };
        if released != SUCCESS {
            retain_unreclaimed("OH_AudioRenderer_Release", released, shared);
            return Err(RendererError::ReleaseUnconfirmed {
                api: "OH_AudioRenderer_Release",
                code: released,
            });
        }
        // Release succeeded, so the stream is gone and no callback can be
        // running or arrive later: the caller may drop the user data now. A
        // failing `Stop` before it is still reported as its own error, not as an
        // unconfirmed release.
        check("OH_AudioRenderer_Stop", stopped)
    }

    /// The callback the system calls for every buffer it needs filled.
    ///
    /// No allocation, no blocking, no panic path: the queue logic lives in
    /// `Shared::callback_fill`, this only validates the native buffer.
    unsafe extern "C" fn on_write_data(
        _renderer: *mut Stream,
        user_data: *mut c_void,
        audio_data: *mut c_void,
        audio_data_size: i32,
    ) -> i32 {
        if user_data.is_null() || audio_data.is_null() || audio_data_size <= 0 {
            return CALLBACK_INVALID;
        }
        let bytes = audio_data_size as usize;
        // `is_aligned` is stable on raw pointers; `is_aligned_to` is not.
        if bytes % 2 != 0 || !audio_data.cast::<i16>().is_aligned() {
            // Not an S16 buffer this sink can fill; ask the system to drop it
            // rather than describe memory it did not write.
            return CALLBACK_INVALID;
        }
        // SAFETY: the SDK hands over `audio_data_size` writable bytes for this
        // callback; every byte is cleared before any of it is written again.
        unsafe { ptr::write_bytes(audio_data.cast::<u8>(), 0, bytes) };
        // SAFETY: same buffer, now a whole number of aligned S16 samples that
        // borrow it only for this call.
        let out = unsafe { slice::from_raw_parts_mut(audio_data.cast::<i16>(), bytes / 2) };
        // SAFETY: `user_data` is the `Arc::as_ptr` of the state the owning
        // renderer keeps alive until a successful release.
        let shared = unsafe { &*(user_data as *const Shared) };
        shared.callback_fill(out);
        CALLBACK_VALID
    }

    /// A builder that destroys itself however configuration ends.
    struct Builder(*mut StreamBuilder);

    impl Builder {
        fn create() -> Result<Self, RendererError> {
            let mut builder = ptr::null_mut();
            check("OH_AudioStreamBuilder_Create", unsafe {
                OH_AudioStreamBuilder_Create(&mut builder, TYPE_RENDERER)
            })?;
            if builder.is_null() {
                return Err(RendererError::NullHandle {
                    api: "OH_AudioStreamBuilder_Create",
                });
            }
            Ok(Self(builder))
        }

        fn generate(&self) -> Result<*mut Stream, RendererError> {
            let mut handle = ptr::null_mut();
            check("OH_AudioStreamBuilder_GenerateRenderer", unsafe {
                OH_AudioStreamBuilder_GenerateRenderer(self.0, &mut handle)
            })?;
            if handle.is_null() {
                return Err(RendererError::NullHandle {
                    api: "OH_AudioStreamBuilder_GenerateRenderer",
                });
            }
            Ok(handle)
        }

        /// Destroys the builder and reports what the SDK returned: a failing
        /// destruction is a real error, not a clean one.
        fn destroy(self, shared: &Arc<Shared>) -> Result<(), RendererError> {
            let builder = self.0;
            // `Drop` must not destroy it a second time.
            std::mem::forget(self);
            let code = unsafe { OH_AudioStreamBuilder_Destroy(builder) };
            if code != SUCCESS {
                // The builder may still retain its callback data. Its failure
                // cannot be reported as a refusal that allocated nothing.
                retain_unreclaimed("OH_AudioStreamBuilder_Destroy", code, shared);
                return Err(RendererError::ReleaseUnconfirmed {
                    api: "OH_AudioStreamBuilder_Destroy",
                    code,
                });
            }
            Ok(())
        }
    }

    impl Drop for Builder {
        fn drop(&mut self) {
            // Backstop for a path that returns before `destroy`: the SDK requires
            // this once the builder is done, and the renderer it generated is
            // independent of it. A `Drop` cannot carry the answer, so every
            // failure path in `open` calls `destroy` itself.
            unsafe { OH_AudioStreamBuilder_Destroy(self.0) };
        }
    }

    /// A generated, not yet started stream plus the callback state bound to it.
    ///
    /// No `Drop`: every path in `open` releases it through `discard`, so the
    /// teardown answer reaches the caller instead of being dropped here.
    struct Pending {
        handle: *mut Stream,
        shared: Arc<Shared>,
    }

    impl Pending {
        /// Reads back the format the native stream actually runs at.
        fn format(&self) -> Result<(i32, i32), RendererError> {
            let mut rate = 0;
            check("OH_AudioRenderer_GetSamplingRate", unsafe {
                OH_AudioRenderer_GetSamplingRate(self.handle, &mut rate)
            })?;
            let mut channels = 0;
            check("OH_AudioRenderer_GetChannelCount", unsafe {
                OH_AudioRenderer_GetChannelCount(self.handle, &mut channels)
            })?;
            Ok((rate, channels))
        }

        /// Releases the stream this pending open owns and reports what the native
        /// calls returned; an unconfirmed release is retained, not freed.
        fn discard(mut self) -> Result<(), RendererError> {
            let handle = std::mem::replace(&mut self.handle, ptr::null_mut());
            teardown(handle, &self.shared)
        }

        fn start(self) -> Result<Renderer, RendererError> {
            let handle = self.handle;
            match check("OH_AudioRenderer_Start", unsafe {
                OH_AudioRenderer_Start(handle)
            }) {
                Ok(()) => Ok(Renderer {
                    state: State::Live(handle),
                    shared: self.shared,
                }),
                // A stream that never started is still taken down, and an
                // unconfirmed release is the answer the caller has to see.
                Err(cause) => Err(super::open_failure(self.discard(), cause)),
            }
        }
    }

    /// A renderer's native stream, or the answer its close already produced.
    enum State {
        Live(*mut Stream),
        /// `close` ran. Its answer is kept so every later `close` repeats what
        /// the native calls really returned instead of reporting a success.
        Closed(Result<(), RendererError>),
    }

    pub(super) struct Renderer {
        state: State,
        shared: Arc<Shared>,
    }

    // SAFETY: the native handle is reached only through `&self`/`&mut self` and
    // the type is not `Sync`, so moving it transfers the sole access; the
    // callback thread touches only the `Sync` state behind the `Arc`.
    unsafe impl Send for Renderer {}

    /// Applies every builder setting this sink requires. Nothing native exists
    /// yet, so a failure here owns the builder and nothing else.
    fn configure(
        builder: &Builder,
        rate: u32,
        channels: u16,
        user_data: *mut c_void,
    ) -> Result<(), RendererError> {
        check("OH_AudioStreamBuilder_SetSamplingRate", unsafe {
            OH_AudioStreamBuilder_SetSamplingRate(builder.0, rate as i32)
        })?;
        check("OH_AudioStreamBuilder_SetChannelCount", unsafe {
            OH_AudioStreamBuilder_SetChannelCount(builder.0, i32::from(channels))
        })?;
        check("OH_AudioStreamBuilder_SetSampleFormat", unsafe {
            OH_AudioStreamBuilder_SetSampleFormat(builder.0, SAMPLE_S16LE)
        })?;
        check("OH_AudioStreamBuilder_SetEncodingType", unsafe {
            OH_AudioStreamBuilder_SetEncodingType(builder.0, ENCODING_RAW)
        })?;
        check("OH_AudioStreamBuilder_SetLatencyMode", unsafe {
            OH_AudioStreamBuilder_SetLatencyMode(builder.0, LATENCY_NORMAL)
        })?;
        check("OH_AudioStreamBuilder_SetRendererInfo", unsafe {
            OH_AudioStreamBuilder_SetRendererInfo(builder.0, USAGE_MUSIC)
        })?;
        // The user data is the `Arc` payload; the system keeps this pointer and
        // calls it until the stream is released, so it must outlive it.
        check(
            "OH_AudioStreamBuilder_SetRendererWriteDataCallback",
            unsafe {
                OH_AudioStreamBuilder_SetRendererWriteDataCallback(
                    builder.0,
                    Some(on_write_data),
                    user_data,
                )
            },
        )
    }

    impl Renderer {
        pub(super) fn open(rate: u32, channels: u16) -> Result<Self, RendererError> {
            super::validate_format(rate, channels)?;
            // A retained teardown means a native stream may still call its user
            // data; a sink that cannot reclaim one stream builds no more.
            admission()?;
            let shared = Shared::new(rate, channels)?;
            let builder = Builder::create()?;
            let user_data = Arc::as_ptr(&shared).cast_mut().cast::<c_void>();
            if let Err(cause) = configure(&builder, rate, channels, user_data) {
                return Err(super::open_failure(builder.destroy(&shared), cause));
            }
            let handle = match builder.generate() {
                Ok(handle) => handle,
                Err(cause) => return Err(super::open_failure(builder.destroy(&shared), cause)),
            };
            // From here a generated stream owns the callback state.
            let pending = Pending { handle, shared };
            // The builder is independent of the stream it generated, but its
            // destruction is still a real call: a failure is reported rather
            // than dropped, and the stream it already produced is released.
            if let Err(cause) = builder.destroy(&pending.shared) {
                return Err(super::open_failure(pending.discard(), cause));
            }
            let (actual_rate, actual_channels) = match pending.format() {
                Ok(format) => format,
                Err(cause) => return Err(super::open_failure(pending.discard(), cause)),
            };
            if actual_rate != rate as i32 || actual_channels != i32::from(channels) {
                // A stream at a format this sink refused to play is released, not
                // played: it would run at the wrong pitch.
                let cause = RendererError::FormatMismatch {
                    requested_rate: rate,
                    requested_channels: channels,
                    actual_rate,
                    actual_channels,
                };
                return Err(super::open_failure(pending.discard(), cause));
            }
            pending.start()
        }

        pub(super) fn push(&self, pcm: &[f32]) -> Result<(), RendererError> {
            if let State::Closed(_) = &self.state {
                return Err(RendererError::Closed);
            }
            self.shared.admit(pcm)
        }

        pub(super) fn is_active(&self) -> Result<bool, RendererError> {
            let handle = match &self.state {
                State::Live(handle) => *handle,
                State::Closed(_) => return Err(RendererError::Closed),
            };
            let mut state = STATE_INVALID;
            check("OH_AudioRenderer_GetCurrentState", unsafe {
                OH_AudioRenderer_GetCurrentState(handle, &mut state)
            })?;
            Ok(state == STATE_RUNNING)
        }

        pub(super) fn stats(&self) -> RendererStats {
            self.shared.stats()
        }

        pub(super) fn close(&mut self) -> Result<(), RendererError> {
            let handle = match &mut self.state {
                State::Live(handle) => {
                    let handle = *handle;
                    // Refuses further PCM before the stream is taken down, even
                    // when the reclamation turns out to be unconfirmed.
                    self.shared.mark_closed();
                    handle
                }
                // Already closed: repeat what the native calls returned then.
                // Nothing is retried, and an unconfirmed release never becomes a
                // success here.
                State::Closed(answer) => return answer.clone(),
            };
            let answer = teardown(handle, &self.shared);
            self.state = State::Closed(answer.clone());
            answer
        }
    }

    impl Drop for Renderer {
        fn drop(&mut self) {
            // Only a stream that is still live is taken down here; a caller that
            // needs the answer calls `close`. An unconfirmed release is retained
            // by `teardown`, so the callback state outlives this drop.
            let handle = match &self.state {
                State::Live(handle) => *handle,
                State::Closed(_) => return,
            };
            self.shared.mark_closed();
            let _ = teardown(handle, &self.shared);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_boundaries_are_rejected() {
        assert!(validate_format(48_000, 2).is_ok());
        assert!(validate_format(8_000, 1).is_ok());
        assert_eq!(validate_format(0, 2), Err(RendererError::InvalidFormat));
        assert_eq!(validate_format(7_999, 1), Err(RendererError::InvalidFormat));
        assert_eq!(
            validate_format(MAX_RATE + 1, 1),
            Err(RendererError::InvalidFormat)
        );
        assert_eq!(
            validate_format(48_000, 0),
            Err(RendererError::InvalidFormat)
        );
        assert_eq!(
            validate_format(48_000, 3),
            Err(RendererError::InvalidFormat)
        );
    }

    #[test]
    fn conversion_saturates_and_nan_is_silence() {
        assert_eq!(to_s16(0.0), 0);
        assert_eq!(to_s16(1.0), 32_767);
        assert_eq!(to_s16(-1.0), -32_767);
        assert_eq!(to_s16(9.5), 32_767);
        assert_eq!(to_s16(f32::INFINITY), 32_767);
        assert_eq!(to_s16(f32::NEG_INFINITY), -32_767);
        assert_eq!(to_s16(f32::NAN), 0);
        assert_eq!(to_s16(0.5), 16_383);
    }

    #[test]
    fn admission_is_bounded_by_two_hundred_milliseconds() {
        let shared = Shared::new(48_000, 2).expect("queue");
        // 200 ms at 48 kHz stereo is 9600 frames, i.e. 19200 interleaved samples.
        let capacity = 19_200;
        shared.admit(&vec![0.5; capacity]).expect("exact fill");
        assert_eq!(shared.stats().queued_samples, capacity as u64);
        // A chunk that does not fit is refused whole, and counted.
        assert_eq!(shared.admit(&[0.5]), Err(RendererError::Backpressure));
        assert_eq!(shared.stats().rejected_pushes, 1);
        assert_eq!(shared.stats().queued_samples, capacity as u64);
        // Admission moves samples into the queue but consumes nothing.
        assert_eq!(shared.stats().played_samples, 0);
    }

    #[test]
    fn callback_fill_copies_queued_samples_and_counts_starvation() {
        let shared = Shared::new(8_000, 1).expect("queue");
        shared.admit(&[0.0, 0.25, -0.25, 1.0]).expect("admit");
        let mut out = [1i16; 10];
        assert_eq!(shared.callback_fill(&mut out), 4);
        assert_eq!(&out[..4], &[0, 8_191, -8_191, 32_767]);
        assert_eq!(shared.stats().played_samples, 4);
        assert_eq!(shared.stats().starved_callbacks, 1);
        // `queued_samples` is `admitted - played`, so consuming everything that
        // was admitted leaves nothing behind, even though this callback was
        // counted as starved for not filling the whole buffer.
        assert_eq!(shared.stats().queued_samples, 0);
        // Nothing is queued now, so a further callback is a starved one.
        assert_eq!(shared.callback_fill(&mut out), 0);
        assert_eq!(shared.stats().starved_callbacks, 2);
    }

    #[test]
    fn ring_wraps_and_keeps_order() {
        let mut queue = Queue::new(8_000, 1).expect("queue");
        let capacity = queue.capacity();
        assert!(queue.admit(&vec![0.0; capacity - 2]));
        let mut first = vec![0i16; capacity - 2];
        assert_eq!(queue.drain_into(&mut first), capacity - 2);
        // Refill across the end of the buffer and read it back in order.
        assert!(queue.admit(&[1.0, 0.5, 0.0, -0.5]));
        let mut out = vec![0i16; 4];
        assert_eq!(queue.drain_into(&mut out), 4);
        assert_eq!(out, vec![32_767, 16_383, 0, -16_383]);
        assert_eq!(queue.drain_into(&mut out), 0);
    }

    #[test]
    fn closed_renderer_refuses_pcm() {
        let shared = Shared::new(48_000, 2).expect("queue");
        shared.mark_closed();
        assert_eq!(shared.admit(&[0.0; 4]), Err(RendererError::Closed));
    }

    #[test]
    fn failed_open_reports_an_unreclaimed_cleanup_first() {
        let unconfirmed = RendererError::ReleaseUnconfirmed {
            api: "OH_AudioRenderer_Release",
            code: -1,
        };
        // A stream may still reach its callback state: that answer outranks the
        // reason the open failed.
        assert_eq!(
            open_failure(Err(unconfirmed.clone()), RendererError::InvalidFormat),
            unconfirmed
        );
        // A cleanup that reclaimed everything leaves the cause.
        assert_eq!(
            open_failure(Ok(()), RendererError::Backpressure),
            RendererError::Backpressure
        );
        // A release that succeeded but did not stop cleanly is its own error.
        let stop = RendererError::Native {
            api: "OH_AudioRenderer_Stop",
            code: -2,
        };
        assert_eq!(
            open_failure(Err(stop.clone()), RendererError::OutOfMemory),
            stop.clone()
        );
        // Releasing a generated stream cannot clear an unreclaimed builder.
        let builder = RendererError::ReleaseUnconfirmed {
            api: "OH_AudioStreamBuilder_Destroy",
            code: -3,
        };
        assert_eq!(open_failure(Err(stop), builder.clone()), builder);
    }
}
