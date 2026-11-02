//! Desktop audio output sink: a real `cpal` output stream that pulls PCM through
//! its data callback.
//!
//! This module owns exactly one thing — the platform end of desktop remote
//! audio playback on every target without `OHAudio`: the machine's default
//! output device is opened in [`AudioRenderer::new`], bounded interleaved float
//! PCM is admitted with [`AudioRenderer::push`], and the backend's own callback
//! thread drains that queue into the buffer it asks for. Opus, the transport,
//! the Viewer and both bridges are elsewhere; so are capture, voice and camera
//! audio, which this sink neither opens nor touches.
//!
//! # Format
//!
//! The stream is opened at the rate and channel count the caller names (1 or 2
//! channels, 8000..=384000 Hz), taken from a configuration the device really
//! offers: [`AudioRenderer::new`] searches `Device::supported_output_configs`
//! for a range that carries the requested rate and channel count, and plays a
//! device's sample type as that type. A device that offers neither is refused
//! with [`RendererError::FormatMismatch`] — this sink does no resampling, so a
//! stream the device would run at another rate or width is never played as if it
//! matched.
//!
//! The one mapping it does perform is stated instead of implied: when the device
//! offers no 1-channel output at all for a mono stream, the sink opens a stereo
//! stream and admits each mono sample into both channels (a plain duplication,
//! no gain change). That is `duplicate_mono` below, set only by that search.
//!
//! # Queue and backpressure
//!
//! The queue holds 200 ms of interleaved samples for the actual rate and channel
//! count and is allocated once, when the stream is opened. `push` admits a whole
//! chunk or nothing: a chunk that does not fit is answered with
//! [`RendererError::Backpressure`] and counted, so a caller cannot mistake a full
//! queue for queued audio. Nothing grows, nothing is dropped silently, and
//! admission never waits on the device. Queued means queued —
//! [`AudioRenderer::stats`] reports the samples still waiting in the queue apart
//! from the samples the backend callback really consumed, so a backlog is never
//! read as a running total.
//!
//! The callback never allocates and never waits: it `try_lock`s the queue,
//! converts straight into the buffer the backend handed it, and fills whatever
//! the queue could not cover with silence while counting a starved callback.
//! Silence there is normal renderer silence, not evidence that anything was
//! decoded.
//!
//! # Ownership, activity and failure
//!
//! `cpal::Stream` may not leave the thread that built it, and it is neither
//! `Send` nor `Sync`. Neither is [`AudioRenderer`]; the one thread that owns
//! playback creates it, pushes into it and closes it, which is what the audio
//! owner does. The queue state behind the `Arc` is the only thing the backend
//! callback thread touches.
//!
//! `close` pauses the stream and then drops it, which is `cpal`'s own
//! destruction contract for the backend stream. A pause the backend refuses is
//! [`RendererError::ReleaseUnconfirmed`], because this sink then cannot say the
//! stream stopped; the stream is still dropped, and every later `close` of that
//! renderer repeats the same answer instead of retrying.
//!
//! `cpal` exposes no state getter, so [`AudioRenderer::is_active`] reports what
//! the backend confirmed and nothing more: `true` after `Stream::play` returned
//! success while no stream error and no close has happened since, `false` once a
//! [`cpal::StreamError`] reached the error callback. A device that disappears without
//! an error callback is a limit of the backend, not something this sink can
//! observe.
//!
//! A failing open reports the backend's own text. A failing `push` is the
//! caller's to classify: this sink only says what the device answered.

use std::sync::{
    Arc, Mutex, TryLockError,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, SizedSample};

/// Queue depth, in milliseconds of interleaved PCM.
const QUEUE_MILLIS: u32 = 200;
/// Channel counts this sink opens: mono and stereo share one interleaved layout,
/// anything wider needs a channel layout that is not requested here.
const MAX_CHANNELS: u16 = 2;
/// Lowest rate a queue is sized for.
const MIN_RATE: u32 = 8_000;
/// Highest sample rate a queue is sized for. No Opus stream and no output device
/// reports more; a larger request is refused rather than allocated for.
const MAX_RATE: u32 = 384_000;

/// Why the sink refused, or which backend call failed.
///
/// Every variant that names an `api` carries the text that call produced; no
/// failure is folded into a success and no code is invented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendererError {
    /// No host or no default output device: this machine has nowhere to play.
    UnsupportedPlatform,
    /// The requested rate or channel count is outside what this sink opens.
    InvalidFormat,
    /// The queue for that rate and channel count could not be allocated.
    OutOfMemory,
    /// The default output device offers no configuration at the requested rate
    /// and channel count, so playing would mean resampling or remixing.
    ///
    /// `actual_*` is the first configuration the device did report, as the
    /// evidence behind the refusal; `0` means it reported none.
    FormatMismatch {
        requested_rate: u32,
        requested_channels: u16,
        actual_rate: i32,
        actual_channels: i32,
    },
    /// The device's sample type is not one this sink converts from interleaved
    /// `f32`. No sample value is reinterpreted to pretend otherwise.
    UnsupportedSampleFormat { format: String },
    /// The bounded queue has no room for the whole chunk; nothing was admitted.
    Backpressure,
    /// This renderer was already closed, so nothing accepts PCM any more.
    Closed,
    /// A backend call reported failure. `message` is `cpal`'s own text.
    Device { api: &'static str, message: String },
    /// Teardown was attempted but reclamation is unconfirmed: the backend refused
    /// the pause, so the caller must not report the sink as released.
    ReleaseUnconfirmed { api: &'static str, message: String },
}

impl std::fmt::Display for RendererError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "this platform has no default audio output device")
            }
            Self::InvalidFormat => write!(
                f,
                "sample rate or channel count outside the 8000..=384000 Hz, 1..=2 channel sink range"
            ),
            Self::OutOfMemory => write!(f, "the PCM queue could not be allocated"),
            Self::FormatMismatch {
                requested_rate,
                requested_channels,
                actual_rate,
                actual_channels,
            } => write!(
                f,
                "the output device offers no {requested_rate} Hz/{requested_channels} ch stream; \
                 it reports {actual_rate} Hz/{actual_channels} ch"
            ),
            Self::UnsupportedSampleFormat { format } => {
                write!(
                    f,
                    "the output device plays {format}, which this sink cannot fill"
                )
            }
            Self::Backpressure => write!(f, "the audio queue is full"),
            Self::Closed => write!(f, "the audio stream is closed"),
            Self::Device { api, message } => write!(f, "{api} failed: {message}"),
            Self::ReleaseUnconfirmed { api, message } => write!(
                f,
                "{api} failed: {message}; the stream is retained and reclamation is unconfirmed"
            ),
        }
    }
}

impl std::error::Error for RendererError {}

/// What the sink counted, kept apart on purpose: admitted PCM is not played PCM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RendererStats {
    /// Interleaved samples still waiting in the queue, in the stream's own
    /// channel count: admitted by `push` and not yet consumed by a callback.
    pub queued_samples: u64,
    /// Samples a backend callback actually copied into its buffer.
    pub played_samples: u64,
    /// Callbacks that ran short of queued PCM (or could not take the queue) and
    /// therefore emitted silence past the queued samples.
    pub starved_callbacks: u64,
    /// `push` calls answered with `Backpressure`.
    pub rejected_pushes: u64,
}

/// Converts one interleaved sample for the queue.
///
/// A NaN has no ordering, so it lands on silence rather than an invented value;
/// everything else is limited to the full-scale range the stream's own format
/// describes, which is what keeps a device-side conversion from wrapping.
fn clamp_sample(sample: f32) -> f32 {
    if sample.is_nan() {
        0.0
    } else {
        sample.clamp(-1.0, 1.0)
    }
}

/// Interleaved `f32` ring buffer with a fixed capacity.
///
/// Allocated once and never resized: the callback only moves samples.
struct Queue {
    samples: Vec<f32>,
    head: usize,
    len: usize,
}

impl Queue {
    fn new(rate: u32, channels: u16) -> Result<Self, RendererError> {
        // 200 ms of frames, then the interleaved samples those frames carry.
        let frames = (u64::from(rate) * u64::from(QUEUE_MILLIS) / 1000) as usize;
        let capacity = frames * usize::from(channels);
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(capacity)
            .map_err(|_| RendererError::OutOfMemory)?;
        samples.resize(capacity, 0.0);
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
    ///
    /// `duplicate` writes every sample into two adjacent slots, which is the
    /// stated mono-to-stereo mapping; the caller only asks for it when the device
    /// has no 1-channel output.
    fn admit(&mut self, pcm: &[f32], duplicate: bool) -> bool {
        let width = if duplicate { 2 } else { 1 };
        let Some(need) = pcm.len().checked_mul(width) else {
            return false;
        };
        if need > self.space() {
            return false;
        }
        let capacity = self.capacity();
        let mut tail = self.head + self.len;
        if tail >= capacity {
            tail -= capacity;
        }
        for &sample in pcm {
            let value = clamp_sample(sample);
            self.samples[tail] = value;
            tail += 1;
            if tail == capacity {
                tail = 0;
            }
            if duplicate {
                self.samples[tail] = value;
                tail += 1;
                if tail == capacity {
                    tail = 0;
                }
            }
        }
        self.len += need;
        true
    }

    /// Copies the queued prefix into `out`, converted to the device's sample
    /// type, and returns how many samples that was; the rest of `out` is left for
    /// the caller to fill.
    fn drain_into<T: FromSample<f32>>(&mut self, out: &mut [T]) -> usize {
        let capacity = self.capacity();
        let taken = out.len().min(self.len);
        let mut cursor = self.head;
        for slot in out.iter_mut().take(taken) {
            *slot = T::from_sample_(self.samples[cursor]);
            cursor += 1;
            if cursor == capacity {
                cursor = 0;
            }
        }
        self.head = cursor;
        self.len -= taken;
        taken
    }
}

/// The state the backend callback thread and the producer thread share.
///
/// Only this allocation is captured by the callback closures; every callback
/// access goes through it, never through the stream.
struct Shared {
    queue: Mutex<Queue>,
    /// An error the backend reported from its own callback thread. The next
    /// `push` answers with it, so the sink's existing API carries the backend's
    /// own text rather than softening a dead stream into an unexplained
    /// inactivity. Taken once, so the same failure is not replayed.
    failure: Mutex<Option<String>>,
    /// Samples `push` admitted. This is a running total, not a backlog:
    /// [`Shared::stats`] subtracts what a callback consumed, so the report is
    /// what is really waiting.
    admitted: AtomicU64,
    played: AtomicU64,
    starved: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicBool,
    playing: AtomicBool,
}

impl Shared {
    fn new(rate: u32, channels: u16) -> Result<Arc<Self>, RendererError> {
        Ok(Arc::new(Self {
            queue: Mutex::new(Queue::new(rate, channels)?),
            failure: Mutex::new(None),
            admitted: AtomicU64::new(0),
            played: AtomicU64::new(0),
            starved: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            playing: AtomicBool::new(false),
        }))
    }

    fn record_failure(&self, message: String) {
        // The stream is gone: no queue entry can be played any more, and the
        // sink must not keep claiming it is running.
        self.playing.store(false, Ordering::Release);
        *self
            .failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(message);
    }

    /// Bounded admission. The lock is held for one conversion pass over the
    /// chunk and never while waiting on the device, so this cannot stall
    /// playback.
    fn admit(&self, pcm: &[f32], duplicate: bool) -> Result<(), RendererError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(RendererError::Closed);
        }
        // A backend that reported its own failure will never consume this PCM,
        // so the answer is that failure and not a queued sample count.
        let reported = self
            .failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(message) = reported {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RendererError::Device {
                api: "output stream",
                message,
            });
        }
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !queue.admit(pcm, duplicate) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(RendererError::Backpressure);
        }
        let admitted = pcm.len() * if duplicate { 2 } else { 1 };
        drop(queue);
        self.admitted.fetch_add(admitted as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Fills `out` from the queue, or leaves it as silence when the producer is
    /// inside its bounded copy. Never blocks, never allocates.
    fn callback_fill<T: FromSample<f32>>(&self, out: &mut [T]) {
        if self.closed.load(Ordering::Relaxed) {
            fill_silence(out);
            return;
        }
        let filled = match self.queue.try_lock() {
            Ok(mut queue) => queue.drain_into(out),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().drain_into(out),
            Err(TryLockError::WouldBlock) => {
                self.starved.fetch_add(1, Ordering::Relaxed);
                fill_silence(out);
                return;
            }
        };
        if filled < out.len() {
            self.starved.fetch_add(1, Ordering::Relaxed);
            fill_silence(&mut out[filled..]);
        }
        self.played.fetch_add(filled as u64, Ordering::Relaxed);
    }

    fn stats(&self) -> RendererStats {
        let admitted = self.admitted.load(Ordering::Relaxed);
        let played = self.played.load(Ordering::Relaxed);
        RendererStats {
            // What is still waiting, not what was ever pushed: the queue never
            // gives up an admitted sample except by playing it, so the difference
            // is exactly the backlog. A running total here would read as a delay
            // that keeps growing while playback is perfectly healthy.
            queued_samples: admitted.saturating_sub(played),
            played_samples: played,
            starved_callbacks: self.starved.load(Ordering::Relaxed),
            rejected_pushes: self.rejected.load(Ordering::Relaxed),
        }
    }

    /// Refuses further PCM before the stream is taken down, so a caller racing
    /// the close cannot hand over samples nothing will ever play.
    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.playing.store(false, Ordering::Relaxed);
    }
}

/// Writes the stream's own silence value; `from_sample_(0.0)` is that value for
/// every float and integer format this sink opens.
fn fill_silence<T: FromSample<f32>>(out: &mut [T]) {
    let silence = T::from_sample_(0.0);
    for slot in out.iter_mut() {
        *slot = silence;
    }
}

fn validate_format(rate: u32, channels: u16) -> Result<(), RendererError> {
    if !(MIN_RATE..=MAX_RATE).contains(&rate) || channels == 0 || channels > MAX_CHANNELS {
        return Err(RendererError::InvalidFormat);
    }
    Ok(())
}

/// Whether this sink converts from interleaved `f32` into the device's type.
///
/// It lists exactly the arms `build` below can open, so a format this sink would
/// have to refuse is never selected in the first place.
fn plain(format: cpal::SampleFormat) -> bool {
    matches!(
        format,
        cpal::SampleFormat::F32
            | cpal::SampleFormat::F64
            | cpal::SampleFormat::I8
            | cpal::SampleFormat::I16
            | cpal::SampleFormat::I32
            | cpal::SampleFormat::I64
            | cpal::SampleFormat::U8
            | cpal::SampleFormat::U16
            | cpal::SampleFormat::U32
            | cpal::SampleFormat::U64
    )
}

/// What the search settled on: the stream to open, the device's sample type and
/// whether mono samples are duplicated into a stereo stream.
struct Selection {
    config: cpal::StreamConfig,
    format: cpal::SampleFormat,
    duplicate_mono: bool,
}

/// Finds a configuration the device really reports for this rate and channel
/// count, preferring a float or 16-bit type before anything wider.
///
/// A range matches only when it carries the requested channel count *and* its own
/// rate span contains the requested rate, so the stream is opened at exactly the
/// rate asked for. When no 1-channel range exists for a mono request, a stereo
/// range at the same rate is the one fallback taken — explicitly, as a
/// duplication the sink performs, never as a mismatch played anyway.
fn select(device: &cpal::Device, rate: u32, channels: u16) -> Result<Selection, RendererError> {
    let ranges: Vec<cpal::SupportedStreamConfigRange> = device
        .supported_output_configs()
        .map_err(|error| RendererError::Device {
            api: "Device::supported_output_configs",
            message: error.to_string(),
        })?
        .collect();
    let wanted = cpal::SampleRate(rate);
    let attempt = |wanted_channels: cpal::ChannelCount, preferred: bool| {
        let wants = |format: cpal::SampleFormat| {
            !preferred || format.is_float() || format == cpal::SampleFormat::I16
        };
        ranges
            .iter()
            .filter(|range| {
                range.channels() == wanted_channels
                    && range.min_sample_rate().0 <= rate
                    && rate <= range.max_sample_rate().0
            })
            .filter(|range| plain(range.sample_format()))
            .filter(|range| wants(range.sample_format()))
            .map(|range| Selection {
                config: cpal::StreamConfig {
                    channels: wanted_channels,
                    sample_rate: wanted,
                    buffer_size: cpal::BufferSize::Default,
                },
                format: range.sample_format(),
                duplicate_mono: false,
            })
            .next()
    };
    let exact = attempt(channels, true).or_else(|| attempt(channels, false));
    let upmixed = if channels == 1 {
        attempt(2, true).or_else(|| attempt(2, false))
    } else {
        None
    };
    match exact.or_else(|| {
        upmixed.map(|mut found| {
            found.duplicate_mono = true;
            found
        })
    }) {
        Some(selection) => Ok(selection),
        None => {
            // The refusal carries what the device did report, so the caller can
            // tell "nothing matches" from "this machine has no output at all".
            let reported = ranges.first();
            Err(RendererError::FormatMismatch {
                requested_rate: rate,
                requested_channels: channels,
                actual_rate: reported.map_or(0, |range| range.max_sample_rate().0 as i32),
                actual_channels: reported.map_or(0, |range| i32::from(range.channels())),
            })
        }
    }
}

/// Builds and starts one stream of exactly `T`, which is the device's own sample
/// type. Both callbacks close over the shared queue state.
fn build<T>(
    device: &cpal::Device,
    selection: &Selection,
    shared: &Arc<Shared>,
) -> Result<cpal::Stream, RendererError>
where
    T: SizedSample + FromSample<f32>,
{
    let payload = Arc::clone(shared);
    let failures = Arc::clone(shared);
    let stream = device
        .build_output_stream(
            &selection.config,
            move |out: &mut [T], _info| {
                payload.callback_fill(out);
            },
            move |error| {
                failures.record_failure(error.to_string());
            },
            None,
        )
        .map_err(|error| RendererError::Device {
            api: "Device::build_output_stream",
            message: error.to_string(),
        })?;
    stream.play().map_err(|error| RendererError::Device {
        api: "Stream::play",
        message: error.to_string(),
    })?;
    shared.playing.store(true, Ordering::Release);
    Ok(stream)
}

/// One OHOS-agnostic output stream, created started.
///
/// Created, pushed into and closed on the single thread that owns playback: the
/// backend stream is neither `Send` nor `Sync`, so this type is neither, and
/// nothing here pretends otherwise.
pub struct AudioRenderer {
    /// `Some` until `close` runs; the answer that close produced is kept so every
    /// later call repeats it instead of reporting a success.
    stream: Option<cpal::Stream>,
    closed: Option<Result<(), RendererError>>,
    shared: Arc<Shared>,
    duplicate_mono: bool,
}

impl AudioRenderer {
    /// Opens and starts a real stream on the default output device for
    /// interleaved PCM at `sample_rate` Hz and `channels` channels.
    pub fn new(sample_rate: u32, channels: u16) -> Result<Self, RendererError> {
        validate_format(sample_rate, channels)?;
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or(RendererError::UnsupportedPlatform)?;
        let selection = select(&device, sample_rate, channels)?;
        let shared = Shared::new(sample_rate, selection.config.channels)?;
        let stream = match selection.format {
            cpal::SampleFormat::F32 => build::<f32>(&device, &selection, &shared),
            cpal::SampleFormat::F64 => build::<f64>(&device, &selection, &shared),
            cpal::SampleFormat::I8 => build::<i8>(&device, &selection, &shared),
            cpal::SampleFormat::I16 => build::<i16>(&device, &selection, &shared),
            cpal::SampleFormat::I32 => build::<i32>(&device, &selection, &shared),
            cpal::SampleFormat::I64 => build::<i64>(&device, &selection, &shared),
            cpal::SampleFormat::U8 => build::<u8>(&device, &selection, &shared),
            cpal::SampleFormat::U16 => build::<u16>(&device, &selection, &shared),
            cpal::SampleFormat::U32 => build::<u32>(&device, &selection, &shared),
            cpal::SampleFormat::U64 => build::<u64>(&device, &selection, &shared),
            other => Err(RendererError::UnsupportedSampleFormat {
                format: other.to_string(),
            }),
        }?;
        Ok(Self {
            stream: Some(stream),
            closed: None,
            shared,
            duplicate_mono: selection.duplicate_mono,
        })
    }

    /// Admits one chunk of interleaved `f32` samples. `Ok` means queued, not
    /// played; a chunk that does not fit the bounded queue is refused whole.
    pub fn push(&self, pcm: &[f32]) -> Result<(), RendererError> {
        self.shared.admit(pcm, self.duplicate_mono)
    }

    /// Whether the backend confirmed the stream is running: `Stream::play`
    /// returned success and no stream error, pause or close has happened since.
    pub fn is_active(&self) -> Result<bool, RendererError> {
        if self.closed.is_some() {
            return Err(RendererError::Closed);
        }
        Ok(self.shared.playing.load(Ordering::Acquire))
    }

    /// Admitted and consumed sample counts, starved callbacks and refused pushes.
    pub fn stats(&self) -> Result<RendererStats, RendererError> {
        Ok(self.shared.stats())
    }

    /// Pauses and destroys the backend stream now. Call it from a blocking
    /// worker: dropping the stream is the destruction contract, and a pause the
    /// backend refuses is reported as an unconfirmed reclamation. A second call
    /// repeats the first answer and never retries the pause.
    pub fn close(&mut self) -> Result<(), RendererError> {
        if let Some(answer) = &self.closed {
            return answer.clone();
        }
        self.shared.mark_closed();
        let Some(stream) = self.stream.take() else {
            let answer = Err(RendererError::ReleaseUnconfirmed {
                api: "Stream::pause",
                message: "the backend stream was dropped without an answer".to_string(),
            });
            self.closed = Some(answer.clone());
            return answer;
        };
        let paused = stream
            .pause()
            .map_err(|error| RendererError::ReleaseUnconfirmed {
                api: "Stream::pause",
                message: error.to_string(),
            });
        // Dropping is the real release whatever the pause answered: `cpal`
        // destroys the backend stream here, and nothing keeps a handle to it.
        drop(stream);
        let answer = paused;
        self.closed = Some(answer.clone());
        answer
    }
}
