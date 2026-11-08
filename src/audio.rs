//! Desktop audio playback: one bounded, generation-stamped path from the peer's
//! Opus packets to the platform's output sink.
//!
//! The wire carries two messages and nothing else about audio: an
//! [`AudioFormat`] naming a sample rate and a channel count, and [`AudioFrame`]
//! messages carrying one Opus packet each. This module turns the second into
//! interleaved PCM with a real Opus decoder and hands it to the platform sink
//! (`crate::platform_audio`), which is `OHAudio` on OpenHarmony and a `cpal`
//! output stream everywhere else. It is the same core for both: which device
//! finally plays the samples never changes what is decoded, how it is bounded or
//! what is reported.
//!
//! # One owner, one bounded queue
//!
//! [`start`] splits the work in two. [`AudioHandle`] is what the wire reader
//! holds: it stamps, admits and refuses, and never blocks. [`AudioOwner`] is the
//! only owner of the decoder and the sink; it runs on one dedicated thread
//! (`spawn_blocking` over `Handle::current().block_on(owner.run())`), which is
//! what the platform sinks require — the OpenHarmony renderer waits for its
//! stream on release, and the `cpal` stream may not leave the thread that built
//! it. Nothing here spawns a task per packet, opens a second runtime, or reads
//! the wire.
//!
//! The queue between them holds eight encoded packets and is allocated once.
//! `offer_frame` copies nothing — the packet's own buffer moves in — and a full
//! queue is answered with [`AudioError::Backpressure`] instead of waiting, so a
//! slow owner can never stall the reader that also has to carry video, clipboard
//! and input. A refused audio packet is the reader's to count; nothing about it
//! touches another wire message.
//!
//! # Generations: permission, mute, close and format
//!
//! Everything that invalidates queued work advances one generation counter:
//! [`AudioHandle::set_allowed`] in either direction, and a format that is new for
//! the generation in force. The allowance, the generation and the declared format
//! are read and written as one value under one short lock, so no reader can see a
//! grant beside another generation's stamp, or a format that belongs to a
//! generation it did not arrive in. The stamp is taken *before* a packet is
//! queued, so a packet admitted under one generation can never be applied to the
//! next one, and a format declared under an older generation never covers a newer
//! one.
//!
//! Withdrawal is therefore synchronous in effect and not merely advisory: the
//! owner wakes on the generation change, closes the platform sink (which is what
//! clears that generation's PCM — the queue belongs to the sink) and waits. A
//! grant starts new work only: the format from before it is stale, so nothing
//! resumes until the peer declares a format again, and no PCM from before the
//! grant is ever played. The Opus decoder is rebuilt with the sink for the same
//! reason — decoder state from before a withdrawal has nothing to say about the
//! stream that follows it.
//!
//! Cancellation is close: [`AudioOwner::run`] treats the session's
//! [`CancellationToken`] as the end of playback and still runs the real teardown,
//! because a sink that owns a native stream must be closed rather than abandoned.
//!
//! # What is reported, and what is not
//!
//! [`AudioSnapshot`] keeps four facts apart that are easy to confuse:
//!
//! * the declared format and the generation it belongs to;
//! * `decoded_packets`, counted when a packet really decoded;
//! * `played_samples`, the samples a platform callback really consumed — not the
//!   samples that were queued;
//! * `resources_unconfirmed`, this owner's own audio reclamation fact. It is set
//!   before the platform sink may allocate anything and cleared only by an open
//!   that allocated nothing or by a close that really succeeded. A worker that
//!   panics or a close that fails leaves it set, because neither is evidence that
//!   the native stream is gone. It is read separately from the video pipeline's
//!   own flag: one release cannot clear the other's failure.
//!
//! Audio failures are not fatal to the session. A format the sink cannot open, a
//! packet libopus refuses, or a machine with no output device becomes
//! `last_error` and an inactive snapshot — never a failed remote-control session,
//! and never a blind retry of the same failure. A new format or a fresh grant is
//! new input and may be tried; the same generation is not. `run` returns an error
//! only for a native stream it could not confirm released — its own teardown, or
//! an open whose cleanup could not reclaim what it created — and keeps the
//! snapshot so the caller can see why.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

use base::message_proto::{AudioFormat, AudioFrame};
use hbb_common::bytes::Bytes;
use magnum_opus::{Channels, Decoder};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::platform_audio::{AudioRenderer, RendererError};

/// Encoded packets the reader may hand over before the owner decodes them.
///
/// Eight of the peer's 10 ms packets are 80 ms of lookahead: enough for scheduler
/// jitter and a sink that briefly runs full, short enough that a stalled owner
/// cannot hide behind it. Deeper is not better here — it would only make the
/// audio later, not smoother.
const AUDIO_PACKETS: usize = 8;
// Bound retained encoded bytes as well as packet count. This covers the peer's
// short packets and the largest unpadded Opus packet, without retaining wire-
// sized arbitrary padding in every queue slot.
const MAX_ENCODED_PACKET_BYTES: usize = 64 * 1024;

/// Opus's own ceiling on one packet's duration (RFC 6716 §3.2.5 allows at most
/// 120 ms of audio in a packet). A decode buffer is sized from the packet's own
/// answer and bounded by this, not by an invented byte limit.
const MAX_PACKET_MILLIS: u64 = 120;

/// The sample rates libopus serves a decoder, which are also the only rates the
/// peer's `AudioFormat` is produced at (the sending side clamps to exactly these).
/// A declared rate outside them is refused here rather than handed to a decoder
/// that cannot open and a device that would have to be resampled into.
const OPUS_RATES: [u32; 5] = [8_000, 12_000, 16_000, 24_000, 48_000];

/// One and two channels are the only values the peer's `AudioFormat` carries and
/// the only layouts this core decodes.
const MAX_CHANNELS: u32 = 2;

/// Attempts at a full sink queue before one decoded chunk is dropped.
///
/// The wait happens on the owner thread only, so it can never delay the reader;
/// the attempt count bounds what a stalled device may postpone.
const PUSH_ATTEMPTS: u32 = 5;
const PUSH_WAIT: Duration = Duration::from_millis(4);

/// Admitted packets between two platform activity reads (about 80 ms of the
/// peer's 10 ms packets). `active` is therefore neither a native poll per packet
/// nor a value frozen at open.
const ACTIVE_EVERY: u64 = 8;

/// Why audio was refused or stopped.
///
/// The first four are the reader's normal answers and are never fatal to the
/// session: a muted, not-yet-declared, cancelled or full queue is a state, not a
/// failure. The rest describe a packet or a device that could not be served and
/// are recorded in [`AudioSnapshot::last_error`] before the owner carries on.
#[derive(Debug, Clone, PartialEq)]
pub enum AudioError {
    /// The session is cancelled or the owner is gone; nothing accepts packets.
    Closed,
    /// Local playback is not allowed: muted, or permission withdrawn.
    Revoked,
    /// A packet arrived before the peer declared a format for this generation.
    NoFormat,
    /// The bounded packet queue is full; nothing was queued.
    Backpressure,
    /// The declared rate or channel count is not one this core serves.
    InvalidFormat,
    /// The packet is not a decodable Opus packet. The text is this core's own
    /// statement of which bound refused it.
    Malformed(&'static str),
    /// The Opus decoder refused. `function` and `description` are libopus's own.
    Decoder {
        function: &'static str,
        description: String,
    },
    /// The platform sink answered with its own error.
    Sink(RendererError),
}

impl std::fmt::Display for AudioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "audio playback is closed"),
            Self::Revoked => write!(f, "local audio playback is not allowed"),
            Self::NoFormat => write!(f, "no audio format was declared for this stream"),
            Self::Backpressure => write!(f, "the audio packet queue is full"),
            Self::InvalidFormat => write!(
                f,
                "the declared audio format is not one Opus serves: 8000/12000/16000/24000/48000 \
                 Hz at 1 or 2 channels"
            ),
            Self::Malformed(reason) => write!(f, "malformed Opus packet: {reason}"),
            Self::Decoder {
                function,
                description,
            } => write!(f, "libopus {function} failed: {description}"),
            Self::Sink(error) => write!(f, "platform audio sink: {error}"),
        }
    }
}

impl std::error::Error for AudioError {}

/// One reading of this session's audio state.
///
/// Cloneable on purpose: the reader, the owner and the bridges each take their
/// own copy rather than sharing a lock. `played_samples` is the only sample count
/// that means "heard"; `queued_samples` is what waits in the sink's own queue.
#[derive(Debug, Clone, PartialEq)]
pub struct AudioSnapshot {
    /// The format in force for `generation`, or nothing while none is declared.
    pub format: Option<AudioFormat>,
    /// Every transition that invalidated queued work advanced this.
    pub generation: u64,
    /// Whether local playback is allowed right now.
    pub allowed: bool,
    /// The platform sink was confirmed started and has not failed or closed
    /// since. Read at most once per eight admitted packets.
    pub active: bool,
    /// Packets this handle accepted into the queue.
    pub received_packets: u64,
    /// Packets the Opus decoder really decoded.
    pub decoded_packets: u64,
    /// Decoded packets whose samples were not played: one libopus refused, one
    /// the sink's queue would not take, or one whose generation ended while the
    /// owner waited on the sink.
    pub dropped_packets: u64,
    /// Packets discarded before they were decoded, because the generation they
    /// were admitted under was superseded (or playback was ending).
    pub stale_packets: u64,
    /// Offers refused by the bounded packet queue.
    pub rejected_packets: u64,
    /// Interleaved samples sitting in the sink's queue.
    pub queued_samples: u64,
    /// Interleaved samples a platform callback really consumed.
    pub played_samples: u64,
    /// The last failure, kept as text so one line explains an inactive sink.
    pub last_error: Option<String>,
    /// A native audio resource may still exist: no open of this owner is
    /// confirmed to have allocated nothing and no close is confirmed to have
    /// reclaimed it.
    pub resources_unconfirmed: bool,
}

/// The policy in force: whether playback is allowed, the generation every
/// transition advances, and the format the peer declared for it.
///
/// The three only mean anything together, so they are read and written as one
/// value under one short lock: no reader can see a grant beside another
/// generation's stamp, and a declaration can never cover a generation it did not
/// arrive in.
#[derive(Clone)]
struct Policy {
    /// Whether local playback is allowed right now.
    allowed: bool,
    /// Every transition that invalidated queued work advanced this.
    generation: u64,
    /// The peer's format, declared for exactly `generation`. Advancing the
    /// generation drops it, so a declaration is never carried over to a
    /// generation it was not made in.
    format: Option<AudioFormat>,
}

impl Policy {
    /// Advances the generation and drops the declaration with it: the format from
    /// before a transition has nothing to say about the stream that follows it.
    /// Exhaustion cannot reuse a ticket and make an old declaration current.
    fn advance(&mut self) {
        self.generation = self.generation.checked_add(1).expect("audio generation exhausted");
        self.format = None;
    }
}

/// The state the handle, the owner and the snapshot share.
///
/// The policy is one short-lived lock because its three fields are only valid
/// together; every count below is atomic, so neither the handle nor the owner
/// waits on a reader to publish one.
struct Shared {
    /// Allowance, generation and declared format, published as one value.
    policy: Mutex<Policy>,
    /// Generation source for the owner: every transition that invalidates queued
    /// work notifies here, so the owner is woken instead of polling. A stored
    /// permit means a transition that lands while the owner is busy still wakes
    /// its next wait.
    wake: Notify,
    received: AtomicU64,
    decoded: AtomicU64,
    dropped: AtomicU64,
    stale: AtomicU64,
    rejected: AtomicU64,
    queued_samples: AtomicU64,
    played_samples: AtomicU64,
    /// Admitted packets since the owner started, used only to space out the
    /// platform activity reads.
    published: AtomicU64,
    active: AtomicBool,
    resources_unconfirmed: AtomicBool,
    last_error: Mutex<Option<String>>,
}

impl Shared {
    fn new() -> Self {
        Self {
            policy: Mutex::new(Policy {
                allowed: false,
                generation: 0,
                format: None,
            }),
            wake: Notify::new(),
            received: AtomicU64::new(0),
            decoded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            stale: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            queued_samples: AtomicU64::new(0),
            played_samples: AtomicU64::new(0),
            published: AtomicU64::new(0),
            active: AtomicBool::new(false),
            resources_unconfirmed: AtomicBool::new(false),
            last_error: Mutex::new(None),
        }
    }

    fn lock_policy(&self) -> std::sync::MutexGuard<'_, Policy> {
        self.policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The policy in force, read once, so allowance, generation and format always
    /// belong to the same generation.
    fn current_policy(&self) -> Policy {
        self.lock_policy().clone()
    }

    /// Applies one policy transition with the policy lock held for that
    /// transition only, and wakes the owner when it advanced the generation.
    ///
    /// `notify_one` cannot fail and keeps at most one permit, which is exactly
    /// enough: the owner re-reads the generation itself, so a transition that
    /// lands while it is busy still wakes its next wait.
    fn transition(&self, edit: impl FnOnce(&mut Policy) -> bool) {
        let advanced = edit(&mut self.lock_policy());
        if advanced {
            self.wake.notify_one();
        }
    }

    fn note_error(&self, error: &AudioError) {
        *self
            .last_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.to_string());
    }

    /// Publishes what the sink itself counted, plus — on a bounded cadence — the
    /// platform's own activity answer.
    ///
    /// The stats are cheap atomic reads; the activity question is a platform
    /// call, so it is asked once per [`ACTIVE_EVERY`] admitted packets and never
    /// guessed from our own bookkeeping.
    fn publish(&self, sink: &AudioRenderer) {
        if let Ok(stats) = sink.stats() {
            self.queued_samples
                .store(stats.queued_samples, Ordering::Relaxed);
            self.played_samples
                .store(stats.played_samples, Ordering::Relaxed);
        }
        if tally(&self.published, 1) % ACTIVE_EVERY == 0 {
            let active = sink.is_active().unwrap_or(false);
            self.active.store(active, Ordering::Release);
        }
    }

    fn snapshot(&self) -> AudioSnapshot {
        let policy = self.current_policy();
        AudioSnapshot {
            format: policy.format,
            generation: policy.generation,
            allowed: policy.allowed,
            active: self.active.load(Ordering::Acquire),
            received_packets: self.received.load(Ordering::Relaxed),
            decoded_packets: self.decoded.load(Ordering::Relaxed),
            dropped_packets: self.dropped.load(Ordering::Relaxed),
            stale_packets: self.stale.load(Ordering::Relaxed),
            rejected_packets: self.rejected.load(Ordering::Relaxed),
            queued_samples: self.queued_samples.load(Ordering::Relaxed),
            played_samples: self.played_samples.load(Ordering::Relaxed),
            last_error: self
                .last_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            resources_unconfirmed: self.resources_unconfirmed.load(Ordering::Acquire),
        }
    }
}

/// Adds to a report counter without wrapping, and answers the new total.
///
/// A wrapped counter reports fewer packets than arrived, which would be a lie
/// about what this session did; a saturated one says "at least this many", which
/// is the honest limit of a `u64` report.
fn tally(counter: &AtomicU64, by: u64) -> u64 {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(by)
        })
        .map_or_else(
            |saturated| saturated,
            |previous| previous.saturating_add(by),
        )
}

/// One encoded packet, stamped with the generation it was admitted under.
struct Encoded {
    generation: u64,
    data: Bytes,
}

/// Both halves of one session's audio playback.
pub struct AudioStart {
    /// What the wire reader holds.
    pub handle: Arc<AudioHandle>,
    /// What one blocking worker thread owns until it ends.
    pub owner: AudioOwner,
}

/// Creates one session's audio playback for `cancel`.
///
/// The handle is usable immediately; nothing is decoded until the owner runs on
/// its own thread and the peer has declared a format.
pub fn start(cancel: CancellationToken) -> AudioStart {
    let (packets, queue) = mpsc::channel(AUDIO_PACKETS);
    let shared = Arc::new(Shared::new());
    AudioStart {
        handle: Arc::new(AudioHandle {
            shared: Arc::clone(&shared),
            cancel: cancel.clone(),
            packets,
        }),
        owner: AudioOwner {
            shared,
            packets: queue,
            cancel,
        },
    }
}

/// The wire reader's half: stamp, admit, refuse. Never blocks, never decodes.
pub struct AudioHandle {
    shared: Arc<Shared>,
    cancel: CancellationToken,
    packets: mpsc::Sender<Encoded>,
}

impl AudioHandle {
    /// Allows or withdraws local playback. Both directions are a new generation,
    /// so nothing queued or declared before the call can be applied after it.
    pub fn set_allowed(&self, allowed: bool) {
        self.shared.transition(|policy| {
            if policy.allowed == allowed {
                return false;
            }
            policy.allowed = allowed;
            policy.advance();
            true
        });
    }

    /// The generation in force: every transition that invalidated queued work
    /// advanced it.
    pub fn revision(&self) -> u64 {
        self.shared.current_policy().generation
    }

    /// The current state, as a copy the caller may keep.
    pub fn snapshot(&self) -> AudioSnapshot {
        self.shared.snapshot()
    }

    /// Declares the format the peer is sending.
    ///
    /// A format that differs from the one in force advances the generation under
    /// the same lock that publishes it, so the new format is never visible beside
    /// the generation it replaced, and a withdrawal racing this call is ordered
    /// against it either way. Repeating the format already in force changes
    /// nothing and does not disturb a sink that is playing it.
    ///
    /// This cannot be refused for backpressure: the format is stored, not queued,
    /// so a full packet queue cannot lose it.
    pub fn offer_format(&self, format: AudioFormat) -> Result<(), AudioError> {
        if self.cancel.is_cancelled() {
            return Err(AudioError::Closed);
        }
        validate(&format)?;
        self.shared.transition(|policy| {
            if policy.format.as_ref() == Some(&format) {
                return false;
            }
            policy.advance();
            policy.format = Some(format);
            true
        });
        Ok(())
    }

    /// Admits one Opus packet, or says why not.
    ///
    /// The allowance, the generation and the format are read as one policy value,
    /// and the generation is stamped before the packet is queued, so a packet can
    /// never be applied to a generation that had not started when it arrived.
    /// The packet's buffer moves into the queue; nothing is copied and no task is
    /// spawned per packet.
    pub fn offer_frame(&self, frame: AudioFrame) -> Result<(), AudioError> {
        if self.cancel.is_cancelled() {
            return Err(AudioError::Closed);
        }
        let policy = self.shared.current_policy();
        if !policy.allowed {
            return Err(AudioError::Revoked);
        }
        if policy.format.is_none() {
            return Err(AudioError::NoFormat);
        }
        if frame.data.len() > MAX_ENCODED_PACKET_BYTES {
            tally(&self.shared.rejected, 1);
            return Err(AudioError::Malformed("the encoded packet exceeds 64 KiB"));
        }
        match self.packets.try_send(Encoded {
            generation: policy.generation,
            data: frame.data,
        }) {
            Ok(()) => {
                tally(&self.shared.received, 1);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                tally(&self.shared.rejected, 1);
                Err(AudioError::Backpressure)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(AudioError::Closed),
        }
    }
}

fn validate(format: &AudioFormat) -> Result<(), AudioError> {
    if !OPUS_RATES.contains(&format.sample_rate)
        || format.channels == 0
        || format.channels > MAX_CHANNELS
    {
        return Err(AudioError::InvalidFormat);
    }
    Ok(())
}

/// The blocking owner of the decoder and the platform sink.
///
/// It holds only `Send` state, so it can be moved into the one blocking worker
/// that will run it. The decoder, the sink and the decode buffer are created
/// inside [`AudioOwner::run`] and never leave that worker's thread.
pub struct AudioOwner {
    shared: Arc<Shared>,
    packets: mpsc::Receiver<Encoded>,
    cancel: CancellationToken,
}

impl AudioOwner {
    /// Decodes and plays until the session ends, then really closes the sink.
    ///
    /// Drive it to completion and never abort it: it owns the native stream, and
    /// its teardown is what confirms that stream is gone. `Ok` means playback
    /// ended and everything it created was reclaimed; an error means a native
    /// stream could not be confirmed released — a close, or an open whose cleanup
    /// could not reclaim what it allocated — which the snapshot still shows.
    pub async fn run(self) -> Result<(), AudioError> {
        let Self {
            shared,
            mut packets,
            cancel,
        } = self;
        let wake = &shared.wake;
        let mut output: Option<Output> = None;
        // The generation whose open or sink failure was already reported. The
        // same failure is not retried; a new generation is new input.
        let mut refused: Option<u64> = None;

        let outcome = loop {
            if cancel.is_cancelled() {
                break Ok(());
            }
            let policy = shared.current_policy();
            if !policy.allowed {
                // Withdrawal outranks anything queued: the sink goes down now,
                // and this generation's PCM goes with it.
                if let Err(error) = shutdown(&shared, &mut output) {
                    break Err(error);
                }
                if !still_wanted(&cancel, wake).await {
                    break Ok(());
                }
                continue;
            }
            if refused == Some(policy.generation) {
                if !still_wanted(&cancel, wake).await {
                    break Ok(());
                }
                continue;
            }
            let Some(format) = policy.format else {
                // Nothing can be decoded until the peer declares a format for
                // this generation; that declaration is what wakes this owner.
                if let Err(error) = shutdown(&shared, &mut output) {
                    break Err(error);
                }
                if !still_wanted(&cancel, wake).await {
                    break Ok(());
                }
                continue;
            };
            // Only an output that already serves this format *and* this
            // generation may keep playing. An output that does not exist yet
            // never does, so the first admitted packet of a generation is opened
            // for here instead of being skipped.
            let serving = output
                .as_ref()
                .is_some_and(|current| current.covers(&format, policy.generation));
            if !serving {
                // A new format, or a new generation, gets its own decoder and its
                // own sink: state from before either has nothing to say after.
                if let Err(error) = shutdown(&shared, &mut output) {
                    break Err(error);
                }
                if cancel.is_cancelled() {
                    break Ok(());
                }
                match Output::open(&shared, &format, policy.generation) {
                    Ok(opened) => output = Some(opened),
                    Err(error) => {
                        // Recorded, not pretended, and not retried for this
                        // generation: a machine with no output device stays that
                        // way until something actually changes.
                        shared.note_error(&error);
                        refused = Some(policy.generation);
                        if matches!(
                            &error,
                            AudioError::Sink(RendererError::ReleaseUnconfirmed { .. })
                        ) {
                            // This open left a native stream it could not confirm
                            // released. Ending here returns that fact, instead of
                            // waiting for a teardown that has nothing left to
                            // close and answering `Ok` over an unreclaimed stream.
                            break Err(error);
                        }
                        if !still_wanted(&cancel, wake).await {
                            break Ok(());
                        }
                        continue;
                    }
                }
            }
            let packet = tokio::select! {
                biased;
                _ = cancel.cancelled() => break Ok(()),
                _ = wake.notified() => continue,
                packet = packets.recv() => match packet {
                    Some(packet) => packet,
                    None => break Ok(()),
                },
            };
            // Read again after the wait: the generation that admitted this packet
            // may have been superseded while this owner waited.
            if packet.generation != shared.current_policy().generation {
                // Admitted under a generation that has since been superseded.
                tally(&shared.stale, 1);
                continue;
            }
            let played = match output.as_mut() {
                Some(current) => current.play(&shared, &packet, &cancel).await,
                None => {
                    // The open above is the only way past this point, so an
                    // output exists here; a packet that reaches a missing sink is
                    // still reported rather than silently dropped.
                    tally(&shared.stale, 1);
                    continue;
                }
            };
            match played {
                Ok(Played::Queued) => {}
                Ok(Played::Stale) => {
                    tally(&shared.stale, 1);
                }
                Ok(Played::Dropped) => {
                    tally(&shared.dropped, 1);
                }
                Err(failure) => {
                    shared.note_error(&failure);
                    tally(&shared.dropped, 1);
                    if matches!(&failure, AudioError::Sink(_)) {
                        // The sink is unusable for this generation, but the
                        // session is not: close it, report, and wait for new
                        // input.
                        refused = Some(policy.generation);
                        if let Err(error) = shutdown(&shared, &mut output) {
                            break Err(error);
                        }
                    }
                }
            }
        };

        // Cancellation is a close, not an abandon: whatever this owner created is
        // closed here, on the same thread that created it.
        shutdown(&shared, &mut output)?;
        outcome
    }
}

/// Waits for the next transition, and says whether playback still has a reason to
/// run: `false` means cancelled.
///
/// A transition that landed before this call is not lost — `Notify` keeps one
/// permit — so the owner never misses the change it is waiting for and never has
/// to poll for one.
async fn still_wanted(cancel: &CancellationToken, wake: &Notify) -> bool {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => false,
        _ = wake.notified() => true,
    }
}

/// What became of one admitted packet.
enum Played {
    /// The chunk was admitted by the sink.
    Queued,
    /// The generation or the session ended before the packet was decoded; it was
    /// never applied to any stream.
    Stale,
    /// The packet decoded, but its PCM never reached the sink: the queue stayed
    /// full, or the generation ended while the owner waited on it. Decoded is
    /// counted, played is not.
    Dropped,
}

/// One generation's decoder and platform sink, created on the owner thread.
struct Output {
    format: AudioFormat,
    generation: u64,
    decoder: Decoder,
    sink: AudioRenderer,
    /// Reused decode buffer: grown to the largest packet the peer sends, bounded
    /// by Opus's own 120 ms ceiling, and never re-allocated per packet after that.
    pcm: Vec<f32>,
}

impl Output {
    /// Whether this output already serves exactly `format` in `generation`.
    fn covers(&self, format: &AudioFormat, generation: u64) -> bool {
        self.generation == generation && self.format == *format
    }

    /// Whether the policy in force still lets this output play: playback allowed,
    /// this output's generation the current one, and the format it was opened for
    /// still the one declared. A withdrawal, a new generation or a new format all
    /// answer `false`.
    fn serves(&self, shared: &Shared) -> bool {
        let policy = shared.current_policy();
        policy.allowed
            && policy.generation == self.generation
            && policy.format.as_ref() == Some(&self.format)
    }

    /// Opens the decoder and then the platform sink for one generation.
    ///
    /// The reclamation flag is set before the sink may allocate anything, and
    /// only the sink's own answer clears it: an unconfirmed release is the one
    /// answer that may still own a native stream.
    fn open(shared: &Shared, format: &AudioFormat, generation: u64) -> Result<Self, AudioError> {
        let channels = if format.channels > 1 {
            Channels::Stereo
        } else {
            Channels::Mono
        };
        let decoder = Decoder::new(format.sample_rate, channels).map_err(from_opus)?;
        shared.resources_unconfirmed.store(true, Ordering::Release);
        let sink = match AudioRenderer::new(format.sample_rate, format.channels as u16) {
            Ok(sink) => sink,
            Err(error) => {
                if !matches!(&error, RendererError::ReleaseUnconfirmed { .. }) {
                    // This open allocated nothing that survived: the sink names
                    // that by answering with anything but an unconfirmed release.
                    shared.resources_unconfirmed.store(false, Ordering::Release);
                }
                shared.active.store(false, Ordering::Release);
                return Err(AudioError::Sink(error));
            }
        };
        // The platform's own answer, not an assumption about `new` succeeding.
        let active = sink.is_active().unwrap_or(false);
        shared.active.store(active, Ordering::Release);
        Ok(Self {
            format: format.clone(),
            generation,
            decoder,
            sink,
            pcm: Vec::new(),
        })
    }

    /// Decodes one packet and hands it to the sink.
    ///
    /// The generation and the allowance are asked again here, before the decoder
    /// is touched and again before every push: the backpressure wait below is
    /// long enough for a withdrawal or a new format to land, and PCM decoded
    /// under one generation must never enter a sink that has already been closed
    /// for it. A full sink queue is waited on here, on the owner thread, and
    /// nowhere else; after the attempts run out the chunk is dropped and counted
    /// rather than allowed to grow anything.
    async fn play(
        &mut self,
        shared: &Shared,
        packet: &Encoded,
        cancel: &CancellationToken,
    ) -> Result<Played, AudioError> {
        if cancel.is_cancelled() || !self.serves(shared) {
            return Ok(Played::Stale);
        }
        let samples = decode_packet(
            &mut self.decoder,
            self.format.sample_rate,
            self.format.channels as u16,
            &mut self.pcm,
            &packet.data,
        )?;
        tally(&shared.decoded, 1);
        let pcm = &self.pcm[..samples];
        let mut attempt = 0;
        loop {
            // Asked again before every push: a transition that landed during the
            // wait above ends this chunk here instead of letting older PCM follow
            // it into the sink.
            if cancel.is_cancelled() || !self.serves(shared) {
                shared.publish(&self.sink);
                return Ok(Played::Dropped);
            }
            match self.sink.push(pcm) {
                Ok(()) => {
                    shared.publish(&self.sink);
                    return Ok(Played::Queued);
                }
                Err(RendererError::Backpressure) if attempt < PUSH_ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(PUSH_WAIT).await;
                }
                Err(RendererError::Backpressure) => {
                    shared.publish(&self.sink);
                    return Ok(Played::Dropped);
                }
                Err(error) => {
                    shared.publish(&self.sink);
                    return Err(AudioError::Sink(error));
                }
            }
        }
    }
}

/// Closes whatever the owner holds and reports what the platform answered.
fn shutdown(shared: &Shared, output: &mut Option<Output>) -> Result<(), AudioError> {
    let Some(mut current) = output.take() else {
        return Ok(());
    };
    let closed = current.sink.close();
    shared.publish(&current.sink);
    // The decoder, the decode buffer and the sink's queue go with `current`; the
    // queue is what carried this generation's PCM, so dropping it is the clear.
    drop(current);
    shared.active.store(false, Ordering::Release);
    match closed {
        Ok(()) => {
            shared.resources_unconfirmed.store(false, Ordering::Release);
            Ok(())
        }
        // A close that could not confirm reclamation keeps the flag set: neither
        // this answer nor the snapshot may claim the native stream is gone.
        Err(error) => {
            let failure = AudioError::Sink(error);
            shared.note_error(&failure);
            Err(failure)
        }
    }
}

/// Decodes one Opus packet into `buffer` as interleaved PCM and returns how many
/// samples that wrote.
///
/// The length comes from libopus's own reading of this packet
/// ([`Decoder::get_nb_samples`]) and is bounded by Opus's 120 ms packet ceiling,
/// so no byte limit has to be invented here. That answer counts samples *per
/// channel*, so the interleaved length is it times the channel count — which is
/// also what [`Decoder::decode_float`] answers.
fn decode_packet(
    decoder: &mut Decoder,
    rate: u32,
    channels: u16,
    buffer: &mut Vec<f32>,
    data: &[u8],
) -> Result<usize, AudioError> {
    if data.is_empty() {
        return Err(AudioError::Malformed("the packet carries no bytes"));
    }
    let per_channel = decoder.get_nb_samples(data).map_err(from_opus)?;
    let ceiling = (u64::from(rate) * MAX_PACKET_MILLIS / 1000) as usize;
    if per_channel == 0 || per_channel > ceiling {
        return Err(AudioError::Malformed(
            "the packet's duration is outside Opus's 120 ms ceiling",
        ));
    }
    let needed = per_channel * usize::from(channels);
    if buffer.len() < needed {
        buffer.resize(needed, 0.0);
    }
    let decoded = decoder
        .decode_float(data, &mut buffer[..needed], false)
        .map_err(from_opus)?;
    Ok(decoded * usize::from(channels))
}

/// libopus's own failure, with its own function name and description.
fn from_opus(error: magnum_opus::Error) -> AudioError {
    AudioError::Decoder {
        function: error.function(),
        description: error.description().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnum_opus::{Application, Encoder};

    fn format(sample_rate: u32, channels: u32) -> AudioFormat {
        AudioFormat {
            sample_rate,
            channels,
            ..Default::default()
        }
    }

    fn packet(bytes: usize) -> AudioFrame {
        AudioFrame {
            data: vec![0x01; bytes].into(),
            ..Default::default()
        }
    }

    /// Withdrawal refuses packets, a grant starts from nothing, and the format
    /// from before either never covers the generation after it.
    #[test]
    fn withdrawal_refuses_and_a_grant_restarts_from_nothing() {
        let cancel = CancellationToken::new();
        let playback = start(cancel);
        let handle = &playback.handle;
        handle.set_allowed(true);
        handle
            .offer_format(format(48_000, 2))
            .expect("a format Opus serves");
        handle.offer_frame(packet(40)).expect("an admitted packet");
        let granted = handle.revision();

        handle.set_allowed(false);
        assert_eq!(handle.revision(), granted + 1);
        assert!(!handle.snapshot().allowed);
        assert_eq!(handle.offer_frame(packet(40)), Err(AudioError::Revoked));

        handle.set_allowed(true);
        assert_eq!(handle.revision(), granted + 2);
        // The declaration belongs to the withdrawn generation, so nothing plays
        // until the peer declares the format again.
        assert_eq!(handle.offer_frame(packet(40)), Err(AudioError::NoFormat));
        assert_eq!(handle.snapshot().format, None);

        handle
            .offer_format(format(48_000, 2))
            .expect("declared again");
        assert_eq!(handle.snapshot().format, Some(format(48_000, 2)));
        // Granting an allowance that is already in force changes nothing.
        let steady = handle.revision();
        handle.set_allowed(true);
        assert_eq!(handle.revision(), steady);
    }

    /// The encoded queue is bounded and says so instead of waiting or growing.
    #[test]
    fn the_packet_queue_is_bounded() {
        let cancel = CancellationToken::new();
        let playback = start(cancel);
        let handle = &playback.handle;
        handle.set_allowed(true);
        handle
            .offer_format(format(48_000, 2))
            .expect("a format Opus serves");
        assert!(matches!(
            handle.offer_frame(packet(MAX_ENCODED_PACKET_BYTES + 1)),
            Err(AudioError::Malformed(_))
        ));
        assert_eq!(handle.snapshot().received_packets, 0);
        for _ in 0..AUDIO_PACKETS {
            handle.offer_frame(packet(40)).expect("queued");
        }
        assert_eq!(handle.offer_frame(packet(40)), Err(AudioError::Backpressure));
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.received_packets, AUDIO_PACKETS as u64);
        assert_eq!(snapshot.rejected_packets, 2);
    }

    /// A repeated format leaves a playing stream alone; a different one and an
    /// impossible one do not.
    #[test]
    fn only_a_new_format_advances_the_generation() {
        let cancel = CancellationToken::new();
        let playback = start(cancel);
        let handle = &playback.handle;
        handle.set_allowed(true);
        handle
            .offer_format(format(48_000, 2))
            .expect("a format Opus serves");
        let declared = handle.revision();
        handle
            .offer_format(format(48_000, 2))
            .expect("the same format again");
        assert_eq!(handle.revision(), declared);
        handle
            .offer_format(format(24_000, 1))
            .expect("another format Opus serves");
        assert_eq!(handle.revision(), declared + 1);
        // Rates and channel counts libopus and this core do not serve are
        // refused as such, not opened and failed later.
        assert_eq!(
            handle.offer_format(format(44_100, 2)),
            Err(AudioError::InvalidFormat)
        );
        assert_eq!(
            handle.offer_format(format(48_000, 3)),
            Err(AudioError::InvalidFormat)
        );
    }

    /// Cancellation is a close: nothing is accepted afterwards.
    #[test]
    fn cancellation_closes_the_handle() {
        let cancel = CancellationToken::new();
        let playback = start(cancel.clone());
        let handle = &playback.handle;
        handle.set_allowed(true);
        assert_eq!(handle.offer_frame(packet(40)), Err(AudioError::NoFormat));
        cancel.cancel();
        assert_eq!(
            handle.offer_format(format(48_000, 2)),
            Err(AudioError::Closed)
        );
        assert_eq!(handle.offer_frame(packet(40)), Err(AudioError::Closed));
    }

    /// A real Opus packet decodes to interleaved PCM at the declared channels.
    ///
    /// This is the whole decoder contract in one place: one packet in, and the
    /// per-channel frame count the decoder answers multiplied by the channel
    /// count as the interleaved length.
    #[test]
    fn opus_packets_decode_to_interleaved_pcm() {
        let rate = 48_000;
        let mut encoder = Encoder::new(rate, Channels::Stereo, Application::Audio)
            .expect("a stereo encoder at 48 kHz");
        let mut decoder = Decoder::new(rate, Channels::Stereo).expect("a stereo decoder");
        // 20 ms of a quiet tone, interleaved, which is one legal Opus frame.
        let tone: Vec<f32> = (0..960)
            .flat_map(|frame| {
                let value = ((frame as f32) * 0.05).sin() * 0.25;
                [value, value]
            })
            .collect();
        let mut encoded = vec![0u8; 4_000];
        let length = encoder
            .encode_float(&tone, &mut encoded)
            .expect("a legal frame encodes");
        let mut buffer = Vec::new();
        let samples = decode_packet(&mut decoder, rate, 2, &mut buffer, &encoded[..length])
            .expect("a packet this core encoded decodes");
        assert_eq!(samples, 960 * 2);
        assert!(
            buffer[..samples].iter().any(|sample| *sample != 0.0),
            "a decoded tone is not silence"
        );
    }

    /// A packet libopus cannot read is refused as malformed, not decoded.
    #[test]
    fn malformed_opus_packets_are_refused() {
        let mut decoder = Decoder::new(48_000, Channels::Mono).expect("a mono decoder");
        let mut buffer = Vec::new();
        for rejected in [&[0u8; 0][..], &[0xffu8][..]] {
            let outcome = decode_packet(&mut decoder, 48_000, 1, &mut buffer, rejected)
                .expect_err("a packet with no legal Opus frame is refused");
            assert!(
                matches!(
                    &outcome,
                    AudioError::Malformed(_) | AudioError::Decoder { .. }
                ),
                "unexpected answer: {outcome}"
            );
        }
    }
}

