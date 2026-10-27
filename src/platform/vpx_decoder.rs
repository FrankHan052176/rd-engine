//! Opt-in software VP8/VP9 decoding through a system libvpx.
//!
//! This is the only backend that decodes VPx on a target that has no platform
//! VPx decoder. It is a CPU path: libvpx writes I420 into its own buffers and
//! this module converts every decoded picture to the engine's BGRA memory
//! order, so pixels leave exclusively through the lease's
//! [`FrameObserver`](crate::surface::FrameObserver) - there is no Surface, no
//! NativeWindow and no GPU involvement anywhere in this file.
//!
//! Integration (owned by the decoder facade, not by this file)
//! -----------------------------------------------------------
//! `src/platform/decoder.rs` declares this file, and nothing here is reachable
//! until it does:
//!
//! ```ignore
//! #[cfg(feature = "software-vpx")]
//! #[path = "vpx_decoder.rs"]
//! pub mod software;
//! ```
//!
//! The facade's later arm is one expression, because the method set below is
//! the facade's own:
//!
//! ```ignore
//! VideoCodec::Vp8 | VideoCodec::Vp9 => SurfaceDecoder::Software(software::Decoder::open(config, lease)?),
//! ```
//!
//! [`probe`] is the capability entry point for the login/ability gate: it is
//! the only thing here that may be called without opening a decoder, and it
//! reports its own evidence level rather than a bare boolean.
//!
//! Gates, in order, all of them fail-closed
//! ----------------------------------------
//! 1. **Feature**: `software-vpx` (default off). Off means this module compiles
//!    to named refusals and every entry point answers
//!    [`DecoderError::UnsupportedCodec`]; no libvpx symbol is referenced, so a
//!    build without the feature cannot link the library at all.
//! 2. **Link**: `build.rs` resolves an installed libvpx (pkg-config, then an
//!    explicit `LIBVPX_*`, then the host's own Homebrew keg and system prefixes
//!    - the last two only when `HOST == TARGET`) and never downloads or builds
//!    one. A cross build with no target library resolves to "unavailable"
//!    instead of linking a host-architecture archive. The MSVC Windows target
//!    is the one pinned exception: an explicit `LIBVPX_PREFIX` decides there
//!    for itself, and every candidate accepted there - named or discovered
//!    through pkg-config - must be the vendored overlay's static
//!    `x64-windows-static-md` prefix at libvpx 1.15.2. So `vpx.lib` is the one
//!    archive a Windows MSVC build links, GNU Windows keeps the Unix archive
//!    name, and no Windows target emits the Unix `m`/`pthread` names. When
//!    nothing resolves, the build is not broken: the feature stays unavailable
//!    and the reason is recorded in [`LINK`].
//! 3. **Runtime version**: `vpx_codec_version()` names the release actually
//!    loaded and must be at or above [`MIN_VERSION`]; an unparseable or absent
//!    answer is refused, never assumed.
//! 4. **Interface**: the codec's own interface must exist and advertise
//!    `VPX_CODEC_CAP_DECODER`.
//! 5. **ABI and allocation**: `vpx_codec_dec_init_ver` is called with the
//!    `VPX_DECODER_ABI_VERSION` that `vpx_ffi.rs` recorded from the headers, so
//!    a library whose layout differs answers `VPX_CODEC_ABI_MISMATCH` instead
//!    of being misread. Only an accepted init makes a decoder, and every init
//!    in this process - `probe`'s and each worker's - runs under one
//!    process-wide lock (`INIT_LOCK`), which is the serialization
//!    `vpx_decoder.h` requires when a library was built
//!    `--disable-multithread`. Decoding itself stays per-context and is never
//!    serialized by it.
//! 6. **Sink**: the lease must expose a frame observer. A display-only lease
//!    (no CPU consumer) is refused with `InvalidConfig` before any allocation,
//!    because publishing decoded pixels nowhere and counting it as a submission
//!    would be a fabricated statistic.
//!
//! What this module refuses to claim
//! ---------------------------------
//! * No H264/H265: they belong to the platform decoder and are named
//!   `UnsupportedCodec` here. This file cannot make a hardware or GPU claim.
//! * No colour conversion beyond what the bitstream says. The conversion is
//!   BT.709 limited-range (the engine's transport contract) derived from exact
//!   spec fractions at compile time, and it honours a stream that signals the
//!   BT.601 family or full range. BT.2020/4:4:4/10-12 bit output is refused by
//!   name rather than relabelled or clipped, matching `media_color.rs`.
//! * No `quarantined`. The OHOS backend retains its lease when a native
//!   destruction failure leaves callbacks that might still run; libvpx is
//!   registered with no callbacks at all and receives no lease, so once the
//!   worker thread has joined, nothing can reach the caller's memory. A failed
//!   `vpx_codec_destroy` is reported as a real failure and never as a retained
//!   lease, so `DecoderProjection::cleanup` stays `Confirmed`.
//! * No fabricated counters. Every number in [`Counters`] is measured here:
//!   latency runs from handing a unit to the codec until its picture is
//!   handed to the observer, and nothing is filled in when it was not measured.
//! * No bitstream proof. [`probe`] proves the library, the ABI and a real
//!   context init; it does not prove that a RustDesk VP8/VP9 stream decodes,
//!   because this module has no sample to decode. See [`CapabilityEvidence`].
//!
//! Lifetime rules taken from `vpx_decoder.h`
//! -----------------------------------------
//! * The coded bytes must stay alive until the frame is decoded: the unit is
//!   borrowed for the whole `vpx_codec_decode` call.
//! * `deadline` is always 0 (the header states it is ignored).
//! * The images `vpx_codec_get_frame` returns are valid only until the next
//!   `vpx_codec_decode`: every picture is converted and published inside that
//!   window, and none is retained for later.
//! * A failed `vpx_codec_dec_init_ver` leaves nothing to destroy, and
//!   `vpx_codec_destroy` is called exactly once, only after a successful init.
//! * Library-owned images are never freed here: `vpx_img_free` belongs to
//!   application-allocated descriptors, and this module never allocates one.
//!
//! Teardown, and a worker that panics
//! ----------------------------------
//! * The worker publishes its own terminal record: a normal return or an error
//!   both end in `closed` after the context is destroyed, so the queue is
//!   empty and every admitted unit that never retired is counted once as
//!   cancelled.
//! * A panic on the worker thread - the caller's frame observer is safe Rust
//!   this worker calls for every picture, so it can panic - unwinds through the
//!   owner, whose `Drop` destroys the context, and is caught by the worker's
//!   entry guard. The guard records `WorkerPanicked` as the failure, settles
//!   the queue the same way a normal close does, sets `closed`, notifies the
//!   capacity waiters and re-raises the payload. `submit_cancellable` therefore
//!   returns instead of waiting forever, `wait_stopped` sees the failure, and
//!   `close` still reports `WorkerPanicked`.
//! * This path retains no lease either: libvpx holds no callback into the
//!   caller's memory, and the context is destroyed on the worker's own stack
//!   before the record is published. Whether that last destroy returned an
//!   error is not observable from the guard and is not claimed.
//!
//! Verification performed when this file was added
//! -----------------------------------------------
//! * The conversion was **executed**. The block from `FIXED_SHIFT` through
//!   `stride_of` and the conversion tests were extracted verbatim into a
//!   throwaway binary and run on this machine: limited- and full-range black
//!   and white, per-row strides with padding, chroma clamping, neutral chroma
//!   across both matrices, and the format/colour refusals all pass against
//!   hand-derived anchors rather than against the formula itself.
//! * The whole file was **type-checked** with `rustc --emit=metadata` in three
//!   configurations (feature off, feature on, feature on with the tests)
//!   against faithful stubs of the facade's own types, the engine's frame
//!   observer and the rect/layout helpers: no errors, and no warning from this
//!   file in any of them.
//! * `build.rs` was type-checked and then **executed** for macOS,
//!   OpenHarmony, Windows-without-a-library, env-override and feature-off
//!   environments; the link lines it emits on each are recorded in its own
//!   documentation, and every one of them was read from a real run.
//! * **Not** verified: no Cargo build, test, link or run of this crate was
//!   performed, so the crate has not yet been linked against libvpx by Cargo
//!   and nothing here has decoded a real VP8/VP9 bitstream. The `probe`
//!   evidence level in this file is therefore `Opened`, never
//!   `FirstNativeOutput`.
//! * The linked probe test added with the Windows integration
//!   (`engine::tests::probe_opens_both_advertised_codecs`) has **not** been run
//!   here either: it needs a target where `build.rs` resolved libvpx, which is
//!   what the Windows workflow provisions. Executing it there is the step that
//!   turns a capability answer into observed evidence; until a runner reports
//!   that pass, every statement in this file about `Opened` is static.
//! * The worker's unwind guard, the shared init lock and `build.rs`'s
//!   target-aware candidate rules were added after that check, by static edit
//!   alone: they are source-reviewed, and they have not been compiled or run
//!   either.

use crate::viewer::decoder::{
    AccessUnit, AccessUnitKind, CleanupVerdict, DecoderConfig, DecoderError, DecoderProjection,
    OpenFailure, RejectedSubmission, RenderTiming, SurfaceLease, VideoCodec,
};
use std::{fmt, sync::Arc};
use tokio_util::sync::CancellationToken;

/// How far this process has actually proved the backend, in the ladder the
/// engine already uses for capability claims (`platform/windows_presentation.rs`).
///
/// This module never reports more than [`CapabilityEvidence::Opened`]: that rung
/// means the library answered, the ABI was accepted, and a real decoder context
/// for this codec initialized and was destroyed. `FirstNativeOutput` needs a
/// real VP8/VP9 bitstream, which this module has none of, so it will not claim
/// it.
pub use crate::windows_presentation::CapabilityEvidence;

// The generated declarations keep libvpx's C names (`vpx_image_t`,
// `vpx_img_fmt_VPX_IMG_FMT_I420`) and declare the whole decoder ABI, not only
// the calls this file makes today: rewriting either by hand is exactly what
// would make a one-shot binding untrustworthy, so the lints that object to
// generated style and to a deliberately complete surface are allowed here.
#[cfg(all(feature = "software-vpx", rd_vpx_linked))]
#[path = "vpx_ffi.rs"]
#[allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]
mod ffi;

/// The release this module was audited against, recorded for provenance. The
/// gate itself reads the *loaded* library at run time ([`MIN_VERSION`]).
pub const AUDITED: &str = "libvpx 1.17.0";

/// Oldest release this module runs at, as `(major, minor, patch)`.
///
/// This is a policy, not a discovery: the module is audited against 1.17.0 and
/// refuses older lines instead of assuming they behave the same way. It is not
/// the safety-critical check - `vpx_codec_dec_init_ver` rejects a library with
/// a different ABI - it is what stops a pre-2016 libvpx from being used as if
/// the audit covered it.
pub const MIN_VERSION: (u32, u32, u32) = (1, 8, 0);

/// How the build resolved libvpx, for logs, bug reports and refusal text.
///
/// Set by `build.rs`, one line: `<static|dylib> via <origin>: headers <dir>
/// library <dir> (<version>)`, or `unavailable: <why>`. Without the feature it
/// says so.
pub const LINK: &str = match option_env!("RD_LIBVPX_PROVENANCE") {
    Some(text) => text,
    None => "software-vpx is not enabled in this build",
};

/// The version the linked library reports about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The packed `major << 16 | minor << 8 | patch` value, as returned.
    pub packed: i32,
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// `vpx_codec_version_str()`, which may carry release-candidate text.
    pub text: String,
}

/// Positive runtime evidence for one codec, from a real context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub codec: VideoCodec,
    pub version: Version,
    /// `vpx_codec_iface_name` for the decoder interface that answered.
    pub iface: String,
    /// The decoder ABI number this build was generated against.
    pub abi: i32,
    /// `vpx_codec_get_caps` for that interface, as reported.
    pub caps: i64,
    pub evidence: CapabilityEvidence,
}

/// Why a probe or version gate did not pass.
///
/// The frozen [`DecoderError`] carries the machine-readable reason; `detail` is
/// the library's own text (bounded, copied out of libvpx immediately, because
/// the header says its strings die at the next call on the context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub reason: DecoderError,
    pub detail: Option<String>,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => write!(formatter, "{:?}: {detail}", self.reason),
            None => write!(formatter, "{:?}", self.reason),
        }
    }
}

impl std::error::Error for Error {}

/// This backend's own decode record.
///
/// Field for field the OHOS backend's `DecoderStats`, because both backends
/// describe the same work; [`DecoderProjection`] is the normalized subset the
/// facade exposes. `queued_units` is read, not counted: it is what is in the
/// decoder's hands *now* (queued plus the unit being decoded), which is why a
/// snapshot cannot be reconstructed from the other counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub accepted_units: u64,
    /// Units handed to the codec (a failed admission never reaches here).
    pub pushed_units: u64,
    /// Pictures handed to the frame observer. Delivery, never scanout.
    pub render_submissions: u64,
    /// Pictures with an actual elapsed-time observation.
    pub render_samples: u64,
    /// Measured from handing a unit to the codec until each of its pictures was
    /// handed to the observer, summed over `render_samples`.
    pub render_ns: u64,
    /// The worst single observation behind `render_ns`.
    pub render_peak_ns: u64,
    /// Pictures the codec produced with no displayable geometry (nothing was
    /// published for them, and they are not counted as submissions).
    pub non_frame_outputs: u64,
    /// Times the decoded geometry changed mid-stream.
    pub format_change_notifications: u64,
    /// Admitted units that ended without being retired: a refused submission is
    /// returned to its caller and is not counted here.
    pub cancelled_units: u64,
    /// Admitted units in the decoder's hands at this snapshot.
    pub queued_units: u64,
    pub end_of_stream_output: bool,
    pub closed: bool,
    /// Always false for this backend; see the module documentation.
    pub quarantined: bool,
    pub failure: Option<DecoderError>,
}

/// The seam's neutral view of this backend's record, built where there is a
/// backend to report on.
#[cfg(all(feature = "software-vpx", rd_vpx_linked))]
fn projection(counters: &Counters) -> DecoderProjection {
    DecoderProjection {
        pushed_units: counters.pushed_units,
        render_submissions: counters.render_submissions,
        render_timing: (counters.render_samples != 0).then_some(RenderTiming {
            samples: counters.render_samples,
            total_ns: counters.render_ns,
            peak_ns: counters.render_peak_ns,
        }),
        queued_units: counters.queued_units,
        closed: counters.closed,
        quarantined: counters.quarantined,
        failure: counters.failure.clone(),
    }
}

/// The version the linked library reports, gated by [`MIN_VERSION`].
///
/// Call it from a blocking context: this is the run-time evidence a capability
/// report is allowed to cite, and it never guesses.
pub fn version() -> Result<Version, Error> {
    engine::version()
}

/// Probes one codec: version, interface, capabilities, and a real context init.
///
/// Only a `Vp8`/`Vp9` argument is a request; asking for `H264`/`H265` is
/// refused because they are never served from here.
pub fn probe(codec: VideoCodec) -> Result<Probe, Error> {
    engine::probe(codec)
}

/// Software VP8/VP9 decoder: one worker thread, one libvpx context per stream.
///
/// Method for method the facade's decoder, so the facade's arm is a
/// construction and not an adapter: `open`, `observer`, `try_submit`,
/// `submit_cancellable`, `codec_name`, `stats`, `request_close`, `close`, and
/// `Drop` joins (the worker is never detached and never leaked).
pub struct Decoder {
    inner: engine::Decoder,
}

impl Decoder {
    /// Opens a decoder, which starts its worker and initializes the context.
    ///
    /// Synchronous and blocking, like the facade's other backends: call it off
    /// an async task. Every failure is `CleanupVerdict::Confirmed` - see the
    /// module documentation for why this backend can never retain a lease.
    pub fn open(config: DecoderConfig, lease: Arc<dyn SurfaceLease>) -> Result<Self, OpenFailure> {
        engine::Decoder::open(config, lease).map(|inner| Self { inner })
    }

    /// A handle that observes without owning or joining the worker; safe to
    /// keep in a snapshot after the decoder was closed.
    pub fn observer(&self) -> Observer {
        Observer {
            inner: self.inner.observer(),
        }
    }

    /// Non-blocking admission. A refusal returns ownership of the unit, so the
    /// caller can retry it ahead of the stream's later units.
    pub fn try_submit(&self, unit: AccessUnit) -> Result<(), RejectedSubmission> {
        self.inner.try_submit(unit)
    }

    /// Admission that waits for capacity and wakes on cancellation.
    ///
    /// The capacity notification is registered before admission, so a wakeup
    /// cannot be lost, and cancellation returns the unit instead of dropping it.
    pub async fn submit_cancellable(
        &self,
        unit: AccessUnit,
        cancel: &CancellationToken,
    ) -> Result<(), RejectedSubmission> {
        self.inner.submit_cancellable(unit, cancel).await
    }

    /// The decoded codec's own name: `libvpx <version> <interface> (software)`.
    /// Never an alias for H264/H265.
    pub fn codec_name(&self) -> Result<&str, DecoderError> {
        self.inner.codec_name()
    }

    /// The normalized projection the facade consumes.
    pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
        self.inner.stats()
    }

    /// This backend's full record, including the counters the projection drops.
    pub fn counters(&self) -> Counters {
        self.inner.counters()
    }

    /// Non-blocking stop request; the worker still has to be joined by `close`.
    pub fn request_close(&self) {
        self.inner.request_close();
    }

    /// Joins the worker and reports its final projection.
    ///
    /// An error here is a real one (a decode-loop failure, a failed
    /// `vpx_codec_destroy`, or a panic on the worker thread, which is
    /// `WorkerPanicked`) and does not mean the lease was retained: read the
    /// projection's `cleanup`, which is `Confirmed` whenever the worker joined.
    pub fn close(self) -> Result<DecoderProjection, DecoderError> {
        self.inner.close()
    }
}

/// Observes a running decoder without owning it.
#[derive(Clone)]
pub struct Observer {
    inner: engine::Observer,
}

impl Observer {
    pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
        self.inner.stats()
    }

    pub fn counters(&self) -> Counters {
        self.inner.counters()
    }

    pub fn request_close(&self) {
        self.inner.request_close()
    }

    /// Completes when the decoder stops, and never with `Ok`: the feeder reads
    /// this future's answer as a stop signal, so a successful stop is `Closed`
    /// (the same contract the OHOS observer has).
    pub async fn wait_stopped(&self) -> Result<(), DecoderError> {
        self.inner.wait_stopped().await
    }
}

#[cfg(all(feature = "software-vpx", rd_vpx_linked))]
mod engine {
    use super::*;
    use crate::{
        protocol::rect::{PixelLayout, Rect},
        surface::FrameObserver,
    };
    use std::{
        collections::VecDeque,
        ffi::CStr,
        mem::MaybeUninit,
        os::raw::{c_int, c_long, c_uint},
        panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
        ptr,
        sync::{Condvar, Mutex, MutexGuard, mpsc},
        thread::{self, JoinHandle},
        time::Instant,
    };

    /// Largest accepted edge of one decoded frame. The same bound the
    /// presentation sink applies (`platform/ohos_surface.rs`), so a peer-named
    /// geometry cannot size a buffer this process could not back.
    const MAX_DIMENSION: u32 = 16_384;
    /// Admission maxima. The viewer asks for 2 units / 32 MiB; a caller asking
    /// for more than these is refused rather than trusted.
    const MAX_QUEUED_UNITS: usize = 64;
    const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;
    /// One worker per stream, one decoder thread inside libvpx: the same
    /// single-threaded-per-stream invariant the OHOS backend keeps.
    const DECODER_THREADS: u32 = 1;
    const DECODER_THREAD_NAME: &str = "rd-vpx-software-decoder";
    /// Alpha byte of every written pixel. The sinks' frame contract is opaque
    /// BGRA (`native/frb/src/frames.rs`), not `PixelLayout::pack`'s zero alpha.
    const OPAQUE: u8 = 0xff;
    /// The layout this module writes must be the one the sinks negotiate; a
    /// change there becomes a compile error here instead of a channel swap.
    const LAYOUT: PixelLayout = PixelLayout::bgra8888();
    const _: () = assert!(
        LAYOUT.bytes_per_pixel == 4
            && LAYOUT.red_shift == 16
            && LAYOUT.green_shift == 8
            && LAYOUT.blue_shift == 0
            && !LAYOUT.big_endian
    );
    const BYTES_PER_PIXEL: usize = LAYOUT.bytes_per_pixel as usize;

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Serializes every `vpx_codec_dec_init_ver` call in this process.
    ///
    /// The header `vpx_ffi.rs` was generated from states it verbatim: "If the
    /// library was configured with --disable-multithread, this call is not
    /// thread safe and should be guarded with a lock if being used in a
    /// multithreaded context." The library this backend links is whatever
    /// pkg-config or `LIBVPX_*` resolved, so a `--disable-multithread` build is
    /// a real possibility and this lock is a precondition, not a precaution.
    ///
    /// `probe` and the worker's `setup` are the only two callers, and both hold
    /// it for the init call alone: `vpx_codec_decode` is per-context and is
    /// never serialized by it.
    static INIT_LOCK: Mutex<()> = Mutex::new(());

    /// The init lock, taken the same poison-tolerant way as every other lock
    /// here: a panic inside one initialization must not wedge every later one,
    /// and this guard's payload is `()` so a poisoned guard carries no
    /// invariant that trusting it could violate.
    fn init_guard() -> MutexGuard<'static, ()> {
        lock(&INIT_LOCK)
    }

    fn error_text(err: ffi::vpx_codec_err_t) -> String {
        let text = unsafe { ffi::vpx_codec_err_to_string(err) };
        if text.is_null() {
            return format!("code {err}");
        }
        unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned()
    }

    fn described(api: &'static str, err: ffi::vpx_codec_err_t) -> Error {
        Error {
            reason: DecoderError::Native {
                api,
                code: err as i32,
            },
            detail: Some(format!("{api}: {} ({err})", error_text(err))),
        }
    }

    pub fn version() -> Result<Version, Error> {
        let packed = unsafe { ffi::vpx_codec_version() };
        let text = unsafe { ffi::vpx_codec_version_str() };
        if text.is_null() {
            return Err(Error {
                reason: DecoderError::NativeReturnedNull {
                    api: "vpx_codec_version_str",
                },
                detail: Some("the library did not name its own release".into()),
            });
        }
        let version = Version {
            packed,
            major: (packed >> 16 & 0xff) as u32,
            minor: (packed >> 8 & 0xff) as u32,
            patch: (packed & 0xff) as u32,
            text: unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned(),
        };
        if packed <= 0 || (version.major, version.minor, version.patch) < MIN_VERSION {
            return Err(Error {
                reason: DecoderError::Native {
                    api: "vpx_codec_version",
                    code: packed,
                },
                detail: Some(format!(
                    "libvpx {} is older than the {}.{}.{} floor this module runs at ({AUDITED})",
                    version.text, MIN_VERSION.0, MIN_VERSION.1, MIN_VERSION.2
                )),
            });
        }
        Ok(version)
    }

    /// The decoder interface for `codec`, with the name the library gives it.
    fn interface(codec: VideoCodec) -> Result<(*const ffi::vpx_codec_iface, String), Error> {
        let (iface, call) = match codec {
            VideoCodec::Vp8 => (unsafe { ffi::vpx_codec_vp8_dx() }, "vpx_codec_vp8_dx"),
            VideoCodec::Vp9 => (unsafe { ffi::vpx_codec_vp9_dx() }, "vpx_codec_vp9_dx"),
            // The two hardware categories are never served from a software
            // library: naming them here keeps the refusal attributable.
            VideoCodec::H264 | VideoCodec::H265 => {
                return Err(Error {
                    reason: DecoderError::UnsupportedCodec,
                    detail: Some(format!(
                        "{codec:?} belongs to the platform decoder backend, never here"
                    )),
                })
            }
        };
        if iface.is_null() {
            return Err(Error {
                reason: DecoderError::NativeReturnedNull { api: call },
                detail: Some(format!("{codec:?} is absent from the linked libvpx")),
            });
        }
        let name = unsafe { ffi::vpx_codec_iface_name(iface) };
        if name.is_null() {
            return Err(Error {
                reason: DecoderError::NativeReturnedNull {
                    api: "vpx_codec_iface_name",
                },
                detail: Some(format!("{call} returned an interface with no name")),
            });
        }
        Ok((
            iface,
            unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned(),
        ))
    }

    fn capabilities(iface: *const ffi::vpx_codec_iface) -> Result<i64, Error> {
        let caps = unsafe { ffi::vpx_codec_get_caps(iface) };
        if caps & (ffi::VPX_CODEC_CAP_DECODER as c_long) == 0 {
            return Err(Error {
                reason: DecoderError::Native {
                    api: "vpx_codec_get_caps",
                    code: caps as i32,
                },
                detail: Some("the interface does not advertise a decoder".into()),
            });
        }
        Ok(caps as i64)
    }

    /// The gate `open` runs before anything is allocated or spawned: the
    /// loaded library's version, the codec's own interface and its decoder
    /// capability. The worker resolves the interface again for itself, because
    /// a raw libvpx pointer is not `Send` and must not cross a thread boundary.
    fn gate(codec: VideoCodec) -> Result<(), DecoderError> {
        version().map_err(|error| error.reason)?;
        let (iface, _) = interface(codec).map_err(|error| error.reason)?;
        capabilities(iface).map_err(|error| error.reason)?;
        Ok(())
    }

    pub fn probe(codec: VideoCodec) -> Result<Probe, Error> {
        let version = version()?;
        let (iface, iface_name) = interface(codec)?;
        let caps = capabilities(iface)?;
        // A real context, initialized with the ABI number baked into
        // `vpx_ffi.rs` and then destroyed: this is what turns "the library is
        // here" into "this codec can actually be opened here", because the ABI
        // is checked by libvpx itself and the allocation is real.
        let cfg = ffi::vpx_codec_dec_cfg_t {
            threads: DECODER_THREADS,
            w: 0,
            h: 0,
        };
        let mut ctx = MaybeUninit::<ffi::vpx_codec_ctx_t>::zeroed();
        // Every context in this process is created under `INIT_LOCK`, and the
        // guard is scoped to the init call: the destroy below runs unlocked.
        let err = {
            let _init = init_guard();
            unsafe {
                ffi::vpx_codec_dec_init_ver(
                    ctx.as_mut_ptr(),
                    iface,
                    &cfg,
                    0,
                    ffi::VPX_DECODER_ABI_VERSION as c_int,
                )
            }
        };
        if err != ffi::vpx_codec_err_t_VPX_CODEC_OK {
            // vpx_decoder.h: a failed init leaves nothing owned, so there is
            // nothing to destroy and nothing unproven to report.
            return Err(described("vpx_codec_dec_init_ver", err));
        }
        let err = unsafe { ffi::vpx_codec_destroy(ctx.as_mut_ptr()) };
        if err != ffi::vpx_codec_err_t_VPX_CODEC_OK {
            return Err(described("vpx_codec_destroy", err));
        }
        Ok(Probe {
            codec,
            version,
            iface: iface_name,
            abi: ffi::VPX_DECODER_ABI_VERSION as i32,
            caps,
            evidence: CapabilityEvidence::Opened,
        })
    }

    // ---- I420 to BGRA ------------------------------------------------------

    /// Fixed-point denominator of every coefficient below: the rounding step is
    /// one `>> FIXED_SHIFT`.
    const FIXED_SHIFT: u32 = 16;
    const FIXED_ONE: i64 = 1 << FIXED_SHIFT;
    /// Half of the denominator, which turns the shift into round-to-nearest.
    const ROUND: i32 = 1 << (FIXED_SHIFT - 1);

    /// Rounds one exact spec fraction to the fixed-point scale, once, at compile
    /// time, so the constants are derived rather than hand-rounded decimals.
    const fn fixed(numerator: i64, denominator: i64) -> i32 {
        ((numerator * FIXED_ONE + denominator / 2) / denominator) as i32
    }

    /// A colour matrix's `Kr`/`Kb`, in units of 1/10000.
    struct Matrix {
        kr: i64,
        kb: i64,
    }
    const MATRIX_DEN: i64 = 10_000;
    /// The engine's SDR contract (`media_color.rs`), and what an unlabelled
    /// stream is treated as: `vpx_image_t.cs` is `VPX_CS_UNKNOWN` for VP8 and
    /// `VPX_CS_SRGB` means BT.709 matrix coefficients in WebM.
    const BT709: Matrix = Matrix { kr: 2126, kb: 722 };
    /// The 601 family, which VP8 streams commonly signal.
    const BT601: Matrix = Matrix { kr: 2990, kb: 1140 };

    /// `(gain/224) * 2 * (1 - Kr)`, the V coefficient of R.
    const fn red_from_v(matrix: &Matrix, gain: i64) -> i32 {
        fixed(gain * 2 * (MATRIX_DEN - matrix.kr), 224 * MATRIX_DEN)
    }
    /// `(gain/224) * 2 * Kb * (1 - Kb) / Kg`, the U coefficient of G.
    const fn green_from_u(matrix: &Matrix, gain: i64) -> i32 {
        fixed(
            gain * 2 * matrix.kb * (MATRIX_DEN - matrix.kb),
            224 * MATRIX_DEN * (MATRIX_DEN - matrix.kr - matrix.kb),
        )
    }
    /// `(gain/224) * 2 * Kr * (1 - Kr) / Kg`, the V coefficient of G.
    const fn green_from_v(matrix: &Matrix, gain: i64) -> i32 {
        fixed(
            gain * 2 * matrix.kr * (MATRIX_DEN - matrix.kr),
            224 * MATRIX_DEN * (MATRIX_DEN - matrix.kr - matrix.kb),
        )
    }
    /// `(gain/224) * 2 * (1 - Kb)`, the U coefficient of B.
    const fn blue_from_u(matrix: &Matrix, gain: i64) -> i32 {
        fixed(gain * 2 * (MATRIX_DEN - matrix.kb), 224 * MATRIX_DEN)
    }

    /// One matrix in one range, as the arithmetic below uses it.
    struct Coeffs {
        y_gain: i32,
        y_bias: i32,
        r_v: i32,
        g_u: i32,
        g_v: i32,
        b_u: i32,
    }

    const fn coefficients(matrix: &Matrix, limited: bool) -> Coeffs {
        // Limited range: Y is expanded from [16, 235] to [0, 255] and chroma
        // from [16, 240]; full range is unscaled. `gain/224` is the chroma
        // scale, `255/219` the luma one.
        let gain = if limited { 255 } else { 224 };
        let y_gain = if limited {
            fixed(255, 219)
        } else {
            fixed(224, 224)
        };
        Coeffs {
            y_gain,
            y_bias: if limited { -(16 * y_gain) } else { 0 },
            r_v: red_from_v(matrix, gain),
            g_u: green_from_u(matrix, gain),
            g_v: green_from_v(matrix, gain),
            b_u: blue_from_u(matrix, gain),
        }
    }

    /// `[matrix][range]`: BT.709 then BT.601, each limited then full range.
    const COEFFS: [[Coeffs; 2]; 2] = [
        [coefficients(&BT709, true), coefficients(&BT709, false)],
        [coefficients(&BT601, true), coefficients(&BT601, false)],
    ];

    fn clamp(value: i32) -> u8 {
        value.clamp(0, 255) as u8
    }

    /// The coefficients this image's own metadata calls for.
    fn coefficients_for(image: &ffi::vpx_image_t) -> Result<&'static Coeffs, DecoderError> {
        // I420 8-bit is the one shape this module converts. 4:4:4/4:2:2 and
        // 10/12-bit output would each need their own reader and bit depth, and
        // a frame this module cannot represent must be named, not approximated.
        if image.fmt != ffi::vpx_img_fmt_VPX_IMG_FMT_I420 || image.bit_depth != 8 {
            return Err(DecoderError::UnsupportedCodec);
        }
        let matrix = match image.cs {
            ffi::vpx_color_space_VPX_CS_BT_601
            | ffi::vpx_color_space_VPX_CS_SMPTE_170
            | ffi::vpx_color_space_VPX_CS_SMPTE_240 => 1,
            ffi::vpx_color_space_VPX_CS_BT_709
            | ffi::vpx_color_space_VPX_CS_SRGB
            | ffi::vpx_color_space_VPX_CS_UNKNOWN => 0,
            // BT.2020 needs primaries and a transfer function this engine has no
            // stage for; `media_color.rs` refuses to relabel such content rather
            // than clip it, and so does this.
            _ => return Err(DecoderError::UnsupportedCodec),
        };
        let range = match image.range {
            ffi::vpx_color_range_VPX_CR_FULL_RANGE => 1,
            _ => 0,
        };
        Ok(&COEFFS[matrix][range])
    }

    /// Converts one decoded picture into the engine's BGRA memory order.
    ///
    /// Reads exactly the visible `d_w` x `d_h` region through each plane's own
    /// stride, so the stored geometry's padding is never touched, and writes
    /// `d_w * 4` bytes per row into `out` at `stride`.
    ///
    /// # Safety
    /// `image` must be a pointer `vpx_codec_get_frame` returned during the
    /// decode that just finished, still inside the window the header allows
    /// (until the next `vpx_codec_decode`), and `out` must be at least
    /// `stride * d_h` bytes.
    unsafe fn convert(
        image: &ffi::vpx_image_t,
        coeffs: &Coeffs,
        out: &mut [u8],
        stride: usize,
    ) -> Result<(), DecoderError> {
        let (stored_w, stored_h) = (image.w, image.h);
        let (width, height) = (image.d_w, image.d_h);
        if stored_w == 0 || stored_h == 0 || width > stored_w || height > stored_h {
            return Err(DecoderError::InvalidAccessUnit);
        }
        let chroma_w = (stored_w as usize + 1) / 2;
        let luma_stride = stride_of(image.stride[0], stored_w as usize)?;
        let chroma_stride = stride_of(image.stride[1], chroma_w)?;
        if image.stride[2] != image.stride[1] {
            // vpx_image.h states the chroma strides are equal for planar
            // formats; a library that disagrees is not one this reads.
            return Err(DecoderError::InvalidAccessUnit);
        }
        let (luma, u_plane, v_plane) = (image.planes[0], image.planes[1], image.planes[2]);
        if luma.is_null() || u_plane.is_null() || v_plane.is_null() {
            return Err(DecoderError::InvalidAccessUnit);
        }
        let rows = height as usize;
        if rows.saturating_mul(stride) > out.len() {
            return Err(DecoderError::InvalidAccessUnit);
        }
        // One unsafe block around the whole read: the planes, their strides and
        // the visible region were all validated above, and every offset below
        // stays inside the row and inside the frame the image reports.
        unsafe {
            for (row, destination) in out.chunks_exact_mut(stride).take(rows).enumerate() {
                let luma_row = luma.add(row * luma_stride);
                let chroma_row = row / 2;
                let u_row = u_plane.add(chroma_row * chroma_stride);
                let v_row = v_plane.add(chroma_row * chroma_stride);
                for (column, pixel) in destination.chunks_exact_mut(BYTES_PER_PIXEL).enumerate() {
                    let luma_value =
                        i32::from(*luma_row.add(column)) * coeffs.y_gain + coeffs.y_bias;
                    let chroma_column = column / 2;
                    let u = i32::from(*u_row.add(chroma_column)) - 128;
                    let v = i32::from(*v_row.add(chroma_column)) - 128;
                    let red = clamp((luma_value + coeffs.r_v * v + ROUND) >> FIXED_SHIFT);
                    let green = clamp(
                        (luma_value - coeffs.g_u * u - coeffs.g_v * v + ROUND) >> FIXED_SHIFT,
                    );
                    let blue = clamp((luma_value + coeffs.b_u * u + ROUND) >> FIXED_SHIFT);
                    pixel[0] = blue;
                    pixel[1] = green;
                    pixel[2] = red;
                    pixel[3] = OPAQUE;
                }
            }
        }
        Ok(())
    }

    fn stride_of(stride: c_int, minimum: usize) -> Result<usize, DecoderError> {
        usize::try_from(stride)
            .ok()
            .filter(|stride| *stride >= minimum)
            .ok_or(DecoderError::InvalidAccessUnit)
    }

    /// One reusable BGRA frame, sized to the geometry actually decoded.
    #[derive(Default)]
    struct FrameBuf {
        bytes: Vec<u8>,
        stride: usize,
        width: u32,
        height: u32,
    }

    impl FrameBuf {
        /// Sized fallibly and reused while the geometry is unchanged, so a
        /// steady stream allocates nothing and a geometry that cannot be backed
        /// is an error rather than an allocator abort. That single allocation
        /// is the only memory this module sizes from decoded output.
        fn prepare(&mut self, width: u32, height: u32) -> Result<usize, DecoderError> {
            let stride = width as usize * BYTES_PER_PIXEL;
            if self.width == width && self.height == height && self.stride == stride {
                return Ok(stride);
            }
            let needed = stride
                .checked_mul(height as usize)
                .ok_or(DecoderError::InvalidAccessUnit)?;
            self.bytes.clear();
            self.bytes
                .try_reserve_exact(needed)
                .map_err(|_| DecoderError::InvalidAccessUnit)?;
            self.bytes.resize(needed, 0);
            self.stride = stride;
            self.width = width;
            self.height = height;
            Ok(stride)
        }
    }

    // ---- the codec context -------------------------------------------------

    /// The libvpx context and the configuration it was initialized with.
    ///
    /// The configuration is a field rather than a temporary because
    /// `vpx_codec_ctx.config.dec` is a pointer into caller memory: whatever
    /// libvpx keeps of it must outlive the context.
    struct Codec {
        ctx: MaybeUninit<ffi::vpx_codec_ctx_t>,
        cfg: ffi::vpx_codec_dec_cfg_t,
        initialized: bool,
    }

    impl Codec {
        fn new() -> Self {
            Self {
                // libvpx initializes every field it uses on a successful init;
                // zeroed storage makes a half-written context impossible.
                ctx: MaybeUninit::zeroed(),
                cfg: ffi::vpx_codec_dec_cfg_t {
                    threads: DECODER_THREADS,
                    w: 0,
                    h: 0,
                },
                initialized: false,
            }
        }

        /// `vpx_decoder.h`: destroy exactly what a successful init created, and
        /// never retry a destroy that already failed.
        fn destroy(&mut self) -> Result<(), ffi::vpx_codec_err_t> {
            if !self.initialized {
                return Ok(());
            }
            self.initialized = false;
            let err = unsafe { ffi::vpx_codec_destroy(self.ctx.as_mut_ptr()) };
            if err == ffi::vpx_codec_err_t_VPX_CODEC_OK {
                Ok(())
            } else {
                Err(err)
            }
        }
    }

    /// Everything the worker owns. Lives on the worker's stack and is dropped
    /// by it, so no libvpx pointer is ever reachable from another thread.
    struct Owner {
        shared: Arc<Shared>,
        /// Resolved by `setup`, on this thread: libvpx interface pointers are
        /// static and immutable, but they are raw pointers and so are not
        /// `Send`, which is why the worker looks its interface up itself
        /// instead of receiving one that `open` resolved.
        iface: *const ffi::vpx_codec_iface,
        version: Version,
        codec: Codec,
        observer: Arc<dyn FrameObserver>,
        /// Anchors the caller's lease for as long as this worker could publish,
        /// so a lease is never dropped under a decoder that is still running.
        _lease: Arc<dyn SurfaceLease>,
        frame: FrameBuf,
        geometry: Option<(u32, u32)>,
    }

    impl Owner {
        fn setup(&mut self, config: DecoderConfig) -> Result<String, DecoderError> {
            let (iface, iface_name) = interface(config.codec).map_err(|error| error.reason)?;
            capabilities(iface).map_err(|error| error.reason)?;
            self.iface = iface;
            self.codec.cfg = ffi::vpx_codec_dec_cfg_t {
                threads: DECODER_THREADS,
                w: config.width as u32,
                h: config.height as u32,
            };
            // The same process-wide lock `probe` takes: a decoder opened while
            // another context is initializing must not enter a
            // `--disable-multithread` library's init concurrently. Only the
            // init call is inside the guard - the decode loop below is not.
            let err = {
                let _init = init_guard();
                unsafe {
                    ffi::vpx_codec_dec_init_ver(
                        self.codec.ctx.as_mut_ptr(),
                        self.iface,
                        &self.codec.cfg,
                        0,
                        ffi::VPX_DECODER_ABI_VERSION as c_int,
                    )
                }
            };
            if err != ffi::vpx_codec_err_t_VPX_CODEC_OK {
                return Err(DecoderError::Native {
                    api: "vpx_codec_dec_init_ver",
                    code: err as i32,
                });
            }
            self.codec.initialized = true;
            Ok(format!(
                "libvpx {} {iface_name} (software)",
                self.version.text
            ))
        }

        /// Destroys the context once and reports a failure as a failure. The
        /// lease is not retained: see the module documentation.
        fn shutdown(&mut self) -> Result<(), DecoderError> {
            match self.codec.destroy() {
                Ok(()) => Ok(()),
                Err(err) => {
                    let error = DecoderError::Native {
                        api: "vpx_codec_destroy",
                        code: err as i32,
                    };
                    self.shared.fail(error.clone());
                    Err(error)
                }
            }
        }

        fn decode(&mut self, unit: &AccessUnit, shared: &Shared) -> Result<(), DecoderError> {
            let (data, size) = match unit.kind {
                // vpx_decoder.h's flush call: NULL data and zero size drain the
                // pictures that are still inside the decoder.
                AccessUnitKind::EndOfStream => (ptr::null(), 0),
                // Admission refuses an empty access unit, so a frame always has
                // bytes, and they stay alive for this whole call.
                _ => (unit.bytes.as_ptr(), unit.bytes.len() as c_uint),
            };
            let err = unsafe {
                ffi::vpx_codec_decode(
                    self.codec.ctx.as_mut_ptr(),
                    data,
                    size,
                    ptr::null_mut(),
                    // The header states this parameter is ignored.
                    0,
                )
            };
            if err != ffi::vpx_codec_err_t_VPX_CODEC_OK {
                return Err(DecoderError::Native {
                    api: "vpx_codec_decode",
                    code: err as i32,
                });
            }
            let mut iter: ffi::vpx_codec_iter_t = ptr::null();
            loop {
                let image = unsafe { ffi::vpx_codec_get_frame(self.codec.ctx.as_mut_ptr(), &mut iter) };
                if image.is_null() {
                    return Ok(());
                }
                // The picture and its planes die at the next vpx_codec_decode,
                // so it is converted and published inside this window; nothing
                // outlives the iteration.
                self.publish(unsafe { &*image }, shared)?;
            }
        }

        fn publish(
            &mut self,
            image: &ffi::vpx_image_t,
            shared: &Shared,
        ) -> Result<(), DecoderError> {
            let (width, height) = (image.d_w, image.d_h);
            if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
                // Decoded, but not a picture anyone could be shown. Counting it
                // as a submission would be the fabricated statistic this module
                // exists to avoid.
                shared.non_frame();
                return Ok(());
            }
            let coeffs = coefficients_for(image)?;
            if self.geometry != Some((width, height)) {
                if self.geometry.is_some() {
                    shared.format_changed();
                }
                self.geometry = Some((width, height));
            }
            let stride = self.frame.prepare(width, height)?;
            unsafe { convert(image, coeffs, &mut self.frame.bytes, stride)? };
            self.observer.frame(
                width as i32,
                height as i32,
                stride,
                &self.frame.bytes,
                // F7: one frame, one full-frame damage rectangle.
                Rect::new(0, 0, width as i32, height as i32),
            );
            shared.published();
            Ok(())
        }
    }

    impl Drop for Owner {
        /// Only an unwind can reach this with a live context: every other path
        /// goes through `shutdown`, which clears `initialized` first, so the
        /// context is destroyed at most once.
        fn drop(&mut self) {
            if self.codec.initialized {
                self.codec.initialized = false;
                unsafe { ffi::vpx_codec_destroy(self.codec.ctx.as_mut_ptr()) };
            }
        }
    }

    // ---- admission, cancellation, accounting -------------------------------

    struct State {
        packets: VecDeque<AccessUnit>,
        /// Admitted units the worker has not retired: the queue plus, while a
        /// unit is being decoded, that unit.
        reserved_units: usize,
        reserved_bytes: usize,
        /// When the unit now being decoded entered the codec; the latency clock
        /// every picture it produces is measured against.
        in_flight: Option<Instant>,
        eos_accepted: bool,
        closing: bool,
        counters: Counters,
    }

    impl State {
        /// The terminal settlement, shared by a normal close and by a panic:
        /// the queue is empty, nothing stays reserved, and every admitted unit
        /// that never retired is counted once as cancelled, so the counters add
        /// up without being padded.
        fn settle(&mut self) {
            self.closing = true;
            self.counters.cancelled_units = self
                .counters
                .cancelled_units
                .saturating_add(self.reserved_units as u64);
            self.packets.clear();
            self.reserved_units = 0;
            self.reserved_bytes = 0;
            self.in_flight = None;
            self.counters.closed = true;
        }
    }

    /// The admission and accounting state shared by the caller and the worker.
    pub struct Shared {
        state: Mutex<State>,
        wake: Condvar,
        limits: DecoderConfig,
        capacity: tokio::sync::Notify,
    }

    impl Shared {
        fn new(limits: DecoderConfig) -> Result<Self, DecoderError> {
            if limits.width <= 0
                || limits.height <= 0
                || limits.width as u32 > MAX_DIMENSION
                || limits.height as u32 > MAX_DIMENSION
                || limits.max_queued_units == 0
                || limits.max_queued_units > MAX_QUEUED_UNITS
                || limits.max_queued_bytes == 0
                || limits.max_queued_bytes > MAX_QUEUED_BYTES
            {
                return Err(DecoderError::InvalidConfig);
            }
            Ok(Self {
                state: Mutex::new(State {
                    packets: VecDeque::with_capacity(limits.max_queued_units),
                    reserved_units: 0,
                    reserved_bytes: 0,
                    in_flight: None,
                    eos_accepted: false,
                    closing: false,
                    counters: Counters::default(),
                }),
                wake: Condvar::new(),
                limits,
                capacity: tokio::sync::Notify::new(),
            })
        }

        /// Returns the unit on every refusal, so a retry keeps stream order.
        fn submit(&self, unit: AccessUnit) -> Result<(), RejectedSubmission> {
            let mut state = lock(&self.state);
            let invalid = match unit.kind {
                // This protocol has no out-of-band VP8/VP9 parameter sets, so a
                // codec-configuration unit is refused by name instead of being
                // handed to the decoder as if it were a picture.
                AccessUnitKind::CodecConfig => true,
                AccessUnitKind::EndOfStream => !unit.bytes.is_empty(),
                AccessUnitKind::Frame { .. } => {
                    unit.bytes.is_empty() || unit.bytes.len() > i32::MAX as usize
                }
            };
            let reason = if state.closing || state.counters.closed {
                Some(DecoderError::Closed)
            } else if let Some(error) = &state.counters.failure {
                Some(error.clone())
            } else if state.eos_accepted {
                Some(DecoderError::EndOfStreamAlreadySubmitted)
            } else if invalid {
                Some(DecoderError::InvalidAccessUnit)
            } else if unit.bytes.len() > self.limits.max_queued_bytes {
                Some(DecoderError::AccessUnitExceedsQueueLimit {
                    size: unit.bytes.len(),
                    limit: self.limits.max_queued_bytes,
                })
            } else if state.reserved_units >= self.limits.max_queued_units
                || unit.bytes.len()
                    > self
                        .limits
                        .max_queued_bytes
                        .saturating_sub(state.reserved_bytes)
            {
                Some(DecoderError::Backpressure)
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(RejectedSubmission { reason, unit });
            }
            state.eos_accepted = unit.kind == AccessUnitKind::EndOfStream;
            state.reserved_units += 1;
            state.reserved_bytes += unit.bytes.len();
            state.counters.accepted_units += 1;
            state.packets.push_back(unit);
            drop(state);
            self.wake.notify_one();
            Ok(())
        }

        /// The worker's one blocking wait. `None` means stop, which is what
        /// close, end of stream and a failure all lead to.
        fn next(&self) -> Option<AccessUnit> {
            let mut state = lock(&self.state);
            loop {
                if state.closing || state.counters.failure.is_some() {
                    return None;
                }
                if let Some(unit) = state.packets.pop_front() {
                    return Some(unit);
                }
                state = self.wake.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }

        fn push_started(&self) {
            let mut state = lock(&self.state);
            state.counters.pushed_units = state.counters.pushed_units.saturating_add(1);
            state.in_flight = Some(Instant::now());
        }

        /// The unit has left the codec's hands; its admission quota is free
        /// again and a waiting submitter may proceed.
        fn retired(&self, bytes: usize) {
            {
                let mut state = lock(&self.state);
                state.reserved_units = state.reserved_units.saturating_sub(1);
                state.reserved_bytes = state.reserved_bytes.saturating_sub(bytes);
                state.in_flight = None;
            }
            self.capacity.notify_waiters();
        }

        fn published(&self) {
            let mut state = lock(&self.state);
            let elapsed = state
                .in_flight
                .map(|started| u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
            state.counters.render_submissions = state.counters.render_submissions.saturating_add(1);
            if let Some(elapsed) = elapsed {
                state.counters.render_samples = state.counters.render_samples.saturating_add(1);
                state.counters.render_ns = state.counters.render_ns.saturating_add(elapsed);
                state.counters.render_peak_ns = state.counters.render_peak_ns.max(elapsed);
            }
        }

        fn non_frame(&self) {
            let mut state = lock(&self.state);
            state.counters.non_frame_outputs = state.counters.non_frame_outputs.saturating_add(1);
        }

        fn format_changed(&self) {
            let mut state = lock(&self.state);
            state.counters.format_change_notifications = state
                .counters
                .format_change_notifications
                .saturating_add(1);
        }

        fn end_of_stream(&self) {
            {
                let mut state = lock(&self.state);
                state.counters.end_of_stream_output = true;
                state.closing = true;
            }
            self.capacity.notify_waiters();
        }

        /// Records the first failure only: later ones are consequences.
        fn fail(&self, error: DecoderError) {
            {
                let mut state = lock(&self.state);
                if state.counters.failure.is_none() {
                    state.counters.failure = Some(error);
                }
            }
            self.wake.notify_one();
            self.capacity.notify_waiters();
        }

        fn request_close(&self) {
            {
                let mut state = lock(&self.state);
                state.closing = true;
            }
            self.wake.notify_one();
            self.capacity.notify_waiters();
        }

        /// The worker's final act: nothing is left queued and the record is
        /// final. Every admitted unit that never retired is counted once as
        /// cancelled here, so the numbers add up without being padded.
        fn closed(&self) {
            {
                let mut state = lock(&self.state);
                state.settle();
            }
            self.capacity.notify_waiters();
        }

        /// The worker's terminal record when it unwound instead of returning.
        ///
        /// `Owner` is dropped during that unwind and its `Drop` destroys the
        /// context, so the codec is already dead when this becomes visible.
        /// Without it the record would still say the decoder is running while
        /// no thread can ever publish again: a parked `submit_cancellable`
        /// would wait for capacity forever and `wait_stopped` for a stop signal
        /// that cannot come.
        ///
        /// `WorkerPanicked` is recorded like any other failure, first one wins,
        /// and the queue settles exactly as a normal close settles it. Only
        /// `capacity` is notified: `wake`'s one waiter is the worker itself,
        /// and the callers park on `capacity`.
        fn panicked(&self) {
            {
                let mut state = lock(&self.state);
                if state.counters.failure.is_none() {
                    state.counters.failure = Some(DecoderError::WorkerPanicked);
                }
                state.settle();
            }
            self.capacity.notify_waiters();
        }

        fn counters(&self) -> Counters {
            let state = lock(&self.state);
            let mut counters = state.counters.clone();
            counters.queued_units = state.reserved_units as u64;
            counters
        }
    }

    /// Admission that waits for capacity and returns its unit on cancellation.
    ///
    /// The notification is registered *before* admission, so a slot freed in
    /// between cannot be missed; there is no timer and no polling retry.
    pub async fn submit_cancellable(
        shared: &Shared,
        mut unit: AccessUnit,
        cancel: &CancellationToken,
    ) -> Result<(), RejectedSubmission> {
        loop {
            let ready = shared.capacity.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if cancel.is_cancelled() {
                return Err(RejectedSubmission {
                    reason: DecoderError::Closed,
                    unit,
                });
            }
            match shared.submit(unit) {
                Ok(()) => return Ok(()),
                Err(rejected) if rejected.reason == DecoderError::Backpressure => unit = rejected.unit,
                Err(rejected) => return Err(rejected),
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(RejectedSubmission {
                    reason: DecoderError::Closed,
                    unit,
                }),
                _ = &mut ready => {}
            }
        }
    }

    // ---- the worker --------------------------------------------------------

    /// The worker's entry point: `run` under an unwind guard.
    ///
    /// The plausible panic on this thread is the caller's own frame observer,
    /// safe Rust this worker calls for every decoded picture. Unwinding already
    /// destroys the codec (`Owner`'s `Drop` owns that), but it would leave the
    /// shared record claiming the decoder is still running: a parked
    /// `submit_cancellable` and `wait_stopped` would then wait for a wakeup no
    /// live thread can send. The guard publishes the terminal record first and
    /// re-raises the payload afterwards, so the thread still ends as panicked
    /// and `join` reports `WorkerPanicked`, exactly as before.
    fn worker(
        owner: Owner,
        config: DecoderConfig,
        shared: Arc<Shared>,
        ready: mpsc::SyncSender<Result<String, DecoderError>>,
    ) -> Result<Counters, DecoderError> {
        let worker_shared = shared.clone();
        // `AssertUnwindSafe` is exact here: the closure owns the only state it
        // mutates besides `Shared`, which is a poison-tolerant mutex record, and
        // every native pointer it holds is destroyed by the unwind itself.
        match catch_unwind(AssertUnwindSafe(move || {
            run(owner, config, worker_shared, ready)
        })) {
            Ok(outcome) => outcome,
            Err(payload) => {
                shared.panicked();
                resume_unwind(payload)
            }
        }
    }

    fn run(
        mut owner: Owner,
        config: DecoderConfig,
        shared: Arc<Shared>,
        ready: mpsc::SyncSender<Result<String, DecoderError>>,
    ) -> Result<Counters, DecoderError> {
        let outcome = match owner.setup(config) {
            Ok(name) => {
                // The caller may already have walked away; teardown below still
                // runs, so a decoder is never left initialized and unowned.
                let _ = ready.send(Ok(name));
                decode_loop(&mut owner, &shared)
            }
            Err(error) => {
                let _ = ready.send(Err(error.clone()));
                Err(error)
            }
        };
        let destroyed = owner.shutdown();
        shared.closed();
        outcome?;
        destroyed?;
        Ok(shared.counters())
    }

    fn decode_loop(owner: &mut Owner, shared: &Shared) -> Result<(), DecoderError> {
        while let Some(unit) = shared.next() {
            let bytes = unit.bytes.len();
            let flushed = unit.kind == AccessUnitKind::EndOfStream;
            shared.push_started();
            let decoded = owner.decode(&unit, shared);
            shared.retired(bytes);
            if let Err(error) = decoded {
                shared.fail(error.clone());
                return Err(error);
            }
            if flushed {
                shared.end_of_stream();
            }
        }
        Ok(())
    }

    pub struct Decoder {
        shared: Arc<Shared>,
        worker: Option<JoinHandle<Result<Counters, DecoderError>>>,
        codec_name: String,
    }

    impl Decoder {
        pub fn open(config: DecoderConfig, lease: Arc<dyn SurfaceLease>) -> Result<Self, OpenFailure> {
            Self::open_inner(config, lease).map_err(|error| OpenFailure {
                error,
                // Nothing this backend can fail with leaves native code able to
                // reach the caller's lease: no callbacks are registered, the
                // lease never enters libvpx, and a failed open has already
                // joined the worker that held it.
                cleanup: CleanupVerdict::Confirmed,
            })
        }

        fn open_inner(
            config: DecoderConfig,
            lease: Arc<dyn SurfaceLease>,
        ) -> Result<Self, DecoderError> {
            match config.codec {
                VideoCodec::Vp8 | VideoCodec::Vp9 => {}
                VideoCodec::H264 | VideoCodec::H265 => return Err(DecoderError::UnsupportedCodec),
            }
            let Some(observer) = lease.frame_observer() else {
                // Software decoding has no way to reach a display Surface: its
                // pixels exist only as the BGRA frames it publishes. A lease
                // with no observer would silently decode into nothing.
                return Err(DecoderError::InvalidConfig);
            };
            // Gate before anything is allocated or spawned.
            let version = version().map_err(|error| error.reason)?;
            gate(config.codec)?;

            let shared = Arc::new(Shared::new(config)?);
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let worker_shared = shared.clone();
            let worker = thread::Builder::new()
                .name(DECODER_THREAD_NAME.into())
                .spawn(move || {
                    let owner = Owner {
                        shared: worker_shared.clone(),
                        iface: ptr::null(),
                        version,
                        codec: Codec::new(),
                        observer,
                        _lease: lease,
                        frame: FrameBuf::default(),
                        geometry: None,
                    };
                    worker(owner, config, worker_shared, ready_tx)
                })
                .map_err(|_| DecoderError::WorkerStartFailed)?;
            match ready_rx.recv() {
                Ok(Ok(codec_name)) => Ok(Self {
                    shared,
                    worker: Some(worker),
                    codec_name,
                }),
                // The worker has already destroyed whatever it created before
                // it answered, so joining it here is the whole cleanup.
                Ok(Err(error)) => {
                    let _ = worker.join();
                    Err(error)
                }
                Err(_) => {
                    let _ = worker.join();
                    Err(DecoderError::WorkerPanicked)
                }
            }
        }

        pub fn observer(&self) -> Observer {
            Observer {
                shared: self.shared.clone(),
            }
        }

        pub fn try_submit(&self, unit: AccessUnit) -> Result<(), RejectedSubmission> {
            self.shared.submit(unit)
        }

        pub async fn submit_cancellable(
            &self,
            unit: AccessUnit,
            cancel: &CancellationToken,
        ) -> Result<(), RejectedSubmission> {
            submit_cancellable(&self.shared, unit, cancel).await
        }

        pub fn codec_name(&self) -> Result<&str, DecoderError> {
            Ok(&self.codec_name)
        }

        pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
            Ok(projection(&self.shared.counters()))
        }

        pub fn counters(&self) -> Counters {
            self.shared.counters()
        }

        pub fn request_close(&self) {
            self.shared.request_close();
        }

        pub fn close(mut self) -> Result<DecoderProjection, DecoderError> {
            self.join()?;
            Ok(projection(&self.shared.counters()))
        }

        fn join(&mut self) -> Result<Counters, DecoderError> {
            self.shared.request_close();
            match self.worker.take() {
                Some(worker) => match worker.join() {
                    Ok(finished) => finished,
                    Err(_) => {
                        // The worker's guard already published `WorkerPanicked`
                        // and the terminal record before the payload left the
                        // thread; recording it again is idempotent (the first
                        // failure wins) and keeps this path correct on its own.
                        self.shared.fail(DecoderError::WorkerPanicked);
                        Err(DecoderError::WorkerPanicked)
                    }
                },
                None => Ok(self.shared.counters()),
            }
        }
    }

    impl Drop for Decoder {
        fn drop(&mut self) {
            // Join, never detach: a dropped decoder must not leave a thread
            // holding the codec or the caller's lease.
            let _ = self.join();
        }
    }

    #[derive(Clone)]
    pub struct Observer {
        shared: Arc<Shared>,
    }

    impl Observer {
        pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
            Ok(projection(&self.shared.counters()))
        }

        pub fn counters(&self) -> Counters {
            self.shared.counters()
        }

        pub fn request_close(&self) {
            self.shared.request_close()
        }

        pub async fn wait_stopped(&self) -> Result<(), DecoderError> {
            loop {
                let changed = self.shared.capacity.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let counters = self.shared.counters();
                if let Some(error) = counters.failure {
                    return Err(error);
                }
                if counters.closed || counters.quarantined || counters.end_of_stream_output {
                    return Err(DecoderError::Closed);
                }
                changed.await;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;

        fn image(
            luma: &[u8],
            u: &[u8],
            v: &[u8],
            width: u32,
            height: u32,
            luma_stride: i32,
            chroma_stride: i32,
            cs: ffi::vpx_color_space_t,
            range: ffi::vpx_color_range_t,
        ) -> ffi::vpx_image_t {
            let mut image: ffi::vpx_image_t = unsafe { MaybeUninit::zeroed().assume_init() };
            image.fmt = ffi::vpx_img_fmt_VPX_IMG_FMT_I420;
            image.cs = cs;
            image.range = range;
            image.w = width;
            image.h = height;
            image.bit_depth = 8;
            image.d_w = width;
            image.d_h = height;
            image.r_w = width;
            image.r_h = height;
            image.x_chroma_shift = 1;
            image.y_chroma_shift = 1;
            image.planes = [
                luma.as_ptr() as *mut u8,
                u.as_ptr() as *mut u8,
                v.as_ptr() as *mut u8,
                ptr::null_mut(),
            ];
            image.stride = [luma_stride, chroma_stride, chroma_stride, 0];
            image
        }

        /// Converts and asserts the one thing a caller sees: the bytes.
        fn convert_frame(image: &ffi::vpx_image_t, out: &mut Vec<u8>) {
            let stride = image.d_w as usize * BYTES_PER_PIXEL;
            out.clear();
            out.resize(stride * image.d_h as usize, 0);
            let coeffs = coefficients_for(image).expect("the fixture is I420 8-bit");
            unsafe { convert(image, coeffs, out, stride) }.expect("the fixture is well formed");
        }

        fn levels(image: &ffi::vpx_image_t) -> Vec<[u8; 4]> {
            let mut out = Vec::new();
            convert_frame(image, &mut out);
            out.chunks_exact(BYTES_PER_PIXEL)
                .map(|pixel| [pixel[0], pixel[1], pixel[2], pixel[3]])
                .collect()
        }

        fn config(max_queued_units: usize, max_queued_bytes: usize) -> DecoderConfig {
            DecoderConfig {
                codec: VideoCodec::Vp9,
                width: 640,
                height: 360,
                max_queued_units,
                max_queued_bytes,
            }
        }

        fn unit(bytes: usize) -> AccessUnit {
            AccessUnit {
                bytes: vec![7; bytes],
                pts_us: 0,
                kind: AccessUnitKind::Frame { key: true },
            }
        }

        /// Both advertised codecs, each probed against the linked library.
        ///
        /// This test exists only in a linked build (`engine` is compiled under
        /// `all(feature = "software-vpx", rd_vpx_linked)`), and it is the only
        /// test here that touches the library: [`probe`](super::probe) reads
        /// the loaded release, resolves the codec's own interface, checks the
        /// decoder capability, then initializes and destroys a real
        /// `vpx_codec_ctx_t` with the ABI number recorded in `vpx_ffi.rs`. On a
        /// Windows runner with the pinned static libvpx this is what turns
        /// "the library is installed" into "VP8 and VP9 open here", which is
        /// the rung the login/ability gate may cite.
        ///
        /// It stops at that rung: nothing decodes a bitstream, so
        /// `FirstNativeOutput` is not claimed and is not asserted here.
        #[test]
        fn probe_opens_both_advertised_codecs() {
            // A linked test must never run against an install the build could
            // not resolve; `LINK` is the build's own record of where libvpx
            // came from.
            let link = super::super::LINK;
            assert!(
                !link.starts_with("unavailable"),
                "this test runs in a linked build, but LINK says {link}"
            );
            let version =
                super::version().expect("a linked library reports a release at or above the floor");
            for codec in [VideoCodec::Vp8, VideoCodec::Vp9] {
                let probe = super::probe(codec)
                    .unwrap_or_else(|error| panic!("{codec:?} must open in a linked build: {error}"));
                assert_eq!(probe.codec, codec);
                assert_eq!(probe.evidence, CapabilityEvidence::Opened);
                assert_eq!(probe.version, version, "{codec:?} read another release");
                assert_eq!(probe.abi, ffi::VPX_DECODER_ABI_VERSION as i32);
                assert_ne!(probe.caps & (ffi::VPX_CODEC_CAP_DECODER as i64), 0);
                assert!(!probe.iface.is_empty(), "{codec:?} named no interface");
            }
            // The probe serves these two codecs and refuses the platform
            // decoder's own, so its answer cannot be read as a hardware claim.
            for codec in [VideoCodec::H264, VideoCodec::H265] {
                let refused = super::probe(codec)
                    .expect_err("the software backend never serves H264/H265");
                assert_eq!(refused.reason, DecoderError::UnsupportedCodec);
            }
        }

        #[test]
        fn limited_range_black_and_white_are_exact() {
            let chroma = [128u8; 1];
            for cs in [
                ffi::vpx_color_space_VPX_CS_BT_709,
                ffi::vpx_color_space_VPX_CS_BT_601,
                ffi::vpx_color_space_VPX_CS_UNKNOWN,
            ] {
                let black = image(
                    &[16u8; 4],
                    &chroma,
                    &chroma,
                    2,
                    2,
                    2,
                    1,
                    cs,
                    ffi::vpx_color_range_VPX_CR_STUDIO_RANGE,
                );
                assert_eq!(levels(&black), vec![[0, 0, 0, OPAQUE]; 4], "cs {cs}");
                let white = image(
                    &[235u8; 4],
                    &chroma,
                    &chroma,
                    2,
                    2,
                    2,
                    1,
                    cs,
                    ffi::vpx_color_range_VPX_CR_STUDIO_RANGE,
                );
                assert_eq!(levels(&white), vec![[255, 255, 255, OPAQUE]; 4], "cs {cs}");
            }
        }

        #[test]
        fn full_range_black_and_white_are_exact() {
            let chroma = [128u8; 1];
            let black = image(
                &[0u8; 4],
                &chroma,
                &chroma,
                2,
                2,
                2,
                1,
                ffi::vpx_color_space_VPX_CS_BT_709,
                ffi::vpx_color_range_VPX_CR_FULL_RANGE,
            );
            assert_eq!(levels(&black), vec![[0, 0, 0, OPAQUE]; 4]);
            let white = image(
                &[255u8; 4],
                &chroma,
                &chroma,
                2,
                2,
                2,
                1,
                ffi::vpx_color_space_VPX_CS_BT_709,
                ffi::vpx_color_range_VPX_CR_FULL_RANGE,
            );
            assert_eq!(levels(&white), vec![[255, 255, 255, OPAQUE]; 4]);
        }

        #[test]
        fn each_row_is_read_through_its_own_stride() {
            // Row 0 black, row 1 white, with four bytes of padding after each
            // stored row: a reader that assumed `stride == width` would report
            // two black rows instead of one black and one white.
            let luma = [
                16u8, 16, 0xaa, 0xaa, 0xaa, 0xaa, 235, 235, 0xbb, 0xbb, 0xbb, 0xbb,
            ];
            let u = [128u8, 0xcc, 0xcc];
            let v = [128u8, 0xdd, 0xdd];
            let frame = image(
                &luma,
                &u,
                &v,
                2,
                2,
                6,
                3,
                ffi::vpx_color_space_VPX_CS_BT_709,
                ffi::vpx_color_range_VPX_CR_STUDIO_RANGE,
            );
            let rows = levels(&frame);
            assert_eq!(rows[0], [0, 0, 0, OPAQUE]);
            assert_eq!(rows[1], [0, 0, 0, OPAQUE]);
            assert_eq!(rows[2], [255, 255, 255, OPAQUE]);
            assert_eq!(rows[3], [255, 255, 255, OPAQUE]);
        }

        #[test]
        fn neutral_chroma_does_not_depend_on_the_matrix() {
            // With U = V = 128 every matrix reduces to the same luma-only
            // result, which is the invariant that makes the two tables
            // interchangeable when a stream carries no colour label.
            let chroma = [128u8; 1];
            let b709 = image(
                &[60u8; 4],
                &chroma,
                &chroma,
                2,
                2,
                2,
                1,
                ffi::vpx_color_space_VPX_CS_BT_709,
                ffi::vpx_color_range_VPX_CR_STUDIO_RANGE,
            );
            let b601 = image(
                &[60u8; 4],
                &chroma,
                &chroma,
                2,
                2,
                2,
                1,
                ffi::vpx_color_space_VPX_CS_BT_601,
                ffi::vpx_color_range_VPX_CR_STUDIO_RANGE,
            );
            assert_eq!(levels(&b709), levels(&b601));
        }

        #[test]
        fn chroma_only_content_saturates_and_clamps() {
            // U = 255 with neutral luma chroma must reach blue's ceiling and
            // clamp, never wrap: the clamp is the difference between a wrong
            // colour and a black frame.
            let frame = image(
                &[16u8; 4],
                &[255u8; 1],
                &[128u8; 1],
                2,
                2,
                2,
                1,
                ffi::vpx_color_space_VPX_CS_BT_709,
                ffi::vpx_color_range_VPX_CR_STUDIO_RANGE,
            );
            let pixel = levels(&frame)[0];
            assert_eq!(pixel[0], 255, "blue channel");
            assert_eq!(pixel[2], 0, "red channel");
            assert_eq!(pixel[3], OPAQUE);
        }

        #[test]
        fn refusal_paths_are_named() {
            let mut shared = Shared::new(config(2, 1024)).expect("2 units / 1 KiB is valid");
            assert!(shared.submit(unit(16)).is_ok());
            assert!(shared.submit(unit(16)).is_ok());
            // The third unit comes back unchanged, so the caller can retry it
            // ahead of the stream's later units.
            let rejected = shared.submit(unit(16)).expect_err("capacity is two units");
            assert_eq!(rejected.reason, DecoderError::Backpressure);
            assert_eq!(rejected.unit.bytes, vec![7u8; 16]);
            assert_eq!(shared.counters().queued_units, 2);
            assert_eq!(shared.counters().accepted_units, 2);
            shared.retired(16);
            assert!(shared.submit(unit(16)).is_ok());
            // A unit larger than the whole byte budget is named, not queued.
            let oversized = shared.submit(unit(4096)).expect_err("over the byte budget");
            assert_eq!(
                oversized.reason,
                DecoderError::AccessUnitExceedsQueueLimit {
                    size: 4096,
                    limit: 1024
                }
            );
            // No out-of-band parameter sets exist for VPx on this protocol.
            let parameter_sets = shared
                .submit(AccessUnit {
                    bytes: vec![1, 2, 3],
                    pts_us: 0,
                    kind: AccessUnitKind::CodecConfig,
                })
                .expect_err("codec configuration is not a picture");
            assert_eq!(parameter_sets.reason, DecoderError::InvalidAccessUnit);
        }

        #[test]
        fn close_counts_what_never_retired_and_refuses_later_units() {
            let shared = Shared::new(config(2, 1024)).expect("2 units / 1 KiB is valid");
            assert!(shared.submit(unit(16)).is_ok());
            assert!(shared.submit(unit(16)).is_ok());
            shared.closed();
            let counters = shared.counters();
            assert_eq!(counters.cancelled_units, 2);
            assert_eq!(counters.queued_units, 0);
            assert!(counters.closed);
            let rejected = shared.submit(unit(16)).expect_err("closed");
            assert_eq!(rejected.reason, DecoderError::Closed);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn cancellation_returns_the_unit() {
            let shared = Arc::new(Shared::new(config(1, 1024)).expect("1 unit / 1 KiB is valid"));
            assert!(shared.submit(unit(16)).is_ok());
            let cancel = CancellationToken::new();
            let waiter = {
                let shared = shared.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    submit_cancellable(&shared, unit(16), &cancel).await
                })
            };
            // Give the waiter a chance to park on capacity, then cancel it.
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel.cancel();
            let rejected = waiter
                .await
                .expect("the waiter task cannot panic")
                .expect_err("a cancelled admission never succeeds");
            assert_eq!(rejected.reason, DecoderError::Closed);
            assert_eq!(rejected.unit.bytes, vec![7u8; 16]);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn close_wakes_a_waiting_submitter() {
            let shared = Arc::new(Shared::new(config(1, 1024)).expect("1 unit / 1 KiB is valid"));
            assert!(shared.submit(unit(16)).is_ok());
            let cancel = CancellationToken::new();
            let closing = {
                let shared = shared.clone();
                tokio::spawn(async move {
                    tokio::task::yield_now().await;
                    shared.request_close();
                })
            };
            let submitted = tokio::select! {
                // The timer only bounds the test: if the wakeup were missing,
                // the select would take this branch instead of hanging.
                _ = tokio::time::sleep(Duration::from_millis(500)) => None,
                answer = submit_cancellable(&shared, unit(16), &cancel) => Some(answer),
            };
            closing.await.expect("the closing task cannot panic");
            let rejected = submitted
                .expect("close must wake a submitter that is parked on capacity")
                .expect_err("a closed decoder accepts nothing");
            assert_eq!(rejected.reason, DecoderError::Closed);
            assert_eq!(rejected.unit.bytes, vec![7u8; 16]);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_panicked_worker_releases_its_waiters() {
            // What the worker's unwind guard publishes when the caller's own
            // frame observer panics. One capacity notification has to release
            // both a submitter parked on capacity and the observer's
            // `wait_stopped`; each wait is bounded by a timer, so a missing
            // wakeup fails the test instead of hanging it.
            let shared = Arc::new(Shared::new(config(1, 1024)).expect("1 unit / 1 KiB is valid"));
            assert!(shared.submit(unit(16)).is_ok());
            let cancel = CancellationToken::new();
            let waiter = {
                let shared = shared.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    submit_cancellable(&shared, unit(16), &cancel).await
                })
            };
            let observer_wait = {
                let observer = Observer { shared: shared.clone() };
                tokio::spawn(async move { observer.wait_stopped().await })
            };
            // Give both waiters a chance to park, then publish the terminal
            // record a panicking worker publishes.
            tokio::time::sleep(Duration::from_millis(20)).await;
            shared.panicked();
            let stopped = tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(500)) => None,
                answer = observer_wait => Some(answer.expect("the observer task cannot panic")),
            };
            assert_eq!(stopped, Some(Err(DecoderError::WorkerPanicked)));
            let rejected = waiter
                .await
                .expect("the submitter task cannot panic")
                .expect_err("a panicked decoder accepts nothing");
            assert_eq!(rejected.reason, DecoderError::Closed);
            assert_eq!(rejected.unit.bytes, vec![7u8; 16]);
            let counters = shared.counters();
            assert!(counters.closed);
            assert_eq!(counters.queued_units, 0);
        }
    }
}

/// A build without the feature, or without a resolved libvpx, answers every
/// entry point by name instead of approximating a decoder.
#[cfg(not(all(feature = "software-vpx", rd_vpx_linked)))]
mod engine {
    use super::*;

    /// The one refusal every path in this configuration returns: the codec is
    /// not served by this build, and `LINK` says why.
    fn unavailable() -> DecoderError {
        DecoderError::UnsupportedCodec
    }

    pub fn version() -> Result<Version, Error> {
        Err(Error {
            reason: unavailable(),
            detail: Some(LINK.to_string()),
        })
    }

    pub fn probe(codec: VideoCodec) -> Result<Probe, Error> {
        Err(Error {
            reason: unavailable(),
            detail: Some(format!(
                "{codec:?} software decoding is not in this build: {LINK}"
            )),
        })
    }

    /// No value of this type can exist: `open` always refuses, so the record
    /// below is unreachable rather than an all-zero imitation of a real one.
    pub struct Decoder {
        _no_backend: (),
    }

    impl Decoder {
        pub fn open(_config: DecoderConfig, _lease: Arc<dyn SurfaceLease>) -> Result<Self, OpenFailure> {
            Err(OpenFailure {
                error: unavailable(),
                cleanup: CleanupVerdict::Confirmed,
            })
        }

        pub fn observer(&self) -> Observer {
            Observer { _no_backend: () }
        }

        pub fn try_submit(&self, unit: AccessUnit) -> Result<(), RejectedSubmission> {
            Err(RejectedSubmission {
                reason: unavailable(),
                unit,
            })
        }

        pub async fn submit_cancellable(
            &self,
            unit: AccessUnit,
            _cancel: &CancellationToken,
        ) -> Result<(), RejectedSubmission> {
            Err(RejectedSubmission {
                reason: unavailable(),
                unit,
            })
        }

        pub fn codec_name(&self) -> Result<&str, DecoderError> {
            Err(unavailable())
        }

        pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
            Err(unavailable())
        }

        pub fn counters(&self) -> Counters {
            Counters::default()
        }

        pub fn request_close(&self) {}

        pub fn close(self) -> Result<DecoderProjection, DecoderError> {
            Err(unavailable())
        }
    }

    #[derive(Clone)]
    pub struct Observer {
        _no_backend: (),
    }

    impl Observer {
        pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
            Err(unavailable())
        }

        pub fn counters(&self) -> Counters {
            Counters::default()
        }

        pub fn request_close(&self) {}

        /// Never `Ok`, exactly like the backend that does run: the feeder reads
        /// this answer as a stop signal.
        pub async fn wait_stopped(&self) -> Result<(), DecoderError> {
            Err(unavailable())
        }
    }
}
