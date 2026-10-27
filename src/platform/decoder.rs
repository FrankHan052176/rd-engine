//! The engine's decoder seam: one facade the viewer names, and the backend this
//! build actually has behind it.
//!
//! Two things live here. First the seam's own vocabulary: an [`OpenFailure`]
//! saying what a failed open settled (with the [`CleanupVerdict`] a caller
//! decides the surface lease with), a [`DecoderProjection`] that is the neutral
//! view of what a decoder has done, and the [`RenderTarget`] a lease may expose.
//! Second the backend selection: [`SurfaceDecoder`] is the one decoder type the
//! rest of the engine names, and the codec in a [`DecoderConfig`] is what picks
//! the implementation behind it.
//!
//! The types the backends share (`VideoCodec`, `DecoderConfig`, `AccessUnit`,
//! `AccessUnitKind`, `DecoderError`, `DecoderStats`, `RejectedSubmission`,
//! `SurfaceLease`) keep their definitions in `ohos_decoder.rs` and are
//! re-exported here unchanged, so every path under `crate::viewer::decoder`
//! resolves exactly as it did and no consumer moved.
//!
//! Selection is by configuration and never by a runtime guess. A codec with no
//! backend in the build is refused by name: the OpenHarmony hardware decoder is
//! not a fallback for anything, and a build without a software VP8/VP9 backend
//! says `UnsupportedCodec` instead of letting another decoder answer for it.
//!
//! The backends differ in what a lease is *for*. OpenHarmony hardware presents
//! into its Surface; Windows hardware requires a typed, live presenter bound to
//! the lease's target epoch. Software VP8/VP9 presents through the frame observer.
//! Selection never changes codec or falls back when a destination is missing.
//! [`SurfaceDecoder::serves_software_vpx`] answers only for the software path.

use std::sync::Arc;

/// The build's hardware backend: the OpenHarmony Surface decoder — and, on every
/// other target, the same module compiled into its refusal-only form, where
/// `open` answers `UnsupportedPlatform` and no native code path exists.
///
/// It is `pub` because [`SurfaceDecoder::Ohos`] carries its decoder: that type
/// was itself reachable at this path before this facade existed, and a private
/// module would hide a public variant's own type.
#[path = "ohos_decoder.rs"]
pub mod ohos;

/// The build's software backend, a further arm of exactly the selection above.
///
/// It is part of the compilation only when its feature is enabled, and the
/// `VideoCodec::Vp8`/`VideoCodec::Vp9` arm of [`SurfaceDecoder::open`] is where
/// it is selected. Without the feature nothing of this module is in the build and
/// those two codecs are refused by name; with it, the module's own link and
/// runtime gates decide, and a refusal there stays a refusal. It is `pub` so the
/// backend keeps one path, and so [`SurfaceDecoder`] can reach its probe instead
/// of keeping a second copy of it.
#[cfg(feature = "software-vpx")]
#[path = "vpx_decoder.rs"]
pub mod software;

/// Windows adaptation compiled on every host against the real backend's own
/// refusal forms. Only Windows builds select it in [`SurfaceDecoder`]; compiling
/// this module elsewhere proves neither Windows availability nor native output.
pub mod windows {
    use super::*;
    use crate::windows_decoder::{WindowsDecoder, WindowsDecoderObserver};

    pub struct Decoder(WindowsDecoder);

    #[derive(Clone)]
    pub struct Observer(WindowsDecoderObserver);

    impl Decoder {
        pub fn open(config: DecoderConfig, lease: Arc<dyn SurfaceLease>) -> Result<Self, OpenFailure> {
            if !matches!(config.codec, VideoCodec::H264 | VideoCodec::H265) {
                return Err(OpenFailure {
                    error: DecoderError::UnsupportedCodec,
                    cleanup: CleanupVerdict::Confirmed,
                });
            }
            let invalid_target = || OpenFailure {
                error: DecoderError::InvalidConfig,
                cleanup: CleanupVerdict::Confirmed,
            };
            let target = lease.render_target().ok_or_else(invalid_target)?;
            if target.epoch == 0 {
                return Err(invalid_target());
            }
            let presentation = lease.windows_presentation().ok_or_else(invalid_target)?;
            if presentation.bound_epoch() != Some(target.epoch) {
                return Err(invalid_target());
            }
            presentation.check_live().map_err(|error| OpenFailure {
                error: DecoderError::WindowsNative(error),
                // No decoder or producer has been created by this attempt.
                cleanup: CleanupVerdict::Confirmed,
            })?;
            WindowsDecoder::open(config, presentation).map(Self).map_err(Into::into)
        }

        pub fn observer(&self) -> Observer {
            Observer(self.0.observer())
        }

        pub fn try_submit(&self, unit: AccessUnit) -> Result<(), RejectedSubmission> {
            self.0.try_submit(unit).map_err(Into::into)
        }

        pub async fn submit_cancellable(
            &self,
            unit: AccessUnit,
            cancel: &tokio_util::sync::CancellationToken,
        ) -> Result<(), RejectedSubmission> {
            self.0.submit_cancellable(unit, cancel).await.map_err(Into::into)
        }

        pub fn codec_name(&self) -> Result<&str, DecoderError> {
            self.0.codec_name().map_err(Into::into)
        }

        pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
            self.0.stats().map(Into::into).map_err(Into::into)
        }

        pub fn request_close(&self) {
            self.0.request_close();
        }

        pub fn close(self) -> Result<DecoderProjection, DecoderError> {
            self.0.close().map(Into::into).map_err(Into::into)
        }
    }

    impl Observer {
        pub async fn wait_stopped(&self) -> Result<(), DecoderError> {
            self.0.wait_stopped().await.map_err(Into::into)
        }

        pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
            self.0.stats().map(Into::into).map_err(Into::into)
        }

        pub fn request_close(&self) {
            self.0.request_close();
        }
    }
}

/// The verdict on a backend's native ownership, from the presenter path that
/// already owns the type (`windows_presentation.rs`).
///
/// It is re-exported rather than defined again: two verdicts with one name could
/// disagree with each other, and a reclamation decision must read the one value
/// the whole engine compares.
pub use crate::windows_presentation::CleanupVerdict;
pub use ohos::{
    AccessUnit, AccessUnitKind, DecoderConfig, DecoderError, DecoderStats, RejectedSubmission,
    SurfaceLease, VideoCodec,
};

/// Observes whichever backend [`SurfaceDecoder`] selected, without owning it.
///
/// It is the seam's own type rather than a backend's because a caller keeps one
/// in its snapshot after the decoder is gone, and the backends answer the same
/// three questions about it: whether the worker stopped, what it has done, and
/// stop now. It holds no state of its own beyond the backend's handle, and the
/// data types the backends share stay where they were.
#[derive(Clone)]
pub enum DecoderObserver {
    /// The OpenHarmony decoder's observer.
    Ohos(ohos::DecoderObserver),
    /// The Windows decoder's observer, selected only on Windows.
    #[cfg(target_os = "windows")]
    Windows(windows::Observer),
    /// The software backend's observer, present only while its feature is
    /// enabled. Reached through [`SurfaceDecoder::observer`], never constructed
    /// by a caller.
    #[cfg(feature = "software-vpx")]
    Software(software::Observer),
}

impl DecoderObserver {
    /// Resolves when the backend stops — or fails.
    ///
    /// A stop is reported as an error (`Closed`, or the failure that ended it),
    /// which is what lets a feeder read one answer instead of polling a state
    /// pair.
    pub async fn wait_stopped(&self) -> Result<(), DecoderError> {
        match self {
            Self::Ohos(observer) => observer.wait_stopped().await,
            #[cfg(target_os = "windows")]
            Self::Windows(observer) => observer.wait_stopped().await,
            #[cfg(feature = "software-vpx")]
            Self::Software(observer) => observer.wait_stopped().await,
        }
    }

    /// What the backend has done so far, in the seam's terms.
    pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
        match self {
            Self::Ohos(observer) => observer.stats(),
            #[cfg(target_os = "windows")]
            Self::Windows(observer) => observer.stats(),
            #[cfg(feature = "software-vpx")]
            Self::Software(observer) => observer.stats(),
        }
    }

    /// Asks the backend to stop without waiting for it. The worker is still
    /// joined by [`SurfaceDecoder::close`].
    pub fn request_close(&self) {
        match self {
            Self::Ohos(observer) => observer.request_close(),
            #[cfg(target_os = "windows")]
            Self::Windows(observer) => observer.request_close(),
            #[cfg(feature = "software-vpx")]
            Self::Software(observer) => observer.request_close(),
        }
    }
}

/// Where a lease's pictures are presented, when that is not the lease's own
/// Surface.
///
/// It carries the identity of a destination and no platform object: a lease that
/// presents through `surface_id`/`frame_observer` answers `None` (the default on
/// [`SurfaceLease`]), and a lease whose session owns a presentation layer names
/// the binding that layer accepted. It is exposed only through the lease — a
/// render destination is never a client option — because the trusted Surface
/// owner is what decides where pixels may land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderTarget {
    /// The epoch a presenter was bound with (`bind_session(epoch != 0)`, bound
    /// once for the session and never re-bound). Never 0: a lease with no
    /// binding answers `None` rather than an unbound target.
    pub epoch: u64,
}

/// Observed push-to-submission latency, excluding network and scanout.
/// `samples` counts only measured pictures, never all presentation submissions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderTiming {
    pub samples: u64,
    pub total_ns: u64,
    pub peak_ns: u64,
}

impl RenderTiming {
    /// Only real samples contribute. A zero-sample record is not a measured
    /// zero-duration frame and leaves an empty aggregate empty.
    pub(crate) fn accumulate(total: &mut Option<Self>, incoming: Option<Self>) {
        let Some(incoming) = incoming.filter(|timing| timing.samples != 0) else {
            return;
        };
        let total = total.get_or_insert_with(Self::default);
        total.samples = total.samples.saturating_add(incoming.samples);
        total.total_ns = total.total_ns.saturating_add(incoming.total_ns);
        total.peak_ns = total.peak_ns.max(incoming.peak_ns);
    }
}

/// What one open decoder has done, in the seam's terms.
///
/// It is the neutral view of a backend's counters — the ones every backend
/// keeps — so the engine's snapshot, its close decision and its diagnostics
/// never read a platform's own counter record. Counters a single backend keeps
/// stay that backend's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecoderProjection {
    /// Compressed units handed to the backend.
    pub pushed_units: u64,
    /// Output buffers submitted for presentation. Not physical presentation.
    pub render_submissions: u64,
    /// `None` means this backend has no actual latency observation yet.
    pub render_timing: Option<RenderTiming>,
    /// Units admitted but not yet handed to the backend at this snapshot.
    pub queued_units: u64,
    pub closed: bool,
    /// Native ownership the backend could not prove it released.
    pub quarantined: bool,
    pub failure: Option<DecoderError>,
}

impl DecoderProjection {
    /// The verdict on the backend's native ownership, from the one state pair
    /// that proves it: a close that returned and left nothing quarantined.
    ///
    /// `Unconfirmed` is not a guess about how long a resource lives; it is the
    /// state in which a caller must keep the surface lease, because a quarantined
    /// decoder may still own it.
    pub fn cleanup(&self) -> CleanupVerdict {
        if self.closed && !self.quarantined {
            CleanupVerdict::Confirmed
        } else {
            CleanupVerdict::Unconfirmed
        }
    }
}

/// One failed open, with the backend's own verdict on what it settled.
///
/// Only the backend knows which of its failures happened before it allocated
/// anything, so the backend is what answers `cleanup`. A caller reads that field
/// instead of matching the backend's error variants, which is what keeps the
/// reclamation decision out of the viewer: `Confirmed` means nothing this open
/// created outlives it and the surface lease stays releasable, while
/// `Unconfirmed` means the backend may still own a codec, its buffers and that
/// lease, and they must be kept.
#[derive(Debug)]
pub struct OpenFailure {
    pub error: DecoderError,
    pub cleanup: CleanupVerdict,
}

/// The decoder this build has, chosen by the codec it is asked for.
///
/// H264/H265 select Windows hardware only on Windows, with a live bound target.
/// Elsewhere they retain the OpenHarmony backend and its off-device refusal.
/// VP8/VP9 select only the feature-gated software backend, whose own link,
/// runtime, ABI and sink gates decide whether it can answer.
pub enum SurfaceDecoder {
    /// The OpenHarmony Surface decoder, from `ohos_decoder.rs`.
    Ohos(ohos::SurfaceDecoder),
    /// The Windows Media Foundation decoder and its typed presentation binding.
    #[cfg(target_os = "windows")]
    Windows(windows::Decoder),
    /// The software VP8/VP9 decoder, from `vpx_decoder.rs`: a CPU path that
    /// publishes through the lease's frame observer and never touches a Surface.
    #[cfg(feature = "software-vpx")]
    Software(software::Decoder),
}

impl SurfaceDecoder {
    /// Opens the backend that serves `config.codec`.
    ///
    /// A codec with no backend in this build is refused here, by name, before any
    /// backend is touched: the hardware decoder is not a software fallback, and a
    /// build without the software backend must state that absence rather than let
    /// another decoder answer for a codec it cannot decode.
    ///
    /// VP8/VP9 go to the software backend, whose own gates run inside this call —
    /// enabled feature, linked library, runtime version, interface, ABI, then the
    /// lease's frame observer — and whose every refusal carries
    /// `CleanupVerdict::Confirmed`, because nothing it created outlives a failed
    /// open. No probe is put in front of that: the open is where the gate belongs,
    /// and a second one could only disagree with the first.
    pub fn open(config: DecoderConfig, lease: Arc<dyn SurfaceLease>) -> Result<Self, OpenFailure> {
        match config.codec {
            // A missing Windows target is a refusal, never a different backend.
            #[cfg(target_os = "windows")]
            VideoCodec::H264 | VideoCodec::H265 => {
                windows::Decoder::open(config, lease).map(Self::Windows)
            }
            #[cfg(not(target_os = "windows"))]
            VideoCodec::H264 | VideoCodec::H265 => {
                ohos::SurfaceDecoder::open(config, lease).map(Self::Ohos)
            }
            // The software categories. With the feature off nothing of that
            // backend is in the build, so the refusal is by name and allocates
            // nothing; with it on, the backend's own gates answer, and a probe
            // that fails leaves the same confirmed refusal.
            #[cfg(feature = "software-vpx")]
            VideoCodec::Vp8 | VideoCodec::Vp9 => {
                software::Decoder::open(config, lease).map(Self::Software)
            }
            #[cfg(not(feature = "software-vpx"))]
            VideoCodec::Vp8 | VideoCodec::Vp9 => Err(OpenFailure {
                error: DecoderError::UnsupportedCodec,
                cleanup: CleanupVerdict::Confirmed,
            }),
        }
    }

    /// Whether this process's software backend really serves `codec`, from its
    /// own runtime probe.
    ///
    /// This is the only capability evidence the engine has for VP8 and VP9:
    /// `true` means the probe reached `Opened` in this process — the library
    /// answered, the ABI was accepted, and a real decoder context for this codec
    /// initialized and was destroyed — and it is never a claim that a bitstream
    /// was decoded, that pixels were produced, or that a picture was presented.
    /// H264/H265, a build without the feature, and a build whose library or
    /// runtime gate refused all answer `false`.
    pub fn serves_software_vpx(codec: VideoCodec) -> bool {
        Self::software_vpx_refusal(codec).is_none()
    }

    /// Why this process's software backend cannot serve `codec`, or `None` when
    /// its probe answered.
    ///
    /// The reason is a local diagnosis, never peer text: which gate refused (the
    /// feature is off in this build, no library was linked, the loaded library's
    /// version or ABI or this codec's interface was refused). A caller states it
    /// instead of reporting an unexplained absence.
    pub fn software_vpx_refusal(codec: VideoCodec) -> Option<String> {
        #[cfg(feature = "software-vpx")]
        {
            match software::probe(codec) {
                // `Opened` is the rung this backend reaches: a real context
                // initialized and destroyed, not a metadata claim.
                Ok(probe) if probe.evidence == software::CapabilityEvidence::Opened => None,
                Ok(probe) => Some(format!("the {codec:?} probe reached only {:?}", probe.evidence)),
                Err(error) => Some(error.to_string()),
            }
        }
        #[cfg(not(feature = "software-vpx"))]
        {
            let _ = codec;
            Some("the software-vpx feature is not enabled in this build".to_owned())
        }
    }

    /// Observes this decoder without owning it.
    pub fn observer(&self) -> DecoderObserver {
        match self {
            Self::Ohos(decoder) => DecoderObserver::Ohos(decoder.observer()),
            #[cfg(target_os = "windows")]
            Self::Windows(decoder) => DecoderObserver::Windows(decoder.observer()),
            #[cfg(feature = "software-vpx")]
            Self::Software(decoder) => DecoderObserver::Software(decoder.observer()),
        }
    }

    pub fn try_submit(&self, unit: AccessUnit) -> Result<(), RejectedSubmission> {
        match self {
            Self::Ohos(decoder) => decoder.try_submit(unit),
            #[cfg(target_os = "windows")]
            Self::Windows(decoder) => decoder.try_submit(unit),
            #[cfg(feature = "software-vpx")]
            Self::Software(decoder) => decoder.try_submit(unit),
        }
    }

    /// Capacity includes an access unit currently inside the backend's own push.
    /// A notification is registered before admission, so no wakeup is lost and
    /// no timer, polling retry or per-frame task is needed. One ordered feeder
    /// calls it.
    pub async fn submit_cancellable(
        &self,
        unit: AccessUnit,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), RejectedSubmission> {
        match self {
            Self::Ohos(decoder) => decoder.submit_cancellable(unit, cancel).await,
            #[cfg(target_os = "windows")]
            Self::Windows(decoder) => decoder.submit_cancellable(unit, cancel).await,
            #[cfg(feature = "software-vpx")]
            Self::Software(decoder) => decoder.submit_cancellable(unit, cancel).await,
        }
    }

    /// The codec name the backend created, by name and never by a
    /// software-fallback constructor.
    pub fn codec_name(&self) -> Result<&str, DecoderError> {
        match self {
            Self::Ohos(decoder) => decoder.codec_name(),
            #[cfg(target_os = "windows")]
            Self::Windows(decoder) => decoder.codec_name(),
            #[cfg(feature = "software-vpx")]
            Self::Software(decoder) => decoder.codec_name(),
        }
    }

    pub fn stats(&self) -> Result<DecoderProjection, DecoderError> {
        match self {
            Self::Ohos(decoder) => decoder.stats(),
            #[cfg(target_os = "windows")]
            Self::Windows(decoder) => decoder.stats(),
            #[cfg(feature = "software-vpx")]
            Self::Software(decoder) => decoder.stats(),
        }
    }

    /// Nonblocking notification; the surface lease must still be retained until
    /// `close` joins the backend.
    pub fn request_close(&self) {
        match self {
            Self::Ohos(decoder) => decoder.request_close(),
            #[cfg(target_os = "windows")]
            Self::Windows(decoder) => decoder.request_close(),
            #[cfg(feature = "software-vpx")]
            Self::Software(decoder) => decoder.request_close(),
        }
    }

    /// Joins the backend's worker; call off UI/callback threads. The projection it
    /// returns is the backend's final state, which is what `cleanup` reads.
    pub fn close(self) -> Result<DecoderProjection, DecoderError> {
        match self {
            Self::Ohos(decoder) => decoder.close(),
            #[cfg(target_os = "windows")]
            Self::Windows(decoder) => decoder.close(),
            #[cfg(feature = "software-vpx")]
            Self::Software(decoder) => decoder.close(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lease that implements the one required method and nothing else: the
    /// readiness and render-target answers are defaults, so the existing
    /// implementors (the OpenHarmony lease and the tests' own) did not change.
    struct Lease(u64);

    // SAFETY: the id is a constant and the lease outlives the decoders it is
    // given to.
    unsafe impl SurfaceLease for Lease {
        fn surface_id(&self) -> u64 {
            self.0
        }
    }

    fn config(codec: VideoCodec) -> DecoderConfig {
        DecoderConfig {
            codec,
            width: 640,
            height: 480,
            max_queued_units: 2,
            max_queued_bytes: 4096,
        }
    }

    fn refusal(codec: VideoCodec) -> OpenFailure {
        match SurfaceDecoder::open(config(codec), Arc::new(Lease(7))) {
            Ok(_) => panic!("the seam opened {codec:?} without a Surface or an observer"),
            Err(failure) => failure,
        }
    }

    #[test]
    fn lease_readiness_defaults_to_its_surface_id() {
        assert!(!Lease(0).is_ready());
        assert!(Lease(7).is_ready());
        assert_eq!(Lease(7).render_target(), None);
    }

    #[test]
    fn unmeasured_backend_does_not_create_zero_latency_samples() {
        let mut total = None;
        RenderTiming::accumulate(&mut total, None);
        assert_eq!(total, None);

        RenderTiming::accumulate(&mut total, Some(RenderTiming::default()));
        assert_eq!(total, None);

        RenderTiming::accumulate(
            &mut total,
            Some(RenderTiming {
                samples: 2,
                total_ns: 9,
                peak_ns: 7,
            }),
        );
        RenderTiming::accumulate(&mut total, None);
        assert_eq!(
            total,
            Some(RenderTiming {
                samples: 2,
                total_ns: 9,
                peak_ns: 7,
            })
        );
    }

    #[cfg(not(feature = "software-vpx"))]
    #[test]
    fn vpx_is_refused_by_name_before_any_backend() {
        for codec in [VideoCodec::Vp8, VideoCodec::Vp9] {
            let failure = refusal(codec);
            assert_eq!(failure.error, DecoderError::UnsupportedCodec);
            // Nothing was allocated, so the caller keeps the right to release.
            assert_eq!(failure.cleanup, CleanupVerdict::Confirmed);
        }
    }

    /// With the software backend linked, a lease that presents nowhere is
    /// refused before a decoder exists, whatever the loaded library reports: a
    /// CPU decoder publishes through the frame observer and has no Surface. The
    /// refusal owns nothing, so the lease stays releasable.
    #[cfg(all(feature = "software-vpx", rd_vpx_linked))]
    #[test]
    fn vpx_is_never_opened_without_a_frame_observer() {
        for codec in [VideoCodec::Vp8, VideoCodec::Vp9] {
            let failure = refusal(codec);
            assert_eq!(failure.error, DecoderError::InvalidConfig);
            assert_eq!(failure.cleanup, CleanupVerdict::Confirmed);
        }
    }

    /// With the feature on and no library resolved, the build is not broken: the
    /// codecs are refused by name, nothing is allocated, and no capability is
    /// claimed.
    #[cfg(all(feature = "software-vpx", not(rd_vpx_linked)))]
    #[test]
    fn an_unlinked_software_backend_refuses_by_name() {
        for codec in [VideoCodec::Vp8, VideoCodec::Vp9] {
            let failure = refusal(codec);
            assert_eq!(failure.error, DecoderError::UnsupportedCodec);
            assert_eq!(failure.cleanup, CleanupVerdict::Confirmed);
            assert!(!SurfaceDecoder::serves_software_vpx(codec));
        }
    }

    /// The capability answer is the backend's own probe, for the two codecs it
    /// serves and no others: the hardware categories belong to the platform
    /// decoder even in a build where this one is fully available.
    #[test]
    fn software_capability_answers_for_its_own_codecs_only() {
        for codec in [VideoCodec::H264, VideoCodec::H265] {
            assert!(!SurfaceDecoder::serves_software_vpx(codec));
            assert!(SurfaceDecoder::software_vpx_refusal(codec).is_some());
        }
    }

    /// A build without the feature states that absence instead of reporting a
    /// library or a runtime it never reached.
    #[cfg(not(feature = "software-vpx"))]
    #[test]
    fn an_absent_software_backend_states_why() {
        for codec in [VideoCodec::Vp8, VideoCodec::Vp9] {
            assert!(!SurfaceDecoder::serves_software_vpx(codec));
            let reason = SurfaceDecoder::software_vpx_refusal(codec)
                .expect("an absent backend has a reason");
            assert!(reason.contains("software-vpx"), "{reason}");
        }
    }

    #[cfg(not(target_env = "ohos"))]
    #[test]
    fn hardware_categories_without_a_target_refuse_without_owning_anything() {
        let failure = refusal(VideoCodec::H264);
        #[cfg(target_os = "windows")]
        assert_eq!(failure.error, DecoderError::InvalidConfig);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(failure.error, DecoderError::UnsupportedPlatform);
        assert_eq!(failure.cleanup, CleanupVerdict::Confirmed);
    }
}
