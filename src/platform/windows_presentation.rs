//! Windows D3D11 presentation ownership, separate from OHOS SurfaceLease.
//!
//! Source-only until Main's Windows integration validation. The native unit is
//! compiled only on Windows; no native library is linked on other targets.
//! Callback flags are FRAME_AVAILABLE=1, UNREGISTER_REQUESTED=2, STATE_CHANGED=4.
//! A successful close proves callback retirement, not physical presentation.
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterLuid { pub low_part: u32, pub high_part: i32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PresentationStatus {
    Ok=0, WouldBlock=1, Busy=2, Closing=3, UnsupportedPlatform=4,
    UnsupportedBackend=5, NoHardwareDecoder=6, UnsupportedFormat=7,
    DeviceLost=8, InvalidToken=9, InvalidArgument=10, NativeFailure=11,
    ReclamationUnconfirmed=12, OwnerLimit=13,
}
impl PresentationStatus {
    pub(crate) fn from_native(value: i32) -> Self {
        match value {
            0=>Self::Ok,1=>Self::WouldBlock,2=>Self::Busy,3=>Self::Closing,
            4=>Self::UnsupportedPlatform,5=>Self::UnsupportedBackend,
            6=>Self::NoHardwareDecoder,7=>Self::UnsupportedFormat,8=>Self::DeviceLost,
            9=>Self::InvalidToken,10=>Self::InvalidArgument,12=>Self::ReclamationUnconfirmed,
            13=>Self::OwnerLimit,_=>Self::NativeFailure,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationError { pub status: PresentationStatus, pub stage: u32, pub hresult: i32 }
impl PresentationError {
    pub(crate) fn plain(status: PresentationStatus, stage: u32) -> Self { Self {status,stage,hresult:0} }
    pub(crate) fn native(status: i32, error: ffi::Error) -> Self {
        Self {status:PresentationStatus::from_native(status),stage:error.stage,hresult:error.hresult}
    }
}
impl std::fmt::Display for PresentationError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        write!(f,"Windows presentation {:?}, stage {}, HRESULT 0x{:08x}",self.status,self.stage,self.hresult as u32)
    }
}
impl std::error::Error for PresentationError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupVerdict { Confirmed, Unconfirmed }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityEvidence { None, MetadataSupported, Opened, FirstNativeOutput }
#[derive(Debug, Clone)]
pub struct WindowsCodecCapability {
    pub codec: crate::viewer::decoder::VideoCodec,
    pub available: bool,
    pub evidence: CapabilityEvidence,
    pub hardware_async: bool,
    pub d3d11_aware: bool,
    /// Negotiated NV12 intent; only FirstNativeOutput proves an actual sample.
    pub native_nv12: bool,
    pub tested_width: u32, pub tested_height: u32, pub tested_profile: u32,
    pub decoder_profiles: u32, pub decoder_configs: u32,
    pub status: PresentationStatus, pub hresult: i32,
    pub clsid: [u8;16], pub name: String,
}
impl From<ffi::CodecCapability> for WindowsCodecCapability {
    fn from(c:ffi::CodecCapability)->Self {
        let length=c.name.iter().position(|c|*c==0).unwrap_or(c.name.len());
        Self {
            codec:if c.codec==2 {crate::viewer::decoder::VideoCodec::H265} else {crate::viewer::decoder::VideoCodec::H264},
            available:c.available!=0,
            evidence:match c.evidence {1=>CapabilityEvidence::MetadataSupported,2=>CapabilityEvidence::Opened,3=>CapabilityEvidence::FirstNativeOutput,_=>CapabilityEvidence::None},
            hardware_async:c.hardware_async!=0,d3d11_aware:c.d3d11_aware!=0,native_nv12:c.native_nv12!=0,
            tested_width:c.tested_width,tested_height:c.tested_height,tested_profile:c.tested_profile,
            decoder_profiles:c.decoder_profiles,decoder_configs:c.decoder_configs,
            status:PresentationStatus::from_native(c.status),hresult:c.hresult,clsid:c.clsid,
            name:String::from_utf16_lossy(&c.name[..length]),
        }
    }
}
#[derive(Debug, Clone)]
pub struct WindowsCapabilities {
    pub adapter: AdapterLuid, pub vendor_id: u32, pub device_id: u32, pub feature_level: u32,
    pub shared_texture: bool, pub video_processor: bool, pub event_completion: bool,
    /// Registration counts only. These transforms are never activated as a fallback.
    pub sync_h264_candidates: u32, pub sync_h265_candidates: u32,
    pub h264: WindowsCodecCapability, pub h265: WindowsCodecCapability,
}
#[derive(Debug, Clone, Default)]
pub struct WindowsPresentationStats {
    pub closing: bool, pub registration_retired: bool, pub producers_live: u32,
    pub current_present: bool, pub pending_present: bool, pub converting: bool,
    pub outstanding_loans: u32, pub unconfirmed: bool, pub dispatch_open: bool,
    pub wake_in_flight: u32, pub unregister_requested: bool,
    pub published_images: u64, pub acquired_images: u64, pub superseded_images: u64,
    pub gpu_fence_completions: u64, pub wake_started: u64, pub wake_finished: u64,
    pub generations_started: u64, pub generations_retired: u64, pub last_hresult: i32,
    pub closed: bool, pub callback_retirement_confirmed: bool, pub callback_panicked: bool,
}
impl From<ffi::PresenterStats> for WindowsPresentationStats {
    fn from(s:ffi::PresenterStats)->Self {
        Self {closing:s.closing!=0,registration_retired:s.registration_retired!=0,producers_live:s.producers_live,
            current_present:s.current_present!=0,pending_present:s.pending_present!=0,converting:s.converting!=0,
            outstanding_loans:s.outstanding_loans,unconfirmed:s.unconfirmed!=0,dispatch_open:s.dispatch_open!=0,
            wake_in_flight:s.wake_in_flight,unregister_requested:s.unregister_requested!=0,
            published_images:s.published_images,acquired_images:s.acquired_images,superseded_images:s.superseded_images,
            gpu_fence_completions:s.gpu_fence_completions,wake_started:s.wake_started,wake_finished:s.wake_finished,
            generations_started:s.generations_started,generations_retired:s.generations_retired,last_hresult:s.last_hresult,
            ..Self::default()}
    }
}
#[derive(Debug)]
pub struct ImportFrame {
    pub pixel_format: u32, pub codec_generation: u64, pub frame_sequence: u64,
    pub pts_100ns: i64, pub width: u32, pub height: u32,
    pub visible_width: u32, pub visible_height: u32,
    /// Borrowed legacy DXGI handle; never CloseHandle it or pass it to Dart.
    pub shared_handle: *mut c_void, pub loan_id: u64,
}
/// The client renderer's own GPU submission entry point (`rd_wd_set_texture`).
/// Its first argument is that client's renderer pointer, never an engine token;
/// its second is a borrowed engine texture valid only inside the call. The
/// callee must not throw or retain either pointer and reports no per-call
/// status of its own, so a returned call is not presentation evidence.
pub type SetTexture=unsafe extern "C" fn(*mut c_void,*mut c_void);
// This is independent of native pointer admission and of the public callback.
// Address-wait keeps check/park atomic without making a notifier take a mutex.
const PROGRESS_CANCELLED:u64=1<<63;
const PROGRESS_CLOSED:u64=1<<62;
const PROGRESS_UNCONFIRMED:u64=1<<61;
const PROGRESS_EXHAUSTED:u64=1<<60;
const PROGRESS_TERMINAL:u64=PROGRESS_CANCELLED|PROGRESS_CLOSED|PROGRESS_UNCONFIRMED|PROGRESS_EXHAUSTED;
struct Progress {revision:AtomicU64,error_claimed:AtomicBool,error:AtomicU64}
impl Progress {
    fn new()->Self {Self {revision:AtomicU64::new(1),error_claimed:AtomicBool::new(false),error:AtomicU64::new(0)}}
    fn notify(&self) {
        #[cfg(target_os="windows")]
        unsafe {ffi::WakeByAddressAll(self.revision.as_ptr().cast());}
    }
    fn advance(&self) {
        if self.revision.fetch_update(Ordering::AcqRel,Ordering::Acquire,|revision| {
            if revision&PROGRESS_TERMINAL!=0 {None}
            // Reaching bit 60 is an explicit terminal exhaustion, not wrapping
            // into an old observed revision and potentially sleeping forever.
            else {Some(revision+1)}
        }).is_ok() {self.notify();}
    }
    fn stop(&self,terminal:u64) {
        if self.revision.fetch_or(terminal,Ordering::AcqRel)&terminal==0 {self.notify();}
    }
    fn fail(&self,error:PresentationError) {
        if !self.error_claimed.swap(true,Ordering::AcqRel) {
            self.error.store((u64::from(error.stage)<<32)|u64::from(error.hresult as u32),Ordering::Relaxed);
            // The release publishes both fields before any waiter observes the
            // terminal flag. Later failures never overwrite the original cause.
            self.stop(PROGRESS_UNCONFIRMED);
        }
    }
    fn failure(&self)->Option<PresentationError> {
        if self.revision.load(Ordering::Acquire)&PROGRESS_UNCONFIRMED==0 {return None;}
        let error=self.error.load(Ordering::Relaxed);
        Some(PresentationError {status:PresentationStatus::ReclamationUnconfirmed,stage:(error>>32) as u32,hresult:error as u32 as i32})
    }
    fn wait(&self,revision:&mut u64,cancel:bool)->Result<(),PresentationError> {
        if cancel {self.stop(PROGRESS_CANCELLED);return Ok(());}
        loop {
            let current=self.revision.load(Ordering::Acquire);
            if let Some(error)=self.failure() {return Err(error);}
            if current&PROGRESS_CANCELLED!=0 {return Err(PresentationError::plain(PresentationStatus::Closing,5));}
            if current&PROGRESS_CLOSED!=0 {return Err(PresentationError::plain(PresentationStatus::Closing,5));}
            if current&PROGRESS_EXHAUSTED!=0 {return Err(PresentationError::plain(PresentationStatus::OwnerLimit,5));}
            if *revision==0 || current!=*revision {*revision=current;return Ok(());}
            #[cfg(target_os="windows")]
            {
                // WaitOnAddress may return spuriously. Only the atomic predicate
                // permits a retry; this is an untimed worker wait, never polling.
                if unsafe {ffi::WaitOnAddress(self.revision.as_ptr().cast(),(&current as *const u64).cast(),8,u32::MAX)}==0 {
                    let code=unsafe {ffi::GetLastError()};
                    let hresult=if (code as i32)<=0 {code as i32}else{(0x80070000u32|(code&0xffff)) as i32};
                    return Err(PresentationError {status:PresentationStatus::NativeFailure,stage:5,hresult});
                }
            }
            #[cfg(not(target_os="windows"))]
            {return Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,5));}
        }
    }
}
struct WakeState {
    callback: Arc<dyn Fn(u32)+Send+Sync+'static>,
    producer: Mutex<Option<(u64,Arc<dyn Fn()+Send+Sync>)>>,
    progress: Progress,
    panicked: AtomicBool,
}
impl WakeState {
    fn producer_slot_retired(&self,wake:Option<Arc<dyn Fn()+Send+Sync>>) {
        // Only real install/retire, first-close and native-event paths hold this
        // slot. Every holder signals its copied current producer after unlock,
        // so a concurrent try_lock failure cannot lose the requested wake. No
        // post-unlock pending bit can accidentally consume a newer generation.
        if let Some(wake)=wake {wake();}
    }
    fn signal_producer(&self) {
        let guard=match self.producer.try_lock() {
            Ok(guard)=>guard,
            Err(std::sync::TryLockError::Poisoned(error))=>error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock)=>return,
        };
        let wake=guard.as_ref().map(|(_,wake)|wake.clone());
        drop(guard);
        self.producer_slot_retired(wake);
    }
    fn dispatch(&self,reasons:u32) {
        self.signal_producer();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(||(self.callback)(reasons))).is_err() {
            self.panicked.store(true,Ordering::Release);
        }
    }
}
#[cfg(target_os="windows")]
unsafe extern "C" fn wake(context:*mut c_void,_token:u64,reasons:u32) {
    // The raw Arc reference belongs to the native callback source until dispose
    // returns OK. Busy, quarantine and owner Drop intentionally retain it.
    let state=unsafe { &*context.cast::<WakeState>() };
    state.dispatch(reasons);
}
#[cfg(target_os="windows")]
unsafe extern "C" fn progress(context:*mut c_void,error:*const ffi::Error) {
    // Synchronous private notification, protected by the source's native call
    // admission or live producer. Never dispatch another public callback here.
    let state=unsafe {&*context.cast::<WakeState>()};
    if let Some(error)=unsafe {error.as_ref()} {
        state.progress.fail(PresentationError::native(PresentationStatus::ReclamationUnconfirmed as i32,*error));
    } else {state.progress.advance();}
}
struct AdmissionRetirement<'a> {pending:&'a AtomicBool,progress:&'a Progress}
impl Drop for AdmissionRetirement<'_> {
    fn drop(&mut self) {
        if self.pending.swap(false,Ordering::SeqCst) {self.progress.advance();}
    }
}
// Fields drop in declaration order: release the actual read/write gate before
// publishing its registered retirement. No raw native pointer is used after it.
struct Admitted<'a,G> {guard:G,_retirement:AdmissionRetirement<'a>}
static NEXT_GENERATION: AtomicU64=AtomicU64::new(1);
static QUARANTINED: AtomicBool=AtomicBool::new(false);
/// Public calls take a shared lifetime gate. Disposal takes an exclusive,
/// nonblocking gate and never races another native call or frees a live pointer.
/// Wake closures must only enqueue bounded metadata and must not reenter this owner.
pub struct WindowsPresentation {
    native: RwLock<Option<usize>>,
    admission_pending: AtomicBool,
    wake: Arc<WakeState>,
    closing: AtomicBool,
    probing: AtomicBool,
    uncertain: AtomicBool,
    epoch: AtomicU64,
    final_stats: Mutex<Option<WindowsPresentationStats>>,
}
impl WindowsPresentation {
    pub fn create(adapter:AdapterLuid,callback:Arc<dyn Fn(u32)+Send+Sync+'static>)->Result<Arc<Self>,PresentationError> {
        #[cfg(not(target_os="windows"))]
        { let _=(adapter,callback); Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,2)) }
        #[cfg(target_os="windows")]
        {
            if QUARANTINED.load(Ordering::Acquire) {
                return Err(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,2));
            }
            let state=Arc::new(WakeState {callback,producer:Mutex::new(None),
                progress:Progress::new(),panicked:AtomicBool::new(false)});
            let retained=Arc::into_raw(state.clone());
            let options=ffi::PresenterOptions {struct_size:std::mem::size_of::<ffi::PresenterOptions>() as u32,
                adapter_luid_low:adapter.low_part,adapter_luid_high:adapter.high_part,reserved:0,
                token:0,wake:Some(wake),wake_context:retained.cast_mut().cast(),progress:Some(progress)};
            let mut raw=std::ptr::null_mut();let mut error=ffi::Error::new();
            let status=unsafe {ffi::rd_wd_presenter_create(&options,&mut raw,&mut error)};
            if status!=0 {
                // Native create installs the callback only after successful device
                // creation. Even partial-device quarantine has no callback source.
                unsafe {drop(Arc::from_raw(retained));}
                return Err(PresentationError::native(status,error));
            }
            if raw.is_null() {
                // ABI violation: do not risk releasing potentially reachable userdata.
                return Err(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,2));
            }
            Ok(Arc::new(Self {native:RwLock::new(Some(raw as usize)),admission_pending:AtomicBool::new(false),wake:state,
                closing:AtomicBool::new(false),probing:AtomicBool::new(false),uncertain:AtomicBool::new(false),
                epoch:AtomicU64::new(0),final_stats:Mutex::new(None)}))
        }
    }
    /// Permanently consumes this registration for exactly one nonzero session
    /// epoch. Even an unsuccessful session cannot rebind the same presentation.
    pub fn bind_session(&self,epoch:u64)->Result<(),PresentationError> {
        if epoch==0 {return Err(PresentationError::plain(PresentationStatus::InvalidArgument,1));}
        if self.is_closing() {return Err(PresentationError::plain(PresentationStatus::Closing,5));}
        self.epoch.compare_exchange(0,epoch,Ordering::AcqRel,Ordering::Acquire)
            .map(|_|()).map_err(|_|PresentationError::plain(PresentationStatus::Busy,1))
    }
    /// The immutable session binding, not evidence of readiness or codec support.
    /// A caller must separately check liveness before starting a producer.
    pub fn bound_epoch(&self)->Option<u64> {
        let epoch=self.epoch.load(Ordering::Acquire);
        (epoch!=0).then_some(epoch)
    }
    /// Snapshot admission only: begin_producer still checks retirement again.
    /// A successful check proves no decoded output, import or physical display.
    pub(crate) fn check_live(&self)->Result<(),PresentationError> {
        if let Some(error)=self.wake.progress.failure() {return Err(error);}
        if self.uncertain.load(Ordering::Acquire)||QUARANTINED.load(Ordering::Acquire) {
            return Err(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,2));
        }
        if self.is_closing() {return Err(PresentationError::plain(PresentationStatus::Closing,5));}
        // The real snapshot takes the native lifetime gate and refuses a disposed
        // pointer; the non-Windows module supplies its own UnsupportedPlatform.
        let stats=self.stats()?;
        if stats.unconfirmed {return Err(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,2));}
        if stats.closing||stats.closed||stats.registration_retired {
            return Err(PresentationError::plain(PresentationStatus::Closing,5));
        }
        Ok(())
    }
    pub(crate) fn is_closing(&self)->bool {self.closing.load(Ordering::Acquire)}
    pub(crate) fn retain_uncertain(&self) {
        self.wake.progress.fail(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,5));
        self.uncertain.store(true,Ordering::Release);
        QUARANTINED.store(true,Ordering::Release);
    }
    fn admitted<G>(&self,guard:G)->Admitted<'_,G> {
        Admitted {guard,_retirement:AdmissionRetirement {pending:&self.admission_pending,progress:&self.wake.progress}}
    }
    fn try_admit<G>(&self,lock:impl Fn()->std::sync::TryLockResult<G>)->Result<Admitted<'_,G>,PresentationError> {
        let result=match lock() {
            Err(std::sync::TryLockError::WouldBlock)=>{
                // Register before recheck, paired with retirement's SeqCst
                // exchange after unlocking. Neither side can miss the other.
                self.admission_pending.store(true,Ordering::SeqCst);
                lock()
            }
            result=>result,
        };
        let guard=result.map_err(|error|match error {
            std::sync::TryLockError::WouldBlock=>PresentationError::plain(PresentationStatus::Busy,5),
            std::sync::TryLockError::Poisoned(_)=>{
                self.retain_uncertain();
                PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,5)
            }
        })?;
        Ok(self.admitted(guard))
    }
    pub(crate) fn native_call<T>(&self,nonblocking:bool,f:impl FnOnce(*mut c_void)->Result<T,PresentationError>)->Result<T,PresentationError> {
        let admitted=if nonblocking {self.try_admit(||self.native.try_read())?}
        else {self.admitted(self.native.read().map_err(|_| {
            self.retain_uncertain();PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,5)
        })?)};
        let raw=admitted.guard.as_ref().copied().ok_or_else(||PresentationError::plain(PresentationStatus::Closing,5))?;
        // Native unconfirmed transitions normally publish their exact error via
        // the private progress callback. The method result remains unchanged.
        f(raw as *mut c_void)
    }
    /// Worker-only durable wait. Bootstrap revision zero BEFORE the operation;
    /// after Busy, wait with that same revision. Cancellation only stops waits,
    /// never acknowledges a loan, callback retirement or native reclamation.
    pub fn wait_progress(&self,revision:&mut u64,cancel:bool)->Result<(),PresentationError> {
        self.wake.progress.wait(revision,cancel)
    }
    pub fn query_capabilities(self:&Arc<Self>)->Result<WindowsCapabilities,PresentationError> {
        #[cfg(not(target_os="windows"))]
        {Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,6))}
        #[cfg(target_os="windows")]
        {
            if self.uncertain.load(Ordering::Acquire) {
                return Err(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,6));
            }
            self.probing.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire)
                .map_err(|_|PresentationError::plain(PresentationStatus::Busy,6))?;
            // An unconfirmed MF probe retains its creating COM apartment, not
            // merely a dangling graph on a terminated thread. One probe per owner.
            let owner=self.clone();let (tx,rx)=std::sync::mpsc::sync_channel(1);
            let worker=std::thread::Builder::new().name("windows-capability".into()).spawn(move || {
                let result=owner.native_call(false,|p| {
                    let mut caps=ffi::Capabilities::new();let mut e=ffi::Error::new();
                    let status=unsafe {ffi::rd_wd_presenter_capabilities(p,&mut caps,&mut e)};
                    if status==0 {Ok(WindowsCapabilities {adapter:AdapterLuid {low_part:caps.adapter_luid_low,high_part:caps.adapter_luid_high},
                        vendor_id:caps.vendor_id,device_id:caps.device_id,feature_level:caps.feature_level,
                        shared_texture:caps.shared_texture!=0,video_processor:caps.video_processor!=0,event_completion:caps.event_completion!=0,
                        sync_h264_candidates:caps.sync_h264_candidates,sync_h265_candidates:caps.sync_h265_candidates,
                        h264:caps.h264.into(),h265:caps.h265.into()})}
                    else {Err(PresentationError::native(status,e))}
                });
                let unconfirmed=matches!(&result,Err(e) if e.status==PresentationStatus::ReclamationUnconfirmed);
                if unconfirmed {owner.retain_uncertain();}
                owner.probing.store(false,Ordering::Release);
                let _=tx.send(result);
                if unconfirmed {loop {std::thread::park();}}
            }).map_err(|_|{self.probing.store(false,Ordering::Release);PresentationError::plain(PresentationStatus::NativeFailure,6)})?;
            let result=rx.recv().map_err(|_|PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,6))?;
            if !matches!(&result,Err(e) if e.status==PresentationStatus::ReclamationUnconfirmed) {
                worker.join().map_err(|_|PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,6))?;
            }
            result
        }
    }
    pub fn acquire_import_loan(&self)->Result<ImportFrame,PresentationError> {
        #[cfg(not(target_os="windows"))]
        {Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,4))}
        #[cfg(target_os="windows")]
        self.native_call(true,|p| {
            let mut f=ffi::Frame::new();let mut e=ffi::Error::new();
            ffi::checked(unsafe {ffi::rd_wd_presenter_acquire(p,&mut f,&mut e)},e)?;
            Ok(ImportFrame {pixel_format:f.pixel_format,codec_generation:f.codec_generation,frame_sequence:f.frame_sequence,
                pts_100ns:f.pts_100ns,width:f.width,height:f.height,visible_width:f.visible_width,visible_height:f.visible_height,
                shared_handle:f.shared_handle,loan_id:f.loan_id})
        })
    }
    pub fn release_import_loan(&self,id:u64)->Result<(),PresentationError> {
        #[cfg(not(target_os="windows"))]
        {let _=id;Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,4))}
        #[cfg(target_os="windows")]
        self.native_call(true,|p| {let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_presenter_release(p,id,&mut e)},e)})
    }
    /// Submits the newest published presentation image to the client's own GPU
    /// renderer in one native call: one loan is taken, that loan's texture is
    /// handed to `set_texture`, and the loan is released before returning.
    /// `renderer_output` is the client's renderer pointer (never an engine
    /// token); the texture pointer `set_texture` receives is valid only inside
    /// that call and the loan never escapes. `WouldBlock` means no image has
    /// been published yet, `Busy` is owner/state contention, and a null renderer
    /// pointer or a closing owner is refused instead of submitted. There is no
    /// generation argument, so the submitted image is simply the newest one
    /// published, exactly as the import path sees it: a returned call does not
    /// prove that the image belongs to the caller's own codec generation.
    ///
    /// OK proves the loan was submitted and released, never that a frame was
    /// physically presented or copied: the client entry point returns no status
    /// and its internal failure counter is silent, so this is not presentation
    /// evidence. Nothing in this engine calls it yet; the consumer wiring is a
    /// separate, Windows-experiment-gated step.
    ///
    /// # Safety
    /// The owner's admission gate protects this presenter and its device, never
    /// a foreign renderer: a non-null check cannot prove an address still names
    /// a live renderer, and the native call hands it straight to the client's
    /// own entry point. The caller must guarantee all of the following.
    ///
    /// - `renderer_output` is the renderer object this submission is for, and it
    ///   stays alive and valid for the whole call; a freed or arbitrary non-null
    ///   address is UB inside `set_texture`.
    /// - `set_texture` is that same renderer's real submission entry point with
    ///   the exact `rd_wd_set_texture` ABI, i.e. this type's
    ///   `unsafe extern "C" fn(*mut c_void,*mut c_void)` for
    ///   `void (*RD_WD_CALL)(void*, void*)`; the native call invokes it
    ///   directly, so an ABI mismatch is UB. As a function pointer type it
    ///   cannot express null, so a null callback stays a C-side refusal.
    /// - Neither `set_texture` nor anything it calls unwinds across the FFI
    ///   boundary. The native call contains a C++ exception, but a Rust panic
    ///   in an `extern "C"` callback aborts the process instead of returning.
    /// - Neither `set_texture` nor anything it calls reenters this presenter's
    ///   submission, conversion or capability paths: the native call holds the
    ///   non-recursive submission mutex across the callback, so a reentrant one
    ///   deadlocks on this thread.
    /// - `set_texture` retains neither pointer it receives past its return. The
    ///   texture pointer is a loan that is released when this call returns, so
    ///   the image may be reused or freed immediately afterwards; the renderer
    ///   pointer is borrowed from the caller only for this call, and the engine
    ///   neither dereferences nor retains it.
    pub unsafe fn publish_gpu(&self,renderer_output:*mut c_void,set_texture:SetTexture)->Result<(),PresentationError> {
        if renderer_output.is_null() {return Err(PresentationError::plain(PresentationStatus::InvalidArgument,1));}
        if self.is_closing() {return Err(PresentationError::plain(PresentationStatus::Closing,4));}
        #[cfg(not(target_os="windows"))]
        {let _=(renderer_output,set_texture);Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,4))}
        #[cfg(target_os="windows")]
        self.native_call(true,|p| {let mut e=ffi::Error::new();
            ffi::checked(unsafe {ffi::rd_wd_presenter_publish_gpu(p,renderer_output,set_texture,&mut e)},e)})
    }
    pub fn request_close(&self)->Result<(),PresentationError> {
        if !self.closing.swap(true,Ordering::AcqRel) {self.wake.signal_producer();}
        #[cfg(not(target_os="windows"))]
        {Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,5))}
        #[cfg(target_os="windows")]
        self.native_call(true,|p| {let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_presenter_request_close(p,&mut e)},e)})
    }
    pub fn registration_retired(&self)->Result<(),PresentationError> {
        #[cfg(not(target_os="windows"))]
        {Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,5))}
        #[cfg(target_os="windows")]
        self.native_call(true,|p| {let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_presenter_registration_retired(p,&mut e)},e)})
    }
    pub fn stats(&self)->Result<WindowsPresentationStats,PresentationError> {
        if let Some(stats)=self.final_stats.lock().unwrap_or_else(|e|e.into_inner()).clone(){return Ok(stats);}
        #[cfg(not(target_os="windows"))]
        {Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,1))}
        #[cfg(target_os="windows")]
        self.native_call(true,|p| {
            let mut stats=ffi::PresenterStats::new();let mut e=ffi::Error::new();
            ffi::checked(unsafe {ffi::rd_wd_presenter_snapshot(p,&mut stats,&mut e)},e)?;
            let mut stats:WindowsPresentationStats=stats.into();
            stats.unconfirmed|=self.uncertain.load(Ordering::Acquire);
            stats.callback_panicked=self.wake.panicked.load(Ordering::Acquire);Ok(stats)
        })
    }
    /// Nonblocking final close. A Busy or Unconfirmed result retains pointer,
    /// callback context and final verdict. Codec generation close never edits it.
    pub fn close(&self)->Result<(),PresentationError> {
        #[cfg(not(target_os="windows"))]
        {Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,5))}
        #[cfg(target_os="windows")]
        {
            if let Some(error)=self.wake.progress.failure() {return Err(error);}
            if self.uncertain.load(Ordering::Acquire) {
                return Err(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,5));
            }
            let mut admitted=self.try_admit(||self.native.try_write())?;
            let Some(raw)=*admitted.guard else {return Ok(());};
            if self.is_closing() {
                // A previous request may have latched Rust cancellation while
                // admission was busy. Apply that intent before final disposal.
                let mut e=ffi::Error::new();
                ffi::checked(unsafe {ffi::rd_wd_presenter_request_close(raw as *mut c_void,&mut e)},e)?;
            }
            let mut snapshot=ffi::PresenterStats::new();let mut e=ffi::Error::new();
            ffi::checked(unsafe {ffi::rd_wd_presenter_snapshot(raw as *mut c_void,&mut snapshot,&mut e)},e)?;
            ffi::checked(unsafe {ffi::rd_wd_presenter_dispose(raw as *mut c_void,&mut e)},e)?;
            *admitted.guard=None;
            let mut stats:WindowsPresentationStats=snapshot.into();
            stats.closed=true;stats.dispatch_open=false;stats.current_present=false;stats.pending_present=false;
            stats.callback_retirement_confirmed=true;stats.callback_panicked=self.wake.panicked.load(Ordering::Acquire);
            *self.final_stats.lock().unwrap_or_else(|e|e.into_inner())=Some(stats);
            // Exactly one raw Arc was transferred at create, released only now.
            unsafe {drop(Arc::from_raw(Arc::as_ptr(&self.wake)));}
            self.wake.progress.stop(PROGRESS_CLOSED);
            Ok(())
        }
    }
    pub fn open_raster(self:&Arc<Self>)->Result<WindowsRaster,PresentationError> {
        Ok(WindowsRaster {producer:Some(self.begin_producer(None)?)})
    }
    pub(crate) fn begin_producer(self:&Arc<Self>,wake:Option<Arc<dyn Fn()+Send+Sync>>)->Result<Producer,PresentationError> {
        if self.epoch.load(Ordering::Acquire)==0 {return Err(PresentationError::plain(PresentationStatus::InvalidArgument,1));}
        if self.is_closing(){return Err(PresentationError::plain(PresentationStatus::Closing,5));}
        if self.uncertain.load(Ordering::Acquire)||QUARANTINED.load(Ordering::Acquire) {
            return Err(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,2));
        }
        #[cfg(not(target_os="windows"))]
        {let _=wake;Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,2))}
        #[cfg(target_os="windows")]
        {
            let generation=NEXT_GENERATION.fetch_update(Ordering::AcqRel,Ordering::Acquire,|n|n.checked_add(1))
                .map_err(|_|PresentationError::plain(PresentationStatus::OwnerLimit,2))?;
            self.native_call(false,|p| {let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_presenter_begin_generation(p,generation,&mut e)},e)})?;
            if let Some(wake)=wake {
                let mut slot=self.wake.producer.lock().unwrap_or_else(|e|e.into_inner());
                *slot=Some((generation,wake.clone()));
                drop(slot);
                self.wake.producer_slot_retired(Some(wake));
            }
            Ok(Producer {owner:self.clone(),generation,retired:false})
        }
    }
}
impl Drop for WindowsPresentation {
    fn drop(&mut self) {
        // No forged registration acknowledgement. If the runner abandoned its
        // registration, retain the bounded native owner and its raw callback Arc.
        let _=self.request_close();let _=self.close();
    }
}
pub(crate) struct Producer {pub(crate) owner:Arc<WindowsPresentation>,pub(crate) generation:u64,retired:bool}
impl Producer {
    pub(crate) fn retire(&mut self)->Result<(),PresentationError> {
        if self.retired{return Ok(());}
        #[cfg(not(target_os="windows"))]
        {Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,5))}
        #[cfg(target_os="windows")]
        {
            self.owner.native_call(false,|p| {let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_presenter_end_generation(p,self.generation,&mut e)},e)})?;
            let mut slot=self.owner.wake.producer.lock().unwrap_or_else(|e|e.into_inner());
            if slot.as_ref().is_some_and(|(generation,_)|*generation==self.generation){*slot=None;}
            let wake=slot.as_ref().map(|(_,wake)|wake.clone());
            drop(slot);
            self.owner.wake.producer_slot_retired(wake);
            self.retired=true;Ok(())
        }
    }
}
/// Borrowed raster upload is an explicit protocol path, never a compressed-video
/// fallback. Keep the same bitmap unchanged on WouldBlock, then retry it.
pub struct WindowsRaster {producer:Option<Producer>}
impl WindowsRaster {
    pub fn present_bgra(&self,bytes:&[u8],width:u32,height:u32,stride:u32,damage:Option<[i32;4]>,pts_us:i64)->Result<(),PresentationError> {
        let p=self.producer.as_ref().ok_or_else(||PresentationError::plain(PresentationStatus::Closing,5))?;
        let pts=pts_us.checked_mul(10).ok_or_else(||PresentationError::plain(PresentationStatus::InvalidArgument,1))?;
        #[cfg(not(target_os="windows"))]
        {let _=(p,bytes,width,height,stride,damage,pts);Err(PresentationError::plain(PresentationStatus::UnsupportedPlatform,3))}
        #[cfg(target_os="windows")]
        {
            let [left,top,right,bottom]=damage.unwrap_or([0,0,i32::try_from(width).map_err(|_|PresentationError::plain(PresentationStatus::InvalidArgument,1))?,i32::try_from(height).map_err(|_|PresentationError::plain(PresentationStatus::InvalidArgument,1))?]);
            let raster=ffi::Raster {struct_size:std::mem::size_of::<ffi::Raster>() as u32,width,height,stride,
                damage_left:left,damage_top:top,damage_right:right,damage_bottom:bottom,pts_100ns:pts,
                codec_generation:p.generation,data:bytes.as_ptr(),data_len:bytes.len()};
            p.owner.native_call(false,|native|{let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_presenter_publish_bgra(native,&raster,&mut e)},e)})
        }
    }
    pub fn close(mut self)->Result<(),PresentationError> {
        if let Some(mut producer)=self.producer.take(){producer.retire()}else{Ok(())}
    }
}
impl Drop for WindowsRaster {fn drop(&mut self){if let Some(p)=self.producer.as_mut(){let _=p.retire();}}}

pub(crate) mod ffi {
    use super::{c_void,PresentationError};
    macro_rules! pod {
        ($name:ident {$($field:ident:$ty:ty),* $(,)?}) => {
            #[repr(C)] #[derive(Clone,Copy)] pub(crate) struct $name {$(pub $field:$ty),*}
            impl $name {pub fn new()->Self {let mut value:Self=unsafe {std::mem::zeroed()};value.struct_size=std::mem::size_of::<Self>() as u32;value}}
        };
    }
    pod!(Error {struct_size:u32,stage:u32,hresult:i32,reserved:u32});
    pod!(PresenterOptions {struct_size:u32,adapter_luid_low:u32,adapter_luid_high:i32,reserved:u32,token:u64,
        wake:Option<unsafe extern "C" fn(*mut c_void,u64,u32)>,wake_context:*mut c_void,
        progress:Option<unsafe extern "C" fn(*mut c_void,*const Error)>});
    pod!(CodecCapability {struct_size:u32,codec:u32,available:u32,evidence:u32,hardware_async:u32,d3d11_aware:u32,
        native_nv12:u32,tested_width:u32,tested_height:u32,tested_profile:u32,decoder_profiles:u32,decoder_configs:u32,
        status:i32,hresult:i32,clsid:[u8;16],name:[u16;128]});
    pod!(Capabilities {struct_size:u32,adapter_luid_low:u32,adapter_luid_high:i32,vendor_id:u32,device_id:u32,
        feature_level:u32,shared_texture:u32,video_processor:u32,event_completion:u32,sync_h264_candidates:u32,
        sync_h265_candidates:u32,reserved:u32,h264:CodecCapability,h265:CodecCapability});
    pod!(Frame {struct_size:u32,pixel_format:u32,codec_generation:u64,frame_sequence:u64,pts_100ns:i64,
        width:u32,height:u32,visible_width:u32,visible_height:u32,shared_handle:*mut c_void,loan_id:u64});
    pod!(PresenterStats {struct_size:u32,closing:u32,registration_retired:u32,producers_live:u32,current_present:u32,
        pending_present:u32,converting:u32,outstanding_loans:u32,unconfirmed:u32,dispatch_open:u32,wake_in_flight:u32,
        unregister_requested:u32,published_images:u64,acquired_images:u64,superseded_images:u64,gpu_fence_completions:u64,
        wake_started:u64,wake_finished:u64,generations_started:u64,generations_retired:u64,last_hresult:i32,reserved:u32});
    pod!(DecodedFrame {struct_size:u32,texture_width:u32,texture_height:u32,subresource:u32,coded_width:u32,
        coded_height:u32,aperture_present:u32,aperture_left:u32,aperture_top:u32,visible_width:u32,visible_height:u32,
        primaries:u32,transfer:u32,matrix:u32,nominal_range:u32,chroma_siting:u32,codec_generation:u64,output_sequence:u64,
        pts_100ns:i64,d3d11_texture2d:*mut c_void,d3d11_device:*mut c_void});
    pod!(Raster {struct_size:u32,width:u32,height:u32,stride:u32,damage_left:i32,damage_top:i32,damage_right:i32,
        damage_bottom:i32,pts_100ns:i64,codec_generation:u64,data:*const u8,data_len:usize});
    pod!(DecoderOptions {struct_size:u32,codec:u32,max_width:u32,max_height:u32,generation:u64,presenter:*mut c_void,
        wake:Option<unsafe extern "C" fn(*mut c_void,u32,i32)>,wake_context:*mut c_void});
    pod!(OpenReport {struct_size:u32,cleanup:u32,identity:CodecCapability});
    pod!(DecoderStats {struct_size:u32,opened:u32,need_input_events:u32,have_output_events:u32,drain_complete:u32,
        stream_changes:u32,unknown_events:u32,event_overflow:u32,callback_in_flight:u32,callbacks_retired:u32,
        input_buffers_live:u32,native_output_seen:u32,last_hresult:i32,reserved:u32,pushed_units:u64,pushed_bytes:u64,
        decoded_pictures:u64,non_picture_outputs:u64,texture_array_size:u32,reserved2:u32,
        texture_allocation_bytes:u64,last_output:DecodedFrame});
    pub fn checked(status:i32,error:Error)->Result<(),PresentationError> {
        if status==0 {Ok(())}else{Err(PresentationError::native(status,error))}
    }
    #[cfg(target_os="windows")]
    #[link(name="synchronization")]
    unsafe extern "system" {
        pub fn WaitOnAddress(address:*const c_void,compare:*const c_void,size:usize,milliseconds:u32)->i32;
        pub fn WakeByAddressAll(address:*mut c_void);
    }
    #[cfg(target_os="windows")]
    #[link(name="kernel32")]
    unsafe extern "system" {pub fn GetLastError()->u32;}
    #[cfg(target_os="windows")]
    unsafe extern "C" {
        pub fn rd_wd_presenter_create(o:*const PresenterOptions,p:*mut *mut c_void,e:*mut Error)->i32;
        pub fn rd_wd_presenter_capabilities(p:*mut c_void,c:*mut Capabilities,e:*mut Error)->i32;
        pub fn rd_wd_presenter_begin_generation(p:*mut c_void,g:u64,e:*mut Error)->i32;
        pub fn rd_wd_presenter_end_generation(p:*mut c_void,g:u64,e:*mut Error)->i32;
        pub fn rd_wd_presenter_acquire(p:*mut c_void,f:*mut Frame,e:*mut Error)->i32;
        pub fn rd_wd_presenter_release(p:*mut c_void,id:u64,e:*mut Error)->i32;
        pub fn rd_wd_presenter_publish(p:*mut c_void,f:*const DecodedFrame,e:*mut Error)->i32;
        pub fn rd_wd_presenter_publish_bgra(p:*mut c_void,r:*const Raster,e:*mut Error)->i32;
        pub fn rd_wd_presenter_publish_gpu(p:*mut c_void,renderer_output:*mut c_void,set_texture:super::SetTexture,e:*mut Error)->i32;
        pub fn rd_wd_presenter_snapshot(p:*mut c_void,s:*mut PresenterStats,e:*mut Error)->i32;
        pub fn rd_wd_presenter_request_close(p:*mut c_void,e:*mut Error)->i32;
        pub fn rd_wd_presenter_registration_retired(p:*mut c_void,e:*mut Error)->i32;
        pub fn rd_wd_presenter_dispose(p:*mut c_void,e:*mut Error)->i32;
        pub fn rd_wd_presenter_device(p:*mut c_void)->*mut c_void;
        pub fn rd_wd_decoder_open(o:*const DecoderOptions,p:*mut *mut c_void,r:*mut OpenReport,e:*mut Error)->i32;
        pub fn rd_wd_decoder_input(p:*mut c_void,data:*mut c_void,size:usize,pts:i64,flags:u32,
            release:unsafe extern "C" fn(*mut c_void),context:*mut c_void,e:*mut Error)->i32;
        pub fn rd_wd_decoder_output(p:*mut c_void,f:*mut DecodedFrame,kind:*mut u32,e:*mut Error)->i32;
        pub fn rd_wd_decoder_release_output(p:*mut c_void,f:*const DecodedFrame);
        pub fn rd_wd_decoder_drain(p:*mut c_void,e:*mut Error)->i32;
        pub fn rd_wd_decoder_flush(p:*mut c_void,e:*mut Error)->i32;
        pub fn rd_wd_decoder_snapshot(p:*const c_void,s:*mut DecoderStats,e:*mut Error)->i32;
        pub fn rd_wd_decoder_close(p:*mut c_void,e:*mut Error)->i32;
    }
    const _: [();16]=[();std::mem::size_of::<Error>()];
    #[cfg(target_pointer_width="64")]
    const _: [();48]=[();std::mem::size_of::<PresenterOptions>()];
    const _: [();328]=[();std::mem::size_of::<CodecCapability>()];
    const _: [();704]=[();std::mem::size_of::<Capabilities>()];
    const _: [();120]=[();std::mem::size_of::<PresenterStats>()];
    #[cfg(target_pointer_width="64")]
    const _: [();208]=[();std::mem::size_of::<DecoderStats>()];
    #[cfg(target_pointer_width="64")]
    const _: [();104]=[();std::mem::size_of::<DecodedFrame>()];
}

#[cfg(all(test,target_os="windows"))]
mod progress_tests {
    use super::*;

    #[test]
    fn gate_retirement_before_wait_is_durable_without_another_callback() {
        let gate=RwLock::new(());
        let progress=Progress::new();
        let pending=AtomicBool::new(false);
        let reader=match gate.read() {Ok(reader)=>reader,Err(error)=>panic!("reader admission poisoned: {error}")};
        let admitted=Admitted {guard:reader,_retirement:AdmissionRetirement {pending:&pending,progress:&progress}};
        let mut revision=0;
        progress.wait(&mut revision,false).unwrap();
        assert!(matches!(gate.try_write(),Err(std::sync::TryLockError::WouldBlock)));
        pending.store(true,Ordering::SeqCst);
        assert!(matches!(gate.try_write(),Err(std::sync::TryLockError::WouldBlock)));
        // The final reader/callback source exits BEFORE the worker enters wait.
        // A pure edge notification would be lost; the address predicate is not.
        drop(admitted);
        progress.wait(&mut revision,false).unwrap();
        assert!(gate.try_write().is_ok());
        let observed=revision;
        let reader=match gate.read() {Ok(reader)=>reader,Err(error)=>panic!("reader admission poisoned: {error}")};
        let admitted=Admitted {guard:reader,_retirement:AdmissionRetirement {pending:&pending,progress:&progress}};
        drop(admitted);
        let mut snapshot=0;
        progress.wait(&mut snapshot,false).unwrap();
        assert_eq!(snapshot,observed,"an unrequested unlock must not create a retry");
    }

    #[test]
    fn cancellation_wakes_existing_waiters_and_is_sticky() {
        let progress=Arc::new(Progress::new());
        let mut revision=0;
        progress.wait(&mut revision,false).unwrap();
        let (ready_tx,ready_rx)=std::sync::mpsc::channel();
        let workers:Vec<_>=(0..2).map(|_| {
            let progress=progress.clone();let ready=ready_tx.clone();
            std::thread::spawn(move || {
                let mut observed=revision;
                ready.send(()).unwrap();
                progress.wait(&mut observed,false)
            })
        }).collect();
        for _ in 0..2 {ready_rx.recv().unwrap();}
        progress.wait(&mut revision,true).unwrap();
        for worker in workers {assert_eq!(worker.join().unwrap().unwrap_err().status,PresentationStatus::Closing);}
        progress.wait(&mut revision,true).unwrap();
        let mut bootstrap=0;
        assert_eq!(progress.wait(&mut bootstrap,false).unwrap_err().status,PresentationStatus::Closing);
    }

    #[test]
    fn unconfirmed_wait_preserves_the_first_native_error() {
        let progress=Progress::new();
        let first=PresentationError {status:PresentationStatus::ReclamationUnconfirmed,stage:3,hresult:0x887a0005u32 as i32};
        progress.fail(first);
        progress.fail(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,5));
        let mut revision=0;
        assert_eq!(progress.wait(&mut revision,false),Err(first));
        progress.wait(&mut revision,true).unwrap();
        assert_eq!(progress.wait(&mut revision,false),Err(first));
    }
}
