//! Strict hardware-category asynchronous Media Foundation decoder owner.
//!
//! Uses the existing complete-AU/config/codec contract, not OHOS evidence. One
//! persistent MTA worker, two admitted AUs and 32MiB including native-retained
//! input buffers, plus one ordered EOS control marker outside that data quota.
//! A rejected submission returns the original Vec. Native input
//! owns that allocation after ProcessInput succeeds and returns it only when the
//! MFT releases its last buffer reference. No bitstream copy, frame task, polling
//! timer, decoded CPU image or compressed-video fallback exists here.
use std::sync::Arc;
pub use crate::viewer::decoder::{AccessUnit,AccessUnitKind,DecoderConfig,VideoCodec};
use crate::windows_presentation::{CleanupVerdict,PresentationError,PresentationStatus,WindowsCodecCapability,WindowsPresentation};

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum WindowsDecoderError {
    UnsupportedPlatform,
    /// This unit names only the H264/H265 hardware Media Foundation
    /// categories, so VP8/VP9 stop before any presenter call, generation, MTA
    /// worker thread or hardware transform is created.
    UnsupportedCodec,
    InvalidConfig, InvalidAccessUnit, TimestampOverflow,
    Backpressure, AccessUnitExceedsQueueLimit {size:usize,limit:usize},
    Closed, EndOfStreamAlreadySubmitted, CallbackOverflow,
    Native(PresentationError), WorkerStartFailed, WorkerPanicked,
}
impl std::fmt::Display for WindowsDecoderError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {write!(f,"Windows decoder {self:?}")}
}
impl std::error::Error for WindowsDecoderError {}
impl From<PresentationError> for WindowsDecoderError {fn from(e:PresentationError)->Self{Self::Native(e)}}
impl From<WindowsDecoderError> for crate::viewer::decoder::DecoderError {
    fn from(error:WindowsDecoderError)->Self {
        match error {
            WindowsDecoderError::UnsupportedPlatform=>Self::UnsupportedPlatform,
            WindowsDecoderError::UnsupportedCodec=>Self::UnsupportedCodec,
            WindowsDecoderError::InvalidConfig=>Self::InvalidConfig,
            WindowsDecoderError::InvalidAccessUnit=>Self::InvalidAccessUnit,
            WindowsDecoderError::TimestampOverflow=>Self::TimestampOverflow,
            WindowsDecoderError::Backpressure=>Self::Backpressure,
            WindowsDecoderError::AccessUnitExceedsQueueLimit {size,limit}=>Self::AccessUnitExceedsQueueLimit {size,limit},
            WindowsDecoderError::Closed=>Self::Closed,
            WindowsDecoderError::EndOfStreamAlreadySubmitted=>Self::EndOfStreamAlreadySubmitted,
            WindowsDecoderError::CallbackOverflow=>Self::CallbackOverflow,
            WindowsDecoderError::Native(error)=>Self::WindowsNative(error),
            WindowsDecoderError::WorkerStartFailed=>Self::WorkerStartFailed,
            WindowsDecoderError::WorkerPanicked=>Self::WorkerPanicked,
        }
    }
}
#[derive(Debug)]
pub struct RejectedSubmission {pub reason:WindowsDecoderError,pub unit:AccessUnit}
#[derive(Debug,Clone)]
pub struct OpenFailure {pub error:WindowsDecoderError,pub cleanup:CleanupVerdict}
impl From<RejectedSubmission> for crate::viewer::decoder::RejectedSubmission {
    fn from(rejected:RejectedSubmission)->Self {
        Self {reason:rejected.reason.into(),unit:rejected.unit}
    }
}
impl From<OpenFailure> for crate::viewer::decoder::OpenFailure {
    fn from(failure:OpenFailure)->Self {
        Self {error:failure.error.into(),cleanup:failure.cleanup}
    }
}
/// Last observed NV12 output metadata, never a live texture/import handle.
#[derive(Debug,Clone)]
pub struct WindowsOutputMetadata {
    pub codec_generation:u64,pub output_sequence:u64,pub pts_100ns:i64,
    pub coded_width:u32,pub coded_height:u32,pub texture_width:u32,pub texture_height:u32,
    pub subresource:u32,pub aperture_present:bool,pub aperture_left:u32,pub aperture_top:u32,
    pub visible_width:u32,pub visible_height:u32,
    pub primaries:u32,pub transfer:u32,pub matrix:u32,pub nominal_range:u32,pub chroma_siting:u32,
}
#[derive(Debug,Clone,Default)]
pub struct WindowsNativeDecoderEvidence {
    pub need_input_events:u32,pub have_output_events:u32,pub stream_changes:u32,pub unknown_events:u32,
    pub event_overflow:bool,pub callbacks_in_flight:u32,pub callbacks_retired:bool,
    pub input_buffers_live:u32,pub first_native_output:bool,pub last_hresult:i32,
    pub pushed_bytes:u64,pub decoded_pictures:u64,pub non_picture_outputs:u64,
    pub texture_array_size:u32,pub texture_allocation_bytes:u64,pub last_output:Option<WindowsOutputMetadata>,
}
#[derive(Debug,Clone,Default)]
pub struct WindowsDecoderStats {
    /// Compressed AUs only; the ordered EOS control marker is never an AU.
    pub accepted_units:u64,pub pushed_units:u64,pub cancelled_units:u64,
    /// Total compressed-data admission, including worker and MFT-retained buffers.
    pub admitted_units:u64,pub admitted_bytes:u64,pub queued_units:u64,
    pub reclaimed_input_units:u64,pub native_inputs_reclaimed_during_cancel:u64,
    /// Producer-fence-complete publication, not Flutter import/scanout or FPS.
    pub published_images:u64,
    pub end_of_stream_output:bool,pub closed:bool,pub quarantined:bool,
    pub cleanup:Option<CleanupVerdict>,pub failure:Option<WindowsDecoderError>,
    pub native:WindowsNativeDecoderEvidence,
}
impl From<WindowsDecoderStats> for crate::viewer::decoder::DecoderProjection {
    fn from(stats:WindowsDecoderStats)->Self {
        Self {pushed_units:stats.pushed_units,render_submissions:stats.published_images,
            // Publication counts are real; this backend has no elapsed-time samples.
            render_timing:None,queued_units:stats.queued_units,
            // Only the worker's actual retirement verdict can confirm ownership.
            closed:stats.closed&&stats.cleanup==Some(CleanupVerdict::Confirmed),
            quarantined:stats.quarantined||stats.cleanup==Some(CleanupVerdict::Unconfirmed),
            failure:stats.failure.map(Into::into)}
    }
}
pub struct WindowsDecoder {
    #[cfg(target_os="windows")]
    shared:Arc<worker::Shared>,
    #[cfg(target_os="windows")]
    worker:Option<std::thread::JoinHandle<()>>,
    #[cfg(target_os="windows")]
    finished:std::sync::Mutex<std::sync::mpsc::Receiver<Result<WindowsDecoderStats,WindowsDecoderError>>>,
    identity:WindowsCodecCapability,
}
#[derive(Clone)]
pub struct WindowsDecoderObserver {
    #[cfg(target_os="windows")]
    shared:Arc<worker::Shared>,
}
impl WindowsDecoderObserver {
    pub fn stats(&self)->Result<WindowsDecoderStats,WindowsDecoderError> {
        #[cfg(target_os="windows")]
        {Ok(self.shared.stats())}
        #[cfg(not(target_os="windows"))]
        {Err(WindowsDecoderError::UnsupportedPlatform)}
    }
    pub fn request_close(&self) {
        #[cfg(target_os="windows")]
        self.shared.request_close();
    }
    /// Like the existing observer, this reports terminal error/Closed; it never
    /// retains or joins the native worker and carries no fictitious OHOS counts.
    pub async fn wait_stopped(&self)->Result<(),WindowsDecoderError> {
        #[cfg(target_os="windows")]
        loop {
            let changed=self.shared.changed.notified();tokio::pin!(changed);changed.as_mut().enable();
            let stats=self.shared.stats();
            if let Some(error)=stats.failure{return Err(error);}
            if stats.closed||stats.quarantined||stats.end_of_stream_output{return Err(WindowsDecoderError::Closed);}
            changed.await;
        }
        #[cfg(not(target_os="windows"))]
        {Err(WindowsDecoderError::UnsupportedPlatform)}
    }
}
impl WindowsDecoder {
    /// Blocking open/join are off UI/raster/network threads. The returned error
    /// separates the failed operation from actual partial-initialization cleanup.
    pub fn open(config:DecoderConfig,presentation:Arc<WindowsPresentation>)->Result<Self,OpenFailure> {
        // Only the two hardware categories mapped below are decodable here.
        // VP8/VP9 are refused first, so the verdict is attributable to the codec
        // alone and precedes the presenter, the generation and the MTA worker:
        // this unit has no software fallback and names no VPx MF category.
        match config.codec {
            VideoCodec::H264|VideoCodec::H265=>{}
            VideoCodec::Vp8|VideoCodec::Vp9=>return Err(OpenFailure {error:WindowsDecoderError::UnsupportedCodec,cleanup:CleanupVerdict::Confirmed}),
        }
        #[cfg(not(target_os="windows"))]
        {let _=(config,presentation);Err(OpenFailure {error:WindowsDecoderError::UnsupportedPlatform,cleanup:CleanupVerdict::Confirmed})}
        #[cfg(target_os="windows")]
        {worker::open(config,presentation)}
    }
    pub fn observer(&self)->WindowsDecoderObserver {
        WindowsDecoderObserver {#[cfg(target_os="windows")] shared:self.shared.clone()}
    }
    pub fn codec_name(&self)->Result<&str,WindowsDecoderError> {Ok(&self.identity.name)}
    pub fn capability(&self)->&WindowsCodecCapability {&self.identity}
    pub fn stats(&self)->Result<WindowsDecoderStats,WindowsDecoderError> {self.observer().stats()}
    pub fn try_submit(&self,unit:AccessUnit)->Result<(),RejectedSubmission> {
        #[cfg(target_os="windows")]
        {self.shared.submit(unit)}
        #[cfg(not(target_os="windows"))]
        {Err(RejectedSubmission {reason:WindowsDecoderError::UnsupportedPlatform,unit})}
    }
    pub async fn submit_cancellable(&self,mut unit:AccessUnit,cancel:&tokio_util::sync::CancellationToken)->Result<(),RejectedSubmission> {
        #[cfg(target_os="windows")]
        loop {
            let capacity=self.shared.changed.notified();tokio::pin!(capacity);capacity.as_mut().enable();
            if cancel.is_cancelled(){return Err(RejectedSubmission {reason:WindowsDecoderError::Closed,unit});}
            match self.try_submit(unit) {
                Ok(())=>return Ok(()),
                Err(rejected) if rejected.reason==WindowsDecoderError::Backpressure=>unit=rejected.unit,
                Err(rejected)=>return Err(rejected),
            }
            tokio::select! {biased;
                _=cancel.cancelled()=>return Err(RejectedSubmission {reason:WindowsDecoderError::Closed,unit}),
                _=&mut capacity=>{},
            }
        }
        #[cfg(not(target_os="windows"))]
        {let _=(cancel,&mut unit);self.try_submit(unit)}
    }
    pub fn request_close(&self) {self.observer().request_close();}
    pub fn close(mut self)->Result<WindowsDecoderStats,WindowsDecoderError> {self.join()}
    fn join(&mut self)->Result<WindowsDecoderStats,WindowsDecoderError> {
        #[cfg(not(target_os="windows"))]
        {Err(WindowsDecoderError::UnsupportedPlatform)}
        #[cfg(target_os="windows")]
        {
            let Some(worker)=self.worker.take() else {return Ok(self.shared.stats());};
            self.shared.request_close();
            let outcome=self.finished.get_mut().unwrap_or_else(|e|e.into_inner()).recv().map_err(|_|WindowsDecoderError::WorkerPanicked);
            let stats=self.shared.stats();
            if stats.quarantined {
                // The graph, callback userdata, producer and creating MTA remain
                // on the parked worker. Joining it would pretend close can finish.
                drop(worker);
            } else if worker.join().is_err() {
                return Err(WindowsDecoderError::WorkerPanicked);
            }
            outcome?
        }
    }
}
impl Drop for WindowsDecoder {fn drop(&mut self){let _=self.join();}}

#[cfg(target_os="windows")]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    fn check() {assert_send_sync::<WindowsDecoder>();}
};

#[cfg(target_os="windows")]
mod worker {
    use super::*;
    use crate::windows_presentation::{ffi,Producer};
    use std::collections::VecDeque;
    use std::ffi::c_void;
    use std::sync::{Mutex,OnceLock};
    use std::sync::atomic::{AtomicBool,AtomicU64,Ordering};
    use tokio::sync::Notify;
    enum QueuedInput {AccessUnit(AccessUnit),EndOfStream}
    struct State {
        queue:VecDeque<QueuedInput>,stats:WindowsDecoderStats,
        eos_queued:bool,
    }
    pub(super) struct Shared {
        state:Mutex<State>,worker:OnceLock<std::thread::Thread>,pub(super) changed:Notify,
        closing:AtomicBool,revision:AtomicU64,
        max_units:usize,max_bytes:usize,
    }
    impl Shared {
        fn wake_worker(&self) {
            self.revision.fetch_add(1,Ordering::Release);
            if let Some(worker)=self.worker.get(){worker.unpark();}
        }
        fn signal(&self) {
            self.wake_worker();self.changed.notify_waiters();
        }
        pub(super) fn stats(&self)->WindowsDecoderStats {self.state.lock().unwrap_or_else(|e|e.into_inner()).stats.clone()}
        pub(super) fn request_close(&self) {
            self.closing.store(true,Ordering::Release);
            self.signal();
        }
        pub(super) fn submit(&self,unit:AccessUnit)->Result<(),RejectedSubmission> {
            let reject=|reason,unit|Err(RejectedSubmission {reason,unit});
            let eos=matches!(unit.kind,AccessUnitKind::EndOfStream);
            if (eos&&!unit.bytes.is_empty())||(!eos&&(unit.bytes.is_empty()||
                !(unit.bytes.starts_with(&[0,0,1])||unit.bytes.starts_with(&[0,0,0,1])))) {
                return reject(WindowsDecoderError::InvalidAccessUnit,unit);
            }
            if unit.pts_us.checked_mul(10).is_none(){return reject(WindowsDecoderError::TimestampOverflow,unit);}
            if unit.bytes.len()>self.max_bytes {
                return reject(WindowsDecoderError::AccessUnitExceedsQueueLimit {size:unit.bytes.len(),limit:self.max_bytes},unit);
            }
            let mut s=self.state.lock().unwrap_or_else(|e|e.into_inner());
            if let Some(error)=s.stats.failure.clone(){return reject(error,unit);}
            if self.closing.load(Ordering::Acquire)||s.stats.closed||s.stats.quarantined{return reject(WindowsDecoderError::Closed,unit);}
            if s.eos_queued{return reject(WindowsDecoderError::EndOfStreamAlreadySubmitted,unit);}
            if eos {
                // Drain must remain admissible even when the MFT retains every
                // data lease until drain. This sticky fence admits one marker.
                s.eos_queued=true;s.queue.push_back(QueuedInput::EndOfStream);
            } else {
                if s.stats.admitted_units>=self.max_units as u64||s.stats.admitted_bytes+unit.bytes.len() as u64>self.max_bytes as u64 {
                    return reject(WindowsDecoderError::Backpressure,unit);
                }
                s.stats.accepted_units+=1;s.stats.admitted_units+=1;
                s.stats.admitted_bytes+=unit.bytes.len() as u64;s.stats.queued_units+=1;
                s.queue.push_back(QueuedInput::AccessUnit(unit));
            }
            drop(s);self.wake_worker();
            if eos {self.changed.notify_waiters();}
            Ok(())
        }
        fn pop_input(&self)->Option<QueuedInput> {
            let mut s=self.state.lock().unwrap_or_else(|e|e.into_inner());
            let input=s.queue.pop_front();
            if matches!(input,Some(QueuedInput::AccessUnit(_))){s.stats.queued_units-=1;}
            input
        }
        fn cancel_queued(&self) {
            while let Some(input)=self.pop_input() {
                if let QueuedInput::AccessUnit(unit)=input {
                    let size=unit.bytes.len();drop(unit);self.reclaimed(size,false);
                }
            }
        }
        fn reclaimed(&self,size:usize,native:bool) {
            {
                let mut s=self.state.lock().unwrap_or_else(|e|e.into_inner());
                s.stats.admitted_units-=1;s.stats.admitted_bytes-=size as u64;
                if native {s.stats.reclaimed_input_units+=1;if self.closing.load(Ordering::Acquire){s.stats.native_inputs_reclaimed_during_cancel+=1;}}
                else {s.stats.cancelled_units+=1;}
            }
            self.signal();
        }
        fn update_native(&self,n:ffi::DecoderStats) {
            let mut s=self.state.lock().unwrap_or_else(|e|e.into_inner());
            s.stats.pushed_units=n.pushed_units;
            s.stats.native=WindowsNativeDecoderEvidence {need_input_events:n.need_input_events,have_output_events:n.have_output_events,
                stream_changes:n.stream_changes,unknown_events:n.unknown_events,event_overflow:n.event_overflow!=0,
                callbacks_in_flight:n.callback_in_flight,callbacks_retired:n.callbacks_retired!=0,input_buffers_live:n.input_buffers_live,
                first_native_output:n.native_output_seen!=0,last_hresult:n.last_hresult,pushed_bytes:n.pushed_bytes,
                decoded_pictures:n.decoded_pictures,non_picture_outputs:n.non_picture_outputs,
                texture_array_size:n.texture_array_size,texture_allocation_bytes:n.texture_allocation_bytes,
                last_output:(n.native_output_seen!=0).then(||WindowsOutputMetadata {
                    codec_generation:n.last_output.codec_generation,output_sequence:n.last_output.output_sequence,pts_100ns:n.last_output.pts_100ns,
                    coded_width:n.last_output.coded_width,coded_height:n.last_output.coded_height,
                    texture_width:n.last_output.texture_width,texture_height:n.last_output.texture_height,subresource:n.last_output.subresource,
                    aperture_present:n.last_output.aperture_present!=0,aperture_left:n.last_output.aperture_left,aperture_top:n.last_output.aperture_top,
                    visible_width:n.last_output.visible_width,visible_height:n.last_output.visible_height,
                    primaries:n.last_output.primaries,transfer:n.last_output.transfer,matrix:n.last_output.matrix,
                    nominal_range:n.last_output.nominal_range,chroma_siting:n.last_output.chroma_siting,
                })};
        }
    }
    struct InputLease {unit:AccessUnit,shared:Arc<Shared>}
    unsafe extern "C" fn release_input(context:*mut c_void) {
        let lease=unsafe {Box::from_raw(context.cast::<InputLease>())};
        let size=lease.unit.bytes.len();let shared=lease.shared.clone();
        drop(lease);shared.reclaimed(size,true);
    }
    unsafe extern "C" fn event(context:*mut c_void,kind:u32,hresult:i32) {
        let shared=unsafe {&*context.cast::<Shared>()};
        if kind==5 {
            let mut s=shared.state.lock().unwrap_or_else(|e|e.into_inner());
            if s.stats.failure.is_none() {
                s.stats.failure=Some(WindowsDecoderError::Native(PresentationError {status:PresentationStatus::NativeFailure,stage:3,hresult}));
            }
        }
        shared.signal();
    }
    fn native_stats(raw:*mut c_void,shared:&Shared)->Result<ffi::DecoderStats,WindowsDecoderError> {
        let mut stats=ffi::DecoderStats::new();let mut e=ffi::Error::new();
        ffi::checked(unsafe {ffi::rd_wd_decoder_snapshot(raw,&mut stats,&mut e)},e)?;
        shared.update_native(stats);Ok(stats)
    }
    fn fail(error:WindowsDecoderError,cleanup:CleanupVerdict)->OpenFailure {OpenFailure {error,cleanup}}
    pub(super) fn open(config:DecoderConfig,presentation:Arc<WindowsPresentation>)->Result<WindowsDecoder,OpenFailure> {
        if config.width<=0||config.height<=0||config.width>16384||config.height>16384||
            u64::from(config.width as u32)*u64::from(config.height as u32)*4>512*1024*1024||
            config.max_queued_units==0||config.max_queued_units>2||config.max_queued_bytes==0||config.max_queued_bytes>32*1024*1024 {
            return Err(fail(WindowsDecoderError::InvalidConfig,CleanupVerdict::Confirmed));
        }
        let shared=Arc::new(Shared {state:Mutex::new(State {queue:VecDeque::with_capacity(config.max_queued_units+1),
            stats:WindowsDecoderStats::default(),eos_queued:false}),worker:OnceLock::new(),changed:Notify::new(),
            closing:AtomicBool::new(false),revision:AtomicU64::new(0),
            max_units:config.max_queued_units,max_bytes:config.max_queued_bytes});
        let weak=Arc::downgrade(&shared);
        let producer=presentation.begin_producer(Some(Arc::new(move ||{if let Some(shared)=weak.upgrade(){shared.signal();}})))
            .map_err(|e|fail(e.into(),CleanupVerdict::Confirmed))?;
        let (opened_tx,opened_rx)=std::sync::mpsc::sync_channel(1);
        let (finished_tx,finished_rx)=std::sync::mpsc::sync_channel(1);
        let state=shared.clone();
        // Keep the producer recoverable when OS thread creation fails.
        let handoff=Arc::new(Mutex::new(Some(producer)));let thread_handoff=handoff.clone();
        let worker=std::thread::Builder::new().name("windows-mf-decoder".into()).spawn(move || {
            let producer=thread_handoff.lock().unwrap_or_else(|e|e.into_inner()).take();
            if let Some(producer)=producer {
                let retained_owner=producer.owner.clone();let retained_state=state.clone();
                let failed_open=opened_tx.clone();let failed_close=finished_tx.clone();
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(||run(config,state,producer,opened_tx,finished_tx))).is_err() {
                    retained_owner.retain_uncertain();
                    {
                        let mut s=retained_state.state.lock().unwrap_or_else(|e|e.into_inner());
                        s.stats.failure=Some(WindowsDecoderError::WorkerPanicked);s.stats.quarantined=true;
                        s.stats.cleanup=Some(CleanupVerdict::Unconfirmed);
                    }
                    retained_state.request_close();
                    let _=failed_open.send(Err(fail(WindowsDecoderError::WorkerPanicked,CleanupVerdict::Unconfirmed)));
                    let _=failed_close.send(Err(WindowsDecoderError::WorkerPanicked));
                    // A panic does not prove native callbacks or COM retired.
                    // Keep their userdata, presentation and MTA on this thread.
                    loop {std::thread::park();}
                }
            }
        });
        let worker=match worker {
            Ok(worker)=>worker,
            Err(_)=>{
                let cleanup=match handoff.lock().unwrap_or_else(|e|e.into_inner()).take() {
                    Some(mut producer)=>if producer.retire().is_ok(){CleanupVerdict::Confirmed}else{CleanupVerdict::Unconfirmed},
                    None=>CleanupVerdict::Unconfirmed,
                };
                return Err(fail(WindowsDecoderError::WorkerStartFailed,cleanup));
            }
        };
        match opened_rx.recv() {
            Ok(Ok(identity))=>Ok(WindowsDecoder {shared,worker:Some(worker),finished:Mutex::new(finished_rx),identity}),
            Ok(Err(failure))=>{
                if failure.cleanup==CleanupVerdict::Confirmed {let _=worker.join();}else{drop(worker);}
                Err(failure)
            }
            Err(_)=>{drop(worker);Err(fail(WindowsDecoderError::WorkerPanicked,CleanupVerdict::Unconfirmed))}
        }
    }
    fn run(config:DecoderConfig,shared:Arc<Shared>,mut producer:Producer,
           opened:std::sync::mpsc::SyncSender<Result<WindowsCodecCapability,OpenFailure>>,
           finished:std::sync::mpsc::SyncSender<Result<WindowsDecoderStats,WindowsDecoderError>>) {
        // Install the existing worker's persistent unpark token before native
        // callbacks can target it. Earlier close intent remains in the atomics.
        shared.worker.get_or_init(std::thread::current);
        let mut raw=std::ptr::null_mut();let mut report=ffi::OpenReport::new();
        let open=producer.owner.native_call(false,|p| {
            let options=ffi::DecoderOptions {struct_size:std::mem::size_of::<ffi::DecoderOptions>() as u32,
                codec:match config.codec {
                    VideoCodec::H264=>1,VideoCodec::H265=>2,
                    // open() refuses VP8/VP9 first: no fallback MF category,
                    // transform attribute or decoder MIME is mapped for a codec
                    // this unit cannot decode, so the native id is never guessed.
                    VideoCodec::Vp8|VideoCodec::Vp9=>return Err(PresentationError::plain(PresentationStatus::UnsupportedFormat,1)),
                },max_width:config.width as u32,max_height:config.height as u32,
                generation:producer.generation,presenter:p,wake:Some(event),wake_context:Arc::as_ptr(&shared).cast_mut().cast()};
            let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_decoder_open(&options,&mut raw,&mut report,&mut e)},e)
        });
        if let Err(error)=open {
            let cleanup=if report.cleanup==1&&raw.is_null()&&producer.retire().is_ok(){CleanupVerdict::Confirmed}else{CleanupVerdict::Unconfirmed};
            let _=opened.send(Err(fail(error.into(),cleanup)));
            if cleanup==CleanupVerdict::Unconfirmed {loop{std::thread::park();}}
            return;
        }
        if raw.is_null() {
            let _=opened.send(Err(fail(PresentationError::plain(PresentationStatus::ReclamationUnconfirmed,2).into(),CleanupVerdict::Unconfirmed)));
            loop{std::thread::park();}
        }
        let _=opened.send(Ok(report.identity.into()));
        let mut next:Option<Box<InputLease>>=None;
        let mut picture:Option<ffi::DecodedFrame>=None;
        let mut draining=false;let mut normal_eos=false;
        let operation=(||->Result<(),WindowsDecoderError> {
            loop {
                // Snapshot before SDK calls. A real callback changes revision;
                // unpark retains its token across the later check-to-park gap.
                let revision=shared.revision.load(Ordering::Acquire);
                {
                    let s=shared.state.lock().unwrap_or_else(|e|e.into_inner());
                    if shared.closing.load(Ordering::Acquire)||producer.owner.is_closing(){break;}
                    if let Some(error)=s.stats.failure.clone(){return Err(error);}
                }
                let mut progress=false;
                if picture.is_none() {
                    let mut frame=ffi::DecodedFrame::new();let mut kind=0;let mut e=ffi::Error::new();
                    let status=unsafe {ffi::rd_wd_decoder_output(raw,&mut frame,&mut kind,&mut e)};
                    if status==0 {progress=true;if kind==1{picture=Some(frame);}}
                    else if status!=1 {return Err(PresentationError::native(status,e).into());}
                }
                if let Some(frame)=picture.as_ref() {
                    let publish=producer.owner.native_call(false,|p| {let mut e=ffi::Error::new();ffi::checked(unsafe {ffi::rd_wd_presenter_publish(p,frame,&mut e)},e)});
                    match publish {
                        Ok(())=>{
                            unsafe {ffi::rd_wd_decoder_release_output(raw,frame);}
                            picture=None;progress=true;
                            shared.state.lock().unwrap_or_else(|e|e.into_inner()).stats.published_images+=1;
                        }
                        Err(e) if e.status==PresentationStatus::WouldBlock||e.status==PresentationStatus::Busy=>{},
                        Err(e) if e.status==PresentationStatus::Closing=>break,
                        Err(e)=>return Err(e.into()),
                    }
                }
                let stats=native_stats(raw,&shared)?;
                if stats.event_overflow!=0 {return Err(WindowsDecoderError::CallbackOverflow);}
                if stats.last_hresult<0 {return Err(PresentationError {status:PresentationStatus::NativeFailure,stage:3,hresult:stats.last_hresult}.into());}
                if draining&&stats.drain_complete!=0&&picture.is_none() {
                    // DrainComplete is sent after the last HaveOutput event, but
                    // callback delivery can run ahead of worker servicing. Check
                    // one more event-driven output attempt before declaring EOS.
                    let mut frame=ffi::DecodedFrame::new();let mut kind=0;let mut e=ffi::Error::new();
                    let status=unsafe {ffi::rd_wd_decoder_output(raw,&mut frame,&mut kind,&mut e)};
                    if status==1 {normal_eos=true;break;}
                    if status!=0 {return Err(PresentationError::native(status,e).into());}
                    if kind==1 {picture=Some(frame);}
                    continue;
                }
                if picture.is_none()&&!draining {
                    if next.is_none() {
                        match shared.pop_input() {
                            Some(QueuedInput::AccessUnit(unit))=>next=Some(Box::new(InputLease {unit,shared:shared.clone()})),
                            Some(QueuedInput::EndOfStream)=>{
                                // All accepted AUs precede this marker, but their
                                // native leases need not be released to start drain.
                                let mut e=ffi::Error::new();
                                let status=unsafe {ffi::rd_wd_decoder_drain(raw,&mut e)};
                                if status!=0 {return Err(PresentationError::native(status,e).into());}
                                draining=true;progress=true;
                            }
                            None=>{},
                        }
                    }
                    if let Some(mut lease)=next.take() {
                        let flags=match lease.unit.kind {AccessUnitKind::CodecConfig=>4,AccessUnitKind::Frame {key:true}=>1,_=>0};
                        let pts=lease.unit.pts_us.checked_mul(10).ok_or(WindowsDecoderError::TimestampOverflow)?;
                        let data=lease.unit.bytes.as_mut_ptr();let size=lease.unit.bytes.len();
                        let pointer=Box::into_raw(lease);let mut e=ffi::Error::new();
                        let status=unsafe {ffi::rd_wd_decoder_input(raw,data.cast(),size,pts,flags,release_input,pointer.cast(),&mut e)};
                        if status==0 {progress=true;}
                        else {
                            next=Some(unsafe {Box::from_raw(pointer)});
                            if status!=1{return Err(PresentationError::native(status,e).into());}
                        }
                    }
                }
                if !progress {
                    while shared.revision.load(Ordering::Acquire)==revision&&!shared.closing.load(Ordering::Acquire)&&!producer.owner.is_closing() {
                        // Spurious wakes or an old token do not retry native work.
                        std::thread::park();
                    }
                }
            }
            Ok(())
        })();
        // Cancellation reclaims queue ownership outside the admission mutex.
        // Normal EOS never flushes, drops reference frames or invents a picture.
        if !normal_eos {shared.request_close();}
        if let Some(lease)=next.take(){let size=lease.unit.bytes.len();drop(lease);shared.reclaimed(size,false);}
        shared.cancel_queued();
        if let Some(frame)=picture.take(){unsafe {ffi::rd_wd_decoder_release_output(raw,&frame);}}
        let mut failure=operation.err();
        if !normal_eos {
            let mut e=ffi::Error::new();let status=unsafe {ffi::rd_wd_decoder_flush(raw,&mut e)};
            if status!=0&&failure.is_none(){failure=Some(PresentationError::native(status,e).into());}
        }
        if let Err(error)=native_stats(raw,&shared){if failure.is_none(){failure=Some(error);}}
        let mut e=ffi::Error::new();let status=unsafe {ffi::rd_wd_decoder_close(raw,&mut e)};
        let mut cleanup=if status==0{CleanupVerdict::Confirmed}else{CleanupVerdict::Unconfirmed};
        if status!=0 {failure=Some(PresentationError::native(status,e).into());}
        if cleanup==CleanupVerdict::Confirmed {
            if let Err(error)=producer.retire(){failure=Some(error.into());cleanup=CleanupVerdict::Unconfirmed;}
        }
        {
            let mut s=shared.state.lock().unwrap_or_else(|e|e.into_inner());
            s.stats.cleanup=Some(cleanup);s.stats.closed=cleanup==CleanupVerdict::Confirmed;s.stats.quarantined=cleanup==CleanupVerdict::Unconfirmed;
            s.stats.end_of_stream_output=normal_eos;s.stats.failure=failure.clone();
            if cleanup==CleanupVerdict::Confirmed {s.stats.native.callbacks_retired=true;s.stats.native.callbacks_in_flight=0;s.stats.native.input_buffers_live=0;}
        }
        shared.signal();
        let outcome=if let Some(error)=failure {Err(error)}else{Ok(shared.stats())};
        let _=finished.send(outcome);
        if cleanup==CleanupVerdict::Unconfirmed {
            // Retain producer, shared callback context, MF graph and its MTA.
            // Owner bounds + process quarantine forbid unbounded reconnection.
            loop{std::thread::park();}
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn shared(max_units:usize)->Arc<Shared> {
            Arc::new(Shared {state:Mutex::new(State {queue:VecDeque::with_capacity(max_units+1),
                stats:WindowsDecoderStats::default(),eos_queued:false}),
                worker:OnceLock::new(),changed:Notify::new(),closing:AtomicBool::new(false),revision:AtomicU64::new(0),
                max_units,max_bytes:max_units*4})
        }

        #[test]
        fn close_intent_and_signal_do_not_wait_for_admission_lock() {
            let shared=shared(1);
            let held=shared.state.lock().unwrap_or_else(|e|e.into_inner());
            let (completed_tx,completed_rx)=std::sync::mpsc::channel();
            let closing=shared.clone();
            let notifier=std::thread::spawn(move || {
                closing.signal();closing.request_close();completed_tx.send(()).unwrap();
            });
            let completed=completed_rx.recv_timeout(std::time::Duration::from_secs(5));
            // Release the deliberately contended lock even on regression so the
            // notifier can exit; the deadline is only a bounded failure guard.
            drop(held);notifier.join().unwrap();
            assert!(completed.is_ok(),"close/wake waited for the admission mutex");
            assert_eq!(shared.submit(packet(1)).unwrap_err().reason,WindowsDecoderError::Closed);
        }

        fn packet(sequence:usize)->AccessUnit {
            AccessUnit {bytes:vec![0,0,1,sequence as u8],pts_us:sequence as i64,kind:AccessUnitKind::Frame {key:false}}
        }
        fn eos()->AccessUnit {
            AccessUnit {bytes:Vec::new(),pts_us:0,kind:AccessUnitKind::EndOfStream}
        }
        fn take_lease(shared:&Arc<Shared>,sequence:usize)->Box<InputLease> {
            let Some(QueuedInput::AccessUnit(unit))=shared.pop_input() else {panic!("data must precede EOS");};
            assert_eq!(unit.pts_us,sequence as i64);
            Box::new(InputLease {unit,shared:shared.clone()})
        }

        #[test]
        fn eos_is_ordered_outside_retained_input_quota() {
            for max_units in [1,2] {
                // Exercise both a full FIFO and native ownership of every AU.
                // No NeedInput event or release callback occurs before EOS.
                for retained_before_eos in [0,max_units] {
                    let shared=shared(max_units);
                    for sequence in 1..=max_units {shared.submit(packet(sequence)).unwrap();}
                    assert_eq!(shared.submit(packet(3)).unwrap_err().reason,WindowsDecoderError::Backpressure);
                    let mut retained=Vec::with_capacity(max_units);
                    for sequence in 1..=retained_before_eos {retained.push(take_lease(&shared,sequence));}

                    shared.submit(eos()).unwrap();
                    assert_eq!(shared.submit(eos()).unwrap_err().reason,WindowsDecoderError::EndOfStreamAlreadySubmitted);
                    assert_eq!(shared.submit(packet(3)).unwrap_err().reason,WindowsDecoderError::EndOfStreamAlreadySubmitted);
                    let stats=shared.stats();
                    assert_eq!((stats.accepted_units,stats.admitted_units,stats.admitted_bytes,stats.queued_units),
                        (max_units as u64,max_units as u64,(max_units*4) as u64,(max_units-retained_before_eos) as u64));

                    for sequence in retained_before_eos+1..=max_units {retained.push(take_lease(&shared,sequence));}
                    // This is the worker's drain action; native leases still own
                    // all data and have not returned any admission capacity.
                    assert!(matches!(shared.pop_input(),Some(QueuedInput::EndOfStream)));
                    assert!(shared.pop_input().is_none());
                    let stats=shared.stats();
                    assert_eq!((stats.admitted_units,stats.admitted_bytes,stats.queued_units,stats.cancelled_units,stats.reclaimed_input_units),
                        (max_units as u64,(max_units*4) as u64,0,0,0));
                    assert_eq!(shared.submit(eos()).unwrap_err().reason,WindowsDecoderError::EndOfStreamAlreadySubmitted);
                    assert_eq!(shared.submit(packet(3)).unwrap_err().reason,WindowsDecoderError::EndOfStreamAlreadySubmitted);

                    for (index,lease) in retained.into_iter().enumerate() {
                        unsafe {release_input(Box::into_raw(lease).cast());}
                        let remaining=(max_units-index-1) as u64;
                        let stats=shared.stats();
                        assert_eq!((stats.admitted_units,stats.admitted_bytes,stats.reclaimed_input_units,stats.cancelled_units),
                            (remaining,remaining*4,(index+1) as u64,0));
                    }
                }
            }
        }

        #[test]
        fn cancelling_eos_reclaims_only_compressed_inputs_once() {
            for native_retained in 0..=2 {
                let shared=shared(2);
                shared.submit(packet(1)).unwrap();shared.submit(packet(2)).unwrap();shared.submit(eos()).unwrap();
                let retained=(1..=native_retained).map(|sequence|take_lease(&shared,sequence)).collect::<Vec<_>>();
                shared.request_close();shared.cancel_queued();shared.cancel_queued();
                assert!(shared.pop_input().is_none());
                let stats=shared.stats();
                assert_eq!((stats.accepted_units,stats.cancelled_units,stats.admitted_units,stats.admitted_bytes,stats.queued_units),
                    (2,(2-native_retained) as u64,native_retained as u64,(native_retained*4) as u64,0));
                assert_eq!((stats.reclaimed_input_units,stats.native_inputs_reclaimed_during_cancel),(0,0));
                assert_eq!(shared.submit(eos()).unwrap_err().reason,WindowsDecoderError::Closed);
                assert_eq!(shared.submit(packet(3)).unwrap_err().reason,WindowsDecoderError::Closed);
                for lease in retained {unsafe {release_input(Box::into_raw(lease).cast());}}
                let stats=shared.stats();
                assert_eq!((stats.admitted_units,stats.admitted_bytes),(0,0));
                assert_eq!((stats.reclaimed_input_units,stats.native_inputs_reclaimed_during_cancel),
                    (native_retained as u64,native_retained as u64));
                assert_eq!(stats.accepted_units,stats.cancelled_units+stats.reclaimed_input_units);
            }
        }

    }
}
