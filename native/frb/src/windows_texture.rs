//! Native-only texture ownership boundary. GPU handles never enter Dart/FRB.
//! The engine owns decoding, publication and reclamation; this module only owns
//! opaque process tokens, validates the native C ABI and forwards real results.
//! The official client's renderer-pointer submission is a different interface:
//! this token/loan ABI never carries the client's renderer pointer and
//! `RdWinTextureFrame` must not grow a COM/texture field. That submission is the
//! separate `WindowsPresentation::publish_gpu` export.

use rd_engine::windows_presentation::{AdapterLuid, PresentationError, WindowsPresentation};
use std::{
    collections::HashMap,
    ffi::c_void,
    mem::size_of,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
};

const OK: i32 = 0;
const INVALID_TOKEN: i32 = 9;
const INVALID_ARGUMENT: i32 = 10;
const NATIVE_FAILURE: i32 = 11;
const OWNER_LIMIT: i32 = 13;
const STAGE_VALIDATE: u32 = 1;
const MAX_OWNERS: usize = 4;

#[repr(C)]
struct TextureCreate {
    struct_size: u32,
    adapter_luid_low: u32,
    adapter_luid_high: i32,
    reserved: u32,
    wake: Option<unsafe extern "C" fn(*mut c_void, u64, u32)>,
    context: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TextureError {
    struct_size: u32,
    stage: u32,
    native_hresult: i32,
    reserved: u32,
}

impl TextureError {
    fn empty() -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            stage: 0,
            native_hresult: 0,
            reserved: 0,
        }
    }
}

#[repr(C)]
struct TextureFrame {
    struct_size: u32,
    pixel_format: u32,
    codec_generation: u64,
    frame_sequence: u64,
    pts_100ns: i64,
    width: u32,
    height: u32,
    visible_width: u32,
    visible_height: u32,
    shared_handle: *mut c_void,
    loan_id: u64,
}

const _: () = {
    assert!(size_of::<TextureCreate>() == 32);
    assert!(size_of::<TextureError>() == 16);
    assert!(size_of::<TextureFrame>() == 64);
};

struct Failure {
    status: i32,
    error: TextureError,
}

impl Failure {
    fn argument(status: i32) -> Self {
        Self {
            status,
            error: TextureError {
                stage: STAGE_VALIDATE,
                ..TextureError::empty()
            },
        }
    }
}

impl From<PresentationError> for Failure {
    fn from(error: PresentationError) -> Self {
        Self {
            status: error.status as i32,
            error: TextureError {
                stage: error.stage,
                native_hresult: error.hresult,
                ..TextureError::empty()
            },
        }
    }
}

struct WakeSink {
    callback: unsafe extern "C" fn(*mut c_void, u64, u32),
    context: *mut c_void,
    token: u64,
    enabled: AtomicBool,
}

// SAFETY: the C ABI explicitly requires a thread-safe callback/context retained
// by the caller through successful disposal. Only the engine invokes it, and
// the engine's successful close guarantees that no callback remains or starts.
unsafe impl Send for WakeSink {}
unsafe impl Sync for WakeSink {}

impl WakeSink {
    fn notify(&self, reasons: u32) {
        if self.enabled.load(Ordering::Acquire) {
            // SAFETY: see the caller-owned lifetime contract above. No pointer
            // or native handle is exposed to Dart by this callback.
            unsafe { (self.callback)(self.context, self.token, reasons) };
        }
    }
}

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static OWNER_SLOTS: AtomicUsize = AtomicUsize::new(0);
static OWNERS: LazyLock<Mutex<HashMap<u64, Arc<Owner>>>> =
    LazyLock::new(|| Mutex::new(HashMap::with_capacity(MAX_OWNERS)));

struct OwnerSlot;

impl OwnerSlot {
    fn reserve() -> Result<Self, Failure> {
        OWNER_SLOTS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_OWNERS).then_some(count + 1)
            })
            .map_err(|_| Failure::argument(OWNER_LIMIT))?;
        Ok(Self)
    }
}

impl Drop for OwnerSlot {
    fn drop(&mut self) {
        OWNER_SLOTS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Owner {
    presentation: Arc<WindowsPresentation>,
    wake: Arc<WakeSink>,
    _slot: OwnerSlot,
}

fn owner(token: u64) -> Result<Arc<Owner>, Failure> {
    let owner = OWNERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&token)
        .cloned()
        .ok_or_else(|| Failure::argument(INVALID_TOKEN))?;
    // Creation cannot produce frames or an unregister request: neither a session
    // nor close has started. Arm callbacks only on a post-create operation, so
    // caller callbacks never race the return of create. Do not synthesize wakes
    // here: the engine remains the sole counted callback source.
    owner.wake.enabled.store(true, Ordering::Release);
    Ok(owner)
}

/// Bind the actual presentation to one session epoch, not an OHOS surface alias.
/// This is the only native-token lookup needed by the product session bridge.
pub(crate) fn bind_presentation(
    token: u64,
    epoch: u64,
) -> anyhow::Result<Arc<WindowsPresentation>> {
    let owner = owner(token).map_err(|failure| {
        anyhow::anyhow!(
            "Native presentation unavailable (status {}, stage {}, HRESULT {:#x})",
            failure.status,
            failure.error.stage,
            failure.error.native_hresult as u32,
        )
    })?;
    owner.presentation.bind_session(epoch).map_err(|error| {
        anyhow::anyhow!(
            "Native presentation binding failed (status {}, stage {}, HRESULT {:#x})",
            error.status as i32,
            error.stage,
            error.hresult as u32,
        )
    })?;
    Ok(owner.presentation.clone())
}

fn valid_pointer<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}

unsafe fn boundary(error: *mut TextureError, action: impl FnOnce() -> Result<(), Failure>) -> i32 {
    if !valid_pointer(error) {
        return INVALID_ARGUMENT;
    }
    // SAFETY: all non-null C pointers are required to name a complete live ABI
    // object; struct_size is a version check, not permission to pass short memory.
    let valid_size = unsafe { (*error).struct_size == size_of::<TextureError>() as u32 };
    unsafe { ptr::write(error, TextureError::empty()) };
    let result = if valid_size {
        catch_unwind(AssertUnwindSafe(action)).unwrap_or_else(|_| {
            Err(Failure {
                status: NATIVE_FAILURE,
                error: TextureError::empty(),
            })
        })
    } else {
        Err(Failure::argument(INVALID_ARGUMENT))
    };
    match result {
        Ok(()) => OK,
        Err(failure) => {
            unsafe { ptr::write(error, failure.error) };
            failure.status
        }
    }
}

#[no_mangle]
unsafe extern "C" fn rd_engine_windows_texture_create(
    options: *const TextureCreate,
    token: *mut u64,
    error: *mut TextureError,
) -> i32 {
    unsafe {
        boundary(error, || {
            if !valid_pointer(options) || !valid_pointer(token) {
                return Err(Failure::argument(INVALID_ARGUMENT));
            }
            ptr::write(token, 0);
            let options = &*options;
            if options.struct_size != size_of::<TextureCreate>() as u32 || options.reserved != 0 {
                return Err(Failure::argument(INVALID_ARGUMENT));
            }
            let callback = options
                .wake
                .ok_or_else(|| Failure::argument(INVALID_ARGUMENT))?;
            let slot = OwnerSlot::reserve()?;
            let id = NEXT_TOKEN
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| Failure::argument(OWNER_LIMIT))?;
            let wake = Arc::new(WakeSink {
                callback,
                context: options.context,
                token: id,
                enabled: AtomicBool::new(false),
            });
            let notification = wake.clone();
            let presentation = WindowsPresentation::create(
                AdapterLuid {
                    low_part: options.adapter_luid_low,
                    high_part: options.adapter_luid_high,
                },
                Arc::new(move |reasons| notification.notify(reasons)),
            )?;
            let owner = Arc::new(Owner {
                presentation,
                wake,
                _slot: slot,
            });
            OWNERS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(id, owner);
            ptr::write(token, id);
            Ok(())
        })
    }
}

#[no_mangle]
unsafe extern "C" fn rd_engine_windows_texture_acquire(
    token: u64,
    frame: *mut TextureFrame,
    error: *mut TextureError,
) -> i32 {
    unsafe {
        boundary(error, || {
            if !valid_pointer(frame) || (*frame).struct_size != size_of::<TextureFrame>() as u32 {
                return Err(Failure::argument(INVALID_ARGUMENT));
            }
            let owner = owner(token)?;
            let imported = owner.presentation.acquire_import_loan()?;
            ptr::write(
                frame,
                TextureFrame {
                    struct_size: size_of::<TextureFrame>() as u32,
                    pixel_format: imported.pixel_format,
                    codec_generation: imported.codec_generation,
                    frame_sequence: imported.frame_sequence,
                    pts_100ns: imported.pts_100ns,
                    width: imported.width,
                    height: imported.height,
                    visible_width: imported.visible_width,
                    visible_height: imported.visible_height,
                    shared_handle: imported.shared_handle,
                    loan_id: imported.loan_id,
                },
            );
            Ok(())
        })
    }
}

#[no_mangle]
unsafe extern "C" fn rd_engine_windows_texture_release(
    token: u64,
    loan_id: u64,
    error: *mut TextureError,
) -> i32 {
    unsafe {
        boundary(error, || {
            owner(token)?.presentation.release_import_loan(loan_id)?;
            Ok(())
        })
    }
}

#[no_mangle]
unsafe extern "C" fn rd_engine_windows_texture_request_close(
    token: u64,
    error: *mut TextureError,
) -> i32 {
    unsafe {
        boundary(error, || {
            owner(token)?.presentation.request_close()?;
            Ok(())
        })
    }
}

#[no_mangle]
unsafe extern "C" fn rd_engine_windows_texture_registration_retired(
    token: u64,
    error: *mut TextureError,
) -> i32 {
    unsafe {
        boundary(error, || {
            owner(token)?.presentation.registration_retired()?;
            Ok(())
        })
    }
}

#[no_mangle]
unsafe extern "C" fn rd_engine_windows_texture_dispose(
    token: u64,
    error: *mut TextureError,
) -> i32 {
    unsafe {
        boundary(error, || {
            let owner = owner(token)?;
            // A busy or unconfirmed close leaves the token and callback context owned.
            owner.presentation.close()?;
            let retired = OWNERS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&token);
            drop(retired);
            Ok(())
        })
    }
}

#[no_mangle]
unsafe extern "C" fn rd_engine_windows_texture_wait_progress(
    token: u64,
    revision: *mut u64,
    flags: u32,
    error: *mut TextureError,
) -> i32 {
    unsafe {
        boundary(error, || {
            if !valid_pointer(revision) || flags > 1 {
                return Err(Failure::argument(INVALID_ARGUMENT));
            }
            // Lookup retains the owner but releases the registry lock before the
            // worker can wait. The presentation keeps no native gate across wait.
            let owner = owner(token)?;
            let mut observed = ptr::read(revision);
            let result = owner.presentation.wait_progress(&mut observed, flags == 1);
            ptr::write(revision, observed);
            result?;
            Ok(())
        })
    }
}
