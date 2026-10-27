//! Raw-pixel presentation surface for rectangles from RFB and RDP.
//!
//! The encoded path (`src/platform/ohos_decoder.rs`, declared as
//! `crate::viewer::decoder`) hands compressed access units to a hardware video
//! decoder. Rectangle protocols have no such stage: the bytes on the wire are
//! already pixels, so running them through a video decoder would be both slower
//! and lossy. This module is the other half of the presentation contract — the
//! same `SurfaceLease` ownership rule and the same quarantine discipline, but a
//! CPU-writable buffer instead of a codec.
//!
//! Two sinks implement `crate::protocol::rect::PixelTarget`: `MemorySurface`,
//! which the host build and the tests use, and `OhosSurface`, which blits into
//! the buffer queue of the HAR-owned ArkUI surface. Both report
//! `PixelLayout::bgra8888()` and own exactly one framebuffer, so a protocol
//! decoder writes surface-ready bytes and no pixel conversion exists on this
//! path. Nothing here is async and nothing here spawns a thread: `present`,
//! `resize` and `close` block on the native window — a buffer request waits
//! inside it for 3000 ms by default — so they must be called from a blocking
//! worker, never from an async task. Every window call goes through `&mut self`,
//! which is also what serializes an API the SDK documents as non-thread-safe.
//!
//! # Deliberate limits
//!
//! * Geometry is capped at [`MAX_DIMENSION`] per edge and
//!   [`MAX_FRAMEBUFFER_BYTES`] in total, so `width * height * 4` cannot overflow
//!   and a hostile `DesktopSize` cannot name a buffer the device could not back.
//!   That single peer-sized allocation is reserved fallibly, so a refused
//!   geometry is an error instead of an allocator abort.
//! * Damage is one accumulated bounding box merged with `Rect::union`, never a
//!   per-rectangle list, and merging allocates nothing.
//! * `present` drains the damage box before it blits and restores it when the
//!   blit fails, so a frame that was not shown is retried instead of lost.
//! * One native buffer may be in flight at a time; the buffer queue is exhausted
//!   otherwise. A buffer that cannot be returned during teardown is reported as
//!   `DestroyFailed` and its window and lease are retained in bounded quarantine,
//!   because the queue may still hand that buffer to the consumer.
//! * At most `MAX_OWNERS = 4` OHOS surfaces exist process-wide, open or
//!   quarantined, because each one holds a native window and a HAR lease. One
//!   quarantine latches further opens off with `LeaseInvalid` rather than
//!   leaking windows whose teardown has already failed.
//! * `OH_NativeWindow_DestroyNativeWindow` returns `void`, so a hard failure
//!   there is unobservable; the teardown failure that *can* be observed — a
//!   buffer that will not come back — is what `DestroyFailed` reports.
//! * `SurfaceError` is a frozen set with no per-call variant, so the name of a
//!   failing `native_window` call is not carried in the value: every failure to
//!   deliver a buffer is reported as `NativeBufferUnavailable`.
//! * Off-device, `open`, `present`, `resize` and `close` return
//!   `SurfaceError::UnsupportedPlatform`. `take_damage` has no error channel in
//!   the frozen API, so it reports the box the framebuffer holds, and
//!   off-device no instance exists that could hold one.

use std::sync::Arc;

use crate::{
    protocol::rect::{PixelError, PixelLayout, PixelTarget, Rect, RectBuf},
    viewer::decoder::SurfaceLease,
};

/// What every sink on this path absorbs, and therefore what RFB negotiates and
/// RDP's codecs are chosen against. The OHOS buffer format that matches it is
/// `NATIVEBUFFER_PIXEL_FMT_BGRA_8888`.
const LAYOUT: PixelLayout = PixelLayout::bgra8888();
/// Bytes per pixel in `LAYOUT`.
const BYTES_PER_PIXEL: usize = LAYOUT.bytes_per_pixel as usize;

/// Largest accepted edge of a framebuffer, in pixels.
///
/// RFB's `DesktopSize` pseudo-encoding carries 16-bit dimensions and RDP caps
/// desktops well below this, so the limit only rejects geometry no real peer
/// reports. It exists so that a stride and an allocation size can never be
/// computed from an unbounded peer value.
pub const MAX_DIMENSION: i32 = 16_384;

/// Largest accepted framebuffer, in bytes: half a gigabyte, twice an 8K desktop.
pub const MAX_FRAMEBUFFER_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceError {
    UnsupportedPlatform,
    InvalidGeometry,
    NativeBufferUnavailable,
    LeaseInvalid,
    DestroyFailed { code: i32 },
}

impl std::fmt::Display for SurfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "this platform has no OHOS native-window surface")
            }
            Self::InvalidGeometry => write!(f, "framebuffer geometry rejected"),
            Self::NativeBufferUnavailable => {
                write!(f, "the OHOS native window did not provide a usable buffer")
            }
            Self::LeaseInvalid => {
                write!(f, "the Surface lease cannot be materialized into a native window")
            }
            Self::DestroyFailed { code } => {
                write!(f, "OHOS native-window teardown failed with code {code}")
            }
        }
    }
}

impl std::error::Error for SurfaceError {}

/// A validated, allocated framebuffer that has not been committed yet.
///
/// A geometry change has to be told to the OHOS window as well as applied here,
/// so the new buffer is built first and committed only once the window accepted
/// the geometry: a rejected geometry then leaves both sides on the old one
/// rather than half-applied.
struct Prepared {
    stride: usize,
    width: i32,
    height: i32,
    pixels: Vec<u8>,
}

impl Prepared {
    fn new(width: i32, height: i32) -> Result<Self, SurfaceError> {
        if width <= 0 || height <= 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(SurfaceError::InvalidGeometry);
        }
        let stride = width as usize * BYTES_PER_PIXEL;
        let bytes = stride
            .checked_mul(height as usize)
            .filter(|bytes| *bytes <= MAX_FRAMEBUFFER_BYTES)
            .ok_or(SurfaceError::InvalidGeometry)?;
        let mut pixels = Vec::new();
        pixels
            .try_reserve_exact(bytes)
            .map_err(|_| SurfaceError::NativeBufferUnavailable)?;
        pixels.resize(bytes, 0);
        Ok(Self {
            stride,
            width,
            height,
            pixels,
        })
    }
}

/// One sink's framebuffer, its row stride and its accumulated damage.
///
/// Shared by both sinks so that the presentation rules — windowing, bounds,
/// union damage, memmove-compatible copies — exist once.
struct Framebuffer {
    pixels: Vec<u8>,
    stride: usize,
    width: i32,
    height: i32,
    damage: Option<Rect>,
}

impl Framebuffer {
    fn new(width: i32, height: i32) -> Result<Self, SurfaceError> {
        let prepared = Prepared::new(width, height)?;
        Ok(Self {
            pixels: prepared.pixels,
            stride: prepared.stride,
            width: prepared.width,
            height: prepared.height,
            damage: None,
        })
    }

    fn size(&self) -> (i32, i32) {
        (self.width, self.height)
    }

    /// True when `rect` is a non-empty window inside this framebuffer. Uses
    /// `i64` so that an extreme peer-supplied extent cannot wrap the compare.
    fn holds(&self, rect: &Rect) -> bool {
        rect.x >= 0
            && rect.y >= 0
            && i64::from(rect.x) + i64::from(rect.width) <= i64::from(self.width)
            && i64::from(rect.y) + i64::from(rect.height) <= i64::from(self.height)
    }

    fn window(&mut self, rect: Rect) -> Result<RectBuf<'_>, PixelError> {
        rect.validate()?;
        if !self.holds(&rect) {
            return Err(PixelError::OutOfBounds);
        }
        Ok(RectBuf::new(
            &mut self.pixels,
            self.stride,
            (0, 0),
            rect,
            BYTES_PER_PIXEL,
        ))
    }

    /// Merges one rectangle into the accumulated box.
    ///
    /// A rectangle that escapes the framebuffer is dropped rather than merged:
    /// `window` already refused it, so no byte of it was written, and recording
    /// it could only grow the blit region past the end of the buffer.
    fn note(&mut self, rect: Rect) {
        if rect.validate().is_err() || !self.holds(&rect) {
            return;
        }
        self.damage = Some(match self.damage {
            Some(previous) => previous.union(&rect),
            None => rect,
        });
    }

    fn take_damage(&mut self) -> Option<Rect> {
        self.damage.take()
    }

    fn copy(&mut self, dst: Rect, src_x: i32, src_y: i32) -> Result<(), PixelError> {
        dst.validate()?;
        let src = Rect::new(src_x, src_y, dst.width, dst.height);
        if !self.holds(&dst) || !self.holds(&src) {
            return Err(PixelError::OutOfBounds);
        }
        let row_bytes = dst.width as usize * BYTES_PER_PIXEL;
        // Rows are copied in the direction that cannot clobber source rows that
        // have not been read yet; `copy_within` is a memmove, so a horizontal
        // overlap inside one row is already handled. Together these give the
        // "source snapshotted first" behaviour `PixelTarget::copy_rect` owes.
        let descend = dst.y > src_y;
        for step in 0..dst.height {
            let row = if descend { dst.height - 1 - step } else { step };
            let src_start = (src_y + row) as usize * self.stride + src_x as usize * BYTES_PER_PIXEL;
            let dst_start = (dst.y + row) as usize * self.stride + dst.x as usize * BYTES_PER_PIXEL;
            let (Some(src_end), Some(dst_end)) = (
                src_start.checked_add(row_bytes),
                dst_start.checked_add(row_bytes),
            ) else {
                return Err(PixelError::OutOfBounds);
            };
            if src_end > self.pixels.len() || dst_end > self.pixels.len() {
                return Err(PixelError::OutOfBounds);
            }
            self.pixels.copy_within(src_start..src_end, dst_start);
        }
        self.note(dst);
        Ok(())
    }

    fn install(&mut self, prepared: Prepared) {
        self.pixels = prepared.pixels;
        self.stride = prepared.stride;
        self.width = prepared.width;
        self.height = prepared.height;
        // A resize repaints everything. The old box could name pixels outside
        // the new geometry, so it is dropped instead of carried over.
        self.damage = None;
    }

    fn resize(&mut self, width: i32, height: i32) -> Result<(), PixelError> {
        let prepared = Prepared::new(width, height).map_err(|_| PixelError::GeometryRejected)?;
        self.install(prepared);
        Ok(())
    }
}

/// One presented frame, in the terms the sink's `bytes` describe: the layout it
/// is in, and the rectangle that changed since the previous presentation.
///
/// The Flutter clients consume the engine through this: there is no display to
/// present into off-device, so the pixels have to leave through a caller.
pub trait FrameObserver: Send + Sync {
    fn frame(&self, width: i32, height: i32, stride: usize, bytes: &[u8], damage: Rect);
}
/// In-memory sink: the host build's presentation target and the tests' one.
///
/// It has no display to talk to, so a presentation is a caller draining the
/// damage box — which `present_count` counts.
pub struct MemorySurface {
    fb: Framebuffer,
    presentations: u64,
    observer: Option<std::sync::Arc<dyn FrameObserver>>,
}

impl MemorySurface {
    pub fn new(width: i32, height: i32) -> Result<Self, SurfaceError> {
        Ok(Self {
            fb: Framebuffer::new(width, height)?,
            presentations: 0,
            observer: None,
        })
    }

    /// Sends every frame this surface presents to `observer` from here on.
    pub fn observe(&mut self, observer: std::sync::Arc<dyn FrameObserver>) {
        self.observer = Some(observer);
    }

    /// Bytes per row, `width * 4`, because this sink owns a plain framebuffer.
    pub fn stride(&self) -> usize {
        self.fb.stride
    }

    /// The whole framebuffer, `stride * height` bytes, laid out as
    /// `PixelLayout::bgra8888()` describes.
    pub fn bytes(&self) -> &[u8] {
        &self.fb.pixels
    }

    /// Returns the accumulated damage and clears it. `None` means nothing was
    /// written since the last call.
    pub fn take_damage(&mut self) -> Option<Rect> {
        let rect = self.fb.take_damage()?;
        self.presentations = self.presentations.saturating_add(1);
        if let Some(observer) = &self.observer {
            let (width, height) = self.fb.size();
            observer.frame(width, height, self.fb.stride, &self.fb.pixels, rect);
        }
        Some(rect)
    }

    /// Damage batches drained for presentation, i.e. the `Some` answers
    /// `take_damage` gave. A `None` drain hands nothing to a presenter and is
    /// not counted.
    pub fn present_count(&self) -> u64 {
        self.presentations
    }
}

impl PixelTarget for MemorySurface {
    fn layout(&self) -> PixelLayout {
        LAYOUT
    }

    fn size(&self) -> (i32, i32) {
        self.fb.size()
    }

    fn rect_mut(&mut self, rect: Rect) -> Result<RectBuf<'_>, PixelError> {
        self.fb.window(rect)
    }

    fn damage(&mut self, rect: Rect) {
        self.fb.note(rect);
    }

    fn copy_rect(&mut self, dst: Rect, src_x: i32, src_y: i32) -> Result<(), PixelError> {
        self.fb.copy(dst, src_x, src_y)
    }

    fn resize(&mut self, width: i32, height: i32) -> Result<(), PixelError> {
        self.fb.resize(width, height)
    }
}

/// OHOS sink: a CPU framebuffer blitted into the buffer queue of the ArkUI
/// surface behind the HAR lease.
///
/// Constructible only on device: everywhere else [`OhosSurface::open`] fails
/// with `SurfaceError::UnsupportedPlatform`, exactly like `SurfaceDecoder`.
pub struct OhosSurface {
    fb: Framebuffer,
    #[cfg(target_env = "ohos")]
    window: native::Window,
}

impl OhosSurface {
    /// Binds a Surface lease to a native window whose buffer geometry is
    /// `width` x `height`. The lease is retained for as long as the window
    /// exists, so the HAR owner must not invalidate the Surface until this sink
    /// is closed or dropped.
    pub fn open(
        lease: Arc<dyn SurfaceLease>,
        width: i32,
        height: i32,
    ) -> Result<Self, SurfaceError> {
        #[cfg(target_env = "ohos")]
        {
            // Geometry is checked before any native work, but the framebuffer is
            // built before the window so a refused geometry costs no window.
            let fb = Framebuffer::new(width, height)?;
            Ok(Self {
                fb,
                window: native::Window::open(lease, width, height)?,
            })
        }
        #[cfg(not(target_env = "ohos"))]
        {
            let _ = (lease, width, height);
            Err(SurfaceError::UnsupportedPlatform)
        }
    }

    /// Blits the damaged region into a requested buffer and flushes it, which
    /// hands the buffer to the consumer. Call it from a blocking worker: the
    /// request waits inside the window and is not cancellable.
    pub fn present(&mut self) -> Result<(), SurfaceError> {
        #[cfg(target_env = "ohos")]
        {
            let Some(damage) = self.fb.take_damage() else {
                // Nothing was written, so there is nothing to show and no
                // reason to move a buffer through the queue.
                return Ok(());
            };
            let presented = self.window.present(&self.fb, damage);
            if presented.is_err() {
                // The region was not shown, so it stays damaged and the next
                // present retries it instead of leaving a stale rectangle up.
                self.fb.note(damage);
            }
            presented
        }
        #[cfg(not(target_env = "ohos"))]
        {
            Err(SurfaceError::UnsupportedPlatform)
        }
    }

    /// Returns the accumulated damage and clears it, without presenting.
    pub fn take_damage(&mut self) -> Option<Rect> {
        self.fb.take_damage()
    }

    /// Reallocates to the new geometry, tells the window about it, and clears
    /// the damage box. Unlike `PixelTarget::resize` this reports why the sink
    /// refused, or the window rejected, the geometry.
    pub fn resize(&mut self, width: i32, height: i32) -> Result<(), SurfaceError> {
        #[cfg(target_env = "ohos")]
        {
            let prepared = Prepared::new(width, height)?;
            self.window.set_geometry(width, height)?;
            self.fb.install(prepared);
            Ok(())
        }
        #[cfg(not(target_env = "ohos"))]
        {
            let _ = (width, height);
            Err(SurfaceError::UnsupportedPlatform)
        }
    }

    /// Destroys the native window and releases the lease. Call it from a
    /// blocking worker; dropping the sink without calling it does the same
    /// teardown, but only this call can report a failure.
    pub fn close(self) -> Result<(), SurfaceError> {
        #[cfg(target_env = "ohos")]
        {
            let mut window = self.window;
            window.close()
        }
        #[cfg(not(target_env = "ohos"))]
        {
            Err(SurfaceError::UnsupportedPlatform)
        }
    }
}

impl PixelTarget for OhosSurface {
    fn layout(&self) -> PixelLayout {
        LAYOUT
    }

    fn size(&self) -> (i32, i32) {
        self.fb.size()
    }

    fn rect_mut(&mut self, rect: Rect) -> Result<RectBuf<'_>, PixelError> {
        self.fb.window(rect)
    }

    fn damage(&mut self, rect: Rect) {
        self.fb.note(rect);
    }

    fn copy_rect(&mut self, dst: Rect, src_x: i32, src_y: i32) -> Result<(), PixelError> {
        self.fb.copy(dst, src_x, src_y)
    }

    /// The same resize as the inherent method, which a caller holding the
    /// concrete type reaches. This one answers in `PixelError` because it is the
    /// contract a `&mut dyn PixelTarget` session sees.
    fn resize(&mut self, width: i32, height: i32) -> Result<(), PixelError> {
        OhosSurface::resize(self, width, height).map_err(|_| PixelError::GeometryRejected)
    }
}

/// Bound on natives the sink is allowed to own, and the accounting that keeps
/// the bound real.
///
/// Mirrors `ohos_decoder`'s owner budget, and is compiled for the device and for
/// tests for the same reason: the arithmetic is worth checking without a device.
#[cfg(any(target_env = "ohos", test))]
mod ownership {
    use super::SurfaceError;

    /// Live-or-retained OHOS surfaces allowed process-wide, mirroring
    /// `ohos_decoder`'s `MAX_OWNERS`. One session owns one surface, and a
    /// retained surface still counts because it still holds a lease.
    pub const MAX_OWNERS: usize = 4;

    #[derive(Default)]
    pub struct OwnerBudget {
        pub live: usize,
        pub retained: usize,
    }

    impl OwnerBudget {
        /// Takes one slot. Refused once anything has been retained: a process
        /// that failed a teardown must not build more native windows, because a
        /// later failure could not be retained inside the same bound.
        pub fn reserve(&mut self) -> Result<(), SurfaceError> {
            if self.retained != 0 || self.live >= MAX_OWNERS {
                return Err(SurfaceError::LeaseInvalid);
            }
            self.live += 1;
            Ok(())
        }
    }
}

#[cfg(target_env = "ohos")]
mod native {
    use std::{
        ffi::c_void,
        ptr,
        sync::{LazyLock, Mutex, MutexGuard},
    };

    use super::{
        Arc, BYTES_PER_PIXEL, Framebuffer, Rect, SurfaceError, SurfaceLease,
        ownership::{MAX_OWNERS, OwnerBudget},
    };

    /// One ArkUI surface, one native window, one buffer request at a time.
    #[repr(C)]
    struct NativeWindow {
        _opaque: [u8; 0],
    }
    #[repr(C)]
    struct NativeWindowBuffer {
        _opaque: [u8; 0],
    }
    /// `BufferHandle` from `native_window/buffer_handle.h`. Field order and
    /// types are the header's; the two the sink blits through are `stride`
    /// (bytes per row) and `vir_addr`. Fields nothing reads are
    /// underscore-prefixed, which leaves the layout untouched. The header's
    /// trailing `int32_t reserve[0]` is a flexible array member of no size, so
    /// it is not bound here.
    #[repr(C)]
    struct BufferHandle {
        _fd: i32,
        width: i32,
        stride: i32,
        height: i32,
        _size: i32,
        _format: i32,
        _usage: u64,
        vir_addr: *mut c_void,
        _key: i32,
        _phy_addr: u64,
        _reserve_fds: u32,
        _reserve_ints: u32,
    }
    /// `Region::Rect`: the dirty rectangle handed to the flush. Its fields are
    /// written for the window to read through the pointer, never read back.
    #[repr(C)]
    #[allow(dead_code)]
    struct RegionRect {
        x: i32,
        y: i32,
        w: u32,
        h: u32,
    }
    /// `Region` from `native_window/external_window.h`: the dirty rectangles of
    /// one flush, passed by value.
    #[repr(C)]
    struct Region {
        rects: *mut RegionRect,
        rect_number: i32,
    }

    /// `NativeWindowOperation::SET_BUFFER_GEOMETRY`, which the header requires
    /// before a buffer request.
    const SET_BUFFER_GEOMETRY: i32 = 0;
    /// `NativeWindowOperation::SET_FORMAT`.
    const SET_FORMAT: i32 = 3;
    /// `OH_NativeBuffer_Format::NATIVEBUFFER_PIXEL_FMT_BGRA_8888`: blue, green,
    /// red, alpha in memory order, which is what `PixelLayout::bgra8888()`
    /// writes with the red channel at shift 16 and blue at shift 0.
    const NATIVEBUFFER_PIXEL_FMT_BGRA_8888: i32 = 20;

    unsafe extern "C" {
        // Required by the SDK, not chosen here: "when the fenceFd is used up,
        // you need to close it", and only the flush closes it for us.
        fn close(fd: i32) -> i32;
    }

    #[link(name = "native_window")]
    unsafe extern "C" {
        fn OH_NativeWindow_CreateNativeWindowFromSurfaceId(
            id: u64,
            window: *mut *mut NativeWindow,
        ) -> i32;
        // Declared with the crate's canonical ABI type for this symbol: other
        // platform modules already bind it as an untyped pointer, and three
        // different opaque pointer types for one C symbol is a redeclaration
        // warning at best and a silent mismatch at worst.
        fn OH_NativeWindow_DestroyNativeWindow(window: *mut core::ffi::c_void);
        fn OH_NativeWindow_NativeWindowHandleOpt(
            window: *mut NativeWindow,
            code: i32,
            ...
        ) -> i32;
        fn OH_NativeWindow_NativeWindowRequestBuffer(
            window: *mut NativeWindow,
            buffer: *mut *mut NativeWindowBuffer,
            fence_fd: *mut i32,
        ) -> i32;
        fn OH_NativeWindow_GetBufferHandleFromNative(
            buffer: *mut NativeWindowBuffer,
        ) -> *mut BufferHandle;
        fn OH_NativeWindow_NativeWindowFlushBuffer(
            window: *mut NativeWindow,
            buffer: *mut NativeWindowBuffer,
            fence_fd: i32,
            region: Region,
        ) -> i32;
        fn OH_NativeWindow_NativeWindowAbortBuffer(
            window: *mut NativeWindow,
            buffer: *mut NativeWindowBuffer,
        ) -> i32;
    }

    /// Maps the `int32_t` result of a `native_window` call onto the frozen error
    /// set. The call's name is not carried, because `SurfaceError` has neither a
    /// `Native { api, code }` variant nor room to grow one here.
    fn buffer_result(code: i32) -> Result<(), SurfaceError> {
        if code == 0 {
            Ok(())
        } else {
            Err(SurfaceError::NativeBufferUnavailable)
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Retention capacity is reserved before the native window exists, so a
    /// failed teardown always has somewhere bounded to go. At most `MAX_OWNERS`
    /// windows (open or retained) exist, one retention latches creation off for
    /// the process, and nothing is retried periodically.
    struct Gate {
        budget: OwnerBudget,
        retained: Vec<Inner>,
    }

    static GATE: LazyLock<Mutex<Gate>> = LazyLock::new(|| {
        Mutex::new(Gate {
            budget: OwnerBudget::default(),
            retained: Vec::with_capacity(MAX_OWNERS),
        })
    });

    /// One reserved owner slot, held for as long as the window or its retained
    /// remains exist.
    struct Permit;

    impl Permit {
        fn acquire() -> Result<Self, SurfaceError> {
            lock(&GATE).budget.reserve()?;
            Ok(Self)
        }
    }

    impl Drop for Permit {
        fn drop(&mut self) {
            let mut gate = lock(&GATE);
            gate.budget.live = gate.budget.live.saturating_sub(1);
        }
    }

    /// A window that was built, however its teardown goes. Holding the lease and
    /// the permit here is what keeps a retained window's Surface alive.
    struct Inner {
        handle: usize,
        /// Buffer requested from the queue and not yet returned to it.
        outstanding: Option<usize>,
        _lease: Arc<dyn SurfaceLease>,
        _permit: Permit,
    }

    fn retain(inner: Inner) {
        let mut gate = lock(&GATE);
        gate.budget.retained = gate.budget.retained.saturating_add(1);
        // `inner` still holds its permit, so `retained.len() <= MAX_OWNERS`.
        gate.retained.push(inner);
    }

    /// Owns the native window until it is destroyed or retained.
    pub(super) struct Window {
        inner: Option<Inner>,
    }

    impl Window {
        pub(super) fn open(
            lease: Arc<dyn SurfaceLease>,
            width: i32,
            height: i32,
        ) -> Result<Self, SurfaceError> {
            if lease.surface_id() == 0 {
                return Err(SurfaceError::LeaseInvalid);
            }
            let permit = Permit::acquire()?;
            let mut window = ptr::null_mut();
            let created = unsafe {
                OH_NativeWindow_CreateNativeWindowFromSurfaceId(lease.surface_id(), &mut window)
            };
            if created != 0 || window.is_null() {
                // The id did not resolve to a live Surface. `permit` is dropped
                // on the way out, which releases the slot it reserved.
                return Err(SurfaceError::LeaseInvalid);
            }
            let handle = window as *mut NativeWindow;
            let opened = Self {
                inner: Some(Inner {
                    handle: window as usize,
                    outstanding: None,
                    _lease: lease,
                    _permit: permit,
                }),
            };
            // The format is constant for the lifetime of the sink, because
            // `layout` promises one layout; the geometry follows the framebuffer.
            // A failure here drops `opened`, which destroys the window it just
            // created.
            buffer_result(unsafe {
                OH_NativeWindow_NativeWindowHandleOpt(
                    handle,
                    SET_FORMAT,
                    NATIVEBUFFER_PIXEL_FMT_BGRA_8888,
                )
            })?;
            buffer_result(unsafe {
                OH_NativeWindow_NativeWindowHandleOpt(handle, SET_BUFFER_GEOMETRY, width, height)
            })?;
            Ok(opened)
        }

        /// Tells the window the geometry the next requested buffer must have.
        pub(super) fn set_geometry(&self, width: i32, height: i32) -> Result<(), SurfaceError> {
            let Some(inner) = self.inner.as_ref() else {
                return Err(SurfaceError::NativeBufferUnavailable);
            };
            buffer_result(unsafe {
                OH_NativeWindow_NativeWindowHandleOpt(
                    inner.handle as *mut NativeWindow,
                    SET_BUFFER_GEOMETRY,
                    width,
                    height,
                )
            })
        }

        /// Copies the damaged rows of `fb` into one requested buffer and flushes
        /// it, returning the buffer to the queue on every path.
        pub(super) fn present(
            &mut self,
            fb: &Framebuffer,
            damage: Rect,
        ) -> Result<(), SurfaceError> {
            let Some(inner) = self.inner.as_mut() else {
                return Err(SurfaceError::NativeBufferUnavailable);
            };
            if inner.outstanding.is_some() {
                // Request and flush are one pair; a second request while the
                // first buffer is still out would exhaust the queue.
                return Err(SurfaceError::NativeBufferUnavailable);
            }
            let window = inner.handle as *mut NativeWindow;
            let mut buffer = ptr::null_mut();
            let mut fence = -1;
            buffer_result(unsafe {
                OH_NativeWindow_NativeWindowRequestBuffer(window, &mut buffer, &mut fence)
            })?;
            if buffer.is_null() {
                return Err(SurfaceError::NativeBufferUnavailable);
            }
            inner.outstanding = Some(buffer as usize);
            let handle = unsafe { OH_NativeWindow_GetBufferHandleFromNative(buffer) };
            let blitted = match unsafe { handle.as_ref() } {
                Some(handle) => unsafe { blit_rows(handle, fb, damage) },
                None => false,
            };
            if !blitted {
                inner.abort(window, fence);
                return Err(SurfaceError::NativeBufferUnavailable);
            }
            let mut rect = RegionRect {
                x: damage.x,
                y: damage.y,
                w: damage.width as u32,
                h: damage.height as u32,
            };
            let code = unsafe {
                OH_NativeWindow_NativeWindowFlushBuffer(
                    window,
                    buffer,
                    fence,
                    Region {
                        rects: &mut rect,
                        rect_number: 1,
                    },
                )
            };
            // Flushed or refused, the buffer is back in the queue now.
            inner.outstanding = None;
            buffer_result(code)
        }

        /// Destroys the window and releases the lease, or retains both when the
        /// queue would not take its buffer back.
        pub(super) fn close(&mut self) -> Result<(), SurfaceError> {
            let Some(mut inner) = self.inner.take() else {
                return Ok(());
            };
            let window = inner.handle as *mut NativeWindow;
            if let Some(buffer) = inner.outstanding.take() {
                let code = unsafe {
                    OH_NativeWindow_NativeWindowAbortBuffer(
                        window,
                        buffer as *mut NativeWindowBuffer,
                    )
                };
                if code != 0 {
                    // The queue may still hand this buffer to the consumer, so
                    // the window must outlive this call, and the lease goes with
                    // it: the HAR owner must not invalidate a Surface a native
                    // window is still blitting into.
                    inner.outstanding = Some(buffer);
                    retain(inner);
                    return Err(SurfaceError::DestroyFailed { code });
                }
            }
            // Returns void, so a hard failure here cannot be reported; that is
            // why `DestroyFailed` carries the abort's code and not this one.
            unsafe { OH_NativeWindow_DestroyNativeWindow(window.cast()) };
            drop(inner); // the lease and the owner slot are released only now.
            Ok(())
        }
    }

    impl Drop for Window {
        fn drop(&mut self) {
            // Same teardown as `close`, whose result a Drop cannot carry: a
            // caller that needs to see the failure has to call `close` itself.
            // Either way a failed teardown retains the window and the lease.
            let _ = self.close();
        }
    }

    impl Inner {
        /// Returns the outstanding buffer to the queue and closes the request's
        /// fence descriptor. A failed abort keeps the handle: it is retried once
        /// at teardown and reported if it fails again.
        fn abort(&mut self, window: *mut NativeWindow, fence: i32) {
            if let Some(buffer) = self.outstanding.take() {
                let code = unsafe {
                    OH_NativeWindow_NativeWindowAbortBuffer(
                        window,
                        buffer as *mut NativeWindowBuffer,
                    )
                };
                if code != 0 {
                    self.outstanding = Some(buffer);
                }
            }
            if fence >= 0 {
                // The SDK closes this only in the flush, so an aborted request
                // still owns it, and leaking it would cost a descriptor per
                // failed frame. A close that fails is not actionable here.
                let _ = unsafe { close(fence) };
            }
        }
    }

    /// Copies the damaged rows of `fb` into the requested buffer.
    ///
    /// Returns false without writing anything when the buffer cannot hold the
    /// frame. The window may hand back a wider stride and padding rows, never a
    /// smaller buffer, and a buffer that disagrees is a window bug rather than
    /// something to clip around.
    ///
    /// # Safety
    /// `handle` must be the handle of a buffer currently requested from a
    /// window, which is what makes `vir_addr` valid for the buffer's geometry.
    unsafe fn blit_rows(handle: &BufferHandle, fb: &Framebuffer, damage: Rect) -> bool {
        if handle.vir_addr.is_null()
            || i64::from(handle.width) < i64::from(fb.width)
            || i64::from(handle.height) < i64::from(fb.height)
            || i64::from(handle.stride) < i64::from(fb.width) * BYTES_PER_PIXEL as i64
        {
            return false;
        }
        let row_bytes = damage.width as usize * BYTES_PER_PIXEL;
        let base = handle.vir_addr as *mut u8;
        for row in 0..damage.height {
            let src_start =
                (damage.y + row) as usize * fb.stride + damage.x as usize * BYTES_PER_PIXEL;
            let dst_start = (damage.y + row) as usize * handle.stride as usize
                + damage.x as usize * BYTES_PER_PIXEL;
            let Some(src) = fb.pixels.get(src_start..src_start + row_bytes) else {
                return false;
            };
            unsafe { ptr::copy_nonoverlapping(src.as_ptr(), base.add(dst_start), row_bytes) };
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{ownership::{MAX_OWNERS, OwnerBudget}, *};

    fn surface(width: i32, height: i32) -> MemorySurface {
        MemorySurface::new(width, height).unwrap()
    }

    /// Records what a frame observer was told, so the hand-off can be asserted
    /// without a display or a Dart runtime.
    struct RecordingObserver {
        seen: std::sync::Mutex<Vec<(i32, i32, usize, usize, Rect)>>,
    }

    impl FrameObserver for RecordingObserver {
        fn frame(&self, width: i32, height: i32, stride: usize, bytes: &[u8], damage: Rect) {
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((width, height, stride, bytes.len(), damage));
        }
    }

    #[test]
    fn an_observer_receives_each_presented_region_once() {
        let mut surface = surface(4, 2);
        let observer = std::sync::Arc::new(RecordingObserver {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        surface.observe(observer.clone());

        // Nothing was written, so there is nothing to present and nothing to
        // report: a drain that answers None must not reach the observer.
        assert!(surface.take_damage().is_none());
        assert!(observer.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

        let written = Rect { x: 1, y: 0, width: 2, height: 2 };
        {
            let mut window = surface
                .rect_mut(written)
                .expect("a rectangle inside the surface is writable");
            for y in written.y..written.y + written.height {
                let row = window
                    .row(y)
                    .expect("every row of the rectangle is addressable");
                row[..written.width as usize * BYTES_PER_PIXEL].fill(7);
            }
        }
        surface.damage(written);
        assert_eq!(surface.take_damage(), Some(written));

        let seen = observer.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1);
        let (width, height, stride, len, damage) = seen[0];
        assert_eq!((width, height), (4, 2));
        assert_eq!(stride, 4 * BYTES_PER_PIXEL);
        assert_eq!(len, 4 * BYTES_PER_PIXEL * 2);
        assert_eq!(damage, written);
    }

    #[test]
    fn layout_stride_and_geometry() {
        let surface = surface(3, 2);
        assert_eq!(surface.layout(), PixelLayout::bgra8888());
        assert_eq!(surface.size(), (3, 2));
        assert_eq!(surface.stride(), 3 * BYTES_PER_PIXEL);
        assert_eq!(surface.bytes().len(), 3 * BYTES_PER_PIXEL * 2);
        assert!(surface.bytes().iter().all(|byte| *byte == 0));
        assert_eq!(surface.present_count(), 0);
        // Geometry is validated before the one allocation sized by peer input,
        // so an extreme DesktopSize is an error rather than an overflow or an
        // allocator abort.
        for (width, height) in [(0, 4), (4, 0), (-1, 4), (4, -1), (i32::MIN, 4), (4, i32::MIN)] {
            assert_eq!(
                MemorySurface::new(width, height).err(),
                Some(SurfaceError::InvalidGeometry),
                "{width}x{height}"
            );
        }
        assert_eq!(
            MemorySurface::new(MAX_DIMENSION + 1, 1).err(),
            Some(SurfaceError::InvalidGeometry)
        );
        assert_eq!(
            MemorySurface::new(1, MAX_DIMENSION + 1).err(),
            Some(SurfaceError::InvalidGeometry)
        );
        // Both edges are inside the per-edge cap, so the byte cap is what
        // refuses this one, and it is refused before anything is allocated.
        assert_eq!(
            MemorySurface::new(MAX_DIMENSION, MAX_DIMENSION).err(),
            Some(SurfaceError::InvalidGeometry)
        );
        assert_eq!(
            MemorySurface::new(i32::MAX, i32::MAX).err(),
            Some(SurfaceError::InvalidGeometry)
        );
    }

    #[test]
    fn rect_window_writes_land_at_the_right_bytes() {
        let mut surface = surface(4, 3);
        let target = Rect::new(1, 1, 2, 2);
        // The window is a rectangle inside a wider framebuffer, so its rows are
        // walked at the framebuffer stride rather than at the rectangle width.
        assert!(surface.stride() > target.width as usize * BYTES_PER_PIXEL);
        {
            let mut rect = surface.rect_mut(target).unwrap();
            assert_eq!(rect.rect(), target);
            assert!(rect.put_row(0, &[1, 2, 3, 4, 5, 6, 7, 8]));
            assert!(rect.put_row(1, &[9, 10, 11, 12, 13, 14, 15, 16]));
            // Rectangle-local, so this is the window's first pixel of row 1.
            rect.put_pixel(0, 1, 0xdead_beef);
        }
        let stride = surface.stride();
        let bytes = surface.bytes();
        // Row 0 of the framebuffer holds only the pixel left of the window.
        assert_eq!(&bytes[0..BYTES_PER_PIXEL], &[0; 4]);
        assert_eq!(&bytes[stride + 4..stride + 12], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            &bytes[2 * stride + 4..2 * stride + 12],
            &[0xef, 0xbe, 0xad, 0xde, 13, 14, 15, 16]
        );
        // Nothing outside the window was touched.
        assert_eq!(&bytes[BYTES_PER_PIXEL..stride], &[0; 12]);
        assert_eq!(&bytes[stride + 12..2 * stride], &[0; 4]);
        assert_eq!(&bytes[2 * stride + 12..], &[0; 4]);
        // A window that escapes the framebuffer is refused, never clipped.
        assert_eq!(
            surface.rect_mut(Rect::new(3, 0, 2, 1)).err(),
            Some(PixelError::OutOfBounds)
        );
        assert_eq!(
            surface.rect_mut(Rect::new(0, 2, 1, 2)).err(),
            Some(PixelError::OutOfBounds)
        );
        assert_eq!(
            surface.rect_mut(Rect::new(i32::MAX, 0, i32::MAX, 1)).err(),
            Some(PixelError::OutOfBounds)
        );
        assert_eq!(
            surface.rect_mut(Rect::new(-1, 0, 1, 1)).err(),
            Some(PixelError::InvalidRect)
        );
        assert_eq!(
            surface.rect_mut(Rect::new(0, 0, 0, 1)).err(),
            Some(PixelError::InvalidRect)
        );
    }

    #[test]
    fn damage_merges_into_one_union_and_clears() {
        let mut surface = surface(8, 8);
        assert_eq!(surface.take_damage(), None);
        assert_eq!(surface.present_count(), 0);

        let first = Rect::new(1, 1, 2, 2);
        surface.damage(first);
        assert_eq!(surface.take_damage(), Some(first));
        // Draining twice hands one batch to a presenter, not two.
        assert_eq!(surface.take_damage(), None);
        assert_eq!(surface.present_count(), 1);

        // Two separated rectangles become one bounding box, not a list.
        surface.damage(first);
        surface.damage(Rect::new(5, 6, 2, 2));
        assert_eq!(surface.take_damage(), Some(Rect::new(1, 1, 6, 7)));
        assert_eq!(surface.present_count(), 2);

        // Both rectangles are inside the union, and nothing else is.
        surface.damage(Rect::new(1, 1, 1, 1));
        surface.damage(Rect::new(7, 7, 1, 1));
        assert_eq!(surface.take_damage(), Some(Rect::new(1, 1, 7, 7)));

        // A rectangle the sink could not have written is not recorded, because
        // it would only grow the blit region past the framebuffer.
        surface.damage(Rect::new(7, 7, 2, 2));
        surface.damage(Rect::new(-1, 0, 1, 1));
        assert_eq!(surface.take_damage(), None);
    }

    /// What `copy_rect` owes: the source region as if it had been snapshotted
    /// before the first byte was written. Staging the rows is exactly that, and
    /// it is what an overlap-blind row copy gets wrong.
    fn memmove_reference(pixels: &mut [u8], stride: usize, dst: Rect, src_x: i32, src_y: i32) {
        let row_bytes = dst.width as usize * BYTES_PER_PIXEL;
        let mut staged = vec![0u8; row_bytes * dst.height as usize];
        for row in 0..dst.height as usize {
            let start = (src_y as usize + row) * stride + src_x as usize * BYTES_PER_PIXEL;
            staged[row * row_bytes..(row + 1) * row_bytes]
                .copy_from_slice(&pixels[start..start + row_bytes]);
        }
        for row in 0..dst.height as usize {
            let start = (dst.y as usize + row) * stride + dst.x as usize * BYTES_PER_PIXEL;
            pixels[start..start + row_bytes]
                .copy_from_slice(&staged[row * row_bytes..(row + 1) * row_bytes]);
        }
    }

    #[test]
    fn copy_rect_matches_a_memmove_reference() {
        let (width, height) = (8, 6);
        let mut surface = surface(width, height);
        {
            // Position-dependent bytes, so a copy that reads what it already
            // overwrote cannot land on the right answer by accident.
            let mut rect = surface.rect_mut(Rect::new(0, 0, width, height)).unwrap();
            for row in 0..height {
                let run: Vec<u8> = (0..width as usize * BYTES_PER_PIXEL)
                    .map(|index| (row as usize * 251 + index * 7 + 3) as u8)
                    .collect();
                assert!(rect.put_row(row, &run));
            }
        }
        let cases = [
            // Disjoint: nothing to overlap.
            (Rect::new(0, 0, 3, 2), 5, 3),
            // Same rows, destination to the right of the source.
            (Rect::new(4, 1, 4, 2), 1, 1),
            // Same rows, destination to the left of the source.
            (Rect::new(1, 1, 4, 2), 4, 1),
            // Destination below the source, rows overlapping and columns equal:
            // a top-down copy would clobber rows it has not read yet.
            (Rect::new(2, 3, 4, 3), 2, 1),
            // Destination above the source, rows overlapping and columns equal:
            // the same hazard, met from the other side.
            (Rect::new(2, 0, 4, 3), 2, 2),
            // Diagonal overlap, destination lower and to the right.
            (Rect::new(1, 2, 5, 3), 3, 1),
            // Diagonal overlap, destination higher and to the right.
            (Rect::new(3, 1, 4, 4), 1, 2),
        ];
        for (dst, src_x, src_y) in cases {
            let mut expected = surface.bytes().to_vec();
            memmove_reference(&mut expected, surface.stride(), dst, src_x, src_y);
            surface.copy_rect(dst, src_x, src_y).unwrap();
            assert_eq!(
                surface.bytes(),
                expected.as_slice(),
                "dst {dst:?} src ({src_x}, {src_y})"
            );
        }
    }

    #[test]
    fn copy_rect_refuses_what_escapes_without_writing() {
        let mut surface = surface(4, 4);
        {
            let mut rect = surface.rect_mut(Rect::new(0, 0, 4, 4)).unwrap();
            for row in 0..4 {
                assert!(rect.put_row(row, &[7; 16]));
            }
        }
        let before = surface.bytes().to_vec();
        // Destination outside, source outside, a source that only starts
        // outside, and a destination that only ends outside: all refused before
        // a single byte is copied, so nothing is clipped silently.
        assert_eq!(
            surface.copy_rect(Rect::new(3, 0, 2, 1), 0, 0),
            Err(PixelError::OutOfBounds)
        );
        assert_eq!(
            surface.copy_rect(Rect::new(0, 0, 2, 1), 3, 0),
            Err(PixelError::OutOfBounds)
        );
        assert_eq!(
            surface.copy_rect(Rect::new(0, 0, 2, 1), -1, 0),
            Err(PixelError::OutOfBounds)
        );
        assert_eq!(
            surface.copy_rect(Rect::new(0, 3, 1, 2), 0, 0),
            Err(PixelError::OutOfBounds)
        );
        assert_eq!(
            surface.copy_rect(Rect::new(0, 0, 0, 1), 0, 0),
            Err(PixelError::InvalidRect)
        );
        assert_eq!(surface.bytes(), before.as_slice());
    }

    #[test]
    fn resize_changes_stride_and_drops_damage() {
        let mut surface = surface(4, 2);
        assert_eq!(surface.stride(), 16);
        surface.damage(Rect::new(0, 0, 4, 2));
        surface.resize(6, 3).unwrap();
        assert_eq!(surface.size(), (6, 3));
        assert_eq!(surface.stride(), 6 * BYTES_PER_PIXEL);
        assert_eq!(surface.bytes().len(), 6 * BYTES_PER_PIXEL * 3);
        // A resize repaints everything; the old box would name pixels of a
        // geometry that no longer exists.
        assert_eq!(surface.take_damage(), None);

        // A refused resize leaves the geometry and the contents alone.
        let before = surface.bytes().to_vec();
        assert_eq!(surface.resize(0, 3), Err(PixelError::GeometryRejected));
        assert_eq!(
            surface.resize(MAX_DIMENSION, MAX_DIMENSION),
            Err(PixelError::GeometryRejected)
        );
        assert_eq!(surface.resize(-1, 3), Err(PixelError::GeometryRejected));
        assert_eq!(surface.size(), (6, 3));
        assert_eq!(surface.bytes(), before.as_slice());

        let mut rect = surface.rect_mut(Rect::new(5, 2, 1, 1)).unwrap();
        rect.put_pixel(0, 0, 0x0102_0304);
        drop(rect);
        assert_eq!(
            &surface.bytes()[2 * 24 + 5 * BYTES_PER_PIXEL..2 * 24 + 6 * BYTES_PER_PIXEL],
            &[4, 3, 2, 1]
        );
    }

    #[cfg(not(target_env = "ohos"))]
    #[test]
    fn ohos_surface_reports_unsupported_platform_off_device() {
        struct Lease;

        // SAFETY: the id is a constant, and off device no native window is
        // created from it, so nothing retains the id beyond this test.
        unsafe impl SurfaceLease for Lease {
            fn surface_id(&self) -> u64 {
                1
            }
        }

        let lease = || -> Arc<dyn SurfaceLease> { Arc::new(Lease) };
        assert_eq!(
            OhosSurface::open(lease(), 64, 48).err(),
            Some(SurfaceError::UnsupportedPlatform)
        );
        // There is no platform to validate against, so geometry does not decide
        // the answer: every entry point fails the same way.
        assert_eq!(
            OhosSurface::open(lease(), 0, 0).err(),
            Some(SurfaceError::UnsupportedPlatform)
        );
        assert_eq!(
            OhosSurface::open(lease(), MAX_DIMENSION, MAX_DIMENSION).err(),
            Some(SurfaceError::UnsupportedPlatform)
        );
    }

    #[test]
    fn owner_budget_is_bounded_and_latches_after_a_retained_teardown() {
        let mut budget = OwnerBudget::default();
        for _ in 0..MAX_OWNERS {
            assert_eq!(budget.reserve(), Ok(()));
        }
        assert_eq!(budget.reserve().err(), Some(SurfaceError::LeaseInvalid));
        // One retained window latches creation off for the process: a later
        // teardown could not be retained inside the same bound.
        budget.retained = 1;
        budget.live -= 1;
        assert_eq!(budget.reserve().err(), Some(SurfaceError::LeaseInvalid));
    }

    #[test]
    fn error_text_names_the_failure() {
        assert!(SurfaceError::UnsupportedPlatform.to_string().contains("platform"));
        assert_eq!(
            SurfaceError::NativeBufferUnavailable.to_string(),
            "the OHOS native window did not provide a usable buffer"
        );
        assert_eq!(
            SurfaceError::DestroyFailed { code: 7 }.to_string(),
            "OHOS native-window teardown failed with code 7"
        );
        // Boxed as the standard error trait, so the impl is required, not just
        // printed.
        let error: Box<dyn std::error::Error> = Box::new(SurfaceError::LeaseInvalid);
        assert_eq!(
            error.to_string(),
            "the Surface lease cannot be materialized into a native window"
        );
    }
}
