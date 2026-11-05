use super::{RfbError, auth::Authentication, diag, session::RfbEvent};
use crate::protocol::rect::{PixelTarget, Rect};
#[cfg(unix)]
use std::os::fd::{AsRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, IntoRawSocket};
use std::{
    cell::Cell,
    ffi::{CStr, CString, c_char, c_int},
    net::TcpStream,
    ptr::NonNull,
    time::Instant,
};

#[repr(C)]
struct Client {
    _private: [u8; 0],
}
#[repr(C)]
struct NativeRect {
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
}
/// Mirrors `rd_vnc_origin`: the first failing native operation.
#[repr(C)]
#[derive(Default)]
struct NativeOrigin {
    stage: c_int,
    os_errno: c_int,
    want: u32,
    buffered: u32,
    reads: u32,
}

/// Only sent after HandleRFBServerMessage returns. The worker does not run
/// another receive until this view has been consumed by RfbSession::pump.
/// Input calls cannot mutate or free these allocations. Even terminal input
/// errors keep the native owner alive until the session is explicitly stopped.
#[repr(C)]
pub(super) struct Frame {
    pixels: *const u8,
    length: usize,
    damage: *const NativeRect,
    damage_count: usize,
    pub width: c_int,
    pub height: c_int,
    resized: c_int,
    painted: c_int,
    bell: c_int,
    clipboard: *const c_char,
    clipboard_length: usize,
    /// The encoding of the most recent real framebuffer rectangle in this
    /// message, and how many it decoded. `rectangles` 0 means this message
    /// carried no pixels, so `encoding` still names an earlier rectangle.
    pub encoding: u32,
    pub rectangles: u32,
    /// The socket's own smoothed round trip in microseconds; a negative value
    /// means the platform could not answer, which is not a measured zero.
    pub tcp_rtt_us: c_int,
}
// SAFETY: exclusive worker ownership and the receive/consume protocol above
// prevent mutation while the caller synchronously borrows these slices.
unsafe impl Send for Frame {}

unsafe extern "C" {
    fn rd_vnc_create(socket: usize, password: *const c_char, shared: c_int) -> *mut Client;
    fn rd_vnc_connect(session: *mut Client) -> c_int;
    fn rd_vnc_handle(session: *mut Client, frame: *mut Frame) -> c_int;
    fn rd_vnc_buffered(session: *const Client) -> c_int;
    fn rd_vnc_pointer(session: *mut Client, x: c_int, y: c_int, buttons: c_int) -> c_int;
    fn rd_vnc_key(session: *mut Client, key: u32, down: c_int) -> c_int;
    fn rd_vnc_clipboard(session: *mut Client, text: *const c_char, length: c_int) -> c_int;
    fn rd_vnc_error_code(session: *const Client) -> c_int;
    fn rd_vnc_origin_get(session: *const Client, out: *mut NativeOrigin) -> c_int;
    fn rd_vnc_error_reason(session: *const Client) -> *const c_char;
    fn rd_vnc_name(session: *const Client) -> *const c_char;
    fn rd_vnc_width(session: *const Client) -> c_int;
    fn rd_vnc_height(session: *const Client) -> c_int;
    fn rd_vnc_authentication(session: *const Client) -> u32;
    fn rd_vnc_destroy(session: *mut Client);
}

pub(super) struct Native(NonNull<Client>, Trace);
/// Worker-thread-only timing for the failure record. Counts and durations only.
#[derive(Default)]
struct Trace {
    connected: Option<Instant>,
    message_started: Option<Instant>,
    messages: u64,
    reported: Cell<bool>,
}
pub(super) struct Connected {
    pub desktop: (i32, i32),
    pub name: String,
    pub authentication: Authentication,
}

impl Native {
    /// Runs only on the dedicated session thread, including destruction.
    pub fn new(stream: TcpStream, password: String, shared: bool) -> Result<Self, RfbError> {
        let secret = CString::new(password).map_err(|_| RfbError::CredentialUnavailable)?;
        #[cfg(unix)]
        let socket = stream.as_raw_fd() as usize;
        #[cfg(windows)]
        let socket = stream.as_raw_socket() as usize;
        let pointer = unsafe { rd_vnc_create(socket, secret.as_ptr(), i32::from(shared)) };
        let mut secret = secret.into_bytes_with_nul();
        hbb_common::sodiumoxide::utils::memzero(&mut secret);
        let pointer = NonNull::new(pointer).ok_or(RfbError::Allocation)?;
        // The C client adopted the descriptor, and cleanup is now its owner.
        #[cfg(unix)]
        let _ = stream.into_raw_fd();
        #[cfg(windows)]
        let _ = stream.into_raw_socket();
        Ok(Self(pointer, Trace::default()))
    }
    pub fn connect(&mut self) -> Result<Connected, RfbError> {
        if unsafe { rd_vnc_connect(self.0.as_ptr()) } == 0 {
            return Err(self.error());
        }
        self.1.connected = Some(Instant::now());
        let authentication = match unsafe { rd_vnc_authentication(self.0.as_ptr()) } {
            1 => Authentication::None,
            2 => Authentication::VncAuth,
            _ => return Err(RfbError::NoUsableSecurityType),
        };
        Ok(Connected {
            desktop: unsafe {
                (
                    rd_vnc_width(self.0.as_ptr()),
                    rd_vnc_height(self.0.as_ptr()),
                )
            },
            name: unsafe { CStr::from_ptr(rd_vnc_name(self.0.as_ptr())) }
                .to_string_lossy()
                .into_owned(),
            authentication,
        })
    }
    pub fn buffered(&self) -> bool {
        unsafe { rd_vnc_buffered(self.0.as_ptr()) != 0 }
    }
    pub fn receive(&mut self) -> Result<Frame, RfbError> {
        // All-zero is a valid empty C output structure; it is read only on success.
        let mut frame: Frame = unsafe { std::mem::zeroed() };
        self.1.message_started = Some(Instant::now());
        if unsafe { rd_vnc_handle(self.0.as_ptr(), &mut frame) } == 0 {
            return Err(self.error());
        }
        self.1.messages += 1;
        Ok(frame)
    }
    pub fn pointer(&mut self, x: u16, y: u16, buttons: u8) -> Result<(), RfbError> {
        match unsafe { rd_vnc_pointer(self.0.as_ptr(), x.into(), y.into(), buttons.into()) } {
            -1 => Err(RfbError::Geometry),
            0 => Err(self.error()),
            _ => Ok(()),
        }
    }
    pub fn key(&mut self, key: u32, down: bool) -> Result<(), RfbError> {
        if unsafe { rd_vnc_key(self.0.as_ptr(), key, down.into()) } == 0 {
            Err(self.error())
        } else {
            Ok(())
        }
    }
    pub fn clipboard(&mut self, text: &str) -> Result<(), RfbError> {
        if unsafe { rd_vnc_clipboard(self.0.as_ptr(), text.as_ptr().cast(), text.len() as c_int) }
            == 0
        {
            Err(self.error())
        } else {
            Ok(())
        }
    }
    fn error(&self) -> RfbError {
        let code = unsafe { rd_vnc_error_code(self.0.as_ptr()) };
        self.report(code);
        let reason = || {
            unsafe { CStr::from_ptr(rd_vnc_error_reason(self.0.as_ptr())) }
                .to_string_lossy()
                .into_owned()
        };
        match code {
            1 => RfbError::Transport,
            2 => RfbError::Closed,
            3 => RfbError::AuthenticationFailed(reason()),
            4 => RfbError::NoUsableSecurityType,
            5 => RfbError::SecurityRefused(reason()),
            6 => RfbError::BadServerVersion,
            7 => RfbError::Geometry,
            9 => RfbError::CredentialUnavailable,
            10 => RfbError::Allocation,
            _ => RfbError::Protocol("LibVNCClient rejected the server message"),
        }
    }
    /// Emits the first native failure once. The peer's reason text, which only
    /// some authentication errors carry, is never part of it.
    fn report(&self, code: c_int) {
        if self.1.reported.replace(true) {
            return;
        }
        let mut origin = NativeOrigin::default();
        let known = unsafe { rd_vnc_origin_get(self.0.as_ptr(), &mut origin) } != 0;
        let millis = |at: Option<Instant>| at.map_or(-1, |at| at.elapsed().as_millis() as i64);
        let code_name = match code {
            0 => "none",
            1 => "transport",
            2 => "closed",
            3 => "auth",
            4 => "security",
            5 => "refused",
            6 => "version",
            7 => "geometry",
            8 => "protocol",
            9 => "credential",
            10 => "memory",
            _ => "unknown",
        };
        // -1 means the point was never reached (e.g. before connect or any receive).
        // since_receive_ms is the age of the most recent receive: for a failed
        // receive it is how long that message had been in progress.
        let (since_connect, since_receive) = (
            millis(self.1.connected),
            millis(self.1.message_started),
        );
        if !known {
            // No I/O or decode stage was recorded: an upstream refusal or a
            // failure before any hook could name it.
            diag::emit(format_args!(
                "layer=native code={code}({code_name}) stage=none messages={} since_connect_ms={since_connect} since_receive_ms={since_receive}",
                self.1.messages
            ));
            return;
        }
        let stage = match origin.stage {
            1 => "read_eof",
            2 => "read_errno",
            3 => "read_timeout",
            4 => "read_wait",
            5 => "write_errno",
            6 => "write_zero",
            7 => "write_wait",
            8 => "write_layer",
            9 => "read_null",
            10 => "handle_false",
            _ => "unknown",
        };
        diag::emit(format_args!(
            "layer=native code={code}({code_name}) stage={stage} errno={} want={} buffered={} reads_in_message={} messages={} since_connect_ms={since_connect} since_receive_ms={since_receive}",
            origin.os_errno, origin.want, origin.buffered, origin.reads, self.1.messages
        ));
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        unsafe { rd_vnc_destroy(self.0.as_ptr()) };
    }
}

impl Frame {
    /// No await point: after this returns no borrowed pointer escapes into a sink.
    pub fn apply(&self, target: &mut dyn PixelTarget) -> Result<Option<RfbEvent>, RfbError> {
        if self.width <= 0 || self.height <= 0 {
            return Err(RfbError::Geometry);
        }
        if target.size() != (self.width, self.height) {
            target
                .resize(self.width, self.height)
                .map_err(|_| RfbError::Sink)?;
        }
        let stride = (self.width as usize)
            .checked_mul(4)
            .ok_or(RfbError::Geometry)?;
        let length = stride
            .checked_mul(self.height as usize)
            .ok_or(RfbError::Geometry)?;
        if length != self.length || self.pixels.is_null() {
            return Err(RfbError::Geometry);
        }
        let pixels = unsafe { std::slice::from_raw_parts(self.pixels, self.length) };
        let damage = if self.damage_count == 0 {
            &[][..]
        } else {
            if self.damage.is_null() {
                return Err(RfbError::Geometry);
            }
            unsafe { std::slice::from_raw_parts(self.damage, self.damage_count) }
        };
        for rect in damage {
            let rect = Rect::new(rect.x, rect.y, rect.width, rect.height);
            rect.validate()?;
            if rect.width > self.width
                || rect.height > self.height
                || rect.x > self.width - rect.width
                || rect.y > self.height - rect.height
            {
                return Err(RfbError::Geometry);
            }
            let mut window = target.rect_mut(rect).map_err(|_| RfbError::Sink)?;
            for row in 0..rect.height {
                let offset = (rect.y + row) as usize * stride + rect.x as usize * 4;
                let source = &pixels[offset..offset + rect.width as usize * 4];
                let output = window.row(row).ok_or(RfbError::Sink)?;
                output.copy_from_slice(source);
                // RFB 32bpp/depth24 leaves this byte undefined. PixelTarget is
                // opaque BGRA8888, so normalize alpha only in damaged sink rows.
                for pixel in output.chunks_exact_mut(4) {
                    pixel[3] = 255;
                }
            }
            target.damage(rect);
        }
        if self.resized != 0 {
            return Ok(Some(RfbEvent::Desktop {
                width: self.width,
                height: self.height,
            }));
        }
        if self.painted != 0 {
            return Ok(Some(RfbEvent::Painted));
        }
        if self.bell != 0 {
            return Ok(Some(RfbEvent::Bell));
        }
        if !self.clipboard.is_null() {
            let bytes = unsafe {
                std::slice::from_raw_parts(self.clipboard.cast::<u8>(), self.clipboard_length)
            };
            return Ok(Some(RfbEvent::Clipboard(
                String::from_utf8_lossy(bytes).into_owned(),
            )));
        }
        Ok(None)
    }
}
