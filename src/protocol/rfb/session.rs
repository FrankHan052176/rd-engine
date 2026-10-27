//! Public VNC session adapter. LibVNCClient owns update request pacing.
use super::{MAX_CUT_TEXT, RfbError, auth::Authentication, native::Frame, worker::{Input, Worker}};
use crate::protocol::{Endpoint, rect::{PixelLayout, PixelTarget}};
use tokio::{net::{TcpStream, lookup_host}, sync::oneshot, time::{Duration, timeout}};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Credentials and dial target. None/VNC authentication are available; TLS and
/// username-bearing authentication are not advertised by this baseline build.
pub struct RfbOptions {
    pub endpoint: Endpoint,
    pub password: String,
    pub shared: bool,
}
impl Drop for RfbOptions {
    fn drop(&mut self) {
        let mut password = std::mem::take(&mut self.password).into_bytes();
        hbb_common::sodiumoxide::utils::memzero(&mut password);
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RfbEvent {
    /// New geometry is already applied. This update may also contain pixels.
    Desktop { width: i32, height: i32 },
    Painted,
    Bell,
    Clipboard(String),
}

pub struct RfbSession {
    worker: Worker,
    /// Retained across cancellation of pump: neither the receiver nor native
    /// stream parsing state belongs to a temporary future or target borrow.
    pending: Option<oneshot::Receiver<Result<Frame, RfbError>>>,
    desktop: (i32, i32),
    name: String,
    authentication: Authentication,
}
impl RfbSession {
    /// Returns after upstream initialization and its initial full update request.
    pub async fn connect(options: RfbOptions, layout: PixelLayout) -> Result<Self, RfbError> {
        if layout != PixelLayout::bgra8888() { return Err(RfbError::Geometry); }
        if options.password.len() > 256 { return Err(RfbError::PasswordTooLong); }
        if options.password.as_bytes().contains(&0) || options.endpoint.user.is_some() {
            return Err(RfbError::CredentialUnavailable);
        }
        let addresses = timeout(RESOLVE_TIMEOUT, lookup_host((options.endpoint.host.as_str(), options.endpoint.port)))
            .await.map_err(|_| RfbError::Transport)??;
        let addresses: Vec<_> = addresses.collect();
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addresses.as_slice()))
            .await.map_err(|_| RfbError::Transport)??;
        stream.set_nodelay(true)?;
        let (worker, connected) = Worker::start(stream.into_std()?, options)?;
        // The local worker guard also handles dropped/timed-out connect futures:
        // shutdown interrupts native authentication and Drop joins its cleanup.
        let info = timeout(CONNECT_TIMEOUT, connected).await
            .map_err(|_| RfbError::Transport)?
            .map_err(|_| RfbError::Closed)??;
        Ok(Self { worker, pending: None, desktop: info.desktop, name: info.name, authentication: info.authentication })
    }
    pub fn desktop(&self) -> (i32, i32) { self.desktop }
    pub fn name(&self) -> &str { &self.name }
    pub fn authentication(&self) -> Authentication { self.authentication }
    pub fn layout(&self) -> PixelLayout { PixelLayout::bgra8888() }

    /// Cancellation-safe: a competing input/policy event may drop this future;
    /// the next call resumes the same native read/result. The native worker
    /// never retains the target and the final damage copy has no await point.
    pub async fn pump(&mut self, target: &mut dyn PixelTarget) -> Result<Option<RfbEvent>, RfbError> {
        self.worker.ensure_open()?;
        if target.layout() != self.layout() { return Err(RfbError::Sink); }
        if self.pending.is_none() { self.pending = Some(self.worker.receive()?); }
        let Some(receiver) = self.pending.as_mut() else { return Err(RfbError::Closed); };
        let received = receiver.await;
        self.pending = None;
        let frame = received.map_err(|_| RfbError::Closed)??;
        let event = frame.apply(target)?;
        self.desktop = (frame.width, frame.height);
        Ok(event)
    }
    /// Completion means LibVNCClient finished the socket write, not enqueue.
    /// Cancelling a send closes and joins the session before releasing its borrow.
    pub async fn send_pointer(&mut self, x: u16, y: u16, buttons: u8) -> Result<(), RfbError> {
        if i32::from(x) >= self.desktop.0 || i32::from(y) >= self.desktop.1 { return Err(RfbError::Geometry); }
        self.worker.input(Input::Pointer { x, y, buttons }).await
    }
    pub async fn send_key(&mut self, keysym: u32, down: bool) -> Result<(), RfbError> {
        self.worker.input(Input::Key { key: keysym, down }).await
    }
    pub async fn send_clipboard(&mut self, text: &str) -> Result<(), RfbError> {
        if text.len() > MAX_CUT_TEXT { return Err(RfbError::Protocol("clipboard text is too long")); }
        self.worker.input(Input::Clipboard(text.into())).await
    }
    /// Interrupts native socket I/O and joins cleanup. No native C operation is
    /// executed by this async task; Drop provides the same stop/join guarantee.
    pub async fn close(&mut self) -> Result<(), RfbError> {
        self.pending = None;
        self.worker.stop()
    }
}
