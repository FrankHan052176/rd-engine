//! RDP adapter over the IronRDP 0.17.0 release family, Rust >= 1.89.
//!
//! Connection, activation and output handling are adapted from the official
//! `crates/ironrdp-client/src/rdp.rs` and `crates/ironrdp/examples/screenshot.rs`
//! at 11a0810cfbbabd8b8023875a05e3041216d4b01b (Devolutions Inc., Teleport).
//! Upstream's MIT license is retained in LICENSE-IRONRDP-MIT. Protocol,
//! authentication, clipboard PDUs and codecs remain library implementations.
//!
//! The library owns its decoded BGRA image. Presentation borrows that image
//! and copies damaged rows into PixelTarget; no cloned full-frame event queue
//! is maintained. All active I/O state, including partially written responses
//! and reactivation, belongs to the session so `pump` can be cancelled safely.

mod clipboard;
mod connection;
mod tls;

use std::collections::VecDeque;
use std::error::Error as _;
use std::fmt;
use std::io;
use std::time::Duration;

use ironrdp_cliprdr::CliprdrClient;
use ironrdp_cliprdr::pdu::{ClipboardFormatId, FileContentsResponse};
use ironrdp_connector::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationSequence, ConnectionActivationState,
};
use ironrdp_connector::{
    ClientConnector, Config, ConnectorError, ConnectorErrorKind, Credentials, DesktopSize,
};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::DrdynvcClient;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_pdu::input::mouse::PointerFlags;
use ironrdp_pdu::rdp::capability_sets::InputFlags;
use ironrdp_pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason};
use ironrdp_tokio::TokioFramed;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use zeroize::{Zeroize as _, Zeroizing};

use crate::protocol::Endpoint;
use crate::protocol::rect::{PixelError, PixelLayout, PixelTarget, Rect};
use clipboard::{Action as ClipboardAction, TextClipboard};

/// An explicit leaf pin replaces PKI name/chain trust. Both policies still
/// verify the TLS handshake's signatures; neither has a permissive fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpTrust {
    SystemRoots,
    CertificateSha256([u8; 32]),
}

pub struct RdpOptions {
    /// `endpoint.user` is the actual RDP account, including a domain if needed.
    pub endpoint: Endpoint,
    /// UTF-8 password bytes. This adapter-owned buffer is wiped on every exit.
    pub password: Vec<u8>,
    pub width: u16,
    pub height: u16,
    pub trust: RdpTrust,
}

impl fmt::Debug for RdpOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpOptions")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl Drop for RdpOptions {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustFailure {
    InvalidServerName,
    RootsUnavailable,
    TlsConfiguration,
    MissingCertificate,
    MalformedCertificate,
    CertificateRejected,
}

/// Error text never contains an upstream error chain, account or password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpError {
    MissingUser,
    InvalidCredentials,
    Authentication,
    Trust(TrustFailure),
    Transport(io::ErrorKind),
    Geometry(PixelError),
    Protocol(&'static str),
    Clipboard(&'static str),
    Unsupported(&'static str),
    Closed,
    CloseTimeout,
}

impl fmt::Display for RdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUser => f.write_str("RDP requires an explicit account"),
            Self::InvalidCredentials => f.write_str("invalid RDP account or UTF-8 password"),
            Self::Authentication => f.write_str("RDP authentication or authorization failed"),
            Self::Trust(reason) => write!(f, "RDP certificate trust failed: {reason:?}"),
            Self::Transport(kind) => write!(f, "RDP transport failed: {kind}"),
            Self::Geometry(reason) => write!(f, "RDP geometry rejected: {reason}"),
            Self::Protocol(stage) => write!(f, "RDP protocol failure: {stage}"),
            Self::Clipboard(reason) => write!(f, "RDP clipboard failure: {reason}"),
            Self::Unsupported(feature) => write!(f, "RDP capability unavailable: {feature}"),
            Self::Closed => f.write_str("RDP session is closed"),
            Self::CloseTimeout => f.write_str("RDP graceful close timed out; transport closed"),
        }
    }
}

impl std::error::Error for RdpError {}

#[derive(Debug, PartialEq, Eq)]
pub enum RdpEvent {
    Painted,
    Desktop { width: i32, height: i32 },
    Clipboard(String),
    Closed,
}

pub struct RdpSession {
    framed: TokioFramed<tls::TlsStream>,
    active: ActiveStage,
    image: DecodedImage,
    activation_factory: ConnectionActivationFactory,
    activation: Option<ConnectionActivationSequence>,
    compression: Option<CompressionType>,
    input_flags: InputFlags,
    writes: VecDeque<Vec<u8>>,
    write_offset: usize,
    needs_flush: bool,
    damage: Option<Rect>,
    desktop_pending: bool,
    events: VecDeque<RdpEvent>,
    termination: Option<Result<(), RdpError>>,
    closed_reported: bool,
}

impl RdpSession {
    /// Requires NLA; legacy graphical-login-only RDP is not treated as an
    /// authenticated connection. Cancelling this future drops any TCP/TLS
    /// connection created so far. No native protocol worker is spawned.
    pub async fn connect(mut options: RdpOptions) -> Result<Self, RdpError> {
        let user = options.endpoint.user.as_deref().ok_or(RdpError::MissingUser)?;
        if user.trim().is_empty() {
            return Err(RdpError::MissingUser);
        }
        if user.contains('\0') || options.password.contains(&0) {
            return Err(RdpError::InvalidCredentials);
        }
        validate_desktop(options.width, options.height)?;
        let server_name = rustls::pki_types::ServerName::try_from(options.endpoint.host.clone())
            .map_err(|_| RdpError::Trust(TrustFailure::InvalidServerName))?;
        let tls_config = tls::config(options.trust).await?;
        let stream = TcpStream::connect((options.endpoint.host.as_str(), options.endpoint.port))
            .await.map_err(transport_error)?;
        stream.set_nodelay(true).map_err(transport_error)?;
        let local_addr = stream.local_addr().map_err(transport_error)?;
        let password = Zeroizing::new(std::mem::take(&mut options.password));
        let password_text = std::str::from_utf8(&password).map_err(|_| RdpError::InvalidCredentials)?;
        let config = connector_config(user.to_owned(), password_text.to_owned(), options.width, options.height);
        // Wipe our source bytes now. ConnectorGuard scrubs the public Config
        // password on errors/cancellation and after ClientInfo encoding, before
        // activation can clone it. Upstream-private authentication copies remain
        // governed by their library lifecycle; we never log Config/Credentials.
        drop(password);
        let mut connector = connection::ConnectorGuard(ClientConnector::new(config, local_addr)
            .with_static_channel(DrdynvcClient::new()
                .with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new()))))
            .with_static_channel(CliprdrClient::new(Box::<TextClipboard>::default())));
        let mut framed = TokioFramed::new(stream);
        let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector.0)
            .await.map_err(connector_error)?;
        let (stream, leftover) = framed.into_inner();
        let (stream, public_key) = tls::upgrade(tls::PrefixedTcp::new(stream, leftover), server_name, tls_config).await?;
        let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector.0);
        let mut framed = TokioFramed::new(stream);
        let mut network = ironrdp_tokio::reqwest::ReqwestNetworkClient::new();
        let (result, input_flags) = connection::finalize(
            upgraded, connector, &mut framed, &mut network,
            options.endpoint.host.clone().into(), public_key,
        ).await?;
        validate_desktop(result.desktop_size.width, result.desktop_size.height)?;
        let image = DecodedImage::new(PixelFormat::BgrA32, result.desktop_size.width, result.desktop_size.height);
        let active = ActiveStageBuilder {
            static_channels: result.static_channels,
            user_channel_id: result.user_channel_id,
            io_channel_id: result.io_channel_id,
            message_channel_id: result.message_channel_id,
            share_id: result.share_id,
            compression_type: result.compression_type,
            enable_server_pointer: result.enable_server_pointer,
            pointer_software_rendering: result.pointer_software_rendering,
        }.build();
        Ok(Self {
            framed,
            active,
            image,
            activation_factory: result.activation_factory,
            activation: None,
            compression: result.compression_type,
            input_flags,
            writes: VecDeque::new(),
            write_offset: 0,
            needs_flush: false,
            damage: None,
            desktop_pending: true,
            events: VecDeque::new(),
            termination: None,
            closed_reported: false,
        })
    }

    pub fn desktop(&self) -> (i32, i32) {
        (i32::from(self.image.width()), i32::from(self.image.height()))
    }

    /// The actual server Input capability, not the client's advertised flags.
    /// Empty before a new DemandActive is confirmed during reactivation. The
    /// Desktop event is emitted only after the new activation is finalized.
    pub fn input_flags(&self) -> InputFlags {
        self.input_flags
    }

    /// Cancellation-safe even during output writes and reactivation. A cancelled
    /// call must be resumed on the same session, not by recreating its framer.
    /// `None` means a control-only PDU was processed, not EOF.
    pub async fn pump(&mut self, target: &mut dyn PixelTarget) -> Result<Option<RdpEvent>, RdpError> {
        if target.layout() != PixelLayout::bgra8888() {
            return Err(RdpError::Geometry(PixelError::UnsupportedFormat));
        }
        self.flush().await?;
        if let Some(event) = self.take_event(target)? {
            return Ok(Some(event));
        }
        self.check_open()?;
        if self.activation.is_some() {
            self.activation_step().await?;
        } else {
            self.read_active().await?;
        }
        self.flush().await?;
        self.take_event(target)
    }

    /// The library encodes the caller's already-authorized input batch. Input
    /// generation, revocation and key policy remain with the viewer. Cancelling
    /// after acceptance preserves queued bytes; callers must not replay a batch.
    pub async fn send_input(&mut self, events: &[FastPathInputEvent]) -> Result<(), RdpError> {
        self.check_open()?;
        self.finish_activation().await?;
        self.flush().await?;
        validate_input_flags(self.input_flags, events)?;
        let outputs = self.active.process_fastpath_input(&mut self.image, events)
            .map_err(|_| RdpError::Protocol("input encoding"))?;
        self.accept_outputs(outputs)?;
        self.flush().await
    }

    /// Advertises Unicode text; subsequent remote format-data requests are
    /// answered by CLIPRDR while pumping. Success means advertisement was sent,
    /// not that the remote user pasted it. Remote rejection is a pump error.
    pub async fn send_clipboard(&mut self, text: &str) -> Result<(), RdpError> {
        self.check_open()?;
        self.finish_activation().await?;
        self.flush().await?;
        self.active.get_svc_processor_mut::<CliprdrClient>()
            .and_then(|channel| channel.downcast_backend_mut::<TextClipboard>())
            .ok_or(RdpError::Unsupported("clipboard channel"))?
            .set_text(text)?;
        self.drain_clipboard()?;
        self.flush().await
    }

    /// Requests actual server resize through Display Control. Geometry changes
    /// only after the server's reactivation sequence, surfaced by `Desktop`.
    pub async fn resize(&mut self, width: u16, height: u16) -> Result<(), RdpError> {
        self.check_open()?;
        validate_desktop(width, height)?;
        if width % 2 != 0 {
            return Err(RdpError::Geometry(PixelError::InvalidRect));
        }
        self.finish_activation().await?;
        self.flush().await?;
        let frame = self.active.encode_resize(u32::from(width), u32::from(height), None, None)
            .ok_or(RdpError::Unsupported("display control channel"))?
            .map_err(|_| RdpError::Geometry(PixelError::GeometryRejected))?;
        self.queue_write(frame);
        self.flush().await
    }

    /// Sends the library shutdown request, processes ShutdownDenied/disconnect
    /// responses, then closes TLS. Timeout/failure still drops the owned socket.
    /// Dropping this future also drops the session and socket; there is no
    /// detached native session work to stop or join.
    pub async fn close(mut self) -> Result<(), RdpError> {
        match tokio::time::timeout(Duration::from_secs(5), self.close_handshake()).await {
            Ok(result) => result,
            Err(_) => Err(RdpError::CloseTimeout),
        }
    }

    async fn close_handshake(&mut self) -> Result<(), RdpError> {
        self.flush().await?;
        let mut requested_close = false;
        if self.termination.is_none() {
            self.finish_activation().await?;
            let outputs = self.active.graceful_shutdown()
                .map_err(|_| RdpError::Protocol("graceful shutdown"))?;
            self.accept_outputs(outputs)?;
            // Past this flush our DisconnectProviderUltimatum is on the wire.
            self.flush().await?;
            requested_close = true;
            while self.termination.is_none() {
                match self.close_step().await {
                    Ok(()) => {}
                    // The DisconnectProviderUltimatum we just sent is the last
                    // PDU and the server owes no reply: upstream
                    // graceful_shutdown sends ShareDataPdu::ShutdownRequest and
                    // ironrdp-server ends the connection on it instead of
                    // answering, so this wait reliably ends in a peer hangup.
                    // That is the shutdown completing, not failing; outside
                    // this post-request wait the same error still surfaces.
                    Err(error) if peer_hung_up(&error) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        }
        let result = self.termination.ok_or(RdpError::Protocol("incomplete graceful shutdown"))?;
        // The TLS close_notify leaves on the same socket, so the rule of the
        // wait above applies to it as well: once our own shutdown request is on
        // the wire, a peer that is already gone is still a normal end. A peer
        // that never got our request is a different case and stays an error.
        //
        // This branch is only reachable when the server *answers* the request
        // before closing. The repo's loopback fixture drops on ShutdownRequest
        // without replying, so it never gets here: a green acceptance probe is
        // no evidence for these bytes, and a failure here has to be read on its
        // own.
        match self.framed.get_inner_mut().0.shutdown().await.map_err(transport_error) {
            Ok(()) => {}
            Err(error) if requested_close && peer_hung_up(&error) => {}
            Err(error) => return Err(error),
        }
        result
    }

    /// One read/response cycle while waiting for the server's shutdown reply.
    /// A reply itself still arrives here as a processed termination; only the
    /// peer disappearing early is special-cased, by `close_handshake`.
    async fn close_step(&mut self) -> Result<(), RdpError> {
        if self.activation.is_some() {
            self.activation_step().await?;
        } else {
            self.read_active().await?;
        }
        self.flush().await
    }

    fn check_open(&self) -> Result<(), RdpError> {
        match self.termination {
            Some(Err(error)) => Err(error),
            Some(Ok(())) => Err(RdpError::Closed),
            None => Ok(()),
        }
    }

    async fn read_active(&mut self) -> Result<(), RdpError> {
        // IronRDP retains partial read bytes in `self.framed`; there is no
        // cancellation point between returning a PDU and saving its outputs.
        let (action, payload) = self.framed.read_pdu().await.map_err(transport_error)?;
        let outputs = self.active.process(&mut self.image, action, &payload)
            .map_err(|_| RdpError::Protocol("active session PDU"))?;
        self.accept_outputs(outputs)?;
        self.drain_clipboard()
    }

    fn accept_outputs(&mut self, outputs: Vec<ActiveStageOutput>) -> Result<(), RdpError> {
        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(frame) => self.queue_write(frame),
                ActiveStageOutput::GraphicsUpdate(rect) => self.add_damage(rect)?,
                ActiveStageOutput::DeactivateAll => {
                    if self.activation.is_some() {
                        return Err(RdpError::Protocol("overlapping reactivation"));
                    }
                    self.activation = Some(self.activation_factory.create());
                    self.input_flags = InputFlags::empty();
                }
                ActiveStageOutput::Terminate(reason) => {
                    self.termination = Some(match reason {
                        GracefulDisconnectReason::UserInitiated | GracefulDisconnectReason::ServerInitiated => Ok(()),
                        GracefulDisconnectReason::Other(_) => Err(RdpError::Protocol("server disconnect error")),
                    });
                }
                // Software pointer rendering is selected in the connector;
                // bitmap/position effects are already in the library image.
                ActiveStageOutput::PointerDefault | ActiveStageOutput::PointerHidden
                | ActiveStageOutput::PointerPosition { .. } | ActiveStageOutput::PointerBitmap(_) => {}
                // The library has already answered bandwidth/RTT requests;
                // NetworkCharacteristicsResult is informational only.
                ActiveStageOutput::AutoDetect(_) => {}
                // UDP was not advertised. Never pretend to establish it.
                ActiveStageOutput::MultitransportRequest(_) => {
                    return Err(RdpError::Unsupported("unnegotiated multitransport"));
                }
            }
        }
        Ok(())
    }

    async fn finish_activation(&mut self) -> Result<(), RdpError> {
        while self.activation.is_some() {
            self.flush().await?;
            self.activation_step().await?;
        }
        Ok(())
    }

    async fn activation_step(&mut self) -> Result<(), RdpError> {
        let Some(activation) = self.activation.as_mut() else {
            return Ok(());
        };
        let mut buffer = WriteBuf::new();
        let observe_input = matches!(activation.connection_activation_state(), ConnectionActivationState::CapabilitiesExchange);
        let written = connection::step_read(
            &mut self.framed, activation, &mut buffer,
            observe_input.then_some(&mut self.input_flags),
        ).await?;
        let state = activation.connection_activation_state();
        let io_channel_id = activation.io_channel_id();
        let user_channel_id = activation.user_channel_id();
        // No await after the sequence step until its write and state are saved.
        if written.size().is_some() {
            self.queue_write(buffer.into_inner());
        }
        if let ConnectionActivationState::Finalized {
            desktop_size, share_id, enable_server_pointer, pointer_software_rendering,
        } = state {
            validate_desktop(desktop_size.width, desktop_size.height)?;
            let bulk_decompressor = self.compression.map(|compression| {
                let compression = match compression {
                    CompressionType::K8 => ironrdp_bulk::CompressionType::Rdp4,
                    CompressionType::K64 => ironrdp_bulk::CompressionType::Rdp5,
                    CompressionType::Rdp6 => ironrdp_bulk::CompressionType::Rdp6,
                    CompressionType::Rdp61 => ironrdp_bulk::CompressionType::Rdp61,
                };
                ironrdp_bulk::BulkCompressor::new(compression)
                    .map_err(|_| RdpError::Protocol("reactivation bulk decompressor"))
            }).transpose()?;
            self.image = DecodedImage::new(PixelFormat::BgrA32, desktop_size.width, desktop_size.height);
            self.active.set_fastpath_processor(ironrdp_session::fast_path::ProcessorBuilder {
                io_channel_id, user_channel_id, share_id, enable_server_pointer,
                pointer_software_rendering, bulk_decompressor,
            }.build());
            self.active.set_share_id(share_id);
            self.active.set_enable_server_pointer(enable_server_pointer);
            self.activation = None;
            // The library has replaced its image, including when geometry is
            // unchanged. That reset is itself full-image damage; otherwise the
            // presentation target could retain pixels from the previous epoch.
            self.damage = Some(Rect::new(0, 0, i32::from(desktop_size.width), i32::from(desktop_size.height)));
            self.desktop_pending = true;
        }
        Ok(())
    }

    fn drain_clipboard(&mut self) -> Result<(), RdpError> {
        loop {
            let Some(channel) = self.active.get_svc_processor_mut::<CliprdrClient>() else {
                return Ok(());
            };
            let backend = channel.downcast_backend_mut::<TextClipboard>()
                .ok_or(RdpError::Clipboard("missing text backend"))?;
            let Some(action) = backend.actions.pop_front() else {
                return Ok(());
            };
            let messages = match action {
                ClipboardAction::Advertise => {
                    let formats = backend.formats();
                    channel.initiate_copy(&formats)
                }
                ClipboardAction::RequestUnicode => channel.initiate_paste(ClipboardFormatId::CF_UNICODETEXT),
                ClipboardAction::Respond(response) => channel.submit_format_data(response),
                ClipboardAction::RejectFile(stream_id) => channel.submit_file_contents(FileContentsResponse::new_error(stream_id)),
                ClipboardAction::Text(text) => {
                    self.events.push_back(RdpEvent::Clipboard(text));
                    continue;
                }
                ClipboardAction::Error(reason) => return Err(RdpError::Clipboard(reason)),
            }.map_err(|_| RdpError::Clipboard("channel operation"))?;
            let frame = self.active.process_svc_processor_messages(messages)
                .map_err(|_| RdpError::Clipboard("channel encoding"))?;
            self.queue_write(frame);
        }
    }

    fn queue_write(&mut self, frame: Vec<u8>) {
        if !frame.is_empty() {
            self.writes.push_back(frame);
        }
    }

    async fn flush(&mut self) -> Result<(), RdpError> {
        while let Some(frame) = self.writes.front() {
            let written = self.framed.get_inner_mut().0.write(&frame[self.write_offset..])
                .await.map_err(transport_error)?;
            if written == 0 {
                return Err(RdpError::Transport(io::ErrorKind::WriteZero));
            }
            self.write_offset += written;
            self.needs_flush = true;
            if self.write_offset == frame.len() {
                self.writes.pop_front();
                self.write_offset = 0;
            }
        }
        if self.needs_flush {
            self.framed.get_inner_mut().0.flush().await.map_err(transport_error)?;
            self.needs_flush = false;
        }
        Ok(())
    }

    fn add_damage(&mut self, rect: InclusiveRectangle) -> Result<(), RdpError> {
        if rect.left > rect.right || rect.top > rect.bottom
            || rect.right >= self.image.width() || rect.bottom >= self.image.height()
        {
            return Err(RdpError::Geometry(PixelError::OutOfBounds));
        }
        let rect = Rect::new(i32::from(rect.left), i32::from(rect.top),
            i32::from(rect.right) - i32::from(rect.left) + 1,
            i32::from(rect.bottom) - i32::from(rect.top) + 1);
        self.damage = Some(self.damage.map_or(rect, |previous| previous.union(&rect)));
        Ok(())
    }

    fn take_event(&mut self, target: &mut dyn PixelTarget) -> Result<Option<RdpEvent>, RdpError> {
        if let Some(Err(error)) = self.termination {
            return Err(error);
        }
        if self.desktop_pending {
            let (width, height) = self.desktop();
            if target.size() != (width, height) {
                target.resize(width, height).map_err(RdpError::Geometry)?;
            }
            if target.size() != (width, height) {
                return Err(RdpError::Geometry(PixelError::GeometryRejected));
            }
            self.desktop_pending = false;
            return Ok(Some(RdpEvent::Desktop { width, height }));
        }
        if let Some(rect) = self.damage {
            if target.size() != self.desktop() {
                return Err(RdpError::Geometry(PixelError::GeometryRejected));
            }
            let stride = usize::from(self.image.width()) * 4;
            let row_bytes = usize::try_from(rect.width).map_err(|_| RdpError::Geometry(PixelError::InvalidRect))? * 4;
            let mut window = target.rect_mut(rect).map_err(RdpError::Geometry)?;
            for y in 0..rect.height {
                let offset = usize::try_from(rect.y + y).map_err(|_| RdpError::Geometry(PixelError::InvalidRect))? * stride
                    + usize::try_from(rect.x).map_err(|_| RdpError::Geometry(PixelError::InvalidRect))? * 4;
                let row = self.image.data().get(offset..offset + row_bytes)
                    .ok_or(RdpError::Geometry(PixelError::OutOfBounds))?;
                if !window.put_row(y, row) {
                    return Err(RdpError::Geometry(PixelError::OutOfBounds));
                }
            }
            target.damage(rect);
            self.damage = None;
            return Ok(Some(RdpEvent::Painted));
        }
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        if self.termination.is_some() && !self.closed_reported {
            self.closed_reported = true;
            return Ok(Some(RdpEvent::Closed));
        }
        Ok(None)
    }
}

/// Shared by synchronous viewer admission and the session's final send check.
/// A successfully encoded PDU is not evidence of server support: only the Input
/// flags received in that server's DemandActive authorize optional input kinds.
pub fn validate_input_flags(flags: InputFlags, events: &[FastPathInputEvent]) -> Result<(), RdpError> {
    if !events.is_empty() && !flags.intersects(InputFlags::FASTPATH_INPUT | InputFlags::FASTPATH_INPUT_2) {
        return Err(RdpError::Unsupported("fast-path input"));
    }
    for event in events {
        let (required, feature) = match event {
            FastPathInputEvent::KeyboardEvent(..) => (InputFlags::SCANCODES, "scancode input"),
            FastPathInputEvent::UnicodeKeyboardEvent(..) => (InputFlags::UNICODE, "Unicode input"),
            FastPathInputEvent::MouseEventEx(_) => (InputFlags::MOUSEX, "extended mouse input"),
            FastPathInputEvent::MouseEventRel(_) => (InputFlags::MOUSE_RELATIVE, "relative mouse input"),
            FastPathInputEvent::QoeEvent(_) => (InputFlags::TS_QOE_TIMESTAMPS, "input QoE timestamps"),
            FastPathInputEvent::MouseEvent(mouse) if mouse.flags.contains(PointerFlags::HORIZONTAL_WHEEL) => {
                (InputFlags::TS_MOUSE_HWHEEL, "horizontal mouse wheel")
            }
            FastPathInputEvent::MouseEvent(_) | FastPathInputEvent::SyncEvent(_) => (InputFlags::empty(), "baseline input"),
        };
        if !flags.contains(required) {
            return Err(RdpError::Unsupported(feature));
        }
    }
    Ok(())
}

fn validate_desktop(width: u16, height: u16) -> Result<(), RdpError> {
    // RDP desktop / Display Control dimensions; check before DecodedImage's
    // allocation, including server-negotiated and reactivation geometry.
    if !(200..=8192).contains(&width) || !(200..=8192).contains(&height) {
        return Err(RdpError::Geometry(PixelError::InvalidRect));
    }
    Ok(())
}

fn transport_error(error: io::Error) -> RdpError {
    RdpError::Transport(error.kind())
}

/// Whether a transport failure means the peer is already gone. Only the close
/// handshake, once our own shutdown request is on the wire, may call this a
/// normal end - both while waiting for the server's reply and for the TLS
/// close_notify that follows one. The same error during a live session, or
/// before that request is sent, is a real failure and stays one.
fn peer_hung_up(error: &RdpError) -> bool {
    matches!(
        error,
        RdpError::Transport(
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
        )
    )
}

fn connector_error(error: ConnectorError) -> RdpError {
    if matches!(error.kind(), ConnectorErrorKind::Credssp(_) | ConnectorErrorKind::AccessDenied) {
        return RdpError::Authentication;
    }
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(error) = cause.downcast_ref::<io::Error>() {
            return RdpError::Transport(error.kind());
        }
        source = cause.source();
    }
    RdpError::Protocol("connection sequence")
}

fn connector_config(username: String, password: String, width: u16, height: u16) -> Config {
    use ironrdp_pdu::gcc::KeyboardType;
    use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
    Config {
        credentials: Credentials::UsernamePassword { username, password },
        domain: None,
        enable_tls: false,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        // Match the viewer's explicit US ASCII physical-shortcut mapping;
        // ordinary text still uses Unicode rather than layout-dependent keys.
        keyboard_layout: 0x0000_0409,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width, height },
        bitmap: None,
        client_build: 0,
        client_name: "rd-engine".to_owned(),
        client_dir: String::new(),
        platform: if cfg!(windows) { MajorPlatformType::WINDOWS }
            else if cfg!(target_os = "macos") { MajorPlatformType::MACINTOSH }
            else { MajorPlatformType::UNIX },
        enable_server_pointer: true,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        // Match the official interactive client's MPPC 64K default. Its x224
        // path does not yet share bulk history with fast-path decoding, so the
        // upstream client explicitly avoids stateful XCRUSH by default.
        compression_type: Some(CompressionType::K64),
        pointer_software_rendering: true,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

#[cfg(test)]
mod tests {
    //! The post-request wait lives in `close_handshake`, which needs a negotiated
    //! session; driving that needs a real peer, so no in-repo test covers it.
    //! What is pinned here is the decision the wait
    //! delegates to `peer_hung_up`, together with the real socket failures that
    //! reach it through `transport_error`: a hangup ends the close normally, and
    //! every other failure still reaches the caller.

    use super::{RdpError, peer_hung_up, transport_error};
    use std::io;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::{TcpListener, TcpStream};

    /// After our own shutdown request the peer hangs up instead of answering.
    /// Those transport failures end the close normally; everything else - a
    /// missing reply, a protocol failure, an authentication failure, or an
    /// unrelated transport failure - must still reach the caller as an error.
    #[test]
    fn requested_close_accepts_peer_hangup_only() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(
                peer_hung_up(&RdpError::Transport(kind)),
                "peer hangup {kind:?} must end a requested close normally"
            );
        }
        for error in [
            RdpError::CloseTimeout,
            RdpError::Protocol("server disconnect error"),
            RdpError::Authentication,
            RdpError::Closed,
            RdpError::Transport(io::ErrorKind::ConnectionRefused),
            RdpError::Transport(io::ErrorKind::TimedOut),
            RdpError::Transport(io::ErrorKind::WriteZero),
        ] {
            assert!(!peer_hung_up(&error), "{error} must stay a close failure");
        }
    }

    /// The decision above holds for a genuine hangup, not just a synthesized
    /// kind: a real peer close surfaces `UnexpectedEof` from an exact read,
    /// which is what the library's framed read reports here, and it reaches the
    /// classifier through the session's own mapping.
    #[tokio::test]
    async fn peer_hangup_on_loopback_classifies_as_normal_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        peer.await.unwrap();

        let mut byte = [0u8; 1];
        let error = client.read_exact(&mut byte).await.unwrap_err();
        assert!(peer_hung_up(&transport_error(error)), "a peer close after our request is the normal end");
    }

    /// The counterpart: a transport failure that is not a hangup stays one, so
    /// the close path is not an unconditional success.
    #[tokio::test]
    async fn transport_failure_without_peer_hangup_stays_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let error = TcpStream::connect(addr).await.unwrap_err();
        assert!(!peer_hung_up(&transport_error(error)), "a refused connection must not close successfully");
    }
}
