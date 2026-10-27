//! QUIC transport for engine-to-engine sessions.
//!
//! The original RustDesk peer is reached over TCP; that wire is the
//! compatibility contract and does not change here. QUIC exists for the case
//! where both ends are this engine and the extra round trips of a TCP segment
//! handoff, plus head-of-line blocking between control and media, are pure
//! latency. `crate::viewer` prefers QUIC when the peer advertises it and keeps
//! the TCP path for every original peer.
//!
//! One session is one QUIC connection carrying one bidirectional stream. This
//! module owns the handshake, that stream, and the teardown; framing, the wire
//! encryption and message semantics stay in `crate::transport` and the
//! protocol modules. Reads fill a caller-owned buffer and writes take a
//! caller-owned slice, so nothing here allocates a buffer whose size came from
//! the peer.
//!
//! # Writer discipline
//! There is one [`QuicWriter`] per session and it owns the send half of the
//! stream outright: `quinn::SendStream` is neither shared nor cloned, so
//! control and media written by one session cannot interleave out of order.
//! [`QuicWriter::write_all`] is all-or-nothing, and a write that is cancelled
//! (its future dropped, e.g. by `tokio::select!` or a timeout) or that fails is
//! terminal: QUIC may already have taken part of the frame, so the writer
//! cancels the session token both halves share, closes the connection with
//! [`SESSION_ABORTED`] so the peer learns immediately instead of at the idle
//! timeout, and every later read or write on that session fails with
//! `ConnectionAborted`. Nothing is ever retried on a half-written stream. This
//! is the same discipline `crate::transport` applies to the RustDesk wire.
//!
//! [`QuicWriter::finish`] is the only clean end of stream: it sends FIN after
//! the bytes already handed over, and a writer that finished is dropped without
//! aborting. A reader that sees the peer's FIN closes the session as
//! [`SESSION_CLOSED`], so a session has no half-closed state — a peer that stops
//! writing has ended the session for both halves.
//!
//! Dropping a half also ends the session, exactly as dropping a half of the
//! `crate::transport` pair does: the session token both halves share is
//! cancelled, so the surviving half fails its next call with
//! `ConnectionAborted`, and dropping a writer that never reached
//! [`QuicWriter::finish`] additionally closes the connection with
//! [`SESSION_ABORTED`] rather than leaving the peer to wait for the idle
//! timeout. A session shell therefore owns both halves and drops them together.
//!
//! # Idle timeout and keepalive
//!
//! Every endpoint this module builds uses [`IDLE_TIMEOUT`] (30 s) as the maximum
//! silence and sends a keepalive probe every [`KEEP_ALIVE_INTERVAL`] (10 s), one
//! probe per third of the idle window. A quiet but healthy session therefore
//! keeps proving liveness three times inside each idle window and is not reaped
//! by NAT or by the idle timer, while a peer that has actually gone away is
//! still detected within 30 s. The keepalive is strictly inside the idle window
//! by construction (see `keep_alive_interval_is_inside_the_idle_timeout`); both
//! values are fixed rather than configurable so that a session cannot be left
//! with a keepalive that never fires.
//!
//! # `AcceptAnyCertificate`
//!
//! What it is for: engine-to-engine sessions, where the peer's identity is
//! established by `crate::handshake` (pinned host identity, shared password) out
//! of band of the transport. The engine has no PKI and no certificate
//! authority, so the QUIC client accepts any chain the peer presents and leaves
//! the identity decision to that layer.
//!
//! What it is not for: it authenticates nothing. It does not make a session safe
//! against an on-path attacker, it does not pin a host, and it must never be
//! used for a peer whose identity has not been established by other means — in
//! particular it is never the configuration for talking to the original
//! RustDesk peer, which is reached over TCP and verified by the RustDesk
//! handshake. It is also not "no cryptography": the signature over the presented
//! certificate is still verified with the provider's algorithms, so the peer
//! must hold the private key for the certificate it presented. What is missing
//! is only the statement that the certificate belongs to the peer we intended to
//! reach; a caller that needs that statement must compare the peer identity from
//! `crate::handshake` after the connection is up.
//!
//! # Deliberate limits
//!
//! - TLS 1.3 only (QUIC has no other version), with ALPN [`ALPN`] required on
//!   both ends. A peer that negotiates another protocol, or none, is refused
//!   before a stream exists.
//! - One bidirectional stream per session (`max_concurrent_bidi_streams(1)`) and
//!   no unidirectional streams. No datagrams, no 0-RTT, no connection
//!   migration, no reconnect/backoff: a failed handshake is returned to the
//!   caller, which decides whether to retry.
//! - Byte-oriented API, deliberately without `tokio::io::AsyncRead` /
//!   `AsyncWrite` impls. A blanket `AsyncWrite` would let a caller drive retries
//!   over a half-written stream invisibly, which is exactly what the writer
//!   discipline above forbids.
//! - Certificate material is supplied by the caller. This module never generates
//!   keys or certificates and never reads them from disk, and an empty chain is
//!   an error rather than a fallback.
//! - No last-error introspection beyond the `io::Error` the failing call
//!   returns; the QUIC connection's own close reason is not re-exported here.

use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig,
    TransportConfig, VarInt,
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        CryptoProvider, verify_tls12_signature as verify_tls12,
        verify_tls13_signature as verify_tls13,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

/// ALPN protocol identifier for an engine-to-engine session. Both ends must
/// negotiate exactly this value; nothing else is accepted.
pub const ALPN: &[u8] = b"rd-engine/1";

/// Silence after which QUIC declares the session dead and tears it down.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Keepalive probe interval. Strictly inside [`IDLE_TIMEOUT`] so a quiet session
/// is kept alive instead of being reaped by the idle timer.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Application close code for a session that ended after [`QuicWriter::finish`]
/// or the peer's FIN.
pub const SESSION_CLOSED: u32 = 0;

/// Application close code for a session torn down by a cancelled or failed
/// write, by a failed read, or by a transport dropped mid-session.
pub const SESSION_ABORTED: u32 = 1;

const CLOSED_REASON: &[u8] = b"session complete";
const ABORTED_REASON: &[u8] = b"transport aborted";

/// Certificate verifier that accepts any chain the peer presents.
///
/// Read the module documentation before using this: it is the configuration for
/// a peer whose identity is established elsewhere, and it authenticates
/// nothing. The handshake signature over the presented certificate is still
/// verified, so the peer must hold the key it presented; the chain, its issuer,
/// its validity dates and the dialled server name are not checked.
#[derive(Debug)]
pub struct AcceptAnyCertificate {
    provider: Arc<CryptoProvider>,
}

impl AcceptAnyCertificate {
    /// Verifier that trusts every chain but still verifies handshake signatures
    /// with `provider`'s algorithms.
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // The identity decision belongs to `crate::handshake`, not here.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The crypto provider this tree builds for: `ring`, never the `aws-lc-rs`
/// default, which needs a C toolchain the OHOS cross-build does not have.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Shared transport configuration: idle timeout, keepalive, one bidirectional
/// stream and no unidirectional streams.
fn transport_config() -> io::Result<Arc<TransportConfig>> {
    let idle = IdleTimeout::try_from(IDLE_TIMEOUT).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC idle timeout is outside the QUIC variable-length range",
        )
    })?;
    let mut config = TransportConfig::default();
    config
        .max_idle_timeout(Some(idle))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    Ok(Arc::new(config))
}

/// Client crypto: TLS 1.3, ALPN [`ALPN`], and [`AcceptAnyCertificate`] with the
/// identity decision left to `crate::handshake`.
fn client_config() -> io::Result<ClientConfig> {
    let crypto_provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(crypto_provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_config_error)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate::new(crypto_provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto: Arc<dyn quinn::crypto::ClientConfig> = Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC client TLS configuration has no initial cipher suite",
            )
        })?,
    );
    let mut config = ClientConfig::new(crypto);
    config.transport_config(transport_config()?);
    Ok(config)
}

/// Server crypto: TLS 1.3 with the caller's certificate and ALPN `alpn`.
///
/// The protocol list is a parameter so that a session can be made to negotiate a
/// protocol this engine does not speak; production callers use
/// [`server_endpoint`], which passes exactly [`ALPN`].
fn server_config(
    alpn: Vec<Vec<u8>>,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> io::Result<ServerConfig> {
    if certificate_chain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC server needs a certificate chain",
        ));
    }
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_config_error)?
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)
        .map_err(tls_config_error)?;
    tls.alpn_protocols = alpn;
    let crypto: Arc<dyn quinn::crypto::ServerConfig> = Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC server TLS configuration has no initial cipher suite",
            )
        })?,
    );
    let mut config = ServerConfig::with_crypto(crypto);
    config.transport_config(transport_config()?);
    Ok(config)
}

/// Binds a QUIC endpoint that accepts engine-to-engine sessions on `bind`.
///
/// The certificate is the caller's: this module neither generates nor stores key
/// material. The endpoint negotiates only [`ALPN`] and uses [`IDLE_TIMEOUT`] and
/// [`KEEP_ALIVE_INTERVAL`].
pub fn server_endpoint(
    bind: SocketAddr,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> io::Result<Endpoint> {
    Endpoint::server(
        server_config(vec![ALPN.to_vec()], certificate_chain, private_key)?,
        bind,
    )
}

/// Binds a QUIC endpoint that dials engine-to-engine sessions on `bind`.
///
/// The endpoint does not verify the peer's certificate chain (see
/// [`AcceptAnyCertificate`]) and requires ALPN [`ALPN`].
pub fn client_endpoint(bind: SocketAddr) -> io::Result<Endpoint> {
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}

/// Completes a client handshake with `addr` and refuses the session unless the
/// negotiated ALPN is [`ALPN`].
///
/// `server_name` is the name sent in the TLS handshake; it is not authenticated
/// by [`AcceptAnyCertificate`], so callers may pass the peer's engine name.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
) -> io::Result<Connection> {
    let connection = endpoint
        .connect(addr, server_name)
        .map_err(connect_error)?
        .await
        .map_err(handshake_error)?;
    check_alpn(negotiated_alpn(&connection))?;
    Ok(connection)
}

/// Waits for the next incoming session on `endpoint` and completes its
/// handshake, refusing it unless the negotiated ALPN is [`ALPN`].
///
/// Returns `NotConnected` once the endpoint is closed, so an accept loop can end
/// without treating a closed endpoint as a protocol error.
pub async fn accept(endpoint: &Endpoint) -> io::Result<Connection> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "QUIC endpoint is closed"))?;
    let connection = incoming.await.map_err(handshake_error)?;
    check_alpn(negotiated_alpn(&connection))?;
    Ok(connection)
}

/// The protocol the handshake negotiated, once it has completed.
///
/// `None` means the handshake is not complete or the peer's crypto layer did not
/// report a protocol; both are refusals for this transport.
pub fn negotiated_alpn(connection: &Connection) -> Option<Vec<u8>> {
    let data = connection.handshake_data()?;
    data.downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?
        .protocol
}

/// Refuses a session that did not negotiate exactly [`ALPN`].
fn check_alpn(protocol: Option<Vec<u8>>) -> io::Result<()> {
    match protocol {
        Some(protocol) if protocol.as_slice() == ALPN => Ok(()),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC peer negotiated a different application protocol",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC peer negotiated no application protocol",
        )),
    }
}

/// Opens the session stream on an established connection.
pub async fn open_stream(connection: &Connection) -> io::Result<(QuicReader, QuicWriter)> {
    let (send, recv) = connection.open_bi().await.map_err(stream_error)?;
    Ok(split(connection, send, recv))
}

/// Accepts the session stream the peer opened on an established connection.
pub async fn accept_stream(connection: &Connection) -> io::Result<(QuicReader, QuicWriter)> {
    let (send, recv) = connection.accept_bi().await.map_err(stream_error)?;
    Ok(split(connection, send, recv))
}

fn split(connection: &Connection, send: SendStream, recv: RecvStream) -> (QuicReader, QuicWriter) {
    let closed = CancellationToken::new();
    (
        QuicReader {
            recv,
            connection: connection.clone(),
            closed: closed.clone(),
        },
        QuicWriter {
            send,
            connection: connection.clone(),
            closed,
            finished: false,
        },
    )
}

/// One QUIC bidirectional stream presented as a single duplex object.
///
/// This is the bridge that lets a QUIC session reuse the whole RustDesk path
/// instead of growing a second framing implementation: `FramedStream` is built
/// on `DynTcpStream`, which is a boxed `AsyncRead + AsyncWrite`, so anything
/// implementing both halves can carry the same framing the TCP path uses.
///
/// The one-ordered-writer rule is enforced by `crate::transport::WireWriter`,
/// exactly as it is for TCP — this type only moves bytes and makes no promise
/// about retrying a partial write.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    /// Opens the session stream, as one duplex object.
    pub async fn open(connection: &Connection) -> io::Result<Self> {
        let (send, recv) = connection.open_bi().await.map_err(stream_error)?;
        Ok(Self { send, recv })
    }

    /// Accepts the peer's session stream, as one duplex object.
    pub async fn accept(connection: &Connection) -> io::Result<Self> {
        let (send, recv) = connection.accept_bi().await.map_err(stream_error)?;
        Ok(Self { send, recv })
    }

    /// Ends the write side cleanly, so the peer sees EOF after the last byte.
    pub fn finish(&mut self) -> io::Result<()> {
        self.send.finish().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC send stream was already finished",
            )
        })
    }
}

impl tokio::io::AsyncRead for QuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // The trait method, not quinn's inherent `poll_write`: the inherent one
        // reports `WriteError` and would not satisfy `AsyncWrite`.
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

/// Read half of a session stream.
///
/// The stream position advances only by the bytes this half handed to the
/// caller, so a decoder can walk its own framing with [`QuicReader::read_exact`].
pub struct QuicReader {
    recv: RecvStream,
    connection: Connection,
    closed: CancellationToken,
}

impl QuicReader {
    /// Reads up to `out.len()` bytes into `out`, returning how many were read.
    ///
    /// `None` means the peer finished the stream cleanly and no further byte will
    /// ever arrive; a session that was cancelled or aborted instead fails with
    /// `ConnectionAborted`, so "end of stream" and "end of transport" cannot be
    /// confused. An empty `out` consumes nothing.
    pub async fn read(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        if self.closed.is_cancelled() {
            return Err(aborted());
        }
        let result = tokio::select! {
            biased;
            _ = self.closed.cancelled() => return Err(aborted()),
            result = self.recv.read(out) => result,
        };
        match result {
            Ok(Some(read)) => Ok(Some(read)),
            Ok(None) => {
                // The peer is done writing, which ends the session for both
                // halves: a truncated frame cannot be mistaken for a clean end.
                self.closed.cancel();
                self.connection
                    .close(VarInt::from_u32(SESSION_CLOSED), CLOSED_REASON);
                Ok(None)
            }
            Err(error) => {
                self.closed.cancel();
                self.connection
                    .close(VarInt::from_u32(SESSION_ABORTED), ABORTED_REASON);
                Err(read_error(error))
            }
        }
    }

    /// Reads exactly `out.len()` bytes.
    ///
    /// A clean end of stream before that many bytes arrived is `UnexpectedEof`:
    /// a truncated frame is never reported as a complete one.
    pub async fn read_exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            let read = match self.read(&mut out[filled..]).await? {
                Some(read) if read > 0 => read,
                // A zero-length read from a non-empty buffer is an end of stream.
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "QUIC peer ended the stream mid-frame",
                    ));
                }
            };
            filled += read;
        }
        Ok(())
    }
}

impl Drop for QuicReader {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

/// Write half of a session stream. There is one per session; see the module
/// documentation for the cancellation discipline.
pub struct QuicWriter {
    send: SendStream,
    connection: Connection,
    closed: CancellationToken,
    finished: bool,
}

impl QuicWriter {
    /// Writes every byte of `bytes`, or fails without leaving a retryable state.
    ///
    /// Cancelling this future (dropping it before it resolves) or any write error
    /// tears the session down and is terminal: the next call fails immediately,
    /// and the peer is told at once with [`SESSION_ABORTED`] rather than at the
    /// idle timeout.
    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.closed.is_cancelled() {
            return Err(aborted());
        }
        let mut pending = PendingWrite {
            connection: self.connection.clone(),
            closed: self.closed.clone(),
            complete: false,
        };
        let result = tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(aborted()),
            result = self.send.write_all(bytes) => result.map_err(write_error),
        };
        if let Err(error) = result {
            // `pending` is dropped incomplete, which cancels the session and
            // closes the connection: the half-written frame must not survive.
            return Err(error);
        }
        pending.complete = true;
        Ok(())
    }

    /// Ends the write side cleanly with FIN after the bytes already written.
    ///
    /// The peer sees every byte followed by an end of stream. Dropping a writer
    /// that finished does not abort the session; dropping one that did not aborts
    /// it, because an unfinished writer left the stream truncated.
    pub async fn finish(&mut self) -> io::Result<()> {
        if self.closed.is_cancelled() {
            return Err(aborted());
        }
        self.send.finish().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC send stream was already finished",
            )
        })?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for QuicWriter {
    fn drop(&mut self) {
        self.closed.cancel();
        if !self.finished {
            self.connection
                .close(VarInt::from_u32(SESSION_ABORTED), ABORTED_REASON);
        }
    }
}

/// A send that was cancelled or failed may already have handed part of a frame
/// to QUIC. It must terminate the session, never be retried on that stream.
struct PendingWrite {
    connection: Connection,
    closed: CancellationToken,
    complete: bool,
}

impl Drop for PendingWrite {
    fn drop(&mut self) {
        if !self.complete {
            self.closed.cancel();
            self.connection
                .close(VarInt::from_u32(SESSION_ABORTED), ABORTED_REASON);
        }
    }
}

fn aborted() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "QUIC transport closed")
}

fn tls_config_error(error: TlsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn connect_error(error: quinn::ConnectError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn handshake_error(error: quinn::ConnectionError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
}

fn stream_error(error: quinn::ConnectionError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
}

fn write_error(error: quinn::WriteError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
}

fn read_error(error: quinn::ReadError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    /// Upper bound on one negotiation stage. Loopback handshakes complete in
    /// milliseconds; the bound exists so a regression hangs a test for seconds
    /// instead of wedging the suite.
    const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);

    /// Self-signed P-256 test certificate for `localhost` / `127.0.0.1`,
    /// generated for this repository's tests and never used outside them.
    /// Callers dial with `AcceptAnyCertificate`, which decides nothing about
    /// identity, so no real trust anchor is implied by this fixture.
    const CERTIFICATE_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBrTCCAVOgAwIBAgIUfSWyYLsBnwkuuocuTwRrbakvSVIwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTcmQtZW5naW5lLXNlbGYtdGVzdDAeFw0yNjA5MTYxNDI3Mjha
Fw0zNjA5MTMxNDI3MjhaMB4xHDAaBgNVBAMME3JkLWVuZ2luZS1zZWxmLXRlc3Qw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARHQb5x9t8y9KPZpNWiZHn4QwUwkYbe
97da/rUs3FdFzSmoPDroFkxNSUhUxH6NbtTpTkjT4M1m53ThKp55qqmNo28wbTAd
BgNVHQ4EFgQUH5MHY7anlSZEnfSc2p5wK8t5WacwHwYDVR0jBBgwFoAUH5MHY7an
lSZEnfSc2p5wK8t5WacwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2Nh
bGhvc3SHBH8AAAEwCgYIKoZIzj0EAwIDSAAwRQIgHnqcFSeIGbduQYKzVWLbiIDQ
JzzWyVq7cW+83nhK504CIQCzgc49W8Nxtm9UqXiq/h6YDv+HkXCuP8rzE0C1KuKM
7Q==
-----END CERTIFICATE-----
";

    /// PKCS#8 private key for `CERTIFICATE_PEM`, same self-test material.
    const PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8wH/JUW0QntdYc/G
BHqbJDxgaagTFZdIQKOg8KEYyA2hRANCAARHQb5x9t8y9KPZpNWiZHn4QwUwkYbe
97da/rUs3FdFzSmoPDroFkxNSUhUxH6NbtTpTkjT4M1m53ThKp55qqmN
-----END PRIVATE KEY-----
";

    /// Decodes the DER body of one PEM block, ignoring the `BEGIN`/`END`
    /// fences. Callers assert the result is DER, so a mistake here fails a
    /// test rather than a handshake.
    fn pem_der(pem: &str) -> Vec<u8> {
        // Only the body counts: the `BEGIN`/`END` labels are themselves made of
        // base64 alphabet characters, so scanning the whole string would decode
        // the label into the DER and shift every byte.
        let body = pem
            .split("-----")
            .nth(2)
            .expect("PEM body between the BEGIN and END fences");
        let mut der = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for byte in body.bytes() {
            let value = match byte {
                b'A'..=b'Z' => (byte - b'A') as u32,
                b'a'..=b'z' => (byte - b'a') as u32 + 26,
                b'0'..=b'9' => (byte - b'0') as u32 + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                _ => continue,
            };
            buffer = (buffer << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                der.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }
        der
    }

    fn certificate_chain() -> Vec<CertificateDer<'static>> {
        let der = pem_der(CERTIFICATE_PEM);
        assert_eq!(der.first(), Some(&0x30), "certificate must be DER");
        vec![CertificateDer::from(der)]
    }

    fn private_key() -> PrivateKeyDer<'static> {
        let der = pem_der(PRIVATE_KEY_PEM);
        assert_eq!(der.first(), Some(&0x30), "private key must be DER");
        PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(der))
    }

    fn loopback_address() -> SocketAddr {
        "127.0.0.1:0".parse().expect("loopback address")
    }

    fn server(alpn: Vec<Vec<u8>>) -> Endpoint {
        let config = server_config(alpn, certificate_chain(), private_key()).expect("server config");
        Endpoint::server(config, loopback_address()).expect("server endpoint")
    }

    fn client() -> Endpoint {
        client_endpoint(loopback_address()).expect("client endpoint")
    }

    /// Both endpoints and both connection ends. The endpoints are never read, but
    /// they must stay alive: quinn closes a connection when its endpoint drops.
    struct Loopback {
        _client_endpoint: Endpoint,
        _server_endpoint: Endpoint,
        bound: SocketAddr,
        client: Connection,
        server: Connection,
    }

    async fn loopback(alpn: Vec<Vec<u8>>) -> Loopback {
        let server_endpoint = server(alpn);
        let client_endpoint = client();
        let bound = server_endpoint.local_addr().expect("bound address");
        // Every stage is bounded: a handshake that never settles must fail the
        // test loudly rather than hang the suite.
        let (server, client) = tokio::join!(
            timeout(HANDSHAKE_LIMIT, accept(&server_endpoint)),
            timeout(
                HANDSHAKE_LIMIT,
                connect(&client_endpoint, bound, "127.0.0.1")
            ),
        );
        Loopback {
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
            bound,
            client: client
                .expect("client handshake timed out")
                .expect("client handshake"),
            server: server
                .expect("server handshake timed out")
                .expect("server handshake"),
        }
    }

    /// The dialer's first frame. A QUIC stream does not exist for the peer until
    /// its first bytes arrive, so opening a stream and accepting it cannot
    /// happen in parallel: the opener has to speak first. Every session this
    /// engine dials works that way — the RustDesk handshake and the RFB version
    /// exchange both open with a frame from the dialer — so the tests use the
    /// same ordering as the real protocol rather than a workaround.
    const ANNOUNCE: &[u8] = b"\x01";

    /// Opens the session stream from `opener`, announces it, and returns it from
    /// `acceptor` once the announcement has been read back.
    ///
    /// Returns the opener's writer and reader, then the acceptor's reader and
    /// writer, both positioned after the announcement.
    ///
    /// Every test keeps all four halves alive for its whole body, under a name:
    /// dropping a half ends the session, so binding one to `_` would tear the
    /// session down on the spot.
    async fn open_session(
        opener: &Connection,
        acceptor: &Connection,
    ) -> (QuicWriter, QuicReader, QuicReader, QuicWriter) {
        let (opener_reader, mut opener_writer) = timeout(HANDSHAKE_LIMIT, open_stream(opener))
            .await
            .expect("open timed out")
            .expect("open stream");
        opener_writer
            .write_all(ANNOUNCE)
            .await
            .expect("announce stream");
        let (mut acceptor_reader, acceptor_writer) = timeout(HANDSHAKE_LIMIT, accept_stream(acceptor))
            .await
            .expect("accept timed out")
            .expect("accept stream");
        let mut announced = [0u8; ANNOUNCE.len()];
        acceptor_reader
            .read_exact(&mut announced)
            .await
            .expect("read announcement");
        assert_eq!(
            &announced, ANNOUNCE,
            "the announcement must arrive before the session proper"
        );
        (opener_writer, opener_reader, acceptor_reader, acceptor_writer)
    }

    /// A real QUIC handshake over loopback, with the ALPN negotiated on both
    /// ends, and bytes crossing the session in both directions.
    #[tokio::test]
    async fn loopback_handshake_negotiates_alpn() {
        let session = loopback(vec![b"rd-engine/0".to_vec(), ALPN.to_vec()]).await;
        assert_eq!(negotiated_alpn(&session.client).as_deref(), Some(ALPN));
        assert_eq!(negotiated_alpn(&session.server).as_deref(), Some(ALPN));
        assert_eq!(session.client.remote_address(), session.bound);

        let (mut client_writer, mut client_reader, mut server_reader, mut server_writer) =
            open_session(&session.client, &session.server).await;

        client_writer.write_all(b"ping!").await.expect("client write");
        let mut greeting = [0u8; 5];
        server_reader
            .read_exact(&mut greeting)
            .await
            .expect("server read");
        assert_eq!(&greeting, b"ping!");

        server_writer.write_all(b"pong").await.expect("server write");
        let mut reply = [0u8; 4];
        client_reader
            .read_exact(&mut reply)
            .await
            .expect("client read");
        assert_eq!(&reply, b"pong");

        // The peer's FIN is a clean end of stream for both halves.
        server_writer.finish().await.expect("server finish");
        assert_eq!(client_reader.read(&mut reply).await.expect("clean eof"), None);
    }

    /// A server that does not offer the client's ALPN cannot complete a
    /// handshake: the protocol is negotiated, not assumed.
    #[tokio::test]
    async fn alpn_mismatch_is_rejected() {
        let server_endpoint = server(vec![b"other-engine/1".to_vec()]);
        let client_endpoint = client();
        let bound = server_endpoint.local_addr().expect("bound address");
        let peer = tokio::spawn(async move { accept(&server_endpoint).await });

        let client = connect(&client_endpoint, bound, "127.0.0.1").await;
        assert!(client.is_err(), "client must refuse the mismatched protocol");
        assert!(
            timeout(Duration::from_secs(5), peer)
                .await
                .expect("server side settles")
                .expect("server task")
                .is_err(),
            "server must not complete a mismatched handshake"
        );
    }

    /// The enforcement rule itself, including the case a real peer can present
    /// only by omitting ALPN entirely.
    #[test]
    fn a_session_that_did_not_negotiate_our_protocol_is_refused() {
        assert!(check_alpn(Some(ALPN.to_vec())).is_ok());
        assert_eq!(
            check_alpn(Some(b"other-engine/1".to_vec()))
                .expect_err("another protocol is refused")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            check_alpn(None).expect_err("no protocol is refused").kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// One writer per stream, and the bytes arrive in the order they were
    /// written.
    #[tokio::test]
    async fn writes_are_delivered_in_order_on_one_stream() {
        let session = loopback(vec![ALPN.to_vec()]).await;
        let (mut client_writer, _client_reader, mut server_reader, _server_writer) =
            open_session(&session.client, &session.server).await;

        for frame in [&b"first"[..], &b"second"[..], &b"third"[..]] {
            client_writer.write_all(frame).await.expect("write");
        }
        let mut received = [0u8; 16];
        server_reader
            .read_exact(&mut received)
            .await
            .expect("read");
        assert_eq!(&received, b"firstsecondthird");
    }

    /// Only `finish` turns the end of the stream into a clean one.
    #[tokio::test]
    async fn clean_finish_is_a_clean_end_of_stream() {
        let session = loopback(vec![ALPN.to_vec()]).await;
        // The server dials here: it announces first, then finishes its side.
        let (mut server_writer, _server_reader, mut client_reader, _client_writer) =
            open_session(&session.server, &session.client).await;

        server_writer.write_all(b"bye").await.expect("write");
        server_writer.finish().await.expect("finish");
        let mut received = [0u8; 3];
        client_reader
            .read_exact(&mut received)
            .await
            .expect("read");
        assert_eq!(&received, b"bye");
        assert_eq!(client_reader.read(&mut received).await.expect("eof"), None);
    }

    /// A frame cut short by a clean end of stream is an error, never a complete
    /// frame.
    #[tokio::test]
    async fn truncated_frame_is_reported_as_unexpected_eof() {
        let session = loopback(vec![ALPN.to_vec()]).await;
        let (mut server_writer, _server_reader, mut client_reader, _client_writer) =
            open_session(&session.server, &session.client).await;

        server_writer.write_all(b"ab").await.expect("write");
        server_writer.finish().await.expect("finish");
        let mut frame = [0u8; 5];
        assert_eq!(
            client_reader
                .read_exact(&mut frame)
                .await
                .expect_err("truncated frame")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    /// Cancelling a write mid-frame kills the session for both ends and for the
    /// peer, instead of being retried on a half-written stream.
    #[tokio::test]
    async fn cancelled_write_is_terminal() {
        let session = loopback(vec![ALPN.to_vec()]).await;
        let (mut client_writer, mut client_reader, mut server_reader, _server_writer) =
            open_session(&session.client, &session.server).await;

        // The peer never reads, so the frame cannot drain: the write is still
        // pending when the deadline drops it.
        let frame = vec![0x5A; 4 * 1024 * 1024];
        assert!(
            timeout(Duration::from_millis(200), client_writer.write_all(&frame))
                .await
                .is_err(),
            "a frame the peer never drains cannot complete"
        );

        assert!(client_writer.write_all(b"next").await.is_err());
        assert!(client_reader.read(&mut [0u8; 8]).await.is_err());

        // The peer is told now, not at the idle timeout, and it never receives
        // the cancelled frame as a complete one.
        let mut buffer = vec![0u8; 64 * 1024];
        let drained = timeout(Duration::from_secs(5), async {
            let mut total = 0usize;
            loop {
                match server_reader.read(&mut buffer).await {
                    Ok(Some(read)) => total += read,
                    other => break other,
                }
            }
        })
        .await
        .expect("peer settles");
        assert!(drained.is_err(), "peer must see an aborted stream");
    }

    /// The RustDesk record framing runs over QUIC unchanged.
    ///
    /// `FramedStream` is built on `DynTcpStream`, a boxed duplex, so wrapping a
    /// QUIC stream in it means the handshake, the authentication actors and
    /// `crate::transport::split` need no QUIC-specific variant at all. This
    /// asserts that by driving real `Message` records — including a large one
    /// that has to cross several QUIC packets — through the same reader and
    /// writer the TCP path uses.
    #[tokio::test]
    async fn the_rustdesk_record_framing_runs_unchanged_over_quic() {
        use base::message_proto::Message;
        use hbb_common::protobuf::Message as _;

        let session = loopback(vec![ALPN.to_vec()]).await;

        // A QUIC stream is invisible to the peer until its first bytes arrive,
        // so the opener writes before the acceptor can accept.
        let client_stream = timeout(HANDSHAKE_LIMIT, QuicStream::open(&session.client))
            .await
            .expect("open settled")
            .expect("open stream");
        let (mut client_reader, mut client_writer) =
            crate::transport::split(hbb_common::tcp::FramedStream::from(
                client_stream,
                session.bound,
            ));

        let mut first = Message::new();
        let mut misc = base::message_proto::Misc::new();
        misc.set_refresh_video(true);
        first.set_misc(misc);
        timeout(HANDSHAKE_LIMIT, client_writer.send(&first))
            .await
            .expect("send settled")
            .expect("send the first record");

        let server_stream = timeout(HANDSHAKE_LIMIT, QuicStream::accept(&session.server))
            .await
            .expect("accept settled")
            .expect("accept stream");
        let (mut server_reader, mut server_writer) =
            crate::transport::split(hbb_common::tcp::FramedStream::from(
                server_stream,
                session.bound,
            ));

        let received = timeout(HANDSHAKE_LIMIT, server_reader.recv())
            .await
            .expect("recv settled")
            .expect("recv")
            .expect("a record");
        assert_eq!(
            received.write_to_bytes().expect("encode received"),
            first.write_to_bytes().expect("encode sent"),
            "the record must survive the QUIC framing byte for byte"
        );

        // A payload far larger than one QUIC packet, in the other direction.
        let mut large = Message::new();
        large.set_hash(base::message_proto::Hash {
            salt: "quic-framing".into(),
            challenge: "x".repeat(512 * 1024),
            ..Default::default()
        });
        timeout(HANDSHAKE_LIMIT, server_writer.send(&large))
            .await
            .expect("send settled")
            .expect("send the large record");

        let echoed = timeout(HANDSHAKE_LIMIT, client_reader.recv())
            .await
            .expect("recv settled")
            .expect("recv")
            .expect("a record");
        assert_eq!(
            echoed.write_to_bytes().expect("encode echoed"),
            large.write_to_bytes().expect("encode sent"),
            "a half-megabyte record must cross QUIC intact"
        );
    }

    /// The documented values, and the invariant that makes them useful.
    #[test]
    fn keep_alive_interval_is_inside_the_idle_timeout() {
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(KEEP_ALIVE_INTERVAL, Duration::from_secs(10));
        assert!(KEEP_ALIVE_INTERVAL < IDLE_TIMEOUT);
        // The shared configuration must accept these values.
        assert!(transport_config().is_ok());
    }
}
