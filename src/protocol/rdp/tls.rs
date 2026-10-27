//! TLS boundary for IronRDP. Certificate parsing follows the official screenshot
//! example at 11a0810cfbbabd8b8023875a05e3041216d4b01b; see LICENSE-IRONRDP-MIT.
//! Unlike that example, neither certificates nor handshake signatures are skipped.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf as _, BytesMut};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_cert::der::Decode as _;

use super::{RdpError, RdpTrust, TrustFailure};

pub(super) type TlsStream = tokio_rustls::client::TlsStream<PrefixedTcp>;

/// Bytes read ahead by the X.224 framer still belong to the transport being
/// upgraded. Feed them into TLS, never into the decrypted RDP framer.
pub(super) struct PrefixedTcp {
    stream: TcpStream,
    prefix: BytesMut,
}

impl PrefixedTcp {
    pub(super) fn new(stream: TcpStream, prefix: BytesMut) -> Self {
        Self { stream, prefix }
    }
}

impl AsyncRead for PrefixedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() && buf.remaining() != 0 {
            let len = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..len]);
            this.prefix.advance(len);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedTcp {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

pub(super) async fn config(trust: RdpTrust) -> Result<Arc<ClientConfig>, RdpError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| RdpError::Trust(TrustFailure::TlsConfiguration))?;
    let mut config = match trust {
        RdpTrust::SystemRoots => {
            // OS certificate enumeration can block; do not run it on a Tokio
            // worker. This finite OS call has no cancellation API. Cancellation
            // here drops no live RDP connection (TCP is opened only afterwards).
            let roots = tokio::task::spawn_blocking(|| {
                let loaded = rustls_native_certs::load_native_certs();
                if !loaded.errors.is_empty() || loaded.certs.is_empty() {
                    return Err(RdpError::Trust(TrustFailure::RootsUnavailable));
                }
                let mut roots = rustls::RootCertStore::empty();
                for cert in loaded.certs {
                    roots.add(cert).map_err(|_| RdpError::Trust(TrustFailure::RootsUnavailable))?;
                }
                Ok(roots)
            })
            .await
            .map_err(|_| RdpError::Trust(TrustFailure::RootsUnavailable))??;
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        RdpTrust::CertificateSha256(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificate { pin, provider }))
            .with_no_client_auth(),
    };
    // CredSSP does not support TLS session resumption (MS-CSSP 1.3).
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

pub(super) async fn upgrade(
    stream: PrefixedTcp,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
) -> Result<(TlsStream, Vec<u8>), RdpError> {
    let stream = TlsConnector::from(config)
        .connect(server_name, stream)
        .await
        .map_err(handshake_error)?;
    let cert = stream.get_ref().1.peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or(RdpError::Trust(TrustFailure::MissingCertificate))?;
    // Same x509-cert extraction as the official example / ironrdp-tls helper;
    // there is no local ASN.1/DER parser.
    let cert = x509_cert::Certificate::from_der(cert.as_ref())
        .map_err(|_| RdpError::Trust(TrustFailure::MalformedCertificate))?;
    let public_key = cert.tbs_certificate.subject_public_key_info.subject_public_key
        .as_bytes()
        .ok_or(RdpError::Trust(TrustFailure::MalformedCertificate))?
        .to_owned();
    Ok((stream, public_key))
}

fn handshake_error(error: io::Error) -> RdpError {
    if let Some(error) = error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        match error {
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
                return RdpError::Trust(TrustFailure::CertificateRejected);
            }
            _ => return RdpError::Protocol("TLS handshake"),
        }
    }
    RdpError::Transport(error.kind())
}

#[derive(Debug)]
struct PinnedCertificate {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if fingerprint.as_ref() != self.pin {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // An explicit leaf pin replaces PKI name/chain trust, not proof that
        // the peer holds the private key: both signature callbacks verify it.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
