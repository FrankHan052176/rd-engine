//! TLS boundary for IronRDP. Certificate parsing follows the official screenshot
//! example at 11a0810cfbbabd8b8023875a05e3041216d4b01b; see LICENSE-IRONRDP-MIT.
//! Unlike that example, neither certificates nor handshake signatures are skipped.
//!
//! A refused certificate is described here, where the check that refused it
//! still holds the peer's leaf: a failed handshake drops the connection, so this
//! is the only point at which the metadata a client asks its operator about can
//! be read. Neither verifier lets a certificate through that its own check
//! refused, and a build without a platform trust store refuses every one.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Buf as _, BytesMut};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_cert::der::Decode as _;
use x509_cert::time::Time;

use super::{CertificateChallenge, CertificateRejection, RdpError, RdpTrust, TrustFailure};

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
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// One connection attempt's trust configuration, and whether the platform could
/// back it at all.
pub(super) struct Setup {
    pub(super) config: Arc<ClientConfig>,
    /// This build could not load a platform trust store. The configuration then
    /// refuses every certificate and the handshake exists only so the peer's real
    /// leaf can be described; nothing can be accepted through it. The refusal it
    /// forces is a consequence of this fact, and the caller reports this one.
    pub(super) roots_unavailable: bool,
}

pub(super) async fn config(trust: RdpTrust, watch: CertificateWatch) -> Result<Setup, RdpError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| RdpError::Trust(TrustFailure::TlsConfiguration))?;
    let (mut config, roots_unavailable) = match trust {
        // An explicit leaf pin needs no platform root: that is what lets a client
        // reach a host whose certificate its operator accepted once on a target
        // whose own system trust store is missing.
        RdpTrust::CertificateSha256(pin) => (
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCertificate {
                    pin,
                    provider,
                    watch,
                }))
                .with_no_client_auth(),
            false,
        ),
        RdpTrust::SystemRoots => {
            let loaded = platform_roots().await;
            let roots_unavailable = loaded.is_err();
            let verifier: Arc<dyn ServerCertVerifier> = match loaded {
                Ok(roots) => {
                    let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
                        Arc::new(roots),
                        Arc::clone(&provider),
                    )
                    .build()
                    .map_err(|_| RdpError::Trust(TrustFailure::TlsConfiguration))?;
                    // The delegating verifier decides; this side only describes
                    // what it refused. The decision itself is unchanged.
                    Arc::new(ObservedCertificate {
                        verifier: Some(webpki),
                        provider,
                        watch,
                    })
                }
                // No platform roots: every certificate is refused here, after it
                // has been described for the client's own decision.
                Err(_) => Arc::new(ObservedCertificate {
                    verifier: None,
                    provider,
                    watch,
                }),
            };
            (
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth(),
                roots_unavailable,
            )
        }
    };
    // CredSSP does not support TLS session resumption (MS-CSSP 1.3).
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Setup {
        config: Arc::new(config),
        roots_unavailable,
    })
}

/// The platform's own trust anchors, or the fact that this build has none.
async fn platform_roots() -> Result<rustls::RootCertStore, RdpError> {
    // OS certificate enumeration can block; do not run it on a Tokio
    // worker. This finite OS call has no cancellation API. Cancellation
    // here drops no live RDP connection (TCP is opened only afterwards).
    tokio::task::spawn_blocking(|| {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() || loaded.certs.is_empty() {
            return Err(RdpError::Trust(TrustFailure::RootsUnavailable));
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in loaded.certs {
            roots
                .add(cert)
                .map_err(|_| RdpError::Trust(TrustFailure::RootsUnavailable))?;
        }
        Ok(roots)
    })
    .await
    .map_err(|_| RdpError::Trust(TrustFailure::RootsUnavailable))?
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
    let cert = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or(RdpError::Trust(TrustFailure::MissingCertificate))?;
    // Same x509-cert extraction as the official example / ironrdp-tls helper;
    // there is no local ASN.1/DER parser.
    let cert = x509_cert::Certificate::from_der(cert.as_ref())
        .map_err(|_| RdpError::Trust(TrustFailure::MalformedCertificate))?;
    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(RdpError::Trust(TrustFailure::MalformedCertificate))?
        .to_owned();
    Ok((stream, public_key))
}

fn handshake_error(error: io::Error) -> RdpError {
    if let Some(error) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        match error {
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
                return RdpError::Trust(TrustFailure::CertificateRejected);
            }
            _ => return RdpError::Protocol("TLS handshake"),
        }
    }
    RdpError::Transport(error.kind())
}

/// The leaf one attempt refused, recorded where the refusal happens.
///
/// One attempt describes at most one leaf: the certificate the peer presented to
/// the check that refused it. Reading it empties the cell, so a retry never
/// reports the previous attempt's certificate as its own.
#[derive(Debug, Clone, Default)]
pub(super) struct CertificateWatch {
    refused: Arc<Mutex<Option<RefusedLeaf>>>,
}

#[derive(Debug, Clone)]
struct RefusedLeaf {
    sha256: [u8; 32],
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    reason: CertificateRejection,
    pinned: Option<[u8; 32]>,
}

impl CertificateWatch {
    /// Describes the leaf a check just refused. A leaf this side cannot parse is
    /// still refused by that check; it simply cannot be described, and no
    /// metadata is invented for it.
    fn record(&self, leaf: &[u8], reason: CertificateRejection, pinned: Option<[u8; 32]>) {
        let digest = ring::digest::digest(&ring::digest::SHA256, leaf);
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(digest.as_ref());
        let Ok(cert) = x509_cert::Certificate::from_der(leaf) else {
            return;
        };
        let mut refused = self.refused.lock().unwrap_or_else(|error| error.into_inner());
        *refused = Some(RefusedLeaf {
            sha256,
            // RFC 4514 rendering by x509-cert, not a local parser.
            subject: cert.tbs_certificate.subject.to_string(),
            issuer: cert.tbs_certificate.issuer.to_string(),
            not_before: iso8601(&cert.tbs_certificate.validity.not_before),
            not_after: iso8601(&cert.tbs_certificate.validity.not_after),
            reason,
            pinned,
        });
    }

    /// The challenge this attempt produced, for the endpoint the session itself
    /// dialled. `None` means no verifier refused a certificate it could read.
    pub(super) fn challenge(&self, target: String) -> Option<CertificateChallenge> {
        let leaf = self
            .refused
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()?;
        Some(CertificateChallenge {
            target,
            sha256: leaf.sha256,
            subject: leaf.subject,
            issuer: leaf.issuer,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            reason: leaf.reason,
            pinned_sha256: leaf.pinned,
        })
    }
}

/// One certificate validity bound as `YYYY-MM-DDTHH:MM:SSZ`, the form a client
/// can parse. The components come from `der`'s own calendar type, so no time
/// arithmetic happens here.
fn iso8601(time: &Time) -> String {
    let date = time.to_date_time();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date.year(),
        date.month(),
        date.day(),
        date.hour(),
        date.minutes(),
        date.seconds()
    )
}

/// Only chain trust, name and validity decisions may offer an explicit pin.
/// Malformed certificates, revocation and cryptographic failures stay failures.
fn rejection(error: &rustls::CertificateError) -> Option<CertificateRejection> {
    match error {
        rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. } => {
            Some(CertificateRejection::Expired)
        }
        rustls::CertificateError::NotValidYet
        | rustls::CertificateError::NotValidYetContext { .. } => Some(CertificateRejection::NotYetValid),
        rustls::CertificateError::NotValidForName
        | rustls::CertificateError::NotValidForNameContext { .. } => {
            Some(CertificateRejection::NameMismatch)
        }
        rustls::CertificateError::UnknownIssuer => Some(CertificateRejection::Untrusted),
        _ => None,
    }
}

/// The platform-root check, with its own refusals described.
///
/// `verifier: None` means this build has no platform trust store at all: every
/// certificate is refused, and the handshake is attempted only so the peer's real
/// leaf can be described. That is a refusal path, never a permissive one.
#[derive(Debug)]
struct ObservedCertificate {
    verifier: Option<Arc<dyn ServerCertVerifier>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    watch: CertificateWatch,
}

impl ServerCertVerifier for ObservedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Some(verifier) = &self.verifier else {
            self.watch
                .record(end_entity.as_ref(), CertificateRejection::Untrusted, None);
            // No chain could be evaluated here. This says the handshake is
            // rejected for a reason of this side's, not that the peer's chain is
            // unknown to a root store this build does not have.
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        };
        match verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(error) => {
                if let rustls::Error::InvalidCertificate(certificate) = &error {
                    if let Some(reason) = rejection(certificate) {
                        self.watch.record(end_entity.as_ref(), reason, None);
                    }
                }
                Err(error)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // A peer that cannot prove it holds the key is refused in every
        // configuration, including one with no certificate trust at all.
        match &self.verifier {
            Some(verifier) => verifier.verify_tls12_signature(message, cert, dss),
            None => rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            ),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match &self.verifier {
            Some(verifier) => verifier.verify_tls13_signature(message, cert, dss),
            None => rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            ),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        match &self.verifier {
            Some(verifier) => verifier.supported_verify_schemes(),
            // The schemes this build can really verify with, so a peer still
            // presents a certificate rather than failing on an empty offer.
            None => self
                .provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

#[derive(Debug)]
struct PinnedCertificate {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
    watch: CertificateWatch,
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
            self.watch.record(
                end_entity.as_ref(),
                CertificateRejection::PinMismatch,
                Some(self.pin),
            );
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
        rustls::crypto::verify_tls12_signature(
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
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

#[cfg(test)]
mod tests {
    //! What `connect` relies on, checked against the real fixtures: the reason a
    //! refused chain reports, the ISO-8601 form a validity bound takes, and the two
    //! verifiers with a real peer presenting `tests/fixtures/rdp-trust/leaf.der`.
    //!
    //! The fixture's key is a throwaway that is deliberately public; see that
    //! directory's README. It is what lets a real handshake prove the peer holds the
    //! leaf's private key, so the pin path's signature verification is exercised
    //! rather than assumed.

    use super::{
        CertificateRejection, CertificateWatch, ObservedCertificate, PinnedCertificate,
        PrefixedTcp, RdpError, RdpTrust, TrustFailure, config, iso8601, rejection, upgrade,
    };
    use bytes::BytesMut;
    use rustls::CertificateError;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use x509_cert::time::Time;

    /// The public test leaf, its deliberately public key, and the leaf's digest as
    /// an independent tool reported it (not this code's own computation).
    const LEAF: &[u8] = include_bytes!("../../../tests/fixtures/rdp-trust/leaf.der");
    const LEAF_KEY: &[u8] = include_bytes!("../../../tests/fixtures/rdp-trust/leaf-key.der");
    const LEAF_SHA256: &str = "d7627513f8876ef4424d2f6caafef5941de543fe058d7900b873b9bedb1ae157";

    #[test]
    fn refused_chains_report_the_reason_that_refused_them() {
        for (error, reason) in [
            (CertificateError::Expired, CertificateRejection::Expired),
            (CertificateError::NotValidYet, CertificateRejection::NotYetValid),
            (
                CertificateError::NotValidForName,
                CertificateRejection::NameMismatch,
            ),
            (
                CertificateError::UnknownIssuer,
                CertificateRejection::Untrusted,
            ),
        ] {
            assert_eq!(rejection(&error), Some(reason), "{error:?}");
        }
        // The same two cases with the extra context rustls now carries.
        for (error, reason) in [
            (
                CertificateError::ExpiredContext {
                    time: rustls::pki_types::UnixTime::since_unix_epoch(
                        std::time::Duration::from_secs(1),
                    ),
                    not_after: rustls::pki_types::UnixTime::since_unix_epoch(
                        std::time::Duration::from_secs(0),
                    ),
                },
                CertificateRejection::Expired,
            ),
            (
                CertificateError::NotValidYetContext {
                    time: rustls::pki_types::UnixTime::since_unix_epoch(
                        std::time::Duration::from_secs(0),
                    ),
                    not_before: rustls::pki_types::UnixTime::since_unix_epoch(
                        std::time::Duration::from_secs(1),
                    ),
                },
                CertificateRejection::NotYetValid,
            ),
        ] {
            assert_eq!(rejection(&error), Some(reason), "{error:?}");
        }
        for error in [
            CertificateError::BadEncoding,
            CertificateError::BadSignature,
            CertificateError::Revoked,
            CertificateError::ApplicationVerificationFailure,
        ] {
            assert_eq!(rejection(&error), None, "{error:?}");
        }
    }

    /// Both encodings a certificate can use become the same UTC form, and the
    /// components are the certificate's own rather than a rounded instant.
    #[test]
    fn validity_bounds_become_iso8601_utc() {
        let utc = Time::from(
            x509_cert::der::asn1::UtcTime::from_date_time(
                x509_cert::der::DateTime::new(2026, 1, 2, 3, 4, 5).unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(iso8601(&utc), "2026-01-02T03:04:05Z");
        let general = Time::from(
            x509_cert::der::asn1::GeneralizedTime::from_date_time(
                x509_cert::der::DateTime::new(2051, 12, 31, 23, 59, 58).unwrap(),
            ),
        );
        assert_eq!(iso8601(&general), "2051-12-31T23:59:58Z");
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn fixture_digest() -> [u8; 32] {
        let digest = ring::digest::digest(&ring::digest::SHA256, LEAF);
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(digest.as_ref());
        sha256
    }

    /// The instant these verifiers are given. The ones that matter here do not read
    /// it, and a fixed value keeps the fixture's own validity out of the assertion.
    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(0))
    }

    fn fixture_name() -> ServerName<'static> {
        ServerName::try_from("localhost").expect("a server name")
    }

    /// A build with no platform trust store refuses every certificate, and the
    /// refusal still describes the peer's real leaf: that description is the only
    /// thing a client can base an explicit decision on.
    #[test]
    fn a_missing_root_store_refuses_but_still_describes_the_leaf() {
        let watch = CertificateWatch::default();
        let verifier = ObservedCertificate {
            verifier: None,
            provider: provider(),
            watch: watch.clone(),
        };
        let leaf = CertificateDer::from(LEAF);
        let error = verifier
            .verify_server_cert(&leaf, &[], &fixture_name(), &[], now())
            .unwrap_err();
        assert!(
            matches!(
                error,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                )
            ),
            "{error:?}"
        );

        let challenge = watch
            .challenge("10.0.0.9:3389".to_owned())
            .expect("the refused leaf is described");
        assert_eq!(challenge.target, "10.0.0.9:3389");
        assert_eq!(challenge.sha256, fixture_digest());
        assert_eq!(challenge.sha256_hex(), LEAF_SHA256);
        assert_eq!(challenge.reason, CertificateRejection::Untrusted);
        assert_eq!(
            challenge.pinned_sha256, None,
            "this attempt carried no pin"
        );
        assert_eq!(
            challenge.subject, challenge.issuer,
            "the fixture leaf is self-signed"
        );
        assert!(
            challenge.subject.contains("CN=rd-engine-rdp-trust-fixture"),
            "{}",
            challenge.subject
        );
        assert!(
            challenge.subject.contains("O=rd-engine"),
            "{}",
            challenge.subject
        );
        assert_eq!(challenge.not_before, "2026-01-01T00:00:00Z");
        assert_eq!(challenge.not_after, "2036-01-01T00:00:00Z");
        // One attempt describes one leaf: reading it empties the cell.
        assert!(watch.challenge("10.0.0.9:3389".to_owned()).is_none());
    }

    /// A leaf this side cannot parse is still refused, and no metadata is invented
    /// for it.
    #[test]
    fn an_unreadable_leaf_is_refused_without_metadata() {
        let watch = CertificateWatch::default();
        let verifier = ObservedCertificate {
            verifier: None,
            provider: provider(),
            watch: watch.clone(),
        };
        let garbage = CertificateDer::from(&b"not a certificate"[..]);
        assert!(
            verifier
                .verify_server_cert(&garbage, &[], &fixture_name(), &[], now())
                .is_err()
        );
        assert!(watch.challenge("10.0.0.9:3389".to_owned()).is_none());
    }

    /// An explicit pin that is not this leaf's fingerprint refuses the peer and
    /// names both fingerprints, so a client can show the one it had and the one it
    /// found.
    #[test]
    fn a_wrong_pin_refuses_and_names_both_fingerprints() {
        let watch = CertificateWatch::default();
        let wrong = [0x11; 32];
        let verifier = PinnedCertificate {
            pin: wrong,
            provider: provider(),
            watch: watch.clone(),
        };
        let leaf = CertificateDer::from(LEAF);
        assert!(
            verifier
                .verify_server_cert(&leaf, &[], &fixture_name(), &[], now())
                .is_err()
        );
        let challenge = watch
            .challenge("10.0.0.9:3389".to_owned())
            .expect("the refused leaf is described");
        assert_eq!(challenge.reason, CertificateRejection::PinMismatch);
        assert_eq!(challenge.pinned_sha256, Some(wrong));
        assert_eq!(challenge.sha256, fixture_digest());
        assert_eq!(
            challenge.pinned_sha256_hex(),
            Some("1".repeat(64)),
            "the pin this attempt carried is the one it reports"
        );
        assert_ne!(
            challenge.pinned_sha256,
            Some(challenge.sha256),
            "a mismatch names two different certificates"
        );
    }

    /// A pin that does match is the whole trust source, and an accepted
    /// certificate raises no challenge.
    #[test]
    fn a_matching_pin_is_accepted_and_raises_no_challenge() {
        let watch = CertificateWatch::default();
        let verifier = PinnedCertificate {
            pin: fixture_digest(),
            provider: provider(),
            watch: watch.clone(),
        };
        let leaf = CertificateDer::from(LEAF);
        assert!(
            verifier
                .verify_server_cert(&leaf, &[], &fixture_name(), &[], now())
                .is_ok()
        );
        assert!(watch.challenge("10.0.0.9:3389".to_owned()).is_none());
        assert!(
            !verifier.supported_verify_schemes().is_empty(),
            "the pin path still verifies the handshake signature"
        );
    }

    /// One loopback peer that answers a handshake with the fixture leaf, so the
    /// configured trust path is exercised through a real handshake.
    async fn fixture_peer() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Some(acceptor) = fixture_acceptor() else {
                return;
            };
            // The client's verdict is the point; its alert ends this side too.
            let _ = acceptor.accept(stream).await;
        });
        (address, server)
    }

    fn fixture_acceptor() -> Option<tokio_rustls::TlsAcceptor> {
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .ok()?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(LEAF)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(LEAF_KEY),
                ),
            )
            .ok()?;
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
    }

    /// The same refusal through a real handshake: the configured pin decides, the
    /// failure reaches the caller as a certificate-trust failure, and the leaf the
    /// peer really presented is what gets described.
    #[tokio::test]
    async fn a_wrong_pin_refuses_the_real_peer_and_describes_its_leaf() {
        let (address, server) = fixture_peer().await;
        let watch = CertificateWatch::default();
        let setup = config(RdpTrust::CertificateSha256([0; 32]), watch.clone())
            .await
            .expect("a pin needs no platform root");
        assert!(!setup.roots_unavailable);
        let stream = TcpStream::connect(address).await.expect("connect");
        let error = match upgrade(
            PrefixedTcp::new(stream, BytesMut::new()),
            fixture_name(),
            setup.config,
        )
        .await
        {
            Ok(_) => panic!("the pin does not name this leaf"),
            Err(error) => error,
        };
        assert_eq!(error, RdpError::Trust(TrustFailure::CertificateRejected));
        let challenge = watch
            .challenge("127.0.0.1:3389".to_owned())
            .expect("the refused leaf is described");
        assert_eq!(challenge.reason, CertificateRejection::PinMismatch);
        assert_eq!(
            challenge.pinned_sha256,
            Some([0; 32]),
            "the pin this attempt carried is the one it reports"
        );
        assert_eq!(challenge.sha256_hex(), LEAF_SHA256);
        let _ = server.await;
    }

    /// The counterpart: the pin that matches lets the same peer through, which is
    /// what a client's explicit decision is worth on a build without roots. The
    /// handshake also proves the peer holds the leaf's key, so accepting the pin
    /// never meant skipping the signature check.
    #[tokio::test]
    async fn a_matching_pin_accepts_the_real_peer() {
        let (address, server) = fixture_peer().await;
        let watch = CertificateWatch::default();
        let setup = config(RdpTrust::CertificateSha256(fixture_digest()), watch.clone())
            .await
            .expect("a pin needs no platform root");
        let stream = TcpStream::connect(address).await.expect("connect");
        let (_stream, public_key) = upgrade(
            PrefixedTcp::new(stream, BytesMut::new()),
            fixture_name(),
            setup.config,
        )
        .await
        .expect("the pin names this leaf");
        assert!(!public_key.is_empty(), "the peer's public key travelled");
        assert!(watch.challenge("127.0.0.1:3389".to_owned()).is_none());
        let _ = server.await;
    }
}
