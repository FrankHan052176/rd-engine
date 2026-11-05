//! Connect through the real IronRDP adapter and receive a decoded desktop frame.
//!
//! Usage: `cargo run --example rdp_connect -- rdp://user@host[:port] [leaf-sha256]`
//! Supply the password on standard input from a secret provider, never argv.
//! The optional certificate fingerprint must come from an independently trusted
//! source. Without a pin, the adapter validates the server using system roots.
//! A received-frame digest is decode evidence, not physical display evidence.

use rd_engine::{
    protocol::{
        Target,
        rdp::{RdpEvent, RdpOptions, RdpSession, RdpTrust, certificate_pin},
        rect::PixelTarget,
    },
    surface::MemorySurface,
};
use std::{
    error::Error,
    io::{self, IsTerminal, Read},
    time::Duration,
};
use zeroize::Zeroizing;

type ProbeResult<T> = Result<T, Box<dyn Error>>;

fn main() -> ProbeResult<()> {
    let mut args = std::env::args().skip(1);
    let target = args.next().ok_or("Expected rdp://user@host[:port]")?;
    let trust = match args.next() {
        Some(value) => RdpTrust::CertificateSha256(
            certificate_pin(&value).ok_or(
                "The trusted leaf SHA-256 must contain exactly 64 hexadecimal digits",
            )?,
        ),
        None => RdpTrust::SystemRoots,
    };
    if args.next().is_some() {
        return Err("Unexpected argument; passwords must not be passed in argv".into());
    }
    let Target::Rdp(endpoint) = Target::parse(&target)? else {
        return Err("An explicit rdp:// target is required".into());
    };
    if endpoint.user.as_deref().is_none_or(str::is_empty) {
        return Err("The RDP target must include the actual account name".into());
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(
            "Provide the password through piped standard input, not an echoed terminal".into(),
        );
    }
    let mut password = Zeroizing::new(Vec::new());
    stdin.lock().take(4099).read_to_end(&mut password)?;
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if password.len() > 4096 {
        return Err("Password input exceeds the supported limit".into());
    }
    let options = RdpOptions {
        endpoint,
        password: std::mem::take(&mut *password),
        width: 1280,
        height: 720,
        trust,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(options))
}

async fn run(options: RdpOptions) -> ProbeResult<()> {
    let mut session =
        match tokio::time::timeout(Duration::from_secs(40), RdpSession::connect(options)).await? {
            Ok(session) => session,
            Err(failure) => {
                // A refused certificate is printed exactly as the engine observed
                // it, so an operator can accept that one leaf out of band. The
                // probe still fails: printing it is not a trust decision.
                if let Some(challenge) = &failure.certificate {
                    println!(
                        "certificate_refused target={} sha256={} reason={} pinned_sha256={} subject={:?} issuer={:?} not_before={} not_after={}",
                        challenge.target,
                        challenge.sha256_hex(),
                        challenge.reason.as_str(),
                        challenge.pinned_sha256_hex().unwrap_or_default(),
                        challenge.subject,
                        challenge.issuer,
                        challenge.not_before,
                        challenge.not_after,
                    );
                }
                let failure: Box<dyn Error> = Box::new(failure);
                return Err(failure);
            }
        };
    let (width, height) = session.desktop();
    let mut surface = MemorySurface::new(width, height)?;
    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match session.pump(&mut surface).await? {
                Some(RdpEvent::Painted) => return Ok::<(), Box<dyn Error>>(()),
                Some(RdpEvent::Closed) => {
                    return Err("Peer closed before a decoded frame arrived".into());
                }
                _ => {}
            }
        }
    })
    .await;
    let closed = session.close().await;
    received??;
    closed?;
    let (width, height) = surface.size();
    let digest = ring::digest::digest(&ring::digest::SHA256, surface.bytes());
    let digest = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("decoded_frame width={width} height={height} bgra_sha256={digest}");
    Ok(())
}
