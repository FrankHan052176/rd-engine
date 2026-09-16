//! Cross-platform host entry point.
//!
//! usage: rd-engine-host [--listen 0.0.0.0:21119] [--id NAME] [--password SECRET]
//!                       [--width N] [--height N] [--fps N] [--bitrate BPS]
//!                       [--codec auto|h264|h265] [--seconds N] [--auto-approve]
//!
//! Runs the engine's host role so an unmodified peer can connect to it directly.
//! The Windows binary stays the native-desktop-capture path; this one exists so
//! the same host role can be exercised on every other platform and in CI.
use hbb_common::{
    base64::{Engine as _, engine::general_purpose::STANDARD},
    sodiumoxide::crypto::sign,
};
use rd_engine::{
    host::{Host, HostOptions},
    publisher::{CodecSelection, PublisherBackend},
};
use std::{error::Error, net::SocketAddr, time::Duration};

struct Cli {
    listen: SocketAddr,
    id: String,
    password: Option<String>,
    width: i32,
    height: i32,
    fps: u32,
    bitrate: i64,
    codec: CodecSelection,
    seconds: u64,
    auto_approve: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:21119".parse().unwrap(),
            id: "rd-engine-host".into(),
            password: None,
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate: 20_000_000,
            codec: CodecSelection::Auto,
            seconds: 0,
            auto_approve: false,
        }
    }
}

fn parse() -> Result<Cli, Box<dyn Error>> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("missing value for {arg}"));
        match arg.as_str() {
            "--listen" => cli.listen = value()?.parse()?,
            "--id" => cli.id = value()?,
            "--password" => cli.password = Some(value()?),
            "--width" => cli.width = value()?.parse()?,
            "--height" => cli.height = value()?.parse()?,
            "--fps" => cli.fps = value()?.parse()?,
            "--bitrate" => cli.bitrate = value()?.parse()?,
            "--codec" => {
                cli.codec = match value()?.as_str() {
                    "auto" => CodecSelection::Auto,
                    "h264" => CodecSelection::H264,
                    "h265" => CodecSelection::H265,
                    other => return Err(format!("unknown codec {other}").into()),
                }
            }
            "--seconds" => cli.seconds = value()?.parse()?,
            "--auto-approve" => cli.auto_approve = true,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    Ok(cli)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse()?;
    let (public_key, signing_key) = sign::gen_keypair();
    println!("host id: {}", cli.id);
    println!("listen: {}", cli.listen);
    println!("signing key (base64): {}", STANDARD.encode(public_key.0));
    println!(
        "password: {}",
        match cli.password.as_deref() {
            Some(password) if !password.is_empty() => "configured",
            _ => "none (interactive approval only)",
        }
    );

    let host = Host::start(HostOptions {
        listen: cli.listen,
        id: cli.id.clone(),
        signing_key,
        width: cli.width,
        height: cli.height,
        fps: cli.fps,
        bitrate: cli.bitrate,
        platform: std::env::consts::OS.into(),
        password: cli.password.clone(),
        publisher_backend: PublisherBackend::Auto,
        output_index: 0,
        codec_selection: cli.codec,
    })?;

    let deadline = (cli.seconds > 0).then(|| tokio::time::Instant::now() + Duration::from_secs(cli.seconds));
    let mut last = String::new();
    loop {
        let snapshot = host.snapshot();
        let line = format!(
            "phase={} error={:?} connected={} encrypted={} codec={} {}x{}@{} sent_units={} sent_bytes={} closed={}",
            snapshot.phase,
            snapshot.error,
            snapshot.connected,
            snapshot.encrypted,
            snapshot.codec,
            snapshot.width,
            snapshot.height,
            snapshot.fps,
            snapshot.sent_units,
            snapshot.sent_bytes,
            snapshot.closed,
        );
        if line != last {
            println!("{line}");
            last = line;
        }
        if !snapshot.approval_request.is_empty() {
            println!(
                "approval requested from {} (request {})",
                snapshot.approval_origin, snapshot.approval_request
            );
            if cli.auto_approve && host.approve(&snapshot.approval_request, true) {
                println!("approved by --auto-approve");
            }
        }
        if snapshot.closed {
            break;
        }
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            break;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
    host.close().await?;
    Ok(())
}
