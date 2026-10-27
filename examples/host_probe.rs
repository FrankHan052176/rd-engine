//! Development-only host probe for interop runs; not a kernel release artifact.
//!
//! usage: cargo run --example host_probe -- [--listen 0.0.0.0:21119] [--id NAME] [--password SECRET]
//!                       [--width N] [--height N] [--bitrate BPS]
//!                       [--codec auto|h264|h265] [--seconds N] [--auto-approve]
//!
//! Runs the engine's host role so an unmodified peer can connect to it directly.
//! The Windows host probe uses native desktop capture; this probe also exercises
//! the shared host role on other platforms and in CI. On
//! Windows the published output is the one the publisher binds, so --width and
//! --height have to match that display's own geometry.
use hbb_common::{
    base64::{Engine as _, engine::general_purpose::STANDARD},
    sodiumoxide::crypto::sign,
};
#[cfg(all(
    any(target_os = "windows", dsh_windows_typecheck),
    feature = "windows-modern-producer"
))]
use rd_engine::publisher::probe_display;
use rd_engine::{
    host::{Host, HostOptions},
    publisher::{CodecSelection, PublisherBackend},
};
use std::{error::Error, net::SocketAddr, time::Duration};

struct Cli {
    listen: SocketAddr,
    id: String,
    password: Option<String>,
    /// Explicitly requested capture geometry. The Windows producer publishes the
    /// display its publisher bound, so a request that does not match that
    /// output is refused instead of being silently replaced by it.
    width: Option<i32>,
    height: Option<i32>,
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
            width: None,
            height: None,
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
            "--width" => cli.width = Some(value()?.parse()?),
            "--height" => cli.height = Some(value()?.parse()?),
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
    // The engine logs through hbb_common, so a host started by a scheduler still
    // writes where the operator can read why a peer was refused.
    let _log = hbb_common::init_log(false, "rd-engine-host");
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

    // The Windows producer publishes the display its publisher bound, so the
    // geometry and the binding key come from that output; an explicitly
    // requested size has to match it rather than be silently replaced. Every
    // other publisher takes the requested size as its own.
    #[cfg(all(
        any(target_os = "windows", dsh_windows_typecheck),
        feature = "windows-modern-producer"
    ))]
    let (output_key, width, height) = {
        let display = probe_display(PublisherBackend::Auto, 0)
            .map_err(|error| format!("no desktop output can be published: {error}"))?;
        if let Some(requested) = cli.width {
            if requested != display.width {
                return Err(format!(
                    "--width {requested} does not match the bound display's {} pixels",
                    display.width
                )
                .into());
            }
        }
        if let Some(requested) = cli.height {
            if requested != display.height {
                return Err(format!(
                    "--height {requested} does not match the bound display's {} pixels",
                    display.height
                )
                .into());
            }
        }
        (display.binding_key, display.width, display.height)
    };
    #[cfg(not(all(
        any(target_os = "windows", dsh_windows_typecheck),
        feature = "windows-modern-producer"
    )))]
    let (width, height) = {
        // Every non-Windows publisher takes the requested size as its own.
        const DEFAULT_WIDTH: i32 = 1920;
        const DEFAULT_HEIGHT: i32 = 1080;
        (
            cli.width.unwrap_or(DEFAULT_WIDTH),
            cli.height.unwrap_or(DEFAULT_HEIGHT),
        )
    };

    let salt = hbb_common::config::Config::get_auto_password(32);
    let mut password = cli.password.unwrap_or_default();
    let policy = if password.is_empty() { rd_engine::authentication::PrimaryPolicy::ClickOnly }
        else { rd_engine::authentication::PrimaryPolicy::PasswordOrClick };
    let values = if password.is_empty() { Vec::new() }
        else { vec![rd_engine::authentication::salted_password(password.as_bytes(), &salt)] };
    unsafe { hbb_common::sodiumoxide::utils::memzero(password.as_bytes_mut()); }
    let credentials = std::sync::Arc::new(rd_engine::host::HostCredentials::new(
        1, salt, rd_engine::authentication::Passwords::from_salted(values), policy,
    ));
    let host = Host::start(HostOptions {
        listen: Some(cli.listen),
        allow_legacy_plain: true,
        id: cli.id.clone(),
        display_name: cli.id.clone(),
        signing_key,
        width,
        height,
        bitrate: cli.bitrate,
        platform: std::env::consts::OS.into(),
        credentials,
        publisher_backend: PublisherBackend::Auto,
        #[cfg(all(
            any(target_os = "windows", dsh_windows_typecheck),
            feature = "windows-modern-producer"
        ))]
        output_key,
        #[cfg(not(all(
            any(target_os = "windows", dsh_windows_typecheck),
            feature = "windows-modern-producer"
        )))]
        output_index: 0,
        // A console host never grants remote input; only a local product
        // surface may turn that on explicitly.
        allow_input: false,
        codec_selection: cli.codec,
    }, None)?;
    println!("display: {width}x{height}");

    let deadline = (cli.seconds > 0).then(|| tokio::time::Instant::now() + Duration::from_secs(cli.seconds));
    let mut last = String::new();
    loop {
        let snapshot = host.snapshot();
        let line = format!(
            "phase={} error={:?} connected={} encrypted={} active_peers={} input_enabled={} codec={} {}x{}@{} sent_units={} sent_bytes={} closed={}",
            snapshot.phase,
            snapshot.error,
            snapshot.connected,
            snapshot.encrypted,
            snapshot.active_peers,
            snapshot.input_enabled,
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
