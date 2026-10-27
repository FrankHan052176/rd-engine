//! One-shot RFB (VNC) interop probe.
//!
//! Dials a real server, runs the whole handshake, then measures what the
//! viewer path actually costs: update wall time, frame rate and damaged area,
//! all against the engine's own presentation sink.
//!
//! It never guesses credentials: the password comes from the command line, and
//! a server that rejects it is reported as an authentication failure rather
//! than retried or worked around.
//!
//! ```text
//! cargo run --release --example vnc_probe -- <host[:port]> <password> [seconds]
//! ```

use rd_engine::protocol::rect::PixelTarget;
use rd_engine::protocol::{
    Endpoint,
    rfb::session::{RfbEvent, RfbOptions, RfbSession},
};
use rd_engine::surface::MemorySurface;
use std::{
    error::Error,
    time::{Duration, Instant},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let password = args.next().unwrap_or_default();
    let seconds: f64 = args
        .next()
        .map(|value| value.parse().unwrap_or(10.0))
        .unwrap_or(10.0);

    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (host.to_owned(), port.parse::<u16>()?),
        None => (target, rd_engine::protocol::VNC_DEFAULT_PORT),
    };

    // The real geometry is only known after ServerInit, so the sink starts at a
    // large desktop and is resized before any pixel arrives.
    let mut sink = MemorySurface::new(4096, 2160)?;
    let started = Instant::now();
    let mut session = match RfbSession::connect(
        RfbOptions {
            endpoint: Endpoint {
                host: host.clone(),
                port,
                user: None,
            },
            password,
            shared: true,
        },
        sink.layout(),
    )
    .await
    {
        Ok(session) => session,
        Err(error) => {
            println!("connect_failed={error}");
            println!("elapsed_ms={}", started.elapsed().as_millis());
            return Ok(());
        }
    };
    println!("handshake_ms={}", started.elapsed().as_millis());
    let (width, height) = session.desktop();
    println!("desktop={width}x{height}");
    println!("name={}", session.name());
    sink.resize(width, height)?;

    let deadline = Instant::now() + Duration::from_secs_f64(seconds);
    let mut updates = 0u64;
    let mut painted = 0u64;
    let mut damaged_pixels = 0i64;
    // Wall time includes waiting for the server and is not decode-only timing.
    let mut wall_total_ms = 0f64;
    let mut wall_worst_ms = 0f64;
    let mut worst_gap_ms = 0f64;
    let mut last = Instant::now();

    while Instant::now() < deadline {
        let before = Instant::now();
        let event = match session.pump(&mut sink).await {
            Ok(event) => event,
            Err(error) => {
                println!("pump_failed={error}");
                break;
            }
        };
        let wall_ms = before.elapsed().as_secs_f64() * 1000.0;
        let gap_ms = last.elapsed().as_secs_f64() * 1000.0;
        last = Instant::now();
        updates += 1;
        match event {
            Some(RfbEvent::Painted) => {
                painted += 1;
                wall_total_ms += wall_ms;
                wall_worst_ms = wall_worst_ms.max(wall_ms);
                worst_gap_ms = worst_gap_ms.max(gap_ms);
                // Count damage consumed by presentation; LibVNCClient owns
                // update requests independently of this observer.
                if let Some(damage) = sink.take_damage() {
                    damaged_pixels = damaged_pixels.saturating_add(damage.pixels());
                }
            }
            Some(RfbEvent::Desktop { width, height }) => {
                println!("desktop_changed={width}x{height}");
                sink.resize(width, height)?;
            }
            Some(RfbEvent::Bell) => println!("bell"),
            Some(RfbEvent::Clipboard(text)) => println!("clipboard_bytes={}", text.len()),
            None => {}
        }
    }
    println!("updates={updates}");
    println!("painted={painted}");
    println!("damaged_pixels={damaged_pixels}");
    if painted > 0 {
        println!("wall_avg_ms={:.3}", wall_total_ms / painted as f64);
        println!("wall_worst_ms={wall_worst_ms:.3}");
        println!("worst_gap_ms={worst_gap_ms:.3}");
    }
    println!("decode_timing=unavailable (LibVNCClient exposes update completion)");
    session.close().await?;
    Ok(())
}
