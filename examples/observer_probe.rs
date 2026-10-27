//! Counts the frames a viewer presents, without a display and without Dart.
//!
//! This is the same path the Flutter bridge uses: a lease that offers a frame
//! observer, a viewer that installs it on the memory sink it creates, and an
//! observer that sees every presented region. It exists so the path can be
//! proved on a machine that has neither a panel nor a Flutter toolchain.
//!
//!     cargo run --example observer_probe -- <host:port> <password> <seconds>

use rd_engine::surface::FrameObserver;
use rd_engine::viewer::{SurfaceLease, Viewer, ViewerInputPolicy, ViewerOptions, ViewerTarget};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Counts what it is shown, in the terms the memory sink reports them.
#[derive(Default)]
struct Counter {
    frames: AtomicU64,
    bytes: AtomicU64,
    damaged_pixels: AtomicU64,
    first: AtomicU64,
    last_width: AtomicU64,
    last_height: AtomicU64,
}

impl FrameObserver for Counter {
    fn frame(&self, width: i32, height: i32, _stride: usize, bytes: &[u8], damage: rd_engine::protocol::rect::Rect) {
        let seen = self.frames.fetch_add(1, Ordering::Relaxed);
        if seen == 0 {
            self.first.store(elapsed_millis(), Ordering::Relaxed);
        }
        self.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        self.damaged_pixels.fetch_add(
            u64::try_from(damage.width).unwrap_or(0) * u64::try_from(damage.height).unwrap_or(0),
            Ordering::Relaxed,
        );
        self.last_width.store(width as u64, Ordering::Relaxed);
        self.last_height.store(height as u64, Ordering::Relaxed);
    }
}

/// Milliseconds since the process started, which is all this probe needs.
fn elapsed_millis() -> u64 {
    START.elapsed().as_millis() as u64
}

static START: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

/// The lease the memory sink needs: no surface id, and the observer the viewer
/// will install on the sink it creates.
struct ProbeLease {
    observer: Arc<dyn FrameObserver>,
}

// SAFETY: the id is a constant and the lease outlives the viewer it is given to.
unsafe impl SurfaceLease for ProbeLease {
    fn surface_id(&self) -> u64 {
        0
    }

    fn frame_observer(&self) -> Option<Arc<dyn FrameObserver>> {
        Some(self.observer.clone())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: observer_probe <host:port> <password> <seconds>");
        std::process::exit(2);
    });
    let password = args.next().unwrap_or_default();
    let seconds: u64 = args.next().and_then(|value| value.parse().ok()).unwrap_or(10);
    let address = target
        .parse()
        .map_err(|_| anyhow::anyhow!("{target:?} is not a host:port"))?;

    let counter = Arc::new(Counter::default());
    let options = ViewerOptions {
        target: ViewerTarget::RustDesk {
            address: Some(address),
        },
        username: target.clone(),
        local_id: "rd-engine-observer-probe".to_string(),
        local_name: "rd-engine-observer-probe".to_string(),
        password,
        requested_fps: 60,
        // The probe presents frames and sends no input at all. Its own policy
        // is the interactive one: it dials a direct peer the engine cannot
        // prove, so an input event here would be refused until this session's
        // operator accepted the connection, which the probe has no operator to
        // ask.
        input_policy: ViewerInputPolicy::interactive(),
    };
    let viewer = Viewer::start(
        options,
        Arc::new(ProbeLease {
            observer: counter.clone(),
        }),
    )?;
    println!("dials {target}, watching for {seconds}s");

    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let snapshot = viewer.snapshot();
        println!(
            "phase={} codec={} {}x{} received={} pushed={} rendered={} queued={} frames_seen={}",
            snapshot.phase,
            snapshot.codec,
            snapshot.width,
            snapshot.height,
            snapshot.received_units,
            snapshot.pushed_units,
            snapshot.render_submissions,
            snapshot.queued_units,
            counter.frames.load(Ordering::Relaxed),
        );
        if snapshot.closed {
            break;
        }
    }
    viewer.request_close();
    let frames = counter.frames.load(Ordering::Relaxed);
    println!(
        "frames the observer was shown: {frames}, first at {} ms, last {}x{}, {:.1} MB, {} damaged pixels",
        counter.first.load(Ordering::Relaxed),
        counter.last_width.load(Ordering::Relaxed),
        counter.last_height.load(Ordering::Relaxed),
        counter.bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0,
        counter.damaged_pixels.load(Ordering::Relaxed),
    );
    if frames == 0 {
        anyhow::bail!("the observer was never shown a frame");
    }
    Ok(())
}
