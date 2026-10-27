//! The viewer shell driving an RFB session.
//!
//! `tests/vnc_session.rs` proves the RFB client speaks the protocol;
//! `tests/direct_auth.rs` proves the shell carries the original wire. This one
//! proves the two are actually connected: `Viewer::start` with a `Vnc` target
//! dials, authenticates, opens a presentation sink at the server's geometry,
//! streams an update into it, and closes with proven reclamation.
//!
//! It is the wiring test for the target dispatch, so it goes through the public
//! `Viewer` API and asserts on `ViewerSnapshot` — the same surface the HAR and
//! the ArkTS toolbar read.

use rd_engine::protocol::Endpoint;
use rd_engine::surface::FrameObserver;
use rd_engine::protocol::rect::Rect;
use rd_engine::viewer::{
    SurfaceLease, Viewer, ViewerError, ViewerInputPolicy, ViewerOptions, ViewerSnapshot,
    ViewerTarget,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

const PASSWORD: &str = "hunter2";
const WIDTH: u16 = 8;
const HEIGHT: u16 = 6;
/// One pixel as the fixture paints it: opaque red in BGRA order.
const RED: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];
const LIMIT: Duration = Duration::from_secs(12);

/// A surface identity, which is all the engine is allowed to know about the
/// renderer. The host build presents into memory, so there is nothing to own.
struct TestLease(AtomicU64, Option<Arc<dyn FrameObserver>>);

impl TestLease {
    fn new(surface_id: u64) -> Self {
        Self(AtomicU64::new(surface_id), None)
    }

    fn bind(&self, surface_id: u64) {
        self.0.store(surface_id, Ordering::Release);
    }

    fn observing(surface_id: u64, observer: Arc<dyn FrameObserver>) -> Self {
        Self(AtomicU64::new(surface_id), Some(observer))
    }
}

unsafe impl SurfaceLease for TestLease {
    fn surface_id(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn frame_observer(&self) -> Option<Arc<dyn FrameObserver>> {
        self.1.clone()
    }
}

async fn read_exact(stream: &mut TcpStream, out: &mut [u8]) {
    timeout(LIMIT, stream.read_exact(out))
        .await
        .expect("fixture read did not stall")
        .expect("fixture read");
}

async fn write_all(stream: &mut TcpStream, bytes: &[u8]) {
    timeout(LIMIT, stream.write_all(bytes))
        .await
        .expect("fixture write did not stall")
        .expect("fixture write");
}

/// Paints the fixture's whole desktop as one raw rectangle.
async fn paint(stream: &mut TcpStream) -> bool {
    let mut message = Vec::new();
    message.push(0);
    message.push(0);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&WIDTH.to_be_bytes());
    message.extend_from_slice(&HEIGHT.to_be_bytes());
    message.extend_from_slice(&0i32.to_be_bytes());
    for _ in 0..(WIDTH as usize * HEIGHT as usize) {
        message.extend_from_slice(&RED);
    }
    matches!(timeout(LIMIT, stream.write_all(&message)).await, Ok(Ok(())))
}

/// Serves one RFB session with `None` security, then keeps the socket open and
/// answers every update request with one raw rectangle until the client leaves.
async fn serve(listener: TcpListener, updates_rx: tokio::sync::mpsc::Sender<()>) {
    let Ok((mut stream, _peer)) = listener.accept().await else {
        return;
    };
    write_all(&mut stream, b"RFB 003.008\n").await;
    let mut banner = [0u8; 12];
    read_exact(&mut stream, &mut banner).await;
    // Security type None only, so this test is about the wiring rather than the
    // credential exchange (which `vnc_session.rs` covers).
    write_all(&mut stream, &[1, 1]).await;
    let mut chosen = [0u8; 1];
    read_exact(&mut stream, &mut chosen).await;
    write_all(&mut stream, &0u32.to_be_bytes()).await;

    let mut shared = [0u8; 1];
    read_exact(&mut stream, &mut shared).await;
    let mut init = Vec::new();
    init.extend_from_slice(&WIDTH.to_be_bytes());
    init.extend_from_slice(&HEIGHT.to_be_bytes());
    init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
    init.extend_from_slice(&5u32.to_be_bytes());
    init.extend_from_slice(b"fixtr");
    write_all(&mut stream, &init).await;

    let mut set_format = [0u8; 20];
    read_exact(&mut stream, &mut set_format).await;
    let mut encoding_header = [0u8; 4];
    read_exact(&mut stream, &mut encoding_header).await;
    let count = usize::from(u16::from_be_bytes([encoding_header[2], encoding_header[3]]));
    let mut encodings = vec![0u8; count * 4];
    read_exact(&mut stream, &mut encodings).await;

    let mut request = [0u8; 10];
    read_exact(&mut stream, &mut request).await;
    loop {
        let _ = updates_rx.try_send(());
        if !paint(&mut stream).await {
            return;
        }
        // LibVNCClient owns subsequent update requests.
        if !matches!(timeout(LIMIT, stream.read_exact(&mut request)).await, Ok(Ok(_))) {
            return;
        }
    }
}

async fn fixture() -> (Endpoint, tokio::sync::mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address: SocketAddr = listener.local_addr().expect("address");
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(serve(listener, tx));
    (
        Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
            user: None,
        },
        rx,
    )
}

fn options(endpoint: Endpoint) -> ViewerOptions {
    ViewerOptions {
        target: ViewerTarget::Vnc(endpoint),
        username: "viewer".into(),
        local_id: "local".into(),
        local_name: "test".into(),
        password: PASSWORD.into(),
        requested_fps: 30,
        input_policy: ViewerInputPolicy::interactive(),
    }
}

async fn until_streaming(viewer: &Viewer) -> ViewerSnapshot {
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        let snapshot = viewer.snapshot();
        if snapshot.phase == "streaming" || snapshot.closed || snapshot.error.is_some() {
            return snapshot;
        }
        if tokio::time::Instant::now() > deadline {
            return snapshot;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn until_awaiting_surface(viewer: &Viewer) -> ViewerSnapshot {
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        let snapshot = viewer.snapshot();
        if snapshot.phase == "awaiting_surface" || snapshot.closed || snapshot.error.is_some() {
            return snapshot;
        }
        if tokio::time::Instant::now() > deadline {
            return snapshot;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

/// One client-to-server message this fixture reports back, in the values the
/// wire carries. Everything else the client sends — the pixel format, the
/// encodings, the update requests themselves — is answered and not reported, so
/// the events a test reads are exactly the input that reached the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientMessage {
    /// RFB carries the whole held pointer state in every pointer event.
    Pointer {
        x: u16,
        y: u16,
        buttons: u8,
    },
    Key {
        keysym: u32,
        down: bool,
    },
}

/// Serves one RFB session with `None` security, answers every update request
/// with one rectangle, and reports every pointer and key event the client sends
/// on `events`.
///
/// It is the same fixture as `serve` with the client's own input read back, so a
/// test can assert what actually reached the peer rather than what a call
/// returned.
async fn serve_observed(listener: TcpListener, events: tokio::sync::mpsc::Sender<ClientMessage>) {
    let Ok((mut stream, _peer)) = listener.accept().await else {
        return;
    };
    write_all(&mut stream, b"RFB 003.008\n").await;
    let mut banner = [0u8; 12];
    read_exact(&mut stream, &mut banner).await;
    write_all(&mut stream, &[1, 1]).await;
    let mut chosen = [0u8; 1];
    read_exact(&mut stream, &mut chosen).await;
    write_all(&mut stream, &0u32.to_be_bytes()).await;
    let mut shared = [0u8; 1];
    read_exact(&mut stream, &mut shared).await;
    let mut init = Vec::new();
    init.extend_from_slice(&WIDTH.to_be_bytes());
    init.extend_from_slice(&HEIGHT.to_be_bytes());
    init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
    init.extend_from_slice(&5u32.to_be_bytes());
    init.extend_from_slice(b"fixtr");
    write_all(&mut stream, &init).await;

    let mut message_type = [0u8; 1];
    if !matches!(timeout(LIMIT, stream.read_exact(&mut message_type)).await, Ok(Ok(_))) {
        return;
    }
    loop {
        match message_type[0] {
            // SetPixelFormat: three bytes of padding and one pixel format.
            0 => {
                let mut body = [0u8; 19];
                read_exact(&mut stream, &mut body).await;
            }
            // SetEncodings: one byte of padding and a count of encodings.
            2 => {
                let mut header = [0u8; 3];
                read_exact(&mut stream, &mut header).await;
                let count = usize::from(u16::from_be_bytes([header[1], header[2]]));
                if count > 0 {
                    let mut encodings = vec![0u8; count * 4];
                    read_exact(&mut stream, &mut encodings).await;
                }
            }
            // A framebuffer update request is what releases the next paint.
            3 => {
                let mut request = [0u8; 9];
                read_exact(&mut stream, &mut request).await;
                if !paint(&mut stream).await {
                    return;
                }
            }
            // KeyEvent: state, two bytes of padding, then the keysym.
            4 => {
                let mut body = [0u8; 7];
                read_exact(&mut stream, &mut body).await;
                let down = body[0] != 0;
                let keysym = u32::from_be_bytes([body[3], body[4], body[5], body[6]]);
                if events
                    .send(ClientMessage::Key { keysym, down })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            // PointerEvent: the button mask, then the position.
            5 => {
                let mut body = [0u8; 5];
                read_exact(&mut stream, &mut body).await;
                let buttons = body[0];
                let x = u16::from_be_bytes([body[1], body[2]]);
                let y = u16::from_be_bytes([body[3], body[4]]);
                if events
                    .send(ClientMessage::Pointer { x, y, buttons })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            // ClientCutText: the engine has no clipboard path, so this is read
            // only to keep the stream aligned, and a length this fixture will
            // not read is the end of the session rather than a desync.
            6 => {
                let mut header = [0u8; 7];
                read_exact(&mut stream, &mut header).await;
                let length =
                    u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
                if length > 4096 {
                    return;
                }
                if length > 0 {
                    let mut text = vec![0u8; length];
                    read_exact(&mut stream, &mut text).await;
                }
            }
            _ => return,
        }
        if !matches!(timeout(LIMIT, stream.read_exact(&mut message_type)).await, Ok(Ok(_))) {
            return;
        }
    }
}

/// The observing fixture: an endpoint and the input it reports back.
async fn observed_fixture() -> (Endpoint, tokio::sync::mpsc::Receiver<ClientMessage>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address: SocketAddr = listener.local_addr().expect("address");
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(serve_observed(listener, tx));
    (
        Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
            user: None,
        },
        rx,
    )
}

async fn next_client_message(
    events: &mut tokio::sync::mpsc::Receiver<ClientMessage>,
) -> ClientMessage {
    timeout(LIMIT, events.recv())
        .await
        .expect("the client sent what the test expected")
        .expect("the fixture is still reading")
}

struct ObserveFrames(tokio::sync::mpsc::Sender<(i32, i32, usize, Vec<u8>)>);

impl FrameObserver for ObserveFrames {
    fn frame(&self, width: i32, height: i32, stride: usize, bytes: &[u8], _damage: Rect) {
        let _ = self.0.try_send((width, height, stride, bytes.to_vec()));
    }
}

/// The whole wiring: dispatch on the target, dial, open a sink at the server's
/// geometry, stream into it, and close with proven reclamation.
#[tokio::test]
async fn a_vnc_target_drives_the_viewer_shell_end_to_end() {
    let (endpoint, mut updates) = fixture().await;
    let (frames, mut received_frames) = tokio::sync::mpsc::channel(1);
    let lease = Arc::new(TestLease::observing(0, Arc::new(ObserveFrames(frames))));
    let viewer = Viewer::start(options(endpoint), lease.clone()).expect("start");

    let awaiting_surface = until_awaiting_surface(&viewer).await;
    assert_eq!(
        awaiting_surface.phase, "awaiting_surface",
        "an authenticated session waits for the client's late-bound Surface"
    );
    assert!(
        awaiting_surface.authenticated,
        "authentication is reported independently of the transient phase"
    );
    assert_eq!(
        (awaiting_surface.width, awaiting_surface.height),
        (WIDTH as i32, HEIGHT as i32),
        "the client receives geometry before it binds the Surface"
    );
    assert_eq!(awaiting_surface.displays.len(), 1);

    lease.bind(1);
    let snapshot = until_streaming(&viewer).await;

    assert!(
        snapshot.error.is_none(),
        "the session must not fail: {:?}",
        snapshot.error
    );
    assert_eq!(snapshot.phase, "streaming", "the shell reached streaming");
    assert_eq!(
        (snapshot.width, snapshot.height),
        (WIDTH as i32, HEIGHT as i32)
    );
    assert_eq!(snapshot.route, "direct_tcp");
    assert_eq!(
        snapshot.codec, "",
        "RFB paints pixels, it does not pick a codec"
    );
    assert_eq!(snapshot.protocol, "vnc", "the snapshot names the wire");
    assert!(
        snapshot.keyboard_allowed,
        "an authenticated RFB session accepts input"
    );

    // The fixture paints once per request, so a second update proves the loop
    // asked for more rather than stalling after the first.
    timeout(LIMIT, updates.recv())
        .await
        .expect("the fixture painted at least once")
        .expect("fixture channel");
    timeout(LIMIT, updates.recv())
        .await
        .expect("the client asked for another update")
        .expect("fixture channel");

    let (width, height, stride, bytes) = timeout(LIMIT, received_frames.recv())
        .await.expect("presentation reaches the shared observer").expect("observer frame");
    assert_eq!((width, height, stride), (i32::from(WIDTH), i32::from(HEIGHT), usize::from(WIDTH) * 4));
    assert_eq!(bytes, RED.repeat(usize::from(WIDTH) * usize::from(HEIGHT)));

    // Closing proves reclamation rather than merely stopping.
    timeout(LIMIT, viewer.close())
        .await
        .expect("close settles")
        .expect("the surface was reclaimed");
    assert_eq!(
        viewer.reclamation_confirmed(),
        Some(true),
        "the terminal snapshot exposes confirmed Surface release separately from session errors",
    );
    let snapshot = viewer.snapshot();
    assert!(snapshot.closed, "a closed session reports itself closed");
    assert!(
        snapshot.error.is_none(),
        "a clean close is not an error: {:?}",
        snapshot.error
    );
}

/// A target the shell refuses must be refused before any socket is opened.
#[tokio::test]
async fn a_target_with_no_reachable_endpoint_is_refused() {
    let error = Viewer::start(
        options(Endpoint {
            host: String::new(),
            port: 0,
            user: None,
        }),
        Arc::new(TestLease::new(1)),
    )
    .err()
    .expect("an empty endpoint is not dialable");
    assert!(
        matches!(error, ViewerError::InvalidOptions),
        "got {error:?}"
    );
}

/// Invalid RDP account/endpoint options are rejected synchronously, before
/// touching the runtime, lease or network. A valid endpoint is no longer refused
/// merely for selecting RDP; real authentication is covered by the smoke probe.
#[test]
fn rdp_requires_an_account_and_a_valid_endpoint_before_starting() {
    for endpoint in [
        Endpoint { host: "127.0.0.1".into(), port: 3389, user: None },
        Endpoint { host: "127.0.0.1".into(), port: 3389, user: Some(" \t".into()) },
        Endpoint { host: "host/path".into(), port: 3389, user: Some("user".into()) },
        Endpoint { host: "bad host".into(), port: 3389, user: Some("user".into()) },
        Endpoint { host: "127.0.0.1".into(), port: 0, user: Some("user".into()) },
        Endpoint { host: "127.0.0.1".into(), port: 3389, user: Some("user\0name".into()) },
    ] {
        let mut config = options(endpoint.clone());
        config.target = ViewerTarget::Rdp(endpoint);
        assert!(matches!(Viewer::start(config, Arc::new(TestLease::new(1))), Err(ViewerError::InvalidOptions)));
    }
}

struct BlockingFrame {
    entered: tokio::sync::Notify,
    released: tokio::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl FrameObserver for BlockingFrame {
    fn frame(&self, _width: i32, _height: i32, _stride: usize, _bytes: &[u8], _damage: Rect) {
        self.entered.notify_one();
        // This is the actual blocking presentation worker, not the IO task.
        let _ = self.released.blocking_lock().recv_timeout(LIMIT);
    }
}

#[tokio::test]
async fn cancellation_joins_an_in_flight_surface_presentation() {
    let (endpoint, _updates) = fixture().await;
    let (release, released) = std::sync::mpsc::channel();
    let observer = Arc::new(BlockingFrame {
        entered: tokio::sync::Notify::new(),
        released: tokio::sync::Mutex::new(released),
    });
    let viewer = Viewer::start(options(endpoint), Arc::new(TestLease::observing(1, observer.clone())))
        .expect("start");
    timeout(LIMIT, observer.entered.notified()).await.expect("a real frame entered presentation");
    viewer.request_close();
    assert!(timeout(Duration::from_millis(100), viewer.close()).await.is_err(),
        "close must await the worker that still owns the sink");
    assert_eq!(viewer.reclamation_confirmed(), None);
    release.send(()).expect("release presentation");
    timeout(LIMIT, viewer.close()).await.expect("close settles after presentation").expect("sink reclaimed");
    assert_eq!(viewer.reclamation_confirmed(), Some(true));
}

#[tokio::test]
async fn cancellation_before_surface_binding_closes_the_authenticated_vnc_session() {
    let (endpoint, _updates) = fixture().await;
    let viewer = Viewer::start(options(endpoint), Arc::new(TestLease::new(0))).expect("start");
    assert!(until_awaiting_surface(&viewer).await.authenticated);
    timeout(LIMIT, viewer.close()).await.expect("native worker joins").expect("no surface leaked");
    assert_eq!(viewer.reclamation_confirmed(), Some(true));
    assert!(viewer.snapshot().error.is_none());
}

/// A read-only policy is the engine's own and is in force before the session
/// starts: the viewer is started with it, no bridge is involved, and the session
/// still authenticates and presents.
#[tokio::test]
async fn a_read_only_viewer_refuses_input_in_the_engine() {
    let (endpoint, _events) = observed_fixture().await;
    let mut read_only = options(endpoint);
    read_only.input_policy = ViewerInputPolicy::read_only();
    let viewer = Viewer::start(read_only, Arc::new(TestLease::new(1))).expect("start");

    let snapshot = until_streaming(&viewer).await;
    assert!(
        snapshot.error.is_none(),
        "a read-only session still streams: {:?}",
        snapshot.error
    );
    assert!(
        snapshot.authenticated,
        "presentation and the input policy are independent facts"
    );
    assert!(
        !snapshot.keyboard_allowed,
        "a read-only viewer reports no input to its client"
    );
    assert_eq!(viewer.input_policy(), ViewerInputPolicy::read_only());
    let generation = snapshot.input_generation;
    assert!(
        matches!(
            viewer.send_mouse(0, 0, 1, 1, generation),
            Err(ViewerError::InputNotAllowed)
        ),
        "the engine refuses pointer input while it is read-only"
    );
    assert!(
        matches!(
            viewer.send_key(0x41, true, generation),
            Err(ViewerError::InputNotAllowed)
        ),
        "the engine refuses key input while it is read-only"
    );

    timeout(LIMIT, viewer.close())
        .await
        .expect("close settles")
        .expect("the surface was reclaimed");
}

/// A withdrawal and the admission that follows it, taken together, still release
/// what this writer emitted before them — and the fresh same-key and same-button
/// input that follows carries none of the old hold.
///
/// This is the ordering the audit's consumer-visible regression names: the wire
/// must carry old button press → release → fresh button press, never a fresh
/// press that stands for a hold the peer never saw released. RFB carries the
/// whole pointer state in every event, so a stale held bit would also be
/// re-asserted by the very event that replaced it.
#[tokio::test]
async fn a_rapid_revoke_and_regrant_releases_before_fresh_same_key_and_button_input() {
    let (endpoint, mut events) = observed_fixture().await;
    let viewer = Viewer::start(options(endpoint), Arc::new(TestLease::new(1))).expect("start");
    let snapshot = until_streaming(&viewer).await;
    assert!(
        snapshot.keyboard_allowed,
        "an authenticated RFB session admits input"
    );
    let first = snapshot.input_generation;
    assert!(
        first > 0,
        "a running viewer names the generation it admits under"
    );

    // One held button and one held key, each queued under the generation the
    // snapshot named and answered with the generation it stamps.
    let down = viewer.send_mouse(1, 1, 5, 4, first).expect("button down");
    assert_eq!(down, first, "the receipt is the stamp the event carries");
    let key_down = viewer.send_key(0x41, true, down).expect("key down");
    assert_eq!(
        key_down, down,
        "an event queued with an earlier receipt's generation is admitted"
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0x01
        }
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0x41,
            down: true
        }
    );

    // Read-only, and admitted again before the writer has reported anything in
    // between: both changes advance the generation, so the holds taken under the
    // old one are still this writer's to release.
    let revoked = viewer.set_input_policy(ViewerInputPolicy::read_only());
    assert!(revoked.revoked, "read-only stops admitting input");
    let regranted = viewer.set_input_policy(ViewerInputPolicy::interactive());
    assert!(
        regranted.input_generation > revoked.input_generation,
        "each change publishes its own generation"
    );
    let second = regranted.input_generation;
    assert_ne!(
        second, first,
        "the generation the first pair was queued under is gone"
    );

    // The same key and the same button again, queued under the generation in
    // force now.
    let fresh_down = viewer
        .send_mouse(1, 1, 5, 4, second)
        .expect("button down again");
    assert_eq!(fresh_down, second);
    let fresh_key = viewer
        .send_key(0x41, true, fresh_down)
        .expect("key down again");
    assert_eq!(fresh_key, fresh_down);
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0,
        },
        "the button the withdrawal ended is let go before the fresh press"
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0x41,
            down: false
        },
        "and so is the key"
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0x01
        },
        "the fresh press is a press of its own, not the old hold restamped"
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0x41,
            down: true
        }
    );

    // Both releases reached the peer, so this writer holds nothing it owes.
    assert_eq!(
        viewer.send_mouse(2, 1, 5, 4, fresh_key).expect("button up"),
        fresh_key
    );
    assert_eq!(
        viewer.send_key(0x41, false, fresh_key).expect("key up"),
        fresh_key
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0
        }
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0x41,
            down: false
        }
    );
    // A move the writer emits after both: the peer holding it is what proves the
    // writer got past recording them, so the answer below is not read mid-pass.
    viewer.send_mouse(0, 0, 7, 5, fresh_key).expect("move");
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 7,
            y: 5,
            buttons: 0
        }
    );
    let settled = viewer.set_input_policy(ViewerInputPolicy::interactive());
    assert_eq!(
        settled.input_generation, fresh_key,
        "a policy that changes nothing leaves the generation every receipt named"
    );
    assert_eq!(
        settled.releases_owed, 0,
        "every hold this writer took was released"
    );
    assert_eq!(
        settled.releases_retired, 0,
        "and no release a change retired is still on its way"
    );

    timeout(LIMIT, viewer.close())
        .await
        .expect("close settles")
        .expect("the surface was reclaimed");
}

/// Revoking input releases exactly the keys and buttons this writer emitted, on
/// the same writer and in the ledger's own order — and nothing queued under the
/// revoked policy is replayed when input is admitted again.
#[tokio::test]
async fn revoking_input_releases_what_this_writer_emitted_and_replays_nothing() {
    let (endpoint, mut events) = observed_fixture().await;
    let viewer = Viewer::start(options(endpoint), Arc::new(TestLease::new(1))).expect("start");
    let snapshot = until_streaming(&viewer).await;
    assert!(
        snapshot.keyboard_allowed,
        "an authenticated RFB session admits input"
    );
    assert!(
        snapshot.input_generation > 0,
        "a running viewer reports the generation its admission answer belongs to"
    );
    assert_eq!(
        snapshot.releases_owed, 0,
        "nothing is held before this writer emits anything"
    );
    let first = snapshot.input_generation;

    // Exactly what this writer owns: one move, one held button, one held key,
    // each queued under the generation the snapshot named.
    assert_eq!(viewer.send_mouse(0, 0, 5, 4, first).expect("move"), first);
    let held = viewer.send_mouse(1, 1, 5, 4, first).expect("button down");
    assert_eq!(held, first);
    assert_eq!(viewer.send_key(0x41, true, held).expect("key down"), held);
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0
        }
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0x01
        }
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0x41,
            down: true
        }
    );

    let revoked = viewer.set_input_policy(ViewerInputPolicy::read_only());
    assert!(
        revoked.revoked,
        "read-only stops admitting what the previous policy admitted"
    );
    assert_eq!(
        revoked.releases_owed, 2,
        "the writer owes one release per hold it emitted"
    );
    assert!(
        !revoked.released(),
        "a release that is still owed is not a completed one"
    );
    assert!(
        matches!(
            viewer.send_mouse(0, 0, 6, 5, first),
            Err(ViewerError::InputNotAllowed)
        ),
        "the engine refuses further input as soon as the policy is revoked"
    );

    // The release goes out on the same writer: the button first, then the key,
    // for the holds the fixture actually saw emitted.
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0
        }
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0x41,
            down: false
        }
    );

    // Admission again, and the events the client queued under the generation it
    // was acting on are refused rather than restamped: the engine never emits an
    // event under a boundary its caller did not see.
    let regranted = viewer.set_input_policy(ViewerInputPolicy::interactive());
    assert!(
        !regranted.revoked,
        "admitting input again is not a revocation"
    );
    assert!(
        regranted.input_generation > revoked.input_generation,
        "the policy change moved the generation the snapshot reports"
    );
    assert!(
        matches!(
            viewer.send_mouse(0, 0, 6, 5, first),
            Err(ViewerError::StaleInputGeneration)
        ),
        "the generation from before the change is refused, not relabelled"
    );

    // The next event, queued under the generation in force now, carries no stale
    // held bit: the hold the release cleared is not reported as one the peer
    // still has.
    let second = regranted.input_generation;
    assert_eq!(
        viewer
            .send_mouse(0, 0, 7, 5, second)
            .expect("move after the release"),
        second
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 7,
            y: 5,
            buttons: 0
        }
    );
    // The same writer runs its release pass before it takes anything else off
    // the queue, so this second answer describes a release that has finished.
    let settled = viewer.set_input_policy(ViewerInputPolicy::interactive());
    assert_eq!(
        settled.releases_owed, 0,
        "the release the revocation owed was made"
    );
    assert!(
        settled.released(),
        "nothing is owed and nothing was left unreleased"
    );

    // The snapshot carries the same boundary a policy answer does — the
    // generation and the release the writer owes, read from the gate together —
    // so a client can settle a release it was told about by polling, without
    // inferring either from the other.
    let after = viewer.snapshot();
    assert_eq!(
        after.input_generation, settled.input_generation,
        "the snapshot names the generation the last change published"
    );
    assert_eq!(
        after.releases_owed, 0,
        "a release the writer made is not reported as still owed"
    );
    assert_eq!(
        after.releases_retired, 0,
        "and it is not reported as a release still on its way"
    );
    assert_eq!(
        after.releases_unreleased, 0,
        "no release of this viewer's was left unreleased"
    );

    timeout(LIMIT, viewer.close())
        .await
        .expect("close settles")
        .expect("the surface was reclaimed");
}

/// A held button and a held modifier, and what a boundary change does to the Up
/// that follows them: the stale Up is refused and stays off the wire, while the
/// fresh generation's Down and Up both arrive.
///
/// This is the engine half of the audit's stale-epoch defect. A client that
/// admitted a Down under one generation must be able to queue the matching Up
/// under a generation the engine still admits; an event named with the epoch the
/// engine has left is refused instead of being restamped, because the hold it
/// refers to was already released by the change and a restamped Up would release
/// a press the peer never received.
#[tokio::test]
async fn a_stale_generation_is_refused_and_a_fresh_generations_down_and_up_both_arrive() {
    let (endpoint, mut events) = observed_fixture().await;
    let viewer = Viewer::start(options(endpoint), Arc::new(TestLease::new(1))).expect("start");
    let snapshot = until_streaming(&viewer).await;
    assert!(
        snapshot.keyboard_allowed,
        "an authenticated RFB session admits input"
    );
    let first = snapshot.input_generation;
    assert!(
        first > 0,
        "a running viewer names the generation it admits under"
    );

    // A button and a modifier, both held under the generation the snapshot named
    // and both answered with the generation the queued event carries.
    let down = viewer.send_mouse(1, 1, 5, 4, first).expect("button down");
    assert_eq!(down, first, "the receipt is the stamp the event carries");
    let shift = viewer.send_key(0xffe1, true, down).expect("modifier down");
    assert_eq!(shift, down);
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0x01
        }
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0xffe1,
            down: true
        }
    );

    // The boundary moves twice while both are held: the policy is revoked and
    // admitted again before the client has seen anything come back.
    let revoked = viewer.set_input_policy(ViewerInputPolicy::read_only());
    let regranted = viewer.set_input_policy(ViewerInputPolicy::interactive());
    assert!(revoked.revoked, "read-only stops admitting input");
    assert!(
        regranted.input_generation > revoked.input_generation,
        "each change publishes its own generation"
    );
    let second = regranted.input_generation;
    assert_ne!(
        second, first,
        "the generation the held pair was queued under is gone"
    );

    // The releases the change made necessary cross the wire first: the button
    // bit, then the modifier.
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0
        },
        "the button the change retired is released"
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0xffe1,
            down: false
        },
        "and so is the modifier"
    );

    // The Up and the modifier release the client queued under the generation it
    // was acting on are refused, not restamped: the next thing the peer sees is
    // the fresh generation's own press, never a stale release replayed.
    assert!(
        matches!(
            viewer.send_mouse(2, 1, 5, 4, first),
            Err(ViewerError::StaleInputGeneration)
        ),
        "a pointer event named with the generation the engine has left is refused"
    );
    assert!(
        matches!(
            viewer.send_key(0xffe1, false, first),
            Err(ViewerError::StaleInputGeneration)
        ),
        "a modifier named with the generation the engine has left is refused"
    );
    assert!(
        matches!(
            viewer.send_mouse(2, 1, 5, 4, revoked.input_generation),
            Err(ViewerError::StaleInputGeneration)
        ),
        "the intermediate generation is not admitted either"
    );

    // Under the generation in force now, a fresh Down and the Up that follows it
    // both arrive, each answered with the stamp it was queued under.
    let fresh_down = viewer.send_mouse(1, 1, 5, 4, second).expect("fresh down");
    assert_eq!(fresh_down, second);
    let fresh_up = viewer.send_mouse(2, 1, 5, 4, fresh_down).expect("fresh up");
    assert_eq!(
        fresh_up, fresh_down,
        "the Up is queued under the generation the Down's receipt named"
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0x01
        },
        "the stale pair reached the peer with nothing instead"
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 5,
            y: 4,
            buttons: 0
        }
    );

    let fresh_shift = viewer
        .send_key(0xffe1, true, fresh_up)
        .expect("fresh modifier");
    assert_eq!(fresh_shift, fresh_up);
    assert_eq!(
        viewer
            .send_key(0xffe1, false, fresh_shift)
            .expect("fresh modifier release"),
        fresh_shift
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0xffe1,
            down: true
        }
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Key {
            keysym: 0xffe1,
            down: false
        }
    );

    // A subsequent emitted move orders this snapshot after the prior Up's
    // local accounting, not merely after the peer received its bytes.
    viewer
        .send_mouse(0, 0, 7, 5, fresh_shift)
        .expect("move after fresh releases");
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 7,
            y: 5,
            buttons: 0
        }
    );
    let settled = viewer.set_input_policy(ViewerInputPolicy::interactive());
    assert_eq!(settled.input_generation, second);
    assert_eq!(
        settled.releases_owed, 0,
        "the fresh pairs released their own holds"
    );
    assert_eq!(
        settled.releases_unreleased, 0,
        "and no hold of this writer's was left unconfirmed"
    );

    // A receipt names the generation its event was queued under, not a standing
    // permission: once the boundary moves again, an event queued with that
    // receipt is refused, and only the generation in force is admitted.
    let moved = viewer.set_input_policy(ViewerInputPolicy::read_only());
    let readmitted = viewer.set_input_policy(ViewerInputPolicy::interactive());
    assert!(
        readmitted.input_generation > moved.input_generation,
        "the boundary moved on from the receipt's generation"
    );
    assert!(
        matches!(
            viewer.send_mouse(0, 0, 6, 5, second),
            Err(ViewerError::StaleInputGeneration)
        ),
        "a receipt from a generation the engine has left cannot be reused"
    );
    assert_eq!(
        viewer
            .send_mouse(0, 0, 6, 5, readmitted.input_generation)
            .expect("the generation in force is admitted"),
        readmitted.input_generation
    );
    assert_eq!(
        next_client_message(&mut events).await,
        ClientMessage::Pointer {
            x: 6,
            y: 5,
            buttons: 0
        },
        "the refused event put nothing on the wire before the admitted one"
    );

    timeout(LIMIT, viewer.close())
        .await
        .expect("close settles")
        .expect("the surface was reclaimed");
}
