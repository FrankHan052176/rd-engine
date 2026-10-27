//! End-to-end RFB session test against a wire-accurate fixture server.
//!
//! The fixture speaks the protocol the way a real server does — version banner,
//! security-type list, the DES challenge, ServerInit, then updates — so the
//! client is exercised across its whole path: negotiation, authentication,
//! `SetPixelFormat` derived from the sink, the encoding list, rectangle
//! decoding into the presentation sink, and input framing back to the server.
//!
//! This follows the shape of `tests/direct_auth.rs`: an independent
//! implementation of the wire contract driving the engine's real types.

use rd_engine::protocol::rect::PixelTarget;
use rd_engine::protocol::{
    Endpoint,
    rfb::{
        RfbError,
        session::{RfbEvent, RfbOptions, RfbSession},
    },
};
use rd_engine::surface::MemorySurface;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

const PASSWORD: &str = "hunter2";
const NAME: &str = "fixture-desktop";
const WIDTH: u16 = 6;
const HEIGHT: u16 = 4;
/// Far longer than a loopback dialogue needs; it exists so a regression fails a
/// test instead of hanging it.
const LIMIT: Duration = Duration::from_secs(12);

const MESSAGE_FRAMEBUFFER_UPDATE: u8 = 0;
const MESSAGE_BELL: u8 = 2;
const MESSAGE_CUT_TEXT: u8 = 3;
const ENCODING_RAW: i32 = 0;
const ENCODING_COPY_RECT: i32 = 1;

/// One pixel as the fixture paints it, in the sink's BGRA order.
const RED: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

/// What the fixture observed from the client, for the assertions that are about
/// the client's outbound bytes rather than about decoded pixels.
#[derive(Debug, Default, PartialEq, Eq)]
struct Observed {
    version: String,
    chosen_security: u8,
    shared: u8,
    pixel_format: Vec<u8>,
    encodings: Vec<i32>,
    first_request: Vec<u8>,
    second_request: Vec<u8>,
    pointer: Vec<u8>,
    key_down: Vec<u8>,
    key_up: Vec<u8>,
    clipboard: Vec<u8>,
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

async fn read_message(stream: &mut TcpStream, length: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; length];
    read_exact(stream, &mut buffer).await;
    buffer
}

/// ClientCutText carries its own length, so it is read in two steps.
async fn read_variable(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = vec![0u8; 8];
    read_exact(stream, &mut head).await;
    let length = u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize;
    let mut body = vec![0u8; length];
    read_exact(stream, &mut body).await;
    head.extend_from_slice(&body);
    head
}

/// A `FramebufferUpdate`: message type, padding, rectangle count, rectangles.
fn update(rectangles: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(MESSAGE_FRAMEBUFFER_UPDATE);
    out.push(0);
    out.extend_from_slice(&(rectangles as u16).to_be_bytes());
    out
}

fn rect_header(out: &mut Vec<u8>, x: i32, y: i32, width: i32, height: i32, encoding: i32) {
    out.extend_from_slice(&(x as u16).to_be_bytes());
    out.extend_from_slice(&(y as u16).to_be_bytes());
    out.extend_from_slice(&(width as u16).to_be_bytes());
    out.extend_from_slice(&(height as u16).to_be_bytes());
    out.extend_from_slice(&encoding.to_be_bytes());
}

/// Serves one complete session, then reports what it saw.
async fn serve(listener: TcpListener) -> Observed {
    let (mut stream, _peer) = timeout(LIMIT, listener.accept())
        .await
        .expect("accept did not stall")
        .expect("accept");
    let mut seen = Observed::default();

    write_all(&mut stream, b"RFB 003.008\n").await;
    let mut banner = [0u8; 12];
    read_exact(&mut stream, &mut banner).await;
    seen.version = String::from_utf8_lossy(&banner).into_owned();

    // Offer VNC auth and None; the client must prefer the one that proves the
    // password.
    write_all(&mut stream, &[2, 1, 2]).await;
    let mut chosen = [0u8; 1];
    read_exact(&mut stream, &mut chosen).await;
    seen.chosen_security = chosen[0];

    let challenge: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    write_all(&mut stream, &challenge).await;
    let response = read_message(&mut stream, 16).await;
    // A real server checks the response, so a wrong password has to fail here
    // rather than be accepted and discovered later.
    // Independent OpenSSL DES-ECB vector for bit-reversed "hunter2\\0".
    // The fixture must not call the client's authentication implementation.
    let expected = [0xae, 0x2f, 0xfb, 0x6b, 0x2f, 0xdd, 0x58, 0xfb,
                    0x77, 0x56, 0x79, 0x77, 0xd8, 0xd5, 0xec, 0xe4];
    assert_eq!(response, expected, "the client's DES response");
    write_all(&mut stream, &0u32.to_be_bytes()).await;

    let mut shared = [0u8; 1];
    read_exact(&mut stream, &mut shared).await;
    seen.shared = shared[0];

    // ServerInit: geometry, a server-side pixel format the client must replace,
    // then the desktop name.
    let mut init = Vec::new();
    init.extend_from_slice(&WIDTH.to_be_bytes());
    init.extend_from_slice(&HEIGHT.to_be_bytes());
    init.extend_from_slice(&[
        32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
    ]);
    init.extend_from_slice(&(NAME.len() as u32).to_be_bytes());
    init.extend_from_slice(NAME.as_bytes());
    write_all(&mut stream, &init).await;

    let mut set_format = [0u8; 20];
    read_exact(&mut stream, &mut set_format).await;
    seen.pixel_format = set_format[4..].to_vec();

    let mut encoding_header = [0u8; 4];
    read_exact(&mut stream, &mut encoding_header).await;
    let count = usize::from(u16::from_be_bytes([encoding_header[2], encoding_header[3]]));
    let encodings = read_message(&mut stream, count * 4).await;
    seen.encodings = encodings
        .chunks_exact(4)
        .map(|chunk| i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    // The first request must ask for the whole desktop, non-incrementally.
    seen.first_request = read_message(&mut stream, 10).await;

    // One raw rectangle covering the desktop.
    let mut message = update(1);
    rect_header(&mut message, 0, 0, WIDTH as i32, HEIGHT as i32, ENCODING_RAW);
    for _ in 0..(WIDTH as usize * HEIGHT as usize) {
        message.extend_from_slice(&RED);
    }
    write_all(&mut stream, &message).await;

    // LibVNCClient automatically asks for the next update while finishing this one.
    seen.second_request = read_message(&mut stream, 10).await;

    // A one-pixel CopyRect: the pixel must move within the sink.
    let mut message = update(1);
    rect_header(&mut message, 1, 1, 1, 1, ENCODING_COPY_RECT);
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    write_all(&mut stream, &message).await;

    let _ = read_message(&mut stream, 10).await;

    seen.pointer = read_message(&mut stream, 6).await;
    seen.key_down = read_message(&mut stream, 8).await;
    seen.key_up = read_message(&mut stream, 8).await;
    seen.clipboard = read_variable(&mut stream).await;

    // A bell carries no pixels; the cut text arrives as its own event.
    write_all(&mut stream, &[MESSAGE_BELL]).await;
    let mut cut = vec![MESSAGE_CUT_TEXT, 0, 0, 0];
    cut.extend_from_slice(&4u32.to_be_bytes());
    cut.extend_from_slice(b"ping");
    write_all(&mut stream, &cut).await;

    seen
}

async fn fixture() -> (SocketAddr, oneshot::Receiver<Observed>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let observed = serve(listener).await;
        let _ = tx.send(observed);
    });
    (address, rx)
}

fn options(address: SocketAddr) -> RfbOptions {
    RfbOptions {
        endpoint: Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
            user: None,
        },
        password: PASSWORD.to_owned(),
        shared: true,
    }
}

fn request_geometry(request: &[u8]) -> (u16, u16, u16, u16) {
    (
        u16::from_be_bytes([request[2], request[3]]),
        u16::from_be_bytes([request[4], request[5]]),
        u16::from_be_bytes([request[6], request[7]]),
        u16::from_be_bytes([request[8], request[9]]),
    )
}

/// Connect, or panic with the client's own error. `RfbSession` deliberately has
/// no `Debug` (it owns credentials), so `expect_err` is not available.
async fn connect_or_panic(address: SocketAddr, sink: &MemorySurface) -> RfbSession {
    match timeout(LIMIT, RfbSession::connect(options(address), sink.layout())).await {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => panic!("connect failed: {error}"),
        Err(_) => panic!("connect did not settle"),
    }
}

async fn connect_error(address: SocketAddr, sink: &MemorySurface) -> RfbError {
    match timeout(LIMIT, RfbSession::connect(options(address), sink.layout())).await {
        Ok(Err(error)) => error,
        Ok(Ok(_)) => panic!("the session must not have connected"),
        Err(_) => panic!("connect did not settle"),
    }
}

/// The whole dialogue: negotiate, authenticate, decode two updates into the
/// sink, and send input back.
#[tokio::test]
async fn a_real_rfb_dialogue_negotiates_authenticates_and_paints() {
    let (address, observed) = fixture().await;
    let mut sink = MemorySurface::new(WIDTH as i32, HEIGHT as i32).expect("sink");
    let mut session = connect_or_panic(address, &sink).await;

    assert_eq!(session.desktop(), (WIDTH as i32, HEIGHT as i32));
    assert_eq!(session.name(), NAME);

    let event = timeout(LIMIT, session.pump(&mut sink))
        .await
        .expect("pump did not stall")
        .expect("pump");
    assert_eq!(event, Some(RfbEvent::Painted));
    let damage = sink.take_damage().expect("damage");
    assert_eq!(
        (damage.x, damage.y, damage.width, damage.height),
        (0, 0, WIDTH as i32, HEIGHT as i32)
    );
    for pixel in sink.bytes().chunks_exact(4) {
        assert_eq!(pixel, RED, "every pixel of the raw rectangle");
    }


    // A CopyRect from (0,0) to (1,1) moves one pixel and damages only that
    // rectangle, so the sink keeps the rest of the frame.
    let event = timeout(LIMIT, session.pump(&mut sink))
        .await
        .expect("pump did not stall")
        .expect("pump");
    assert_eq!(event, Some(RfbEvent::Painted));
    let damage = sink.take_damage().expect("copy damage");
    assert_eq!((damage.x, damage.y, damage.width, damage.height), (1, 1, 1, 1));
    assert_eq!(&sink.bytes()[..4], &RED, "the first pixel is untouched");
    let stride = sink.stride();
    assert_eq!(
        &sink.bytes()[stride + 4..stride + 8],
        &RED,
        "the copied pixel landed at (1, 1)"
    );

    session.send_pointer(3, 2, 1).await.expect("pointer");
    session.send_key(0x0041, true).await.expect("key down");
    session.send_key(0x0041, false).await.expect("key up");
    session.send_clipboard("hello").await.expect("clipboard");

    let event = timeout(LIMIT, session.pump(&mut sink))
        .await
        .expect("pump did not stall")
        .expect("pump");
    assert_eq!(event, Some(RfbEvent::Bell), "a bell carries no pixels");
    let event = timeout(LIMIT, session.pump(&mut sink))
        .await
        .expect("pump did not stall")
        .expect("pump");
    assert_eq!(event, Some(RfbEvent::Clipboard("ping".into())));


    let observed = timeout(LIMIT, observed)
        .await
        .expect("fixture finished")
        .expect("fixture reported");

    assert_eq!(observed.version, "RFB 003.008\n");
    assert_eq!(observed.chosen_security, 2, "VNC auth beats None");
    assert_eq!(observed.shared, 1, "the shared flag travels in ClientInit");
    assert_eq!(
        observed.pixel_format,
        vec![32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0],
        "SetPixelFormat must describe the sink's BGRA layout"
    );
    assert!(
        observed.encodings.contains(&ENCODING_RAW),
        "raw must be advertised: {:?}",
        observed.encodings
    );
    assert!(
        observed.encodings.contains(&ENCODING_COPY_RECT),
        "copy-rect must be advertised"
    );

    assert_eq!(observed.first_request[0], 3, "FramebufferUpdateRequest");
    assert_eq!(observed.first_request[1], 0, "the first request is full");
    assert_eq!(
        request_geometry(&observed.first_request),
        (0, 0, WIDTH, HEIGHT)
    );
    assert_eq!(
        observed.second_request[1], 1,
        "later requests are incremental"
    );

    assert_eq!(observed.pointer[0], 5, "PointerEvent");
    assert_eq!(observed.pointer[1], 1, "left button down");
    assert_eq!(
        u16::from_be_bytes([observed.pointer[2], observed.pointer[3]]),
        3
    );
    assert_eq!(
        u16::from_be_bytes([observed.pointer[4], observed.pointer[5]]),
        2
    );
    assert_eq!(observed.key_down[0], 4, "KeyEvent");
    assert_eq!(observed.key_down[1], 1, "the first key event is a press");
    assert_eq!(observed.key_up[1], 0, "the second is a release");
    assert_eq!(
        u32::from_be_bytes([
            observed.key_down[4],
            observed.key_down[5],
            observed.key_down[6],
            observed.key_down[7]
        ]),
        0x0041
    );
    assert_eq!(observed.clipboard[0], 6, "ClientCutText");
    assert_eq!(&observed.clipboard[8..], b"hello");
}

/// A server that refuses the password must be reported as an authentication
/// failure, not as a transport error.
#[tokio::test]
async fn a_rejected_password_is_reported_as_an_authentication_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        write_all(&mut stream, b"RFB 003.008\n").await;
        let mut banner = [0u8; 12];
        read_exact(&mut stream, &mut banner).await;
        write_all(&mut stream, &[1, 2]).await;
        let mut chosen = [0u8; 1];
        read_exact(&mut stream, &mut chosen).await;
        write_all(&mut stream, &[0u8; 16]).await;
        let _ = read_message(&mut stream, 16).await;
        // SecurityResult = 1, then the reason string 3.8 sends after a failure.
        write_all(&mut stream, &1u32.to_be_bytes()).await;
        let mut reason = Vec::new();
        reason.extend_from_slice(&(b"bad password".len() as u32).to_be_bytes());
        reason.extend_from_slice(b"bad password");
        write_all(&mut stream, &reason).await;
    });

    let mut sink = MemorySurface::new(2, 2).expect("sink");
    match connect_error(address, &sink).await {
        RfbError::AuthenticationFailed(detail) => {
            assert_eq!(detail, "bad password", "the server's reason is carried");
        }
        other => panic!("expected an authentication failure, got {other}"),
    }
    assert!(sink.take_damage().is_none(), "a failed login paints nothing");
}

/// A server offering only types this client cannot complete is refused rather
/// than connected to unauthenticated.
#[tokio::test]
async fn a_server_with_no_usable_security_type_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        write_all(&mut stream, b"RFB 003.008\n").await;
        let mut banner = [0u8; 12];
        read_exact(&mut stream, &mut banner).await;
        // Apple's own types only: neither None nor VNC authentication.
        write_all(&mut stream, &[3, 30, 33, 36]).await;
        // Hold the connection open, so the refusal comes from the client's own
        // decision rather than from a socket that closed underneath it.
        let mut sink = [0u8; 1];
        let _ = timeout(LIMIT, stream.read(&mut sink)).await;
    });

    let sink = MemorySurface::new(2, 2).expect("sink");
    let error = connect_error(address, &sink).await;
    assert!(
        matches!(error, RfbError::NoUsableSecurityType),
        "got {error}"
    );
}

/// Upstream owns the initial and subsequent requests. An ordinary update must
/// produce exactly one incremental request without a viewer-side request call.
#[tokio::test]
async fn upstream_sends_exactly_one_incremental_request_per_update() {
    /// Long enough that a request the client meant to send would have arrived.
    const QUIET: Duration = Duration::from_millis(250);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        write_all(&mut stream, b"RFB 003.008\n").await;
        let mut banner = [0u8; 12];
        read_exact(&mut stream, &mut banner).await;
        // Security type None: this test is about request pacing, not about the
        // authentication exchange.
        write_all(&mut stream, &[1, 1]).await;
        let mut chosen = [0u8; 1];
        read_exact(&mut stream, &mut chosen).await;
        assert_eq!(chosen[0], 1, "the only offered type is accepted");
        write_all(&mut stream, &0u32.to_be_bytes()).await;

        let mut shared = [0u8; 1];
        read_exact(&mut stream, &mut shared).await;
        let mut init = Vec::new();
        init.extend_from_slice(&4u16.to_be_bytes());
        init.extend_from_slice(&2u16.to_be_bytes());
        init.extend_from_slice(&[
            32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
        ]);
        init.extend_from_slice(&0u32.to_be_bytes());
        write_all(&mut stream, &init).await;

        let mut set_format = [0u8; 20];
        read_exact(&mut stream, &mut set_format).await;
        let mut encoding_header = [0u8; 4];
        read_exact(&mut stream, &mut encoding_header).await;
        let count = usize::from(u16::from_be_bytes([encoding_header[2], encoding_header[3]]));
        let _ = read_message(&mut stream, count * 4).await;

        // The first request must be the only thing on the wire right now.
        let first = read_message(&mut stream, 10).await;
        let mut probe = [0u8; 1];
        let quiet = timeout(QUIET, stream.read(&mut probe)).await;

        // Answer, then observe the library-driven incremental request.
        let mut update = update(1);
        rect_header(&mut update, 0, 0, 4, 2, ENCODING_RAW);
        update.extend_from_slice(&[0u8; 32]);
        write_all(&mut stream, &update).await;
        let second = read_message(&mut stream, 10).await;
        let duplicate = timeout(QUIET, stream.read(&mut probe)).await;
        let _ = tx.send((first, quiet.is_err(), second, duplicate.is_err()));
    });

    let mut sink = MemorySurface::new(4, 2).expect("sink");
    let mut session = connect_or_panic(address, &sink).await;
    // The first pump blocks until the fixture answers, so it runs concurrently
    // with the fixture's quiet window.
    let event = timeout(LIMIT, session.pump(&mut sink))
        .await
        .expect("pump did not stall")
        .expect("pump");
    assert_eq!(event, Some(RfbEvent::Painted));


    let (first, was_quiet, second, no_duplicate) = timeout(LIMIT, rx)
        .await
        .expect("fixture finished")
        .expect("fixture reported");
    assert_eq!(first[1], 0, "the first request is a full one");
    assert!(
        was_quiet,
        "the client sent another request before receiving an update"
    );
    assert_eq!(
        second[1], 1,
        "upstream requests the next update without a caller request"
    );
    assert!(no_duplicate, "the adapter duplicated upstream's incremental request");
}
