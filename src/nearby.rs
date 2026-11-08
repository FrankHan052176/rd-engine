//! The bounded byte transport behind a nearby share.
//!
//! A nearby share has no address: the bytes of the same RustDesk record stream a
//! direct share would have carried over TCP travel the platform's own connection
//! manager instead, one application frame per `sendData` call. Only the transport
//! differs, so this module speaks no RustDesk protocol of its own. The engine side
//! is a real [`FramedStream`], whose `BytesCodec` keeps the record boundaries, and
//! the platform side is a bounded queue of whole frames.
//!
//! Every frame is an envelope — its sequence number and its payload length, four
//! bytes each, little-endian — followed by exactly that many bytes. A lost,
//! repeated, reordered or lying frame, a queue overflow or a wire that stopped
//! ends the transport once, with the first cause it had; a record stream cannot
//! be replayed, so nothing here acknowledges, retries or patches over it.

use hbb_common::tcp::FramedStream;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

/// Most payload bytes one platform frame carries, envelope aside.
///
/// This is this bridge's own queue bound, not the platform's smaller
/// single-message limit: no caller has to cut a frame up itself.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;

/// The sequence number and the payload length a frame starts with.
pub const ENVELOPE_BYTES: usize = 8;

/// How many payload bytes the engine-facing pipe may hold before a write waits.
const DUPLEX_BYTES: usize = MAX_CHUNK_BYTES;

/// How many whole frames one direction may queue.
const QUEUED_FRAMES: usize = 4;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Why this transport ended, kept as the first cause that ended it.
#[derive(Clone, Copy)]
struct Terminal {
    kind: io::ErrorKind,
    reason: &'static str,
}

impl Terminal {
    fn aborted(reason: &'static str) -> Self {
        Self {
            kind: io::ErrorKind::ConnectionAborted,
            reason,
        }
    }
    fn invalid(reason: &'static str) -> Self {
        Self {
            kind: io::ErrorKind::InvalidData,
            reason,
        }
    }
    fn error(self) -> io::Error {
        io::Error::new(self.kind, self.reason)
    }
}

/// The fact that a share's transport ended, shared with the two pumps.
///
/// The first real cause is the one every later observation reports, so a read
/// that noticed the engine went away cannot overwrite the sequence number that
/// actually ended the wire.
struct Status {
    closed: AtomicBool,
    cancel: CancellationToken,
    terminal: Mutex<Option<Terminal>>,
}

impl Status {
    fn close(&self, terminal: Option<Terminal>) {
        if let Some(terminal) = terminal {
            let mut slot = lock(&self.terminal);
            if slot.is_none() {
                *slot = Some(terminal);
            }
        }
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    /// What every call after the end reports: the cause that ended this
    /// transport, or the plain close of an owner that named none.
    fn ended(&self) -> io::Error {
        match *lock(&self.terminal) {
            Some(terminal) => terminal.error(),
            None => io::Error::new(io::ErrorKind::ConnectionAborted, "Nearby bridge closed"),
        }
    }
}

/// The platform side of one nearby RustDesk wire, bounded in both directions.
///
/// The engine owns the paired [`FramedStream`]; this owner only ever sees the
/// bytes of that record stream, cut into frames. Dropping it ends the transport,
/// so the pumps and the engine's wire are released with it.
pub struct Bridge {
    status: Arc<Status>,
    /// Frames the pump queued for the platform, in wire order.
    output: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Frames the platform handed over, waiting for the pump to write them.
    input: mpsc::Sender<Vec<u8>>,
    /// The sequence number the input side has to arrive with next. It is held
    /// across the hand-over below so two callers cannot both spend it.
    expected: Mutex<u32>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.status.close(None);
    }
}

impl Bridge {
    /// Pairs one engine-side wire with the platform side this owner drives.
    ///
    /// Nothing is dialled, resolved or bound: both halves are one bounded
    /// in-memory pipe, so the engine's handshake, encryption and record framing
    /// run exactly as they do on a socket.
    pub fn pair() -> io::Result<(Arc<Self>, FramedStream)> {
        let runtime =
            crate::executor::runtime().map_err(|_| io::Error::other("Executor unavailable"))?;
        let (engine, platform) = tokio::io::duplex(DUPLEX_BYTES);
        let (reader, writer) = tokio::io::split(platform);
        let status = Arc::new(Status {
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
            terminal: Mutex::new(None),
        });
        let (output, output_frames) = mpsc::channel(QUEUED_FRAMES);
        let (input_frames, input) = mpsc::channel(QUEUED_FRAMES);
        runtime.spawn(pump_output(Arc::clone(&status), reader, output));
        runtime.spawn(pump_input(Arc::clone(&status), writer, input));
        let bridge = Arc::new(Self {
            status,
            output: Mutex::new(output_frames),
            input: input_frames,
            expected: Mutex::new(0),
        });
        // A `FramedStream` records an address beside its codec. This wire has
        // none of its own, so the value is bookkeeping that is never dialled,
        // displayed or put in an invitation.
        let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        Ok((bridge, FramedStream::from(engine, address)))
    }

    /// Takes the next frame the engine wrote, in wire order.
    ///
    /// `Ok(None)` means nothing is queued right now and the wire is still open.
    /// `Err` is terminal: nothing is queued afterwards either, and the error is
    /// the transport's own cause for ending.
    pub fn take_output(&self) -> io::Result<Option<Vec<u8>>> {
        let mut output = lock(&self.output);
        // A revoked transport hands out nothing more. Frames still queued belong
        // to a session that is over — bytes encrypted under its own nonce
        // counters must never leave after the cancellation that ended it.
        if self.status.is_closed() {
            output.close();
            while output.try_recv().is_ok() {}
            return Err(self.status.ended());
        }
        match output.try_recv() {
            Ok(frame) => Ok(Some(frame)),
            // The pump drops its sender when it ends, and a queue only empties
            // before it disconnects, so nothing queued is lost here.
            Err(mpsc::error::TryRecvError::Disconnected) => Err(self.status.ended()),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
        }
    }

    /// Hands one frame received from the platform to the engine.
    ///
    /// The frame has to carry the next sequence number and say exactly how many
    /// bytes it has. A missing, repeated or reordered frame, a length its own
    /// bytes do not match, or a queue with no room ends the transport: the
    /// engine's record stream is never moved past bytes it did not see.
    pub fn push_input(&self, frame: &[u8]) -> io::Result<()> {
        let mut expected = lock(&self.expected);
        if self.status.is_closed() {
            return Err(self.status.ended());
        }
        let Some((sequence, length)) = envelope(frame) else {
            let terminal = Terminal::invalid("Nearby frame does not carry its own length");
            self.status.close(Some(terminal));
            return Err(terminal.error());
        };
        if sequence != *expected {
            let terminal = Terminal::invalid("Nearby frame arrived out of order");
            self.status.close(Some(terminal));
            return Err(terminal.error());
        }
        *expected = expected.wrapping_add(1);
        match self.input.try_send(frame[ENVELOPE_BYTES..ENVELOPE_BYTES + length].to_vec()) {
            Ok(()) => Ok(()),
            Err(_) => {
                let terminal = Terminal::aborted("Nearby bridge input queue overflowed");
                self.status.close(Some(terminal));
                Err(terminal.error())
            }
        }
    }

    /// Ends this transport: both pumps stop, the engine's wire closes, and every
    /// later call reports the terminal error.
    pub fn close(&self) {
        self.status.close(None);
    }

    /// Whether this transport has ended, whatever the cause.
    pub fn is_closed(&self) -> bool {
        self.status.is_closed()
    }
}

/// Reads one frame's envelope and checks that it describes exactly this frame.
fn envelope(frame: &[u8]) -> Option<(u32, usize)> {
    let header = frame.get(..ENVELOPE_BYTES)?;
    let sequence = u32::from_le_bytes(header.get(..4)?.try_into().ok()?);
    let length = usize::try_from(u32::from_le_bytes(header.get(4..)?.try_into().ok()?)).ok()?;
    (length <= MAX_CHUNK_BYTES && frame.len() == ENVELOPE_BYTES + length)
        .then_some((sequence, length))
}

/// Pumps the engine's record-stream bytes into whole platform frames.
///
/// Both waits end with the transport: a full queue never outlives a cancelled
/// bridge, and a cancelled read consumes nothing it did not return.
async fn pump_output(
    status: Arc<Status>,
    mut reader: ReadHalf<DuplexStream>,
    output: mpsc::Sender<Vec<u8>>,
) {
    // One frame's payload, never larger than the buffer the engine writes into.
    let mut payload = vec![0u8; MAX_CHUNK_BYTES];
    let mut sequence = 0u32;
    let terminal = loop {
        let read = tokio::select! {
            biased;
            _ = status.cancel.cancelled() => break None,
            read = reader.read(&mut payload) => read,
        };
        let Ok(bytes) = read else {
            break Some(Terminal::aborted("Nearby bridge could not read the engine wire"));
        };
        if bytes == 0 {
            break Some(Terminal::aborted("The engine closed the nearby wire"));
        }
        let mut frame = Vec::with_capacity(ENVELOPE_BYTES + bytes);
        frame.extend_from_slice(&sequence.to_le_bytes());
        // `bytes` was read into a `MAX_CHUNK_BYTES` buffer, so it always fits.
        frame.extend_from_slice(&(bytes as u32).to_le_bytes());
        frame.extend_from_slice(&payload[..bytes]);
        sequence = sequence.wrapping_add(1);
        // Waiting here is what bounds this direction: the pipe stops being
        // drained instead of the frames being buffered without limit.
        let sent = tokio::select! {
            biased;
            _ = status.cancel.cancelled() => break None,
            sent = output.send(frame) => sent,
        };
        if sent.is_err() {
            break Some(Terminal::aborted("The nearby bridge closed before a frame was taken"));
        }
    };
    status.close(terminal);
}

/// Writes whole platform frames into the engine's record stream.
///
/// A cancelled write is not retried: it may have started a record the engine
/// cannot tell from a complete one, so it ends this transport instead.
async fn pump_input(
    status: Arc<Status>,
    mut writer: WriteHalf<DuplexStream>,
    mut input: mpsc::Receiver<Vec<u8>>,
) {
    let terminal = loop {
        let frame = tokio::select! {
            biased;
            _ = status.cancel.cancelled() => break None,
            frame = input.recv() => match frame {
                Some(frame) => frame,
                // Every sender is gone: the owner neither closed this bridge nor
                // kept it, so there is nothing left to write and no cause to name.
                None => break None,
            },
        };
        let written = tokio::select! {
            biased;
            _ = status.cancel.cancelled() => break None,
            written = writer.write_all(&frame) => written,
        };
        if written.is_err() {
            break Some(Terminal::aborted("Nearby bridge could not write the engine wire"));
        }
    };
    // Dropping the write half is what ends the engine's read side, so a session
    // waiting for the peer's next record sees the transport end rather than
    // waiting for a frame that can no longer arrive.
    status.close(terminal);
}
