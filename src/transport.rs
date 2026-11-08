//! Full-duplex RustDesk transport, without the legacy read/write select loop.
//! Handshake code supplies the established framing/encryption state. Splitting
//! preserves both nonce counters and already-buffered bytes. There is one writer
//! so control/media interleaving cannot race the encryption sequence.

use base::message_proto::Message;
use hbb_common::{
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    futures::{
        SinkExt, StreamExt,
        stream::{SplitSink, SplitStream},
    },
    protobuf::Message as ProtobufMessage,
    tcp::{DynTcpStream, Encrypt, FramedStream},
};
use std::{
    io,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio_util::{codec::Framed, sync::CancellationToken};

const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
type Framing = Framed<DynTcpStream, BytesCodec>;

/// The stage the one reader of a session is standing in, as a fixed label.
///
/// The list is closed: a reader publishes one of these and nothing derives a
/// label from a message, so no address, message kind or payload text can ever
/// appear in a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderPhase {
    /// Waiting for a complete framed record to arrive.
    WireWait,
    /// A complete record was taken and is being decrypted and parsed.
    WireDecode,
    VideoDispatch,
    CursorDispatch,
    TransferDispatch,
    CliprdrDispatch,
    ControlDispatch,
    OtherDispatch,
    /// Terminal: this reader has returned, so it stands in no stage any more.
    Stopped,
}

impl ReaderPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::WireWait => "wire_wait",
            Self::WireDecode => "wire_decode",
            Self::VideoDispatch => "video_dispatch",
            Self::CursorDispatch => "cursor_dispatch",
            Self::TransferDispatch => "transfer_dispatch",
            Self::CliprdrDispatch => "cliprdr_dispatch",
            Self::ControlDispatch => "control_dispatch",
            Self::OtherDispatch => "other_dispatch",
            Self::Stopped => "stopped",
        }
    }
}

/// One reading of where the reader stands and how long it has stood there.
///
/// `age_ms` is dwell time in `phase` on the same monotonic clock the stage was
/// entered with. It is not CPU time, not a per-frame duration and never an
/// average: for `stopped` it is how long the reading has been over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderProgressSnapshot {
    pub phase: &'static str,
    pub age_ms: u64,
}

/// Where the one reader of a session is standing right now.
///
/// It is deliberately a small lock of its own and not part of the session's
/// state: a reader records its stage *before* the work that stage can block on,
/// so the stage a session is stuck in stays readable while the reader itself
/// waits for state it is about to touch. Nothing here is aggregated, sampled or
/// replayed, no history is kept, and the lock is never held while the reader
/// waits.
pub struct ReaderProgress {
    current: Mutex<Option<(ReaderPhase, Instant)>>,
}

impl ReaderProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(None),
        })
    }

    fn current(&self) -> MutexGuard<'_, Option<(ReaderPhase, Instant)>> {
        self.current.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Records the stage this reader is entering now, with a fresh clock.
    pub fn enter(&self, phase: ReaderPhase) {
        *self.current() = Some((phase, Instant::now()));
    }

    /// Ends the reading: the reader stands in no stage afterwards, so the stage
    /// it left is never left standing as if it were still in it.
    pub fn end(&self) {
        self.enter(ReaderPhase::Stopped);
    }

    /// The stage and its dwell age, or `None` when no reader publishes a stage
    /// for this session yet.
    pub fn snapshot(&self) -> Option<ReaderProgressSnapshot> {
        let (phase, since) = (*self.current())?;
        Some(ReaderProgressSnapshot {
            phase: phase.label(),
            age_ms: u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

pub struct WireReader {
    stream: SplitStream<Framing>,
    cipher: Option<Encrypt>,
    closed: CancellationToken,
    /// Set only by a session reader that wants its stages published. Every other
    /// caller leaves it unset and behaves exactly as before.
    progress: Option<Arc<ReaderProgress>>,
}

pub struct WireWriter {
    sink: SplitSink<Framing, Bytes>,
    cipher: Option<Encrypt>,
    deadline: Option<Duration>,
    closed: CancellationToken,
}

/// An intentionally plain negotiated connection is supported; this function
/// does not make authentication decisions. Complete key transitions first.
pub fn split(mut wire: FramedStream) -> (WireReader, WireWriter) {
    wire.0.codec_mut().set_max_packet_length(
        MAX_MESSAGE_BYTES + hbb_common::sodiumoxide::crypto::secretbox::MACBYTES,
    );
    let deadline = (wire.3 != 0).then(|| Duration::from_millis(wire.3));
    let cipher = wire.2;
    let (sink, stream) = wire.0.split();
    let closed = CancellationToken::new();
    (
        WireReader {
            stream,
            cipher: cipher.clone(),
            closed: closed.clone(),
            progress: None,
        },
        WireWriter {
            sink,
            cipher,
            deadline,
            closed,
        },
    )
}

fn disconnected() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "RustDesk transport closed",
    )
}

impl WireReader {
    pub async fn recv(&mut self) -> io::Result<Option<Message>> {
        self.publish(ReaderPhase::WireWait);
        let packet = tokio::select! {
            biased;
            _ = self.closed.cancelled() => return Err(disconnected()),
            packet = self.stream.next() => packet,
        };
        let result = match packet {
            None => {
                self.closed.cancel();
                return Ok(None);
            }
            Some(Err(error)) => Err(error),
            Some(Ok(mut bytes)) => {
                // The record is complete here, so what follows is this session's
                // own decryption and parsing: a reader waiting in this stage is
                // not waiting for the wire.
                self.publish(ReaderPhase::WireDecode);
                self.decode(&mut bytes)
            }
        };
        if result.is_err() {
            self.closed.cancel();
        }
        result.map(Some)
    }

    /// Turns publishing on for this reader, which is off by default so no other
    /// caller of the transport changes behavior.
    pub fn track_progress(&mut self, progress: Arc<ReaderProgress>) {
        self.progress = Some(progress);
    }

    /// Publishes one stage when a session asked this reader to.
    fn publish(&self, phase: ReaderPhase) {
        if let Some(progress) = &self.progress {
            progress.enter(phase);
        }
    }

    fn decode(&mut self, bytes: &mut BytesMut) -> io::Result<Message> {
        if let Some(cipher) = &mut self.cipher {
            cipher.dec(bytes)?;
        }
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Oversized RustDesk message",
            ));
        }
        Message::parse_from_bytes(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

/// A cancelled send may already have consumed its nonce or written part of a
/// frame. It must terminate the connection, never retry on the same byte stream.
struct PendingWrite {
    closed: CancellationToken,
    complete: bool,
}
impl Drop for PendingWrite {
    fn drop(&mut self) {
        if !self.complete {
            self.closed.cancel();
        }
    }
}

impl WireWriter {
    pub async fn send(&mut self, message: &Message) -> io::Result<()> {
        if self.closed.is_cancelled() {
            return Err(disconnected());
        }
        if message.compute_size() > MAX_MESSAGE_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Oversized RustDesk message",
            ));
        }
        let mut bytes = message
            .write_to_bytes()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut pending = PendingWrite {
            closed: self.closed.clone(),
            complete: false,
        };
        if let Some(cipher) = &mut self.cipher {
            bytes = cipher.enc(&bytes);
        }
        let deadline = self.deadline;
        let send = self.sink.send(Bytes::from(bytes));
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => return Err(disconnected()),
            result = async {
                match deadline {
                    Some(limit) => tokio::time::timeout(limit, send).await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "RustDesk write timeout"))?,
                    None => send.await,
                }
            } => result?,
        }
        pending.complete = true;
        Ok(())
    }
}

impl Drop for WireReader {
    fn drop(&mut self) {
        self.closed.cancel();
        // A reader that has returned publishes no active stage: the stage it
        // left is replaced by the terminal one instead of staying on display.
        if let Some(progress) = &self.progress {
            progress.end();
        }
    }
}
impl Drop for WireWriter {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::Hash;
    use hbb_common::sodiumoxide::crypto::secretbox;

    fn message(challenge: &str) -> Message {
        let mut message = Message::new();
        message.set_hash(Hash {
            salt: "test-salt".into(),
            challenge: challenge.into(),
            ..Default::default()
        });
        message
    }

    fn pair() -> (FramedStream, FramedStream) {
        let (a, b) = tokio::io::duplex(1024);
        let address = "127.0.0.1:1".parse().unwrap();
        (
            FramedStream::from(a, address),
            FramedStream::from(b, address),
        )
    }

    #[tokio::test]
    async fn upstream_peer_roundtrip_preserves_nonce_counters_and_buffered_frames() {
        hbb_common::sodiumoxide::init().unwrap();
        let (mut current, mut upstream) = pair();
        current.set_key(secretbox::Key([7; secretbox::KEYBYTES]));
        upstream.set_key(secretbox::Key([7; secretbox::KEYBYTES]));
        let first = message("before-split");
        current.send(&first).await.unwrap();
        upstream.next().await.unwrap().unwrap();
        upstream.send(&first).await.unwrap();
        current.next().await.unwrap().unwrap();
        let later = message("after-split");
        upstream.send(&later).await.unwrap();
        let (mut reader, mut writer) = split(current);
        assert_eq!(reader.recv().await.unwrap().unwrap(), later);
        writer.send(&later).await.unwrap();
        let bytes = upstream.next().await.unwrap().unwrap();
        assert_eq!(Message::parse_from_bytes(&bytes).unwrap(), later);
    }

    #[tokio::test]
    async fn cancelled_partial_send_is_terminal_and_does_not_retry_nonce() {
        let (current, _upstream) = pair();
        let (mut reader, mut writer) = split(current);
        let large = message(&"x".repeat(8192));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), writer.send(&large))
                .await
                .is_err()
        );
        assert!(writer.send(&message("must-not-send")).await.is_err());
        assert!(reader.recv().await.is_err());
    }

    /// A tracked reader publishes the stage it stands in before it waits for it,
    /// and a reader that has ended is published as stopped instead of being left
    /// standing in the stage it left.
    #[tokio::test]
    async fn reader_progress_publishes_the_wire_stage_and_a_stopped_terminus() {
        let (current, mut upstream) = pair();
        let (mut reader, _writer) = split(current);
        let progress = ReaderProgress::new();
        reader.track_progress(Arc::clone(&progress));
        assert_eq!(progress.snapshot(), None, "no stage before the reader runs");

        // Poll the read without sending anything: `recv` records its stage before
        // it waits, so the stage exists while the read is still pending.
        let mut pending = Box::pin(reader.recv());
        tokio::select! {
            biased;
            _ = &mut pending => panic!("a read with nothing to take returned"),
            _ = tokio::task::yield_now() => {}
        }
        let waiting = progress.snapshot().expect("the waiting read is published");
        assert_eq!(waiting.phase, "wire_wait");
        // A real wait, so the age below is a measurement rather than the zero a
        // getter would return.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let grown = progress.snapshot().expect("the stage is still the same one");
        assert_eq!(grown.phase, "wire_wait");
        assert!(
            grown.age_ms >= waiting.age_ms + 15,
            "the dwell age grows while the read waits: {} -> {}",
            waiting.age_ms,
            grown.age_ms
        );

        let later = message("one");
        upstream.send(&later).await.unwrap();
        assert_eq!(pending.await.unwrap().unwrap(), later);

        drop(reader);
        let stopped = progress.snapshot().expect("an ended reader is still observed");
        assert_eq!(
            stopped.phase, "stopped",
            "a finished reader is not left standing in a stage"
        );
    }
}
