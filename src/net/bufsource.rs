//! Buffered read side for the byte-stream protocols (RFB and RDP).
//!
//! The original RustDesk transport frames every record with a length prefix and
//! is parsed as a whole `Message` (see `crate::transport`). Neither RFB nor RDP
//! works that way: RFB has no outer frame at all and RDP's TPKT length is only
//! the first framing layer, so both need "give me at least N contiguous bytes,
//! refilling from the socket as required" while a decoder walks the structure.
//!
//! This is deliberately the only place those protocols read a socket. It owns
//! no async trait object: `window` is generic over the reader, so the decoders
//! in `crate::protocol` stay plain generic `async fn`s and still write pixels
//! through a `&mut dyn PixelTarget`.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Upper bound on one contiguous window. A peer that announces a larger
/// rectangle than this is rejected before any allocation happens.
pub const MAX_WINDOW_BYTES: usize = 16 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;

pub struct BufSource<S> {
    stream: S,
    buf: Vec<u8>,
    /// Bytes before `start` are already consumed and may be reclaimed.
    start: usize,
    filled: usize,
    /// Time spent awaiting the socket. A decode budget excludes transport, so
    /// a caller measuring one subtracts this across the operation.
    blocked: std::time::Duration,
}

impl<S: AsyncRead + Unpin> BufSource<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            start: 0,
            filled: 0,
            blocked: std::time::Duration::ZERO,
        }
    }

    /// Bytes already buffered but not yet consumed.
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..self.filled]
    }

    /// Bytes already buffered without waiting for a refill, or `None` when the
    /// caller must await `window`. Lets a decoder take the common
    /// "everything is already in the buffer" path without an await point.
    pub fn ready(&self, n: usize) -> Option<&[u8]> {
        let len = self.filled - self.start;
        (len >= n).then(|| &self.buf[self.start..self.filled])
    }

    /// Total time this source has spent awaiting its underlying reader.
    ///
    /// A decode budget is about decode, not transport, so a caller measuring one
    /// takes this before and after an operation and subtracts the difference.
    /// Monotonic, and only advances on a read that actually had to wait.
    pub fn blocked_time(&self) -> std::time::Duration {
        self.blocked
    }

    pub fn consume(&mut self, n: usize) {
        debug_assert!(self.start + n <= self.filled);
        self.start = (self.start + n).min(self.filled);
        if self.start == self.filled {
            self.start = 0;
            self.filled = 0;
        }
    }

    /// Discards every buffered byte. Used when a protocol resynchronises.
    pub fn clear(&mut self) {
        self.start = 0;
        self.filled = 0;
    }

    /// Returns at least `n` contiguous unconsumed bytes, refilling as needed.
    ///
    /// The returned slice is invalidated by the next `consume`/`window` call.
    pub async fn window(&mut self, n: usize) -> io::Result<&[u8]> {
        if n > MAX_WINDOW_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Framed read window exceeds the protocol limit",
            ));
        }
        self.refill_to(n).await?;
        Ok(&self.buf[self.start..self.filled])
    }

    /// Reads exactly `n` bytes into `out`, reusing its capacity.
    ///
    /// The caller keeps ownership so a steady-state stream does not allocate
    /// per rectangle; only a rectangle larger than the current buffer grows it.
    pub async fn fill(&mut self, n: usize, out: &mut Vec<u8>) -> io::Result<()> {
        if n > MAX_WINDOW_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Protocol payload exceeds the read limit",
            ));
        }
        out.clear();
        let buffered = self.buffered();
        let take = buffered.len().min(n);
        out.extend_from_slice(&buffered[..take]);
        self.consume(take);
        if take == n {
            return Ok(());
        }
        out.resize(n, 0);
        self.stream.read_exact(&mut out[take..]).await?;
        Ok(())
    }

    async fn refill_to(&mut self, n: usize) -> io::Result<()> {
        if self.filled - self.start >= n {
            return Ok(());
        }
        self.compact();
        while self.filled - self.start < n {
            let want = (n - (self.filled - self.start)).max(READ_CHUNK);
            self.buf.resize(self.filled + want, 0);
            // Everything spent inside this read is transport, not decode, so it
            // is accumulated here for a caller that is measuring a decode budget.
            let waiting = std::time::Instant::now();
            let read = self.stream.read(&mut self.buf[self.filled..]).await;
            self.blocked += waiting.elapsed();
            let read = read?;
            if read == 0 {
                self.buf.truncate(self.filled);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Peer closed mid-structure",
                ));
            }
            self.filled += read;
        }
        self.buf.truncate(self.filled);
        Ok(())
    }

    /// Moves the unconsumed tail to the front so the window can grow again.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        self.buf.copy_within(self.start..self.filled, 0);
        self.filled -= self.start;
        self.start = 0;
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A reader that hands out one byte per poll, so `window` has to loop
    /// instead of relying on a single large read.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for Trickle {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.pos >= self.data.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let byte = self.data[self.pos];
            self.pos += 1;
            buf.put_slice(&[byte]);
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn window_refills_across_short_reads_and_reports_eof() {
        let mut source = BufSource::new(Trickle {
            data: b"framebuffer".to_vec(),
            pos: 0,
        });
        assert_eq!(&source.window(5).await.unwrap()[..5], b"frame");
        assert!(source.ready(5).is_some());
        source.consume(5);
        let window = source.window(6).await.unwrap();
        assert_eq!(&window[..6], b"buffer");
        source.consume(6);
        assert!(source.window(1).await.is_err());
    }

    #[tokio::test]
    async fn fill_reuses_capacity_and_compacts_consumed_prefix() {
        let (client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = server.write_all(b"0123456789").await;
        });
        let mut source = BufSource::new(client);
        let mut out = Vec::new();
        source.fill(4, &mut out).await.unwrap();
        assert_eq!(out, b"0123");
        source.fill(6, &mut out).await.unwrap();
        assert_eq!(out, b"456789");
    }

    #[tokio::test]
    async fn oversized_window_is_rejected_before_allocating() {
        let (client, _server) = tokio::io::duplex(64);
        let mut source = BufSource::new(client);
        assert!(source.window(MAX_WINDOW_BYTES + 1).await.is_err());
    }

    #[tokio::test]
    async fn a_data_that_already_arrived_costs_no_blocked_time() {
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(b"abcdefgh").await.unwrap();
        let mut source = BufSource::new(client);
        // The first window has to read: whatever it spends is transport.
        let _ = source.window(8).await.unwrap();
        let after_first = source.blocked_time();
        source.consume(4);
        // The second window is already buffered, so it cannot add any.
        let _ = source.window(4).await.unwrap();
        assert_eq!(
            source.blocked_time(),
            after_first,
            "a satisfied window must not be charged to the socket"
        );
    }

    #[tokio::test]
    async fn waiting_for_a_late_byte_is_charged_to_the_socket() {
        let (client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = server.write_all(b"late").await;
        });
        let mut source = BufSource::new(client);
        assert_eq!(source.blocked_time(), std::time::Duration::ZERO);
        let _ = source.window(4).await.unwrap();
        assert!(
            source.blocked_time() >= std::time::Duration::from_millis(40),
            "the wait belongs to transport, not to the caller's decode budget: {:?}",
            source.blocked_time()
        );
    }
}
