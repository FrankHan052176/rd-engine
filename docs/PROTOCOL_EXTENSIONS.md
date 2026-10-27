# Historical protocol extension report

This records the pre-cutover VNC/RDP/QUIC design, not the current build or
acceptance contract. RDP now uses pinned IronRDP and VNC uses LibVNCClient;
the bespoke protocol paths and fixture results below are historical only.
Current ownership and validation requirements are in `../AGENTS.md` and
`MODERN_RUNTIME.md`. The engine exports HarmonyOS HAR for Resk and non-HarmonyOS
FRB for the official Flutter client; it does not ship its own client application.

## The reuse boundary

The requirement was that VNC and RDP reuse this engine's infrastructure instead
of growing parallel stacks. That boundary is:

| Layer | Shared | Protocol-specific |
| --- | --- | --- |
| Runtime and cancellation | `executor::runtime`, one cancellation token per session | — |
| Byte transport | `net::BufSource` (buffered async reads) | RFB and RDP framing; RustDesk keeps `transport::WireReader/Writer` |
| Presentation | `protocol::rect::{PixelTarget, RectBuf, Rect}` and `platform::ohos_surface` | the wire encoding that fills the rectangle |
| Lifecycle, snapshot, teardown | `viewer::{ViewerOptions, ViewerSnapshot, ViewerError}`, `Viewer::request_close/close` | the connect/auth step |
| HAR surface | `native/ohos_napi` entry points | target parsing in `protocol::Target` |

What each protocol does **not** own: its own framebuffer, its own session
actor, its own snapshot/telemetry, its own teardown ordering, or its own
input-permission model. There is exactly one presentation contract and one
session lifecycle in the engine.

### Routing

The ArkTS client selects a protocol with a URL scheme in the session target
(`RustDeskIndex.ets::sessionTargetForKind`) and hands the string to
`sessionAdd` unchanged. `protocol::Target::parse` therefore accepts
`vnc://host[:port]` (default 5900) and `rdp://host[:port]` (default 3389), and
keeps a bare `host:port` or peer id as RustDesk — the client's own rule is that
only an explicit scheme selects another protocol, because treating
`10.0.0.1:5900` as VNC would break every direct RustDesk connection.

RDP needs a username and the client's login payload carries only a password, so
`rdp://user@host` carries it in the target; the directory model's `rdpUsername`
field is not yet wired into the connection target (see Open).

### No queue on the media path

There is no frame queue between the socket and the surface:

- **RFB** paces itself by request. The session keeps exactly one
  `FramebufferUpdateRequest` outstanding: it decodes an update into the sink,
  the caller presents it, and only then does `request_update` ask for more. A
  slow presentation stage stops asking and the server stops sending, which is
  the protocol's own flow control rather than a queue that would hold stale
  frames.
- **RDP** is drained update by update through `RfbSession`-equivalent
  `pump(&mut dyn PixelTarget)`: a bitmap rectangle is decoded straight into the
  sink.
- **Pixel format is negotiated to match the sink.** `SetPixelFormat` is built
  from `PixelTarget::layout()`, so the bytes a server sends are the bytes the
  surface stores and no conversion exists on the path. The 32-bit
  little-endian RFB format with red at bit 16 *is* BGRA-in-memory, which is what
  the OHOS surface buffer already is.

## Verified state

Everything below was observed in this repository; commands are given so the
numbers can be reproduced.

### Test suite

`cargo test` — **185 tests, 0 failures**:

| Suite | Tests | What it covers |
| --- | --- | --- |
| `src/protocol/rfb/encoding` | 45 | Raw, CopyRect, RRE, Hextile, zlib, TRLE, ZRLE/TRLE tiles, DesktopSize and ExtendedDesktopSize, plus a malformed-input case per encoding |
| `src/protocol/rdp/wire` | 70 | X.224, MCS/BER, security negotiation, capability sets, fastpath framing, RLE and interleaved-RLE bitmaps, 16/24/32bpp expansion, input PDUs |
| `src/net/quic` | 8 | real loopback handshake with ALPN, ordering, clean FIN, truncation, cancelled write |
| `src/protocol/rfb/{auth,session}` | 12 | version parsing, security selection, DES challenge/response against real ciphertext, wire pixel format |
| `src/platform/ohos_surface` | 9 | stride windows, damage merging, memmove-equivalent `copy_rect`, resize |
| `tests/vnc_session.rs` | 3 | a full RFB dialogue against a wire-accurate fixture server |
| pre-existing (`direct_auth`, `pinned_host`, `rendezvous`) | 15 | unchanged and still green |

### Live interop against a real server

`cargo run --example vnc_probe -- 127.0.0.1:5900 <password> 10` against the
macOS Screen Sharing server (`screensharingd`), observed:

```
connect_failed=RFB authentication failed: Authentication or authorization failure
elapsed_ms=2578
```

That is the real Apple server: it advertises `RFB 003.889` and the security
types `[30, 33, 36, 2, 35]`, and the engine negotiated 3.8, selected type 2
(VNC authentication — the only type it can complete), received the 16-octet
challenge, sent its DES response, and parsed the server's own failure reason out
of the 3.8 SecurityResult. The probe above used a deliberately wrong password;
a successful authentication needs the target's Screen Sharing password and has
not been run.

### OpenHarmony cross-build

`cargo check --target aarch64-unknown-linux-ohos` finishes clean (~2 min). The
new modules contribute **zero** warnings; the 14 remaining are pre-existing FFI
redeclaration disagreements between `ohos_decoder.rs` and `ohos_publisher.rs`.

Dependency choices that make this build work: `ring` (not `aws-lc-rs`, which
would need cmake and a C toolchain) for rustls and quinn, and flate2's
`rust_backend` (pure-Rust miniz_oxide, no C zlib).

## Defects the tests and integration found

These are worth recording because each one is a real bug that a
"looks plausible" implementation shipped:

1. **`ACTION_X224` was `0x01`.** MS-RDPBCGR defines
   `FASTPATH_OUTPUT_ACTION_X224` as `0x3`. With `0x01`, a TPKT frame whose
   version octet is `3` was classified as a fastpath PDU, so a real server's
   slow-path reply would have been misparsed from the first byte.
2. **`BITMAP_DATA_HEADER` was `24`; `TS_BITMAP_DATA`'s fixed part is `18`.**
   The rectangle walk advanced six bytes too far, so every rectangle after the
   first in a bitmap update decoded from the wrong offset.
3. **The X.224 Connection Confirm sliced its variable part from the length
   indicator** instead of from the end of the fixed header, so the negotiation
   block was always empty and the TCP/relay decision could never be read.
4. **MCS `SendDataRequest` wrote `dataPriority` and `segmentation` as INTEGER
   TLVs** where the structure defines OCTET STRINGs — a strict server parses the
   tag.
5. **The RFB pixel format had the wrong field order and inverted shift
   semantics.** `PIXEL_FORMAT` groups the three maxima and then the three
   shifts (not max/shift pairs), and a channel's shift is its bit position in
   the 32-bit value — not a count from the most significant bit. The original
   version would have told every server to send a 3-bit red channel.
6. **QUIC streams are invisible to the peer until their first bytes arrive**, so
   "open on one side, accept on the other, then write" deadlocks. The tests now
   mirror the real ordering: the dialer speaks first, which is also what the
   RustDesk handshake and the RFB version exchange do.

Three test fixtures were also wrong in ways worth noting, because the
correction is the point: a self-signed PEM whose decoder consumed the `BEGIN`
label as base64, a capability-set offset that read the wrong field, and DES
vectors computed with a mistyped key. Every one was caught by comparing against
an independent source (`openssl enc -des-ecb`) rather than by trusting the
first plausible constant.

## Deliberate limits

**RFB**

- Tight (7) is not implemented and never advertised, so a server that respects
  `SetEncodings` does not send it. Its JPEG/PNG subencodings and negotiated
  quality levels are the reason.
- A zlib stream is reset per rectangle for ZLIB and ZRLE. RFC 6143 permits one
  stream per session; the servers targeted here emit self-contained streams.
- Only `None` and VNC Authentication security types. Apple's 30/33/36,
  VeNCrypt and Tight are refused by name rather than downgraded: "connected
  without authenticating" is not a state a remote-control session may reach by
  accident.

**RDP**

- No NLA/CredSSP. A server that demands `PROTOCOL_HYBRID` gets a typed
  `Unsupported`, not a half-finished handshake.
- No RemoteFX/EGFX progressive codecs; the capability sets advertise none, so a
  conforming server uses the standard bitmap path.
- TLS-only security: plain RC4 RDP security is refused.
- Untrusted server certificates are accepted **and their fingerprint is
  recorded** (`certificate_fingerprint()`), because RDP servers are normally
  self-signed. Surfacing that fingerprint to the user is the client's job and is
  not yet done.

**QUIC**

- Used for engine-to-engine sessions only. The original RustDesk peer is reached
  over TCP, and that wire is the compatibility contract.
- `Trust::AcceptAnyCertificate` exists only for peers already authenticated by
  the RustDesk handshake; it is not a general-purpose escape hatch.
- No route selection. A session runs over QUIC because the caller asked for it;
  nothing negotiates it, and no peer advertises that it speaks QUIC. Inventing
  that advertisement would mean changing a RustDesk message, which
  `MODERN_RUNTIME.md` forbids.

### How a QUIC session is built (no second protocol implementation)

`hbb_common::tcp::FramedStream` is built on `DynTcpStream`, a **boxed**
`AsyncRead + AsyncWrite`. `net::quic::QuicStream` implements those two traits
over a QUIC bidirectional stream, so `FramedStream::from(QuicStream, addr)`
produces exactly the object the TCP path produces, and everything above it is
unchanged and unaware:

```text
QuicStream -> FramedStream::from -> handshake::viewer -> ViewerSession::connect_over
                                    (RustDesk handshake  <->  transport::split
                                     and both auth roles)      -> WireReader/WireWriter
```

That is verified rather than asserted:
`net::quic::tests::the_rustdesk_record_framing_runs_unchanged_over_quic` runs a
real QUIC handshake, drives the same `transport::split` reader and writer the
TCP path uses, and round-trips a `Message` plus a 512 KiB record.

## Open

1. **Live RDP validation.** The Windows test host (`ssh rustdesk-windows`) was
   unreachable for this whole session, so the RDP client has never spoken to a
   real server. Its tests are wire-level plus a fixture; the connection path
   (X.224 → TLS → MCS → capabilities → demand active) is unproven end to end.
2. **A successful live VNC authentication.** The handshake and the failure path
   are verified against Apple's server; the success path needs the target's
   Screen Sharing password.
3. **Viewer/session wiring.** `RfbSession` and the RDP wire layers are
   standalone; `Viewer` does not yet dispatch on `Target` to drive them, and the
   HAR bridge still parses only `SocketAddr`. The pieces are built and tested;
   the integration is the next step.
4. **`rdpUsername` never reaches the target.** The ArkTS directory model stores
   it, but `PeerCard.connectionTarget()` returns `peer.id` alone, so an RDP
   session started from a saved peer has no username unless the user typed it
   into the target as `rdp://user@host`.
5. **The encoded-video decode budget is recorded but not measured on device.**
   `crate::latency::DecodeLatency` exists, the RFB session fills it, and
   `vnc_probe` prints it. The RustDesk path's hardware-decoder stage is where
   the 3 ms budget actually applies, and that measurement needs a device: the
   record is in place, the number is not.
6. **No host-side QUIC listener.** The client half of the QUIC route is complete
   and tested (`QuicStream` → `FramedStream::from` →
   `ViewerSession::connect_over`), but `Host` still binds TCP only and nothing
   selects QUIC for a session. Closing this is a product decision — how a viewer
   learns a peer speaks QUIC — rather than a missing implementation.
