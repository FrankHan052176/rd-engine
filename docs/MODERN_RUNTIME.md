# Protocol-compatible replacement runtime

## Scope and ownership

The shared engine is owned by `rd-engine/src`. It produces a HarmonyOS-only HAR
through `native/ohos_napi` for Resk and non-HarmonyOS FRB artifacts through
`native/frb` for the official RustDesk Flutter client. It does not ship its own
Flutter application. `R_RustDesk-Flutter` remains the separate HarmonyOS port of
the official client, with its own upstream-derived kernel and release chain.

Upstream protobuf messages, packet framing and mature cryptographic primitives
remain authoritative. Existing field meanings, authentication compatibility,
identity and permission decisions must not be repurposed for media features.
HAR and FRB stay thin platform boundaries; their clients own UI and platform
lifecycle, never a second protocol implementation.

## Runtime layout

- **Protocol/session actor:** explicit connecting, securing, authenticating,
  active and closing states; viewer and host roles use the same wire contract.
  Media or input is never dispatched merely because a TCP socket connected.
- **Independent reader and writer:** one ordered writer owns the encryption
  sequence; incoming traffic is not held behind an awaited outbound send.
  A cancelled/failed partial write closes the transport instead of retrying an
  already-consumed nonce. No per-frame runtime creation or timer polling.
- **Media workers:** persistent per-stream workers with bounded ownership.
  Wait for actual resources, not latency-derived FPS penalties. Never discard
  arbitrary encoded reference frames to make a queue look short.
- **Platform providers:** capture, encode, decode and presentation expose typed
  format/capability/lease contracts. GPU submission completion and safe resource
  release are explicit; unknown completion is not a reusable buffer.
- **Feature services:** audio, input, clipboard and file transfer run behind
  authenticated permissions and bounded work admission. Their protocol meanings
  must match the corresponding original-client behavior.

## Implementation order and acceptance

1. Real wire transport and both authentication roles, tested against upstream
   framing/crypto and then original executables. A self-roundtrip is insufficient.
2. A usable bidirectional SDR remote-desktop session through the new engine,
   with input/permissions, disconnect/reconnect and display lifecycle working.
3. Platform zero-copy capture/codec/display providers and remaining service
   compatibility. Rebuild engine → HAR → Resk and engine → FRB → the pinned
   official non-HarmonyOS Flutter client; a library build alone proves neither.
4. HDR with explicit compatible profile, bit depth, transfer, primaries, range
   and metadata handling. An H265 capability bit alone never enables HDR. Missing
   peer capability means no HDR claim; a separately negotiated SDR session is not
   an HDR pass. No changes to existing protobuf field meanings for this purpose.
5. Independently test 1280×720, 1920×1080, 2560×1440 and 3840×2160 at 120FPS targets.
   Separate source production, codec throughput, rendering submission and physical
   display results. No resolution reductions, repeated frames or discarded
   dependency chains may manufacture a pass.

Codec throughput, desktop-capture throughput and presentation throughput are
different gates. A platform capture API limit must be reported as such; it cannot
be bypassed by reporting codec-only test-pattern throughput as screen sharing.

## Session frame-rate ownership

The connecting client owns the session target through `LoginRequest.option.custom_fps`.
The host has no independent FPS setting or cap: requests from 1 through 240 are
used exactly; missing/zero uses rd-engine's default of 60, while negative or
above-240 requests fail with `InvalidFrameRate`. These are engine policies, not
protobuf-mandated defaults. Changing a running viewer's target requires reconnecting.

Startup codec discovery performs a real initialization at 1 FPS, followed by
checked teardown. This conservative probe is not a throughput guarantee or proof
that driver modes are monotonic. Each authenticated session opens its publisher
at its own resolved target and reports actual initialization failures without
silently lowering the rate or repeating frames.

`HostSnapshot.client_requested_fps` and `fps` describe the most recently begun
session attempt: 0/0 before any attempt, 0/60 for an unspecified request, and
120/120 for an explicit 120 request. They are not measurements or aggregate rates
for all peers. Host sent-unit and compressed-payload byte counters remain
cumulative across peers; receive, presentation submission and physical scanout
must be measured separately.

## Windows producer boundary

The Windows implementation is an independent Desktop Duplication and direct
NVENC path. It acquires the exact D3D11 duplication texture and keeps the DXGI
frame lease until the synchronous NVENC output loan has been copied into the
protocol buffer and released. NVENC registers and maps that texture directly;
there is no staging texture, `CopyResource`, D3D map, CPU pixel conversion,
scaling, GDI/WARP or software fallback.

Only full-range RGB G22/BT.709 SDR and full-range RGB PQ/BT.2020 desktop color
spaces are accepted. PQ requires a real R10 duplication surface and never falls
back to legacy BGRA duplication. Display luminance reported by DXGI is diagnostic
display capability, not content mastering metadata or MaxCLL/MaxFALL. A stream
cannot be relabeled HDR without separately valid source HDR metadata. FP16 scRGB
is represented by the generic color contract but is not accepted by the direct
NVENC desktop path because conversion to a supported NVENC input would require
an additional pixel surface.

Desktop Duplication itself does not expose content mastering-display,
MaxCLL/MaxFALL metadata for the composited desktop. Therefore the current strict
native path can capture and identify a PQ/R10 surface but cannot truthfully open
an HDR10 publishing contract from that source alone. It does not substitute the
monitor capability values from `GetDesc1`. Supplying trustworthy source content
metadata (or adding a different direct source that carries it) remains an
explicit Windows HDR capability gap.

## Current state

The independent full-duplex transport, original authentication actors, hbbs/hbbr
ID routing, HAR entry and ArkTS route selection are implemented. Public hbbs
control-plane and strict failure-closed device checks have passed. The generic
SDR/SDR10/HDR10/HLG/scRGB color contract and Windows native producer source are
also implemented.

The Windows native source still requires an actual x64 MSVC build and NVIDIA
runtime validation. A hosted Windows compile cannot prove D3D11/NVENC interop,
HDR correctness or sustained 120FPS. Valid peer-ID sessions against unmodified
official binaries and four-tier capture/codec/presentation acceptance are still
open, so this is not yet a complete replacement release.
