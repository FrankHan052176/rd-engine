# Historical coverage against the original RustDesk core

All capability tables, roadmap notes, and measurements below are historical
snapshots, not acceptance results for
the current product or instructions for rebuilding the active chain. In
particular, their host-side `--fps` examples predate client-controlled frame
rates: the current host has no `--fps` option, and the connecting client supplies
`LoginRequest.option.custom_fps`. See [MODERN_RUNTIME.md](MODERN_RUNTIME.md) for
the current request/default/range contract. A requested rate is not a measured
receive, presentation, or physical display rate.

The current product boundary also supersedes the historical gap list: camera
viewing/streaming, text chat and voice calls are deliberately excluded by the
user's 2026-09-24 decision. They must not be restored as parity work in either
bridge or its paired consumer. Desktop video, desktop audio playback, screen
recording and local QR scanning are separate capabilities; this exclusion neither
removes them nor establishes that an unavailable capability is implemented.

"Absent" means the code explicitly refuses or disables the path, not that it is
unfinished-but-present.

Legend: **yes** implemented and exercised · **partial** present with a stated
limit · **no** deliberately absent.

## Protocol and session

| Capability | Status | Evidence |
| --- | --- | --- |
| Direct TCP viewer and host roles | yes | `src/session.rs`, `src/viewer.rs`, `src/host.rs`; live A/B run this session |
| Framed encrypted transport, single ordered writer | yes | `src/transport.rs` (nonce is never retried after a partial send) |
| Password login (both roles agree byte for byte) | yes | `src/authentication.rs::salted_password`; verified live: `password challenge received` → `authorized` |
| Interactive approval policy | yes | `host.rs` `LocalApproval` + `Host::approve` |
| Two-factor | **no** | `NoSecondFactor::verify` returns `FactorResult::Unsupported`; viewer maps `2FA Required` to `SecondFactorUnsupported` |
| Rate/whitelist policy across reconnects | partial | `AttemptPolicy` trait + `BoundedPasswordAttempts`; hbbs whitelist not consulted |
| TCP hole punch and relay (hbbs/hbbr) | yes | `src/rendezvous.rs`, `tests/rendezvous.rs` |
| UDP / KCP / WebSocket / proxy routes | **no** | `rendezvous.rs` header: "No UDP/KCP/WebSocket/proxy or account token route is implied" |
| Account/token identity routes | **no** | same header |
| WebRTC | **no** | not referenced anywhere in `src/` |
| Multi-display switching | **no** (display 0 only) | `session.rs` treats `switch_display == 0` and `RefreshVideoDisplay(0)` as keyframe/control only |

## Media

| Capability | Status | Evidence |
| --- | --- | --- |
| H264 / H265 (hardware only, no software fallback) | yes | `windows_native.rs`, `platform/ohos_publisher.rs`, `platform/ohos_decoder.rs` |
| VP8 / VP9 / AV1 | **no** | `viewer.rs` advertises `ability_vp9/vp8/av1 = 0` deliberately |
| Colour contract incl. HDR10 / HLG / scRGB classification | yes | `src/media_color.rs` |
| HDR from a Windows desktop source | **no** (documented gap) | Desktop Duplication exposes no mastering/MaxCLL metadata; `MODERN_RUNTIME.md` states it is not fabricated |
| Frame cadence policy | **differs at defaults, tunable** | `WindowsPublisher::next_unit` is capture-change driven and then thins to the negotiated fps by PTS; no timer re-encodes a cached frame. Same host, same desktop, 8 s windows: engine 60 fps/20 Mbps -> 467 frames / 10.83 MB; 60 fps/1 Mbps -> 414 / 2.02 MB; 30 fps/1 Mbps -> 236 (29.5 fps) / 1.47 MB; original on defaults -> 162 (20.3 fps) / 0.96 MB. Auth and first-frame stayed equal or better in every run (145-172 ms / 236-271 ms vs 195 ms / 311 ms). The original's lower default rate is its own policy, not a configured cap: neither `RustDesk.toml` nor `RustDesk2.toml` on that host sets fps/abr/bitrate |
| Rate control and keyframe policy | **fixed, then re-verified** | 60 s at `--fps 30 --bitrate 1000000` with a one-frame VBV: 11.66 MB = 1.55 Mbit/s, ~55% over the request. Two identical repeat runs differed by 0.5%, so that number was real, and the fix was the VBV window itself (`windows_nvenc.cpp` set `vbvBufferSize` to a single frame, which cannot absorb an IDR): one second of budget yields **6.26 MB = 0.83 Mbit/s** over the same 60 s with the same 61 keyframes, i.e. no overshoot, while fps (29.9), first frame (238 ms vs 311 ms original) and the worst gap (156 ms vs 172 ms) stayed equal or better. A 5 s IDR period was tried first and reverted (+48% payload) |

## Feature services

| Capability | Status | Evidence |
| --- | --- | --- |
| Mouse input from viewer | yes | `Viewer::send_mouse` |
| Keyboard injection | **no** | `viewer.rs` sets `disable_keyboard` from `LOCAL_MOUSE_ENABLED`; `host.rs` header: "System input/file/audio/clipboard adapters are absent and never granted" |
| Clipboard | **no** | viewer advertises `disable_clipboard = Yes`; host adapters absent |
| Audio | **no** | viewer advertises `disable_audio = Yes`; OHOS publisher requests zero audio rates/channels |
| File transfer | **no** | viewer advertises `enable_file_transfer = No` |
| Camera | **no** | viewer advertises `disable_camera = Yes` |
| Terminal, port forward, printer, remote RDP | **no** | absent from `src/` |

## Platform backends

| Platform | Host (capture+encode) | Viewer (decode) |
| --- | --- | --- |
| Windows | yes — DXGI Desktop Duplication + direct NVENC, no staging/copy/software path | capability query only |
| OpenHarmony | yes — `ohos_publisher` (system consent UI, RGBA8/SDR) | yes — `ohos_decoder` by hardware name |
| macOS / Linux | **no** — `NoHardwareCodec`, verified on this Mac | capability query only |

## Closing the gap, in order of impact

1. Frame cadence and bitrate policy: match the original's change-driven output so
   idle desktops do not cost ~11x the bandwidth.
2. Keyboard/clipboard/audio/file adapters behind the existing permission bits
   (`Permissions { keyboard, clipboard, audio, file }` already exist and are
   intersected, so the protocol side is ready).
3. Two-factor authentication.
4. macOS/Linux publishing backend (`NoHardwareCodec` today) — needed before the
   engine can be a host there.
5. HDR source metadata for the Windows desktop path, or state the limit in the
   product rather than in the code comment.

## Measured against a live Windows peer (2026-09-17)

`rd-engine-viewer 192.168.108.155:21119 rdetest2026 12` against the engine's own
Windows host (`rd-engine-windows-host --listen 0.0.0.0:21119 --codec auto --fps 60
--bitrate 20000000`), 2560x1440 desktop:

| Number | Value |
| --- | --- |
| Authentication | 107 ms |
| First frame | 366 ms |
| Frames in 12 s | 638 (≈ 53 fps) |
| Inter-frame gap | min 0.01 ms, avg 18.25 ms, max 96.71 ms over 637 samples |
| Codec | H265, 12 keyframes, 17,467,500 encoded bytes for 151,533 in the sampled record |

## On the Pad (2026-09-17)

Same host, same password, driven from the client's own UI on a HUAWEI MatePad
11.5''S (HarmonyOS NEXT). The engine's snapshot, read once a second through the
HAR while the client showed the session:

```
{"codec":"H265","phase":"streaming","pushed_units":596->1126,
 "received_units":596->1127,"render_submissions":595->1126}
```

| Number | Value |
| --- | --- |
| Frames in 9.093 s | 530 (58.3 fps; per-second deltas 50-61) |
| Received vs pushed vs rendered | equal within one frame at every sample |
| Codec | H265, decoded by the device's hardware decoder |

Two things this settles. The client's surface is bound and being presented into
- it reports the remote-control session as active and its window holds the
preview `XComponent` - and the engine holds **no queue**: every frame it
received in that window was pushed and rendered, with at most one frame in
flight, which is the no-queue property the runtime is built for.

Interop against unmodified official binaries is still open, and so is a
glass-to-glass latency figure; the counters above bound the engine's own path,
not the network or the panel.

## Latency on the Pad (2026-09-17)

The same session, read through the client's own telemetry once a second. The
engine now times each unit from the moment the decoder owns it to the moment its
picture is submitted for rendering, and the client turns those sums into a mean:

| Number | Value |
| --- | --- |
| Backend-to-render-submission, mean | **9.09 ms** over 301 frames in 5.043 s |
| Worst single frame | **48.9 ms** |
| Frame rate in the same window | 59.5 fps |
| Units queued at every sample | **0** |

What this figure is and is not: it starts when the unit is pushed into the
device's hardware decoder and ends at the render submission, so it includes the
codec's own output pipeline depth and excludes the network, the panel and
scanout. It is not a measurement of the decode work alone - the hardware codec
exposes no decode interval, and this layer reports none rather than a zero
standing in for one (`decodeTimingAvailable` is false). The no-queue property is
separate and holds: at every one-second sample received, decoded, submitted and
rendered counts were equal, and nothing waited for a decoder slot - admission
refuses rather than queues, so no frame spends time in one.

## Against the unmodified official RustDesk (2026-09-17)

Two directions, both against the official 1.4.9 host on the same box:

| Direction | Result |
| --- | --- |
| Engine viewer -> official host | `auth_ms=160..197`, `authorized`, H265, 2560x1440, `first_frame_ms=406`, 161 frames in 8 s |
| Pad (client on the engine) -> official host | `phase=streaming`, 40 s of session, 1910 -> 2012 frames in 2 s (51 fps), mean backend-to-render-submission 14.0 ms, worst 63.7 ms, nothing queued |

The same viewer against the engine's own host on the same box: `auth_ms=114`,
H265, `first_frame_ms=442`, mean gap 18.14 ms.

Two things this settles. The engine speaks the official wire contract in both
directions, including the two-stage credential (SHA256 of the password and the
peer's salt, then SHA256 of that and the peer's challenge), which the official
host accepts byte for byte. And the Pad's own client, driven by the engine,
holds a session with an unmodified official host, which is what the ArkTS
client's contract was written against.

The engine host enforces its password through the same exchange; the value it
compares is the one `--password` carries. A host started without an interactive
stdin cannot approve a session interactively, and `--test-auto-approve` is what
the test host uses for that case.

## 2K at 120 fps on the Pad (2026-09-17)

The engine's host captured 2560x1440 at `--fps 120 --bitrate 40000000` and the
Pad's client, driven by the engine, held the session:

| Number | Value |
| --- | --- |
| Frames in 1.008 s | 113 (about 112 fps) |
| Received / decoded / submitted / rendered | equal at every sample, nothing queued |
| Mean backend-to-render-submission | 11.3 ms (1.2887 s over 114 calls) |
| Worst single frame | 124.2 ms, against 55.7 ms at 60 fps |

The decode and submission path really does run at 112 fps; what the eye sees is
bounded by the device's own panel, which reports 60 Hz. The worst-frame figure
doubling with the frame rate is the load, not a queue: submission stayed equal to
arrival throughout.

The same session-view tree that carries the picture is the client's
`rustdesk-preview-input-layer` over the `XComponent` the decoder presents into;
the client's metrics live in its `SessionToolbar`, fed from the snapshot fields
this engine reports, and that toolbar is not part of the always-present tree.

### Correction: `--fps` is a ceiling, measured together on one timeline

The 120 fps figure above is the host's configured rate, not what it achieves.
Sampling both ends over the same ten seconds:

| Side | Reading | Rate |
| --- | --- | --- |
| Host (its own log) | `sent_units` 30781 -> 31445 | 66.4 /s |
| Pad (its own snapshot) | `decodedFrames` 31119 -> 31721 over 9.135 s | 65.9 /s |
| Pad | `receivedPackets` 31120 -> 31721 | nothing queued |

So on an idle desktop this producer sends about 66 a second while configured for
120, and the Pad decodes and renders every unit that arrives - received, decoded
and rendered stayed equal. The 112 fps window recorded in the section above was
measured while the desktop was changing, which is the behaviour this producer
shows: it is change-driven. The displayed figure in the client was therefore
truthful in both windows, and the ceiling is upstream of the Pad, not in the
client and not in the panel.
