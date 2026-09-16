# Coverage against the original RustDesk core

Every row is backed by the engine source or by a measurement in this repository;
"absent" means the code explicitly refuses or disables the path, not that it is
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
| Rate control and keyframe policy | **needs work** | 60 s at `--fps 30 --bitrate 1000000`: fps honoured (1790 frames, 29.96 fps) but 11.66 MB = 1.55 Mbit/s, ~55% over the request, with 61 keyframes (~1/s, ~0.27 Mbit/s). A 5 s IDR period (13 keyframes) was tried and **reverted**: the same measurement produced 17.29 MB / 2.30 Mbit/s and a 630 ms stall, so the overshoot is not simply keyframe rate. NVENC runs CBR with `maxBitRate == averageBitRate` and a one-frame VBV buffer (`windows_nvenc.cpp`); that and a content-controlled A/B are the next things to examine. Single-sample desktop runs are not comparable to each other |

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
