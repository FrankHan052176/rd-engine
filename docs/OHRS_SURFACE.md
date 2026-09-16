# OpenHarmony HAR surface required by the ArkTS client

The legacy bridge (`R_RustDesk-Core/native/ohos_napi/src/lib.rs`) exports about
**286** `#[napi]` functions (runtime_*, controlled_*, input_interceptor_*,
session_*, account/address-book/2FA control). The shipped ArkTS client uses a
much smaller subset: `NativeSessionBridge.ets` calls exactly these **35**
functions, all of them `session*`:

```
sessionAdd            sessionStart          sessionLogin          sessionClose
sessionClose          sessionPollEvents     sessionRefresh        sessionCancelJob
sessionSetCommon      sessionSetCustomFps   sessionSetSize        sessionSetViewOnly
sessionSetVideoPaused sessionSetImageQuality sessionSetCustomImageQuality
sessionSetClipboardFileRoot                   sessionSetConfirmOverrideFile
sessionInputString    sessionSend2fa         sessionSwitchDisplay
sessionSendFiles      sessionReadRemoteDir   transferNextJobId
sessionSendClipboard  sessionSendClipboardFiles  sessionSendClipboardImage
sessionTakeClipboard  sessionTakeClipboardImage
sessionToggleOption   sessionGetToggleOption sessionGetImageQuality
sessionGetConnToken   sessionGetEnableTrustedDevices
sessionGetRemoteAudioState  sessionGetFrameRateSnapshot
```

## Minimal first slice for a viewer session

To take one end-to-end viewer session on the engine (connect, log in, receive
video, present, close) the bridge needs only:

| Function | Purpose in the engine |
| --- | --- |
| `session_add` / `session_start` | create the session record and dial (direct or rendezvous) via `rd_engine::viewer::Viewer` |
| `session_login` | hand the password to the `Viewer` and drive the auth state machine |
| `session_poll_events` | drain the viewer event stream (authorized, permission change, frames, closed) |
| `session_refresh` / `session_set_custom_fps` | request a keyframe and set the cadence the viewer asks for |
| `session_get_frame_rate_snapshot` | answer with the engine's own counters, not a second source |
| `session_close` | terminate the transport and release the decoder surface |

Everything else in the list is either a feature the engine does not implement
yet (clipboard, file transfer, 2FA, audio, multi-display) or bookkeeping the
legacy bridge needed and the engine does not (job ids, conn tokens, toggle
options). Those must be answered explicitly as unsupported rather than stubbed
with fabricated values.

## What the engine still lacks for this

1. A NAPI crate in this repository (`native/ohos_napi`) that wraps
   `viewer`/`host`/`session` and produces `package.har`.
2. Decode and present on the device: `platform/ohos_decoder.rs` and
   `platform/ohos_publisher.rs` exist, but nothing binds them to the ArkTS
   surface/renderer path yet.
3. Input injection for the viewer role (mouse/keyboard into the peer) is only
   `Viewer::send_mouse` today.
