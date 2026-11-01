# HarmonyOS HAR surface for Resk

`native/ohos_napi` is rd-engine's HarmonyOS-only kernel output, consumed by
`R_RustDesk-ArkTS` (Resk). Its non-HarmonyOS FRB sibling lives in `native/frb`
and serves the official RustDesk Flutter client; Resk does not consume it.

The sections below document the NAPI/engine contract, not a separate HAR project.
The retired Core/Har checkouts are not implementation sources. The active
HarmonyOS Flutter port (`R_RustDesk-Flutter`) is a different product, not a
retired tree and not the source carrier for this HAR.

No ArkTS build, runtime or device validation is claimed by this document. The
machine-readable truth for one build is `harSurfaceManifest`, described below.

## Deliberate product exclusions

The user's 2026-09-24 decision excludes remote camera viewing/capture, text chat
and voice calls from rd-engine and its paired consumers. These are not temporary
gaps or future parity work. The NAPI implementation/export inventory, package
forwards and active ArkTS facade have no dedicated exports for these features;
do not add compatibility stubs or no-op entry points.

`sessionAdd(sessionId, target, optionsJson)` keeps its existing signature. It
rejects the legacy `isViewCamera: true` request with `ok:false`; a present
non-boolean value returns `isViewCamera must be a boolean`. Absence or `false`
follows the existing path. This negative-only guard runs before target parsing,
approved-route admission, password extraction and session registration; it does
not publish a camera option or broaden validation of other options. The active
`RustDeskIndex`/`EngineSessionOptions` already had no camera field. Removing the
old `SessionStartOptions`/`TransferManager` flag and misleading resource text is
not removal of a previously running HarmonyOS camera implementation.

The core's existing boundaries remain unchanged: the viewer login sets
`disable_camera = Yes`, the host rejects `ViewCamera`, and pre-authentication
`ChatMessage` packets are tolerated as ignored `PreAuthControl`, not an
authentication grant or a chat service. Upstream protocol definitions remain.

Desktop video, desktop audio playback and screen recording are separate scopes;
their current implementation and limitations are unchanged, as are unrelated
file, clipboard and terminal capabilities. In particular, this HAR's viewer
still disables desktop audio and has no playback operation to forward; excluding
voice calls does not claim that desktop playback or recording is implemented.

## Client inventory vs. this HAR

- ArkTS imports the active typed surface from `rustdesk-ohrs`; the declarations
  are in `native/ohos_napi/package/libs/index.d.ts`. The crate and package are
  active: `native/ohos_napi/Cargo.toml` (`rd_engine_native_har`), built into
  `target/package.har` with `librd_engine_native_har.so`. Source exports live in
  `native/ohos_napi/package/index.ets`; binaries and provenance are assembled under `target/har/`.
- This build exports 42 functions. `package/libs/index.d.ts` and
  `package/index.ets` are maintained together with the Rust NAPI exports; the
  packaging build copies them rather than generating missing declarations.
  Coverage is partial, not parity: a name the client imports that is absent from
  the paired declarations has no export here,
  and a name appearing in an older HAR, a forwarded helper or a historical list
  is not an export. Names outside the surface stay absent rather than becoming
  compatibility stubs.
- `harSurfaceManifest` (`native/ohos_napi/src/lib.rs`) reports `implemented` from
  the compile-time `implemented_entry_points!` list, `pending` as the client
  import list compiled into the same function minus `implemented`/`registry_only`,
  plus the static `refused_entry_points` and `not_served` classifications. Read
  that answer instead of inferring support from a name. The 42 exported names
  include the explicitly refused `sessionCancelJob`; the 41 implemented names
  exclude it. `pending` means no implemented behavior, not necessarily no export.
  Read the paired declarations and refusal classifications together.

### The 35-name `session*` list is a historical baseline

The names below are the historical baseline this document recorded: the legacy
client's `session*` call set as it stood then, kept here as provenance. They are
**not** the current full ArkTS import contract, and a name appearing here is not
a commitment to implement it. `har_surface_manifest` computes `pending` against
the client import list compiled into it, not against this baseline, and neither
list is a parity report for the current client: a pending name is not implemented
(and may have an explicit refusal export), while this historical list undercounts
the client's real imports.

```
sessionAdd            sessionStart          sessionLogin          sessionClose
sessionClose          sessionPollEvents     sessionRefresh        sessionCancelJob
sessionSetCommon      sessionSetCustomFps   sessionSetSize        sessionSetViewOnly
sessionSetVideoPaused sessionSetImageQuality sessionSetCustomImageQuality
sessionSetClipboardFileRoot                   sessionSetConfirmOverrideFile
sessionInputString    sessionSend2fa         sessionSwitchDisplay
sessionSendFiles      sessionReadRemoteDir   transferNextJobId
sessionSendClipboard  sessionSendClipboardFiles  sessionSendClipboardImage
sessionTakeClipboard  sessionTakeClipboardImage  sessionToggleOption
sessionGetToggleOption sessionGetImageQuality
sessionGetConnToken   sessionGetEnableTrustedDevices
sessionGetRemoteAudioState  sessionGetFrameRateSnapshot
```

`sessionClose` appears twice in the original list; there are 34 distinct names.
The other legacy entry points (clipboard, files, 2FA, audio, multi-display,
quality setters, toggles, job ids) are not a checklist: names without a real
engine operation must be answered as unsupported rather than stubbed with
fabricated values.

## Entry points this HAR serves

| Export | Engine backing |
| --- | --- |
| `nativeVersion` | `CARGO_PKG_VERSION` of the HAR crate |
| `harSurfaceManifest` | compiled `IMPLEMENTED` list and the client import list in the same function |
| `queryDecoderCapabilities` | `AsyncTask` query of `media_capability::query_h264_hardware_decoder` and `query_hevc_hardware_decoder`; returns advertised metadata or per-query errors off the ArkTS UI thread, never measured throughput/HDR or a codec instance |
| `appSetLifecycle` | synchronously fences consent/foreground and app epoch, requests old-owner close even after revocation, then waits for owned LAN cleanup and admitted bootstrap I/O in an `AsyncTask`; foreground never starts a scan |
| `appInit` | serializes private `filesDir/rustdesk` bootstrap, sets official `APP_DIR`/`APP_HOME_DIR`, initializes crypto and obtains official `Config::get_id` off UI before publishing ready |
| `validateServerProfile` | pure shared endpoint and STANDARD-base64 Ed25519-key validation; no Config, DNS, socket, save or approval |
| `lanScanStart` | memory-only generation admission → `rd_engine::lan::LanOwner::start`, then worker-side actual cache snapshot; only explicit calls scan |
| `lanPeersQuery` | generation/scan-fenced worker-side `LanOwner::query_blocking`, with another epoch/scan/revision check at promise resolution |
| `lanScanStop` | exact scan admission → `request_stop`, then off-UI `LanCompletion::wait_blocking` and actual cache query |
| `lanPeerRemove` | exact owner/scan admission → core-owned removal gate and `request_remove`, then off-UI completion and actual cache query |
| `sessionAdd` | captures a direct target or owned v2 explicit-save ID route and initialized local ID; no dial/Config/persistence; refuses existing ids and a full 256-record registry without eviction |
| `sessionStart` | captured ID route → existing strict `Viewer::start_rendezvous`; direct RustDesk/VNC/authenticated RDP → unchanged `Viewer::start` |
| `sessionLogin` | records a password only on a nonterminal/nonclosing record; a live unauthenticated viewer returns `restart_required`, requiring close → final poll → ACK → new registration/start, not same-viewer reauthentication |
| `sessionSend2fa` | admits one six-digit code only while this same RustDesk authentication is waiting; `queued:true` is not authorization. A peer challenge revision makes repeated Wrong replies observable; `trustThisDevice:true` is explicitly refused until enrollment has a real owner |
| `sessionBindSurface` | takes the opaque `componentId` that `xcomponentAttach` returned on this UI environment (a Surface id, a node label or any other string is refused) and borrows that holder's real lease through `xcomponent::borrow_surface`; the record's single `PendingSurfaceLease` slot is published once and a second component is refused instead of redirecting a running viewer. An empty `componentId` is a give-back request that only a never-started or confirmed-reclaimed record may answer `released:true`, and a held give-back is a refusal, never a release |
| `sessionClose` | `Promise` that resolves after native teardown, not on request acceptance: it requests close, waits for the owned reclamation verdict and answers `released`/`settle`; confirmed reclamation scrubs the registry password/Viewer but retains the final receipt, and it never removes the record or ACKs it |
| `sessionAcknowledgeClose` | consumes a confirmed, already-constructed terminal receipt for the exact `lifecycleEpoch` and only then removes that one record; refused while closing, unconfirmed, or before a complete close/poll receipt |
| `sessionPollEvents` | live or retained final `Viewer::snapshot()` facts, persistent `login_failure` and typed `peer_close_reason`, and one-shot authorization/close events (see "Polling" below) |
| `sessionRefresh` | `Viewer::request_keyframe` |
| `sessionCancelJob` | always answers `unsupported:true` with `record_removed:false`: no transfer-job owner is wired here, and no `actId` (including `0`) closes a viewer, releases a Surface or ACKs a receipt |
| `sessionSetCommon` | `view-only` and `fps` are acted on; every other pair is recorded and not applied |
| `sessionSetCustomFps` | applies to the next `sessionStart`; a running viewer keeps its rate |
| `sessionSetViewOnly` | `Viewer::set_input_policy`; closes admission independently of input-queue capacity, retires the old generation, and wakes the writer to release its holds; acceptance is not release completion |
| `sessionSetUnverifiedInputAccepted` | changes only the operator's input-consent policy for an encrypted but unverified RustDesk peer; never sets `peer_verified` or overrides authentication, view-only, or the peer's keyboard grant |
| `sessionSendMouse` | `Viewer::send_mouse`; converts compact client button codes to the wire bits and requires coordinates on absolute moves (or a prior absolute position for button transitions) |
| `sessionInputKey` | `Viewer::send_rustdesk_key` on the legacy RustDesk key wire |
| `sessionInputString` | `Viewer::send_rustdesk_key` with the text sequence |
| `sessionGetFrameRateSnapshot` | cumulative counters from `Viewer::snapshot()` |
| `runtimeGetServerConfig` | reads this bridge's own saved `server-profile.json`; `approved:false`/`config:null` when nothing was saved, a read failure is an error rather than an empty profile |
| `runtimeSetServerConfig` | the explicit save: same admission as `validateServerProfile`, atomic private write under the reserved root, answers `approvedProfile` (`schemaVersion` 2, `approval:"explicit-save"`, new `revision`) and `committed`; not a reachability claim |
| `runtimeTestServerConfig` | one bounded TCP connect per configured endpoint (two addresses, 2.5 s each); transport observation only, saves nothing |
| `runtimeListRecentPeers` | engine-owned device directory rows; `ok:true, exists:false` means no store yet and `ok:false` is a read failure with no rows |
| `runtimeListFavorites` | the same store's favorite targets, in insertion order |
| `runtimeSetFavorite` | adds or removes one favorite id and reports the persisted list |
| `runtimeRecordRecentPeer` | persists only the normalized fields the client observed; never infers a success time |
| `runtimeRemoveRecentPeer` | removes one recent row by id and reports whether a row was removed |
| `peerQueryOnline` | strict single hbbs `OnlineResponse` for the listed ids against the approved profile; any other message, short answer or wrong count is an error, not an offline guess |
| `peerPresenceCancel` | cancels exactly the named query generation; a stale token changes nothing |
| `xcomponentAttach` | adopts one live ArkUI `SurfaceHolder` on its UI environment thread behind manual XComponent lifecycle, returns the opaque never-reused `componentId`; real `ace_ndk.z`/`native_window` calls (API 20+) |
| `xcomponentDetach` | releases the holder only when no loan, native callback or operation still owns it; otherwise `held:true` and everything stays retained |
| `xcomponentSetFrameRateRangeNative` | declares the draw rate and registers the on-frame signal callback; `frameCallbacks` counts signals, not decoded or presented frames |

## Private app bootstrap, discovery and trusted ID routes

The new typed exports are forwarded by `package/index.ets` and declared in
`package/libs/index.d.ts`:

```typescript
appSetLifecycle(privacyAccepted: boolean, foreground: boolean): Promise<string>
appInit(filesDir: string): Promise<string>
validateServerProfile(profileJson: string): string
lanScanStart(ownerGeneration: string): Promise<string>
lanPeersQuery(ownerGeneration: string, expectedScanId: string): Promise<string>
lanScanStop(ownerGeneration: string, scanId: string): Promise<string>
lanPeerRemove(ownerGeneration: string, expectedScanId: string, claimedId: string): Promise<string>
```

Lifecycle JSON is `{ok, ownerGeneration, ready, discoveryAllowed, error?}`.
`ready` is a private-bootstrap fact, not consent or hbbs registration. The current
core owner's `ownerGeneration` is a decimal string; it is empty while no owner is
available. The caller supplies the real system privacy result and foreground
state through the single app lifecycle service, never a default-true boolean.
Background, page detach, destroy and consent loss close admission immediately;
`appSetLifecycle(false, false)` remains callable to await cleanup. An old lifecycle
promise cannot publish a replacement owner's token. Restoring foreground can
restore an initialized owner, but does not scan or connect.
Every admitted lifecycle update, including a same-state privacy reread, fences
the previous epoch and retires its owner; the resulting owner is idle and an
initial `expectedScanId=""` query never adopts a previous scan.

Only `EntryAbility.context.filesDir` supplies the root. Native reserves the absolute
root before lazy configuration use and never permits another root, even after
failure, revocation or environment teardown. Same-root calls serialize/coalesce;
canonicalization, directory preparation, both global path writes, sodium init and
official `Config::get_id` run in the worker after admission. The canonical config
directory must remain a direct child of the canonical private root. Successful
initialization keeps the nonempty official ID in memory; official Config writes
are void/log-only, so this is **not** proof of durable identity storage. Failed
bootstrap stays failed for this process rather than switching paths. A host-platform
build of this HarmonyOS-only crate refuses bootstrap instead of touching desktop
Config. Session registration/start and profile validation never bootstrap lazily.

The supported `napi-ohos` environment cleanup hook revokes the app epoch and calls
core `request_close` without blocking the environment thread. Core retirement
continues independently of dropped bridge promises. The explicit lifecycle promise
is the off-UI cleanup receipt; the environment hook itself does not promise a
completed join to a destroyed JS environment, and no orderly cleanup is claimed
for forced process termination. No cleanup waits with the session registry lock.

LAN replies are
`{ok, ownerGeneration, scanId, revision, state, peers, terminal?, error?}`.
All native u64 owner/scan/revision values travel as decimal strings, independently
of media/input generations. An idle `scanId` can be empty. Peers have exactly the
official `id`, `username`, `hostname`, `platform` projection from the actual cache.
States are `idle`, `scanning`, `stopping`, `removing`, `closed`; terminal reasons,
when present, are `inactivity`, `cancelled`, `deadline`, `failed`. Admission checks
happen at export reception, again before worker queries, and at resolution. Stop
and removal target the named scan, never a later one. Core invalidation only
updates a native atomic revision; it never queries or calls JS. A stale/denied
admission returns `ok:false`, empty peers and revision `"0"` without hidden cache
I/O; this is a closed admission, **not** a successful empty list. Consumers retain
existing rows on refusal and apply only matching owner/scan/revision results.

The bridge consumes `rd_engine::lan`'s pinned official outbound scanner; it has no
parallel scanner, responder, advertised-address fallback or WOL path. Repeated
starts coalesce under the core owner. The core bounds ingress to 256 records and
uses official 3-second inactivity plus a 10-second admitted monotonic deadline;
the deadline stops new work, not a hard-time reclamation guarantee. Official peer
and cache counts remain unbounded. Completion means owned work ended, **not** that
the void/log-only official store durably saved a removal/scan. Returned peers are
read from the actual cache, and observable coordinator/query/cleanup failures
remain errors. Cached peers are untrusted, unknown-online observations, not peer
or server trust. Large-result JSON parsing/list cost remains a performance
acceptance item; no silent truncation is added.

`sessionAdd(sessionId, target, optionsJson)` keeps its signature. Only a RustDesk
ID (`address=None`) consumes `options.approvedServerProfile`:

```json
{"schemaVersion":2,"approval":"explicit-save","revision":1,"mode":"official","idServer":"","relayServer":"","key":""}
```
`options.rustdeskIdOnly` is an optional boolean. LAN-sourced connection attempts
set it to `true` and retain that intent through retry, password replacement and
saved/recent entries. In this branch even an IP-shaped claimed ID remains a
RustDesk ID and must use the approved route; the adapter never calls
`direct_address` for it. Explicit VNC/RDP targets conflict with the intent and are
refused. Absent/false preserves manually entered direct-address routing. No
numeric-ID whitelist or LAN-derived server trust is introduced.


The revision must be a positive safe integer. Missing/legacy records and editable
drafts are not approved. The approved source is now this bridge's own save:
`runtimeSetServerConfig` validates the profile with the same rules as
`validateServerProfile`, writes it atomically under the fixed private root and
answers `approvedProfile` (`schemaVersion` 2, `approval:"explicit-save"`, the new
`revision`) together with `committed`; `runtimeGetServerConfig` re-reads that
store and answers `approved:false`/`config:null` when nothing was saved, a read
failure being an error rather than an empty profile. The earlier Resk Preferences
approval candidate was never applied, so nothing here claims a Preferences flush
or a real UI pairing.
Official mode ignores residual custom fields and uses only pinned
`RENDEZVOUS_SERVERS[0]` and `RS_PUB_KEY`, matching the upstream `PUBLIC_SERVER`
branch, never mutable Config server getters. Custom mode requires an explicit
valid ID endpoint, optional valid relay and a STANDARD-base64 key decoding to
exactly 32 Ed25519 bytes, without a default-key fallback. Validation returns
`{ok, normalizedProfile?:{mode,idServer,relayServer,key}, error?}`; it neither saves,
approves nor network-tests that profile.

The record owns canonical peer ID, normalized endpoints, original raw wire key,
decoded signer key and initialized local ID. `sessionStart` constructs only from
that snapshot, requiring its current admission generation; it does not reread
editable config. Connect, retry and password replacement must preserve the same
captured connection attempt in ArkTS. Targets, handoffs, and LAN metadata cannot
override the server/key. No `apiServer`, force-relay, UDP/KCP or account activation
is added. The existing direct connectors and their identity/security policy stay
unchanged, and unverified input acceptance still starts false.

These are source contracts, not runtime acceptance. Bootstrap/revocation races,
environment teardown, storage failures, stale command isolation, real broadcast
and interface availability, public/custom interoperability, direct-protocol
regressions and large-cache performance are unverified here. Main owns the final
paired generation/compilation/linking/packaging; the user owns functional,
device/permission and performance acceptance.

## Engine-owned stores, directory and presence

These exports own small app-private files; none of them is discovery, server
identity or a reachability claim. All of them are admitted under the app
generation and the root `appInit` reserved, and every one answers a refusal
instead of a fabricated success when that scope is unavailable.

- Store owner: `app_storage.rs`. Files live only in the canonical
  `<private root>/rustdesk` directory, and a write goes through a `0o600`
  temporary file plus `rename`, so a failed write cannot leave a half store. A
  missing file is "no store yet", which callers report separately from a read
  failure.
- Server profile: `app_profile.rs` (`server-profile.json`, 16 KiB cap, bounded
  request JSON). `runtimeSetServerConfig` is the explicit save and increments the
  stored revision up to the safe-integer bound; `runtimeGetServerConfig` reports
  `approved`/`config`/`approvedProfile`/`revision` or that no profile was saved;
  `runtimeTestServerConfig` saves nothing and reports one bounded TCP connection
  attempt per configured endpoint (two addresses, 2.5 s each). An accepted TCP
  connection does not identify the server and does not prove the RustDesk wire.
- Device directory: `app_directory.rs` (`device-directory.json`, 512 KiB cap, 256
  recent plus 256 favorites, one store mutex per read-modify-write).
  `runtimeListRecentPeers`/`runtimeListFavorites` answer `ok:true, exists:false`
  when no store exists and `ok:false` without rows on a read failure. A row is
  what the client recorded after it observed a session, never a LAN hit and never
  an online fact; `runtimeRecordRecentPeer`, `runtimeRemoveRecentPeer` and
  `runtimeSetFavorite` persist the normalized fields they were given.
- Presence: `app_presence.rs` performs the hbbs `OnlineRequest`/`OnlineResponse`
  exchange with the pinned wire types and frame codec over a bounded blocking
  socket, because this crate drives no engine runtime and may not start a second
  one. The endpoint is the host of the approved profile re-normalized onto the
  fixed presence port 21115; the local id comes from the initialized app, the peer
  list is 1..=4096 validated ids, and only one query owns the admission at a time.
  A peer is `online` only when a strict single `OnlineResponse` marks that exact
  slot; any other message, a short answer or a wrong count is an error, never an
  offline guess. The whole query (DNS, connect, write, one record) has a 15 s
  deadline and reads in 250 ms slices so `peerPresenceCancel` can be observed
  between slices; the name resolution itself is a blocking `to_socket_addrs` call
  that cannot be interrupted, so a stuck resolver is not bounded by that deadline.
  A LAN scan hit, a stored address, a successful TCP connect or a session in
  progress is never evidence that a server exists or a peer is online.

## Presentation and frame-rate reporting

Presentation is the **native bound Surface**, not an RGBA pull.
`xcomponentAttach` adopts one live ArkUI FrameNode's `SurfaceHolder` on its UI
environment thread: manual XComponent lifecycle, the surface callbacks, a pinned
`NativeWindow` reference and an opaque, never-reused `componentId`.
`sessionBindSurface` accepts only that `componentId`, borrows the holder's real
lease through `xcomponent::borrow_surface` and publishes it once into the
record's `PendingSurfaceLease`; the engine reads it when it opens the surface for
the first frame. There is no string-to-lease path, no `OhosSurfaceLease::bind` and
no `AtomicU64` id holder: any of those would name a destination the engine never
really owned. `xcomponentDetach` answers `released:true` only after the loan can no
longer be upgraded and no native callback or operation is still active; otherwise
`held:true` and the holder, its callback and its window stay retained for a later
detach. The three `xcomponent*` exports call the real `ace_ndk.z`/`native_window`
APIs and need API 20+ at runtime; a build without that surface ownership answers
`ok:false` with that requirement instead of pretending to bind.

The manifest names `sessionGetRgbaSize`, `sessionNextRgba` and
`sessionTakeRgbaFrame` under `not_served.rgba_pull` with the reason that the
engine presents into the bound surface and has no CPU-side RGBA pull path. That
gap is the HAR's missing readback, not a decision against a product RGBA feature:
a client that wants frames over RGBA needs a real engine readback this layer does
not have, and a JS frame-pull path must not be added to satisfy the names.

Late binding is already handled on the encoded RustDesk path: `feed_loop` waits
at phase `awaiting_surface` for a nonzero lease up to `SURFACE_WAIT` (20 s, polled
every `SURFACE_POLL` = 20 ms), and a lease that never receives an id fails at the
open (`SurfaceError::LeaseInvalid`) instead of presenting into nothing. The RFB
path now applies the same wait (see Protocol status). `Viewer::start`
deliberately does not require the surface to exist at dial time, because the
ArkTS client creates it after it asks for the session.

Known limits of this path (recorded, being repaired; not to be read as guarantees):

- Native ownership, not a lease id, is what keeps the Surface alive:
  `src/platform/ohos_decoder.rs` requires it to outlive every lease, so the holder
  registry retains the pinned window, callback and holder until that loan ends.
  `sessionClose` requests cancellation and retains the viewer and lease until the
  actual terminal reclamation verdict. ArkTS must keep the XComponent alive until
  close or a poll answers `released:true` with a terminal `settle` (`settled` or
  `neverstarted`) and only then call `xcomponentDetach`; a successful bind or
  close request, and the terminal record itself, are not a platform guarantee
  against component disposal. An unexpected ArkUI destruction revokes admission
  and calls `request_close` on the record's viewer without any JS round trip, and
  it releases nothing natively, so the terminal path still has to prove
  reclamation.
- The retirement link is registered in either arrival order: `sessionStart`
  watches the loan this record already holds, and `sessionBindSurface` also
  watches a viewer that is already running when it publishes. A Surface destroyed
  before or after the dial therefore asks that viewer to close, and a bind whose
  watch fails keeps both the binding and the viewer (the record is closing) rather
  than dropping an owner the terminal path still has to settle.
- `sessionGetFrameRateSnapshot` is honest about being cumulative: it reports
  `received_units` as `receivedPackets`, `pushed_units` as `decodedFrames`,
  `render_submissions` as `submittedFrames`, with `generation`/`intentRevision`
  taken from the record's dial count so ArkTS starts a fresh window whenever the
  viewer is dialled again. ArkTS owns the sampling window and computes rates
  from those counters (`FrameRateTelemetry`); this layer never invents an
  average it did not measure. `status` forwards `ViewerSnapshot.phase`, including
  pre-media and terminal states; ArkTS admits the current engine lifecycle
  vocabulary while redacting unknown status strings. Remaining Audit A8 limits
  are unchanged: wait fields are zero on this path and RFB does not update these
  video counters.
  Confirmed terminal snapshots and their elapsed sample time are retained until
  ACK, so dropping the registry's Viewer does not relabel telemetry as never-started.

## Polling: snapshot-derived, no `ViewerEvent` queue

`ViewerEvent` (`src/session.rs`) is consumed inside `Viewer::start`; the public
`Viewer` API exposes **no event stream**. `sessionPollEvents` therefore answers
from `Viewer::snapshot()` and translates the states the snapshot carries into the
client's event vocabulary, once per viewer (the per-record `Reported` state keeps
a repeated poll from repeating an event the client already acted on):

- `awaiting_approval` remains a waiting phase, not a refused password; it never
  fabricates an `input-password` msgbox,
- the peer authorization → `peer_info` plus `connection_ready`, carrying the
  observed security and route evidence,
- the end of the viewer → `close`, with the snapshot's own error string.

The persistent top-level `login_failure` is an explicit match of the frozen
`LoginFailure` enum, not an inference from `AuthenticationFailed`, phase, the
entered password or remote text:

| Snapshot fact | `login_failure` | Resk behavior |
| --- | --- | --- |
| `EmptyPassword` | `"empty_password"` | Offer a new password only after safe terminal consumption/ACK |
| `WrongPassword` | `"wrong_password"` | Same, with a local, resource-backed wrong-password error |
| `Refused` | `"refused"` | Ordinary failure, no password prompt |
| No classified password failure | `null` | No password prompt; approval waiting, 2FA unsupported, transport/certificate errors and normal close remain distinct |

The optional top-level `peer_close_reason` is `"manual_request"` only for
`PeerCloseReason::ManualRequest` on a confirmed terminal snapshot, otherwise
`null` (including registered and never-started records). The shared RustDesk
viewer classifies only the exact `Misc.CloseReason("Closed manually by the peer")`
wire reason and publishes that typed fact only when the final outcome is
`RemoteClosed` with confirmed reclamation. NAPI matches the enum, never parses
an error/debug string or forwards arbitrary peer text. The reason survives
terminal snapshot retention and repeated polls until ACK, without changing the
existing safe `error` string, one-shot close event, password retry or ACK gates.
Unknown/unconfirmed reclamation still retains quarantine ownership and reports
no manual-close fact. This is metadata, not a new export or Resk action; RDP and
VNC do not acquire RustDesk manual-close semantics.

At confirmed `closed && reclamation_confirmed() == Some(true)`, NAPI first
retains the complete final snapshot (including the actual release counters and
telemetry), then clears the lease and uses `mem::take(...).into_bytes()` plus
`sodiumoxide::utils::memzero` to scrub its password before releasing its Viewer.
Password replacement also scrubs the old registry-owned copy. This does **not**
claim to erase ArkTS strings, JSON input buffers or every transient credential
copy. A never-started record can close safely but has no runtime input generation
or counters to invent. Unknown/failed reclamation retains the Viewer, lease and
record; it is never converted to successful reclamation or evicted.

Final facts are stable across repeated polls, even when `events` is empty after
the one-shot `close`. Constructing a successful confirmed terminal poll sets a
separate consumption flag; reporting an event or calling `sessionClose` does not.
`sessionAcknowledgeClose(sessionId, lifecycleEpoch)` is that ACK: it requires the
exact current epoch, confirmed reclamation **and** the complete-receipt flag
before returning `{ok:true, record_removed:true}` and removing that one record
under the registry lock. Unknown ids, stale epochs, unconfirmed/quarantined
records and unpolled terminals are refused, and `sessionCancelJob` can do none of
this. After ACK, old ids return unknown; no timer or delayed id-based deletion is
used.
Start/login/bind and policy/common/FPS setters cannot refill a closed tombstone.

Registration never overwrites a still-registered id. `MAX_SESSION_RECORDS=256`
counts registered, live, quarantine and unacknowledged terminal records alike;
capacity exhaustion explicitly refuses registration rather than dropping a final
receipt or unconfirmed ownership. Registration may observe and scrub confirmed
old viewers, but does not consume their receipts. This is a record-count bound,
not a byte bound or an autonomous secret-scrubbing deadline.

Resk consumes the terminal error before ACK and captures the immutable source
`ConnectionAttempt`, source session id, input policy and intent revision. Only
natural Empty/Wrong termination with confirmed Surface reclamation, a known
input generation, known release state, no pending release and zero unreleased
holds can open the password dialog. Missing/unsafe input receipts on a password
failure keep the source id and block redial, including generic Retry; they are
not described as unconfirmed Surface reclamation. After ACK succeeds, Resk drops the old id,
switches HOME and renders a source-id-keyed dialog in the root Stack. A manually
entered nonempty password creates `sourceAttempt.withPassword(...)`, then a new
session id and `sessionAdd` → Surface bind → `sessionStart`. Approved route,
ID-only intent, requested FPS and view-only are preserved; unverified-input
acceptance is reset for the new session. There is no automatic password retry,
old-closed-id `sessionLogin`, 2FA form or prompt for a non-password failure.
Cancel, replacement intent, disposal and stale source/prompt callbacks invalidate
the retry. ACK failure keeps the source handle and reports receipt-confirmation
failure separately from Surface-reclamation failure.

These are changed JSON/lifecycle semantics with unchanged exported function
signatures. Native `.so`, typed package and Resk must be delivered from paired
sources through a refreshed HAR; source-only inspection is not build, device,
Surface-lifetime or functional authentication evidence.

**No separate ViewerEvent queue or drain task needs to be added** — the snapshot
already contains the facts the client acts on. The snapshot carries
`authenticated` as a real connection fact derived from `State::authenticated`
(`Viewer::snapshot`): it is set when the session is authorized, cleared when it
is closing or finished, and is not inferred from `phase`. A session can be
authenticated while still binding its surface at phase `awaiting_surface`; the
NAPI translation forwards this snapshot fact to ArkTS.

Input admission and the peer's keyboard grant share one engine generation.
`input_generation` advances when either the local policy or that grant changes,
including revoke/regrant between two polls. ArkTS retires cached keys, modifiers,
buttons, gestures, and active IME editing contexts on a changed generation; a
missing generation conveys no such transition. Queued old-generation input is
not replayed. Both wire writers
release stale holds before accepting fresh-generation input, independently of
which `select!` branch wakes first.

Polls and accepted policy actions carry the engine's release accounting:

- `releases_owed`: all held/reserved input, including ordinary current holds;
- `releases_retired`: old-generation holds still awaiting a writer release;
- `release_pending`: whether `releases_retired` is nonzero;
- `releases_unreleased`: holds the stopped writer could not release.

An active Ctrl or button hold is not itself a pending release. ArkTS shows the
release-specific `note` while pending/unreleased and clears that report only
when a reply supplies known settled counters. Missing counters cannot clear an
earlier warning. Neither policy acceptance, generation change, nor successful
writer emission proves that the remote OS or application applied an Up event.

`sessionSendMouse`, `sessionInputKey`, and `sessionInputString` require a third
`inputGeneration: number` argument; it must be a positive safe integer. The
payload/text argument is unchanged. Each underlying `Viewer` input call checks
that expected epoch against the same gate view used for permission admission.
A stale request is refused, never restamped or automatically retried. Success
returns the actual queued `input_generation`, not a snapshot taken afterwards.
A refusal with a running viewer can report its current epoch so the page can
retire obsolete ownership, but that report is not an acceptance receipt.

The page records a hold only for a matching receipt in the same session and
current epoch. Lower epochs cannot clear newer ownership. Soft-keyboard latch
display and outgoing modifiers follow the page's accepted ownership, not an
independently toggled panel state. A failed final gesture move must still leave
an already-admitted same-epoch button release visible to the release drain.

Each touch-event batch and IME delta keeps its entry epoch; it cannot resume in
a newer epoch. A refused or interrupted IME delta ends that editing context and
resets its local baseline. Already-admitted operations are not undone or replayed.
Late callbacks while the editor is inactive cannot import old text into the reset
baseline; an explicit reopen starts a fresh editing context.

Mouse coordinate resolution is read-only until the engine accepts the event.
The record lock orders resolution, synchronous admission, and coordinate commit;
a refused move cannot affect a later coordinate-less button. The last admitted
position remains available across policy changes, but is not evidence that the
remote OS applied that movement.

## Engine API the HAR binds (verified against current source)

| Extension point | Engine API |
| --- | --- |
| build a viewer | `Viewer::start(ViewerOptions, Arc<dyn SurfaceLease>)` (direct, legacy-unverified dial), `Viewer::start_verified(options, lease, expected_id, peer_signing_key)` (direct, pinned trust), `Viewer::start_rendezvous(options, lease, RendezvousConfig)` (hbbs/hbbr) — all in `src/viewer.rs` |
| options | `ViewerOptions { target, username, local_id, local_name, password, requested_fps, input_policy }`; `ViewerTarget::{RustDesk, Vnc, Rdp}`. `start` validates direct endpoints and RDP account options before creating the runtime or opening a socket. RDP is served by IronRDP, not categorically rejected as in the historical bridge. Input policy is active before asynchronous startup; accepting unverified RustDesk input requires explicit operator consent. |
| surface | every constructor takes `Arc<dyn SurfaceLease>` (`pub use decoder::SurfaceLease`); the lease is read when the first frame opens the surface, and a zero id fails that open |
| snapshot | `ViewerSnapshot { phase, protocol, error, login_failure, peer_close_reason, width, height, codec, route, received_units, pushed_units, render_submissions, render_timing, queued_units, keyboard_allowed, input_generation, releases_owed, releases_retired, releases_unreleased, closed, authenticated, encrypted, peer_verified, platform, version, displays, current_display }`; NAPI derives `release_pending` from `releases_retired` and retains final facts until receipt ACK |
| input and lifecycle | `Viewer::send_mouse`, `Viewer::send_key` (RFB X11 keysyms), `Viewer::send_rustdesk_key`, `Viewer::request_keyframe`, `Viewer::request_close`, `Viewer::close` (returns `ReclamationUnconfirmed` when resource reclamation is unproven) |

Input permissions are never fabricated. Input must satisfy authentication, the
peer's keyboard grant, local view-only policy, and the protocol's trust policy.
For RustDesk, encryption is required and an unverified peer needs explicit
operator consent; that consent does not authenticate or verify the peer. RFB
has no RustDesk peer-verification evidence. `send_key` takes VNC X11 keysyms;
the core supports that path, but `sessionInputKey` still builds a RustDesk key
event and does not route to it.

## Protocol status

| Target form | Status |
| --- | --- |
| RustDesk direct address | Registered and dialled by `session_add`/`session_start` → `Viewer::start`. The direct connector is unverified: trust comes from the socket unless `start_verified` is used. |
| RustDesk peer id | Requires initialized foreground consent and a v2 explicit-save approved profile at registration. The record owns its resolved route and local identity; `sessionStart` uses the existing strict `Viewer::start_rendezvous` with matching canonical username/config ID, original wire key and decoded server key. Missing/unapproved/stale routes fail closed; there is no default-profile activation or unverified direct fallback. |
| VNC | Driver exists (`run_rfb`) and the late-binding/reclamation repair is in place: RFB authenticates before the ArkTS XComponent surface exists and publishes the actual geometry and authentication fact (`State::desktop_geometry` plus `ViewerSnapshot::authenticated`; RFB carries no platform, version or security evidence, so those stay empty rather than being guessed), waits for a nonzero lease at phase `awaiting_surface` with the same `SURFACE_WAIT`/`SURFACE_POLL` budget as the encoded path, then opens at `opening_surface`. The blocking `Sink::open` is joined even when cancellation wins the race, `resources_unconfirmed` is raised before native ownership starts, and a sink close only clears it when the platform confirmed the release (`close_sink`), so `Viewer::close` reports `ReclamationUnconfirmed` instead of `Ok` while native creation or surface release is unproven. |
| RDP | The engine has a maintained IronRDP session driver through `ViewerTarget::Rdp`; the HAR target parser must preserve that route rather than restore the historical blanket refusal. TLS/NLA, presentation, input permission and reclamation remain engine-owned. A HAR build is not device or real-peer RDP acceptance. |

## Host: core lifecycle only, not the old controlled-host product

`src/host.rs` implements `Host::start(HostOptions) -> Result<Host, HostError>`,
`Host::snapshot() -> HostSnapshot`, `Host::approve(request_id, allow)`,
`Host::request_close()` and `async Host::close()`. `HostSnapshot` carries a
locally generated approval-request epoch, the observed TCP origin (not a
cryptographic controller identity), geometry/fps/codec, `connected`/`encrypted`
and sent counters.

That is not the legacy controlled-host management surface, and it is not
available merely because `Host` exists:

- No password management (get/refresh/set-permanent/verification-method) and no
  settings setter. `HostOptions.passwords: Vec<String>` is only the set of
  secrets accepted for one start: empty means `ClickOnly`, otherwise
  `PasswordOrClick`, and the second factor is `NoSecondFactor`. Secret-selection
  mode is not an authentication-policy API, and it provides no temporary-password
  generation, permanent-password storage or runtime rotation.
- No 2FA enrollment/management and no trusted-device management.
- `HostSnapshot` has no peer-id, trusted-identity, multi-user or
  recording-authorization fields. `connected` is an authenticated connection
  fact; it is not OS capture consent and not proof that streaming is active.
- This crate has no host binding yet (`native/ohos_napi/src` has no host module).
  Any future binding must forward the core lifecycle only. The active Windows
  Flutter product consumes `HostRuntime` through its own Rust bridge; that does
  not expose a HarmonyOS host or add capture capability to this HAR. Approval
  request ownership and checked peer/task reclamation belong to `src/host.rs`.

## Not served today (explicit, not stubbed)

- Clipboard, file transfer, remote directory reads, desktop audio playback, multi-display
  switching, video pause, codec/image-quality setters, trusted-device enrollment,
  and the legacy toggle/job-id bookkeeping have no `Viewer` public operation
  to forward. The RustDesk login request disables audio, clipboard and file
  transfer. Second-factor answers now use the same authentication and its
  original absolute deadline; they do not create a new connection. The remaining
  unsupported operations must be answered as unsupported
  — never with default state, a silently swallowed call, or a fabricated success.
- `sessionCancelJob` has no job owner to cancel and is refused as a whole; it is
  neither a viewer close nor a terminal ACK (see the ACK contract above).
- `queryDecoderCapabilities` is metadata-only: `src/media_capability.rs` reports
  real H264/HEVC decoder advertisements while preserving unmeasured and
  advertised distinctions. Its `AsyncTask` performs the possibly-IPC capability
  queries off the JS/UI thread, does not start capture, raise permissions or
  create codec instances, and returns the individual query errors rather than a
  synthetic unsupported success. `runtimeGetDecoderCapabilities` is a real export
  that runs the same asynchronous advertised-metadata query under its legacy name.
- LAN responding/advertising, WOL, host registration, UDP/KCP route selection,
  account login and cloud address-book synchronization are not activated by the
  outbound discovery/approved-profile increment. A cached ID is not online proof.

## Status of this document

The statements above describe the current active sources. RDP uses the maintained
IronRDP adapter in `src/viewer.rs`; NAPI accepts explicit RDP endpoints and account
options rather than rejecting the protocol categorically. The RFB
late-binding/reclamation lifecycle (`awaiting_surface` → `opening_surface` →
`streaming`, joined blocking open, `close_sink` reclamation tracking), snapshot
authentication events, decoder-capability task and manifest entry remain exposed.
The ArkTS bridge consumes the asynchronous decoder query. Frame-rate telemetry
status follows the actual
`ViewerSnapshot.phase`; it is not a synthetic `streaming` value. Cross-layer
changes require a fresh HAR, refresh into ArkTS, an ArkTS build, and current
device evidence. Source descriptions here do not replace that deployment proof.
