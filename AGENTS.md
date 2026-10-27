# rd-engine Product Guide

## Product boundary

`rd-engine` is a shared Rust engine, not a client application. It has exactly two kernel outputs:

```text
src -> native/ohos_napi -> HAR           HarmonyOS only -> Resk (R_RustDesk-ArkTS)
src -> native/frb -> FRB Rust/Dart ABI   Non-HarmonyOS only -> official RustDesk Flutter client
```

The FRB surface is an official-client integration, not a separate Flutter product. Keep its
upstream revision, generated bindings and native runner/texture contracts explicit. Do not copy a
complete official application into this repository or substitute a custom Flutter frontend.

`R_RustDesk-Flutter` is the official upstream client's HarmonyOS port, distributed as RustDesk
Unofficial with its own upstream-derived kernel and release chain. The non-HarmonyOS FRB output
does not replace that port's HarmonyOS kernel. `R_RustDesk-ArkTS` is the Resk frontend.

The withdrawn Core/Har checkouts do not survive and are not dependencies. Earlier rules limiting
this engine to the HarmonyOS client or forbidding official-client FRB integration are superseded.

## Ownership

- `src/` owns shared protocol, connection, session, decode, presentation, input, configuration and lifecycle behavior.
- `native/ohos_napi/` owns HarmonyOS-only NAPI/HAR exports, declaration surface, metadata and packaging.
- `native/frb/` owns non-HarmonyOS official-client FRB exports, generated Rust/Dart bindings and required native integration.
- `R_RustDesk-ArkTS` owns the Resk ArkTS UI and HarmonyOS integration and consumes the HAR.
- Tests and probes are development tools. Do not ship a standalone engine Flutter app or host executable as a third product.

Bridge adapters convert types and hand off lifecycle, events and frames to real engine behavior.
Matching the official client's ABI is legitimate and required for FRB; fake state, no-op APIs and
synthetic success are not. Reuse pinned upstream behavior, including capture/codecs/input, and explicitly report missing
capabilities instead of claiming compatibility from matching function names.

The user's 2026-09-23 account decision keeps password/verification login, account lifecycle, and
cloud address-book synchronization/CRUD in the pinned official Dart owner. Do not translate that
business logic into this engine or the Resk ArkTS frontend. Native OIDC/HTTP, private credential
storage and cache support may back the official Dart consumer only where genuinely implemented;
unimplemented backing must remain explicit. Resk marks account login and cloud address-book
features as unsupported, independently of server API configuration or cached account state. Local
recent/favorite devices and existing remote connections are not disabled by this decision.

The user's 2026-09-24 decision deliberately excludes remote camera viewing/streaming,
text chat and voice calls from this engine, both bridges and their paired
consumers. They are not missing parity work. Keep their public APIs, UI actions,
session modes and feature-specific event consumers removed together; reject old
camera connection requests rather than treating them as ordinary desktop access.
Upstream protocol definitions and ignored control packets may remain for wire
compatibility, but must not activate a communication feature. Desktop video,
desktop audio playback and recording are distinct and must not be cut under
this rule. Do not alter protected capture/codec/presentation/input paths or the
separate HarmonyOS Flutter product to implement this exclusion.

## Legacy material

Historical material is evidence only, and neither withdrawn checkout survives. Do not merge, copy, link, or build anything from a withdrawn tree into this product. Historical tests, artifacts, and telemetry do not establish current behavior.

## Upstream-first implementation

- Directly reuse pinned `rustdesk/rustdesk` source for screen capture, encoding/decoding, keyboard/mouse acquisition and injection, and other cross-platform behavior. The user's 2026-09-23 instruction withdraws the custom-frame-pipeline exception. Stop extending the bespoke implementations; replace them with upstream source, not newly written equivalents. The RDP/VNC wires below retain their maintained protocol libraries.
- Preserve the existing high-frame-rate chain under the user's later 2026-09-23 instruction: an upstream transplant must not overwrite or silently downgrade native capture/encode, GPU/native-Surface decode/presentation, frame pacing, negotiated rate limits, bounded queues, cancellation/ownership or receive/display telemetry. Keep its current implementation and selection intact until replacement equivalence is demonstrated on the real targets. A successful compile or CPU-only image is not that evidence; when Windows/device verification is unavailable, do not delete or switch this path. Continue upstream adoption outside that boundary without adding a permanent duplicate backend or extending bespoke algorithms.
- Keep the engine as the active owner; reusable official libraries and source modules belong here, not a copied full client application. Do not revive a withdrawn checkout or merge the separate HarmonyOS products. Restrict local adaptations to the existing bridge/lifecycle contracts and genuinely missing platform APIs, explicitly identifying HarmonyOS-only adaptations.
- Reuse mature RDP and VNC libraries or client implementations instead of maintaining bespoke protocol, security negotiation, authentication, and encoding code. Limit local code to the connection, input, output, lifecycle, and platform adapters the product needs.
- Preserve upstream behavior, dependencies and required security boundaries. Change upstream code only for an actual integration/platform constraint or concrete correctness/security defect; speculative performance work is not a reason to replace its capture, codec or input implementations.
- Pin source revisions and dependency versions and retain attribution/licenses. A clean cutover removes superseded bespoke logic after the replacement works, not before. Do not create an additional generic service framework around already complete upstream behavior.
- Do not duplicate upstream algorithm/unit-test suites or run unrelated full suites just for transplantation. Check exact source provenance, compilation/linking, and the changed consumer path. Missing platform runtime evidence must remain explicit; copying official source does not prove an adapter works.

## Protocol implementations (current)

The engine no longer carries a bespoke RDP or RFB stack; both wires are upstream implementations
behind this engine's lifecycle.

- `src/protocol/rdp/**` is the real IronRDP adapter on pinned crates (`ironrdp-core`, `-pdu`,
  `-connector`, `-session`, `-graphics`, `-async`, `-tokio`, plus `-cliprdr`, `-dcontrol`, `-dvc`,
  `-bulk`). TLS uses rustls with native roots, NLA/CredSSP is mandatory, and the peer's real
  `DemandActive` input capabilities decide what may be sent.
- `src/protocol/rfb/**` with `native/vnc/rd_vnc.c` is the real LibVNCClient wrapper. Upstream owns
  update-request pacing, decoding and the pointer/keyboard encoders; this side owns the
  cancellation-safe receive/close contract and type conversion only.
- `src/viewer.rs` is the shell both wires plug into (`ViewerTarget::{RustDesk,Vnc,Rdp}`).

Extending either protocol means extending these upstream types. Do not add a parallel encoder,
decoder or handshake to route around upstream behaviour, and never present a hand-written protocol
fixture as interop evidence.

## Vendored dependencies

`vendor/ironrdp-pdu` is the published 0.9.0 crate plus one documented fix: the missing
`MouseEventRel` payload delegation in `FastPathInputEvent::encode`. `UPSTREAM.txt` holds the
provenance and `relative-input.patch` the exact diff; keep both current with the vendored source.

`vendor/libsodium-sys` is the pinned 0.2.7 crate (FrankHan052176/sodiumoxide commit
`a09de89d843f88a7bfccd80266150fe5d33e1eee`, libsodium 1.0.18 commit `8acd22717f6af798b1ed5fd275e2b4c789425cf5`)
with build-only ExFAT archive corrections. `build-aux/ltmain.sh` uses directory-based
locking (`mkdir`/`rmdir`) instead of unsupported hard links and excludes `._*` AppleDouble
metadata when collecting extracted objects, preventing invalid archive members. Crate
version, `build.rs`, and crypto/Rust FFI APIs remain unchanged. `UPSTREAM.json` records provenance
and `archive-directory-lock.patch` records the exact diff.

Three separate Cargo workspaces select these vendored crates — the engine root, `native/frb`, and
`native/ohos_napi`. Any change to vendored sources or patch tables must land in all three workspaces
(root relative `vendor/...`, bridge relative `../../vendor/...`), or a build silently falls back to
an unpatched upstream/Git release without the fix or hangs on the ExFAT hard-link lock. Never patch
the registry or Git cache; vendor and record instead.

The native provenance verifier requires Python 3.11+ and parses the actual Cargo dependency
and patch tables; matching text in another table is not accepted as source ownership. CI
installs Python 3.12 before verification.

## Shared-source integration verification checkpoint

- The engine and both bridges select the same path-owned `base`, `hbb_common` and
  `libsodium-sys`; the libsodium source cutover preserves every other locked package record.
- Reverse-applying the recorded integration patches reproduces all 132 imported RustDesk/common
  Git blobs and all 566 libsodium dependency Git blobs. At that integration checkpoint,
  provenance covered 983 files across seven source trees; later account additions are recorded below.
- On macOS, `cargo check --locked --all-targets`, 101 engine library tests, and the linked
  `native/frb` library build pass. Loading that library and exercising its generated synchronous
  version-conversion ABI passes; this does not establish full Flutter-client compatibility.
- The configured libtool was exercised on the NAS for concurrent extraction, successful/error
  lock cleanup, original failure status retention, and a dry run preserving another lock.
  Universal/fat-archive and forced-termination branches were not exercised.
- The refreshed OHOS HAR builds and Resk passes `assembleApp` (`default`, `debug`, unsigned).
  Installed library/declaration bytes match the HAR, and all 23 loadable ELF sections in the
  final App match the current native build. No device installation or runtime claim follows.
- At the shared-source checkpoint, all 32 protected high-frame-rate runtime source files
  were byte-identical. The subsequent Windows SDK 10.0.28000 build required changing only
  the decoder's `d3d10.h` include to `d3d10_1.h` to satisfy the SDK's header ordering.
  That compile-only change does not replace the selected producer/decoder, rate controls
  or lifecycle implementation. Windows SSH access is now restored as recorded below;
  actual Windows/device/GPU/FPS acceptance remains unproven.

## Current account integration delivery boundary

- The user keeps password/verification login and cloud address-book/group business in the
  pinned official Dart consumer. `official-account` is selected by the non-HarmonyOS FRB
  bridge only; Resk does not expose account login or cloud synchronization.
- The user's current acceptance workflow is paired generation, compilation/linking and
  packaging, followed by user-run functional testing. Do not run account, device or
  performance scenarios on their behalf or treat a source audit as runtime acceptance.
- The corrected account bridge passes the macOS release library build; all six scoped
  account wire exports are present. The exact pinned official consumer with the recorded
  patches passes the Flutter 3.24.5 / Dart 3.5.4 `darwin` debug bundle compilation. This
  is compile/link evidence only. At that checkpoint provenance covered 1043 files
  in nine trees; fresh patch replay reproduced the compiled consumer sources.
- At the earlier account-integration checkpoint, the then-current OHOS HAR was refreshed
  through the Resk refresh script and Resk passed `assembleApp` (`default`, `debug`)
  with a controlled debug signing profile, producing signed HAP and App artifacts.
  Installed declarations/native bytes matched that HAR; both signed packages contained
  all 23 matching allocated native ELF sections. This is historical evidence, not the
  current unsigned host-parity build or a device installation/runtime result.
- In the 2026-09-24 host-parity build, the shared engine rebuilt the OHOS NAPI
  HAR from a dirty local source tree and Resk refreshed its local package. The
  installed native library and declarations match that HAR. Resk's `default`,
  `debug` `assembleApp` completed without a signing profile, producing
  `entry-default-unsigned.hap` and `R_RustDesk-ArkTS-default-unsigned.app`;
  each contains the same 23 allocated ELF sections as the freshly built native
  library. These unsigned packages were not installed or run on a device.
- Windows build access is restored: the user independently confirmed ED25519 fingerprint
  `SHA256:WGVgFGUAsp3Twd5xTmyg4nbI9ay4zxT/cODxW72YtmI`; `rustdesk-windows` now resolves to
  `10.53.176.3`, and a strictly verified session returned `FrankHanWin` / `frankhanwin\23820`.
  The old `.2` endpoint presents a different Dropbear identity, not this Windows key. Do not
  bypass verification or treat restored SSH access as client compilation/runtime evidence.
- At the earlier account-only checkpoint, a Windows build at
  `C:/Users/23820/rd-account-final-20260924` compiled the
  release FRB DLL and pinned official client `1.5.0+68` with Flutter 3.24.5/Dart 3.5.4,
  Rust 1.95, VS2022/v143 and the selected static-md libvpx 1.15.2/Zlib 1.3.2 prefix.
  The complete Flutter Release INSTALL bundle has 90 files; its `librustdesk.dll`
  matches the newly compiled DLL (`d880a674a96715a4b98f700b776de3a8483b2cb8a2af4081eb9aba85b6b04fbc`).
  Static inspection confirms all six scoped account exports and the required texture
  wait export. The private ZIP is compiled/packaged evidence, not runtime acceptance.
- Windows patch application preserves LF bytes with process-local Git options. The
  client resolves its unchanged locked dependencies in its own `.pub-cache`; the
  existing shared cache contained modified `settings_ui` and `extended_text` sources
  for unrelated SDKs and was left intact. No global SDK/cache/configuration was patched.
  Do not replace the private cache with that shared cache or relax the lock gate.
- This Mac has Command Line Tools but no full Xcode/CocoaPods client build environment; a
  macOS native library and Dart bundle must not be called a runnable desktop application.

## Current host-control and version-identified delivery (2026-09-24)

- Native provenance verifies 1166 local source and adaptation files in 16 trees
  against `native/frb/UPSTREAM.lock`; separately, the official Git objects at
  `092a961b629d318fe290eeafac0cd214a1e9deeb` establish Cargo product
  version `1.5.0` and Flutter package version `1.5.0+68`. Lock integrity does
  not claim that every adapted native file is byte-identical to upstream.
  `main_get_version` now reports the pinned product version to the official
  About consumer, not the independently versioned `rd-engine-flutter` crate.
  Paired FRB bindings were regenerated with 1.80.1 / Dart 3.5.4; a linked
  macOS-library call through generated Dart returned `1.5.0`.
- A fresh Windows build at `C:/Users/23820/rd-host-version-20260924` compiled the
  release engine DLL and pinned official Flutter client with Rust 1.95,
  Flutter 3.24.5 / Dart 3.5.4, VS2022/v143, and selected static-md libvpx
  1.15.2 / Zlib 1.3.2. The 81-file Release INSTALL bundle contains the newly
  compiled DLL under the consumer's `librustdesk.dll` name; both SHA-256 values
  are `fbd39c292e017f732afcc790e655b1e9e779802916a4591543e54afd894c6b4b`.
  The build's `official-version-identity.txt` records the product/package pin,
  upstream revision, source-lock hashes and that DLL digest separately from
  the runtime implementation. The byte-checked ZIP and identity record live in
  `/Volumes/nas/BuildCache/RustDesk/windows-host-version-20260924/`; ZIP SHA-256
  is `7f36aa572101a8a01b4bd459949f7bef43490a203222fe2831f0b6623fe3bb5a`.
  The preceding 81-file `windows-host-parity-20260924` ZIP remains historical:
  it compiled but its About version would identify the bridge as `0.1.0`.
- A subsequent source-gated build at `C:/Users/23820/rd-host-snapshot-20260924`
  verified all 205 copied official-client files against raw, replacement-free Git
  blobs at the pin before staging the private Windows source tree. It copied only
  that immutable snapshot, the reviewed CMake override and two lock-verified
  generated bindings; ordered client patches applied to the private build copy.
  The VS2022/Flutter 3.24.5/Rust 1.95 build completed CMake INSTALL with 81
  files. Its compiled and bundled DLLs share SHA-256
  `ab0bd97046bdedd50db15a2408f4b3aed9db569984a7a715ba9651f53bc7c061`.
  The ZIP and identity record at
  `/Volumes/nas/BuildCache/RustDesk/windows-host-snapshot-20260924/` were
  checked member-by-member against the Windows bundle; the copied ZIP SHA-256 is
  `f25e68db3befed5baa33109340f4d72e96ab1b1aa8a1fb42c7bf3fa33896972e`.
  The earlier `windows-host-version-20260924` ZIP remains compile evidence but
  predates the raw-source gate: its mutable-worktree `git status` check did not
  prove that all copied official bytes matched the pinned Git commit.
- The user's first launch of the source-gated package exposed a bridge startup
  defect: after `ConvertSidToStringSidW` succeeded, the local text guard required
  the whole `S-1-...` string to contain only digits and hyphens, so every real SID
  failed on its leading `S` before host ID/password initialization. The guard now
  checks only safe standard SID field syntax while keeping token origin, user and
  logon SID, authentication ID, terminal session, executable identity and pipe
  DACL checks unchanged. Two Windows-only focused tests pass for canonical user,
  logon, hexadecimal-authority and malformed/SDDL-injection cases.
- A fresh full retry at `C:/Users/23820/rd-host-sidfix-20260924-retry1`
  repeated the 1166-file native lock and 205-blob official-client gates, built the
  release DLL and completed the 81-file Flutter CMake INSTALL. The engine DLL,
  bundled `librustdesk.dll` and ZIP member share SHA-256
  `96b861258f3e5750ed61a2e453be32d01a0c3c5a48e9dbfd9828bd91ea7aaa9f`.
  The member-by-member verified ZIP and identity record live at
  `/Volumes/nas/BuildCache/RustDesk/windows-host-sidfix-20260924/`; ZIP SHA-256 is
  `e14f5592a6a9ea3bfffe10787d697c68d412dd19d9b76e594285b42314552436`.
  The app was not launched by this workflow, so the user must still confirm that
  the replacement package reaches ready ID/password state without a new error.
- These are dirty-source private compile/link/package checks, not a signed
  release or app launch. No Windows account, approved host/CM, direct-LAN
  session, media decode/presentation, GPU, device or high-frame-rate runtime
  acceptance was performed. The official product version identifies the paired
  consumer source; it does not certify parity of this replacement Rust runtime.

## Current routed-service verification

- The three registration corrections are source-audited: a relay UUID reservation follows the
  owned transport (not the temporary route envelope), invalid configured endpoints return
  `InvalidInput` without publishing registration state, and one absolute deadline covers the
  entire route acquisition. The final tree passes `cargo check --locked --all-targets` and
  `cargo test --locked --lib --test rendezvous`: 102 library tests plus 16 rendezvous integration
  tests. The separate clock-driven
  local-route regression proves a listener cannot restart the acquisition budget and is reclaimed
  at expiry; it does not simulate stalled DNS or writes.
- A fresh build of official `rustdesk/rustdesk-server` at
  `a7736be5e40f85bfc141120dce587e836e5d4b80`, with its actual `hbb_common` submodule
  `69cea8dafee147848ae88702029f4bf7df7224c3` and unchanged lockfile, runs on this Mac.
  Its registry dependencies were mirrored with `cargo vendor` to avoid NAS AppleDouble files in
  ring's source enumeration; no server protocol source or dependency version was changed.
- The real hbbs/hbbr smoke exercises engine registration, online/offline presence, hbbs-signed
  peer verification on the viewer's direct route, and host local-route handoff. A controller-side
  `RequestRelay` driver separately exercises engine host relay acquisition, duplicate-UUID refusal,
  and real hbbr pairing; the relayed viewer pins the generated host key out of band. Both paths
  complete encrypted password authentication (wrong password then correct password), bidirectional
  application records, close, and explicit registration cancellation with the consumer still alive.
  This is not acceptance of the viewer's automatic relay fallback.
- Official hbbs presence and hbbr relay ports treat loopback *source* addresses as text-console
  connections. The smoke uses source-bound local forwarders while all destinations and server
  listeners remain loopback; a process sandbox denies non-loopback outbound connections. This is
  local service interoperability, not Internet NAT traversal, LAN discovery, Windows, HarmonyOS,
  host media, UI integration, or high-frame-rate acceptance. The broader client integration remains
  incomplete.
- The disposable service checkout, mirrored sources, server identity/database, probe source and
  final probe binary were removed after acceptance; both managed services were stopped. Repeat
  interoperability acceptance from pinned sources, not a retained fixture or historical binary.

## Windows texture boundary (`native/frb`)

`native/frb/include/rd_engine_windows_texture.h` is the public ABI a Windows client compiles
against; `native/frb/src/windows_texture.rs` implements it.

- `rd_engine_windows_texture_wait_progress` is required: a client must reject a DLL that does not
  export it rather than poll for it. `WAIT` is worker-only — never from the Flutter platform/render
  thread or a native wake callback — and its revision snapshot is taken before the operation that
  may report `BUSY`.
- Acquisition is nonblocking. `BUSY` is transient owner/state contention, `WOULD_BLOCK` means no
  image is available, and a full loan table is an owner limit. None of them owns a loan; a worker
  that sees `BUSY` waits for a real retirement edge and asks Flutter to present again instead of
  retrying in a loop.
- `release` ends an import loan only. It never signals GPU completion and never permits recycling.
- `request_close` and `CANCEL` reclaim nothing on their own: cancellation only wakes waiters, and
  disposal stays `BUSY` (retained) or `UNCONFIRMED` (quarantined) until the real conditions are met.
  A recorded terminal failure keeps its actual status/stage/HRESULT even after cancellation.
- One serialized lifecycle/retry worker per owner; passive waiters may be concurrent.

## Historical verification (before the two-output restructuring)

The following results were recorded on macOS before the current restructuring. The native source
directory was missing at its start; these results do not prove the present working tree builds.

- `cargo test --locked --lib viewer::tests::rdp_` passes — eight tests, including the relative-mouse
  encode regression that proves the vendored fix is the one actually being built.
- `cargo check --locked --all-targets` passes, and `cargo test --locked --lib` is 95 passing tests.
  That check previously stopped on `examples/vnc_probe.rs`, whose calls into the removed bespoke
  pacing/timing API were migrated with the cutover.
- Real loopback peers are the acceptance path: a genuine `libvncserver` example peer and a genuine
  `ironrdp-server` peer (TLS+NLA, trust supplied per process through `SSL_CERT_FILE`, never by
  loosening system roots). The ad-hoc probe and fixture used for this round's acceptance were removed
  with the workspace cleanup; repeating it means rebuilding those upstream peers.

- `cargo test --locked --test vnc_session --test viewer_vnc` passes — thirteen tests over the real
  LibVNCClient wrapper, including the input-policy regressions. `native/vnc/rd_vnc.c` must keep
  normalising upstream's `rfbBool` `TRUE` (`-1`) to 1: `-1` is reserved for its own geometry
  rejection, and handing it back as a completed write tore the session down after the first accepted
  input event.

- A real-peer RDP acceptance passes: TLS+NLA against a genuine `ironrdp-server`, a `streaming`
  session with `encrypted`/`peer_verified`, decoded presentation at the peer's own cadence, real
  scancode input (modifier down/up, pointer move and click), a held key released on a live policy
  revocation, stale-generation refusal, fresh input after regrant, and a close that reclaims the
  surface with nothing owed or unconfirmed. The peer's own log carries the same events in the same
  order.
- The reactivation path was exercised against a peer that resizes mid-session: a key held across
  Deactivate-All → Demand-Active is retired and really released, the new geometry is published, the
  input generation advances with the re-read capabilities, presentation continues, fresh input is
  admitted afterwards, and the close still settles with nothing owed or unconfirmed.
- The RFB path was exercised against a real `libvncserver` peer: real handshake, `streaming`,
  accepted input, a revocation released on the wire, and a close that returns success. That peer
  repaints only when our own input reaches it (its pointer/key handlers mark rectangles modified), so
  its frame count reflects our input rather than a rate — use a peer whose picture moves to measure
  frame flow.
- Rejection paths are classified, not guessed: an unknown CA and a name mismatch both fail as a
  certificate-trust error with `phase=failed`, `authenticated=false` and the surface reclaimed, and a
  wrong password fails as an authentication error distinct from transport or protocol failures.
- The RDP adapter clears the plaintext password during `SecureSettingsExchange` — before upstream
  clones its config into the activation sequence and the activation factory — with a drop guard
  covering failed or cancelled attempts. Keep that ordering: moving the wipe earlier breaks
  ClientInfo encoding, and moving it later restores session-lifetime retention.
- A fixture that re-sends byte-identical frames will not advance the observer: frame progress needs
  changing content. Animate the fixture's pixels when measuring a presentation rate.
- A cancelled pump was exercised: a pump future dropped while it waits for a PDU resumes on the
  same session and keeps presenting, so the adapter keeps the framing it had already read.
- The `native/ohos_napi` crate — which consumes `rd_engine::viewer` directly — builds for
  `aarch64-unknown-linux-ohos` against the migrated engine (`scripts/ohos-env.sh` then
  `cargo build --release --target aarch64-unknown-linux-ohos`), the prerequisite for refreshing the
  HAR. That is a cross-compile, not device proof.

Not yet proven:

- No runtime evidence yet for a cancelled **write**: that half needs a peer which stalls its receive
  window, which no fixture here does.
- The close branch where the server answers our shutdown request *and then* closes — the branch the
  final TLS `shutdown()` sits in — is only reachable with a peer that replies before closing. The
  loopback `ironrdp-server` disconnects on the request itself, so no run so far covers it.
- Nothing has run on a HarmonyOS device. The two-output restructuring has now
  cross-built the current HarmonyOS HAR, refreshed it into Resk, verified the
  installed native-library/declaration hashes, and built Resk with `assembleApp`
  (`default`, `debug`, unsigned). This is compile/integration evidence, not device
  runtime or release acceptance. Windows native build/runtime had not been re-verified
  at that checkpoint. Current trusted host access and later delivery evidence are recorded above.

## Engineering rules

1. Fix a missing API, toolchain, dependency, or lifecycle at its owner.
2. Keep allocations, copies, and per-frame work out of hot paths unless evidence requires them.
3. Avoid `unwrap()` and `expect()` in production code; propagate or handle errors explicitly.
4. Do not create nested Tokio runtimes, call `block_on` from async code, hold locks across `.await`, or use `std::thread::sleep()` in async code.
5. Keep changes minimal and local; do not perform unrelated refactors, dependency upgrades, or formatting passes.
6. For an exported contract change, update the Rust implementation, NAPI export, typed declaration, package artifact, and ArkTS caller as one cutover.
7. Input admits only what the peer's real capabilities allow, and a hold this writer already emitted
   must stay releasable after the capability that admitted it disappears — an enqueue-time check
   that cannot see the writer's held ledger must not reject that release.
8. Credentials live only until their last legitimate use: clear the plaintext password before
   upstream clones the connector configuration into session-lifetime activation state, and keep any
   lifetime comment honest about what the code actually retains.

## Build and validation

- Repeating the real-peer acceptance means rebuilding the peers from upstream: a `libvncserver`
  example server, and an `ironrdp-server` with TLS+NLA whose leaf certificate is trusted per process
  through `SSL_CERT_FILE`. Never point a probe at a fixture by loosening system roots, and never pass
  a credential through argv.
- Build `native/ohos_napi` from this project, then refresh `R_RustDesk-ArkTS/rustdesk-ohrs.har` using the ArkTS refresh script. Never edit the HAR binary.
- Validate current behavior with current build output and runtime evidence. For Pad interaction, wake the selected target, confirm its state and bounds, and stop the keep-awake task on exit.
- A high-frame-rate claim requires measured receive and display telemetry during a real direct-LAN session; a selected target rate alone is insufficient.
