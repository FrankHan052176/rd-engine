# Official-client FRB kernel output

This directory is a **non-HarmonyOS kernel artifact**, not another Flutter
application. It adapts the official RustDesk Flutter client's ABI to the shared
`rd-engine` library. HarmonyOS builds use `native/ohos_napi` instead; the separate
`R_RustDesk-Flutter` HarmonyOS port keeps its own kernel and release chain.

## Deliberately excluded communication features

Camera viewing/streaming, text chat and voice calls are outside this product by
the user's 2026-09-24 decision, not missing parity features to implement later.
The paired bridge omits their eight chat/call APIs and the camera argument from
session creation/adoption. Regenerate both binding halves for this reduced ABI;
an unmodified official client's generated bindings are not interchangeable.

`patches/official-client-product-scope.patch` is the final required consumer
adaptation, after the render, account, SDK-lock and LAN patches. It removes the
three feature-specific consumer paths instead of leaving callable unsupported
buttons. Old camera commands/URLs/window requests must be rejected, never
reinterpreted as ordinary desktop access or another window type. Other window
types keep their existing serialized identities.

This boundary does not cut desktop video, desktop audio playback, screen
recording or local QR scanning, and does not imply those unavailable features
have been implemented. Upstream protocol/source snapshots may still name the
excluded messages; their presence is not a product service or permission to
restore one. The separate HarmonyOS Flutter product is unchanged.

## Authoritative consumer and generation

`UPSTREAM.txt` pins the independent official `rustdesk/rustdesk` source to
`092a961b629d318fe290eeafac0cd214a1e9deeb`. Its `src/flutter_ffi.rs`,
`src/flutter.rs`, Dart models and native runners define this consumer contract.
Do not use bindings from the HarmonyOS fork or a withdrawn Core/Har checkout.

The pinned official checkout owns two related identifiers: Cargo's product version
`1.5.0` and Flutter's package/build version `1.5.0+68`. `UPSTREAM.txt` records
both beside the exact commit. The FRB `main_get_version` ABI serves the official
product version to the unchanged client's About page, not this bridge crate's
independent `0.1.0` version; neither value promises official engine feature
parity. The native build reads its offline pinned version metadata, while the
Windows source gate compares that pin against the exact committed upstream
manifests and the patched client's effective pubspec. The Windows build retains
the bridge version, official revision and compiled DLL hash as separate artifact
provenance. Do not change only the About label or bump the bridge crate to mask a
source/version mismatch.

Run from the engine checkout with Cargo and Dart on PATH:

```bash
bash native/frb/generate-bindings.sh
cargo build --manifest-path native/frb/Cargo.toml --locked --release
```

`native/frb/Cargo.toml` is the one place the shared engine's `software-vpx`
feature is selected, because the frame path this output serves is the CPU one: a
release build of this kernel links an installed libvpx for the target and decodes
VP8/VP9 through `src/platform/vpx_decoder.rs`. The root crate's default features
are unchanged and the HarmonyOS output keeps its platform media stack. A target
where no libvpx resolves still builds and refuses VPx by name, with the reason in
`RD_LIBVPX_PROVENANCE`; on Windows the install is the pinned static `vpx.lib`
built by `native/frb/vcpkg-overlays/libvpx` (libvpx 1.15.2), named by
`LIBVPX_PREFIX`.

The generator must be **flutter_rust_bridge_codegen 1.80.1**. Rust and Dart both
pin the 1.80.1 runtime. `FRB_CODEGEN` can select that executable and `LLVM_PATH`
can select libclang. The generation script resolves the Dart package and keeps
build_runner enabled so that the `EventToUI` Freezed part is produced.
The pinned official desktop consumer uses Flutter 3.24.5 (Dart 3.5.4). Generate
and check the paired bindings with that SDK rather than resolving against an
unrelated current Dart installation.

`patches/official-client-flutter-lock.patch` records the pinned SDK's exact
resolution of the official client's inconsistent committed lockfile. It restores
the declared `flutter_test` SDK dependency and its required transitive versions;
`pubspec.yaml` and all nine Git resolved refs remain unchanged. The resolved
lock is then enforced on Windows, rather than silently resolving again. This is
a recorded build integration, not a dependency upgrade or a change to the
separate HarmonyOS Flutter product's lockfile.

The final product-scope patch then removes `dash_chat_2` and
`draggable_float_widget` plus their fourteen newly unreachable transitive
packages. Its lock was resolved with the same Flutter/Dart SDK: no retained
package record or SDK floor changes, and no package is added or upgraded.
Windows enforces the resulting final lock digest in `build-windows.ps1`.

Inputs and outputs:

- `src/client_compat.rs`: official-client function names, arguments and events.
- `src/bridge_generated*.rs`: paired native wire implementation.
- `dart/lib/generated_bridge*.dart`: generated `Rustdesk`/`RustdeskImpl` bindings,
  including the Freezed part. `dart/` is a bindings package, not a UI product.
- `src/localization/`: the pinned official language catalogue and lookup rules;
  its provenance manifest and integration patch record the bridge-only adaptations.
- `src/c_entry_points.rs`: the native-runner and RGBA-pointer ABI outside FRB.
- Cargo produces `rd_engine_flutter.dll` on Windows, or the corresponding native
  library on the selected non-HarmonyOS platform. Cargo's configured target and
  intermediate directories are preserved; the NAS guard is not bypassed.

Regenerate both halves whenever the input changes. Do not hand-patch generated
wire code, reuse a stale Dart file, or count matching symbol names as functional
compatibility. Error-capable Rust returns must preserve the official Dart call
shape: `Result<T>` for asynchronous results, `Result<SyncReturn<T>>` for
synchronous results.

## Official localization

The language list and translation lookup belong to the pinned official Rust
implementation, not a second Dart localization system. The bridge imports the
catalogues and lookup at the revision in `UPSTREAM.txt`; the local provenance
manifest records every imported Git blob and the exact integration patch.
`main_get_langs` serializes the official language pairs and reports serialization
errors through the existing asynchronous Dart error channel. `translate` uses
the saved `LocalConfig` language, supplied locale, English/key fallback and
placeholder rules from that implementation. A missing catalogue must not be
represented by an empty language list or an identity translation stub.

## Consumer integration

Use an independent checkout at the exact pinned upstream revision. The Windows
build template `scripts/client-windows-CMakeLists.txt` is that upstream CMake file
plus an explicit build-time library selection; it installs the FRB DLL under the
official runner's expected name, `librustdesk.dll`.

`scripts/sync-client-to-windows.sh` checks the checkout's official origin and
revision, then stages only the copied Flutter inputs from raw, replacement-free
Git blobs at the pin. `scripts/stage-official-client.py` compares every copied
worktree file and the complete selected file set (including ignored additions)
against that tree, rejecting links and other special files. The reviewed Windows
CMake override and exactly two provenance-locked generated Dart bindings replace
their named destinations; no other checkout bytes can enter the private snapshot.
Patch replay and Windows transfer read only that snapshot, never the mutable
checkout again. Generated plugin files come from Windows Pub, not this snapshot.
Recorded render/account/LAN/SDK-lock/product-scope/host-control patches apply
only to private build copies in their declared order; neither local handwritten
Dart nor an installed client is changed.
The build names its Windows Flutter, Rust, VS2022 and CMake inputs explicitly;
`REMOTE_LIBVPX_PREFIX` and `REMOTE_CMAKE_TOOLCHAIN_FILE` select the target's
isolated static-md libvpx/Zlib installation. Ambient Flutter or a prior SSH
command's environment is not a valid toolchain selection.

Stock Flutter 3.24.5 chooses the wrong generator when its discovery selects the
installed VS18 BuildTools. The explicit VS2022 CMake configuration preserves the
official project's Flutter assemble/AOT/asset target and stages `INSTALL` only
into its private bundle directory. It does not patch the SDK, omit native
plugins, switch renderers, or substitute a Dart-only bundle. The produced FRB
DLL must match the bundled `librustdesk.dll` digest. SSH host-key verification
remains mandatory.

The Windows runner requires `rustdesk_core_main_args` and `free_c_args`; the
non-Windows runners use `rustdesk_core_main`. The Dart frame consumer resolves
`session_get_rgba`. Native library loading names and ownership follow the pinned
runner, not a new standalone engine launcher.

## Official Dart account backing

Only this FRB artifact selects `official-account`. Password/verification login,
account UI and cloud address-book/group business stay in the pinned official
Dart sources. Resk does not gain those business features from this integration.
`src/official_account/UPSTREAM.json` records the native resolver, transport and
OIDC source provenance and the exact security/platform adaptations.

The paired consumer requires `patches/official-client-account-safety.patch`.
Its native account work captures one asynchronous protected snapshot: API,
token, account receipt and independent address-book/group cache receipts.
Mutations compare the originating receipt under the native account and OS file
locks. OIDC start returns an attempt receipt; result/cancel are bound to it, and
successful commitment returns the exact successor account scope. A new getter
cannot authorize an old pending login or cache write. The old unscoped account
write/cache/OIDC ABI signatures remain explicit refusals, not success shims.
The legacy synchronous local-option read remains blocking; new account flows
use the asynchronous snapshot instead of performing protected I/O on the UI
isolate. Private snapshots and business responses are never diagnostics.

The random account master key is distinct from the engine identity. Its
platform backing is macOS's normal application-authorized user Keychain, iOS
WhenUnlockedThisDeviceOnly Keychain, Windows current-user DPAPI, Linux Secret
Service without unlock/create prompts, or AndroidKeyStore. macOS may ask the
actual user for OS authorization; denial is an error, never a plaintext fallback.
The Android runner additionally requires
`patches/official-client-account-storage.patch`: its application calls the real
`onAppStart` lifecycle before initializing protected account storage. API 22
uses authenticated signed-RSA wrapping and API 23+ uses AES-GCM, with an
immutable creation reservation preventing ambiguous errors from regenerating
an existing key. These are explicit platform adapters, not upstream business
logic or independent credential implementations.

The user's delivery workflow is code generation, compilation, linking and
packaging, followed by user-run functional testing. Source review or a successful
build does not establish login, cross-process revocation, OS authorization,
restart recovery or target-device behavior. No such runtime acceptance is
implied by this section.

## Outbound LAN discovery

The LAN entrypoints use the pinned official outbound scanner in `src/lan`, not a
synthetic empty list or a second wire implementation. Its recorded source and
adaptation patches preserve the official peer-ID filter, discovery protobuf,
interface broadcasts, identity comparison and cache merge precedence. The shared
owner supplies bounded ingress, cancellation, serialized cache access and actual
worker retirement. `default-net` 0.14.1 is path-owned with recorded enumeration-only
and Windows allocation corrections; new `netlink-sys` remains at upstream 0.8.6.

The main event-stream registration owns discovery. Replacing/removing that stream
or closing the main window fences old publication before requesting retirement.
Normal FRB workers perform cache queries and retirement waits, never a Flutter
render callback. A notification coalesces queries; the current registration and
cache revision are checked again at the actual event enqueue. Favorites supplement
stored peer records with the same serialized LAN snapshot, without deriving any
credential or trusted server configuration from discovery metadata.

`patches/official-client-lan-actions.patch` removes scanning from the discovered
view's `build()` and supplies an explicit refresh action. Listing cached peers
does not start a scan. Deleting a discovered row waits for the old scan and the
official cache-removal/store attempt, then reloads the actual cache; it does not
display a durable-save success toast. The upstream `LanPeers::store` is log-only,
so completion cannot prove that disk persistence succeeded. Scan failures reach
the existing native error channel consumed by the official desktop page.

This does not add an incoming discovery responder, Wake-on-LAN, host service,
hbbs identity registration or a network reachability guarantee. Cached discovery
data is not identity trust. Resk's additional approved-profile and claimed-ID-only
route contract is documented in `docs/OHRS_SURFACE.md`; FRB retains its official
consumer's target-classification contract. Current evidence is compilation and
source/artifact inspection only; actual scanning and lifecycle acceptance belong
to the user.

## CPU frame delivery, libvpx, and the recorded client patch

The frame path this kernel offers the official client is the CPU one, and it is
the only one that exists here: `EventToUI::Rgba(0)` carries a frame that
`session_get_rgba_size` and the engine-owned pointer from `session_get_rgba`
expose to the official `ImageModel.onRgba`/`ImagePainter`. A published allocation
stays valid until `session_next_rgba` releases it, including across close,
reconnect and geometry changes. The engine keeps that ownership; no registration
success is fabricated anywhere on this path.

Nothing here reports a texture or GPU render path. The official client's
`platformFFI.registerPixelbufferTexture` reaches this kernel as
`session_register_pixelbuffer_texture`, which is an explicit refusal, and
`mainGetUseTextureRender()` answers false because that path does not exist in
this kernel.

Upstream's `TextureModel.updateCurrentDisplay` allocates a `_PixelbufferTexture`
and registers it for every display it is asked about, whatever that answer says.
`native/frb/patches/official-client-cpu-rgba.patch` records the whole
integration: one guard that returns before any allocation when
`bind.mainGetUseTextureRender()` is false. Where the kernel reports texture
render the method body is untouched, so texture-mode allocation, registration and
retirement stay upstream's. `scripts/sync-client-to-windows.sh` is its only
caller: it verifies the patch applies to the clean pinned local checkout, copies
it with the bridge sources, applies it to the **remote build copy** before
`flutter pub get`, and never modifies the local official checkout. Applicability
is checked rather than assumed, locally and again on the host. Existing remote
client/engine trees are rejected and retained; retries use a fresh staging root
instead of replacing or patching a failed tree twice.

`REMOTE_LIBVPX_PREFIX` must name the remote target's own libvpx install - the
vcpkg `x64-windows-static-md` prefix the overlay produces, holding
`include/vpx/vpx_decoder.h`, `lib/vpx.lib` and `lib/pkgconfig/vpx.pc`. The script
checks those three files on the host and exports the prefix for the bridge's
cargo command alone. A missing or mismatched install fails the run before
anything is copied; it never turns into a capability claim, and no local prefix
is ever substituted for it.

## Behavioral and ownership boundaries

The adapter must hand session lifecycle, protocol, frame production and input
admission to the shared engine. In particular:

- Preserve `EventToUI` variant order `Event`, `Rgba`, `Texture` and the official
  JSON event dialect consumed by the pinned Dart models.
- Mouse, keyboard and text input must pass the engine's policy and current input
  generation; an unverified peer is not implicitly trusted by this bridge.
- Borrowed RGBA bytes must stay immutable and alive until `session_next_rgba`
  releases them, including close, reconnect and geometry changes. Sending a new
  frame event does not itself end an outstanding pointer loan.
- Configuration uses the pinned shared/upstream implementation rather than a
  second in-memory imitation. Authentication data must not enter diagnostics or
  an ad-hoc plaintext preference store.
- Unsupported operations return explicit errors. Capability queries may report
  genuine absence; unimplemented data access must not masquerade as empty state
  or a successful action. Getter calls must never start a host service.

The adapter currently exposes a viewer, not a host service or installer. It
initializes the official client's `Input source 2` and translates its physical
HID/platform key codes. Each physical hold keeps its emitted wire identity
through repeat and release; reconnect clears that connection's translator state.
Stored view-only policy and explicit acceptance of an unverified peer feed the
engine's input gate rather than bypassing it.

A failed connection attempt leaves the official session stream alive for Retry.
Authentication failure emits the client's password/re-entry event; ordinary
transport failure emits its retryable error. Unsupported session modes, forced
relay, side switching and token login stay refused even when the client calls
start or retry after admission failed. Only explicit session close ends the
session's stream and registry ownership.

Peer lists come from the pinned shared store. Credentials are stripped from
serialized peer records and never included in list hashes. Passwords and OS/RDP
credentials are not exposed or persisted through general option accessors;
remembered-password login is explicitly refused. Account tokens use only the
protected account boundary above, not LocalConfig's plaintext option store.
Recording and other unavailable features remain explicit refusals, including
synchronous errors where the official API has a synchronous getter.

The engine's `include/rd_engine_windows_texture.h` token/loan ABI is **not** the
same interface as the official client's renderer-pointer registration API.
Keeping the real engine texture exports does not establish that the official
GPU renderer is supported. Do not advertise GPU/texture support without the
actual renderer and retirement integration.

## Acceptance

Current delivery is compile-only at the user's request: paired generation,
native compilation/linking, actual client compilation and packaging. Functional
testing is performed by the user, not by an assistant-run smoke or regression
suite. Real session/frame/input, Windows/GPU and device claims still require
that actual target evidence; a successful build establishes none of them.
Unsupported product features remain explicit rather than compatibility stubs.

Earlier account-only compilation evidence (before the product-scope cut):

- The paired bindings were regenerated with FRB 1.80.1 and Dart 3.5.4. The
  corrected `native/frb` passes `cargo build --locked --release --lib` on macOS;
  static inspection finds all six scoped account wire exports in that library.
- An external copy of the exact pinned official client, with the recorded
  render/account patches and these bindings, passes
  `flutter build bundle --no-pub --debug --target-platform darwin` using Flutter
  3.24.5. Fresh patch application reproduces the compiled consumer source bytes.
  This is Dart compilation, not a linked/runnable desktop application.
- A fresh isolated Windows source/output tree passes the locked release native build
  and the pinned official client `1.5.0+68` Flutter Release assemble/CMake INSTALL.
  The 90-file bundle includes all 11 generated Windows method-channel plugins;
  its `librustdesk.dll` is byte-identical to the newly compiled FRB DLL. Static
  inspection confirms all six scoped account exports and the required texture wait
  export. libvpx 1.15.2 and Zlib 1.3.2 remain the selected static-md dependencies.
  The unchanged approved Pub lock is enforced in a build-private cache, without
  consuming or modifying another SDK's patched shared packages. This establishes
  compilation/linking/packaging only, not that the client starts or functions.
- This Mac lacks the full Xcode/CocoaPods environment for a macOS runner. No client
  launch, account entrypoint, login, protected-store authorization or device scenario
  was run on either platform; those checks remain with the user.

VP8/VP9 runtime verification remains a separate gate. The Windows workflow is
configured to install pinned static libvpx through the vendored overlay, verify
its installed files, and run the linked decoder probe. That workflow was not run
for this delivery. No current bitstream-decode, `FirstNativeOutput`, GPU/texture,
H264/H265, 10-bit or HDR claim follows from the native/client compilation above;
actual consumer operation and decoder behavior still require target runtime evidence.
