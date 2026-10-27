# rd-engine

Shared Rust engine with exactly two kernel outputs:

| Output | Platform | Consumer | Owner |
| --- | --- | --- | --- |
| `rustdesk-ohrs` HAR | HarmonyOS only | Resk (`R_RustDesk-ArkTS`) | `native/ohos_napi` |
| FRB native library and generated Dart bindings | Non-HarmonyOS | Pinned official RustDesk Flutter client | `native/frb` |

There is no standalone rd-engine Flutter application. `R_RustDesk-Flutter` is the
separate HarmonyOS port of the official client, distributed as RustDesk Unofficial,
with its own upstream-derived kernel and AppGallery release chain. It is neither
this engine's source carrier nor the Resk kernel.

## Layout

```text
src/                       Shared session, transport, media, input and lifecycle
native/
  ohos_napi/               HarmonyOS NAPI declarations and HAR packaging
  frb/                     Non-HarmonyOS FRB ABI, generated Dart and native integration
  vnc/                     Pinned LibVNCClient and the engine's thin adapter
  windows-capture/         Desktop Duplication capture
  windows-nvenc/           NVENC producer
  windows-decoder/         Windows decoder
  windows-input/           Windows input boundary
vendor/ironrdp-pdu/         Pinned IronRDP crate with documented relative-input fix
examples/                  Development probes, not shipping applications
scripts/                   Shared build environment and integration entrypoints
```

RustDesk wire definitions, framing and cryptography use the pinned `hbb_common`
dependency. RDP uses IronRDP; VNC uses LibVNCClient. Outside the custom frame
pipeline, reuse pinned upstream RustDesk behavior rather than creating another
service or protocol implementation. The retired Core/Har repositories are not
build inputs or fallbacks.

## HarmonyOS HAR

With Rust and the HarmonyOS NDK installed:

```bash
bash native/ohos_napi/build-har.sh
```

This builds `native/ohos_napi/target/package.har` only; it does not build or install an
application. Its package includes `release-provenance.json` naming this engine's
revision and whether the source tree was dirty. A local dirty build is a development
artifact, not a release candidate.
Assembly happens under `native/ohos_napi/target/har/`; the source `package/` directory
contains metadata/declarations only, never generated libraries or embedded provenance.

Consume it from the Resk checkout:

```bash
bash scripts/refresh-native-har.sh
hvigorw assembleApp -p product=default -p buildMode=debug --no-daemon --no-incremental
```

The refresh script defaults to the sibling engine's HAR and rebuilds OHPM
installation state. Set `OHPM` or `OHOS_CLI_HOME` for the local toolchain;
`NATIVE_HAR_PATH` selects a specific already-built artifact. Never edit a HAR binary.

## Non-HarmonyOS FRB

`native/frb` owns the native library and its generated Dart package; it does not own
an application. Its `CLIENT_SURFACE.md` records the pinned official-client contract,
code generation, integration requirements and capability limitations. Generate Rust
and Dart bindings together before building the crate; do not substitute bindings
from the HarmonyOS fork or the removed standalone endpoint.

A successful library build or a matching export name is not full RustDesk feature
parity. Supported paths must be exercised through the pinned consumer; unsupported
features and unverified platform behavior remain explicit. The engine's Windows
texture-loan ABI is distinct from the official client's pointer-renderer contract.

The Windows workflow builds the FRB DLL and collects the Dart package and native
headers. It no longer packages a host executable as a separate product.

### Official client CI (Windows, Linux, macOS, Android, iOS)

`.github/workflows/flutter-client.yml` ("Official Flutter clients") compiles and
packages the pinned official RustDesk Flutter client against this engine's FRB
library on each non-HarmonyOS platform. It runs on `workflow_dispatch`, `push` and
`pull_request` with read-only repository permission and needs no signing secret.
The official checkout is the commit in `native/frb/UPSTREAM.txt`
(`092a961b629d318fe290eeafac0cd214a1e9deeb`); only the client is taken from it and
the upstream Rust core is never built. Pins: Rust 1.95.0, Flutter 3.24.5, Dart 3.5.4,
vcpkg `9e593bb18ea69cc5095e012465dcd675a822ed0d`, Android NDK 28.2.13676358.

1. `source-gate` runs `scripts/verify-native-provenance.sh --verify --require-tracked`
   (every locked native path must be tracked), checks out the pinned official commit
   and runs `scripts/test-flutter-ci.py`. That test stages each platform's snapshot
   from raw pinned Git blobs, replays `native/frb/patches/*` and rejects mutable
   runner drift or an existing output directory. It does not compile a client.
2. `client` builds eight targets in parallel (`fail-fast: false`):

   | Id | Runner | Rust target | vcpkg triplet | Uploaded artifact |
   | --- | --- | --- | --- | --- |
   | `windows-x64` | `windows-2022` | `x86_64-pc-windows-msvc` | `x64-windows-static-md` | bundle `.tar.gz` |
   | `linux-x64` | `ubuntu-24.04` | `x86_64-unknown-linux-gnu` | `x64-linux` | bundle `.tar.gz` |
   | `macos-x64` | `macos-15-intel` | `x86_64-apple-darwin` | `x64-osx` | `RustDesk.app` `.tar.gz` |
   | `macos-arm64` | `macos-14` | `aarch64-apple-darwin` | `arm64-osx` | `RustDesk.app` `.tar.gz` |
   | `android-arm64` | `ubuntu-24.04` | `aarch64-linux-android` | `arm64-android` | `*-ci-debug-key.apk` |
   | `android-armv7` | `ubuntu-24.04` | `armv7-linux-androideabi` | `arm-neon-android` | `*-ci-debug-key.apk` |
   | `android-x64` | `ubuntu-24.04` | `x86_64-linux-android` | `x64-android` | `*-ci-debug-key.apk` |
   | `ios-arm64` | `macos-14` | `aarch64-apple-ios` | `arm64-ios` | unsigned `.xcarchive` `.tar.gz` |

   `scripts/prepare-flutter-ci.py` stages and patches the client in a disposable
   directory; `scripts/build-flutter-ci.py` builds libvpx/libsodium/zlib through vcpkg
   (the pinned `native/frb/vcpkg-overlays`), builds `native/frb` with `--locked`,
   checks the required exports (including `rd_engine_windows_texture_wait_progress` on
   Windows and the JNI entry points on Android), installs the library under the
   consumer's expected name, then runs the client's own `flutter build` and verifies that
   the packaged client contains exactly that library (iOS: that the linked `Runner`
   keeps the FRB symbols). Every artifact set carries `client-inputs.json` (pins, patch,
   binding and native digests) and `SHA256SUMS`.

Not covered, deliberately: Windows/Linux ARM64 (the official ARM64 jobs need a
different Flutter SDK than this repository's lock), Android x86, installers, store or
release publication, and signing. Android packages use the CI's ephemeral debug key and
the iOS output is an unsigned archive, not an installable IPA. Artifacts are compile
and packaging evidence only: they are neither launched nor functionally tested, and
they do not establish GPU/hardware-codec, camera/chat/voice (excluded by product
decision) or high-frame-rate behavior.

Status: the workflow, scripts and docs are local, uncommitted work in a dirty tree, so
`--require-tracked` will fail until the locked native sources are committed. No
Actions run of `flutter-client.yml` has happened, so no platform may be reported as
built by this CI yet. Local checks so far: Python/YAML/bash syntax, and the staging
test above on the real pinned commit for all five platforms. A platform counts as built
only after its matrix job succeeds in GitHub Actions.

## Shared engine checks

Run inside this checkout, after restoring/installing its pinned native dependencies:

```bash
cargo check --locked --all-targets
cargo test --locked --lib
cargo test --locked --test vnc_session --test viewer_vnc
```

`examples/host_probe.rs`, `viewer_probe.rs`, and `windows_host_probe.rs` are explicit
development tools, run with `cargo run --example <name> -- ...`; `cargo build` has no
application binary targets. Real session, device and performance claims require
current runtime evidence, not historical test counts or selected FPS values.

## Verification and historical material

See [GitHub and Resk AGC release readiness](docs/RELEASE_READINESS.md) for the
2026-10-26 source/CI audit, observed GitHub status and proposed delivery order.
The Resk source audit and end-to-end invitation-test release remain unverified.

The current restructuring started with `native/` absent from the working tree.
Restoration uses this engine's own Git source and recorded source edits, with pinned
upstream dependencies fetched independently. Old `.so`/HAR files are not replacement
source or acceptance evidence.

See `AGENTS.md` for ownership and validation rules, `docs/MODERN_RUNTIME.md` for runtime
invariants, and `docs/OHRS_SURFACE.md` for Resk's HAR contract. `HANDOVER.md`,
`docs/PROTOCOL_EXTENSIONS.md`, and `docs/PARITY.md` retain historical records; old paths,
protocol implementations and test counts in them are not current build instructions.
