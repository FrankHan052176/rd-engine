# RECOVERY MANIFEST - two-output baseline (rd-engine)

created_utc: 2026-09-22T15:42:57Z
branch: recovery/two-output-baseline-20260922T154257Z
base_sha: afe594f03ec36f5d165d9c41b419628d85aa33ed (branch main, the pre-tracking HEAD; unchanged by this work)
commit_identity: recovery <recovery@local> (inline `-c user.name/-c user.email`, no config file written)

## External snapshot (pre-tracking state; the only pre-existing copy of this source)
snapshot_path: /Volumes/nas/BuildCache/RustDesk/recovery-snapshots/rd-engine-afe594f0-pretracking-20260922T153254Z/rd-engine-source.tar.gz
snapshot_sha256: cf26010700feea0ba45d71b0f6c0f421fe314fc55f273d6f36326965bd6102b5
snapshot_files: 388
snapshot_note: verified by read-back; AppleDouble controlled-cache cleanup completed, evidence in the same snapshot directory.

## Commits (parent-linear; this file is C1's only added path)
C1 (this commit)  = afe594f03ec36f5d165d9c41b419628d85aa33ed tree + every tracked worktree change (43 modified, 41 deleted) verbatim + this manifest.
C2 (C1's child)   = C1 + the 279 untracked two-output build-input sources under
                    native/vnc/**, native/windows-input/**, native/windows-decoder/**, native/frb/**,
                    vendor/ironrdp-pdu/**  (gitignore-respecting: no target/, no .dart_tool/, no build/ output).
C3 (C2's child)   = C2 + the remaining 34 untracked current-source files (this commit). C3 is the frozen
                    representative of the current working tree for `git archive <branch>`.
tip = C3 = refs/heads/recovery/two-output-baseline-20260922T154257Z

## Declaration: main worktree untouched
All three commits were built with a temporary alternate index (GIT_INDEX_FILE); no add/commit ever
targeted the main index, and no checkout/switch/reset/stash/clean/restore/merge/rebase ran.
main still points at afe594f03ec36f5d165d9c41b419628d85aa33ed, HEAD is still refs/heads/main, `git status --short` is byte-identical to
the pre-seal reading (117 entries: 0 staged / 84 unstaged / 33 untracked entries), and .git/index is unchanged.
No working-tree file was created, modified or removed. Nothing was pushed; no remote was written.

## Coverage policy
- C1: tracked-only. `git add -u` against the live worktree, never `-A`, so no untracked path can leak in.
- C2: only the five native/vendor source groups above; `native/ohos_napi/build-har.sh` is deliberately NOT
  here (it lands in C3), and no ignored artifact is included.
- C3: every remaining untracked file that is genuinely current source. Beyond the paths named in the work
  order (23 of them) these 11 additional files were included because excluding them would make the archived
  tree non-buildable (evidence in each line):
    src/identity.rs                 - `pub mod identity;` in src/lib.rs
    src/platform/identity_store.rs  - `#[path = "platform/identity_store.rs"]` in src/identity.rs
    src/wake_on_lan.rs              - `pub mod wake_on_lan;` in src/lib.rs
    src/protocol/rdp/clipboard.rs   - `mod clipboard;` in src/protocol/rdp/mod.rs
    src/protocol/rdp/connection.rs  - `mod connection;` in src/protocol/rdp/mod.rs
    src/protocol/rdp/tls.rs         - `mod tls;` in src/protocol/rdp/mod.rs
    src/protocol/rfb/native.rs      - `mod native;` in src/protocol/rfb/mod.rs
    src/protocol/rfb/worker.rs      - `mod worker;` in src/protocol/rfb/mod.rs
    src/protocol/rdp/LICENSE-IRONRDP-MIT - license of the ironrdp-derived rdp sources committed alongside it
    native/ohos_napi/src/capabilities.rs - `mod capabilities;` in native/ohos_napi/src/lib.rs
    scripts/ohos-env.sh             - sourced by native/ohos_napi/build-har.sh line 31
  `flutter/pubspec.yaml` / `flutter/pubspec.lock` are already tracked, so they have no C3 role.

## Explicit non-scope (never added by C1..C3)
.omp/**, .DS_Store, logs/**, target/** (incl. native/frb/target, native/ohos_napi/target),
any .dart_tool/** or build/** cache tree, and any binary artifact.

## Excluded untracked entries (all 6, verbatim)
  - .DS_Store   (macOS Finder metadata, not engine source)
  - .omp/agents/audit.md   (agent/policy config, not engine source)
  - .omp/agents/coder.md   (agent/policy config, not engine source)
  - .omp/agents/evaluator.md   (agent/policy config, not engine source)
  - .omp/agents/quick.md   (agent/policy config, not engine source)
  - .omp/agents/visual-audit.md   (agent/policy config, not engine source)

## status-before (raw `git --no-optional-locks status --short`, 117 entries)
```
 M .github/workflows/windows.yml
 M .gitignore
 M Cargo.lock
 M Cargo.toml
 M HANDOVER.md
 M README.md
 D R_RustDesk-Core/flutter/windows/CMakeLists.txt
 M build.rs
 M docs/MODERN_RUNTIME.md
 M docs/OHRS_SURFACE.md
 M docs/PARITY.md
 M docs/PROTOCOL_EXTENSIONS.md
 M examples/observer_probe.rs
 M examples/rdp_connect.rs
 D examples/rdp_probe.rs
 M examples/vnc_probe.rs
 D flutter/.dart_tool/package_config.json
 D flutter/.dart_tool/package_graph.json
 D flutter/.dart_tool/pub/bin/ffigen/ffigen.dart-3.13.3.snapshot
 M flutter/pubspec.lock
 M flutter/pubspec.yaml
 D flutter/rust/CLIENT_SURFACE.md
 D flutter/rust/Cargo.lock
 D flutter/rust/Cargo.toml
 D flutter/rust/src/api.rs
 D flutter/rust/src/bridge_generated.io.rs
 D flutter/rust/src/bridge_generated.rs
 D flutter/rust/src/c_entry_points.rs
 D flutter/rust/src/client_compat.rs
 D flutter/rust/src/lib.rs
 D flutter_rust_bridge.yaml
 D logs/2026-09-17.log
 M native/ohos_napi/.gitignore
 M native/ohos_napi/Cargo.lock
 M native/ohos_napi/Cargo.toml
 M native/ohos_napi/build.rs
 D native/ohos_napi/pack-and-build-hap.sh
 D native/ohos_napi/package.har
 M native/ohos_napi/package/index.ets
 D native/ohos_napi/package/libs/arm64-v8a/libc++_shared.so
 D native/ohos_napi/package/libs/arm64-v8a/librd_engine_native_har.so
 M native/ohos_napi/package/libs/index.d.ts
 M native/ohos_napi/package/oh-package.json5
 M native/ohos_napi/src/lib.rs
 M scripts/client-windows-CMakeLists.txt
 M scripts/sync-client-to-windows.sh
 D src/bin/rd-engine-host.rs
 D src/bin/rd-engine-viewer.rs
 D src/bin/rd-engine-windows-host.rs
 D src/bridge_generated.io.rs
 D src/bridge_generated.rs
 M src/host.rs
 M src/lib.rs
 M src/media_capability.rs
 M src/platform/ohos_capability.rs
 M src/platform/ohos_decoder.rs
 M src/platform/windows_host_publisher.rs
 M src/platform/windows_publisher.rs
 M src/protocol/rdp/mod.rs
 D src/protocol/rdp/wire/bitmap.rs
 D src/protocol/rdp/wire/capability.rs
 D src/protocol/rdp/wire/fastpath.rs
 D src/protocol/rdp/wire/input.rs
 D src/protocol/rdp/wire/mcs.rs
 D src/protocol/rdp/wire/mod.rs
 D src/protocol/rdp/wire/security.rs
 D src/protocol/rdp/wire/x224.rs
 M src/protocol/rect.rs
 M src/protocol/rfb/auth.rs
 D src/protocol/rfb/encoding/copy_rect.rs
 D src/protocol/rfb/encoding/desktop_size.rs
 D src/protocol/rfb/encoding/hextile.rs
 D src/protocol/rfb/encoding/mod.rs
 D src/protocol/rfb/encoding/raw.rs
 D src/protocol/rfb/encoding/rre.rs
 D src/protocol/rfb/encoding/zlib_stream.rs
 D src/protocol/rfb/encoding/zrle.rs
 M src/protocol/rfb/mod.rs
 M src/protocol/rfb/session.rs
 M src/rendezvous.rs
 M src/viewer.rs
 M tests/rendezvous.rs
 M tests/viewer_vnc.rs
 M tests/vnc_session.rs
?? .DS_Store
?? .omp/
?? AGENTS.md
?? examples/host_probe.rs
?? examples/viewer_probe.rs
?? examples/windows_host_probe.rs
?? flutter/lib/client/
?? flutter/lib/engine_bridge.dart
?? flutter/lib/host/
?? flutter/lib/main.dart
?? flutter/macos/Flutter/
?? flutter/tool/
?? native/frb/
?? native/ohos_napi/build-har.sh
?? native/ohos_napi/src/capabilities.rs
?? native/vnc/
?? native/windows-decoder/
?? native/windows-input/
?? scripts/ohos-env.sh
?? src/identity.rs
?? src/platform/identity_store.rs
?? src/platform/windows_decoder.rs
?? src/platform/windows_input.rs
?? src/platform/windows_presentation.rs
?? src/protocol/rdp/LICENSE-IRONRDP-MIT
?? src/protocol/rdp/clipboard.rs
?? src/protocol/rdp/connection.rs
?? src/protocol/rdp/tls.rs
?? src/protocol/rfb/native.rs
?? src/protocol/rfb/worker.rs
?? src/rendezvous/
?? src/wake_on_lan.rs
?? vendor/
```
