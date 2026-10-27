#!/usr/bin/env bash
#
# Compiles and privately packages the official Flutter client with rd-engine on Windows.
#
# The local client's hand-written Dart stays untouched; generated bindings come from
# the same native/frb build input as the engine library. The client build's
# windows/CMakeLists.txt installs RUSTDESK_LIB_OVERRIDE as librustdesk.dll, the
# name its official runner loads. Sources use this layout:
#
#   <remote root>/client                 the client tree the build runs in
#   <remote root>/engine                 the rd-engine crate
#   <remote root>/engine/native/frb      the bridge crate and generated bindings
#
# The bridge's `rd-engine = { path = "../.." }` resolves only in that layout, so
# the bridge is never copied anywhere else. The verified build-windows.ps1 driver
# builds the bridge and the client, then this script proves the private bundle
# contains that exact freshly compiled engine DLL by comparing SHA-256 digests.
#
# Steps:
#   1. source gates   native provenance, official client identity, clean sources,
#                     patch applicability and CMake/plugin integration contract
#   2. resolve        authenticated cmd.exe host, home and isolated build root
#   3. preflight      prepare only the root, copy the verified PowerShell driver,
#                     validate the selected installed tools and native dependencies
#   4. sync           create fresh client/engine subtrees and copy source inputs
#   5. patch          apply recorded render/account/LAN/SDK-lock/product-scope/host adaptations
#   6. kernel        driver builds locked Release x86_64-pc-windows-msvc FRB
#   7. client        driver enforces target pub resolution, checks target plugins,
#                     then configures VS2022 CMake and builds Flutter assemble/INSTALL
#   8. verify        private bundle exists and its engine DLL has the exact hash
#
# Fail-closed: no client/engine source tree is copied until native/frb/UPSTREAM.lock
# verifies the engine and driver, the official client revision and clean copied
# paths match, all recorded patches apply locally, the CMake override/plugin
# integration is intact, and the selected Windows prerequisites pass preflight.
# The root may already contain deps/, but client/ and engine/ must not exist.
# No remote tree is deleted; failures retain the staged sources, logs and outputs.
# Driver diagnostics stream to stdout/stderr; capture the invocation externally
# when retaining a build log. This script never removes logs or build artifacts.
#
# CPU delivery and native dependency provenance
# --------------------------------------------
# The frame path this engine offers the client is the CPU one: `EventToUI::Rgba`
# through `session_get_rgba_size` and the engine-owned pointer, consumed by the
# official `ImageModel.onRgba`/ImagePainter. Upstream's
# `TextureModel.updateCurrentDisplay` allocates a pixelbuffer texture for every
# display it is asked about and registers its pointer through
# `platformFFI.registerPixelbufferTexture`, which this kernel refuses as
# `session_register_pixelbuffer_texture`. `mainGetUseTextureRender()` answers
# false here, so `native/frb/patches/official-client-cpu-rgba.patch` returns
# before that allocation, and only the **remote build copy** receives it: the
# local official checkout is checked with `git apply --check` and never modified.
#
# The bridge selects the engine's software-vpx feature (native/frb/Cargo.toml).
# REMOTE_LIBVPX_PREFIX names the remote x64-windows-static-md dependency install,
# never a prefix from this machine. The driver verifies pinned libvpx 1.15.2 and
# Zlib 1.3.2 in that same .../installed/x64-windows-static-md prefix, plus the
# selected CMake toolchain wrapper pointing at its installed root. Cargo receives
# both LIBVPX_PREFIX and ZLIB_ROOT in its own process environment. This script
# installs no native dependencies and changes no renderer or feature selection.
#
# `scripts/verify-native-provenance.sh --require-tracked` and the Windows
# workflow's libvpx overlay (`native/frb/vcpkg-overlays/libvpx`) are how a clean
# runner gets that prefix; a Windows host the operator provisions has to name its
# own.
#
# The D3 capability gate is not this script's to change. It ships the bridge only
# while the whole FRB surface matches native/frb/UPSTREAM.lock, so no run can
# hand-edit the frozen surface into advertising GPU/texture support, and the dll
# that reaches the bundle is the one built from those verified sources.
#
# Required installed build inputs (selected explicitly, never ambient Flutter):
#   - REMOTE_FLUTTER_ROOT: official Flutter 3.24.5 / Dart 3.5.4 for enforced pub
#     resolution and the unchanged Windows Flutter tool backend.
#   - REMOTE_RUST_TOOLCHAIN: pinned 1.95-x86_64-pc-windows-msvc by default; the
#     driver checks the selected compiler reports 1.95.0, rather than using the
#     host's unrelated default toolchain. Cargo feature selection is unchanged.
#   - REMOTE_VS_ROOT: VS2022 with x64 MSVC/v143, Windows SDK and vcvars64.bat.
#   - REMOTE_CMAKE: the selected VS2022 bundled CMake executable (3.31.6-msvc6),
#     not a newer unrelated global CMake. Quoted spaces in tool paths are supported.
#   - REMOTE_CMAKE_TOOLCHAIN_FILE: the provisioned vcpkg wrapper selecting the
#     actual installed root and x64-windows-static-md triplet for Cargo's native
#     dependencies. It is not passed to the Flutter runner's CMake configuration.
#   - REMOTE_LIBVPX_PREFIX: that install's static-md prefix, containing the pinned
#     libvpx and Zlib headers, libraries and provenance checked by the driver.
#   - Git and rustup proxies on the host's PATH; git applies patches to the copied
#     client (which carries no .git). Network or complete caches for locked Cargo
#     dependencies and the selected SDK's Windows build artifacts. Client Pub
#     packages need network access: each fresh client resolves them into its own
#     .pub-cache, never consuming or modifying another SDK's shared Pub cache.
#   - Local ssh/scp and a trusted Windows OpenSSH host whose login shell is cmd.exe.
#   - Optional REMOTE_HTTP_PROXY: an explicit http(s)://host:port dependency
#     proxy, without credentials. It applies only to driver processes, never to
#     global Windows/Cargo/Git settings; absent means the existing environment.
#
# The driver sets toolchain environment only within its build processes. It does
# not change SDK sources, rustup defaults or global settings. Flutter's stock
# `build windows` cannot select this host's intended VS instance, so the driver
# instead supplies VS2022/v143 and RUSTDESK_LIB_OVERRIDE explicitly to CMake.
# The original flutter_assemble target compiles the Release app and assets;
# INSTALL stages them solely into <root>/client/build/windows/x64/runner/Release.
# A successful build/package is not functional, device, account or performance
# acceptance. This script never launches the app or replaces an installed app.
#
# Windows inputs must be absolute drive-qualified paths. Backslashes normalize
# to forward slashes; command metacharacters and ambiguous path components are
# rejected. The scp destination root additionally excludes spaces/shell delimiters.
#
# Usage:
#   RUSTDESK_CLIENT_TREE=/path/to/pristine-official-checkout \
#     REMOTE_HOST=rustdesk-windows REMOTE_ROOT=C:/Users/me/rd-build \
#     REMOTE_FLUTTER_ROOT=C:/flutter324 \
#     REMOTE_RUST_TOOLCHAIN=1.95-x86_64-pc-windows-msvc \
#     REMOTE_VS_ROOT='C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools' \
#     REMOTE_CMAKE='C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe' \
#     REMOTE_CMAKE_TOOLCHAIN_FILE=C:/Users/me/rd-build/deps/rd-engine-vcpkg.cmake \
#     REMOTE_LIBVPX_PREFIX=C:/Users/me/rd-build/deps/vcpkg/installed/x64-windows-static-md \
#     bash scripts/sync-client-to-windows.sh
#
# REMOTE_HOST defaults to rustdesk-windows; REMOTE_ROOT defaults to the authenticated
# user's profile/rd-sync. All other inputs above are required except the pinned
# REMOTE_RUST_TOOLCHAIN default. SKIP_CARGO and ENGINE_DLL are rejected, not knobs:
# every run compiles <root>/engine/native/frb/target/x86_64-pc-windows-msvc/release/
# rd_engine_flutter.dll from fresh source/output subtrees and installs that DLL.
#
# The client tree is an explicit independent official-upstream checkout. The
# HarmonyOS port has its own kernel and is not the non-HarmonyOS FRB carrier.
#
set -euo pipefail

engine_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
client_tree="${RUSTDESK_CLIENT_TREE:-}"
bridge_dir="$engine_root/native/frb"
cpu_patch="$bridge_dir/patches/official-client-cpu-rgba.patch"
account_patch="$bridge_dir/patches/official-client-account-safety.patch"
flutter_lock_patch="$bridge_dir/patches/official-client-flutter-lock.patch"
lan_patch="$bridge_dir/patches/official-client-lan-actions.patch"
scope_patch="$bridge_dir/patches/official-client-product-scope.patch"
host_patch="$bridge_dir/patches/official-client-host-control.patch"
build_driver="$bridge_dir/build-windows.ps1"
remote_host="${REMOTE_HOST:-rustdesk-windows}"
remote_http_proxy="${REMOTE_HTTP_PROXY:-}"

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Every remote command uses a fresh cmd.exe environment. Disable AutoRun and
# delayed expansion in that process; all interpolated Windows inputs are checked
# before they reach it. The authenticated login shell must also be cmd.exe.
remote() { ssh "$remote_host" "cmd.exe /d /v:off /s /c \"$1\""; }

# sha256 of a file on the host, as bare hex: certutil prints the digest between
# its banner line and its completion note.
remote_sha256() {
  remote "certutil -hashfile \"$1\" SHA256" 2>&1 \
    | tr -d ' \r' | grep -Eio '[0-9a-f]{64}' | head -n 1 || true
}

# These paths cross cmd.exe, PowerShell -File and CMake. Keep spaces/parentheses
# (the verified VS installation needs them), but reject expansion, command/list
# delimiters, control characters and Windows aliases such as ../ or trailing dots.
windows_path() {
  local name="$1" path="${2//\\//}"
  [[ -n "$path" ]] || die "$name is required: name an absolute Windows build-input path"
  path="${path%/}"
  case "$path" in
    [A-Za-z]:/*) ;;
    *) die "$name must be an absolute drive-qualified Windows path; got '$path'" ;;
  esac
  case "$path" in
    *\"* | *%* | *'!'* | *'&'* | *'|'* | *'<'* | *'>'* | *'^'* | *'*'* | *'?'* | *';'* | *'$'* | *'`'*)
      die "$name contains a character unsafe for cmd.exe/PowerShell/CMake: '$path'" ;;
  esac
  [[ ! "$path" =~ [[:cntrl:]] ]] || die "$name contains a control character"
  case "${path:3}" in
    '' | /* | *//* | *:*) die "$name contains an empty or invalid Windows path component: '$path'" ;;
  esac
  case "$path/" in
    */./* | */../* | *./* | *' /'*) die "$name contains a dot or trailing-dot/space component: '$path'" ;;
  esac
  printf '%s\n' "$path"
}

# All stages receive the same explicit inputs. Paths are ordinary build inputs,
# not credentials; the helper owns tool/dependency validation and build setup.
run_stage() {
  local environment=''
  if [[ -n "$remote_http_proxy" ]]; then
    environment="set \"HTTP_PROXY=$remote_http_proxy\" && set \"HTTPS_PROXY=$remote_http_proxy\" && set \"CARGO_HTTP_PROXY=$remote_http_proxy\" && "
  fi
  remote "${environment}powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"$remote_driver\" -Stage \"$1\" $driver_arguments"
}

step "Checking local build inputs"
[[ -n "$client_tree" ]] || die \
  "RUSTDESK_CLIENT_TREE is required: name the pristine official checkout (its windows/CMakeLists.txt must carry the RUSTDESK_LIB_OVERRIDE hook; scripts/client-windows-CMakeLists.txt is the template)"
[[ -z "${SKIP_CARGO+x}" ]] || die "SKIP_CARGO is no longer supported: unset it; every run compiles a fresh engine DLL"
[[ -z "${ENGINE_DLL+x}" ]] || die "ENGINE_DLL is no longer supported: unset it; only this run's exact target DLL can be bundled"
client_tree="$(cd "$client_tree" && pwd -P)" || die "cannot resolve RUSTDESK_CLIENT_TREE"
client_dir="$client_tree/flutter"
for tool in ssh scp grep git sed cmp python3; do
  command -v "$tool" >/dev/null || die "$tool is required"
done

[[ -f "$bridge_dir/Cargo.toml" ]] || die "no engine bridge crate at $bridge_dir"
[[ -f "$bridge_dir/UPSTREAM.txt" ]] || die "missing FRB upstream provenance"
[[ -f "$bridge_dir/UPSTREAM.lock" ]] || die \
  "missing native/frb/UPSTREAM.lock: it pins the FRB revision and generation environment"
[[ -f "$cpu_patch" ]] || die \
  "missing $cpu_patch: the remote client copy needs the recorded CPU render patch (see native/frb/CLIENT_SURFACE.md)"
[[ -f "$account_patch" ]] || die \
  "missing $account_patch: the scoped account ABI requires its paired official Dart consumer"
[[ -f "$flutter_lock_patch" ]] || die \
  "missing $flutter_lock_patch: the pinned Flutter SDK requires its recorded official-client lock adaptation"
[[ -f "$lan_patch" ]] || die \
  "missing $lan_patch: discovery requires its explicit official-client scan action"
[[ -f "$scope_patch" ]] || die \
  "missing $scope_patch: excluded camera/chat/call capabilities must not reach the client"
[[ -f "$host_patch" ]] || die \
  "missing $host_patch: controlled-host commands require their authoritative CM consumer"
[[ -f "$build_driver" ]] || die "missing verified Windows build driver $build_driver"
upstream_revision="$(sed -n 's/^Commit: //p' "$bridge_dir/UPSTREAM.txt")"
[[ "$upstream_revision" =~ ^[0-9a-f]{40}$ ]] || die "invalid FRB upstream commit pin"
lock_revision="$(sed -n 's/^Upstream commit: //p' "$bridge_dir/UPSTREAM.lock")"
[[ "$lock_revision" == "$upstream_revision" ]] || die \
  "native/frb/UPSTREAM.lock pins $lock_revision while native/frb/UPSTREAM.txt pins $upstream_revision"
frb_dart_runtime="$(sed -n 's/^Dart runtime: //p' "$bridge_dir/UPSTREAM.lock")"
[[ -n "$frb_dart_runtime" ]] || die "native/frb/UPSTREAM.lock records no Dart runtime"
for binding in generated_bridge.dart generated_bridge.freezed.dart; do
  [[ -f "$bridge_dir/dart/lib/$binding" ]] || die \
    "missing FRB binding $binding: generate native/frb Rust and Dart together first"
done
# A client tree inside rd-engine is always wrong: this script would mirror the
# engine's own tree as if it were a client and then build it against itself.
case "$client_dir" in
  "$engine_root"/*) die "the client tree resolves inside rd-engine ($client_dir): point RUSTDESK_CLIENT_TREE at a client checkout outside this repository" ;;
esac
[[ -d "$client_dir/windows" ]] || die "no client tree at $client_dir (set RUSTDESK_CLIENT_TREE)"
[[ -f "$client_dir/windows/CMakeLists.txt" ]] || die "no $client_dir/windows/CMakeLists.txt"

step "Checking the client identity"
# The FRB carrier is the official rustdesk/rustdesk checkout, nothing else: a
# fork or the HarmonyOS port keeps its own kernel, and this engine does not
# replace it. The wrong tree here is how the engine would be forced into a client
# the product boundary excludes.
client_remote="$(git -C "$client_tree" remote get-url origin 2>/dev/null)" || die \
  "client must be a Git checkout with an origin remote: $client_tree"
case "$client_remote" in
  https://github.com/rustdesk/rustdesk | https://github.com/rustdesk/rustdesk.git | \
    git@github.com:rustdesk/rustdesk | git@github.com:rustdesk/rustdesk.git) ;;
  *) die \
    "client origin is '$client_remote': the FRB output runs on an independent rustdesk/rustdesk checkout, never on a fork or on the HarmonyOS port" ;;
esac
[[ ! -e "$client_dir/ohos" ]] || die \
  "$client_dir/ohos exists: that is the HarmonyOS port's platform directory, which keeps its own kernel"
client_revision="$(git -C "$client_tree" rev-parse HEAD)" || die "client must be an independent Git checkout"
[[ "$client_revision" == "$upstream_revision" ]] || die \
  "official client revision $client_revision does not match FRB pin $upstream_revision"

step "Verifying native provenance and the pinned official product versions"
bash "$engine_root/scripts/verify-native-provenance.sh" --official-client-tree "$client_tree" || die \
  "native/official-client provenance verification failed: fix the source, or refresh native/frb/UPSTREAM.lock after an intended change"
official_flutter_version="$(sed -n 's/^Official Flutter package version: //p' "$bridge_dir/UPSTREAM.txt")"

# Stage the exact copied source set from raw, replacement-free pinned Git blobs.
# A clean git status does not detect assumed-unchanged files or ignored additions;
# verification and transfer must use the same private snapshot, never reread the
# mutable checkout. Only the reviewed CMake override and two locked FRB bindings
# replace upstream source bytes.
client_snapshot_root="$(mktemp -d "${TMPDIR:-/tmp}/rd-official-client.XXXXXXXX")" || die \
  "cannot create the private official-client snapshot directory"
trap 'rm -rf -- "$client_snapshot_root"' EXIT
python3 "$engine_root/scripts/stage-official-client.py" \
  --official-client-tree "$client_tree" --output "$client_snapshot_root/client" || die \
  "the official client source set differs from its pinned Git blobs or reviewed overrides"
client_dir="$client_snapshot_root/client"
# Check the complete ordered patch stack in a disposable snapshot child. Later
# product exclusions intentionally consume files already changed by account/LAN.
patch_check_dir="$client_snapshot_root/patch-check"
mkdir "$patch_check_dir"
cp -R "$client_dir/lib" "$client_dir/assets" "$patch_check_dir/"
cp "$client_dir/pubspec.yaml" "$client_dir/pubspec.lock" "$patch_check_dir/"
mkdir -p "$patch_check_dir/windows/runner"
cp "$client_dir/windows/runner/main.cpp" "$patch_check_dir/windows/runner/"
for patch in "$cpu_patch" "$account_patch" "$flutter_lock_patch" "$lan_patch" "$scope_patch" "$host_patch"; do
  git -c core.autocrlf=false -c core.eol=lf -C "$patch_check_dir" apply --check "$patch" || die \
    "the ordered client patch $patch does not apply to the pinned source"
  git -c core.autocrlf=false -c core.eol=lf -C "$patch_check_dir" apply "$patch" || die \
    "the ordered client patch $patch failed in the private source check"
done
[[ "$(grep -cE '^version[[:blank:]]*:' "$patch_check_dir/pubspec.yaml" || true)" == 1 ]] || die \
  "the effective postpatch pubspec.yaml must contain exactly one version declaration"
postpatch_flutter_version="$(sed -n 's/^version[[:blank:]]*:[[:blank:]]*//p' "$patch_check_dir/pubspec.yaml" |
  sed 's/[[:blank:]]*#.*//; s/[[:blank:]]*$//')"
[[ "$postpatch_flutter_version" == "$official_flutter_version" ]] || die \
  "the effective postpatch Flutter version $postpatch_flutter_version does not match Official Flutter package version $official_flutter_version"
rm -rf -- "$patch_check_dir"
frb_dart_pin="${frb_dart_runtime##* }"
grep -Eq "^[[:space:]]*flutter_rust_bridge:[[:space:]]*[^#]*$frb_dart_pin" "$client_dir/pubspec.yaml" || die \
  "the client's pubspec.yaml does not pin flutter_rust_bridge $frb_dart_pin: the copied bindings are generated for that Dart runtime"

step "Checking the source CMake override and plugin integration contract"
template="$engine_root/scripts/client-windows-CMakeLists.txt"
[[ -f "$template" ]] || die "missing $template"
cmp -s "$client_dir/windows/CMakeLists.txt" "$template" || die \
  "the client's windows/CMakeLists.txt must exactly match scripts/client-windows-CMakeLists.txt; unreviewed CMake changes cannot be copied"
# The lines that carry the override into CMake and install the engine dll under
# the official runner's name. The template holds them too, so a drifted template
# fails here instead of quietly relaxing the contract.
contract_lines=(
  'set(RUSTDESK_LIB_OVERRIDE "" CACHE FILEPATH'
  'string(STRIP "$ENV{RUSTDESK_LIB_OVERRIDE}" RUSTDESK_LIB_OVERRIDE)'
  'set(RUSTDESK_LIB "${RUSTDESK_LIB_OVERRIDE}")'
  'install(FILES "${RUSTDESK_LIB}" DESTINATION "${INSTALL_BUNDLE_LIB_DIR}" COMPONENT Runtime RENAME librustdesk.dll)'
  'include(flutter/generated_plugins.cmake)'
)
# Comments dropped and all whitespace collapsed, so a line break inside the
# install() command cannot hide a missing contract line.
collapse() { sed 's/#.*//' "$1" | tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g'; }
client_cmake="$(collapse "$client_dir/windows/CMakeLists.txt")"
template_cmake="$(collapse "$template")"
for line in "${contract_lines[@]}"; do
  printf '%s\n' "$template_cmake" | grep -Fq -- "$line" || die \
    "scripts/client-windows-CMakeLists.txt no longer carries the contract line: $line"
  printf '%s\n' "$client_cmake" | grep -Fq -- "$line" || die \
    "the client's windows/CMakeLists.txt does not carry the contract line: $line"
done
# Upstream's own default plus exactly one override assignment, and the override
# has to be the last word: a later set(RUSTDESK_LIB ...) would install the
# client's own library while every message still claimed the engine.
lib_assignments="$(grep -cE '^[[:space:]]*set\(RUSTDESK_LIB ' "$client_dir/windows/CMakeLists.txt" || true)"
[[ "$lib_assignments" == 2 ]] || die \
  "the client's windows/CMakeLists.txt has $lib_assignments set(RUSTDESK_LIB ...) lines; exactly the upstream default and the override are expected"
grep -E '^[[:space:]]*set\(RUSTDESK_LIB ' "$client_dir/windows/CMakeLists.txt" | sed -n '$p' |
  grep -q RUSTDESK_LIB_OVERRIDE || die \
  "the last set(RUSTDESK_LIB ...) in the client's windows/CMakeLists.txt is not the override: the bundle would not receive this engine"
# The pristine pubspec and Windows Flutter CMake sources establish integration
# provenance, not target resolution. Windows pub get regenerates the plugin
# lists/registrants and the driver checks both plugin lists and their real target
# sources there. No local generated plugin files or ephemeral links are evidence.
# The bridge copy carries the frozen Windows texture ABI, and the pinned client
# rejects a dll that does not export the wait entry point, so a bridge missing it
# must not be copied at all.
texture_header="$bridge_dir/include/rd_engine_windows_texture.h"
[[ -f "$texture_header" ]] || die "missing $texture_header: the bridge copy must carry the frozen texture ABI"
grep -q 'rd_engine_windows_texture_wait_progress' "$texture_header" || die \
  "$texture_header does not declare rd_engine_windows_texture_wait_progress: a client must reject a dll that lacks it"

# Resolve every copied source-only input before preparing anything on the host.
for path in pubspec.yaml pubspec.lock analysis_options.yaml .metadata lib assets \
            windows/.gitignore windows/CMakeLists.txt windows/runner windows/flutter/CMakeLists.txt; do
  [[ -e "$client_dir/$path" ]] || die "missing $client_dir/$path"
done
engine_sources=()
for path in Cargo.toml Cargo.lock build.rs src examples vendor; do
  [[ -e "$engine_root/$path" ]] || die "missing $engine_root/$path"
  engine_sources+=("$engine_root/$path")
done
native_sources=()
for path in native/windows-capture native/windows-nvenc native/windows-decoder native/windows-input native/vnc; do
  [[ -d "$engine_root/$path" ]] || die "missing $engine_root/$path"
  native_sources+=("$engine_root/$path")
done
bridge_sources=()
for path in Cargo.toml Cargo.lock UPSTREAM.txt UPSTREAM.lock build.rs src include patches build-windows.ps1; do
  [[ -e "$bridge_dir/$path" ]] || die "missing $bridge_dir/$path"
  bridge_sources+=("$bridge_dir/$path")
done

remote_flutter_root="$(windows_path REMOTE_FLUTTER_ROOT "${REMOTE_FLUTTER_ROOT:-}")"
remote_vs_root="$(windows_path REMOTE_VS_ROOT "${REMOTE_VS_ROOT:-}")"
remote_cmake="$(windows_path REMOTE_CMAKE "${REMOTE_CMAKE:-}")"
remote_cmake_toolchain_file="$(windows_path REMOTE_CMAKE_TOOLCHAIN_FILE "${REMOTE_CMAKE_TOOLCHAIN_FILE:-}")"
remote_libvpx_prefix="$(windows_path REMOTE_LIBVPX_PREFIX "${REMOTE_LIBVPX_PREFIX:-}")"
remote_rust_toolchain="${REMOTE_RUST_TOOLCHAIN:-1.95-x86_64-pc-windows-msvc}"
[[ "$remote_rust_toolchain" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die \
  "REMOTE_RUST_TOOLCHAIN must be a rustup toolchain name without command metacharacters (do not prefix it with +)"
if [[ -n "$remote_http_proxy" ]]; then
  [[ "$remote_http_proxy" =~ ^https?://[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}/?$ ]] || die \
    "REMOTE_HTTP_PROXY must be http(s)://host:port without credentials or command metacharacters"
fi

step "Resolving $remote_host"
# Every command below names cmd.exe, which only means anything if the host's
# login shell is cmd.exe: `echo %OS%` answers with the literal when it is not.
login_probe="$(ssh "$remote_host" 'echo %OS%' 2>/dev/null | tr -d '\r\n' || true)"
case "$login_probe" in
  *Windows_NT*) ;;
  *) die "ssh to $remote_host did not answer as cmd.exe ('$login_probe'): set the host's OpenSSH DefaultShell to cmd.exe" ;;
esac
if ! remote_home="$(remote 'echo %USERPROFILE%' | tr -d '\r\n')"; then
  die "cannot reach $remote_host over ssh"
fi
remote_home="$(windows_path USERPROFILE "$remote_home")"
# The copied client carries no .git: the host must support standalone git apply
# before staging any source. Its path is a transport prerequisite, not a SDK choice.
remote "git --version" >/dev/null 2>&1 || die \
  "$remote_host has no git on PATH: the recorded client patches require git apply"
# Only this layout resolves the bridge's ../.. engine dependency. The root and
# provisioned deps/ may preexist; source and output subtrees must be fresh.
remote_root="$(windows_path REMOTE_ROOT "${REMOTE_ROOT:-$remote_home/rd-sync}")"
case "$remote_root" in
  *" "* | *'('* | *')'* | *"'"* | *'['* | *']'* | *'{'* | *'}'*)
    die "the remote root '$remote_root' contains spaces or scp shell/path delimiters: set REMOTE_ROOT to a plain staging path" ;;
esac
remote_client="$remote_root/client"
remote_engine="$remote_root/engine"
remote_bridge="$remote_engine/native/frb"
remote_patch="$remote_bridge/patches/official-client-cpu-rgba.patch"
remote_account_patch="$remote_bridge/patches/official-client-account-safety.patch"
remote_flutter_lock_patch="$remote_bridge/patches/official-client-flutter-lock.patch"
remote_lan_patch="$remote_bridge/patches/official-client-lan-actions.patch"
remote_scope_patch="$remote_bridge/patches/official-client-product-scope.patch"
remote_host_patch="$remote_bridge/patches/official-client-host-control.patch"
remote_engine_dll="$remote_bridge/target/x86_64-pc-windows-msvc/release/rd_engine_flutter.dll"
remote_driver="$remote_root/build-windows.ps1"
remote_bundle="$remote_client/build/windows/x64/runner/Release"
remote_bundle_dll="$remote_bundle/librustdesk.dll"
printf -v driver_arguments '%s' \
  "-ClientDirectory \"$remote_client\" " \
  "-BridgeDirectory \"$remote_bridge\" " \
  "-FlutterRoot \"$remote_flutter_root\" " \
  "-RustToolchain \"$remote_rust_toolchain\" " \
  "-VisualStudioRoot \"$remote_vs_root\" " \
  "-CMakePath \"$remote_cmake\" " \
  "-CMakeToolchainFile \"$remote_cmake_toolchain_file\" " \
  "-LibvpxPrefix \"$remote_libvpx_prefix\" " \
  "-EngineDll \"$remote_engine_dll\""
echo "    tree: $remote_root"

step "Requiring fresh client and engine subtrees"
for subtree in "$remote_client" "$remote_engine"; do
  remote "if exist \"$subtree\" exit /b 1" || die \
    "$subtree already exists or cannot be checked on $remote_host: choose a fresh staging root; existing sources, logs and artifacts are never deleted"
done

step "Preparing only the remote root and verified build driver"
remote "if not exist \"$remote_root/.\" mkdir \"$remote_root\"" || die \
  "cannot prepare $remote_root on $remote_host"
scp "$build_driver" "$remote_host:$remote_root/"

step "Preflighting the selected Windows tools and native dependencies"
# The driver must validate the SDKs, MSVC/CMake and pinned libvpx/Zlib install
# without reading, creating or modifying the still-absent client/engine trees.
run_stage preflight || die \
  "Windows build preflight failed; no client or engine sources were copied; $remote_root is retained"

step "Creating fresh remote source subtrees (nothing is deleted)"
# Plain mkdir, not an overlay: fail if another run created either subtree while
# preflight was in progress. Failed staging/builds remain for inspection.
remote "mkdir \"$remote_client\"" || die "cannot create fresh $remote_client on $remote_host"
remote "mkdir \"$remote_engine\"" || die "cannot create fresh $remote_engine on $remote_host"
# scp creates each source's basename, but not its destination's parents.
remote "mkdir \"$remote_client/windows/flutter\"" || die \
  "cannot create $remote_client/windows/flutter on $remote_host"
remote "mkdir \"$remote_bridge\"" || die \
  "cannot create $remote_bridge on $remote_host"

step "Copying the client tree to $remote_client"
# scp drops a source into the destination directory under its basename: it does
# not rebuild the source's parent directories. So each call below names the
# destination directory that mirrors the sources it carries.
# Only the pristine Flutter CMake source travels: pub get on Windows regenerates
# registrants, generated_plugins.cmake and ephemeral links. No host-local plugin
# cache, generated configuration or previous build output is copied.
scp -r "$client_dir/pubspec.yaml" "$client_dir/pubspec.lock" \
  "$client_dir/analysis_options.yaml" "$client_dir/.metadata" "$client_dir/lib" \
  "$client_dir/assets" "$remote_host:$remote_client/"
scp -r "$client_dir/windows/.gitignore" "$client_dir/windows/CMakeLists.txt" \
  "$client_dir/windows/runner" "$remote_host:$remote_client/windows/"
scp "$client_dir/windows/flutter/CMakeLists.txt" "$remote_host:$remote_client/windows/flutter/"

step "Copying the engine to $remote_engine"
# Include every source-only input named by the shared engine and its patched
# dependencies. No target directory or historical packaged library is copied.
scp -r "${engine_sources[@]}" "$remote_host:$remote_engine/"
scp -r "${native_sources[@]}" "$remote_host:$remote_engine/native/"

step "Copying the bridge to $remote_bridge"
# The bridge workspace depends on the shared engine two directories above.
# Headers, the build driver and all recorded client patches travel with the
# generated Rust source. No cached targets or historical libraries are copied.
scp -r "${bridge_sources[@]}" "$remote_host:$remote_bridge/"

step "Applying recorded render, account, LAN, SDK-lock, product-scope and host-control patches"
# Fresh upstream files receive every required adaptation, fail-closed. The local
# official checkout, its original lock and its dependency declarations stay intact.
# Preserve the checked LF bytes despite Git-for-Windows' ambient autocrlf setting.
# This is per command, not a change to the host's Git configuration.
for patch in "$remote_patch" "$remote_account_patch" "$remote_flutter_lock_patch" "$remote_lan_patch" "$remote_scope_patch" "$remote_host_patch"; do
  remote "if not exist \"$patch\" exit /b 1" || die \
    "the recorded client patch did not reach $patch on $remote_host"
  remote "git -c core.autocrlf=false -c core.eol=lf -C \"$remote_client\" apply --check \"$patch\"" || die \
    "the recorded patch $patch does not apply to $remote_client on $remote_host"
  remote "git -c core.autocrlf=false -c core.eol=lf -C \"$remote_client\" apply \"$patch\"" || die \
    "applying $patch to $remote_client failed on $remote_host"
done

step "Building the fresh engine bridge with the selected Rust/MSVC toolchain"
run_stage kernel || die \
  "Windows kernel build failed; staged sources and build artifacts remain at $remote_root"

step "Checking the engine dll"
remote "if not exist \"$remote_engine_dll\" exit /b 1" || die \
  "no engine dll at $remote_engine_dll on $remote_host"

step "Building the private client with enforced pub resolution and VS2022 CMake"
run_stage client || die \
  "Windows client CMake/Flutter assemble/INSTALL failed; staged sources and build artifacts remain at $remote_root"

step "Checking the private Release bundle"
remote "if not exist \"$remote_bundle/rustdesk.exe\" exit /b 1" || die \
  "no compiled client at $remote_bundle/rustdesk.exe: see the driver output"
remote "if not exist \"$remote_bundle_dll\" exit /b 1" || die \
  "no bundled librustdesk.dll at $remote_bundle_dll: see the driver output"

step "Comparing digests"
engine_sha="$(remote_sha256 "$remote_engine_dll")"
bundle_sha="$(remote_sha256 "$remote_bundle_dll")"
[[ -n "$engine_sha" ]] || die "could not hash $remote_engine_dll on $remote_host"
[[ -n "$bundle_sha" ]] || die "could not hash $remote_bundle_dll on $remote_host"
printf '    engine   dll %s\n' "$remote_engine_dll"
printf '                 %s\n' "$engine_sha"
printf '    bundled dll %s\n' "$remote_bundle_dll"
printf '                 %s\n' "$bundle_sha"
[[ "$engine_sha" == "$bundle_sha" ]] || die \
  "the bundled librustdesk.dll is not the engine's dll"

printf '\nprivate bundle: %s\ncompiled executable (not launched): %s/rustdesk.exe\n' "$remote_bundle" "$remote_bundle"
