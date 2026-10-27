#!/usr/bin/env bash
# Generate the native and Dart halves together; this is not a Flutter app build.
#
# CI byte-compares both halves against the committed bindings, so the generation
# environment is part of the contract: the generator and the Dart SDK are pinned
# in native/frb/UPSTREAM.lock and enforced here, and `dart pub get` may not
# re-resolve the committed package graph.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="$crate_dir/UPSTREAM.lock"
codegen="${FRB_CODEGEN:-flutter_rust_bridge_codegen}"

die() { printf '%s\n' "$*" >&2; exit 1; }
lock_field() {
  [[ -f "$lock" ]] || die 'missing native/frb/UPSTREAM.lock: it pins the generator and the Dart SDK this half must be generated with'
  sed -n "s/^$1: //p" "$lock" | sed -n '1p'
}
if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die 'sha256sum or shasum is required to prove dart pub get kept the committed resolution'
fi

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf '%s\n' \
    'Usage: bash native/frb/generate-bindings.sh' \
    'Requires: the flutter_rust_bridge_codegen and Dart SDK versions pinned in' \
    'native/frb/UPSTREAM.lock (Generator, Dart SDK), plus libclang.' \
    'FRB_CODEGEN selects the generator; LLVM_PATH optionally selects libclang.' \
    'Outputs: native/frb/src/bridge_generated*.rs and native/frb/dart/lib/generated_bridge*.dart.' \
    'Fails if the generator or the Dart SDK differs from the pin, or if dart pub get' \
    're-resolves native/frb/dart/pubspec.lock.'
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo 'Unexpected arguments; use --help for usage.' >&2
  exit 2
fi
expected_codegen="$(lock_field Generator)"
expected_dart="$(lock_field 'Dart SDK')"
[[ -n "$expected_codegen" ]] || die 'native/frb/UPSTREAM.lock records no Generator pin'
[[ -n "$expected_dart" ]] || die 'native/frb/UPSTREAM.lock records no Dart SDK pin'
actual_version="$("$codegen" --version)"
if [[ "$actual_version" != "$expected_codegen" ]]; then
  printf 'Expected %s (native/frb/UPSTREAM.lock), got: %s\n' "$expected_codegen" "$actual_version" >&2
  exit 1
fi
command -v dart >/dev/null || die \
  "dart is required: the pinned official consumer SDK is Flutter 3.24.5 (Dart $expected_dart), see native/frb/CLIENT_SURFACE.md"
# `dart --version` writes to stderr, as `Dart SDK version: 3.5.4 (stable) (...)`.
actual_dart="$(dart --version 2>&1 | sed -n 's/^Dart SDK version: \([0-9][0-9.]*\).*/\1/p' | sed -n '1p')"
[[ -n "$actual_dart" ]] || die 'could not read the Dart SDK version from `dart --version`'
if [[ "$actual_dart" != "$expected_dart" ]]; then
  printf 'Expected Dart SDK %s (native/frb/UPSTREAM.lock), got %s: another SDK reformats the Dart half and re-resolves its dependencies, so both halves must be regenerated with the pinned SDK\n' \
    "$expected_dart" "$actual_dart" >&2
  exit 1
fi
dart_lockfile="$crate_dir/dart/pubspec.lock"
[[ -f "$dart_lockfile" ]] || die \
  'missing native/frb/dart/pubspec.lock: the resolved package graph is a generation input, not a side effect'
dart_lock_before="$(hash_file "$dart_lockfile")"
mkdir -p "$crate_dir/dart/lib"
(
  cd "$crate_dir/dart"
  dart pub get
)
dart_lock_after="$(hash_file "$dart_lockfile")"
if [[ "$dart_lock_before" != "$dart_lock_after" ]]; then
  printf 'dart pub get re-resolved native/frb/dart/pubspec.lock under Dart %s: the Dart half would no longer match the committed resolution; regenerate with the pinned SDK or commit the new resolution together with both halves\n' \
    "$actual_dart" >&2
  exit 1
fi
args=(
  --skip-deps-check
  --rust-input "$crate_dir/src/client_compat.rs"
  --rust-crate-dir "$crate_dir"
  --rust-output "$crate_dir/src/bridge_generated.rs"
  --dart-root "$crate_dir/dart"
  --dart-output "$crate_dir/dart/lib/generated_bridge.dart"
  --class-name Rustdesk
  --skip-add-mod-to-lib
)
if [[ -n "${LLVM_PATH:-}" ]]; then
  args+=(--llvm-path "$LLVM_PATH")
fi
if [[ "$(uname -s)" == Darwin ]]; then
  args+=("--llvm-compiler-opts=--sysroot=$(xcrun --sdk macosx --show-sdk-path)")
fi
# build_runner is intentionally enabled: EventToUI requires its Freezed part.
"$codegen" "${args[@]}"
for binding in src/bridge_generated.rs src/bridge_generated.io.rs \
               dart/lib/generated_bridge.dart dart/lib/generated_bridge.freezed.dart; do
  [[ -s "$crate_dir/$binding" ]] || die "Generator did not produce $binding"
done
printf 'generated with %s and Dart SDK %s\n' "$actual_version" "$actual_dart"
