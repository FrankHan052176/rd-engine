#!/usr/bin/env bash
#
# Fail-closed provenance verification for the native sources the non-HarmonyOS
# kernel is built from.
#
# native/frb/UPSTREAM.lock records, for the required source trees, every
# source file with its SHA-256 plus the upstream/generator/runtime versions those
# sources claim. Verification fails on a missing file, an unexpected file, a
# changed digest, or any version that disagrees with the file that owns it:
# nothing is repaired silently and no warning is downgraded to a success.
# Requires Python 3.11+ for standard-library TOML parsing of the selected owners.
#
# Usage:
#   bash scripts/verify-native-provenance.sh                   # verify this working tree
#   bash scripts/verify-native-provenance.sh --require-tracked # CI: every locked path must be tracked
#   bash scripts/verify-native-provenance.sh --update          # rewrite the lock from this tree
#   bash scripts/verify-native-provenance.sh --update --dart-sdk 3.5.4
#   bash scripts/verify-native-provenance.sh --official-client-tree /path/to/rustdesk
#   bash scripts/verify-native-provenance.sh --update --official-client-tree /path/to/rustdesk
#
# Scope:
#   - The required tree list and the excluded build-product directories are fixed
#     here, not read from the lock: a tampered lock can neither widen nor narrow
#     what is verified, and it can never drop a tree from its own scope.
#   - Only sources are locked. Cargo's target/, Dart's .dart_tool/ and build/,
#     and any nested .git/ are excluded by directory name, so a lock never
#     records build products and CI never needs them.
#   - The lock file itself is excluded: it cannot hash itself.
#   - Version fields are cross-checked against the provenance files that own
#     them (native/frb/UPSTREAM.txt, native/vnc/ORIGIN.txt,
#     vendor/ironrdp-pdu/UPSTREAM.txt, the FRB crate and Dart manifests, the
#     generated binding headers, the three Cargo workspaces that must select the
#     vendored crate) instead of being trusted on their own.
#   - Official product/package versions come from native/frb/UPSTREAM.txt. With
#     --official-client-tree, compare the exact Commit's local Git objects, never
#     dirty working-tree manifests. A changed tuple needs this check before an
#     update; an unchanged tuple can be refreshed offline without a checkout.
#
# What this does not decide:
#   - It pins the frozen FRB surface (native/frb/src/client_compat.rs and the
#     generated halves) to exact bytes, so a run cannot silently ship a modified
#     capability surface. It does not assert any capability value: the D3 gate
#     (GPU/hwcodec/texture advertisements stay false until a real renderer and
#     runtime verification exist) is owned by that surface and by the Windows
#     build, not by this script.
#   - It says nothing about whether the pinned sources compile or run. Windows
#     build and runtime evidence stay with the Windows workflow and its V5/V6
#     authorization.
#
# After an intentional source change under a locked tree, refresh the lock and
# commit it with the change:
#
#   bash scripts/verify-native-provenance.sh --update
#
set -euo pipefail
LC_ALL=C
export LC_ALL

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_rel='native/frb/UPSTREAM.lock'
lock="$repo_root/$lock_rel"

# Fixed scope. Keep in sync with the workflow's required-source list.
trees=(native/vnc native/windows-input native/windows-decoder native/frb vendor/ironrdp-pdu vendor/rustdesk vendor/libsodium-sys src/official_account vendor/secret-service src/lan vendor/default-net src/host src/host.rs src/authentication.rs src/session.rs src/platform/windows_input.rs)
trees_field='native/vnc native/windows-input native/windows-decoder native/frb vendor/ironrdp-pdu vendor/rustdesk vendor/libsodium-sys src/official_account vendor/secret-service src/lan vendor/default-net src/host src/host.rs src/authentication.rs src/session.rs src/platform/windows_input.rs'
lock_schema='rd-engine-native-provenance 1'
tree_paths=()
for tree in "${trees[@]}"; do
  tree_paths+=("$repo_root/$tree")
done

upstream_txt="$repo_root/native/frb/UPSTREAM.txt"
vnc_origin="$repo_root/native/vnc/ORIGIN.txt"
vendor_upstream="$repo_root/vendor/ironrdp-pdu/UPSTREAM.txt"
frb_cargo="$repo_root/native/frb/Cargo.toml"
frb_dart_pubspec="$repo_root/native/frb/dart/pubspec.yaml"
bridge_rs="$repo_root/native/frb/src/bridge_generated.rs"
bridge_dart="$repo_root/native/frb/dart/lib/generated_bridge.dart"
vendored_manifest="$repo_root/vendor/ironrdp-pdu/Cargo.toml"

usage() {
  cat <<'USAGE'
Usage: bash scripts/verify-native-provenance.sh [--verify | --update [--dart-sdk <version>]]
                                                [--require-tracked]
                                                [--official-client-tree <checkout-root>]

  --verify            verify this working tree against native/frb/UPSTREAM.lock (default)
  --require-tracked   additionally require every locked path to be tracked by git,
                      so a clean clone can reproduce the tree (used by CI)
  --update            rewrite native/frb/UPSTREAM.lock from this working tree
  --dart-sdk <value>  set the Dart SDK pin when writing a lock for the first time
  --official-client-tree <checkout-root>
                      validate product/package versions against the pinned Commit's
                      Cargo.toml and flutter/pubspec.yaml Git objects (no network);
                      required on --update when the old lock's tuple differs or is absent
USAGE
}

mode='verify'
require_tracked=0
dart_sdk_override=''
official_client_tree=''
while [ $# -gt 0 ]; do
  case "$1" in
    --verify) mode='verify' ;;
    --update) mode='update' ;;
    --require-tracked) require_tracked=1 ;;
    --dart-sdk)
      shift
      [ $# -gt 0 ] || { printf 'provenance: --dart-sdk needs a value\n' >&2; exit 2; }
      dart_sdk_override="$1"
      ;;
    --official-client-tree)
      shift
      [ $# -gt 0 ] && [ -n "$1" ] || { printf 'provenance: --official-client-tree needs a checkout root\n' >&2; exit 2; }
      official_client_tree="$1"
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      printf 'provenance: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

problems=()
problem_count=0
problem() {
  problems+=("$1")
  problem_count=$((problem_count + 1))
}
die() { printf 'provenance: %s\n' "$1" >&2; exit 1; }

# First-match accessor. check_official_versions rejects duplicate source/lock
# metadata before these accessors are used for either verification or update.
field() {
  [ -f "$1" ] || die "required provenance file is missing: ${1#"$repo_root/"}"
  sed -n "s/^$2: //p" "$1" | sed -n '1p'
}
first_token() { printf '%s' "$1" | cut -d' ' -f1; }
lock_field() { field "$lock" "$1"; }

# Keep the offline build.rs tuple grammar in sync: lowercase SHA-1, numeric
# X.Y.Z product and matching X.Y.Z+N Flutter package, no leading zeros.
check_official_versions() {
  python3 - "$upstream_txt" "$lock" "$mode" "$official_client_tree" <<'PY'
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    raise SystemExit('provenance: Python 3.11+ is required for Cargo TOML validation')

source_path, lock_path = map(Path, sys.argv[1:3])
mode, official_client_tree = sys.argv[3:5]
product_key = 'Official product version'
flutter_key = 'Official Flutter package version'
tuple_keys = {'Commit', 'Upstream commit', product_key, flutter_key}
number = r'(?:0|[1-9][0-9]*)'
product_pattern = rf'{number}\.{number}\.{number}'
flutter_pattern = rf'{product_pattern}\+{number}'


def fail(message):
    raise SystemExit(f'provenance: {message}')


def read_metadata(path):
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except (OSError, UnicodeError):
        fail(f'cannot read {path.name} metadata')
    fields = {}
    for line in lines:
        raw_key, separator, _ = line.partition(':')
        key = raw_key.strip()
        if not separator or not re.fullmatch(r'[A-Za-z][A-Za-z0-9 -]*', key):
            continue
        # Indented prose is not metadata; a disguised tuple field still fails.
        if line[0].isspace() and key not in tuple_keys:
            continue
        if key in fields:
            fail(f'{path.name} repeats metadata field {key!r}')
        fields[key] = line
    return fields


def required_field(fields, key, path):
    line = fields.get(key)
    if line is None:
        fail(f'{path.name} is missing {key!r}')
    prefix = f'{key}: '
    if not line.startswith(prefix):
        fail(f'{path.name} requires {key!r} in exact "Key: value" form')
    value = line[len(prefix):]
    if not value or value != value.strip():
        fail(f'{path.name} has a malformed {key!r}')
    return value


def revision_field(fields, key, path):
    revision = required_field(fields, key, path)
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        fail(f'{path.name} {key!r} must be exactly 40 lowercase hexadecimal characters')
    return revision


def official_tuple(fields, revision_key, path):
    revision = revision_field(fields, revision_key, path)
    product = required_field(fields, product_key, path)
    flutter = required_field(fields, flutter_key, path)
    if not re.fullmatch(product_pattern, product):
        fail(f'{path.name} {product_key!r} must be numeric X.Y.Z without leading zeros')
    if not re.fullmatch(flutter_pattern, flutter):
        fail(f'{path.name} {flutter_key!r} must be numeric X.Y.Z+N without leading zeros')
    if flutter.split('+', 1)[0] != product:
        fail(f'{path.name} official product and Flutter package versions disagree')
    return revision, product, flutter


source_tuple = official_tuple(read_metadata(source_path), 'Commit', source_path)
locked_tuple = None
if lock_path.exists():
    locked_fields = read_metadata(lock_path)
    if mode == 'verify' or product_key in locked_fields or flutter_key in locked_fields:
        locked_tuple = official_tuple(locked_fields, 'Upstream commit', lock_path)
    else:
        # A legacy lock lacks both version fields. It can only migrate with an
        # exact Git-object check; partial or malformed new tuples are refused.
        revision_field(locked_fields, 'Upstream commit', lock_path)
elif mode == 'verify':
    fail('no provenance lock at native/frb/UPSTREAM.lock: create it with --update')

if mode == 'verify' and source_tuple != locked_tuple:
    fail('official revision/product/Flutter tuple in UPSTREAM.lock disagrees with UPSTREAM.txt')
if mode == 'update' and source_tuple != locked_tuple and not official_client_tree:
    fail('a new or changed official revision/product/Flutter tuple requires --official-client-tree before --update')

if official_client_tree:
    try:
        checkout = Path(official_client_tree).resolve(strict=True)
    except (OSError, RuntimeError):
        fail('--official-client-tree is not an available checkout root')
    git_env = os.environ.copy()
    # A replacement ref or partial-clone fetch must not substitute for the
    # pinned, locally present Git objects. Do not expose Git stderr/remote URLs.
    git_env['GIT_NO_REPLACE_OBJECTS'] = '1'
    git_env['GIT_NO_LAZY_FETCH'] = '1'
    git_env['GIT_TERMINAL_PROMPT'] = '0'
    git_env['GIT_ALLOW_PROTOCOL'] = ''

    def git(*args):
        try:
            return subprocess.run(
                ['git', '--no-replace-objects', '-C', str(checkout), *args],
                env=git_env, check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, encoding='utf-8',
            ).stdout
        except (OSError, subprocess.CalledProcessError, UnicodeError):
            fail(f'cannot read the required local official Git objects ({args[0]})')

    if Path(git('rev-parse', '--show-toplevel').strip()).resolve() != checkout:
        fail('--official-client-tree must name the Git checkout root')
    revision, product, flutter = source_tuple
    if git('cat-file', '-t', revision).strip() != 'commit':
        fail('UPSTREAM.txt Commit does not identify a local Git commit object')
    try:
        cargo = tomllib.loads(git('cat-file', 'blob', f'{revision}:Cargo.toml'))
    except tomllib.TOMLDecodeError:
        fail('the pinned Cargo.toml Git object is not valid TOML')
    package = cargo.get('package')
    if not isinstance(package, dict) or package.get('version') != product:
        fail(f'{revision}:Cargo.toml [package].version disagrees with {product_key!r}')

    pubspec = git('cat-file', 'blob', f'{revision}:flutter/pubspec.yaml')
    version_key = r'''(?:version|"version"|'version')'''
    version_lines = [line for line in pubspec.splitlines()
                     if re.match(version_key + r'[ \t]*:', line)]
    if len(version_lines) != 1:
        fail('the pinned Flutter pubspec must have exactly one top-level version field')
    match = re.fullmatch(
        version_key + rf'''[ \t]*:[ \t]*(?P<quote>["']?)(?P<version>{flutter_pattern})(?P=quote)(?:[ \t]+#.*)?[ \t]*''',
        version_lines[0],
    )
    if not match:
        fail('the pinned Flutter pubspec version must be a numeric X.Y.Z+N scalar')
    if match.group('version') != flutter:
        fail(f'{revision}:flutter/pubspec.yaml version disagrees with {flutter_key!r}')
    print(f'provenance: official Git objects at {revision} declare product {product}, Flutter {flutter}')
PY
}

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die 'sha256sum or shasum is required to verify the lock'
fi

list_files() {
  find "${tree_paths[@]}" \
    -type d \( -name target -o -name .dart_tool -o -name build -o -name .git \) -prune \
    -o -type f -print | sort
}

# `<sha256>  <path>` lines, sha256sum-compatible, repository-relative paths,
# byte-order sorted, the lock file and build products excluded.
manifest() {
  while IFS= read -r path; do
    rel="${path#"$repo_root/"}"
    [ "$rel" = "$lock_rel" ] && continue
    printf '%s  %s\n' "$(hash_file "$path")" "$rel"
  done < <(list_files)
}

lock_header() {
  cat <<'LOCK_HEADER'
# native/frb/UPSTREAM.lock
#
# Fail-closed provenance lock for the native and official library source trees the non-HarmonyOS
# kernel is built from. Written and verified by
# scripts/verify-native-provenance.sh; refresh it with `--update` after an
# intentional source change and commit it with that change.
#
# Format: `Key: value` metadata lines, then one `<sha256>  <path>` line per
# locked source file (sha256sum order, repository-relative paths) sorted by path.
# Build products (target/, .dart_tool/, build/) and this file itself are never
# locked. Metadata values are cross-checked against native/frb/UPSTREAM.txt,
# native/vnc/ORIGIN.txt, vendor/ironrdp-pdu/UPSTREAM.txt, the FRB manifests and
# the generated binding headers; a mismatch, a missing file, an extra file or a
# changed digest is a non-zero exit.
#
# `Generator`, `Dart SDK` and `Flutter SDK` are the generation environment for
# the paired bindings: the codegen version is enforced by
# native/frb/generate-bindings.sh (which also enforces the Dart SDK), and
# native/frb/CLIENT_SURFACE.md names Flutter 3.24.5 (Dart 3.5.4) as the pinned
# official consumer SDK. Change `Dart SDK` only together with a regeneration of
# both binding halves under the new SDK.
#
# `Official product version` and `Official Flutter package version` identify the
# pinned official consumer, not engine/bridge crate versions or feature parity.
# They mirror UPSTREAM.txt; changing that revision/version tuple on --update
# requires --official-client-tree to check the exact owning Git objects.
LOCK_HEADER
}

metadata() {
  local upstream_commit repo generator rust_runtime dart_runtime flutter_sdk dart_sdk
  local official_product official_flutter
  local vcpkg_url vcpkg_commit rdev_url rdev_commit vnc_url vnc_release vnc_commit vendored

  upstream_commit="$(field "$upstream_txt" 'Commit')"
  official_product="$(field "$upstream_txt" 'Official product version')"
  official_flutter="$(field "$upstream_txt" 'Official Flutter package version')"
  repo="$(field "$upstream_txt" 'Repository')"
  generator="$(field "$upstream_txt" 'Generator')"
  rust_runtime="$(field "$upstream_txt" 'Rust runtime')"
  dart_runtime="$(field "$upstream_txt" 'Dart runtime')"
  flutter_sdk="$(sed -n 's/^Default official consumer SDK: Flutter \([0-9][0-9.]*\).*/\1/p' "$upstream_txt" | sed -n '1p')"
  vcpkg_url="$(field "$upstream_txt" 'Windows dependency toolchain')"
  vcpkg_commit="$(first_token "$(field "$upstream_txt" 'Windows dependency commit')")"
  rdev_url="$(field "$upstream_txt" 'Keyboard dependency')"
  rdev_commit="$(first_token "$(field "$upstream_txt" 'Keyboard dependency commit')")"
  vnc_url="$(field "$vnc_origin" 'Upstream')"
  vnc_release="$(field "$vnc_origin" 'Release')"
  vnc_commit="$(first_token "$(field "$vnc_origin" 'Commit')")"
  vendored="$(field "$vendor_upstream" 'Version')"

  dart_sdk=''
  if [ -n "$dart_sdk_override" ]; then
    dart_sdk="$dart_sdk_override"
  elif [ -f "$lock" ]; then
    dart_sdk="$(sed -n 's/^Dart SDK: //p' "$lock" | sed -n '1p')"
  fi
  [ -n "$dart_sdk" ] || die \
    'no Dart SDK pin: pass --dart-sdk <version> once (the pinned official consumer SDK is Flutter 3.24.5 / Dart 3.5.4, see native/frb/CLIENT_SURFACE.md)'

  for value in "$upstream_commit" "$official_product" "$official_flutter" "$repo" "$generator" "$rust_runtime" "$dart_runtime" \
    "$flutter_sdk" "$vcpkg_url" "$vcpkg_commit" "$rdev_url" "$rdev_commit" \
    "$vnc_url" "$vnc_release" "$vnc_commit" "$vendored"; do
    [ -n "$value" ] || die 'a provenance file no longer carries a field this lock derives; refusing to write an incomplete lock'
  done

  printf '%s\n' \
    "Lock: $lock_schema" \
    "Upstream: $repo" \
    "Upstream commit: $upstream_commit" \
    "Official product version: $official_product" \
    "Official Flutter package version: $official_flutter" \
    "Generator: $generator" \
    "Rust runtime: $rust_runtime" \
    "Dart runtime: $dart_runtime" \
    "Flutter SDK: $flutter_sdk" \
    "Dart SDK: $dart_sdk" \
    "Windows dependency toolchain: $vcpkg_url" \
    "Windows dependency toolchain commit: $vcpkg_commit" \
    "Keyboard dependency: $rdev_url" \
    "Keyboard dependency commit: $rdev_commit" \
    "VNC upstream: $vnc_url" \
    "VNC release: $vnc_release" \
    "VNC commit: $vnc_commit" \
    "Vendored crate: $vendored" \
    "Trees: $trees_field"
}

check_tracked() {
  command -v git >/dev/null 2>&1 || die 'git is required for --require-tracked'
  local tracked untracked path
  tracked="$(git -C "$repo_root" ls-files -- "${trees[@]}")" || die 'git ls-files failed'
  untracked=''
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    # A here-string, not a pipe: with pipefail, grep -q exiting at an early match
    # makes printf die of SIGPIPE and falsely reports a tracked path as missing.
    grep -Fxq -- "$path" <<< "$tracked" || untracked="$untracked $path"
  done < <(sed -n 's/^[0-9a-f]\{64\}  //p' "$lock")
  [ -z "$untracked" ] || problem \
    "locked paths are not tracked by git, so a clean clone cannot reproduce them:$untracked"
}

report_mismatches() {
  local header="$1" text="$2" limit
  limit="$(printf '%s\n' "$text" | sed -n '1,10p')"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    problem "$header ${line#*  }"
  done <<< "$limit"
}

verify() {
  [ -f "$lock" ] || die "no provenance lock at $lock_rel: create it with --update"
  local key value expected

  while IFS= read -r key; do
    value="$(lock_field "$key")"
    [ -n "$value" ] || problem "the lock is missing a value for '$key'"
  done <<'KEYS'
Lock
Upstream
Upstream commit
Official product version
Official Flutter package version
Generator
Rust runtime
Dart runtime
Flutter SDK
Dart SDK
Windows dependency toolchain
Windows dependency toolchain commit
Keyboard dependency
Keyboard dependency commit
VNC upstream
VNC release
VNC commit
Vendored crate
Trees
Files
KEYS

  [ "$(lock_field Lock)" = "$lock_schema" ] || problem \
    "lock schema is '$(lock_field Lock)', expected '$lock_schema'"
  [ "$(lock_field Trees)" = "$trees_field" ] || problem \
    "lock Trees is '$(lock_field Trees)', expected '$trees_field'"

  # Check required source paths directly so a missing path names itself even
  # when the lock already lists its files; paths may be directories or files.
  for tree in "${trees[@]}"; do
    [ -e "$repo_root/$tree" ] || problem "required native source path is missing: $tree"
  done

  # Upstream/generator identity, against the file that owns each value.
  expected="$(field "$upstream_txt" 'Repository')"
  [ "$(lock_field Upstream)" = "$expected" ] || problem \
    "Upstream is '$(lock_field Upstream)', native/frb/UPSTREAM.txt says '$expected'"
  expected="$(first_token "$(field "$upstream_txt" 'Commit')")"
  [ "$(lock_field 'Upstream commit')" = "$expected" ] || problem \
    "Upstream commit is '$(lock_field 'Upstream commit')', native/frb/UPSTREAM.txt says '$expected'"
  case "$expected" in
    *[!0-9a-f]* | '') problem "upstream commit is not a lowercase hex revision: '$expected'" ;;
  esac
  [ ${#expected} -eq 40 ] || problem "upstream commit is not a 40-character revision: '$expected'"

  local generator codegen_version
  generator="$(field "$upstream_txt" 'Generator')"
  [ "$(lock_field Generator)" = "$generator" ] || problem \
    "Generator is '$(lock_field Generator)', native/frb/UPSTREAM.txt says '$generator'"
  codegen_version="${generator##* }"
  case "$generator" in
    'flutter_rust_bridge_codegen '*) ;;
    *) problem "Generator does not name flutter_rust_bridge_codegen: '$generator'" ;;
  esac
  for generated in "$bridge_rs" "$bridge_dart"; do
    grep -Fq "Generated by \`flutter_rust_bridge\`@ $codegen_version." "$generated" || problem \
      "${generated#"$repo_root/"} does not carry the '$codegen_version' generator header"
  done

  local rust_runtime rust_version dart_runtime dart_version
  rust_runtime="$(field "$upstream_txt" 'Rust runtime')"
  [ "$(lock_field 'Rust runtime')" = "$rust_runtime" ] || problem \
    "Rust runtime is '$(lock_field 'Rust runtime')', native/frb/UPSTREAM.txt says '$rust_runtime'"
  rust_version="${rust_runtime##* }"
  grep -Fq "\"=$rust_version\"" "$frb_cargo" || problem \
    "native/frb/Cargo.toml does not pin flutter_rust_bridge to '=$rust_version'"
  dart_runtime="$(field "$upstream_txt" 'Dart runtime')"
  [ "$(lock_field 'Dart runtime')" = "$dart_runtime" ] || problem \
    "Dart runtime is '$(lock_field 'Dart runtime')', native/frb/UPSTREAM.txt says '$dart_runtime'"
  dart_version="${dart_runtime##* }"
  expected="$(sed -n 's/^  flutter_rust_bridge: //p' "$frb_dart_pubspec" | sed -n '1p')"
  [ "$expected" = "$dart_version" ] || problem \
    "native/frb/dart/pubspec.yaml pins flutter_rust_bridge '$expected', native/frb/UPSTREAM.txt says '$dart_version'"

  # Generation environment. The Dart SDK value is enforced against the installed
  # SDK by native/frb/generate-bindings.sh, which is the only place that has Dart.
  expected="$(sed -n 's/^Default official consumer SDK: Flutter \([0-9][0-9.]*\).*/\1/p' "$upstream_txt" | sed -n '1p')"
  [ -n "$expected" ] || problem 'native/frb/UPSTREAM.txt no longer names the pinned official consumer SDK'
  [ "$(lock_field 'Flutter SDK')" = "$expected" ] || problem \
    "Flutter SDK is '$(lock_field 'Flutter SDK')', native/frb/UPSTREAM.txt says '$expected'"
  case "$(lock_field 'Dart SDK')" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) problem "Dart SDK is not a pinned version: '$(lock_field 'Dart SDK')'" ;;
  esac

  local vcpkg_commit rdev_commit
  vcpkg_commit="$(first_token "$(field "$upstream_txt" 'Windows dependency commit')")"
  [ "$(lock_field 'Windows dependency toolchain commit')" = "$vcpkg_commit" ] || problem \
    "Windows dependency toolchain commit is '$(lock_field 'Windows dependency toolchain commit')', native/frb/UPSTREAM.txt says '$vcpkg_commit'"
  rdev_commit="$(first_token "$(field "$upstream_txt" 'Keyboard dependency commit')")"
  [ "$(lock_field 'Keyboard dependency commit')" = "$rdev_commit" ] || problem \
    "Keyboard dependency commit is '$(lock_field 'Keyboard dependency commit')', native/frb/UPSTREAM.txt says '$rdev_commit'"

  # Vendored trees.
  expected="$(field "$vnc_origin" 'Upstream')"
  [ "$(lock_field 'VNC upstream')" = "$expected" ] || problem \
    "VNC upstream is '$(lock_field 'VNC upstream')', native/vnc/ORIGIN.txt says '$expected'"
  expected="$(field "$vnc_origin" 'Release')"
  [ "$(lock_field 'VNC release')" = "$expected" ] || problem \
    "VNC release is '$(lock_field 'VNC release')', native/vnc/ORIGIN.txt says '$expected'"
  expected="$(first_token "$(field "$vnc_origin" 'Commit')")"
  [ "$(lock_field 'VNC commit')" = "$expected" ] || problem \
    "VNC commit is '$(lock_field 'VNC commit')', native/vnc/ORIGIN.txt says '$expected'"
  expected="$(field "$vendor_upstream" 'Version')"
  [ "$(lock_field 'Vendored crate')" = "$expected" ] || problem \
    "Vendored crate is '$(lock_field 'Vendored crate')', vendor/ironrdp-pdu/UPSTREAM.txt says '$expected'"
  expected="$(printf '%s' "$(lock_field 'Vendored crate')" | cut -d' ' -f2)"
  grep -Fq "version = \"$expected\"" "$vendored_manifest" || problem \
    "vendor/ironrdp-pdu/Cargo.toml does not declare version '$expected'"

  # Parse Cargo's effective tables: matching text in an inert metadata table is
  # not evidence that the build selects the shared, hashed source owner.
  if ! python3 - "$repo_root" <<'PY'
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    raise SystemExit('provenance: Python 3.11+ is required for Cargo TOML validation')

root = Path(sys.argv[1])
failed = False
for relative in ('Cargo.toml', 'native/frb/Cargo.toml', 'native/ohos_napi/Cargo.toml'):
    try:
        with (root / relative).open('rb') as source:
            manifest = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f'provenance: cannot parse {relative}: {error}', file=sys.stderr)
        failed = True
        continue
    prefix = '' if relative == 'Cargo.toml' else '../../'
    owners = (
        (manifest.get('patch', {}).get('crates-io', {}), 'ironrdp-pdu', 'vendor/ironrdp-pdu'),
        (manifest.get('patch', {}).get('crates-io', {}), 'libsodium-sys', 'vendor/libsodium-sys'),
        (manifest.get('dependencies', {}), 'base', 'vendor/rustdesk/libs/base'),
        (manifest.get('dependencies', {}), 'hbb_common', 'vendor/rustdesk/libs/hbb_common'),
    )
    for table, package, path in owners:
        if table.get(package) != {'path': prefix + path}:
            print(f'provenance: {relative} must select {package} from {prefix + path} in its owning Cargo table', file=sys.stderr)
            failed = True

with (root / 'Cargo.toml').open('rb') as source:
    engine = tomllib.load(source)
discovery = engine.get('dependencies', {}).get('default-net', {})
if discovery != {'path': 'vendor/default-net', 'version': '=0.14.1'}:
    print('provenance: LAN discovery must select the pinned enumeration-only default-net source owner', file=sys.stderr)
    failed = True
linux_target = 'cfg(all(target_os = "linux", not(target_env = "ohos")))'
secret = engine.get('target', {}).get(linux_target, {}).get('dependencies', {}).get('secret-service', {})
if (secret.get('path') != 'vendor/secret-service' or secret.get('version') != '=5.2.0'
        or secret.get('default-features') is not False
        or secret.get('features') != ['rt-async-io-crypto-rust']
        or secret.get('optional') is not True):
    print('provenance: official account storage must select the pinned no-prompt Secret Service source owner', file=sys.stderr)
    failed = True
for relative in ('native/frb/Cargo.toml', 'native/ohos_napi/Cargo.toml'):
    with (root / relative).open('rb') as source:
        bridge = tomllib.load(source)
    dependency = bridge.get('dependencies', {}).get('rd-engine', {})
    features = dependency.get('features', [])
    if dependency.get('path') != '../..' or ('official-account' in features) != ('/frb/' in relative):
        print(f'provenance: {relative} does not preserve the FRB-only account owner selection', file=sys.stderr)
        failed = True
sys.exit(1 if failed else 0)
PY
  then
    problem 'Cargo manifests do not select the required shared source owners'
  fi


  # Content: exact file set and exact digests.
  local actual locked_lines count
  actual="$(manifest)"
  count="$(printf '%s\n' "$actual" | grep -c . || true)"
  [ "$(lock_field Files)" = "$count" ] || problem \
    "lock records $(lock_field Files) files, this tree has $count"
  locked_lines="$(grep -E '^[0-9a-f]{64}  ' "$lock" || true)"
  [ -n "$locked_lines" ] || problem 'the lock carries no file digests'

  local missing extra
  # Both sides are sorted by whole line before comm: the lock's own order is by
  # path, and comm requires its inputs to be sorted the same way.
  missing="$(comm -23 <(printf '%s\n' "$locked_lines" | sort) <(printf '%s\n' "$actual" | sort))"
  extra="$(comm -13 <(printf '%s\n' "$locked_lines" | sort) <(printf '%s\n' "$actual" | sort))"
  if [ -n "$missing" ]; then
    problem "$(printf '%s\n' "$missing" | grep -c . || true) locked file(s) are missing or changed"
    report_mismatches 'missing or changed:' "$missing"
  fi
  if [ -n "$extra" ]; then
    problem "$(printf '%s\n' "$extra" | grep -c . || true) file(s) under a locked tree are not in the lock"
    report_mismatches 'not in the lock:' "$extra"
  fi

  [ "$require_tracked" = 0 ] || check_tracked

  if [ "$problem_count" -gt 0 ]; then
    printf 'provenance: %s problem(s) against %s\n' "$problem_count" "$lock_rel" >&2
    for entry in ${problems[@]+"${problems[@]}"}; do
      printf '  - %s\n' "$entry" >&2
    done
    printf 'provenance: verification failed; refresh the lock only after the source change is intended\n' >&2
    exit 1
  fi
  printf 'provenance: %s files across %s trees verified against %s\n' \
    "$count" "${#trees[@]}" "$lock_rel"
  printf 'provenance: upstream %s, generator %s, Flutter %s, Dart %s\n' \
    "$(lock_field 'Upstream commit')" "$(lock_field Generator)" \
    "$(lock_field 'Flutter SDK')" "$(lock_field 'Dart SDK')"
}

update() {
  local staged manifest_text count
  staged="$(mktemp "${TMPDIR:-/tmp}/rd-engine-upstream-lock.XXXXXX")"
  trap 'rm -f "$staged"' EXIT
  manifest_text="$(manifest)"
  count="$(printf '%s\n' "$manifest_text" | grep -c . || true)"
  {
    lock_header
    metadata
    printf 'Files: %s\n' "$count"
    printf '%s\n' "$manifest_text"
  } >"$staged"
  mv "$staged" "$lock"
  trap - EXIT
  printf 'provenance: wrote %s (%s files)\n' "$lock_rel" "$count"
  printf 'provenance: commit it together with the source change it records\n'
}

# Validate before update creates or replaces anything, including an old lock
# that predates the product/package version fields.
check_official_versions

case "$mode" in
  update) update ;;
  *) verify ;;
esac
