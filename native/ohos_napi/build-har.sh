#!/usr/bin/env bash
# Build only rd-engine's HarmonyOS kernel output. No UI checkout, HAP build,
# signing, installation, or publication is performed here.
set -euo pipefail

release_claim=0
case "${1:-}" in
  "") ;;
  --release-claim) release_claim=1 ;;
  --help|-h)
    printf '%s\n' \
      'Usage: bash native/ohos_napi/build-har.sh [--release-claim]' \
      'Requires: Rust OHOS target, Python 3, Git, and the SDK/native dependencies' \
      'configured by scripts/ohos-env.sh (OHOS_NDK_HOME / OHOS_VCPKG_PREFIX).' \
      'Outputs: target/package.har and target/release-provenance.json in native/ohos_napi.' \
      'Local builds may be dirty and say so; --release-claim requires clean sources.' \
      'HAR_PACKAGE_VERSION optionally versions the staged package without modifying sources.'
    exit 0
    ;;
  *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then
  echo 'Only --release-claim is accepted' >&2
  exit 2
fi

engine_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate_dir="$engine_root/native/ohos_napi"
export PATH="$HOME/.cargo/bin:${OHOS_CLI_HOME:-$HOME/command-line-tools}/bin:$PATH"
# Preserve Cargo's existing cache configuration and NAS guard.
# shellcheck source=../../scripts/ohos-env.sh
source "$engine_root/scripts/ohos-env.sh"

python3 - "$engine_root" "$crate_dir" "$release_claim" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

engine = Path(sys.argv[1]).resolve()
crate = Path(sys.argv[2]).resolve()
release_claim = sys.argv[3] == '1'
target = 'aarch64-unknown-linux-ohos'
source_package = crate / 'package'
package = crate / 'target/har/package'
archive = crate / 'target/package.har'
archive_tmp = crate / 'target/package.har.tmp'
sidecar = crate / 'target/release-provenance.json'
embedded = package / 'release-provenance.json'


def git(*args):
    return subprocess.check_output(['git', '-C', str(engine), *args], text=True).strip()


def dirty():
    return bool(git('status', '--porcelain=v1', '--untracked-files=all'))


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


# Fail before compiling if the checkout or release claim is not genuine.
if Path(git('rev-parse', '--show-toplevel')).resolve() != engine:
    raise SystemExit('rd-engine must be its own Git checkout for engine provenance')
engine_sha = git('rev-parse', 'HEAD')
source_dirty = dirty()
if release_claim and source_dirty:
    raise SystemExit('Refusing release claim: rd-engine has dirty sources')
metadata = json.loads((source_package / 'oh-package.json5').read_text(encoding='utf-8'))
if metadata.get('name') != 'rustdesk-ohrs':
    raise SystemExit('HAR package metadata must name rustdesk-ohrs')
version = os.environ.get('HAR_PACKAGE_VERSION', metadata.get('version', ''))
if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?', version):
    raise SystemExit('HAR package version must be an exact semantic version')
metadata['version'] = version
libcxx = Path(os.environ['OHOS_NDK_HOME']) / 'native/llvm/lib/aarch64-linux-ohos/libc++_shared.so'
if not libcxx.is_file():
    raise SystemExit('SDK libc++_shared.so not found: ' + str(libcxx))

# Cargo determines its own target directory; do not bypass the machine's cache
# guard with a private target-dir override. Locked builds never rewrite sources.
cargo_metadata = json.loads(subprocess.check_output(
    ['cargo', 'metadata', '--no-deps', '--locked', '--format-version=1'], cwd=crate, text=True))
library = Path(cargo_metadata['target_directory']) / target / 'release/librd_engine_native_har.so'
subprocess.run(['cargo', 'build', '--locked', '--release', '--target', target], cwd=crate, check=True)
if not library.is_file():
    raise SystemExit('Cargo did not produce the HarmonyOS NAPI library: ' + str(library))

# Only this ignored staging tree receives generated libraries and provenance.
# Never recreate the historical tracked binary paths inside source_package.
if package.exists():
    shutil.rmtree(package)
shutil.copytree(source_package, package,
                ignore=shutil.ignore_patterns('*.so', 'release-provenance.json'))
write_json(package / 'oh-package.json5', metadata)
libs = package / 'libs/arm64-v8a'
libs.mkdir(parents=True, exist_ok=True)
shutil.copy2(library, libs / library.name)
shutil.copy2(libcxx, libs / libcxx.name)
if git('rev-parse', 'HEAD') != engine_sha:
    raise SystemExit('Refusing provenance: engine HEAD changed during the build')
source_dirty = source_dirty or dirty()
if release_claim and source_dirty:
    raise SystemExit('Refusing release claim: rd-engine became dirty during the build')
provenance = {
    'provenance_version': 2,
    'kind': 'har',
    'engine_repository': 'https://github.com/FrankHan052176/rd-engine',
    'engine_sha': engine_sha,
    'source_dirty': source_dirty,
    'package_name': metadata['name'],
    'package_version': metadata['version'],
    'target': target,
    'library_sha256': sha256(libs / library.name),
    'libcxx_sha256': sha256(libs / libcxx.name),
}
write_json(embedded, provenance)
with tarfile.open(archive_tmp, 'w:gz') as output:
    output.add(package, arcname='package')
os.replace(archive_tmp, archive)
# The HAR cannot contain its own hash. Only the adjacent sidecar adds it.
write_json(sidecar, {**provenance, 'har_sha256': sha256(archive)})
print('HAR: ' + str(archive))
print('Provenance: ' + str(sidecar))
print('Source: ' + engine_sha + (' (dirty local build)' if source_dirty else ' (clean)'))
PY
