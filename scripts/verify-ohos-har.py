#!/usr/bin/env python3
"""Verify the HAR/provenance boundary before publication or consumption."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile


def verify(archive, engine_sha, version, sidecar=None):
    if not re.fullmatch(r'[0-9a-f]{40}', engine_sha):
        raise ValueError('engine SHA must be a fixed Git commit')
    with tarfile.open(archive, 'r:gz') as package:
        for member in package.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != 'package' or '..' in parts or member.issym() or member.islnk():
                raise ValueError('HAR contains an unsafe entry')
        def read(name):
            stream = package.extractfile('package/' + name)
            if stream is None:
                raise ValueError('HAR member is not a file: ' + name)
            return stream.read()
        metadata = json.loads(read('oh-package.json5'))
        provenance = json.loads(read('release-provenance.json'))
        expected = {
            'provenance_version': 2,
            'kind': 'har',
            'engine_repository': 'https://github.com/FrankHan052176/rd-engine',
            'engine_sha': engine_sha,
            'source_dirty': False,
            'package_name': 'rustdesk-ohrs',
            'package_version': version,
            'target': 'aarch64-unknown-linux-ohos',
        }
        for key, value in expected.items():
            if provenance.get(key) != value:
                raise ValueError('HAR provenance mismatch: ' + key)
        if metadata.get('name') != 'rustdesk-ohrs' or metadata.get('version') != version:
            raise ValueError('HAR package metadata does not match its provenance')
        for name, key in [('librd_engine_native_har.so', 'library_sha256'), ('libc++_shared.so', 'libcxx_sha256')]:
            library = read('libs/arm64-v8a/' + name)
            # ELF64, little-endian, EM_AARCH64; do not accept a host-built .so.
            if library[:6] != b'\x7fELF\x02\x01' or library[18:20] != b'\xb7\x00':
                raise ValueError('HAR library is not an AArch64 ELF: ' + name)
            if hashlib.sha256(library).hexdigest() != provenance.get(key):
                raise ValueError('HAR library digest mismatch: ' + name)
        read('index.ets')
        read('libs/index.d.ts')
    digest = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
    result = {**provenance, 'har_sha256': digest}
    if sidecar and json.loads(Path(sidecar).read_text()) != result:
        raise ValueError('HAR does not match its release sidecar')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--engine-sha', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--sidecar', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.archive, args.engine_sha, args.version, args.sidecar), indent=2, sort_keys=True))
