#!/usr/bin/env python3
"""Focused tests of the HAR artifact/provenance trust boundary (not runtime tests)."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('har', Path(__file__).with_name('verify-ohos-har.py'))
har = importlib.util.module_from_spec(spec)
spec.loader.exec_module(har)
SHA = '1' * 40
VERSION = '0.1.0-ci.1.1.g11111111'


class HarBoundary(unittest.TestCase):
    def fixture(self, directory, *, dirty=False, corrupt=False, machine=b'\xb7\x00'):
        library = b'\x7fELF\x02\x01' + bytes(12) + machine + bytes(44)
        provenance = {
            'provenance_version': 2, 'kind': 'har',
            'engine_repository': 'https://github.com/FrankHan052176/rd-engine',
            'engine_sha': SHA, 'source_dirty': dirty,
            'package_name': 'rustdesk-ohrs', 'package_version': VERSION,
            'target': 'aarch64-unknown-linux-ohos',
            'library_sha256': hashlib.sha256(library).hexdigest(),
            'libcxx_sha256': hashlib.sha256(library).hexdigest(),
        }
        files = {
            'oh-package.json5': json.dumps({'name': 'rustdesk-ohrs', 'version': VERSION}).encode(),
            'release-provenance.json': json.dumps(provenance).encode(),
            'index.ets': b'export {};', 'libs/index.d.ts': b'export {};',
            'libs/arm64-v8a/librd_engine_native_har.so': library + (b'tamper' if corrupt else b''),
            'libs/arm64-v8a/libc++_shared.so': library,
        }
        archive = directory / 'package.har'
        with tarfile.open(archive, 'w:gz') as output:
            for name, content in files.items():
                info = tarfile.TarInfo('package/' + name)
                info.size = len(content)
                output.addfile(info, io.BytesIO(content))
        sidecar = directory / 'release-provenance.json'
        sidecar.write_text(json.dumps({**provenance, 'har_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}))
        return archive, sidecar

    def test_exact_archive_and_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, sidecar = self.fixture(Path(temporary))
            self.assertFalse(har.verify(archive, SHA, VERSION, sidecar)['source_dirty'])
            with self.assertRaisesRegex(ValueError, 'engine_sha'):
                har.verify(archive, '2' * 40, VERSION, sidecar)
            data = json.loads(sidecar.read_text())
            data['har_sha256'] = '0' * 64
            sidecar.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'sidecar'):
                har.verify(archive, SHA, VERSION, sidecar)

    def test_refuse_dirty_tampered_or_host_libraries(self):
        for options, message in [({'dirty': True}, 'source_dirty'), ({'corrupt': True}, 'digest'), ({'machine': b'\x3e\x00'}, 'AArch64')]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                archive, sidecar = self.fixture(Path(temporary), **options)
                with self.assertRaisesRegex(ValueError, message):
                    har.verify(archive, SHA, VERSION, sidecar)


if __name__ == '__main__':
    unittest.main()
