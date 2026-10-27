#!/usr/bin/env python3
"""Exercise real pinned platform staging/patch replay without compiling/running a client."""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("prepare_client", ROOT / "scripts/prepare-flutter-ci.py")
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)


def git(checkout, *args):
    return subprocess.check_output(["git", "-C", str(checkout), *args], text=True).strip()


def suite(checkout):
    class PlatformInputs(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            (ROOT / ".build-deps").mkdir(exist_ok=True)
            cls.temporary = tempfile.TemporaryDirectory(prefix="flutter-ci-test-", dir=ROOT / ".build-deps")
            cls.root = Path(cls.temporary.name)
            cls.fixture = cls.root / "official"
            revision = preparation.staging.field((ROOT / "native/frb/UPSTREAM.txt").read_text(), "Commit")
            # Fetch only this commit: a partial caller clone need not possess
            # unrelated history, and tests must not lazily fetch that history.
            subprocess.run(["git", "init", "--quiet", str(cls.fixture)], check=True)
            git(cls.fixture, "config", "core.autocrlf", "false")
            git(cls.fixture, "fetch", "--quiet", "--no-tags", "--depth=1", str(checkout), revision)
            git(cls.fixture, "sparse-checkout", "set", "flutter")
            git(cls.fixture, "checkout", "--quiet", "--detach", revision)
            # This override is only in the disposable fixture, not the caller's
            # checkout; the default stager still requires exact reviewed bytes.
            (cls.fixture / "flutter/windows/CMakeLists.txt").write_bytes(
                (ROOT / "scripts/client-windows-CMakeLists.txt").read_bytes())

        @classmethod
        def tearDownClass(cls):
            cls.temporary.cleanup()

        def test_five_actual_platform_snapshots(self):
            runners = {"windows": "windows/runner/main.cpp", "linux": "linux/main.cc",
                       "macos": "macos/Runner/MainFlutterWindow.swift",
                       "android": "android/app/build.gradle", "ios": "ios/Runner/AppDelegate.swift"}
            for platform, runner in runners.items():
                with self.subTest(platform=platform):
                    output = self.root / platform / "flutter"
                    preparation.prepare(self.fixture, output, platform)
                    self.assertTrue((output / runner).is_file())
                    metadata = json.loads((output.parent / "client-inputs.json").read_text())
                    self.assertEqual(metadata["platform"], platform)
                    self.assertEqual(len(metadata["bindings"]), 2)
                    self.assertEqual(len(metadata["patches"]), 7 if platform == "android" else 6)
                    self.assertFalse((output / "lib/mobile/pages/view_camera_page.dart").exists())
                    self.assertFalse((output / "Cargo.toml").exists(), "must not stage/build the old Rust core")
                    if platform != "windows":
                        self.assertFalse((output / "windows").exists(), "do not export unrelated runners")
            # Only the reviewed Windows override changes inside the fixture.
            self.assertEqual(git(self.fixture, "diff", "--name-only"), "flutter/windows/CMakeLists.txt")

        def test_mutable_runner_drift_is_rejected(self):
            source = self.fixture / "flutter/linux/main.cc"
            original = source.read_bytes()
            source.write_bytes(original + b"\n// unreviewed mutation\n")
            try:
                with self.assertRaisesRegex(ValueError, "differs from pinned raw Git blob"):
                    preparation.staging.stage(self.fixture, self.root / "drift/flutter", "linux")
            finally:
                source.write_bytes(original)

        def test_existing_output_is_not_overwritten(self):
            output = self.root / "already-present"
            output.mkdir()
            sentinel = output / "keep"
            sentinel.write_text("existing build inputs")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite snapshot"):
                preparation.staging.stage(self.fixture, output, "linux")
            self.assertEqual(sentinel.read_text(), "existing build inputs")

    return unittest.defaultTestLoader.loadTestsFromTestCase(PlatformInputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official-client-tree", type=Path, required=True)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(suite(args.official_client_tree.resolve(strict=True)))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
