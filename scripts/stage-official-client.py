#!/usr/bin/env python3
"""Stage only the official Flutter inputs verified against the pinned Git blobs.

The caller verifies the native source lock and the official checkout origin/HEAD
first. Never copy a mutable checkout after verification: all subsequent patch
replay and client builds must read the snapshot this script creates.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = ("windows", "linux", "macos", "android", "ios")
COMMON_DIRS = ("flutter/lib", "flutter/assets")
COMMON_FILES = (
    "flutter/pubspec.yaml", "flutter/pubspec.lock", "flutter/analysis_options.yaml",
    "flutter/.metadata",
)
BINDINGS = ("generated_bridge.dart", "generated_bridge.freezed.dart")


def selection(platform):
    if platform == "windows":
        return COMMON_DIRS + ("flutter/windows/runner",), COMMON_FILES + (
            "flutter/windows/.gitignore", "flutter/windows/flutter/CMakeLists.txt",
        )
    return COMMON_DIRS + (f"flutter/{platform}",), COMMON_FILES


def reject(message):
    raise ValueError(message)


def field(text, name):
    values = [line[len(name) + 2:] for line in text.splitlines()
              if line.startswith(name + ": ")]
    if len(values) != 1 or not values[0]:
        reject(f"expected exactly one {name} field")
    return values[0]


def ordinary(path):
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        reject(f"missing source {path}: {error}")
    if not stat.S_ISREG(mode):
        reject(f"source is not an ordinary file: {path}")
    return path.read_bytes()


def directory(path):
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        reject(f"missing source directory {path}: {error}")
    if not stat.S_ISDIR(mode):
        reject(f"source is not an ordinary directory: {path}")


def git(checkout, *args, input_bytes=None):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1",
               GIT_TERMINAL_PROMPT="0", GIT_ALLOW_PROTOCOL="")
    try:
        run = subprocess.run(["git", "--no-replace-objects", "-C", str(checkout), *args],
                             input=input_bytes, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, check=True)
    except (OSError, subprocess.CalledProcessError):
        reject(f"cannot read pinned official Git objects ({args[0]})")
    return run.stdout


def manifest(checkout, revision, tree_dirs, tree_files):
    selected = tree_dirs + tree_files
    raw = git(checkout, "ls-tree", "-r", "-z", "--full-tree", revision, "--", *selected)
    if not raw.endswith(b"\0"):
        reject("incomplete pinned client Git tree")
    entries = {}
    for item in raw[:-1].split(b"\0"):
        try:
            header, name = item.split(b"\t", 1)
            mode, kind, oid = header.split(b" ")
            relative = name.decode("utf-8")
        except (ValueError, UnicodeError):
            reject("invalid pinned Git tree entry")
        if (mode not in (b"100644", b"100755") or kind != b"blob" or
                not re.fullmatch(rb"[0-9a-f]{40,64}", oid) or
                relative in entries or relative.startswith("/") or
                any(part in ("", ".", "..") for part in relative.split("/")) or
                not any(relative.startswith(prefix + "/") for prefix in tree_dirs) and
                relative not in tree_files):
            reject(f"unsupported pinned client source entry: {relative}")
        entries[relative] = (mode, oid)
    for name in tree_files:
        if name not in entries:
            reject(f"missing pinned client source: {name}")
    for name in tree_dirs:
        if not any(relative.startswith(name + "/") for relative in entries):
            reject(f"empty or missing pinned client source: {name}")
    return entries


def source_entries(checkout, expected, tree_dirs, tree_files):
    directory(checkout / "flutter")
    actual = set(tree_files)
    for name in tree_files:
        parent = Path(name).parent
        while parent.as_posix() != "flutter":
            directory(checkout / parent)
            parent = parent.parent
        ordinary(checkout / name)
    for root in tree_dirs:
        stack = [root]
        while stack:
            current = stack.pop()
            directory(checkout / current)
            actual.add(current)
            for entry in os.scandir(checkout / current):
                relative = current + "/" + entry.name
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    stack.append(relative)
                elif stat.S_ISREG(mode):
                    actual.add(relative)
                else:
                    reject(f"unsupported client source type: {relative}")
    allowed = {"flutter/lib/" + name for name in BINDINGS}
    expected_paths = set(expected)
    expected_dirs = set(tree_dirs)
    for name in expected:
        parent = Path(name).parent
        while str(parent) != "flutter":
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    extras = actual - expected_paths - expected_dirs - allowed
    missing = expected_paths - actual
    if extras or missing:
        reject(f"pinned client source set differs: unexpected={sorted(extras)[:5]}, missing={sorted(missing)[:5]}")
    # Generated bindings are overwritten from the native lock, but an existing
    # path must never be a link or directory which SCP might resolve differently.
    for name in allowed & actual:
        ordinary(checkout / name)


def blobs(checkout, entries):
    order = sorted(entries)
    response = git(checkout, "cat-file", "--batch",
                   input_bytes=b"".join(entries[name][1] + b"\n" for name in order))
    offset = 0
    for name in order:
        end = response.find(b"\n", offset)
        if end == -1:
            reject(f"incomplete pinned client blob: {name}")
        header = response[offset:end].split(b" ")
        if len(header) != 3 or header[0] != entries[name][1] or header[1] != b"blob":
            reject(f"missing or invalid pinned client blob: {name}")
        try:
            size = int(header[2])
        except ValueError:
            reject(f"invalid pinned client blob length: {name}")
        start = end + 1
        stop = start + size
        if size < 0 or stop >= len(response) or response[stop:stop + 1] != b"\n":
            reject(f"truncated pinned client blob: {name}")
        yield name, response[start:stop]
        offset = stop + 1
    if offset != len(response):
        reject("unexpected pinned client blob output")


def binding_bytes(name, lock):
    relative = "native/frb/dart/lib/" + name
    matches = re.findall(r"(?m)^([0-9a-f]{64})  " + re.escape(relative) + r"$", lock)
    if len(matches) != 1:
        reject(f"expected exactly one native lock digest for {relative}")
    data = ordinary(ROOT / relative)
    if hashlib.sha256(data).hexdigest() != matches[0]:
        reject(f"native binding disagrees with provenance lock: {relative}")
    return data


def stage(checkout, output, platform="windows"):
    tree_dirs, tree_files = selection(platform)
    if output.exists() or output.is_symlink():
        reject(f"refusing to overwrite snapshot: {output}")
    directory(checkout)
    if Path(os.fsdecode(git(checkout, "rev-parse", "--show-toplevel").strip())).resolve() != checkout:
        reject("official client path must be the checkout root")
    upstream = ordinary(ROOT / "native/frb/UPSTREAM.txt").decode("utf-8")
    revision = field(upstream, "Commit")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        reject("invalid pinned official client revision")
    head = git(checkout, "rev-parse", "HEAD").decode("ascii").strip()
    if head != revision:
        reject("official checkout HEAD disagrees with pinned revision")
    expected = manifest(checkout, revision, tree_dirs, tree_files)
    source_entries(checkout, expected, tree_dirs, tree_files)
    template = None
    if platform == "windows":
        template = ordinary(ROOT / "scripts/client-windows-CMakeLists.txt")
        if ordinary(checkout / "flutter/windows/CMakeLists.txt") != template:
            reject("official Windows CMake override differs from the reviewed template")
    lock = ordinary(ROOT / "native/frb/UPSTREAM.lock").decode("utf-8")
    owned = {name: binding_bytes(name, lock) for name in BINDINGS}
    # Compare and use the same immutable blob bytes for the snapshot. The
    # checkout is never reread by the transfer after this operation.
    output.mkdir(parents=True)
    count = 0
    for name, content in blobs(checkout, expected):
        if ordinary(checkout / name) != content:
            reject(f"official checkout source differs from pinned raw Git blob: {name}")
        destination = output / name.removeprefix("flutter/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        destination.chmod(0o755 if expected[name][0] == b"100755" else 0o644)
        count += 1
    if template is not None:
        cmake = output / "windows/CMakeLists.txt"
        cmake.parent.mkdir(parents=True, exist_ok=True)
        cmake.write_bytes(template)
    for name, content in owned.items():
        (output / "lib" / name).write_bytes(content)
    print(f"official {platform} client snapshot: {count} raw Git blobs at {revision}, "
          f"{'reviewed CMake override, ' if template is not None else ''}"
          "two locked native bindings")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official-client-tree", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--platform", choices=PLATFORMS, default="windows")
    args = parser.parse_args()
    try:
        stage(args.official_client_tree.resolve(strict=True), args.output, args.platform)
    except (ValueError, OSError, UnicodeError) as error:
        print(f"official client snapshot: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
