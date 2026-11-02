#!/usr/bin/env python3
"""Build the pinned Opus static library for the OHOS target and for host tests.

magnum-opus 588c6e1f9ed50c3a01fa64f3bd3e7cdb0378a114 (the pin native/frb/Cargo.toml
records) derives the vcpkg triplet it links from CARGO_CFG_TARGET_OS/ARCH.
aarch64-unknown-linux-ohos reports target_os "linux", so it reads
$VCPKG_ROOT/installed/arm64-linux, and a host test build reads
$VCPKG_ROOT/installed/x64-linux. Its FFI header opus_ffi.h includes
<opus/opus_multistream.h> and it links "opus" statically, so each of those
directories needs lib/libopus.a and include/opus/.

Source and version are the ones the pinned vcpkg commit
9e593bb18ea69cc5095e012465dcd675a822ed0d declares in ports/opus: vcpkg.json
1.5.2 port-version 1, and portfile.cmake with REF v1.5.2 plus the SHA512 below.
Every target is compiled from that one verified source with its own compiler, so
the OHOS archive cannot contain host objects and the host archive cannot contain
OHOS objects. Source scripts/ohos-env.sh first: it exports OHOS_NDK_HOME and
VCPKG_ROOT, and this script never creates a second SDK or prefix layout.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import urllib.request

OPUS_VERSION = "1.5.2"
OPUS_URL = "https://github.com/xiph/opus/archive/v1.5.2.tar.gz"
OPUS_SHA512 = (
    "4ffefd9c035671024f9720c5129bfe395dea04f0d6b730041c2804e89b1db6e4"
    "d19633ad1ae58855afc355034233537361e707f26dc53adac916554830038fab"
)
VCPKG_COMMIT = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
# vcpkg triplet directory -> (ELF e_machine, name) the archive must contain.
TARGETS = {"x64-linux": (62, "x86_64"), "arm64-linux": (183, "aarch64")}


def run(args):
    print("+ " + " ".join(str(arg) for arg in args), flush=True)
    subprocess.run([str(arg) for arg in args], check=True)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha512(path):
    digest = hashlib.sha512()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(directory):
    """Fetch the exact tarball the pinned port names, verified by its SHA512."""
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"opus-{OPUS_VERSION}.tar.gz"
    if not archive.is_file() or sha512(archive) != OPUS_SHA512:
        print("downloading " + OPUS_URL, flush=True)
        with urllib.request.urlopen(OPUS_URL, timeout=120) as response:
            with archive.open("wb") as output:
                shutil.copyfileobj(response, output)
    actual = sha512(archive)
    if actual != OPUS_SHA512:
        raise ValueError(f"opus tarball SHA512 mismatch: {actual} != {OPUS_SHA512}")
    return archive


def unpack(archive, directory):
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        for name in tar.getnames():
            member = Path(name)
            if member.is_absolute() or ".." in member.parts:
                raise ValueError("refusing unsafe archive member: " + name)
        tar.extractall(directory)
    roots = [path for path in directory.iterdir() if path.is_dir()]
    if len(roots) != 1 or not (roots[0] / "CMakeLists.txt").is_file():
        raise ValueError(f"opus archive is not one source tree: {directory}")
    return roots[0]


def ohos_toolchain(build):
    """The workflow's SDK toolchain, with the one ABI this SDK output targets."""
    ndk = os.environ.get("OHOS_NDK_HOME")
    if not ndk:
        raise ValueError("OHOS_NDK_HOME is not set; source scripts/ohos-env.sh first")
    toolchain = Path(ndk) / "native/build/cmake/ohos.toolchain.cmake"
    if not toolchain.is_file():
        raise ValueError(f"HarmonyOS CMake toolchain not found: {toolchain}")
    build.mkdir(parents=True, exist_ok=True)
    wrapper = build / "ohos-arm64-v8a.cmake"
    wrapper.write_text(
        'set(OHOS_ARCH arm64-v8a CACHE STRING "")\n'
        'set(OHOS_STL c++_shared CACHE STRING "")\n'
        f'include("{toolchain.as_posix()}")\n',
        encoding="utf-8",
    )
    return wrapper


def elf_machine(archive):
    """e_machine of the first object member, from the archive's own bytes."""
    data = archive.read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError(f"not an ar archive: {archive}")
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        name = header[:16].decode("ascii", "replace").strip()
        size = int(header[48:58].decode("ascii").strip() or 0)
        body = data[offset + 60:offset + 60 + size]
        offset += 60 + size + (size % 2)
        # GNU ar writes the symbol index as "/" and BSD as "__.SYMDEF".
        if name.startswith("/") or name.startswith("__.SYMDEF"):
            continue
        if body[:4] != b"\x7fELF":
            raise ValueError(f"first archive member is not ELF: {name}")
        if body[4] != 2:
            raise ValueError(f"archive member is not 64-bit: {name}")
        order = "<" if body[5] == 1 else ">"
        return struct.unpack_from(order + "H", body, 18)[0]
    raise ValueError(f"no ELF object member in {archive}")


def build(source, target, root, prefix):
    build_dir = root / target
    if build_dir.exists():
        # A stale tree can hold another SDK's compiler cache.
        shutil.rmtree(build_dir)
    arguments = [
        "cmake", "-S", source, "-B", build_dir,
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_INSTALL_PREFIX={prefix}",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        f"-DPACKAGE_VERSION={OPUS_VERSION}",
        "-DOPUS_BUILD_PROGRAMS=OFF",
        "-DOPUS_BUILD_TESTING=OFF",
        "-DOPUS_INSTALL_PKG_CONFIG_MODULE=OFF",
        "-DOPUS_INSTALL_CMAKE_CONFIG_MODULE=OFF",
    ]
    if target == "arm64-linux":
        arguments.append("-DCMAKE_TOOLCHAIN_FILE=" + str(ohos_toolchain(build_dir)))
    run(arguments)
    run(["cmake", "--build", build_dir])
    # --prefix decides the install root regardless of what the toolchain caches.
    run(["cmake", "--install", build_dir, "--prefix", prefix])


def verify(prefix, target):
    library = prefix / "lib/libopus.a"
    header = prefix / "include/opus/opus_multistream.h"
    if not library.is_file() or library.stat().st_size == 0:
        raise ValueError(f"Opus static library missing: {library}")
    if not header.is_file():
        raise ValueError(f"Opus headers missing: {header}")
    shared = sorted((prefix / "lib").glob("libopus.so*"))
    if shared:
        raise ValueError(f"Opus install is not static-only: {shared}")
    expected, name = TARGETS[target]
    machine = elf_machine(library)
    if machine != expected:
        raise ValueError(f"{target} Opus archive is e_machine {machine}, not {name}")
    return library, header


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", nargs="+", choices=tuple(TARGETS), required=True,
                        help="vcpkg triplet directories magnum-opus reads")
    args = parser.parse_args()
    if not os.environ.get("VCPKG_ROOT"):
        raise SystemExit("VCPKG_ROOT is not set; source scripts/ohos-env.sh first")
    root = Path(os.environ["VCPKG_ROOT"]).resolve()
    build_root = root.parent / "opus-build"
    archive = download(build_root / "download")
    source = unpack(archive, build_root / f"opus-{OPUS_VERSION}-source")
    print(f"opus {OPUS_VERSION} {OPUS_URL} sha512={OPUS_SHA512}")
    print(f"version and source from vcpkg {VCPKG_COMMIT} ports/opus")
    for target in args.target:
        prefix = root / "installed" / target
        prefix.mkdir(parents=True, exist_ok=True)
        build(source, target, build_root, prefix)
        library, header = verify(prefix, target)
        print(f"{target}: {library} sha256={sha256(library)}")
        print(f"{target}: {header} sha256={sha256(header)}")
        print(f"{target}: static PIC opus for {TARGETS[target][1]} in {prefix}")


if __name__ == "__main__":
    main()
