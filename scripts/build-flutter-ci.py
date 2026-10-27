#!/usr/bin/env python3
"""Build rd-engine FRB, then the staged official Flutter application (no run/publish)."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
VCPKG_COMMIT = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
NDK_VERSION = "28.2.13676358"  # r28c, matching the pinned official workflow
ANDROID = {
    "aarch64-linux-android": ("arm64-v8a", "android-arm64", "aarch64-linux-android"),
    "armv7-linux-androideabi": ("armeabi-v7a", "android-arm", "armv7a-linux-androideabi"),
    "x86_64-linux-android": ("x86_64", "android-x64", "x86_64-linux-android"),
}


def run(args, cwd=ROOT, env=None, capture=False, check=True):
    print("+ " + " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=check,
                          text=capture, stdout=subprocess.PIPE if capture else None).stdout


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"missing/empty build output: {path}")
    return path


def dependencies(platform, target, triplet):
    vcpkg = ROOT / ".build-deps/vcpkg"
    run(["git", "clone", "--filter=blob:none", "--no-checkout", "https://github.com/microsoft/vcpkg.git", vcpkg])
    run(["git", "fetch", "--depth=1", "origin", VCPKG_COMMIT], cwd=vcpkg)
    run(["git", "checkout", "--detach", VCPKG_COMMIT], cwd=vcpkg)
    env = os.environ.copy()
    if platform == "android":
        ndk = Path(env["ANDROID_HOME"]) / "ndk" / NDK_VERSION
        if not ndk.is_dir():
            raise ValueError(f"install the pinned NDK first: {ndk}")
        env["ANDROID_NDK_HOME"] = str(ndk)
    if platform == "windows":
        run(["cmd", "/c", vcpkg / "bootstrap-vcpkg.bat", "-disableMetrics"], env=env)
        exe = vcpkg / "vcpkg.exe"
    else:
        run(["bash", vcpkg / "bootstrap-vcpkg.sh", "-disableMetrics"], env=env)
        exe = vcpkg / "vcpkg"
    ports = [f"libvpx:{triplet}", f"zlib:{triplet}"]
    if platform != "ios":
        ports.append(f"libsodium:{triplet}")
    # iOS: the vendored libsodium-sys has its own iOS configure (--host=arm-apple-darwin10).
    # vcpkg's libsodium port passes host==build there, so its probes try to run arm64 programs.
    if platform == "android":
        ports.append(f"openssl:{triplet}")  # reqwest's native-tls is also enabled
    run([exe, "install", *ports,
         "--overlay-ports=" + str(ROOT / "native/frb/vcpkg-overlays"), "--disable-metrics"], env=env)
    prefix = vcpkg / "installed" / triplet
    vpx = require(prefix / "lib" / ("vpx.lib" if platform == "windows" else "libvpx.a"))
    require(prefix / "include/vpx/vpx_decoder.h")
    if platform != "ios":
        require(prefix / "lib" / ("libsodium.lib" if platform == "windows" else "libsodium.a"))
        env["SODIUM_LIB_DIR"] = str(prefix / "lib")
    env.update({"LIBVPX_PREFIX": str(prefix), "LIBVPX_STATIC": "1", "VCPKG_ROOT": str(vcpkg),
                "CMAKE_TOOLCHAIN_FILE": str(vcpkg / "scripts/buildsystems/vcpkg.cmake"),
                "VCPKG_TARGET_TRIPLET": triplet, "CMAKE_POLICY_VERSION_MINIMUM": "3.5"})
    # Pinned zlib 1.3.2 names the Windows static-md library zs.lib.
    # The vcpkg CMake wrapper supplies its matching imported ZLIB target.
    definitions = [f'set(VCPKG_TARGET_TRIPLET "{triplet}" CACHE STRING "")',
                   f'set(ZLIB_ROOT "{prefix.as_posix()}" CACHE PATH "")']
    if platform == "windows":
        require(prefix / "lib/zs.lib")
        env["ZLIB_ROOT"] = str(prefix)
    elif platform == "android":
        abi, _, clang = ANDROID[target]
        ndk = Path(env["ANDROID_NDK_HOME"])
        toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
        cc = str(toolchain / f"{clang}22-clang")
        cxx = str(toolchain / f"{clang}22-clang++")
        suffix = target.replace("-", "_")
        env.update({f"CC_{suffix}": cc, f"CXX_{suffix}": cxx,
                    f"AR_{suffix}": str(toolchain / "llvm-ar"),
                    "CARGO_TARGET_" + suffix.upper() + "_LINKER": cc,
                    "CMAKE_TOOLCHAIN_FILE": str(ndk / "build/cmake/android.toolchain.cmake"),
                    "CMAKE_ANDROID_ARCH_ABI": abi, "CMAKE_SYSTEM_VERSION": "22",
                    "ANDROID_ABI": abi, "ANDROID_PLATFORM": "android-22",
                    "ZLIB_ROOT": str(prefix), "PKG_CONFIG_ALLOW_CROSS": "1",
                    "PKG_CONFIG_LIBDIR": str(prefix / "lib/pkgconfig")})
        env.update({"OPENSSL_DIR": str(prefix), "OPENSSL_STATIC": "1"})
        definitions += [f'set(ANDROID_ABI "{abi}" CACHE STRING "")',
                        'set(ANDROID_PLATFORM "android-22" CACHE STRING "")']
    elif platform == "ios":
        env["IPHONEOS_DEPLOYMENT_TARGET"] = "13.0"
        sdk = run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], capture=True).strip()
        definitions += ['set(CMAKE_SYSTEM_NAME iOS)',
                        f'set(CMAKE_OSX_SYSROOT "{sdk}" CACHE PATH "")',
                        'set(CMAKE_OSX_ARCHITECTURES arm64 CACHE STRING "")',
                        'set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "")']
    # CMake does not import arbitrary environment variables as cache settings.
    # Forward the actual target ABI/SDK explicitly, including on the NDK path.
    definitions.append(f'include("{Path(env["CMAKE_TOOLCHAIN_FILE"]).as_posix()}")')
    if platform == "android":
        definitions += [f'set(ZLIB_INCLUDE_DIR "{prefix.as_posix()}/include" CACHE PATH "")',
                        f'set(ZLIB_LIBRARY "{prefix.as_posix()}/lib/libz.a" CACHE FILEPATH "")']
    toolchain = ROOT / ".build-deps/native-toolchain.cmake"
    toolchain.write_text("\n".join(definitions) + "\n", encoding="utf-8")
    env["CMAKE_TOOLCHAIN_FILE"] = str(toolchain)
    return env, vpx


def build(platform, target, triplet, client):
    if platform == "windows":
        # Git Bash puts Git\usr\bin first; its coreutils link.exe then shadows
        # MSVC's linker ("/usr/bin/link: extra operand ...") for every rustc link.
        git_coreutils = os.path.join("git", "usr", "bin")
        os.environ["PATH"] = os.pathsep.join(
            entry for entry in os.environ["PATH"].split(os.pathsep)
            if not os.path.normpath(entry).lower().endswith(git_coreutils))
    env, vpx = dependencies(platform, target, triplet)
    run(["cargo", "build", "--locked", "--release", "--manifest-path", ROOT / "native/frb/Cargo.toml",
         "--target", target], env=env)
    # No CARGO_TARGET_DIR override: respect the project's normal cache policy.
    metadata = json.loads(run(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1",
                               "--manifest-path", ROOT / "native/frb/Cargo.toml"], env=env, capture=True))
    cargo_output = Path(metadata["target_directory"]) / target / "release"
    names = {
        "windows": ("rd_engine_flutter.dll", "librustdesk.dll"),
        "linux": ("librd_engine_flutter.so", "librustdesk.so"),
        "android": ("librd_engine_flutter.so", "librustdesk.so"),
        "macos": ("librd_engine_flutter.dylib", "liblibrustdesk.dylib"),
        "ios": ("librd_engine_flutter.a", "liblibrustdesk.a"),
    }
    source_name, consumer_name = names[platform]
    source = require(cargo_output / source_name)
    native = client.parent / "native"
    native.mkdir()
    library = native / consumer_name
    shutil.copy2(source, library)
    if platform == "macos":
        # The renamed FRB dylib must also identify its bundled path to dyld;
        # copying a cargo install_name into the app leaves an external dependency.
        run(["install_name_tool", "-id", "@rpath/liblibrustdesk.dylib", library])
    if platform == "windows":
        symbols = run(["dumpbin", "/exports", library], capture=True)
    elif platform == "android":
        nm = Path(env["ANDROID_NDK_HOME"]) / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm"
        symbols = run([nm, "-D", "--defined-only", library], capture=True)
    elif platform == "linux":
        symbols = run(["nm", "-D", "--defined-only", library], capture=True)
    else:
        # Xcode's nm also reads the LLVM 22 bitcode embedded in the prebuilt Rust std
        # objects of an iOS archive, fails on it and exits non-zero after listing
        # the rest. The required symbols are still asserted below.
        symbols = run(["nm", "-gU", library], capture=True, check=platform != "ios")
    for symbol in ("wire_main_init", "session_get_rgba"):
        if symbol not in symbols:
            raise ValueError(f"native library does not export {symbol}")
    if platform == "windows" and "rd_engine_windows_texture_wait_progress" not in symbols:
        raise ValueError("Windows WAIT progress export missing")
    if platform == "android":
        for symbol in ("JNI_OnLoad", "Java_ffi_FFI_initAccountStorage"):
            if symbol not in symbols:
                raise ValueError(f"Android lifecycle/storage export missing: {symbol}")
        jni = client / "android/app/src/main/jniLibs" / ANDROID[target][0]
        jni.mkdir(parents=True)
        shutil.copy2(library, jni / "librustdesk.so")

    # Do not let a resolver silently replace the reviewed effective client lock.
    lock = client / "pubspec.lock"
    lock_hash = sha256(lock)
    # On Windows the SDK entry point is flutter.bat, which CreateProcess does not
    # find from the bare name; resolve it through PATH/PATHEXT once.
    flutter = shutil.which("flutter")
    if flutter is None:
        raise ValueError("flutter is not on PATH")
    run([flutter, "--version"])
    run([flutter, "pub", "get", "--enforce-lockfile"], cwd=client)
    if sha256(lock) != lock_hash:
        raise ValueError("flutter pub get changed the reviewed client lock")
    client_env = os.environ.copy()
    command = [flutter, "build", platform, "--release", "--no-pub"]
    if platform == "windows":
        client_env["RUSTDESK_LIB_OVERRIDE"] = str(library)
    elif platform == "android":
        command = [flutter, "build", "apk", "--release", "--no-pub", "--target-platform", ANDROID[target][1]]
    elif platform == "macos":
        client_env.update({"FLUTTER_XCODE_ARCHS": "arm64" if target.startswith("aarch64") else "x86_64",
                           "FLUTTER_XCODE_ONLY_ACTIVE_ARCH": "YES", "CODE_SIGNING_ALLOWED": "NO"})
    elif platform == "ios":
        command = [flutter, "build", "ipa", "--release", "--no-pub", "--no-codesign"]
    run(command, cwd=client, env=client_env)
    if sha256(lock) != lock_hash:
        raise ValueError("client build changed the reviewed client lock")

    artifact = client.parent / "artifacts"
    artifact.mkdir()
    stem = f"rd-engine-flutter-{platform}-{target}"
    if platform == "windows":
        bundle = client / "build/windows/x64/runner/Release"
        require(bundle / "rustdesk.exe")
        packaged = require(bundle / "librustdesk.dll")
    elif platform == "linux":
        arch = "arm64" if target.startswith("aarch64") else "x64"
        bundle = client / f"build/linux/{arch}/release/bundle"
        require(bundle / "rustdesk")
        packaged = require(bundle / "lib/librustdesk.so")
    elif platform == "macos":
        bundle = client / "build/macos/Build/Products/Release/RustDesk.app"
        require(bundle / "Contents/MacOS/RustDesk")
        packaged = require(bundle / "Contents/Frameworks/liblibrustdesk.dylib")
    elif platform == "ios":
        archives = list((client / "build/ios/archive").glob("*.xcarchive"))
        if len(archives) != 1:
            raise ValueError("expected one unsigned iOS xcarchive")
        bundle = archives[0]
        apps = list((bundle / "Products/Applications").glob("*.app"))
        if len(apps) != 1:
            raise ValueError("unsigned iOS archive does not contain one real app")
        binary = require(apps[0] / "Runner")
        exports = run(["nm", "-gU", binary], capture=True, check=False)
        if "wire_main_init" not in exports or "session_get_rgba" not in exports:
            raise ValueError("iOS application lost statically linked FRB symbols")
        packaged = None  # the archive is linked into Runner, not copied alongside it
    else:
        apk = require(client / "build/app/outputs/flutter-apk/app-release.apk")
        with zipfile.ZipFile(apk) as archive:
            embedded = archive.read(f"lib/{ANDROID[target][0]}/librustdesk.so")
        if hashlib.sha256(embedded).hexdigest() != sha256(library):
            raise ValueError("APK contains a different native engine")
        shutil.copy2(apk, artifact / f"{stem}-ci-debug-key.apk")
        bundle, packaged = None, None
    if packaged is not None and sha256(packaged) != sha256(library):
        raise ValueError("client bundle contains a different native engine")
    if bundle is not None:
        # tar preserves Unix permissions and framework symlinks (artifact ZIP
        # transport itself does not). No installer or signing credentials.
        with tarfile.open(artifact / f"{stem}.tar.gz", "w:gz") as archive:
            archive.add(bundle, arcname=bundle.name)
    inputs = json.loads((client.parent / "client-inputs.json").read_text())
    inputs.update({"target": target, "vcpkg_commit": VCPKG_COMMIT, "vcpkg_triplet": triplet,
                   "native_sha256": sha256(library), "libvpx_sha256": sha256(vpx),
                   "distribution": "unsigned-xcarchive" if platform == "ios" else
                                   "ci-debug-key-apk" if platform == "android" else "unsigned-bundle"})
    (artifact / "client-inputs.json").write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")
    outputs = sorted(artifact.iterdir())
    (artifact / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in outputs), encoding="utf-8")
    print(f"built application artifacts: {artifact}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "linux", "macos", "android", "ios"), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--triplet", required=True)
    parser.add_argument("--client", type=Path, required=True)
    args = parser.parse_args()
    build(args.platform, args.target, args.triplet, args.client.resolve(strict=True))


if __name__ == "__main__":
    main()
