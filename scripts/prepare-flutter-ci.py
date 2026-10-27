#!/usr/bin/env python3
"""Prepare a fresh, pinned official Flutter consumer; never build the upstream core.

The workflow runs verify-native-provenance.sh --require-tracked before this.
Only the staged snapshot is patched. The Windows caller supplies the reviewed
CMake override in its disposable official checkout, as the existing sync does.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("stage_client", ROOT / "scripts/stage-official-client.py")
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)
PATCHES = (
    "official-client-cpu-rgba.patch", "official-client-account-safety.patch",
    "official-client-flutter-lock.patch", "official-client-lan-actions.patch",
    "official-client-product-scope.patch", "official-client-host-control.patch",
)
CLIENT_LOCK_SHA256 = "bc58506b80464e5b3f6c73669c79ef270949b3cbc85401c290aa92e4573df7f7"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace(path, old, new, count=1):
    text = path.read_text(encoding="utf-8")
    if text.count(old) != count:
        raise ValueError(f"{path}: expected {count} occurrences of reviewed integration anchor {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def add_build_setting(path, setting, blocks, missing):
    """Add a setting only to Xcode buildSettings blocks that do not define it.

    A duplicate key in one block is ambiguous project text, so existing project
    level definitions are left untouched. The reviewed block counts are checked.
    """
    key = setting.split(" =", 1)[0]
    seen = absent = 0

    def edit(match):
        nonlocal seen, absent
        seen += 1
        if re.search(rf"^\s*{key} =", match.group(1), re.M):
            return match.group(0)
        absent += 1
        return f"buildSettings = {{\n\t\t\t\t{setting}\n{match.group(1)}\n\t\t\t}};"

    text = re.sub(r"buildSettings = \{\n(.*?)\n\t\t\t\};", edit, path.read_text(encoding="utf-8"), flags=re.S)
    if (seen, absent) != (blocks, missing):
        raise ValueError(f"{path}: expected {blocks} buildSettings blocks ({missing} without {key}), saw {seen} ({absent})")
    path.write_text(text, encoding="utf-8", newline="\n")


def prepare(checkout, output, platform):
    staging.stage(checkout, output, platform)
    applied = list(PATCHES)
    if platform == "android":
        applied.append("official-client-account-storage.patch")
    patch_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    # A staged client lives below rd-engine, not inside the official Git repo.
    # Prevent parent-repo discovery: otherwise git apply can silently skip every
    # hunk as outside the current repository subdirectory, even with --no-index.
    patch_env["GIT_CEILING_DIRECTORIES"] = str(output.parent)
    for name in applied:
        # Preserve the recorded patch bytes, including upstream whitespace;
        # applicability and the effective lock hash, not reformatting, are gates.
        command = ["git", "apply", "--no-index", "--whitespace=nowarn"]
        # The product-scope patch also changes a Windows-only runner. Do not
        # export another platform's runner just to replay that unrelated hunk.
        if platform != "windows":
            command += ["--exclude=windows/runner/main.cpp"]
        patch = str(ROOT / "native/frb/patches" / name)
        subprocess.run(command + ["--check", patch], cwd=output, env=patch_env, check=True)
        subprocess.run(command + [patch], cwd=output, env=patch_env, check=True)
    if digest(output / "pubspec.lock") != CLIENT_LOCK_SHA256:
        raise ValueError("effective official client pubspec.lock differs from the reviewed SDK/product-scope lock")

    if platform == "linux":
        library = (output.parent / "native/librustdesk.so").as_posix()
        replace(output / "linux/CMakeLists.txt",
                'set(RUSTDESK_LIB "../../target/${RUSTDESK_LIB_BUILD_TYPE}/liblibrustdesk.so")',
                f'set(RUSTDESK_LIB "{library}")')
    elif platform in ("macos", "ios"):
        project = output / platform / "Runner.xcodeproj/project.pbxproj"
        if platform == "macos":
            replace(project, "../../target/release", "../../native", count=2)
            replace(project, "ATTRIBUTES = (CodeSignOnCopy, );", "ATTRIBUTES = ();", count=1)
            add_build_setting(project, "CODE_SIGNING_ALLOWED = NO;", blocks=9, missing=9)
            add_build_setting(project, "COPY_PHASE_STRIP = NO;", blocks=9, missing=6)
            (output / "macos/Runner/Runner-Bridging-Header.h").write_text(
                '#import "bridge_generated.h"\n', encoding="utf-8")
        else:
            replace(project, "../../target/aarch64-apple-ios/release", "../../native", count=7)
            # Dart resolves wire functions through DynamicLibrary.process().
            # Retain the FRB static archive even without direct ObjC references.
            replace(project, '"$(PROJECT_DIR)/../../native/liblibrustdesk.a",',
                    '"-force_load",\n\t\t\t\t\t"$(PROJECT_DIR)/../../native/liblibrustdesk.a",', count=3)
            add_build_setting(project, "DEAD_CODE_STRIPPING = NO;", blocks=6, missing=3)
            replace(project, '\t\t\t\t\t"-framework",\n\t\t\t\t\t"\\\"video_player_avfoundation\\\"",\n', "", count=3)
            replace(project, '"-ObjC",', '"-ObjC",\n\t\t\t\t\t"-framework", "Security",\n\t\t\t\t\t"-framework", "SystemConfiguration",\n\t\t\t\t\t"-framework", "CoreFoundation",', count=3)
        # The official generated C header is not a source blob. The Swift runners
        # call the C entry points below; Dart uses the locked generated bindings.
        # Real signatures are in native/frb/src/c_entry_points.rs.
        header = ["#pragma once", "#include <stdbool.h>", "#include <stdint.h>",
                  "bool rustdesk_core_main(void);",
                  # Upstream's FRB header defines this to reference every wire_*
                  # symbol so a static link cannot drop them. Here the FRB code is
                  # kept by -force_load (iOS) or lives in the embedded dylib (macOS).
                  "static inline int64_t dummy_method_to_enforce_bundling(void) { return 0; }"]
        if platform == "macos":
            # Upstream's dock re-open hook acts only in its `--server` process role,
            # which the engine does not have (rustdesk_core_main always starts the UI).
            header.append("static inline void handle_applicationShouldOpenUntitledFile(void) {}")
        else:
            header.append("const uint8_t *session_get_rgba(const char *session_uuid_str, int display);")
        (output / platform / "Runner/bridge_generated.h").write_text("\n".join(header) + "\n", encoding="utf-8")
    elif platform == "android":
        gradle = output / "android/app/build.gradle"
        replace(gradle, 'it.workingDir = new File("../..")',
                f'it.workingDir = new File("{(ROOT / "native/frb").as_posix()}")')
        replace(gradle, 'commandLine("cargo", "metadata", "--format-version", "1")',
                'commandLine("cargo", "metadata", "--locked", "--format-version", "1")')
        replace(gradle, "main.proto.srcDirs += '../../../libs/base/protos'",
                f"main.proto.srcDirs += '{(ROOT / 'vendor/rustdesk/libs/base/protos').as_posix()}'")
        # No release credentials in PR CI. Use Android's ephemeral debug key,
        # while still compiling release/AOT code. This is not a store signature.
        replace(gradle, "signingConfig signingConfigs.release", "signingConfig signingConfigs.debug")
        replace(gradle, '    compileSdkVersion 36',
                '    compileSdkVersion 36\n    packagingOptions { jniLibs { keepDebugSymbols += ["**/librustdesk.so"] } }')
        # Upstream's 1 GiB Gradle heap makes the release build's JVM thrash
        # ("Gradle build daemon has been stopped: ... garbage collector is thrashing").
        replace(output / "android/gradle.properties", "org.gradle.jvmargs=-Xmx1024M",
                "org.gradle.jvmargs=-Xmx5120M -XX:MaxMetaspaceSize=1024M\nkotlin.daemon.jvmargs=-Xmx3072M")

    metadata = {
        "official_commit": staging.field((ROOT / "native/frb/UPSTREAM.txt").read_text(), "Commit"),
        "platform": platform, "flutter": "3.24.5", "dart": "3.5.4", "frb": "1.80.1",
        "pubspec_lock_sha256": CLIENT_LOCK_SHA256,
        "bindings": {name: digest(output / "lib" / name) for name in staging.BINDINGS},
        "patches": {name: digest(ROOT / "native/frb/patches" / name) for name in applied},
        "native_lock_sha256": digest(ROOT / "native/frb/UPSTREAM.lock"),
    }
    (output.parent / "client-inputs.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"prepared {platform} official Flutter client at {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official-client-tree", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", choices=staging.PLATFORMS, required=True)
    args = parser.parse_args()
    prepare(args.official_client_tree.resolve(strict=True), args.output.absolute(), args.platform)


if __name__ == "__main__":
    main()
