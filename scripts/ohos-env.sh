#!/usr/bin/env bash
# Source this file before building rd-engine for OpenHarmony.
set -euo pipefail

target_triple="aarch64-unknown-linux-ohos"
engine_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

find_ohos_ndk_home() {
  if [[ -n "${OHOS_NDK_HOME:-}" ]]; then
    printf '%s\n' "$OHOS_NDK_HOME"
    return 0
  fi

  if [[ -n "${OHOS_SDK_HOME:-}" && -d "$OHOS_SDK_HOME/default/openharmony" ]]; then
    printf '%s\n' "$OHOS_SDK_HOME/default/openharmony"
    return 0
  fi

  local candidate
  for candidate in \
    "$HOME/Huawei/Sdk/default/openharmony" \
    "$HOME/Library/Huawei/Sdk/default/openharmony" \
    "$HOME/command-line-tools/sdk/default/openharmony" \
    "/opt/harmonyos/sdk/default/openharmony"; do
    if [[ -d "$candidate/native/llvm/bin" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

find_tool() {
  local name="$1"
  local suffix
  for suffix in "" ".exe" ".cmd"; do
    if [[ -f "$toolchain_bin/$name$suffix" ]]; then
      printf '%s\n' "$toolchain_bin/$name$suffix"
      return 0
    fi
  done

  return 1
}

OHOS_NDK_HOME="$(find_ohos_ndk_home || true)"
if [[ -z "$OHOS_NDK_HOME" ]]; then
  cat >&2 <<'EOF'
OHOS_NDK_HOME is not set and no HarmonyOS/OpenHarmony SDK was found.

Set it to the SDK's openharmony directory, for example:
  export OHOS_NDK_HOME="$HOME/command-line-tools/sdk/default/openharmony"
EOF
  exit 2
fi

OHOS_NDK_HOME="$(cd "$OHOS_NDK_HOME" && pwd)"
toolchain_bin="$OHOS_NDK_HOME/native/llvm/bin"
sysroot="$OHOS_NDK_HOME/native/sysroot"
if [[ ! -d "$toolchain_bin" ]]; then
  echo "OHOS_NDK_HOME does not contain native/llvm/bin: $OHOS_NDK_HOME" >&2
  exit 2
fi

clang="$(find_tool "${target_triple}-clang")"
clangxx="$(find_tool "${target_triple}-clang++")"
ar="$(find_tool "llvm-ar")"
ranlib="$(find_tool "llvm-ranlib")"
common_flags="--target=$target_triple --sysroot=$sysroot"

export OHOS_NDK_HOME
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_LINKER="$clang"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUSTFLAGS="-C link-arg=--target=aarch64-linux-ohos -C link-arg=--sysroot=$sysroot"
export CC_aarch64_unknown_linux_ohos="$clang"
export CXX_aarch64_unknown_linux_ohos="$clangxx"
export AR_aarch64_unknown_linux_ohos="$ar"
export RANLIB_aarch64_unknown_linux_ohos="$ranlib"
export CMAKE_TOOLCHAIN_FILE_aarch64_unknown_linux_ohos="${CMAKE_TOOLCHAIN_FILE_aarch64_unknown_linux_ohos:-$OHOS_NDK_HOME/native/build/cmake/ohos.toolchain.cmake}"
export LIBCLANG_PATH="${LIBCLANG_PATH:-$OHOS_NDK_HOME/native/llvm/lib}"
export CFLAGS_aarch64_unknown_linux_ohos="${CFLAGS_aarch64_unknown_linux_ohos:-$common_flags}"
export CXXFLAGS_aarch64_unknown_linux_ohos="${CXXFLAGS_aarch64_unknown_linux_ohos:-$common_flags}"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_ohos="${BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_ohos:-$common_flags}"
export PKG_CONFIG_ALLOW_CROSS="${PKG_CONFIG_ALLOW_CROSS:-1}"
export VCPKG_ROOT="${VCPKG_ROOT:-$engine_root/target/ohos-vcpkg}"
export VCPKG_INSTALLED_ROOT="${VCPKG_INSTALLED_ROOT:-$VCPKG_ROOT/installed}"
export OHOS_VCPKG_PREFIX="${OHOS_VCPKG_PREFIX:-$VCPKG_INSTALLED_ROOT/arm64-linux}"

echo "OHOS_NDK_HOME=$OHOS_NDK_HOME"
echo "OHOS target=$target_triple"
echo "OHOS linker=$CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_LINKER"
echo "OHOS vcpkg prefix=$OHOS_VCPKG_PREFIX"
echo "Engine=$engine_root"
