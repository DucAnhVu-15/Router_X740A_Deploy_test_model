#!/bin/bash
# Link sdc_infer và sdc_agent tĩnh với ONNX Runtime đã build cho aarch64 musl.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$HERE")"
SRC="$HOME/sdc-router/ort-src"
BUILD="$HOME/sdc-router/ort-build/MinSizeRel"
TC="$HOME/sdc-router/toolchains/aarch64--musl--stable-2024.05-1/bin/aarch64-buildroot-linux-musl-"

mapfile -t LIBS < <(find "$BUILD" -name '*.a' ! -path '*/CMakeFiles/*' | sort)
echo "static libs: ${#LIBS[@]}"

build() {
  local out="$PROJECT/build/$1"
  shift
  "${TC}g++" -std=c++17 -Os -ffunction-sections -fdata-sections -fno-rtti -static -pthread -s \
    -Wl,--gc-sections \
    -I"$SRC/include/onnxruntime/core/session" \
    -I"$BUILD/_deps/re2-src" \
    -I"$BUILD/_deps/abseil_cpp-src" \
    "$@" "$PROJECT/agent/hostname_engine.cpp" \
    -Wl,--start-group "${LIBS[@]}" -Wl,--end-group \
    -o "$out"
  ls -la "$out"
  printf 'xz_MB='; xz -9ec "$out" | wc -c | awk '{printf "%.2f\n", $1/1048576}'
}

build sdc_infer "$PROJECT/agent/sdc_infer.cpp"
build sdc_agent "$PROJECT/agent/sdc_agent.cpp" "$PROJECT/agent/feature_extract.cpp"
