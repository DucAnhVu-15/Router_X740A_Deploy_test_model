#!/bin/bash
# Build ids_agent tĩnh cho router (aarch64 musl), dùng toolchain và thư viện ORT đã có trong ~/sdc-router.
# Chạy trong WSL: bash build_ids.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$HERE")"
SRC="$HOME/sdc-router/ort-src"
BUILD="$HOME/sdc-router/ort-build/MinSizeRel"
TC="$HOME/sdc-router/toolchains/aarch64--musl--stable-2024.05-1/bin/aarch64-buildroot-linux-musl-"

mapfile -t LIBS < <(find "$BUILD" -name '*.a' ! -path '*/CMakeFiles/*' | sort)
echo "static libs: ${#LIBS[@]}"

mkdir -p "$PROJECT/build"
"${TC}g++" -std=c++17 -Os -ffunction-sections -fdata-sections -fno-rtti -static -pthread -s \
  -Wall -Wextra -Wl,--gc-sections \
  -I"$SRC/include/onnxruntime/core/session" \
  "$PROJECT/agent/ids_agent.cpp" \
  -Wl,--start-group "${LIBS[@]}" -Wl,--end-group \
  -o "$PROJECT/build/ids_agent"
ls -la "$PROJECT/build/ids_agent"
