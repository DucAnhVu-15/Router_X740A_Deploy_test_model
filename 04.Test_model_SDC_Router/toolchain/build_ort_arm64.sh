#!/bin/bash
# Build ONNX Runtime rút gọn (chỉ các op model dùng) cho aarch64 musl.
# Cách dùng: bash build_ort_arm64.sh <file required_operators.config>
set -uo pipefail

CONFIG="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HOME/sdc-router/ort-src"
BUILD="$HOME/sdc-router/ort-build"
PYDEPS="$HOME/sdc-router/pydeps"
LOCAL_CONFIG="$HOME/sdc-router/required_operators.config"

cp "$CONFIG" "$LOCAL_CONFIG"
export PYTHONPATH="$PYDEPS"
cd "$SRC"

python3 tools/ci_build/build.py \
  --build_dir "$BUILD" \
  --config MinSizeRel \
  --update --build \
  --skip_submodule_sync \
  --skip_tests \
  --parallel 10 \
  --cmake_generator Ninja \
  --compile_no_warning_as_error \
  --minimal_build \
  --disable_rtti \
  --include_ops_by_config "$LOCAL_CONFIG" \
  --cmake_extra_defines \
    CMAKE_TOOLCHAIN_FILE="$HERE/aarch64-musl.cmake" \
    onnxruntime_BUILD_SHARED_LIB=OFF \
    onnxruntime_BUILD_UNIT_TESTS=OFF \
    onnxruntime_ENABLE_CPUINFO=OFF
status=$?
echo "BUILD_EXIT=$status"
exit "$status"
