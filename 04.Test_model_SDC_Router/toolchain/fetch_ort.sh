#!/bin/bash
# Tải mã nguồn ONNX Runtime và kiểm tra công cụ cần cho bản build.
set -euo pipefail
VER="1.28.0"
SRC="$HOME/sdc-router/ort-src"
if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --branch "v$VER" https://github.com/microsoft/onnxruntime.git "$SRC" 2>&1 | tail -2
fi
cd "$SRC"
git log -1 --format='commit %h %s'
du -sh .
printf 'pip: '; python3 -m pip --version 2>&1 | head -1
printf 'flatbuffers: '; python3 -c 'import flatbuffers; print(flatbuffers.__version__)' 2>&1 | tail -1
cmake --version | head -1
