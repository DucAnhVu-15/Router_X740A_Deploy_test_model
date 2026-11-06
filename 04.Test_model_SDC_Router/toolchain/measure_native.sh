#!/bin/bash
# Đo model bằng ONNX Runtime C++ trên Linux x64 và kiểm tra mức nén của file model.
set -euo pipefail

VER="1.28.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL="/mnt/d/01.AI_Security/02.SDC/Models/20261104_145810/release/sdc_os.onnx"
WORK="$HOME/sdc-router/ort-x64"
NAME="onnxruntime-linux-x64-$VER"

mkdir -p "$WORK"
cd "$WORK"
if [ ! -d "$NAME" ]; then
  curl -fsSL --retry 3 -o "$NAME.tgz" \
    "https://github.com/microsoft/onnxruntime/releases/download/v$VER/$NAME.tgz"
  tar -xzf "$NAME.tgz"
fi

g++ -std=c++17 -O2 "$HERE/mem_probe.cpp" -o mem_probe \
  -I"$NAME/include" -L"$NAME/lib" -lonnxruntime -Wl,-rpath,"$WORK/$NAME/lib"

echo "== runtime =="
ls -la "$NAME"/lib/libonnxruntime.so.* | awk '{print $5, $9}'
strip -o stripped.so "$(ls "$NAME"/lib/libonnxruntime.so.*.* | head -1)"
printf 'stripped_MB='; du -m stripped.so | cut -f1
printf 'stripped_gzip_MB='; gzip -9c stripped.so | wc -c | awk '{printf "%.1f\n", $1/1048576}'
printf 'stripped_xz_MB='; xz -9c stripped.so | wc -c | awk '{printf "%.1f\n", $1/1048576}'

echo "== model =="
cp "$MODEL" model.onnx
printf 'model_MB='; wc -c < model.onnx | awk '{printf "%.1f\n", $1/1048576}'
printf 'model_gzip_MB='; gzip -9c model.onnx | wc -c | awk '{printf "%.1f\n", $1/1048576}'
printf 'model_xz_MB='; xz -9c model.onnx | wc -c | awk '{printf "%.1f\n", $1/1048576}'

for level in off basic all; do
  echo "== optimisation: $level =="
  ./mem_probe model.onnx "$level"
done
