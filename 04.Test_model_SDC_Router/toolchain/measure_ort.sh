#!/bin/bash
# Đo sdc_os.ort đã chuyển đổi. Cách dùng: bash measure_ort.sh <đường dẫn file .ort>
set -euo pipefail

VER="1.28.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORT_FILE="$1"
WORK="$HOME/sdc-router/ort-x64"
NAME="onnxruntime-linux-x64-$VER"

cd "$WORK"
g++ -std=c++17 -O2 "$HERE/mem_probe.cpp" -o mem_probe \
  -I"$NAME/include" -L"$NAME/lib" -lonnxruntime -Wl,-rpath,"$WORK/$NAME/lib"

# Đặt trên tmpfs giống /tmp của router; /dev/shm là tmpfs có sẵn trong WSL.
TARGET=/dev/shm/sdc_os.ort
cp "$ORT_FILE" "$TARGET"
trap 'rm -f "$TARGET"' EXIT

printf 'ort_MB='; wc -c < "$TARGET" | awk '{printf "%.1f\n", $1/1048576}'
printf 'ort_gzip_MB='; gzip -9c "$TARGET" | wc -c | awk '{printf "%.1f\n", $1/1048576}'
printf 'ort_xz_MB='; xz -9c "$TARGET" | wc -c | awk '{printf "%.1f\n", $1/1048576}'

echo "== .ort from tmpfs =="
./mem_probe "$TARGET"
echo "== .onnx baseline =="
./mem_probe model.onnx off
