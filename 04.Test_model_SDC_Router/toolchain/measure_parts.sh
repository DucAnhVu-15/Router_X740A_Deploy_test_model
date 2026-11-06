#!/bin/bash
# Đo RSS khi nạp từng phần của model. Các phần không chạy được suy luận, chỉ lấy dòng "loaded".
# Cách dùng: bash measure_parts.sh <thư mục chứa part_*.onnx>
set -uo pipefail
WORK="$HOME/sdc-router/ort-x64"
for f in "$1"/part_*.onnx; do
  echo "== $(basename "$f") =="
  cp "$f" "$WORK/_part.onnx"
  "$WORK/mem_probe" "$WORK/_part.onnx" off 2>&1 | grep -E 'load_seconds|loaded|inferred|Error|error|terminate' | cut -c1-140
done
rm -f "$WORK/_part.onnx"
