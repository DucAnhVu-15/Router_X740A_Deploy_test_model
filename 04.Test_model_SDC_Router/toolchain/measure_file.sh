#!/bin/bash
# Chạy mem_probe trên một file model. Cách dùng: bash measure_file.sh <model> [all|basic|off]
set -euo pipefail
WORK="$HOME/sdc-router/ort-x64"
cp "$1" "$WORK/_measure.onnx"
trap 'rm -f "$WORK/_measure.onnx"' EXIT
"$WORK/mem_probe" "$WORK/_measure.onnx" "${2:-off}"
