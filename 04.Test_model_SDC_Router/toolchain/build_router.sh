#!/bin/bash
# Phần chạy trong WSL của deploy_model.py, dùng build/ort đã sinh trên Windows:
#   build lại ORT nếu danh sách op đổi -> link sdc_agent/sdc_infer -> đối chiếu trên QEMU
#   -> chạy agent trên pcap thử -> gom build/router.
# Cách dùng: bash build_router.sh [số dòng parity, mặc định tất cả]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")/build"
NEW_OPS="$ROOT/ort/required_operators.config"
BUILT_OPS="$HOME/sdc-router/required_operators.config"
PARITY_ROWS="${1:-}"

# Mỗi dòng config "domain;opset;op1,op2" tách thành từng "domain;opset;op".
ops() {
  [ -f "$1" ] || return 0
  grep -v '^#' "$1" | sed 's/\r$//' \
    | awk -F';' 'NF == 3 { n = split($3, a, ","); for (i = 1; i <= n; i++) print $1 ";" $2 ";" a[i] }' | sort -u
}

echo "== [WSL 1/5] Danh sách op của model"
ORT_LIBS="$(find "$HOME/sdc-router/ort-build/MinSizeRel" -name '*.a' ! -path '*/CMakeFiles/*' -print -quit 2>/dev/null || true)"
MISSING="$(comm -23 <(ops "$NEW_OPS") <(ops "$BUILT_OPS"))"
if [ -f "$BUILT_OPS" ] && [ -n "$ORT_LIBS" ] && [ -z "$MISSING" ]; then
  echo "Bản ORT đã build có đủ op cho model, không cần build lại ORT"
else
  echo "Bản ORT đã build thiếu op cho model:"
  echo "${MISSING:-(chưa có bản ORT nào)}"
  echo "Build lại ONNX Runtime (mất khá lâu)..."
  if ! bash "$HERE/build_ort_arm64.sh" "$NEW_OPS"; then
    rm -f "$BUILT_OPS"  # để lần chạy sau biết phải build lại
    echo "LỖI: build ONNX Runtime thất bại" >&2
    exit 1
  fi
fi

echo "== [WSL 2/5] Link sdc_infer, sdc_agent"
bash "$HERE/build_agent.sh"

echo "== [WSL 3/5] Đối chiếu với model gốc trên QEMU (${PARITY_ROWS:-tất cả} dòng)"
if ! bash "$HERE/test_parity.sh" $PARITY_ROWS; then
  echo "LỖI: sdc_infer lệch với model gốc, dừng lại, không đóng gói" >&2
  exit 1
fi

echo "== [WSL 4/5] Chạy sdc_agent trên pcap thử"
bash "$HERE/test_agent.sh" "$ROOT/test/obs.pcap" "$ROOT/test/agent.jsonl"
lines=$(wc -l < "$ROOT/test/agent.jsonl")
if [ "$lines" -eq 0 ]; then
  echo "LỖI: sdc_agent không in kết quả nào" >&2
  exit 1
fi

echo "== [WSL 5/5] Gom file cho router"
bash "$HERE/package_router.sh"
