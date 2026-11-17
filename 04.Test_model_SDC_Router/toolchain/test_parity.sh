#!/bin/bash
# Chạy sdc_infer bản ARM bằng QEMU trên bộ test đối chiếu. Đạt khi lech_packet=lech_hostname=lech_final=0.
# Cách dùng: bash test_parity.sh [số dòng tối đa, mặc định tất cả]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build"
"$HOME/sdc-router/qemu/qemu-aarch64" "$ROOT/sdc_infer" "$ROOT/ort" "$ROOT/ort/parity_cases.txt" ${1:+"$1"}
status=$?
echo "parity_exit=$status"
exit "$status"
