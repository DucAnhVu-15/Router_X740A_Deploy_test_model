#!/bin/bash
# Chạy ids_agent bản ARM bằng QEMU trên một pcap, ghi mọi cửa sổ kèm 97 đặc trưng.
# Cách dùng trong WSL: bash test_agent.sh <file pcap> <windows.csv> [alerts.jsonl]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build"
ALERTS="${3:-/dev/null}"
"$HOME/sdc-router/qemu/qemu-aarch64" "$ROOT/ids_agent" "$ROOT/ort/ids_model.ort" \
  --windows "$2" --features --quiet --output "$ALERTS" < "$1"
echo "agent_exit=$?"
