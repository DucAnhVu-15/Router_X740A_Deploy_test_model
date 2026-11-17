#!/bin/bash
# Chạy sdc_agent bản ARM bằng QEMU trên pcap thử.
# Cách dùng: bash test_agent.sh <file pcap> <đầu ra jsonl> [window]
# Observation của từng lần suy luận ghi vào <đầu ra>_obs.jsonl.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build"
OBS="${2%.jsonl}_obs.jsonl"
rm -f "$OBS"
"$HOME/sdc-router/qemu/qemu-aarch64" "$ROOT/sdc_agent" "$ROOT/ort" --window "${3:-300}" --columns \
  --leases /nonexistent --obs-output "$OBS" < "$1" > "$2"
echo "agent_exit=$?"
wc -l "$2" "$OBS"
