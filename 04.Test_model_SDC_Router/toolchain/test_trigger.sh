#!/bin/bash
# Kiểm tra chế độ --trigger-dhcp bằng QEMU.
# Cách dùng: bash test_trigger.sh <file pcap kịch bản>
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build"
QEMU="$HOME/sdc-router/qemu/qemu-aarch64"
SUMMARY='import json,sys
for l in sys.stdin:
    r=json.loads(l)
    print(r["mac"][-2:],r["reason"],"elapsed",r["elapsed_s"],r["sources"],r["hostname"],"|",r["make"],"|",r["type"],"|",r["model"])'

echo "== kich ban, doc het file =="
"$QEMU" "$ROOT/sdc_agent" "$ROOT/ort" --trigger-dhcp --timeout 300 --leases /nonexistent < "$1" 2>/dev/null | python3 -c "$SUMMARY"

echo "== timeout khi mang im lang: giu pipe mo, timeout 3 giay =="
start=$(date +%s)
( cat "$1"; sleep 12 ) | "$QEMU" "$ROOT/sdc_agent" "$ROOT/ort" --trigger-dhcp --timeout 3 --leases /nonexistent 2>/dev/null \
  | python3 -c "$SUMMARY" | tail -1
