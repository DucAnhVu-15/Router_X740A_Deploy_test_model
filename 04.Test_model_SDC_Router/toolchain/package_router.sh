#!/bin/bash
# Gom file cần chép sang router và ghi checksum để kiểm tra sau khi chép.
set -euo pipefail
PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$PROJECT/build"
OUT="$ROOT/router"
FILES="sdc_infer sdc_agent run_sdc.sh sdc_monitor.sh sdc_packet.ort sdc_tail.ort sdc_hn.bin parity_1000.txt"
mkdir -p "$OUT"
cp "$ROOT/sdc_infer" "$ROOT/sdc_agent" "$PROJECT/agent/run_sdc.sh" "$PROJECT/agent/sdc_monitor.sh" "$OUT/"
cp "$ROOT/ort/sdc_packet.ort" "$ROOT/ort/sdc_tail.ort" "$ROOT/ort/sdc_hn.bin" "$OUT/"
head -1000 "$ROOT/ort/parity_cases.txt" > "$OUT/parity_1000.txt"
cd "$OUT"
md5sum $FILES > checksums.md5
grep -c $'\r' run_sdc.sh || true
du -ch $FILES | tail -1
ls -la
