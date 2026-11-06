#!/bin/bash
# Gom file cần chép sang router, tạo bộ tự kiểm tra và checksum.
# Chạy trong WSL sau build_ids.sh: bash package_router.sh
set -euo pipefail
PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$PROJECT/build"
OUT="$ROOT/router"
QEMU="$HOME/sdc-router/qemu/qemu-aarch64"
SELFTEST="$ROOT/test/lab/tcp_syn_scan_0004.pcap"
FILES="ids_agent ids_model.ort run_ids.sh capture_ids.sh check_router.sh ids_monitor.sh selftest.pcap selftest.expected"

mkdir -p "$OUT"
cp "$ROOT/ids_agent" "$ROOT/ort/ids_model.ort" "$OUT/"
cp "$PROJECT/agent/run_ids.sh" "$PROJECT/agent/capture_ids.sh" "$PROJECT/agent/check_router.sh" "$PROJECT/agent/ids_monitor.sh" "$OUT/"
cp "$SELFTEST" "$OUT/selftest.pcap"

"$QEMU" "$OUT/ids_agent" "$OUT/ids_model.ort" --quiet --windows /tmp/ids_expected.csv < "$OUT/selftest.pcap" 2>/dev/null
cut -d, -f1-6 /tmp/ids_expected.csv > "$OUT/selftest.expected"
rm -f /tmp/ids_expected.csv

# Thứ tự đặc trưng trong binary phải đúng với deploy_config.json của run.
python3 - "$PROJECT/model/20261105_1550/deploy_config.json" <<EOF
import json, subprocess, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
got = subprocess.run(["$QEMU", "$OUT/ids_agent", "--print-features"], capture_output=True, text=True).stdout.split()
assert got == config["features"], "thu tu dac trung khac deploy_config.json"
print("thu tu dac trung khop deploy_config.json:", len(got))
EOF

cd "$OUT"
for script in *.sh; do
  if grep -q $'\r' "$script"; then echo "LOI: $script co ky tu CR"; exit 1; fi
done
md5sum $FILES > checksums.md5
du -ch $FILES | tail -1
ls -la
