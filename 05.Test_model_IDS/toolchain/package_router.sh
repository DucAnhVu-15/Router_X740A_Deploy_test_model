#!/bin/bash
# Gom file cần chép sang router, tạo bộ tự kiểm tra và checksum.
# Chạy trong WSL sau build_ids.sh: bash package_router.sh [run_id]
set -euo pipefail
PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="${1:-20261111_1058}"
CONFIG="$PROJECT/model/$RUN/deploy_config.json"
ROOT="$PROJECT/build"
OUT="$ROOT/router"
QEMU="$HOME/sdc-router/qemu/qemu-aarch64"
SELFTEST="$ROOT/test/lab/tcp_syn_scan_0004.pcap"
FILES="ids_agent ids_model.ort run_ids.sh capture_ids.sh check_router.sh ids_monitor.sh diag_lan.sh selftest.pcap selftest.expected"

mkdir -p "$OUT"
cp "$ROOT/ids_agent" "$ROOT/ort/ids_model.ort" "$OUT/"
cp "$PROJECT/agent/run_ids.sh" "$PROJECT/agent/capture_ids.sh" "$PROJECT/agent/check_router.sh" "$PROJECT/agent/ids_monitor.sh" "$PROJECT/agent/diag_lan.sh" "$OUT/"
cp "$SELFTEST" "$OUT/selftest.pcap"

"$QEMU" "$OUT/ids_agent" "$OUT/ids_model.ort" --quiet --windows /tmp/ids_expected.csv < "$OUT/selftest.pcap" 2>/tmp/ids_expected.err
cut -d, -f1-6 /tmp/ids_expected.csv > "$OUT/selftest.expected"

# Binary phải khớp deploy_config.json của run: thứ tự đặc trưng, lớp, cửa sổ và ngưỡng.
python3 - "$CONFIG" "$QEMU" "$OUT/ids_agent" /tmp/ids_expected.err <<'EOF'
import json, re, subprocess, sys
config_path, qemu, agent, err_path = sys.argv[1:]
config = json.load(open(config_path, encoding="utf-8"))
got = subprocess.run([qemu, agent, "--print-features"], capture_output=True, text=True).stdout.split()
assert got == config["features"], "LOI: thu tu dac trung khac deploy_config.json, phai sua ids_agent.cpp"
assert config["classes"] == ["benign", "recon", "bruteforce", "dos"], "LOI: lop khac, phai sua ids_agent.cpp"
assert config["window"] == {"n_pkt": 50, "t_max": 10, "ctx": [60, 300], "new_gap": 300}, "LOI: cua so khac, phai sua ids_agent.cpp"
printed = float(re.search(r"nguong=([0-9.eE+-]+)", open(err_path, encoding="utf-8").read()).group(1))
assert abs(printed - config["threshold"]) < 1e-5, f"LOI: nguong trong binary {printed} khac {config['threshold']}, build lai voi run_id"
print(f"run {config['run_id']}: dac trung {len(got)}, lop, cua so, nguong {printed} deu khop deploy_config.json")
EOF
rm -f /tmp/ids_expected.csv /tmp/ids_expected.err

cd "$OUT"
for script in *.sh; do
  if grep -q $'\r' "$script"; then echo "LOI: $script co ky tu CR"; exit 1; fi
done
md5sum $FILES > checksums.md5
du -ch $FILES | tail -1
