#!/bin/sh
# Kiểm tra router trước khi test. Chỉ đọc thông số và bắt gói thử, không thay đổi cấu hình.
# Cách dùng: sh check_router.sh [IP máy tấn công] [IP mục tiêu] [số giây bắt thử]
# Trong lúc bắt thử, từ máy tấn công hãy ping mục tiêu: ping -c 15 <IP mục tiêu>
ATTACKER="${1:-192.168.1.236}"
TARGET="${2:-192.168.1.182}"
SECONDS_TEST="${3:-15}"
IFACE="${IFACE:-br-lan}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "== he thong =="
uname -m
awk '/^MemTotal:|^MemAvailable:/ { printf "%s %d MB\n", $1, $2 / 1024 }' /proc/meminfo
grep -c '^processor' /proc/cpuinfo | sed 's/^/so core: /'
df -k /tmp | awk 'NR == 2 { printf "/tmp con trong: %d MB\n", $4 / 1024 }'
date -u

echo "== cong cu =="
for tool in tcpdump nice killall; do
    printf "%-8s %s\n" "$tool" "$(command -v "$tool" || echo THIEU)"
done

echo "== mang =="
ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet / { print "IP " $2 }'
[ -d "/sys/class/net/$IFACE/brif" ] && echo "cong bridge: $(ls "/sys/class/net/$IFACE/brif" | tr '\n' ' ')"

echo "== tang toc phan cung (co the lam tcpdump khong thay goi) =="
for key in flow_offloading flow_offloading_hw; do
    value=$(uci -q get "firewall.@defaults[0].$key" 2>/dev/null)
    echo "$key=${value:-khong dat}"
done
lsmod 2>/dev/null | grep -iE 'hnat|hw_nat|fastpath|fast_path|flow_offload|nss|ecm|ppe|sfe|fal_' | awk '{ print "module: " $1 }'

echo "== bat thu $SECONDS_TEST s: $ATTACKER <-> $TARGET =="
echo "Hay ping tu $ATTACKER toi $TARGET ngay bay gio"
LOG=/tmp/ids_check.log
( sleep "$SECONDS_TEST"; killall tcpdump ) &
TIMER=$!
tcpdump -i "$IFACE" -n -s 128 -l "host $ATTACKER and host $TARGET and icmp" >/tmp/ids_check.txt 2>"$LOG"
kill "$TIMER" 2>/dev/null
A=$(grep -c "$ATTACKER > $TARGET" /tmp/ids_check.txt)
B=$(grep -c "$TARGET > $ATTACKER" /tmp/ids_check.txt)
echo "goi $ATTACKER -> $TARGET: $A"
echo "goi $TARGET -> $ATTACKER: $B"
if [ "$A" -gt 0 ] && [ "$B" -gt 0 ]; then
    echo "KET LUAN: thay ca hai chieu, test duoc"
else
    echo "KET LUAN: thieu mot chieu; model se bi sai dac trung (rx). Kiem tra hai may co cung di qua br-lan khong"
fi
rm -f /tmp/ids_check.txt "$LOG"

if [ -f "$DIR/selftest.pcap" ] && [ -x "$DIR/ids_agent" ]; then
    echo "== tu kiem tra model tren phan cung that =="
    "$DIR/ids_agent" "$DIR/ids_model.ort" --quiet --windows /tmp/ids_selftest.csv <"$DIR/selftest.pcap" 2>&1 | tail -1
    cut -d, -f1-6 /tmp/ids_selftest.csv >/tmp/ids_selftest.cut
    if cmp -s /tmp/ids_selftest.cut "$DIR/selftest.expected"; then
        echo "KET LUAN: ket qua giong het ban QEMU"
    else
        echo "KET LUAN: KHAC ban QEMU, chua nen test tiep"
    fi
    rm -f /tmp/ids_selftest.csv /tmp/ids_selftest.cut
fi
