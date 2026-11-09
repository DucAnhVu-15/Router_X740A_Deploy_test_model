#!/bin/sh
# Bắt gói trên router rồi chạy model. Nhấn Ctrl+C để dừng.
# Thiết bị join qua DHCP mở một phiên; model chạy khi đủ DHCP + DNS + mDNS + TLS hoặc hết timeout.
# Cách dùng: sh run_sdc.sh [timeout giây] [thư mục model, mặc định là thư mục chứa script]
TIMEOUT="${1:-300}"
DIR="${2:-$(cd "$(dirname "$0")" && pwd)}"
IFACE="br-lan"
OUTPUT="/tmp/sdc_results.jsonl"
TCPDUMP_LOG="/tmp/sdc_tcpdump.log"
MEMORY_LIMIT_KB=180000
ROUTER_MAC="$(cat /sys/class/net/$IFACE/address)"

NICE=""
command -v nice >/dev/null 2>&1 && NICE="nice -n 10"

# DHCP, DNS, mDNS, và TLS đi ra cổng 443.
# ClientHello có thể chia nhiều đoạn: lấy gói mở đầu handshake và gói có cờ PSH,
# bỏ qua các gói dữ liệu đầy MSS để không tốn CPU khi tải lên nhiều.
FILTER='udp port 67 or udp port 68 or udp dst port 53 or udp port 5353'
FILTER="$FILTER or (tcp dst port 443 and (tcp[13] & 8 != 0 or tcp[((tcp[12] & 0xf0) >> 2)] = 22))"
FILTER="$FILTER or (ip6 and tcp dst port 443 and (ip6[53] & 8 != 0 or ip6[40 + ((ip6[52] & 0xf0) >> 2)] = 22))"

tcpdump -i "$IFACE" -n -U -s 4096 -w - "$FILTER" 2>"$TCPDUMP_LOG" | (
    ulimit -v "$MEMORY_LIMIT_KB"
    exec $NICE "$DIR/sdc_agent" "$DIR" --trigger-dhcp --timeout "$TIMEOUT" --output "$OUTPUT" --router-mac "$ROUTER_MAC"
)
tail -3 "$TCPDUMP_LOG"
