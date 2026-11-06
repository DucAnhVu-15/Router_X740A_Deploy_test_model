#!/bin/sh
# Chỉ bắt gói ra file, để chép về PC rồi chấm bằng tools/pkt_features_ref.py.
# Cách dùng: sh capture_ids.sh [số giây] [số gói tối đa] [file ra]
# /tmp nằm trên RAM nên luôn có giới hạn số gói. Mỗi gói tối đa 144 byte trong file.
DURATION="${1:-300}"
MAX_PACKETS="${2:-300000}"
OUTPUT="${3:-/tmp/ids_capture.pcap}"
IFACE="${IFACE:-br-lan}"
SNAPLEN=128

NEED_KB=$((MAX_PACKETS * 144 / 1024))
FREE_KB=$(df -k /tmp | awk 'NR == 2 { print $4 }')
if [ "$NEED_KB" -gt "$FREE_KB" ]; then
    echo "/tmp chi con $FREE_KB KB, can toi da $NEED_KB KB: giam so goi"
    exit 1
fi

( sleep "$DURATION"; killall tcpdump ) &
TIMER=$!
tcpdump -i "$IFACE" -n -s "$SNAPLEN" -B 8192 -c "$MAX_PACKETS" -w "$OUTPUT" 'ip or arp'
kill "$TIMER" 2>/dev/null
ls -la "$OUTPUT"
