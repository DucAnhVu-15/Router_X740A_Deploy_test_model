#!/bin/sh
# Bắt gói trên router và chấm trực tiếp bằng model IDS. Nhấn Ctrl+C để dừng.
# Cách dùng: sh run_ids.sh [số giây, 0 = chạy tới khi dừng tay]
# Đổi tham số qua biến môi trường:
#   INTERVAL=3 sh run_ids.sh      in log mỗi 3 giây (mặc định 5) — xem real-time
#   LIVE=1 sh run_ids.sh          chế độ bảng cập nhật tại chỗ như lệnh top
#   EXCLUDE=192.168.1.1 sh run_ids.sh 600
DURATION="${1:-0}"
DIR="${DIR:-$(cd "$(dirname "$0")" && pwd)}"
IFACE="${IFACE:-br-lan}"
ALERTS="${ALERTS:-/tmp/ids_alerts.jsonl}"
WINDOWS="${WINDOWS:-/tmp/ids_windows.csv}"
INTERVAL="${INTERVAL:-5}"
TCPDUMP_LOG="/tmp/ids_tcpdump.log"
MEMORY_LIMIT_KB=180000
SNAPLEN=128   # đủ header Ethernet + IP + TCP; frame.len vẫn lấy từ độ dài gốc
BUFFER_KB=8192

NICE=""
command -v nice >/dev/null 2>&1 && NICE="nice -n 5"

EXTRA="--status --interval $INTERVAL"
[ "$LIVE" = "1" ] && EXTRA="$EXTRA --live"
[ -n "$EXCLUDE" ] && EXTRA="$EXTRA --exclude $EXCLUDE"

echo "bat dau: iface=$IFACE canh bao=$ALERTS cua so=$WINDOWS"
# Router không có lệnh timeout: hẹn giờ bằng sleep rồi dừng tcpdump, agent tự kết thúc khi hết stdin.
TIMER=""
if [ "$DURATION" -gt 0 ]; then
    ( sleep "$DURATION"; killall tcpdump ) &
    TIMER=$!
fi
# Không dùng -p: cần chế độ promiscuous thì br-lan mới thấy gói chuyển giữa hai thiết bị trong LAN.
tcpdump -i "$IFACE" -n -U -s "$SNAPLEN" -B "$BUFFER_KB" -w - 'ip or arp' 2>"$TCPDUMP_LOG" | (
    ulimit -v "$MEMORY_LIMIT_KB"
    exec $NICE "$DIR/ids_agent" "$DIR/ids_model.ort" --output "$ALERTS" --windows "$WINDOWS" $EXTRA
)
[ -n "$TIMER" ] && kill "$TIMER" 2>/dev/null
echo "--- tcpdump ---"
tail -3 "$TCPDUMP_LOG"
