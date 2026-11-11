#!/bin/sh
# Bắt gói trên router và chấm trực tiếp bằng model IDS. Nhấn Ctrl+C để dừng.
# Cách dùng: sh run_ids.sh [số giây, 0 = chạy tới khi dừng tay]
# Mặc định in nhãn của mọi cửa sổ ngay khi chấm (BENIGN/RECON/BRUTEFORCE/DOS), không in dòng báo động.
# Đổi tham số qua biến môi trường:
#   LABELS=0 sh run_ids.sh        kiểu cũ: dòng BAO DONG đầu mỗi đợt + bảng trạng thái mỗi INTERVAL giây
#   INTERVAL=3 sh run_ids.sh      (LABELS=0) in bảng mỗi 3 giây (mặc định 5)
#   LIVE=1 sh run_ids.sh          (LABELS=0) bảng cập nhật tại chỗ như lệnh top
#   EXCLUDE=192.168.1.1 sh run_ids.sh 600
#   THRESHOLD=0.9 sh run_ids.sh   đổi ngưỡng báo động (mặc định lấy theo model trong ids_agent)
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

LABELS="${LABELS:-1}"
[ "$LIVE" = "1" ] && LABELS=0
if [ "$LABELS" = "1" ]; then
    EXTRA="--labels"   # dòng thống kê tổng vẫn in mỗi 30 giây
else
    EXTRA="--status --interval $INTERVAL"
    [ "$LIVE" = "1" ] && EXTRA="$EXTRA --live"
fi
[ -n "$EXCLUDE" ] && EXTRA="$EXTRA --exclude $EXCLUDE"
[ -n "$THRESHOLD" ] && EXTRA="$EXTRA --threshold $THRESHOLD"

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
