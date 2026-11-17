#!/bin/sh
# Chạy run_sdc.sh dưới nền, tách khỏi phiên SSH: rớt SSH hay đóng cửa sổ thì agent vẫn chạy.
# Cách dùng:
#   sh sdc_service.sh start [timeout giây]   chạy nền (timeout mặc định 300)
#   sh sdc_service.sh status                 đang chạy không, RAM, số kết quả
#   sh sdc_service.sh log                    xem log trực tiếp; Ctrl+C chỉ thoát xem, agent vẫn chạy
#   sh sdc_service.sh stop                   dừng; phiên đang gom dở được chấm luôn (reason "eof")
# Biến SDC_OBS của run_sdc.sh vẫn dùng được: SDC_OBS= sh sdc_service.sh start
DIR="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="/tmp/sdc_run.pid"
LOG="/tmp/sdc_run.log"
RESULTS="/tmp/sdc_results.jsonl"

running() {
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

# PID các tiến trình con của $1 có tên $2.
children() {
    for stat in /proc/[0-9]*/stat; do
        read -r pid comm state ppid rest 2>/dev/null <"$stat" || continue
        [ "$ppid" = "$1" ] && [ "$comm" = "($2)" ] && echo "$pid"
    done
}

case "${1:-status}" in
start)
    if running; then
        echo "dang chay roi (pid $(cat "$PIDFILE")). Xem: sh $0 status"
        exit 0
    fi
    if [ -n "$(pidof sdc_agent)" ]; then
        echo "co sdc_agent khac dang chay (pid $(pidof sdc_agent)), dung truoc: killall sdc_agent"
        exit 1
    fi
    # Bỏ qua SIGHUP như nohup (router không có nohup). tcpdump và sdc_agent giữ nguyên trạng thái bỏ qua này.
    (
        trap '' HUP
        exec sh "$DIR/run_sdc.sh" "${2:-300}"
    ) </dev/null >>"$LOG" 2>&1 &
    echo $! >"$PIDFILE"
    sleep 1
    if running; then
        echo "da chay nen (pid $!), timeout ${2:-300} s"
        echo "log: $LOG    ket qua: $RESULTS"
        echo "xem: sh $0 log    dung: sh $0 stop"
    else
        echo "khong chay duoc, xem $LOG:"
        tail -5 "$LOG"
        exit 1
    fi
    ;;
stop)
    if ! running; then
        rm -f "$PIDFILE"
        echo "khong chay"
        exit 0
    fi
    PID=$(cat "$PIDFILE")
    # Chỉ dừng tcpdump của agent này. Agent nhận EOF, chấm các phiên dở rồi tự thoát.
    for p in $(children "$PID" tcpdump); do kill "$p" 2>/dev/null; done
    i=0
    while running && [ "$i" -lt 15 ]; do
        sleep 1
        i=$((i + 1))
    done
    if running; then
        for p in $(children "$PID" sdc_agent); do kill "$p" 2>/dev/null; done
        kill "$PID" 2>/dev/null
    fi
    rm -f "$PIDFILE"
    echo "da dung"
    ;;
status)
    if running; then
        PID=$(cat "$PIDFILE")
        AGENT=$(children "$PID" sdc_agent)
        echo "dang chay: run_sdc.sh pid $PID, sdc_agent pid ${AGENT:-?}"
        [ -n "$AGENT" ] && awk '/^VmRSS:/{ printf "sdc_agent RAM: %.1f MB\n", $2 / 1024 }' "/proc/$AGENT/status"
    else
        echo "khong chay"
        [ -f "$LOG" ] && echo "--- cuoi $LOG:" && tail -5 "$LOG"
    fi
    [ -f "$RESULTS" ] && echo "ket qua: $(wc -l <"$RESULTS") dong trong $RESULTS"
    ;;
log)
    tail -n 20 -f "$LOG"
    ;;
*)
    echo "cach dung: sh $0 start [timeout] | stop | status | log"
    exit 2
    ;;
esac
