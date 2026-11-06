#!/bin/sh
# Theo dõi RAM và CPU của router. Chỉ đọc thông số, không thay đổi gì.
# Cách dùng:
#   sh sdc_monitor.sh baseline [số giây] [chu kỳ]   đo lúc chưa chạy agent
#   sh sdc_monitor.sh running  [số giây] [chu kỳ]   đo lúc agent đang chạy
#   sh sdc_monitor.sh compare                       so sánh hai lần đo
LABEL="${1:-running}"
DURATION="${2:-60}"
INTERVAL="${3:-2}"
DIR="/tmp"
HZ=100

summary() {
    awk -F, 'NR > 1 {
        n++
        avail = $2 + 0; if (min_avail == "" || avail < min_avail) min_avail = avail
        sum_avail += avail
        if ($7 + 0 > max_rss) max_rss = $7 + 0
        if ($8 + 0 > max_hwm) max_hwm = $8 + 0
        if ($9 + 0 > max_tcpdump) max_tcpdump = $9 + 0
        sum_cpu += $10
        if ($10 + 0 > max_cpu) max_cpu = $10 + 0
        sum_agent += $11
        if ($11 + 0 > max_agent) max_agent = $11 + 0
        if ($12 + 0 > max_load) max_load = $12 + 0
        tmp = $6
    } END {
        if (!n) { print "khong co du lieu"; exit }
        printf "%.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f %.2f %.1f %d\n",
            sum_avail / n, min_avail, max_rss, max_hwm, max_tcpdump,
            sum_cpu / n, max_cpu, sum_agent / n, max_agent, max_load, tmp, n
    }' "$1"
}

if [ "$LABEL" = "compare" ]; then
    BASE="$DIR/sdc_monitor_baseline.csv"
    RUN="$DIR/sdc_monitor_running.csv"
    if [ ! -f "$BASE" ] || [ ! -f "$RUN" ]; then
        echo "can do baseline va running truoc"
        exit 1
    fi
    summary "$BASE" >/tmp/sdc_monitor_a.txt
    summary "$RUN" >/tmp/sdc_monitor_b.txt
    awk 'NR == FNR { for (i = 1; i <= NF; i++) a[i] = $i; next }
    {
        split("MemAvailable_TB_MB MemAvailable_thap_nhat_MB Agent_RSS_max_MB Agent_RSS_dinh_MB tcpdump_RSS_max_MB CPU_router_TB_% CPU_router_max_% Agent_CPU_TB_%_1core Agent_CPU_max_%_1core Load_max tmp_dung_MB so_mau", name, " ")
        printf "%-28s %12s %12s %12s\n", "chi_so", "binh_thuong", "chay_model", "chenh_lech"
        for (i = 1; i <= NF; i++) printf "%-28s %12s %12s %12.2f\n", name[i], a[i], $i, $i - a[i]
    }' /tmp/sdc_monitor_a.txt /tmp/sdc_monitor_b.txt
    rm -f /tmp/sdc_monitor_a.txt /tmp/sdc_monitor_b.txt
    exit 0
fi

OUTPUT="$DIR/sdc_monitor_$LABEL.csv"
echo "time,mem_avail_mb,mem_free_mb,cached_mb,shmem_mb,tmp_used_mb,agent_rss_mb,agent_peak_mb,tcpdump_rss_mb,cpu_pct,agent_cpu_pct,load1" >"$OUTPUT"

cpu_ticks() {
    awk '/^cpu /{ print $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9, $5 + $6; exit }' /proc/stat
}

find_pid() {
    for entry in /proc/[0-9]*; do
        if [ "$(cat "$entry/comm" 2>/dev/null)" = "$1" ]; then
            echo "${entry#/proc/}"
            return
        fi
    done
}

proc_ticks() {
    [ -n "$1" ] && [ -r "/proc/$1/stat" ] && awk '{ print $14 + $15 }' "/proc/$1/stat" 2>/dev/null
}

proc_memory() {
    if [ -n "$1" ] && [ -r "/proc/$1/status" ]; then
        awk '/^VmRSS:/{ r = $2 } /^VmHWM:/{ h = $2 } END { printf "%.1f %.1f\n", r / 1024, h / 1024 }' "/proc/$1/status" 2>/dev/null
    else
        echo "0 0"
    fi
}

set -- $(cpu_ticks)
PREV_TOTAL=$1
PREV_IDLE=$2
PREV_UPTIME=$(awk '{ print $1 }' /proc/uptime)
PREV_AGENT=""
END=$(($(date +%s) + DURATION))

printf "%-8s %8s %8s %8s %7s %8s %8s %8s %6s %7s %5s\n" gio avail_MB shmem_MB tmp_MB rss_MB dinh_MB tcpd_MB cpu_% agent% load
while [ "$(date +%s)" -lt "$END" ]; do
    sleep "$INTERVAL"
    AGENT_PID=$(find_pid sdc_agent)
    TCPDUMP_PID=$(find_pid tcpdump)

    set -- $(awk '/^MemAvailable:/{ a = $2 } /^MemFree:/{ f = $2 } /^Cached:/{ c = $2 } /^Shmem:/{ s = $2 }
        END { printf "%.1f %.1f %.1f %.1f\n", a / 1024, f / 1024, c / 1024, s / 1024 }' /proc/meminfo)
    AVAIL=$1 FREE=$2 CACHED=$3 SHMEM=$4
    TMP_USED=$(df -k /tmp | awk 'NR == 2 { printf "%.1f", $3 / 1024 }')
    set -- $(proc_memory "$AGENT_PID")
    RSS=$1 PEAK=$2
    set -- $(proc_memory "$TCPDUMP_PID")
    TCPDUMP_RSS=$1

    set -- $(cpu_ticks)
    TOTAL=$1 IDLE=$2
    UPTIME=$(awk '{ print $1 }' /proc/uptime)
    AGENT_NOW=$(proc_ticks "$AGENT_PID")
    set -- $(awk -v t="$TOTAL" -v pt="$PREV_TOTAL" -v i="$IDLE" -v pi="$PREV_IDLE" -v u="$UPTIME" -v pu="$PREV_UPTIME" \
        -v a="${AGENT_NOW:-0}" -v pa="${PREV_AGENT:-${AGENT_NOW:-0}}" -v hz="$HZ" 'BEGIN {
            dt = t - pt; cpu = dt > 0 ? 100 * (dt - (i - pi)) / dt : 0
            du = u - pu; agent = du > 0 ? 100 * (a - pa) / (hz * du) : 0
            printf "%.1f %.1f\n", cpu, agent
        }')
    CPU=$1 AGENT_CPU=$2
    PREV_TOTAL=$TOTAL PREV_IDLE=$IDLE PREV_UPTIME=$UPTIME PREV_AGENT=$AGENT_NOW
    LOAD=$(awk '{ print $1 }' /proc/loadavg)
    NOW=$(date +%H:%M:%S)

    echo "$NOW,$AVAIL,$FREE,$CACHED,$SHMEM,$TMP_USED,$RSS,$PEAK,$TCPDUMP_RSS,$CPU,$AGENT_CPU,$LOAD" >>"$OUTPUT"
    printf "%-8s %8s %8s %8s %7s %8s %8s %8s %6s %7s %5s\n" "$NOW" "$AVAIL" "$SHMEM" "$TMP_USED" "$RSS" "$PEAK" "$TCPDUMP_RSS" "$CPU" "$AGENT_CPU" "$LOAD"
done

set -- $(summary "$OUTPUT")
echo "--- $LABEL: $OUTPUT ---"
echo "MemAvailable TB/thap nhat: $1 / $2 MB; agent RSS max/dinh: $3 / $4 MB; tcpdump RSS max: $5 MB"
echo "CPU router TB/max: $6 / $7 %; agent CPU TB/max: $8 / $9 % cua 1 core; load max: ${10}"
