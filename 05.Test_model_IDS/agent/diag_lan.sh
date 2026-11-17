#!/bin/sh
# Tìm xem traffic giữa hai máy trong LAN có đi qua CPU router không, và hiện ra trên interface nào.
# Chỉ đọc thông số và bắt gói thử, không thay đổi cấu hình router.
# Cách dùng: sh diag_lan.sh <IP máy A> <IP máy B> [số giây, mặc định 20]
# Trong lúc chạy, từ máy A vừa ping liên tục máy B, vừa tạo traffic TCP tới B (vd nmap -sT hoặc ssh).
A="$1"
B="$2"
SECS="${3:-20}"
if [ -z "$A" ] || [ -z "$B" ]; then
    echo "cach dung: sh diag_lan.sh <IP may A> <IP may B> [so giay]"
    exit 1
fi
OUT=/tmp/diag_lan
rm -rf "$OUT"
mkdir -p "$OUT"

echo "== cong trong br-lan =="
for port in /sys/class/net/br-lan/brif/*; do
    [ -e "$port" ] && echo "$(basename "$port") port_no=$(printf '%d' "$(cat "$port/port_no")")"
done

echo "== interface =="
for path in /sys/class/net/*; do
    name=$(basename "$path")
    [ "$name" = lo ] && continue
    state=$(cat "$path/operstate" 2>/dev/null)
    driver=$(readlink "$path/device/driver" 2>/dev/null)
    master=$(readlink "$path/master" 2>/dev/null)
    switch=$(cat "$path/phys_switch_id" 2>/dev/null)
    wifi=""
    [ -e "$path/wireless" ] || [ -e "$path/phy80211" ] && wifi="wifi"
    printf "%-14s %-8s driver=%-14s master=%-8s %s %s\n" "$name" "$state" "${driver##*/}" "${master##*/}" \
        "${switch:+switch=$switch}" "$wifi"
done

echo "== switch phan cung =="
if command -v swconfig >/dev/null 2>&1; then
    swconfig list
    for sw in $(swconfig list 2>/dev/null | awk '{ print $2 }'); do
        swconfig dev "$sw" show 2>/dev/null | grep -iE 'enable_vlan|mirror|vlan:|ports:' | head -30
    done
else
    echo "khong co swconfig"
fi

echo "== MAC cua hai may hoc o cong nao (doi chieu port_no o tren) =="
MAC_A=$(awk -v ip="$A" '$1 == ip { print $4 }' /proc/net/arp)
MAC_B=$(awk -v ip="$B" '$1 == ip { print $4 }' /proc/net/arp)
echo "$A mac=${MAC_A:-chua co trong ARP}"
echo "$B mac=${MAC_B:-chua co trong ARP}"
if [ -n "$MAC_A$MAC_B" ]; then
    PATTERN=$(echo "$MAC_A|$MAC_B" | sed 's/^|//; s/|$//')
    if command -v bridge >/dev/null 2>&1; then
        bridge fdb show br br-lan 2>/dev/null | grep -iE "$PATTERN"
    else
        brctl showmacs br-lan 2>/dev/null | grep -iE "port|$PATTERN"
    fi
fi

echo "== tang toc phan cung =="
for key in flow_offloading flow_offloading_hw; do
    value=$(uci -q get "firewall.@defaults[0].$key" 2>/dev/null)
    echo "$key=${value:-khong dat}"
done
lsmod 2>/dev/null | grep -iE 'hnat|hw_nat|wed|warp|mtk|mt7|nss|ecm|ppe|sfe|fast|offload|qca' | awk '{ print "module: " $1 }'
for path in /sys/kernel/debug/hnat /proc/mtketh /proc/hnat /proc/sys/net/netfilter/nf_flowtable_tcp_timeout; do
    [ -e "$path" ] && echo "co: $path"
done

echo "== bat thu $SECS s tren moi interface: $A <-> $B =="
echo ">>> NGAY BAY GIO tren may $A chay: ping -t $B   va   nmap -Pn -n -sT -p 1-500 $B"
PIDS=""
IFACES=""
for path in /sys/class/net/*; do
    name=$(basename "$path")
    [ "$name" = lo ] && continue
    [ "$(cat "$path/operstate" 2>/dev/null)" = down ] && continue
    tcpdump -i "$name" -n -q -l -s 96 "host $A and host $B" >"$OUT/$name.txt" 2>/dev/null &
    PIDS="$PIDS $!"
    IFACES="$IFACES $name"
done
sleep "$SECS"
kill $PIDS 2>/dev/null
sleep 1

# In: file bắt gói. Ra: "A->B B->A tcp" (tcp tính cả hai chiều).
count() {
    awk -v a="$A" -v b="$B" '
    {
        for (i = 1; i <= NF; i++) if ($i == ">") break
        if (i > NF) next
        split($(i - 1), s, "."); split($(i + 1), d, "[.:]")
        src = s[1] "." s[2] "." s[3] "." s[4]; dst = d[1] "." d[2] "." d[3] "." d[4]
        if (src == a && dst == b) ab++; else if (src == b && dst == a) ba++; else next
        if ($0 ~ /: tcp /) tcp++
    }
    END { printf "%d %d %d\n", ab, ba, tcp }' "$1"
}

printf "%-14s %8s %8s %8s\n" interface "A->B" "B->A" "tcp"
SEEN=""
BR_AB=0
BR_BA=0
for name in $IFACES; do
    set -- $(count "$OUT/$name.txt")
    if [ "$name" = br-lan ]; then
        BR_AB=$1
        BR_BA=$2
    fi
    if [ "$1" -gt 0 ] || [ "$2" -gt 0 ] || [ "$name" = br-lan ]; then
        printf "%-14s %8s %8s %8s\n" "$name" "$1" "$2" "$3"
    fi
    if [ "$name" != br-lan ] && { [ "$1" -gt 0 ] || [ "$2" -gt 0 ]; }; then
        SEEN="$SEEN $name"
    fi
done
rm -rf "$OUT"

if [ "$BR_AB" -gt 0 ] && [ "$BR_BA" -gt 0 ]; then
    echo "KET LUAN: br-lan thay ca hai chieu -> IDS thay duoc cap may nay."
    echo "          Neu cot tcp cua br-lan it hon interface khac nhieu, tang toc phan cung dang lay mat luong TCP."
elif [ -n "$SEEN" ]; then
    echo "KET LUAN: br-lan khong thay du, nhung CPU van thay tren:$SEEN"
    echo "          Goi duoc chuyen thang trong driver (thuong la 2 may cung Wi-Fi). Can bat goi tren interface nay."
else
    echo "KET LUAN: khong interface nao thay -> chip switch hoac tang toc Wi-Fi chuyen goi thang, CPU khong thay."
    echo "          (Kiem tra lai: may $A co thuc su dang ping/nmap may $B trong luc bat khong.)"
fi
