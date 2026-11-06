"""Thống kê bộ test đối chiếu: nhánh hostname có thật sự được kiểm tra không."""
import collections
import sys

sys.stdout.reconfigure(encoding="utf-8")
UNKNOWN = "__unknown__"
NAMES = ("make", "type", "model")

rows = [line.rstrip("\n").split("\x1f") for line in open(sys.argv[1], encoding="utf-8", newline="\n")]
print("rows", len(rows), "fields", {len(r) for r in rows})
packet = [r[12:15] for r in rows]
host = [r[15:18] for r in rows]
final = [r[18:21] for r in rows]

print("dòng hostname đổi kết quả packet:", sum(p != h for p, h in zip(packet, host)))
print("dòng tầng OS đổi kết quả hostname:", sum(h != f for h, f in zip(host, final)))
for i, name in enumerate(NAMES):
    changed = sum(p[i] != h[i] for p, h in zip(packet, host))
    filled = sum(p[i] == UNKNOWN and h[i] != UNKNOWN for p, h in zip(packet, host))
    dropped = sum(p[i] != UNKNOWN and h[i] == UNKNOWN for p, h in zip(packet, host))
    distinct = len({h[i] for h in host})
    print(f"{name:6} đổi={changed:6} điền_nhãn={filled:6} bị_xoá={dropped:5} số_nhãn_khác_nhau={distinct}")
print("hostname khác nhau", len({r[10] for r in rows}))
print("mdns mạnh/khác", collections.Counter(r[11] for r in rows).most_common(4))
