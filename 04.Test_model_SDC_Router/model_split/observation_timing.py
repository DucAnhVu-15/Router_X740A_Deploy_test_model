"""Thống kê thời gian trong observation: mỗi nguồn xuất hiện sau bao lâu, đủ 4 nguồn lúc nào.

Cách dùng: python observation_timing.py <observations.jsonl ...>
"""
import collections
import datetime as dt
import json
import statistics
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
SOURCES = ("dhcp", "dns", "mdns", "tls")


def stamp(record):
    text = record.get("timestamp")
    if not text:
        return None
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def main(paths):
    rows = []
    for path in paths:
        rows += [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    print("observations", len(rows), "macs", len({r["mac"] for r in rows}))
    print("mẫu khoá", {s: sorted(rows[0][s][0].keys())[:9] for s in SOURCES if rows[0][s]})

    missing = collections.Counter()
    durations, to_all, combos, first_after = [], [], collections.Counter(), collections.defaultdict(list)
    for row in rows:
        times = {}
        for source in SOURCES:
            values = [stamp(r) for r in row[source]]
            missing[source] += sum(v is None for v in values)
            values = [v for v in values if v is not None]
            if values:
                times[source] = min(values)
        everything = [stamp(r) for s in SOURCES for r in row[s]]
        everything = [v for v in everything if v is not None]
        combos["+".join(s for s in SOURCES if row[s])] += 1
        if not everything:
            continue
        start = min(everything)
        durations.append(max(everything) - start)
        for source, value in times.items():
            first_after[source].append(value - start)
        if len(times) == 4:
            to_all.append(max(times.values()) - start)

    print("record thiếu timestamp", dict(missing))
    print("tổ hợp nguồn", combos.most_common(8))
    q = lambda v, p: sorted(v)[min(len(v) - 1, int(len(v) * p))]
    print(f"thời lượng s: median={statistics.median(durations):.0f} p90={q(durations, .9):.0f} max={max(durations):.0f}")
    for source, values in first_after.items():
        print(f"{source} xuất hiện sau s: n={len(values)} median={statistics.median(values):.1f} p90={q(values, .9):.1f}")
    if to_all:
        print(f"đủ 4 nguồn sau s: n={len(to_all)}/{len(rows)} median={statistics.median(to_all):.1f} p90={q(to_all, .9):.1f}")


if __name__ == "__main__":
    main(sys.argv[1:])
