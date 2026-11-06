"""Phát lại observation thật để so các chính sách dừng phiên sau khi thiết bị join.

Mỗi lần join (DISCOVER, hoặc REQUEST có option 50) mở phiên tối đa HORIZON giây. Record của cùng MAC
trong khoảng đó được ghép lại, rồi chạy model gốc tại mỗi mốc STEP giây. Mốc tham chiếu là kết quả
lúc HORIZON giây, tức chiến lược chờ đủ 5 phút.

Cách dùng: python replay_policy.py <full.onnx> <device_labels.csv hoặc -> <observations.jsonl ...>
"""
import collections
import csv
import datetime as dt
import json
import statistics
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, r"D:\01.AI_Security\02.SDC\Code")
from test_release_observations import COLUMNS, feature_row  # noqa: E402

ort.set_default_logger_severity(3)
SOURCES = ("dhcp", "dns", "mdns", "tls")
HORIZON = 300
STEP = 5
UNKNOWN = "__unknown__"
TYPE_ALIAS = {"Smartphone": "Smartphone/Tablet", "Tablet": "Smartphone/Tablet"}


def stamp(record):
    return dt.datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).timestamp()


def is_join(record):
    if record.get("message_type") == 1:
        return True
    return record.get("message_type") == 3 and any(o.get("code") == 50 for o in record.get("options", []))


def load_sessions(paths):
    per_mac = collections.defaultdict(list)
    names = {}
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            names[row["mac"]] = row.get("hostname") or names.get(row["mac"], "")
            for source in SOURCES:
                for record in row[source]:
                    per_mac[row["mac"]].append((stamp(record), source, record))

    sessions = []
    for mac, items in per_mac.items():
        items.sort(key=lambda item: item[0])
        last_start = None
        for moment, source, record in items:
            if source != "dhcp" or not is_join(record):
                continue
            if last_start is not None and moment - last_start < HORIZON:
                continue
            last_start = moment
            sessions.append({"mac": mac, "hostname": names[mac], "start": moment,
                             "items": [(t - moment, s, r) for t, s, r in items if 0 <= t - moment <= HORIZON]})
    return sessions


class Model:
    def __init__(self, path):
        self.session = ort.InferenceSession(path)
        self.cache = {}

    def labels(self, session, limit):
        observation = {"mac": session["mac"], "hostname": session["hostname"], **{s: [] for s in SOURCES}}
        for offset, source, record in session["items"]:
            if offset <= limit:
                observation[source].append(record)
        row = feature_row(observation)
        key = tuple(row[c] for c in COLUMNS)
        if key not in self.cache:
            out = self.session.run(["output"], {"input": np.array([list(key)], dtype=object)})[0][0]
            self.cache[key] = tuple(str(v) for v in out)
        return self.cache[key]


def first_all_sources(session):
    seen = {}
    for offset, source, _ in session["items"]:
        seen.setdefault(source, offset)
    return max(seen.values()) if len(seen) == 4 else None


def decide_all4(trace, session, settle=0):
    reached = first_all_sources(session)
    return HORIZON if reached is None else min(HORIZON, reached + settle)


def decide_stable(trace, session, checks, need_known, minimum=0):
    """Dừng khi nhãn giữ nguyên qua `checks` mốc liên tiếp, sau `minimum` giây."""
    run = 0
    previous = None
    reached = first_all_sources(session)
    for moment in sorted(trace):
        labels = trace[moment]
        run = run + 1 if labels == previous else 1
        previous = labels
        if need_known == "make_type":
            known = labels[0] != UNKNOWN and labels[1] != UNKNOWN
        elif need_known == "all":
            known = UNKNOWN not in labels
        elif need_known == "all_or_sources":
            known = UNKNOWN not in labels or (reached is not None and moment >= reached)
        else:
            known = True
        if moment >= minimum and run >= checks and known:
            return moment
    return HORIZON


def load_truth(path):
    if path == "-" or not Path(path).is_file():
        return {}
    truth = {}
    for row in csv.DictReader(open(path, encoding="utf-8-sig")):
        lowered = {k.lower(): v for k, v in row.items()}
        mac = (lowered.get("mac") or "").lower()
        if mac and all(k in lowered for k in ("make", "type", "model")):
            truth[mac] = (lowered["make"], TYPE_ALIAS.get(lowered["type"], lowered["type"]), lowered["model"])
    return truth


def main(model_path, truth_path, paths):
    sessions = load_sessions(paths)
    model = Model(model_path)
    truth = load_truth(truth_path)
    print("phiên join", len(sessions), "MAC", len({s["mac"] for s in sessions}), "MAC có nhãn thật", len(truth))
    have_all = [first_all_sources(s) for s in sessions]
    print("phiên đủ 4 nguồn trong 5 phút:", sum(v is not None for v in have_all))
    lengths = [max((i[0] for i in s["items"]), default=0) for s in sessions]
    print(f"phiên có dữ liệu kéo dài: median={statistics.median(lengths):.0f}s, >=120s: {sum(v >= 120 for v in lengths)}")

    traces = []
    for session in sessions:
        traces.append({t: model.labels(session, t) for t in range(0, HORIZON + 1, STEP)})
    print("số dòng model khác nhau", len(model.cache))

    policies = {
        "Đủ 4 nguồn, chạy ngay (hiện tại)": lambda tr, s: decide_all4(tr, s),
        "Đủ 4 nguồn + chờ 10s": lambda tr, s: decide_all4(tr, s, 10),
        "Đủ 4 nguồn + chờ 30s": lambda tr, s: decide_all4(tr, s, 30),
        "Đủ 4 nguồn + chờ 60s": lambda tr, s: decide_all4(tr, s, 60),
        "Chờ cố định 60s": lambda tr, s: 60,
        "Chờ cố định 120s": lambda tr, s: 120,
        "Ổn định 15s, đủ 3 nhãn": lambda tr, s: decide_stable(tr, s, 4, "all"),
        "Ổn định 15s, đủ 3 nhãn hoặc đủ 4 nguồn": lambda tr, s: decide_stable(tr, s, 4, "all_or_sources"),
        "Ổn định 30s, đủ 3 nhãn hoặc đủ 4 nguồn": lambda tr, s: decide_stable(tr, s, 7, "all_or_sources"),
        "Ổn định 30s, có make+type": lambda tr, s: decide_stable(tr, s, 7, "make_type"),
        "Ổn định 60s, bất kể nhãn": lambda tr, s: decide_stable(tr, s, 13, "any"),
        "Chờ đủ 5 phút (tham chiếu)": lambda tr, s: HORIZON,
    }

    report("Mọi phiên", policies, traces, sessions, truth)
    long_pairs = [(t, s) for t, s, n in zip(traces, sessions, lengths) if n >= 120]
    report("Chỉ phiên có dữ liệu >= 120 giây", policies, [t for t, _ in long_pairs], [s for _, s in long_pairs], truth)


def report(title, policies, traces, sessions, truth):
    print(f"\n=== {title}: {len(sessions)} phiên ===")
    print(f"{'chính sách':44} {'TB giây':>7} {'trung vị':>8} {'chạy hết 5p':>11} "
          f"{'khớp 5p':>8} {'mất model':>9} {'có model':>8} {'đúng/nhãn':>10}")
    for name, policy in policies.items():
        times, same, lost, known, correct, labeled = [], 0, 0, 0, 0, 0
        for trace, session in zip(traces, sessions):
            moment = policy(trace, session)
            times.append(moment)
            snapped = min(trace, key=lambda t: abs(t - moment) if t >= moment else 10 ** 9)
            got, final = trace[snapped], trace[HORIZON]
            same += got == final
            lost += got[2] == UNKNOWN and final[2] != UNKNOWN
            known += got[2] != UNKNOWN
            want = truth.get(session["mac"].lower())
            if want:
                labeled += 3
                correct += sum(a == b for a, b in zip(got, want))
        count = len(sessions)
        accuracy = f"{correct / labeled:.1%}" if labeled else "-"
        print(f"{name:44} {statistics.mean(times):7.0f} {statistics.median(times):8.0f} "
              f"{sum(t >= HORIZON for t in times) / count:11.0%} {same / count:8.0%} {lost:9} {known / count:8.0%} {accuracy:>10}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
