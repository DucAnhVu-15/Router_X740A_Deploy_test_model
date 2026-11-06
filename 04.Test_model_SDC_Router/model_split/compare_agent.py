"""So 12 cột và nhãn do sdc_agent in ra với kết quả Python của cùng observation.

Cách dùng: python compare_agent.py <expected.jsonl> <agent.jsonl> <window>
"""
import collections
import datetime as dt
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")
BASE = 1_800_000_000


def main(expected_path, agent_path, window):
    expected = {}
    for line in open(expected_path, encoding="utf-8"):
        item = json.loads(line)
        expected[(item["index"], item["mac"])] = item

    bad_columns = collections.Counter()
    bad_labels = shown = 0
    seen = set()
    for line in open(agent_path, encoding="utf-8"):
        got = json.loads(line)
        moment = dt.datetime.strptime(got["window_start"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        index = round((moment.timestamp() - 1 - BASE) / window)
        key = (index, got["mac"])
        if key not in expected:
            print("thừa", key)
            continue
        seen.add(key)
        want = expected[key]
        for column, value in want["columns"].items():
            if got["columns"][column] != value:
                bad_columns[column] += 1
                if shown < 10:
                    shown += 1
                    print(f"LỆCH {column} mac={got['mac']}\n  agent : {got['columns'][column][:200]}\n  python: {value[:200]}")
        labels = [got["make"], got["type"], got["model"]]
        if labels != want["labels"]:
            bad_labels += 1
            if shown < 10:
                shown += 1
                print("LỆCH nhãn", got["mac"], labels, want["labels"])

    print(f"windows mong đợi={len(expected)} agent trả={len(seen)} thiếu={len(expected) - len(seen)}")
    print("lệch theo cột:", dict(bad_columns) or "không có")
    print("lệch nhãn:", bad_labels)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
