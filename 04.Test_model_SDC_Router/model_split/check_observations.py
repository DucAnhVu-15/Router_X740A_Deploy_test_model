"""Đọc observation do sdc_agent ghi (--obs-output) và kiểm tra từng lần suy luận.

Với mỗi dòng: tính lại 12 cột bằng feature_row() của test_release_observations.py (code bên train)
từ các bản ghi dhcp/dns/mdns/tls thô, so với 12 cột agent đã đưa vào model ("inference.columns").
Có --model thì chạy lại model ONNX gốc trên 12 cột của agent và so nhãn.

Cách dùng: python check_observations.py <sdc_observations.jsonl> [--model sdc_os.onnx] [--show N]
"""
import argparse
import collections
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, r"D:\01.AI_Security\02.SDC\Code")
from test_release_observations import COLUMNS, feature_row  # noqa: E402

MAX_RECORDS = 64  # agent và bộ thu thập chỉ giữ 64 bản ghi đầu mỗi nguồn


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("observations")
    parser.add_argument("--model", help="sdc_os.onnx để so nhãn")
    parser.add_argument("--show", type=int, default=10, help="số dòng lệch in chi tiết")
    args = parser.parse_args()

    session = None
    if args.model:
        import numpy as np
        import onnxruntime as ort

        ort.set_default_logger_severity(3)
        session = ort.InferenceSession(args.model)

    rows = shown = bad_rows = bad_labels = capped = 0
    bad_columns = collections.Counter()
    for number, line in enumerate(open(args.observations, encoding="utf-8"), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        rows += 1
        result = item["inference"]
        packets = result["packets"]
        counts = {k: len(item[k]) for k in ("dhcp", "dns", "mdns", "tls")}
        print(f"#{number} {item['mac']} {result['window_start']} {result['reason']:8s} "
              f"{result['make']} | {result['type']} | {result['model']}  "
              f"hostname={item['hostname']!r} dhcp={counts['dhcp']} dns={counts['dns']}/{packets['dns']} "
              f"mdns={counts['mdns']}/{packets['mdns']} tls={counts['tls']}/{packets['tls']}")

        # Quá 64 gói thì agent tính feature trên nhiều gói hơn phần được ghi lại, có thể lệch hợp lệ.
        over = any(packets[k] > MAX_RECORDS for k in ("dhcp", "dns", "mdns", "tls"))
        capped += over
        want = feature_row(item)
        diff = [c for c in COLUMNS if want[c] != result["columns"][c]]
        if diff:
            bad_rows += 1
            bad_columns.update(diff)
            if shown < args.show:
                shown += 1
                for column in diff:
                    print(f"   LỆCH {column}{' (quá 64 gói)' if over else ''}\n"
                          f"     agent : {result['columns'][column][:200]}\n"
                          f"     python: {want[column][:200]}")
        if session is not None:
            matrix = np.array([[result["columns"][c] for c in COLUMNS]], dtype=object)
            labels = [str(v) for v in session.run(["output"], {"input": matrix})[0][0]]
            if labels != [result["make"], result["type"], result["model"]]:
                bad_labels += 1
                print(f"   LỆCH nhãn: model gốc {labels}")

    print(f"\nsố lần suy luận={rows} lệch cột={bad_rows} (có nguồn quá 64 gói: {capped})")
    print("lệch theo cột:", dict(bad_columns) or "không có")
    if session is not None:
        print("lệch nhãn so với model gốc:", bad_labels)


if __name__ == "__main__":
    main()
