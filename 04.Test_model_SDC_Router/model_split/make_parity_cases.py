"""Sinh bộ test đối chiếu cho bản C++ từ model gốc.

Mỗi dòng ghi 12 cột input, packet_output và kết quả hostname (sdc/hn/result) của model gốc.
Trường ngăn bằng \\x1f, dòng ngăn bằng \\n.
Cách dùng: python make_parity_cases.py <sdc_probe_full.onnx> <hostname_dataset_split.csv> <đầu ra> <số mẫu> <báo cáo ...>
"""
import csv
import random
import sys

import numpy as np
import onnxruntime as ort

sys.stdout.reconfigure(encoding="utf-8")
ort.set_default_logger_severity(3)
csv.field_size_limit(10_000_000)

COLUMNS = ["dhcp_prl", "tls_fp", "tls_version", "tls_alpn", "tls_ciphers", "dhcp_vci", "dns_tokens",
           "mdns_tokens", "tls_sni_tokens", "mac_oui", "dhcp_hostname", "mdns_model"]
HOST, OUI, MDNS = COLUMNS.index("dhcp_hostname"), COLUMNS.index("mac_oui"), COLUMNS.index("mdns_model")
STRONG_MDNS = ["iPhone15,2", "redmi note 10", "vnpt smartbox 3"]
STRONG_OUI = ["44:bb:3b", "a4:f4:c2", "e4:5f:01"]
EDGE_HOSTS = ["<missing>", "", " ", "null", "none", "nan", "<na>", "__unknown__", "NULL", "  None  ",
              "a", "ab", "abc", "x" * 252, "x" * 253, "x" * 254, "x" * 300, "iphone", "iPhone-cua-Minh",
              "điện-thoại-của-minh", "máy tính", "ＩＰＨＯＮＥ", "ß-phone", "desktop-abc123", "laptop-1",
              "galaxy-s25-ultra", "redmi note 10", "mi-10", "android-1234567890abcdef", "tab a8", "俊的iPhone"]


def report_rows(paths):
    rows = []
    for path in paths:
        for record in csv.DictReader(open(path, encoding="utf-8-sig")):
            row = {c: record[c] for c in COLUMNS if c != "dhcp_hostname"}
            row["dhcp_hostname"] = record["input_dhcp_hostname"]
            rows.append([row[c] for c in COLUMNS])
    return rows


def hostnames(path):
    with open(path, encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        column = next(c for c in reader.fieldnames if "host" in c.lower())
        return sorted({r[column] for r in reader if r[column]})


def main(model, dataset, target, sample, reports):
    rng = random.Random(42)
    base = report_rows(reports)
    pool = hostnames(dataset)
    print("hostname pool", len(pool), "report rows", len(base))
    hosts = EDGE_HOSTS + [row[HOST] for row in base] + rng.sample(pool, min(sample, len(pool)))

    rows = []
    for host in hosts:
        row = list(rng.choice(base))
        row[HOST] = host
        chance = rng.random()
        if chance < 0.05:
            row[MDNS] = rng.choice(STRONG_MDNS)
        elif chance < 0.10:
            row[OUI] = rng.choice(STRONG_OUI)
        rows.append(row)

    session = ort.InferenceSession(model)
    names = ["sdc/packet_output", "sdc/hn/result", "output"]
    with open(target, "w", encoding="utf-8", newline="\n") as out:
        for start in range(0, len(rows), 1):
            row = rows[start]
            packet, host, final = session.run(names, {"input": np.array([row], dtype=object)})
            fields = row + [str(v) for v in packet[0]] + [str(v) for v in host[0]] + [str(v) for v in final[0]]
            if any("\x1f" in f or "\n" in f for f in fields):
                raise ValueError("dữ liệu chứa ký tự ngăn")
            out.write("\x1f".join(fields) + "\n")
            if start % 1000 == 0:
                print("done", start, flush=True)
    print("wrote", len(rows))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5:])
