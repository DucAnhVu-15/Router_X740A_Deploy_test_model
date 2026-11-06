"""Đối chiếu hai đoạn đã tách với model gốc, từng dòng một (batch = 1 như trên router).

Cách dùng: python verify_split.py <thư mục model> <thư mục Reports> <báo cáo ...>
"""
import csv
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

sys.stdout.reconfigure(encoding="utf-8")
ort.set_default_logger_severity(3)

COLUMNS = ["dhcp_prl", "tls_fp", "tls_version", "tls_alpn", "tls_ciphers", "dhcp_vci", "dns_tokens",
           "mdns_tokens", "tls_sni_tokens", "mac_oui", "dhcp_hostname", "mdns_model"]


def load_rows(paths):
    rows = []
    for path in paths:
        for record in csv.DictReader(open(path, encoding="utf-8-sig")):
            row = {c: record[c] for c in COLUMNS if c != "dhcp_hostname"}
            row["dhcp_hostname"] = record["input_dhcp_hostname"]
            rows.append([row[c] for c in COLUMNS])
            # Cùng dòng khi không có hostname: nhánh else của If.
            rows.append([row[c] if c != "dhcp_hostname" else "<missing>" for c in COLUMNS])
    return rows


def main(model_dir, reports):
    base = Path(model_dir)
    full = ort.InferenceSession(str(base / "sdc_probe_full.onnx"))
    packet = ort.InferenceSession(str(base / "sdc_packet.onnx"))
    tail = ort.InferenceSession(str(base / "sdc_tail.onnx"))
    print("tail inputs", [i.name for i in tail.get_inputs()])

    rows = load_rows(reports)
    bad_packet = bad_tail = 0
    for row in rows:
        x = np.array([row], dtype=object)
        final, packet_out, host = full.run(["output", "sdc/packet_output", "sdc/hn/result"], {"input": x})
        got_packet = packet.run(["sdc/packet_output"], {"input": x})[0]
        got_final = tail.run(["output"], {"input": x, "hn_result": host})[0]
        bad_packet += int(not np.array_equal(got_packet, packet_out))
        bad_tail += int(not np.array_equal(got_final, final))
    print(f"rows={len(rows)} packet_mismatch={bad_packet} tail_mismatch={bad_tail}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
