"""Sinh bộ test đối chiếu cho bản C++ từ model gốc, dùng bộ input cố định (không cần dataset).

Input: file mỗi dòng 12 cột (ngăn bằng \\x1f), ví dụ build/test/parity_inputs.txt. File có nhiều hơn
12 trường (như parity_cases.txt cũ) thì chỉ lấy 12 trường đầu.
Thêm vài dòng dùng mDNS/OUI "mạnh" lấy từ contract của model để phủ nhánh ưu tiên mDNS/OUI.

Mỗi dòng ra: 12 cột input, sdc/packet_output, sdc/hn/result, output của model gốc (21 trường).
Cùng lúc kiểm tra sdc_packet.onnx và sdc_tail.onnx (đã tách) cho kết quả giống hệt model gốc, batch = 1
như trên router.

Cách dùng: python make_parity.py <thư mục model tách> <sdc_os.onnx> <parity_inputs.txt> <đầu ra>
"""
import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort

sys.stdout.reconfigure(encoding="utf-8")
ort.set_default_logger_severity(3)

COLUMNS = ["dhcp_prl", "tls_fp", "tls_version", "tls_alpn", "tls_ciphers", "dhcp_vci", "dns_tokens",
           "mdns_tokens", "tls_sni_tokens", "mac_oui", "dhcp_hostname", "mdns_model"]
OUI, MDNS = COLUMNS.index("mac_oui"), COLUMNS.index("mdns_model")
ROWS_PER_STRONG = 10


def load_inputs(path):
    rows = []
    with open(path, encoding="utf-8", newline="\n") as handle:
        for number, line in enumerate(handle, 1):
            fields = line.rstrip("\n").split("\x1f")
            if len(fields) < len(COLUMNS):
                raise ValueError(f"{path}:{number}: cần ít nhất {len(COLUMNS)} trường, thấy {len(fields)}")
            rows.append(fields[:len(COLUMNS)])
    return rows


def contract_of(source):
    meta = {p.key: p.value for p in onnx.load(source, load_external_data=False).metadata_props}
    contract = json.loads(meta["sdc.contract"])
    if contract.get("columns") != COLUMNS:
        raise ValueError(f"thứ tự 12 cột của model khác agent C++:\n  model: {contract.get('columns')}\n"
                         f"  agent: {COLUMNS}")
    if contract.get("heads", ["make", "type", "model"]) != ["make", "type", "model"]:
        raise ValueError(f"heads khác make/type/model: {contract.get('heads')}")
    return contract


def main(model_dir, source, inputs, target):
    base = Path(model_dir)
    contract = contract_of(source)
    host = contract["hostname"]

    rows = load_inputs(inputs)
    rng = random.Random(42)
    extra = 0
    for column, values in ((MDNS, host.get("strong_mdns", [])), (OUI, host.get("strong_oui", []))):
        for value in values:
            for _ in range(ROWS_PER_STRONG):
                row = list(rng.choice(rows))
                row[column] = value
                rows.append(row)
                extra += 1
    print(f"rows {len(rows)} (input {len(rows) - extra}, thêm mDNS/OUI mạnh {extra})", flush=True)

    full = ort.InferenceSession(str(base / "sdc_probe_full.onnx"))
    packet = ort.InferenceSession(str(base / "sdc_packet.onnx"))
    tail = ort.InferenceSession(str(base / "sdc_tail.onnx"))
    names = ["sdc/packet_output", "sdc/hn/result", "output"]

    bad_packet = bad_tail = changed_by_host = 0
    start = time.time()
    with open(target, "w", encoding="utf-8", newline="\n") as out:
        for number, row in enumerate(rows):
            x = np.array([row], dtype=object)
            want_packet, want_host, want_final = full.run(names, {"input": x})
            got_packet = packet.run(["sdc/packet_output"], {"input": x})[0]
            got_final = tail.run(["output"], {"input": x, "hn_result": want_host})[0]
            bad_packet += int(not np.array_equal(got_packet, want_packet))
            bad_tail += int(not np.array_equal(got_final, want_final))
            changed_by_host += int(not np.array_equal(want_packet, want_host))

            fields = row + [str(v) for v in want_packet[0]] + [str(v) for v in want_host[0]] \
                + [str(v) for v in want_final[0]]
            if any("\x1f" in f or "\n" in f for f in fields):
                raise ValueError("dữ liệu chứa ký tự ngăn")
            out.write("\x1f".join(fields) + "\n")
            if number % 2000 == 0:
                print(f"  {number}/{len(rows)}  {time.time() - start:.0f}s", flush=True)

    print(f"wrote {len(rows)} -> {target}")
    print(f"hostname đổi kết quả packet ở {changed_by_host} dòng")
    print(f"split: packet_mismatch={bad_packet} tail_mismatch={bad_tail}")
    if bad_packet or bad_tail:
        raise SystemExit("LỖI: model tách cho kết quả khác model gốc")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    main(*sys.argv[1:])
