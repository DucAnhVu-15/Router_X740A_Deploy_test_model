"""Dựng pcap từ observation thật để kiểm tra toàn bộ đường đi của sdc_agent.

Gói DHCP/DNS/mDNS/TLS được ghi đúng định dạng trên dây, mỗi observation một cửa sổ riêng.
Kết quả mong đợi tính bằng feature_row() của test_release_observations.py và model gốc.
Một nửa ClientHello bị chia thành hai đoạn TCP để kiểm tra phần ghép gói.

Cách dùng: python make_test_pcap.py <full.onnx> <đầu ra.pcap> <đầu ra.jsonl> <window> <observations.jsonl ...>
"""
import json
import random
import struct
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, r"D:\01.AI_Security\02.SDC\Code")
from test_release_observations import COLUMNS, feature_row  # noqa: E402

ort.set_default_logger_severity(3)
BROADCAST = b"\xff" * 6
ROUTER = bytes.fromhex("020000000001")
MDNS_MAC = bytes.fromhex("01005e0000fb")


def mac_bytes(text):
    return bytes.fromhex(text.replace(":", ""))


def ipv4(proto, payload, src, dst):
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    return header + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, payload, flags=0x18):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 1, 5 << 4, flags, 65535, 0, 0) + payload


def frame(src, dst, packet):
    return dst + src + b"\x08\x00" + packet


def dns_name(name):
    out = b""
    for label in name.rstrip(".").encode("utf-8").split(b"."):
        while label:
            out += bytes([min(len(label), 63)]) + label[:63]
            label = label[63:]
    return out + b"\0"


def dhcp(mac, record):
    body = struct.pack(">BBBBIHH", 1, 1, 6, 0, 1234, 0, 0) + b"\0" * 16 + mac + b"\0" * 10 + b"\0" * 192
    body += b"\x63\x82\x53\x63" + bytes([53, 1, 3])
    for code, raw in ((12, str(record.get("hostname") or "").encode("utf-8")),
                      (60, str(record.get("vendor_class_id") or "").encode("utf-8")),
                      (55, bytes(record.get("parameter_request_list") or []))):
        if raw:
            body += bytes([code, len(raw)]) + raw
    return body + b"\xff"


def dns_query(record):
    questions = record.get("questions", [])
    body = struct.pack(">HHHHHH", 7, 0x0100, len(questions), 0, 0, 0)
    for entry in questions:
        body += dns_name(str(entry.get("name", ""))) + struct.pack(">HH", 1, 1)
    return body


def txt_rdata(value):
    out = b""
    for part in str(value).split(";"):
        raw = part.encode("utf-8")[:255]
        out += bytes([len(raw)]) + raw
    return out


def mdns_packet(record):
    sections = [record.get(k, []) for k in ("questions", "answers", "authorities", "additionals")]
    body = struct.pack(">HHHHHH", 0, 0x8400, *[len(s) for s in sections])
    for entry in sections[0]:
        body += dns_name(str(entry.get("name", ""))) + struct.pack(">HH", 12, 1)
    for section in sections[1:]:
        for entry in section:
            rdata = txt_rdata(entry.get("value", ""))
            body += dns_name(str(entry.get("name", ""))) + struct.pack(">HHIH", 16, 1, 120, len(rdata)) + rdata
    return body


def client_hello(record):
    version = int(str(record.get("legacy_version") or "0303"), 16)
    ciphers = [int(c) for c in record.get("cipher_suites") or []]
    extensions = b""
    for name in record.get("server_names") or []:
        raw = str(name).encode("utf-8")
        item = b"\0" + struct.pack(">H", len(raw)) + raw
        extensions += struct.pack(">HH", 0, len(item) + 2) + struct.pack(">H", len(item)) + item
    protocols = record.get("alpn") or []
    if protocols:
        names = b"".join(bytes([len(p.encode())]) + p.encode() for p in protocols)
        extensions += struct.pack(">HH", 16, len(names) + 2) + struct.pack(">H", len(names)) + names
    extensions += struct.pack(">HH", 21, 1600) + b"\0" * 1600  # padding: ép ClientHello dài hơn 1 đoạn TCP
    hello = struct.pack(">H", version) + b"\x11" * 32 + b"\0"
    hello += struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)
    hello += b"\x01\0" + struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def packets(observation, rng):
    mac = mac_bytes(observation["mac"])
    client, server = bytes([192, 168, 1, 10]), bytes([1, 1, 1, 1])
    host = str(observation.get("hostname") or "")
    records = [r for r in observation.get("dhcp", [])
               if r.get("hostname") or r.get("vendor_class_id") or r.get("parameter_request_list")]
    if not any(r.get("hostname") for r in records) and host:
        records.append({"hostname": host})
    for record in records:
        yield frame(mac, BROADCAST, ipv4(17, udp(68, 67, dhcp(mac, record)), bytes(4), b"\xff" * 4))
    for record in observation.get("dns", []):
        yield frame(mac, ROUTER, ipv4(17, udp(rng.randint(1024, 60000), 53, dns_query(record)), client, server))
    for record in observation.get("mdns", []):
        yield frame(mac, MDNS_MAC, ipv4(17, udp(5353, 5353, mdns_packet(record)), client, bytes([224, 0, 0, 251])))
    for index, record in enumerate(observation.get("tls", [])):
        hello = client_hello(record)
        sport = 40000 + index
        if index % 2:
            yield frame(mac, ROUTER, ipv4(6, tcp(sport, 443, 100, hello, 0x10), client, server))
        else:
            cut = 1200
            yield frame(mac, ROUTER, ipv4(6, tcp(sport, 443, 100, hello[:cut], 0x10), client, server))
            yield frame(mac, ROUTER, ipv4(6, tcp(sport, 443, 100 + cut, hello[cut:]), client, server))


def main(model, pcap_path, expected_path, window, sources):
    rng = random.Random(1)
    observations = []
    for source in sources:
        observations += [json.loads(l) for l in Path(source).read_text(encoding="utf-8").splitlines() if l.strip()]
    print("observations", len(observations))
    session = ort.InferenceSession(model)

    with open(pcap_path, "wb") as pcap, open(expected_path, "w", encoding="utf-8") as expected:
        pcap.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 4096 * 16, 1))
        base = 1_800_000_000
        written = 0
        for index, observation in enumerate(observations):
            start = base + index * window
            count = 0
            for packet in packets(observation, rng):
                pcap.write(struct.pack("<IIII", start + 1, count, len(packet), len(packet)) + packet)
                count += 1
            if not count:
                continue
            row = feature_row(observation)
            labels = session.run(["output"], {"input": np.array([[row[c] for c in COLUMNS]], dtype=object)})[0][0]
            expected.write(json.dumps({"index": index, "mac": observation["mac"], "columns": row,
                                       "labels": [str(v) for v in labels]}, ensure_ascii=False) + "\n")
            written += 1
        print("windows", written)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5:])
