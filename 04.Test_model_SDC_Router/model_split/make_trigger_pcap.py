"""Dựng pcap kịch bản cho chế độ --trigger-dhcp.

  A: join đủ 4 nguồn trong 4 giây                 -> reason=complete, elapsed=4
  B: join, chỉ có DNS                             -> reason=timeout, elapsed=300
  C: có traffic nhưng không có DHCP               -> không có kết quả
  D: chỉ gia hạn lease (ciaddr khác 0)            -> không có kết quả
  A join lại ngay trong thời gian chờ             -> bị bỏ qua
  A join lại sau thời gian chờ, đủ 4 nguồn        -> phiên thứ hai, reason=complete
  E: join ngay trước khi hết file, chỉ có DHCP    -> reason=eof, hoặc timeout nếu có --timeout ngắn

Cách dùng: python make_trigger_pcap.py <đầu ra.pcap>
"""
import random
import struct
import sys

sys.path.insert(0, r"D:\01.AI_Security\04.Test_model_SDC_Router\model_split")
from make_test_pcap import (BROADCAST, MDNS_MAC, ROUTER, client_hello, dhcp, dns_query, frame, ipv4,  # noqa: E402
                            mdns_packet, tcp, udp)

A = bytes.fromhex("3c5ab4000001")
B = bytes.fromhex("3c5ab4000002")
C = bytes.fromhex("3c5ab4000003")
D = bytes.fromhex("3c5ab4000004")
E = bytes.fromhex("3c5ab4000005")
CLIENT, SERVER = bytes([192, 168, 1, 10]), bytes([1, 1, 1, 1])
BASE = 1_800_000_000


def join_packet(mac, name, message=3, ciaddr=bytes(4)):
    record = {"hostname": name, "vendor_class_id": "android-dhcp-14", "parameter_request_list": [1, 3, 6, 15]}
    body = bytearray(dhcp(mac, record))
    body[12:16] = ciaddr
    body[242] = message  # giá trị option 53
    source = ciaddr if ciaddr != bytes(4) else bytes(4)
    return frame(mac, BROADCAST, ipv4(17, udp(68, 67, bytes(body)), source, b"\xff" * 4))


def dns(mac, name="google.com"):
    return frame(mac, ROUTER, ipv4(17, udp(5000, 53, dns_query({"questions": [{"name": name}]})), CLIENT, SERVER))


def mdns(mac):
    packet = mdns_packet({"questions": [{"name": "_googlecast._tcp.local"}]})
    return frame(mac, MDNS_MAC, ipv4(17, udp(5353, 5353, packet), CLIENT, bytes([224, 0, 0, 251])))


def tls(mac):
    hello = client_hello({"legacy_version": "0303", "cipher_suites": [4865, 4866], "alpn": ["h2"],
                          "server_names": ["www.google.com"]})
    return frame(mac, ROUTER, ipv4(6, tcp(40000, 443, 100, hello), CLIENT, SERVER))


SCENARIO = [
    (0, join_packet(A, "phone-a", 1)), (1, join_packet(A, "phone-a", 3)),
    (2, dns(A)), (3, mdns(A)), (4, tls(A)),
    (5, dns(C)), (6, tls(C)),
    (10, join_packet(B, "cam-b", 1)), (20, dns(B)),
    (12, join_packet(D, "laptop-d", 3, bytes([192, 168, 1, 50]))), (13, dns(D)),
    (30, join_packet(A, "phone-a", 1)), (31, dns(A)),
    (200, mdns(C)), (305, mdns(C)), (311, mdns(C)),
    (400, join_packet(A, "phone-a", 1)), (401, dns(A)), (402, mdns(A)), (403, tls(A)),
    (500, join_packet(E, "tablet-e", 1)),
]


def main(path):
    random.seed(1)
    with open(path, "wb") as pcap:
        pcap.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1))
        for offset, packet in sorted(SCENARIO, key=lambda item: item[0]):
            pcap.write(struct.pack("<IIII", BASE + offset, 0, len(packet), len(packet)) + packet)
    print("packets", len(SCENARIO))


if __name__ == "__main__":
    main(sys.argv[1])
