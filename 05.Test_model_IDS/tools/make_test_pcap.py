#!/usr/bin/env python
"""Sinh pcap tổng hợp để kiểm tra ids_agent: nền bình thường xen kẽ flood, quét, quét ARP, phân mảnh.

Dùng để so ids_agent với pkt_features_ref.py. Đây không phải dữ liệu đo chất lượng model.
Cách dùng: python make_test_pcap.py <file ra>
"""
import random
import socket
import struct
import sys

BASE = 1790000000.0
GATEWAY, VICTIM = "192.168.1.1", "192.168.1.182"
ROUTER_MAC, HOST_MAC = bytes.fromhex("dea632c8beff"), bytes.fromhex("50bbb5fed8b8")


def ethernet(kind):
    return HOST_MAC + ROUTER_MAC + struct.pack("!H", kind)


def ipv4(src, dst, proto, payload, offset=0, more=False, total=None):
    size = total if total is not None else 20 + len(payload)
    field = offset | (0x2000 if more else 0)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, size, 1, field, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    return ethernet(0x0800) + head + payload


def tcp(src, dst, sport, dport, flags, payload=b""):
    head = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, flags, 8192, 0, 0)
    return ipv4(src, dst, 6, head + payload)


def udp(src, dst, sport, dport, payload=b""):
    head = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return ipv4(src, dst, 17, head + payload)


def icmp(src, dst, kind, payload=b""):
    return ipv4(src, dst, 1, struct.pack("!BBHHH", kind, 0, 0, 1, 1) + payload)


def arp(src, dst, op):
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, HOST_MAC, socket.inet_aton(src), bytes(6), socket.inet_aton(dst))
    return ethernet(0x0806) + body


def background(out, rng, length):
    time = 0.0
    while time < length:
        time += rng.expovariate(4.0)
        host = rng.choice(["192.168.1.50", "192.168.1.51", "192.168.1.52"])
        far = f"142.250.{rng.randint(1, 3)}.{rng.randint(1, 6)}"
        pick = rng.random()
        if pick < 0.2:
            out.append((time, udp(host, GATEWAY, rng.randint(1024, 65000), 53, bytes(40))))
            out.append((time + 0.01, udp(GATEWAY, host, 53, rng.randint(1024, 65000), bytes(90))))
        elif pick < 0.6:
            out.append((time, tcp(host, far, 44000, 443, 0x18, bytes(rng.randint(50, 900)))))
            out.append((time + 0.02, tcp(far, host, 443, 44000, 0x10)))
        elif pick < 0.8:
            out.append((time, tcp(host, far, rng.randint(1024, 65000), 443, 0x02)))
            out.append((time + 0.02, tcp(far, host, 443, 44000, 0x12)))
        else:
            out.append((time, arp(host, GATEWAY, 1)))
            out.append((time + 0.001, arp(GATEWAY, host, 2)))


def attacks(out, rng):
    attacker = "192.168.1.236"
    for i in range(45000):  # SYN flood, nạn nhân trả lời
        time = 30 + i / 3000
        out.append((time, tcp(attacker, VICTIM, 1024 + i % 60000, 80, 0x02)))
        out.append((time + 0.0002, tcp(VICTIM, attacker, 80, 1024 + i % 60000, 0x12)))
    for i in range(50000):  # UDP flood nhiều port
        time = 120 + i / 5000
        out.append((time, udp(attacker, VICTIM, 40000, rng.randint(1, 65535), bytes(1000))))
        if i % 10 == 0:
            out.append((time + 0.0002, icmp(VICTIM, attacker, 3, bytes(28))))
    for i in range(20000):  # ICMP flood
        time = 200 + i / 2000
        out.append((time, icmp(attacker, VICTIM, 8, bytes(56))))
        out.append((time + 0.0002, icmp(VICTIM, attacker, 0, bytes(56))))
    for i in range(30000):  # ACK flood, nạn nhân RST
        time = 300 + i / 3000
        out.append((time, tcp(attacker, VICTIM, 40001, 443, 0x10)))
        out.append((time + 0.0002, tcp(VICTIM, attacker, 443, 40001, 0x04)))
    scanner = "192.168.1.237"
    for port in range(1, 1001):  # quét SYN
        time = 400 + port / 200
        out.append((time, tcp(scanner, VICTIM, 50000, port, 0x02)))
        out.append((time + 0.0003, tcp(VICTIM, scanner, port, 50000, 0x12 if port in (22, 80) else 0x14)))
    for port in range(1, 301):  # quét FIN, NULL, XMAS
        time = 420 + port / 100
        out.append((time, tcp(scanner, VICTIM, 50001, port, (0x01, 0x00, 0x29)[port % 3])))
    sweeper = "192.168.1.238"
    for last in range(2, 255):  # quét ARP
        out.append((500 + last / 25, arp(sweeper, f"192.168.1.{last}", 1)))
    fragger = "192.168.1.239"
    for i in range(1500):  # gói lớn bị phân mảnh, mảnh sau không có header L4
        time = 600 + i / 100
        head = struct.pack("!HHIIBBHHH", 2000, 443, 1, 1, 0x50, 0x18, 8192, 0, 0)
        out.append((time, ipv4(fragger, VICTIM, 6, head + bytes(1460), more=True)))
        out.append((time + 0.0001, ipv4(fragger, VICTIM, 6, bytes(1480), offset=185)))
        out.append((time + 0.0002, ipv4(fragger, VICTIM, 17, struct.pack("!HHHH", 5000, 53, 2000, 0) + bytes(1472), more=True)))
        out.append((time + 0.0003, ipv4(fragger, VICTIM, 17, bytes(500), offset=185)))


def main():
    rng = random.Random(7)
    packets = []
    background(packets, rng, 720.0)
    attacks(packets, rng)
    packets.sort(key=lambda item: item[0])
    with open(sys.argv[1], "wb") as file:
        file.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for time, frame in packets:
            stamp = BASE + time
            seconds = int(stamp)
            file.write(struct.pack("<IIII", seconds, int(round((stamp - seconds) * 1e6)) % 1000000, len(frame), len(frame)))
            file.write(frame)
    print(f"{len(packets)} gói -> {sys.argv[1]}")


if __name__ == "__main__":
    main()
