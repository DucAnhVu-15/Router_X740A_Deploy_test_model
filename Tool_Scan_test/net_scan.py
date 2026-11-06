#!/usr/bin/env python
"""Quét host và cổng trong mạng LAN để kiểm thử lớp 'recon' của model IDS.

Hai pha, như nmap:
  1. Dò host: thử vài cổng phổ biến trên cả dải -> tìm máy đang sống.
  2. Quét cổng: quét dải cổng yêu cầu trên các máy sống.

Dùng TCP connect (socket thường), KHONG can admin. Nguồn ép về card .186 cho khớp test khác.
Chỉ quét dải IP riêng (lab). Đây là tool sinh traffic recon, không khai thác gì.

Cách dùng:
  python net_scan.py 192.168.1.0/24                 # dò host rồi quét cổng 1-1024
  python net_scan.py 192.168.1.0/24 --ports all     # quét toàn bộ 65535 cổng (cham)
  python net_scan.py 192.168.1.27 --ports 1-65535   # quét một máy, mọi cổng
  python net_scan.py 192.168.1.0/24 --discover-only  # chi tim host dang song
"""
import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

DEFAULT_SRC = "192.168.1.186"
DISCOVER_PORTS = [21, 22, 23, 53, 80, 139, 443, 445, 554, 1900, 3389, 8080, 8443, 8000, 9000]
# Vài cổng hay gặp để chế độ 'top' quét nhanh.
TOP_PORTS = DISCOVER_PORTS + [25, 110, 143, 993, 995, 3306, 5432, 5900, 6379, 8888, 37777, 34567, 5000, 1883]


def parse_ports(text):
    if text == "all":
        return range(1, 65536)
    if text == "top":
        return sorted(set(TOP_PORTS))
    ports = set()
    for part in text.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def parse_targets(text):
    if "/" in text:
        return [str(ip) for ip in ipaddress.ip_network(text, strict=False).hosts()]
    if "-" in text.split(".")[-1]:
        head, last = text.rsplit(".", 1)
        lo, hi = last.split("-")
        return [f"{head}.{i}" for i in range(int(lo), int(hi) + 1)]
    return [text]


def check(host, port, timeout, src):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((src, 0))
    except OSError:
        pass
    sock.settimeout(timeout)
    try:
        return host, port, sock.connect_ex((host, port)) == 0
    except OSError:
        return host, port, False
    finally:
        sock.close()


def arp_discover(subnet, src):
    """Dò host bằng ARP (thấy cả máy bật firewall). Cần admin + Npcap. Cũng là traffic recon cho model."""
    try:
        import scapy.all as scapy
        from scapy.all import ARP, Ether
    except ImportError:
        print("Can scapy cho che do ARP: python -m pip install scapy")
        return []
    iface = next((i for i in scapy.get_working_ifaces() if getattr(i, "ip", None) == src), None)
    if iface is None:
        print(f"Khong tim thay card co IP {src}.")
        return []
    answered, _ = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                            iface=iface, timeout=2, verbose=False)
    return [received.psrc for _, received in answered]


def scan(jobs, threads, timeout, src):
    open_ports = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(check, host, port, timeout, src) for host, port in jobs]
        for future in futures:
            host, port, is_open = future.result()
            if is_open:
                open_ports.setdefault(host, []).append(port)
    return open_ports


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="IP, dải CIDR (192.168.1.0/24) hoặc khoảng (192.168.1.1-50)")
    parser.add_argument("--ports", default="1-1024", help="1-1024 | all | top | 22,80,443")
    parser.add_argument("--threads", type=int, default=400)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--src", default=DEFAULT_SRC, help="IP nguồn (card đi ra)")
    parser.add_argument("--discover-only", action="store_true", help="chỉ tìm host sống")
    parser.add_argument("--arp", action="store_true", help="dò host bằng ARP (thấy cả máy firewall; cần admin)")
    parser.add_argument("--skip-discover", action="store_true", help="bỏ qua dò, quét cổng mọi IP trong dải")
    parser.add_argument("--allow-public", action="store_true")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    targets = parse_targets(args.target)
    for host in targets:
        if not (args.allow_public or ipaddress.ip_address(host).is_private):
            print(f"Tu choi: {host} khong phai IP lab (dai rieng). Dung --allow-public neu that su muon.")
            return 2

    start = time.time()
    if len(targets) == 1 or args.skip_discover:
        live = targets
        if args.skip_discover:
            print(f"Bo qua do: quét cổng thẳng {len(targets)} IP.")
    elif args.arp:
        print(f"Pha 1: dò host bằng ARP trên {args.target}...")
        live = sorted(arp_discover(args.target, args.src), key=lambda ip: tuple(int(x) for x in ip.split(".")))
        print(f"  thay {len(live)} host song: {', '.join(live) if live else '(khong co)'}")
    else:
        print(f"Pha 1: do {len(targets)} host tren {len(DISCOVER_PORTS)} cong pho bien (TCP)...")
        jobs = [(host, port) for host in targets for port in DISCOVER_PORTS]
        found = scan(jobs, args.threads, args.timeout, args.src)
        live = sorted(found, key=lambda ip: tuple(int(x) for x in ip.split(".")))
        print(f"  thay {len(live)} host song (may bat firewall co the bi sot; dung --arp de thay het)")
        print(f"  {', '.join(live) if live else '(khong co)'}")

    if args.discover_only or not live:
        print(f"Xong trong {time.time() - start:.1f}s.")
        return 0

    ports = list(parse_ports(args.ports))
    print(f"Pha 2: quét {len(ports)} cổng tren {len(live)} host...")
    jobs = [(host, port) for host in live for port in ports]
    result = scan(jobs, args.threads, args.timeout, args.src)

    print(f"\n=== Ket qua ({time.time() - start:.1f}s, {len(jobs)} ket noi) ===")
    if not result:
        print("Khong thay cong mo nao.")
    for host in sorted(result, key=lambda ip: tuple(int(x) for x in ip.split("."))):
        opened = sorted(result[host])
        print(f"{host}: {len(opened)} cong mo -> {', '.join(map(str, opened))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
