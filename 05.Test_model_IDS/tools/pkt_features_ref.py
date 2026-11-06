#!/usr/bin/env python
"""Chấm một file pcap bằng model IDS, tính đặc trưng theo feature_pipeline_bruteforce_recon_dos.md.

Đây là bản viết lại từ tài liệu, KHÔNG phải pkt_features.py gốc. Điểm tài liệu chưa nói rõ:
độ lệch chuẩn dùng ddof nào (mặc định 0, đổi bằng --ddof).

Cách dùng:
  python pkt_features_ref.py cap.pcap
  python pkt_features_ref.py cap.pcap --out windows.csv --host 192.168.1.236
"""
import argparse
import csv
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd

HERE = Path(__file__).resolve().parent
RUN_DIR = HERE.parent / "model" / "20261105_1550"
TSHARK_WINDOWS = r"C:\Program Files\Wireshark\tshark.exe"

FIELDS = [
    ("frame.time_epoch", "ts"), ("frame.len", "len"), ("eth.src", "eth_src"), ("eth.dst", "eth_dst"),
    ("ip.src", "ip_src"), ("ip.dst", "ip_dst"), ("ip.proto", "ip_proto"), ("ip.ttl", "ttl"),
    ("tcp.srcport", "tcp_sport"), ("tcp.dstport", "tcp_dport"), ("tcp.flags", "tcp_flags"),
    ("tcp.len", "tcp_len"), ("udp.srcport", "udp_sport"), ("udp.dstport", "udp_dport"),
    ("icmp.type", "icmp_type"), ("arp.opcode", "arp_op"), ("arp.src.hw_mac", "arp_sha"),
    ("arp.src.proto_ipv4", "arp_spa"), ("arp.dst.proto_ipv4", "arp_tpa"),
]
KINDS = ["tcp", "syn", "synack", "rst", "fin_only", "null", "xmas", "ack_only", "udp", "icmp_echo",
         "arp_req", "arp_rep"]
CONTEXTS = (60, 300)


def tshark_path():
    return shutil.which("tshark") or TSHARK_WINDOWS


def read_pcap(path, display_filter=None):
    command = [tshark_path(), "-r", str(path), "-n", "-T", "fields", "-E", "occurrence=f",
               "-E", "separator=/t"]
    if display_filter:
        command += ["-Y", display_filter]
    for field, _ in FIELDS:
        command += ["-e", field]
    done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if done.returncode != 0:
        raise RuntimeError(f"tshark lỗi: {done.stderr[-400:]}")
    names = [name for _, name in FIELDS]
    frame = pd.read_csv(io.StringIO(done.stdout), sep="\t", names=names, header=None, dtype=str,
                        keep_default_na=False, quoting=csv.QUOTE_NONE)
    for name in ("ts", "len", "ip_proto", "tcp_sport", "tcp_dport", "tcp_len", "udp_sport", "udp_dport",
                 "icmp_type", "arp_op"):
        frame[name] = pd.to_numeric(frame[name], errors="coerce")
    frame["tcp_flags"] = frame["tcp_flags"].map(lambda text: int(text, 16) if text else np.nan).astype(float)
    # Gói ICMP lỗi mang header TCP/UDP của gói gốc bên trong: không tính là gói TCP/UDP.
    icmp = frame["ip_proto"] == 1
    for name in ("tcp_sport", "tcp_dport", "tcp_flags", "tcp_len", "udp_sport", "udp_dport"):
        frame.loc[icmp, name] = np.nan
    return frame


def packet_table(frame):
    src = frame["ip_src"].where(frame["ip_src"] != "", frame["arp_spa"])
    dst = frame["ip_dst"].where(frame["ip_dst"] != "", frame["arp_tpa"])
    tcp = (frame["ip_proto"] == 6).to_numpy()
    udp = (frame["ip_proto"] == 17).to_numpy()
    icmp = (frame["ip_proto"] == 1).to_numpy()
    flags_raw = frame["tcp_flags"].to_numpy()
    hdr = tcp & ~np.isnan(flags_raw)
    flags = np.nan_to_num(flags_raw, nan=0).astype(np.int64)
    tcp_len = frame["tcp_len"].fillna(0).to_numpy()
    dport = np.where(tcp, frame["tcp_dport"], np.where(udp, frame["udp_dport"], -1.0))
    dport = np.nan_to_num(dport, nan=-1).astype(np.int64)
    table = pd.DataFrame({
        "src": src.to_numpy(), "dst": dst.to_numpy(), "ts": frame["ts"].to_numpy(),
        "len": frame["len"].to_numpy(), "dport": dport,
        "tcp": tcp,
        "syn": hdr & ((flags & 0x12) == 0x02),
        "synack": hdr & ((flags & 0x12) == 0x12),
        "rst": hdr & ((flags & 0x04) != 0),
        "fin_only": hdr & ((flags & 0x17) == 0x01),
        "null": hdr & (flags == 0),
        "xmas": hdr & ((flags & 0x29) == 0x29),
        "ack_only": hdr & (flags == 0x10) & (tcp_len == 0),
        "udp": udp,
        "icmp_echo": icmp & (frame["icmp_type"] == 8).to_numpy(),
        "icmp_unreach": icmp & (frame["icmp_type"] == 3).to_numpy(),
        "arp_req": (frame["arp_op"] == 1).to_numpy(),
        "arp_rep": (frame["arp_op"] == 2).to_numpy(),
    })
    return table.sort_values("ts", kind="stable").reset_index(drop=True)


def previous_index(keys, mask):
    """prev[i] = vị trí lần xuất hiện trước của keys[i] trong các gói mask; -1 nếu lần đầu; n nếu ngoài mask."""
    size = len(keys)
    prev = np.full(size, size, dtype=np.int64)
    where = np.flatnonzero(mask)
    if where.size == 0:
        return prev
    order = where[np.argsort(keys[where], kind="stable")]
    prev[order] = -1
    same = keys[order[1:]] == keys[order[:-1]]
    prev[order[1:][same]] = order[:-1][same]
    return prev


def distinct(prev, low, high):
    return int((prev[low:high] < low).sum())


def new_flags(prev, ts, gap):
    size = len(ts)
    inside = prev < size
    is_new = np.zeros(size, dtype=bool)
    first = inside & (prev < 0)
    is_new[first] = True
    seen = inside & (prev >= 0)
    is_new[seen] = (ts[seen] - ts[prev[seen]]) > gap
    return is_new


def host_windows(tx, rx, config, ddof):
    """Trả về danh sách dict đặc trưng cho một host. tx/rx là DataFrame đã sắp theo thời gian."""
    n_pkt = config["window"]["n_pkt"]
    t_max = config["window"]["t_max"]
    new_gap = config["window"]["new_gap"]
    ts = tx["ts"].to_numpy()
    lengths = tx["len"].to_numpy().astype(float)
    size = len(ts)
    kinds = {kind: tx[kind].to_numpy() for kind in KINDS}
    rx_ts = rx["ts"].to_numpy()
    rx_kinds = {"rst": rx["rst"].to_numpy(), "synack": rx["synack"].to_numpy(),
                "unreach": rx["icmp_unreach"].to_numpy()}

    cum = {kind: np.concatenate([[0], np.cumsum(values)]) for kind, values in kinds.items()}
    cum_bytes = np.concatenate([[0.0], np.cumsum(lengths)])
    rx_cum = {kind: np.concatenate([[0], np.cumsum(values)]) for kind, values in rx_kinds.items()}

    dst_code = pd.factorize(tx["dst"].fillna("").to_numpy())[0].astype(np.int64)
    has_dst = tx["dst"].fillna("").to_numpy() != ""
    dport = tx["dport"].to_numpy()
    has_port = dport >= 0
    pair = dst_code * 65536 + dport
    prev = {
        "dst": previous_index(dst_code, has_dst),
        "pair": previous_index(pair, has_port & has_dst),
        "port": previous_index(dport, has_port),
        "syn_pair": previous_index(pair, kinds["syn"] & has_port & has_dst),
        "arp": previous_index(dst_code, kinds["arp_req"] & has_dst),
        "icmp": previous_index(dst_code, kinds["icmp_echo"] & has_dst),
    }
    is_new = {name: new_flags(prev[name], ts, new_gap) for name in ("dst", "pair", "port")}
    cum_new = {name: np.concatenate([[0], np.cumsum(flags)]) for name, flags in is_new.items()}

    rows = []
    first = 0
    while first < size:
        t_first = ts[first]
        stop = min(int(np.searchsorted(ts, t_first + t_max, side="right")), first + n_pkt)
        count = stop - first
        by_count = count == n_pkt
        t_last = ts[stop - 1]
        t_end = t_last if by_count else t_first + t_max
        duration = t_end - t_first
        gaps = np.diff(ts[first:stop])
        window_len = lengths[first:stop]
        row = {
            "host": tx["src"].iloc[0], "t_first": t_first, "t_end": t_end,
            "f_w_pkts": count, "f_w_by_count": int(by_count), "f_w_dur": duration,
            "f_w_span": t_last - t_first, "f_w_pps": count / max(duration, 0.001),
            "f_w_iat_mean": gaps.mean() if gaps.size else 0.0,
            "f_w_iat_std": gaps.std(ddof=ddof) if gaps.size > ddof else 0.0,
            "f_w_iat_max": gaps.max() if gaps.size else 0.0,
            "f_w_len_mean": window_len.mean(),
            "f_w_len_std": window_len.std(ddof=ddof) if count > ddof else 0.0,
            "f_w_len_min": window_len.min(), "f_w_len_max": window_len.max(),
        }
        for kind in KINDS:
            row[f"f_w_r_{kind}"] = (cum[kind][stop] - cum[kind][first]) / count
        low = int(np.searchsorted(rx_ts, t_first, side="left"))
        high = int(np.searchsorted(rx_ts, t_end, side="right"))
        row["f_w_rx_ratio"] = (high - low) / count
        row["f_w_rx_rst_ratio"] = (rx_cum["rst"][high] - rx_cum["rst"][low]) / count
        row["f_w_rx_synack_ratio"] = (rx_cum["synack"][high] - rx_cum["synack"][low]) / count
        row["f_w_rx_unreach_ratio"] = (rx_cum["unreach"][high] - rx_cum["unreach"][low]) / count
        for name in ("dst", "pair", "port", "syn_pair", "arp", "icmp"):
            row[f"f_w_d_{name}"] = distinct(prev[name], first, stop)
        for name in ("dst", "pair", "port"):
            row[f"f_w_new_{name}_ratio"] = (cum_new[name][stop] - cum_new[name][first]) / count

        for span in CONTEXTS:
            low = int(np.searchsorted(ts, t_end - span, side="right"))
            high = int(np.searchsorted(ts, t_end, side="right"))
            rx_low = int(np.searchsorted(rx_ts, t_end - span, side="right"))
            rx_high = int(np.searchsorted(rx_ts, t_end, side="right"))
            pkts = high - low
            byte_sum = cum_bytes[high] - cum_bytes[low]
            row[f"f_pkts_{span}"] = pkts
            row[f"f_bytes_{span}"] = byte_sum
            for kind in KINDS:
                row[f"f_{kind}_{span}"] = cum[kind][high] - cum[kind][low]
            rx_rst = rx_cum["rst"][rx_high] - rx_cum["rst"][rx_low]
            rx_unreach = rx_cum["unreach"][rx_high] - rx_cum["unreach"][rx_low]
            row[f"f_rx_pkts_{span}"] = rx_high - rx_low
            row[f"f_rx_rst_{span}"] = rx_rst
            row[f"f_rx_synack_{span}"] = rx_cum["synack"][rx_high] - rx_cum["synack"][rx_low]
            row[f"f_rx_icmp_unreach_{span}"] = rx_unreach
            d_values = {name: distinct(prev[name], low, high)
                        for name in ("dst", "pair", "port", "syn_pair", "arp", "icmp")}
            for name, value in d_values.items():
                row[f"f_d_{name}_{span}"] = value
            syn = row[f"f_syn_{span}"]
            row[f"f_syn_ratio_{span}"] = syn / max(row[f"f_tcp_{span}"], 1)
            row[f"f_rx_rst_ratio_{span}"] = rx_rst / max(pkts, 1)
            row[f"f_rx_unreach_ratio_{span}"] = rx_unreach / max(pkts, 1)
            row[f"f_syn_per_pair_{span}"] = syn / max(d_values["syn_pair"], 1)
            row[f"f_port_per_dst_{span}"] = d_values["port"] / max(d_values["dst"], 1)
            row[f"f_bytes_per_pkt_{span}"] = byte_sum / max(pkts, 1)
        rows.append(row)
        first = stop
    return rows


def windows(table, config, hosts=None, ddof=0):
    prefix = config["lan_prefix"]
    source = table["src"].fillna("").to_numpy()
    target = table["dst"].fillna("").to_numpy()
    if hosts:
        chosen = sorted(hosts)
    else:
        chosen = sorted({ip for ip in set(source) if ip.startswith(prefix)})
    rows = []
    for host in chosen:
        tx = table[source == host]
        if len(tx) == 0:
            continue
        rows += host_windows(tx.reset_index(drop=True), table[target == host].reset_index(drop=True), config, ddof)
    return pd.DataFrame(rows)


class Model:
    def __init__(self, run_dir=RUN_DIR):
        self.config = json.loads((Path(run_dir) / "deploy_config.json").read_text(encoding="utf-8"))
        self.session = ort.InferenceSession(str(Path(run_dir) / self.config["onnx"]),
                                            providers=["CPUExecutionProvider"])

    def score(self, frame):
        names = self.config["features"]
        missing = [name for name in names if name not in frame.columns]
        if missing:
            raise ValueError(f"thiếu đặc trưng: {missing[:5]}")
        values = frame[names].to_numpy(dtype=np.float32)
        proba = self.session.run([self.config["output_proba"]], {self.config["input"]: values})[0]
        out = frame.copy()
        classes = self.config["classes"]
        out["score"] = 1 - proba[:, 0]
        out["alarm"] = out["score"] >= self.config["threshold"]
        out["attack_class"] = [classes[index + 1] for index in proba[:, 1:].argmax(axis=1)]
        return out


def episodes(scored, gap):
    rows = []
    for host, group in scored[scored["alarm"]].groupby("host"):
        group = group.sort_values("t_end")
        start = 0
        ends = group["t_end"].to_numpy()
        for index in range(1, len(group) + 1):
            if index == len(group) or ends[index] - ends[index - 1] > gap:
                part = group.iloc[start:index]
                rows.append({"host": host, "start": part["t_end"].iloc[0], "end": part["t_end"].iloc[-1],
                             "windows": len(part), "class": part["attack_class"].mode().iloc[0],
                             "max_score": part["score"].max()})
                start = index
    return pd.DataFrame(rows)


def score_pcap(path, model, hosts=None, ddof=0, display_filter=None):
    frame = read_pcap(path, display_filter)
    if frame.empty:
        return pd.DataFrame()
    result = windows(packet_table(frame), model.config, hosts, ddof)
    return model.score(result) if not result.empty else result


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcap")
    parser.add_argument("--run-dir", default=str(RUN_DIR))
    parser.add_argument("--host", action="append", help="chỉ chấm host này (lặp lại được)")
    parser.add_argument("--filter", help="display filter của tshark")
    parser.add_argument("--ddof", type=int, default=0, choices=(0, 1))
    parser.add_argument("--out", help="ghi mọi cửa sổ ra CSV")
    args = parser.parse_args()

    model = Model(args.run_dir)
    scored = score_pcap(args.pcap, model, args.host, args.ddof, args.filter)
    if scored.empty:
        print("không có cửa sổ nào")
        return 0
    if args.out:
        scored.to_csv(args.out, index=False)
    summary = scored.groupby("host").agg(windows=("alarm", "size"), alarms=("alarm", "sum"),
                                         max_score=("score", "max"))
    print(summary.to_string())
    found = episodes(scored, model.config["episode_gap_s"])
    print("\nĐợt báo động:")
    print(found.to_string(index=False) if not found.empty else "  không có")
    return 0


if __name__ == "__main__":
    sys.exit(main())
