#!/usr/bin/env python
"""Đo kết quả thay đổi bao nhiêu nếu pkt_features.py gốc dùng ddof=1 thay vì ddof=0 cho độ lệch chuẩn."""
import sys
from pathlib import Path

import numpy as np

from pkt_features_ref import Model, score_pcap

TEST = Path(__file__).resolve().parent.parent / "build" / "test"


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    model = Model()
    paths = sorted((TEST / "lab").glob("*.pcap")) + [TEST / "synthetic.pcap"]
    windows = flips = 0
    largest = 0.0
    for path in paths:
        first = score_pcap(path, model, ddof=0)
        second = score_pcap(path, model, ddof=1)
        windows += len(first)
        flips += int((first["alarm"].to_numpy() != second["alarm"].to_numpy()).sum())
        largest = max(largest, float(np.abs(first["score"].to_numpy() - second["score"].to_numpy()).max()))
    print(f"{len(paths)} pcap, {windows} cửa sổ: đổi báo động {flips}, điểm lệch tối đa {largest:.4f}")


if __name__ == "__main__":
    main()
