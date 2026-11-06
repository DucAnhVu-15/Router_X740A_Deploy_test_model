#!/usr/bin/env python
"""So ids_agent (ARM qua QEMU) với pkt_features_ref.py trên từng cửa sổ và từng đặc trưng.

Cách dùng: python compare_agent.py <pcap> [<pcap> ...]
           python compare_agent.py --lab 4      lấy 4 pcap lab nhỏ mỗi kịch bản từ real_data.zip
"""
import subprocess
import sys
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from pkt_features_ref import RUN_DIR, Model, score_pcap
from validate_lab import ZIP, pcap_name

PROJECT = Path(__file__).resolve().parent.parent
TEST = PROJECT / "build" / "test"
SCRIPT = "/mnt/d/01.AI_Security/Router_X740_A/05.Test_model_IDS/toolchain/test_agent.sh"


def to_wsl(path):
    text = str(Path(path).resolve()).replace("\\", "/")
    return f"/mnt/{text[0].lower()}{text[2:]}"


def lab_pcaps(per_scenario, max_mb=8):
    tasks = pd.read_csv(RUN_DIR / "test_per_task.csv")
    tasks = tasks[~tasks["scenario"].str.startswith("dos") & ~tasks["sample_id"].str.contains("aug")]
    archive = zipfile.ZipFile(ZIP)
    sizes = {item.filename: item.file_size for item in archive.infolist()}
    paths = []
    for scenario, group in tasks.groupby("scenario"):
        used = 0
        for sample in group["sample_id"]:
            name = pcap_name(sample, scenario)
            if name not in sizes or not 1000 < sizes[name] < max_mb * 1e6:
                continue
            target = TEST / "lab" / f"{sample}.pcap"
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
            paths.append(target)
            used += 1
            if used >= per_scenario:
                break
    return paths


def compare(path, model):
    output = TEST / f"{Path(path).stem}.agent.csv"
    done = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--exec", "bash", SCRIPT, to_wsl(path), to_wsl(output)],
                          capture_output=True, text=True)
    if "agent_exit=0" not in done.stdout:
        raise RuntimeError(f"{path}: {done.stdout[-300:]} {done.stderr[-300:]}")
    agent = pd.read_csv(output)
    reference = score_pcap(path, model)
    names = model.config["features"]
    agent["key"] = agent["host"] + "|" + agent["t_first"].round(3).astype(str)
    reference = reference.copy()
    reference["key"] = reference["host"] + "|" + reference["t_first"].round(3).astype(str)
    joined = agent.merge(reference, on="key", suffixes=("_a", "_r"))
    size = len(joined)
    gap = np.abs(joined[[f"{name}_a" for name in names]].to_numpy(float) -
                 joined[[f"{name}_r" for name in names]].to_numpy(float))
    scale = np.maximum(np.abs(joined[[f"{name}_r" for name in names]].to_numpy(float)), 1e-3)
    bad = gap / scale > 1e-3
    worst = pd.Series(bad.sum(axis=0), index=names).sort_values(ascending=False).head(4)
    return {
        "pcap": Path(path).stem, "w_agent": len(agent), "w_ref": len(reference), "matched": size,
        "bad_windows": int(bad.any(axis=1).sum()),
        "score_max_diff": round(float(np.abs(joined["score_a"] - joined["score_r"]).max()), 4) if size else 0,
        "alarm_agent": int(agent["alarm"].sum()), "alarm_ref": int(reference["alarm"].sum()),
        "alarm_diff": int((joined["alarm_a"].astype(bool) != joined["alarm_r"].astype(bool)).sum()),
        "worst": ",".join(f"{name}:{count}" for name, count in worst.items() if count),
    }


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    arguments = sys.argv[1:]
    paths = lab_pcaps(int(arguments[1])) if arguments[:1] == ["--lab"] else arguments
    model = Model()
    TEST.mkdir(parents=True, exist_ok=True)
    rows = [compare(path, model) for path in paths]
    table = pd.DataFrame(rows)
    pd.set_option("display.width", 220, "display.max_colwidth", 90)
    print(table.to_string(index=False))
    print(f"\nTổng: {table['matched'].sum()} cửa sổ khớp được, lệch đặc trưng {table['bad_windows'].sum()}, "
          f"lệch báo động {table['alarm_diff'].sum()}")


if __name__ == "__main__":
    main()
