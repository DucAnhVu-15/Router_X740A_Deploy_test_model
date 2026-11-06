#!/usr/bin/env python
"""Đối chiếu bản đặc trưng viết lại với kết quả test của run, trên chính các pcap lab của tập test.

Pcap gốc chưa trộn nền nên số cửa sổ có thể lệch một ít so với test_per_task.csv. Điều cần xem là
từng kịch bản có cho cùng kết luận không (tỉ lệ cửa sổ báo động, phát hiện hay trượt, đúng lớp).

Cách dùng: python validate_lab.py [số task mỗi kịch bản] [giới hạn MB mỗi pcap]
"""
import sys
import tempfile
import zipfile
from pathlib import Path

import pandas as pd

from pkt_features_ref import RUN_DIR, Model, score_pcap

ZIP = Path(r"D:\01.AI_Security\03.Brute_Force_vs_Recon\Data\real_data.zip")
ATTACKER = "192.168.1.236"


def pcap_name(sample_id, scenario):
    number = sample_id.rsplit("_", 1)[1]
    folder = "brute_force/ssh" if scenario == "ssh" else f"recon/{scenario}"
    return f"real_data/{folder}/pcaps/task_{number}.pcap"


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    per_scenario = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    max_mb = float(sys.argv[2]) if len(sys.argv) > 2 else 20
    tasks = pd.read_csv(RUN_DIR / "test_per_task.csv")
    tasks = tasks[~tasks["scenario"].str.startswith("dos") & ~tasks["sample_id"].str.contains("aug")]
    model = Model()
    archive = zipfile.ZipFile(ZIP)
    sizes = {item.filename: item.file_size for item in archive.infolist()}

    rows = []
    with tempfile.TemporaryDirectory() as work:
        for scenario, group in tasks.groupby("scenario"):
            used = 0
            for task in group.itertuples():
                name = pcap_name(task.sample_id, scenario)
                if name not in sizes or sizes[name] > max_mb * 1e6 or sizes[name] == 0:
                    continue
                path = archive.extract(name, work)
                scored = score_pcap(path, model, hosts=[ATTACKER])
                Path(path).unlink()
                if scored.empty:
                    continue
                majority = scored[scored["alarm"]]["attack_class"].mode()
                rows.append({
                    "sample_id": task.sample_id, "scenario": scenario, "true_class": task[3],
                    "run_attack_w": task.attack_windows, "run_alarm_w": task.alarm_windows,
                    "run_detected": task.detected, "ref_windows": len(scored),
                    "ref_alarm_w": int(scored["alarm"].sum()), "ref_detected": bool(scored["alarm"].any()),
                    "ref_class": majority.iloc[0] if len(majority) else "",
                    "ref_max_score": round(float(scored["score"].max()), 4),
                })
                used += 1
                if used >= per_scenario:
                    break
    result = pd.DataFrame(rows)
    out = Path(__file__).resolve().parent.parent / "build" / "validate_lab.csv"
    result.to_csv(out, index=False)
    summary = result.groupby("scenario").agg(
        tasks=("sample_id", "size"), run_detect=("run_detected", "mean"), ref_detect=("ref_detected", "mean"),
        run_alarm_w=("run_alarm_w", "sum"), run_attack_w=("run_attack_w", "sum"),
        ref_alarm_w=("ref_alarm_w", "sum"), ref_windows=("ref_windows", "sum"),
    )
    summary["class_ok"] = result.assign(ok=lambda f: f["ref_class"] == f["true_class"]).groupby("scenario")["ok"].mean()
    print(summary.round(3).to_string())
    print(f"\nGhi chi tiết: {out}")
    agree = (result["run_detected"] == result["ref_detected"]).mean()
    print(f"Cùng kết luận phát hiện/trượt: {agree:.1%} trên {len(result)} task")


if __name__ == "__main__":
    main()
