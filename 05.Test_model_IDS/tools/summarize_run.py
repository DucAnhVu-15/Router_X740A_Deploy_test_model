#!/usr/bin/env python
"""Tóm tắt một lần chạy ids_agent từ file cửa sổ (ids_windows.csv).

Cách dùng: python summarize_run.py ids_windows.csv
"""
import sys

import pandas as pd

EPISODE_GAP = 60


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    windows = pd.read_csv(sys.argv[1], usecols=["host", "t_first", "t_end", "score", "alarm", "attack_class", "infer_us"])
    hours = max((windows["t_end"].max() - windows["t_first"].min()) / 3600, 1e-9)
    alarms = windows[windows["alarm"] == 1].sort_values(["host", "t_end"])
    alarms = alarms.assign(episode=(alarms.groupby("host")["t_end"].diff().fillna(1e9) > EPISODE_GAP).cumsum())
    print(f"thời lượng {hours * 60:.1f} phút, {len(windows)} cửa sổ, {len(alarms)} báo động, "
          f"{alarms['episode'].nunique()} đợt, suy luận TB {windows['infer_us'].mean():.0f} µs")
    table = windows.groupby("host").agg(windows=("score", "size"), alarms=("alarm", "sum"),
                                        score_p99=("score", lambda s: s.quantile(0.99)), score_max=("score", "max"))
    print(table.sort_values("alarms", ascending=False).round(4).to_string())
    if len(alarms):
        print("\nCác đợt báo động:")
        rows = alarms.groupby(["host", "episode"]).agg(
            start=("t_end", "min"), end=("t_end", "max"), windows=("score", "size"),
            cls=("attack_class", lambda s: s.mode().iloc[0]), max_score=("score", "max")).reset_index()
        rows["start"] = pd.to_datetime(rows["start"], unit="s").dt.strftime("%m-%d %H:%M:%S")
        rows["seconds"] = (rows["end"] - alarms.groupby(["host", "episode"])["t_end"].min().to_numpy()).round(1)
        print(rows[["host", "start", "seconds", "windows", "cls", "max_score"]].round(4).to_string(index=False))


if __name__ == "__main__":
    main()
