"""
Pre-aggregate 60s windows for Thursday 15-02 and Wednesday 21-02 CSE-CIC-IDS2018.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.windowing import aggregate_csecicids2018_windows

DAYS = [
    ("Thursday-15-02-2018", "data/raw/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv", "data/processed/csecicids2018_thursday_60s_any_attack.parquet"),
    ("Wednesday-21-02-2018", "data/raw/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv", "data/processed/csecicids2018_wednesday_60s_any_attack.parquet")
]

for day_name, raw_path, out_parquet in DAYS:
    if os.path.exists(out_parquet):
        print(f"Already exists: {out_parquet}")
        continue
    print(f"Processing {day_name}...")
    win_df = aggregate_csecicids2018_windows(raw_path, window_sec=60, label_rule="any_attack")
    win_df.to_parquet(out_parquet, index=False)
    print(f"  Saved {len(win_df)} windows to {out_parquet} | Attacks: {win_df['Label'].sum()} ({win_df['Label'].mean()*100:.2f}%)")

print("Done processing CSE-CIC-IDS2018 days.")
