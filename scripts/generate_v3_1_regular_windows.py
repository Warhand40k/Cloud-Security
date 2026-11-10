"""
Generate regular 60s window datasets for CSE-CIC-IDS2018 (Thursday, Friday, Wednesday)
with fill_empty_windows=True.
Zero-count telemetry rows are populated for quiescent minutes.
True epoch timestamps and ISO strings are preserved for every window.
"""

import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.windowing import aggregate_csecicids2018_windows

CSE_DAYS = [
    ("Thursday-15-02-2018", "data/raw/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv", "data/processed/csecicids2018_thursday_60s_regular.parquet"),
    ("Friday-16-02-2018", "data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv", "data/processed/csecicids2018_friday_60s_regular.parquet"),
    ("Wednesday-21-02-2018", "data/raw/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv", "data/processed/csecicids2018_wednesday_60s_regular.parquet")
]

def main():
    os.makedirs("data/processed", exist_ok=True)
    for day_name, raw_path, out_parquet in CSE_DAYS:
        print(f"Aggregating {day_name} from {raw_path}...")
        df_win = aggregate_csecicids2018_windows(raw_path, window_sec=60, label_rule="any_attack", fill_empty_windows=True)
        df_win.to_parquet(out_parquet, index=False)
        t_start = pd.to_datetime(df_win["window_time"].iloc[0], unit="s")
        t_end = pd.to_datetime(df_win["window_time"].iloc[-1], unit="s")
        n_empty = (df_win["flow_count"] == 0).sum()
        n_atk = df_win["Label"].sum()
        print(f"  -> Saved {len(df_win)} windows to {out_parquet}")
        print(f"     Time range: {t_start} to {t_end}")
        print(f"     Empty windows: {n_empty} ({n_empty / len(df_win):.2%}) | Attack windows: {n_atk} ({n_atk / len(df_win):.2%})")

    # Also ensure unsw_nb15_10s_any_attack has window_dt
    unsw_p = "data/processed/unsw_nb15_10s_any_attack.parquet"
    if os.path.exists(unsw_p):
        df_unsw = pd.read_parquet(unsw_p)
        if "window_dt" not in df_unsw.columns and "window_time" in df_unsw.columns:
            df_unsw["window_dt"] = pd.to_datetime(df_unsw["window_time"], unit="s").astype(str)
            df_unsw.to_parquet(unsw_p, index=False)
            print("Added window_dt to unsw_nb15_10s_any_attack.parquet")

if __name__ == "__main__":
    main()

