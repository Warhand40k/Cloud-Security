"""
Inspection and Day-1 verification script for CSE-CIC-IDS2018 (Friday-16-02-2018).
Checks timestamps, attack block contiguity, and feature distributions.
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime

CSV_PATH = "data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"

def run_csecicids2018_verification():
    print("=" * 80)
    print("CSE-CIC-IDS2018 DAY-1 VERIFICATION REPORT (Friday-16-02-2018)")
    print("=" * 80)

    size_mb = os.path.getsize(CSV_PATH) / (1024 * 1024)
    print(f"File: {os.path.basename(CSV_PATH)} | Size: {size_mb:.2f} MB")

    # Read header and first 10 rows
    sample = pd.read_csv(CSV_PATH, nrows=10)
    print(f"Total columns: {len(sample.columns)}")
    print(f"Column list: {sample.columns.tolist()[:15]} ... (total {len(sample.columns)})")

    # Read full file or large sample
    print("\nLoading dataset (handling embedded headers / invalid rows)...")
    df = pd.read_csv(CSV_PATH, low_memory=False)
    print(f"Total raw rows loaded: {len(df):,d}")

    # Check for repeated header rows
    header_mask = df["Timestamp"] == "Timestamp"
    if header_mask.any():
        print(f"  Detected {header_mask.sum()} duplicate embedded header rows. Removing...")
        df = df[~header_mask].copy().reset_index(drop=True)

    # 1. Label distribution
    print("\n--- 1. Label Distribution ---")
    labels = df["Label"].value_counts(dropna=False)
    for lbl, cnt in labels.items():
        pct = (cnt / len(df)) * 100
        print(f"  {str(lbl):30s}: {cnt:10,d} ({pct:6.2f}%)")

    binary_label = (df["Label"] != "Benign").astype(int)
    df["binary_label"] = binary_label

    # 2. Timestamp analysis
    print("\n--- 2. Timestamp Parsing & Chronology ---")
    # Date format in Friday-16-02-2018 is usually 'dd/MM/yyyy HH:mm:ss'
    print("Parsing timestamps...")
    df["dt"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    null_ts = df["dt"].isna().sum()
    print(f"  Null/unparseable timestamps: {null_ts:,d}")

    t_min = df["dt"].min()
    t_max = df["dt"].max()
    print(f"  Timestamp range: {t_min} to {t_max}")
    duration_hours = (t_max - t_min).total_seconds() / 3600.0
    print(f"  Total duration spanned: {duration_hours:.2f} hours")

    is_sorted = df["dt"].is_monotonic_increasing
    print(f"  Is data monotonically sorted in time? {is_sorted}")
    if not is_sorted:
        diffs = df["dt"].diff().dt.total_seconds()
        jumps = (diffs < 0).sum()
        print(f"  Backward time jumps in raw order: {jumps:,d}")

    # Sort strictly chronologically
    df_sorted = df.sort_values(by="dt").reset_index(drop=True)

    # 3. Attack Episode Contiguity Analysis
    print("\n--- 3. Attack Episode Contiguity (DoS Flooding Analysis) ---")
    lbls = df_sorted["binary_label"].values
    run_changes = np.diff(lbls) != 0
    run_starts = np.insert(run_changes, 0, True)
    run_ids = np.cumsum(run_starts)

    df_sorted["run_id"] = run_ids
    run_summary = df_sorted.groupby(["run_id", "binary_label"]).agg(
        length=("binary_label", "count"),
        start_time=("dt", "min"),
        end_time=("dt", "max")
    ).reset_index()

    attack_runs = run_summary[run_summary["binary_label"] == 1]
    normal_runs = run_summary[run_summary["binary_label"] == 0]

    print(f"  Total distinct attack episodes: {len(attack_runs):,d}")
    print(f"  Attack run lengths (flows per contiguous block):")
    print(f"    Min:    {attack_runs['length'].min():,d}")
    print(f"    Median: {attack_runs['length'].median():.0f}")
    print(f"    Mean:   {attack_runs['length'].mean():.2f}")
    print(f"    Max:    {attack_runs['length'].max():,d}")
    print(f"    Total attack flows: {attack_runs['length'].sum():,d}")

    print("\n  Top Attack Episodes (Chronological Schedule):")
    for idx, row in attack_runs.sort_values(by="length", ascending=False).head(5).iterrows():
        dur_sec = (row["end_time"] - row["start_time"]).total_seconds()
        print(f"    Episode {row['run_id']:4d}: {row['length']:8,d} flows | {row['start_time']} -> {row['end_time']} ({dur_sec:.0f}s / {dur_sec/60:.1f}m)")

    # 4. Window Aggregation Check (60s and 10s intervals)
    print("\n--- 4. Window Aggregation Feasibility (60s vs 10s) ---")
    epoch_sec = (df_sorted["dt"] - pd.Timestamp("1970-01-01")) // pd.Timedelta("1s")
    df_sorted["epoch_sec"] = epoch_sec

    for w_sec in [10, 60]:
        win_id = (epoch_sec // w_sec) * w_sec
        win_agg = df_sorted.groupby(win_id)["binary_label"].agg(["count", "sum"])
        n_wins = len(win_agg)
        atk_wins = (win_agg["sum"] > 0).sum()
        pure_atk_wins = (win_agg["sum"] == win_agg["count"]).sum()
        print(f"  Window {w_sec:2d}s: {n_wins:6,d} active windows | {atk_wins:5,d} attack windows ({atk_wins/n_wins*100:5.2f}%) | {pure_atk_wins:5d} 100% attack windows")

    print("\n" + "=" * 80)
    print("CSE-CIC-IDS2018 VERIFICATION COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_csecicids2018_verification()
