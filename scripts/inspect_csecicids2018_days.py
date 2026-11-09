"""
Inspect multiple CSE-CIC-IDS2018 days:
- Check row counts and truncation issues (e.g. Excel 1,048,575 limit)
- Check timestamps and monotonic order
- Check attacks, classes, and contiguity
"""

import os
import pandas as pd
import numpy as np

FILES = [
    "data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "data/raw/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "data/raw/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
]

def inspect_file(filepath):
    print("=" * 80)
    print(f"FILE: {os.path.basename(filepath)}")
    print("=" * 80)
    
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return
        
    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    print(f"Size on disk: {size_mb:.2f} MB")
    
    # Check total lines using wc -l equivalent or chunk counting
    line_count = 0
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024*16), b''):
            line_count += chunk.count(b'\n')
    print(f"Raw line count (newline count): {line_count:,d}")
    print(f"Exact 1,048,576 rows (Excel limit + 1 header)? {line_count == 1048576 or line_count == 1048575}")
    
    # Read first and last lines
    with open(filepath, 'r', errors='ignore') as f:
        header = f.readline().strip()
        f.seek(max(0, os.path.getsize(filepath) - 2000))
        tail = f.readlines()[-3:]
    print(f"Columns in header: {len(header.split(','))}")
    print("Last lines sample:")
    for t in tail:
        print("  ", t.strip()[:100])
        
    # Read subset with pandas to check label distribution and timestamps
    df = pd.read_csv(filepath, low_memory=False)
    
    # Remove duplicate header rows
    header_mask = df["Timestamp"] == "Timestamp"
    if header_mask.any():
        print(f"Detected {header_mask.sum()} duplicate header rows! Removing...")
        df = df[~header_mask].copy().reset_index(drop=True)
        
    print(f"Data rows after header dedup: {len(df):,d}")
    
    # Labels
    print("\nLabels distribution:")
    labels = df["Label"].value_counts(dropna=False)
    for lbl, cnt in labels.items():
        pct = (cnt / len(df)) * 100
        print(f"  {str(lbl):35s}: {cnt:10,d} ({pct:6.2f}%)")
        
    # Timestamp parsing
    df["dt"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    null_ts = df["dt"].isna().sum()
    print(f"\nUnparseable timestamps: {null_ts}")
    t_min = df["dt"].min()
    t_max = df["dt"].max()
    dur_hrs = (t_max - t_min).total_seconds() / 3600.0
    print(f"Time range: {t_min} to {t_max} ({dur_hrs:.2f} hours)")
    
    # Backward jumps
    diffs = df["dt"].diff().dt.total_seconds()
    jumps = (diffs < 0).sum()
    print(f"Backward time jumps in raw order: {jumps:,d}")
    
    # Attack contiguity
    df_sorted = df.sort_values(by="dt").reset_index(drop=True)
    binary_label = (df_sorted["Label"] != "Benign").astype(int)
    
    run_changes = np.diff(binary_label) != 0
    run_starts = np.insert(run_changes, 0, True)
    run_ids = np.cumsum(run_starts)
    
    df_sorted["run_id"] = run_ids
    run_summary = df_sorted.groupby(["run_id", binary_label]).agg(
        length=("Label", "count"),
        start_time=("dt", "min"),
        end_time=("dt", "max")
    ).reset_index()
    
    attack_runs = run_summary[run_summary["Label"] == 1]
    print(f"\nAttack contiguity:")
    print(f"  Distinct attack episodes: {len(attack_runs):,d}")
    if len(attack_runs) > 0:
        print(f"  Max attack run length (flows): {attack_runs['length'].max():,d}")
        print(f"  Median attack run length: {attack_runs['length'].median():.0f}")
        print(f"  Total attack flows: {attack_runs['length'].sum():,d}")
        print("  Top 3 attack runs:")
        for _, r in attack_runs.sort_values(by="length", ascending=False).head(3).iterrows():
            dur_s = (r["end_time"] - r["start_time"]).total_seconds()
            print(f"    Episode {r['run_id']:4d}: {r['length']:8,d} flows | {r['start_time']} -> {r['end_time']} ({dur_s:.0f}s)")
    print()

if __name__ == "__main__":
    for f in FILES:
        if os.path.exists(f):
            inspect_file(f)
