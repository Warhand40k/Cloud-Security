"""
Verification and Day-1 inspection script for raw UNSW-NB15 dataset.
Implements the verification checks from Section 4.1 of README.md.
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime, timezone

RAW_DIR = "data/raw"
FILES = [
    os.path.join(RAW_DIR, f"UNSW-NB15_{i}.csv")
    for i in range(1, 5)
]
FEATURES_FILE = os.path.join(RAW_DIR, "NUSW-NB15_features.csv")

def load_feature_names():
    df_feat = pd.read_csv(FEATURES_FILE, encoding="latin-1")
    col_names = df_feat["Name"].str.strip().tolist()
    return col_names

def run_verification():
    print("=" * 80)
    print("UNSW-NB15 DAY-1 VERIFICATION REPORT")
    print("=" * 80)

    col_names = load_feature_names()
    print(f"Loaded {len(col_names)} feature definitions from schema.")

    # 1. Inspect Files and Row Counts
    total_rows = 0
    file_stats = []

    for fpath in FILES:
        if not os.path.exists(fpath):
            print(f"Error: {fpath} does not exist!")
            return
        size_mb = os.path.getsize(fpath) / (1024 * 1024)
        
        with open(fpath, "rb") as f:
            lines = sum(1 for _ in f)
        total_rows += lines
        file_stats.append((os.path.basename(fpath), size_mb, lines))

    print("\n--- 1. File Statistics ---")
    for name, sz, lines in file_stats:
        print(f"  {name:20s}: {sz:8.2f} MB | {lines:10,d} rows")
    print(f"  {'Total':20s}: {sum(s[1] for s in file_stats):8.2f} MB | {total_rows:10,d} rows")

    # 2. Check Paper Features
    print("\n--- 2. Loading and Validating Data ---")
    paper_features = ["sloss", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", "dloss", "service"]
    missing_paper_features = [f for f in paper_features if f not in [c.lower() for c in col_names]]
    if missing_paper_features:
        print(f"  WARNING: Missing expected paper features: {missing_paper_features}")
    else:
        print(f"  SUCCESS: All 9 paper features present in schema: {paper_features}")

    # Map column names case-insensitively to exact names in col_names
    col_map = {c.lower(): c for c in col_names}
    stime_col = col_map["stime"]
    ltime_col = col_map["ltime"]
    label_col = col_map["label"]
    attack_col = col_map["attack_cat"]

    target_cols = [stime_col, ltime_col, label_col, attack_col]
    for pf in paper_features:
        actual = col_map[pf]
        if actual not in target_cols:
            target_cols.append(actual)

    dfs = []
    print("\nReading raw CSV files into dataframe (selecting target columns)...")
    for fpath in FILES:
        print(f"  Reading {os.path.basename(fpath)}...")
        df = pd.read_csv(
            fpath,
            header=None,
            names=col_names,
            usecols=target_cols,
            low_memory=False,
            encoding="latin-1"
        )
        dfs.append(df)

    full_df = pd.concat(dfs, ignore_index=True)
    print(f"  Total records loaded: {len(full_df):,d}")

    # 3. Timestamp Analysis
    print("\n--- 3. Timestamp Consistency & Chronology ---")
    stimes = full_df[stime_col].astype(np.int64)
    ltimes = full_df[ltime_col].astype(np.int64)
    
    print(f"  Stime null count: {stimes.isna().sum():,d}")
    print(f"  Ltime null count: {ltimes.isna().sum():,d}")
    
    st_min, st_max = int(stimes.min()), int(stimes.max())
    lt_min, lt_max = int(ltimes.min()), int(ltimes.max())
    
    dt_st_min = datetime.fromtimestamp(st_min, timezone.utc)
    dt_st_max = datetime.fromtimestamp(st_max, timezone.utc)
    dt_lt_min = datetime.fromtimestamp(lt_min, timezone.utc)
    dt_lt_max = datetime.fromtimestamp(lt_max, timezone.utc)

    print(f"  Stime range: {st_min} to {st_max} ({dt_st_min} to {dt_st_max} UTC)")
    print(f"  Ltime range: {lt_min} to {lt_max} ({dt_lt_min} to {dt_lt_max} UTC)")
    duration_span_sec = st_max - st_min
    print(f"  Total duration spanned: {duration_span_sec / 3600:.2f} hours ({duration_span_sec / 86400:.2f} days)")

    invalid_order = (stimes > ltimes).sum()
    print(f"  Inverted duration records (Stime > Ltime): {invalid_order:,d}")

    is_sorted = full_df[stime_col].is_monotonic_increasing
    print(f"  Are records strictly sorted chronologically across files? {is_sorted}")
    
    if not is_sorted:
        diffs = full_df[stime_col].diff()
        negative_diffs = (diffs < 0).sum()
        print(f"  Number of backward time jumps in raw concatenation: {negative_diffs:,d}")

    # 4. Class Balance & Attack Categories
    print("\n--- 4. Class Balance & Ground Truth ---")
    label_counts = full_df[label_col].value_counts(dropna=False)
    print("  Binary Label distribution:")
    for lbl, cnt in label_counts.items():
        pct = (cnt / len(full_df)) * 100
        lbl_str = "Normal (0)" if lbl == 0 else ("Attack (1)" if lbl == 1 else str(lbl))
        print(f"    {lbl_str:15s}: {cnt:10,d} ({pct:6.2f}%)")

    print("\n  Attack Category distribution:")
    attack_cats = full_df[attack_col].fillna("Normal").astype(str).str.strip()
    attack_counts = attack_cats.value_counts()
    for cat, cnt in attack_counts.items():
        pct = (cnt / len(full_df)) * 100
        print(f"    {cat:20s}: {cnt:10,d} ({pct:6.2f}%)")

    # Cross-check: label vs attack_cat
    normal_with_attack_cat = ((full_df[label_col] == 0) & (attack_cats != "Normal") & (attack_cats != "")).sum()
    attack_with_normal_cat = ((full_df[label_col] == 1) & ((attack_cats == "Normal") | (attack_cats == ""))).sum()
    print(f"\n  Integrity checks:")
    print(f"    Label=0 but has attack category: {normal_with_attack_cat:,d}")
    print(f"    Label=1 but marked Normal category: {attack_with_normal_cat:,d}")

    # 5. Paper Features Inspection
    print("\n--- 5. Paper's 9 Features Inspection ---")
    for pf in paper_features:
        col_actual = col_map[pf]
        s = full_df[col_actual]
        null_cnt = s.isna().sum()
        dtype = s.dtype
        if dtype == object or str(dtype).startswith("str"):
            missing_dash = (s == "-").sum()
            missing_q = (s == "?").sum()
            unique_cnt = s.nunique()
            top_vals = s.value_counts().head(5).to_dict()
            print(f"  {col_actual:10s} [CATEGORICAL] nulls={null_cnt}, '-'={missing_dash:,d}, '?'={missing_q:,d}, unique={unique_cnt}")
            print(f"             Top values: {top_vals}")
        else:
            print(f"  {col_actual:10s} [NUMERIC] nulls={null_cnt}, min={s.min()}, max={s.max()}, mean={s.mean():.4f}")

    # 6. Temporal Attack Distribution (Interleaved vs. Episodic Analysis)
    print("\n--- 6. Temporal Attack Distribution (Interleaved vs. Episodic Analysis) ---")
    df_sorted = full_df.sort_values(by=[stime_col, ltime_col]).reset_index(drop=True)
    
    labels = df_sorted[label_col].values
    run_changes = np.diff(labels) != 0
    run_starts = np.insert(run_changes, 0, True)
    run_ids = np.cumsum(run_starts)
    
    df_sorted["run_id"] = run_ids
    run_lengths = df_sorted.groupby(["run_id", label_col]).size().reset_index(name="run_length")
    
    attack_runs = run_lengths[run_lengths[label_col] == 1]["run_length"]
    normal_runs = run_lengths[run_lengths[label_col] == 0]["run_length"]
    
    print(f"  Total distinct attack runs (episodes): {len(attack_runs):,d}")
    print(f"  Attack run lengths (flows per run):")
    print(f"    Min:    {attack_runs.min():,d}")
    print(f"    25%:    {attack_runs.quantile(0.25):.0f}")
    print(f"    Median: {attack_runs.median():.0f}")
    print(f"    75%:    {attack_runs.quantile(0.75):.0f}")
    print(f"    Mean:   {attack_runs.mean():.2f}")
    print(f"    Max:    {attack_runs.max():,d}")
    print(f"    Runs with length == 1 flow: {(attack_runs == 1).mean() * 100:.2f}% ({sum(attack_runs == 1):,d} runs)")
    print(f"    Runs with length <= 5 flows: {(attack_runs <= 5).mean() * 100:.2f}%")
    print(f"    Runs with length >= 50 flows: {(attack_runs >= 50).mean() * 100:.2f}%")

    print(f"\n  Normal run lengths (flows per run):")
    print(f"    Min:    {normal_runs.min():,d}")
    print(f"    Median: {normal_runs.median():.0f}")
    print(f"    Mean:   {normal_runs.mean():.2f}")
    print(f"    Max:    {normal_runs.max():,d}")

    # 7. Window Aggregation Check (10s intervals as in base paper)
    print("\n--- 7. Window Aggregation Check (10-second intervals) ---")
    df_sorted["window_10s"] = (df_sorted[stime_col] // 10) * 10
    window_summary = df_sorted.groupby("window_10s").agg(
        flow_count=(label_col, "count"),
        attack_count=(label_col, "sum"),
        has_attack=(label_col, lambda x: (x > 0).any().astype(int))
    ).reset_index()

    total_windows = len(window_summary)
    attack_windows = window_summary["has_attack"].sum()
    normal_windows = total_windows - attack_windows
    
    print(f"  Total 10s windows with traffic: {total_windows:,d}")
    print(f"  Normal windows (0 attacks): {normal_windows:,d} ({normal_windows/total_windows*100:.2f}%)")
    print(f"  Attack windows (>=1 attack): {attack_windows:,d} ({attack_windows/total_windows*100:.2f}%)")
    print(f"  Average flows per 10s window: {window_summary['flow_count'].mean():.2f} (max={window_summary['flow_count'].max():,d})")

    # Check temporal continuity of windows (are there gaps?)
    time_steps = window_summary["window_10s"].diff()
    gaps = time_steps[time_steps > 10]
    print(f"  Number of time gaps > 10s between active windows: {len(gaps):,d}")
    if len(gaps) > 0:
        print(f"  Largest gap: {gaps.max():.0f} seconds ({gaps.max() / 3600:.2f} hours)")

    print("\n" + "=" * 80)
    print("VERIFICATION COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_verification()
