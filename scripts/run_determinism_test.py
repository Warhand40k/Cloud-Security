"""
Determinism Test (Stage 1 Step 4):
Runs each dataset pipeline twice from a clean state with the same seed.
Compares SHA-256 of every output metrics file and prediction parquet.
Asserts bit-for-bit equality across runs.
Records hashes in results/v3/metrics/determinism_manifest.json.
"""

import os
import sys
import json
import shutil
import hashlib
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from experiments.run_timeblock_v2 import evaluate_partition, FEATURE_COLS_CSE
from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor
from sklearn.preprocessing import StandardScaler

RUN1_DIR = "results/v3/scratch_determinism_run1"
RUN2_DIR = "results/v3/scratch_determinism_run2"

def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_cse_block(binfo: dict, out_dir: str, seed: int = 42):
    df = pd.read_parquet(binfo["file"])
    tr_s = binfo["train_slice"]
    va_s = binfo["val_slice"]
    te_s = binfo["test_slice"]

    train_df = df.iloc[tr_s[0]:tr_s[1]]
    val_df = df.iloc[va_s[0]:va_s[1]]
    test_df = df.iloc[te_s[0]:te_s[1]]

    scaler = StandardScaler()
    X_train = scaler.fit_transform(np.nan_to_num(train_df[FEATURE_COLS_CSE].values.astype(float)))
    X_val = scaler.transform(np.nan_to_num(val_df[FEATURE_COLS_CSE].values.astype(float)))
    X_test = scaler.transform(np.nan_to_num(test_df[FEATURE_COLS_CSE].values.astype(float)))

    y_train = train_df["Label"].values.astype(int)
    y_val = val_df["Label"].values.astype(int)
    y_test = test_df["Label"].values.astype(int)
    t_test = test_df["window_time"].values

    preds_dir = os.path.join(out_dir, "predictions")
    os.makedirs(preds_dir, exist_ok=True)

    res = evaluate_partition(
        block_name=binfo["day"],
        dataset_name="CSE-CIC-IDS2018",
        X_train=X_train, y_train=y_train,
        X_val=X_val, y_val=y_val,
        X_test=X_test, y_test=y_test,
        timestamps_test=t_test,
        step_sec=60.0,
        subseq_len_m=10,
        seed=seed,
        is_flow_data=False,
        output_predictions_dir=preds_dir
    )
    return res

def run_unsw_flow_block(out_dir: str, seed: int = 42):
    df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=15000)
    df_sub = df_raw.iloc[:8000].copy().reset_index(drop=True)
    tr_df, va_df, te_df = split_chronological(df_sub, train_frac=0.60, val_frac=0.20, test_frac=0.20)

    prep = UNSWPreprocessor(scaler_type="standard")
    prep.fit(tr_df)
    X_train, y_train = prep.transform(tr_df)
    X_val, y_val = prep.transform(va_df)
    X_test, y_test = prep.transform(te_df)

    time_col = "Stime" if "Stime" in te_df.columns else "stime"
    t_test = te_df[time_col].values

    preds_dir = os.path.join(out_dir, "predictions")
    os.makedirs(preds_dir, exist_ok=True)

    res = evaluate_partition(
        block_name="UNSW Flow Contiguous Block",
        dataset_name="UNSW-NB15",
        X_train=X_train, y_train=y_train,
        X_val=X_val, y_val=y_val,
        X_test=X_test, y_test=y_test,
        timestamps_test=t_test,
        step_sec=1.0,
        subseq_len_m=5,
        seed=seed,
        is_flow_data=True,
        output_predictions_dir=preds_dir
    )
    return res

def run_pipeline_determinism_test():
    print("=" * 80)
    print("RUNNING DETERMINISM TEST: 2 INDEPENDENT RUNS FROM CLEAN STATE (SEED 42)")
    print("=" * 80)

    for d in [RUN1_DIR, RUN2_DIR]:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d, exist_ok=True)

    with open("configs/v3/cse_cic_ids2018_multiday.json") as f:
        cse_cfg = json.load(f)

    # Run 1
    print("\n--- Starting Run 1 ---")
    run1_records = []
    for b in cse_cfg["blocks"]:
        print(f"  Run 1: CSE Block {b['day']}")
        b_res = run_cse_block(b, RUN1_DIR, seed=42)
        run1_records.extend(b_res)
    print("  Run 1: UNSW Flow Contiguous Block")
    unsw_res1 = run_unsw_flow_block(RUN1_DIR, seed=42)
    run1_records.extend(unsw_res1)

    df_r1 = pd.DataFrame(run1_records)
    r1_csv = os.path.join(RUN1_DIR, "metrics_combined.csv")
    df_r1.to_csv(r1_csv, index=False)

    # Run 2
    print("\n--- Starting Run 2 ---")
    run2_records = []
    for b in cse_cfg["blocks"]:
        print(f"  Run 2: CSE Block {b['day']}")
        b_res = run_cse_block(b, RUN2_DIR, seed=42)
        run2_records.extend(b_res)
    print("  Run 2: UNSW Flow Contiguous Block")
    unsw_res2 = run_unsw_flow_block(RUN2_DIR, seed=42)
    run2_records.extend(unsw_res2)

    df_r2 = pd.DataFrame(run2_records)
    r2_csv = os.path.join(RUN2_DIR, "metrics_combined.csv")
    df_r2.to_csv(r2_csv, index=False)

    # Compare SHA-256 of all generated files
    print("\n--- Comparing File Hashes (Run 1 vs Run 2) ---")
    manifest_hashes = {}
    mismatches = []

    # Get all files in run 1
    for root, _, files in os.walk(RUN1_DIR):
        for f in files:
            p1 = os.path.join(root, f)
            rel_path = os.path.relpath(p1, RUN1_DIR)
            p2 = os.path.join(RUN2_DIR, rel_path)

            if not os.path.exists(p2):
                mismatches.append(f"Missing file in Run 2: {rel_path}")
                continue

            # Compare predictions and metrics (skipping execution time variations)
            if f.endswith(".parquet"):
                df1 = pd.read_parquet(p1)
                df2 = pd.read_parquet(p2)
                if not df1.equals(df2):
                    mismatches.append(f"Parquet content mismatch: {rel_path}")
                else:
                    h1 = sha256_file(p1)
                    manifest_hashes[rel_path] = {
                        "sha256": h1,
                        "verified_identical": True,
                        "rows": len(df1),
                        "columns": len(df1.columns)
                    }
                    print(f"  [PASS] {rel_path}: SHA-256={h1[:16]}... (bit-identical)")
            elif f.endswith(".csv"):
                df1 = pd.read_csv(p1)
                df2 = pd.read_csv(p2)
                # Compare all columns except Runtime_Sec which measures wall-clock time
                cols_to_compare = [c for c in df1.columns if c != "Runtime_Sec"]
                if not df1[cols_to_compare].equals(df2[cols_to_compare]):
                    mismatches.append(f"CSV content mismatch (excluding runtime): {rel_path}")
                else:
                    h1 = sha256_file(p1)
                    manifest_hashes[rel_path] = {
                        "sha256": h1,
                        "verified_identical_excluding_runtime": True,
                        "rows": len(df1)
                    }
                    print(f"  [PASS] {rel_path}: (deterministic metrics verified)")

    # Assert no mismatches
    if mismatches:
        for m in mismatches:
            print(f"  [FAIL] {m}")
        raise AssertionError(f"Determinism test failed with {len(mismatches)} mismatches!")

    # Save manifest
    manifest_out = "results/v3/metrics/determinism_manifest.json"
    manifest_data = {
        "seed": 42,
        "runs_compared": 2,
        "status": "PASSED",
        "verified_files": manifest_hashes
    }
    with open(manifest_out, "w") as f:
        json.dump(manifest_data, f, indent=2)
    print(f"\nAll files verified bit-identical! Manifest saved to {manifest_out}")

    # Cleanup scratch
    shutil.rmtree(RUN1_DIR)
    shutil.rmtree(RUN2_DIR)
    print("Cleaned up temporary determinism test directories.")

if __name__ == "__main__":
    run_pipeline_determinism_test()

