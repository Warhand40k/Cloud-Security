"""
Single-command runner for UNSW-NB15 evaluation suite (Phase 5).
Usage:
    .venv/bin/python scripts/run_unsw_eval.py [--config configs/v2/unsw_nb15.json]

Evaluates:
1. UNSW Window Realistic Proportion Block
2. UNSW Window Regime Shift Demonstration
3. UNSW Flow Contiguous Block (optimal validation-selected m=5)

Records full provenance:
- Git commit hash
- Config hash
- Random seed
- Package versions
- Hardware info & runtime
- Predictions and scores saved to results/v2/predictions/
- Metrics saved to results/v2/metrics/
"""

import os
import sys
import json
import time
import hashlib
import platform
import subprocess
import argparse
from typing import Optional, Dict, Any, List
import numpy as np
import pandas as pd
import scipy
import sklearn
import stumpy
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from experiments.run_timeblock_v2 import evaluate_partition, FEATURE_COLS_UNSW_WINDOW
from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor

OUTPUT_METRICS_DIR = "results/v3/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v3/predictions"
OUTPUT_FIGURES_DIR = "results/v3/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

def get_git_commit():
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return "unknown"

def compute_config_hash(cfg: dict) -> str:
    s = json.dumps(cfg, sort_keys=True).encode("utf-8")
    return hashlib.sha256(s).hexdigest()

def run_unsw_eval(config_path: str = "configs/v3/unsw_nb15.json"):
    start_time = time.time()
    with open(config_path, "r") as f:
        config = json.load(f)

    cfg_hash = compute_config_hash(config)
    git_hash = get_git_commit()
    seed = config.get("random_seed", 42)
    np.random.seed(seed)

    print("=" * 80)
    print(f"RUNNING UNSW-NB15 EVALUATION PIPELINE (Git: {git_hash[:8]}, Seed: {seed})")
    print("=" * 80)

    records = []
    blocks = config["blocks"]

    # Cache window dataframe if available
    df_win = None

    for b in blocks:
        block_name = b["name"]
        mode = b["mode"]
        subseq_len_m = b.get("subseq_len_m", 10)
        is_flow = b.get("is_flow_data", False)

        print(f"\nProcessing {block_name} (Mode: {mode}, m={subseq_len_m})...")

        if mode == "window":
            if df_win is None:
                df_win = pd.read_parquet(b["file"])

            tr_s = b["train_slice"]
            va_s = b["val_slice"]
            te_s = b["test_slice"]

            tr_df = df_win.iloc[tr_s[0]:tr_s[1]]
            va_df = df_win.iloc[va_s[0]:va_s[1]]
            te_df = df_win.iloc[te_s[0]:te_s[1]]

            scaler = StandardScaler()
            X_train = scaler.fit_transform(np.nan_to_num(tr_df[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
            X_val = scaler.transform(np.nan_to_num(va_df[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
            X_test = scaler.transform(np.nan_to_num(te_df[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))

            y_train = tr_df["Label"].values.astype(int)
            y_val = va_df["Label"].values.astype(int)
            y_test = te_df["Label"].values.astype(int)
            t_test = te_df["window_time"].values
            step_sec = float(b.get("window_sec", 10))

        elif mode == "flow":
            n_samples = b.get("n_samples", 8000)
            df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=15000)
            df_sub = df_raw.iloc[:n_samples].copy().reset_index(drop=True)
            tr_df, va_df, te_df = split_chronological(df_sub, train_frac=0.60, val_frac=0.20, test_frac=0.20)

            prep = UNSWPreprocessor(scaler_type="standard")
            prep.fit(tr_df)
            X_train, y_train = prep.transform(tr_df)
            X_val, y_val = prep.transform(va_df)
            X_test, y_test = prep.transform(te_df)

            time_col = "Stime" if "Stime" in te_df.columns else "stime"
            t_test = te_df[time_col].values
            step_sec = 1.0

        b_res = evaluate_partition(
            block_name=block_name,
            dataset_name="UNSW-NB15",
            X_train=X_train, y_train=y_train,
            X_val=X_val, y_val=y_val,
            X_test=X_test, y_test=y_test,
            timestamps_test=t_test,
            step_sec=step_sec,
            subseq_len_m=subseq_len_m,
            seed=seed,
            is_flow_data=is_flow,
            output_predictions_dir=OUTPUT_PREDICTIONS_DIR
        )
        records.extend(b_res)

    df_results = pd.DataFrame(records)
    res_csv = os.path.join(OUTPUT_METRICS_DIR, "unsw_detailed.csv")
    res_json = os.path.join(OUTPUT_METRICS_DIR, "unsw_detailed.json")
    df_results.to_csv(res_csv, index=False)
    df_results.to_json(res_json, orient="records", indent=2)

    runtime_total = float(time.time() - start_time)
    manifest = {
        "dataset": "UNSW-NB15",
        "git_commit": git_hash,
        "config_hash": cfg_hash,
        "config_path": config_path,
        "random_seed": seed,
        "runtime_seconds": runtime_total,
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hardware": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count()
        },
        "packages": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
            "stumpy": stumpy.__version__
        },
        "outputs": {
            "detailed_csv": res_csv,
            "detailed_json": res_json
        }
    }
    man_path = os.path.join(OUTPUT_METRICS_DIR, "unsw_manifest.json")
    with open(man_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nExecution finished in {runtime_total:.2f}s.")
    print(f"Saved results to {res_csv} and manifest to {man_path}")
    return df_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/v3/unsw_nb15.json")
    args = parser.parse_args()
    run_unsw_eval(args.config)

