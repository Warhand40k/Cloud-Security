"""
Single-command runner for CSE-CIC-IDS2018 multi-day evaluation (Phase 5).
Usage:
    .venv/bin/python scripts/run_csecicids2018_eval.py [--config configs/v2/cse_cic_ids2018_multiday.json]

Records full provenance:
- Git commit hash
- Config hash
- Random seed
- Package versions (NumPy, SciPy, Pandas, STUMPY, scikit-learn)
- Hardware info & execution runtime
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

from experiments.run_timeblock_v2 import evaluate_partition, FEATURE_COLS_CSE

OUTPUT_METRICS_DIR = "results/v2/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v2/predictions"
OUTPUT_FIGURES_DIR = "results/v2/figures"
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

def run_cse_eval(config_path: str = "configs/v2/cse_cic_ids2018_multiday.json"):
    start_time = time.time()
    with open(config_path, "r") as f:
        config = json.load(f)

    cfg_hash = compute_config_hash(config)
    git_hash = get_git_commit()
    seed = config.get("random_seed", 42)
    np.random.seed(seed)

    print("=" * 80)
    print(f"RUNNING CSE-CIC-IDS2018 MULTI-DAY PIPELINE (Git: {git_hash[:8]}, Seed: {seed})")
    print("=" * 80)

    records = []
    blocks = config["blocks"]

    for b in blocks:
        day_name = b["day"]
        file_path = b["file"]
        tr_s = b["train_slice"]
        va_s = b["val_slice"]
        te_s = b["test_slice"]

        print(f"\nProcessing {day_name}...")
        df = pd.read_parquet(file_path)
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

        b_res = evaluate_partition(
            block_name=day_name,
            dataset_name="CSE-CIC-IDS2018",
            X_train=X_train, y_train=y_train,
            X_val=X_val, y_val=y_val,
            X_test=X_test, y_test=y_test,
            timestamps_test=t_test,
            step_sec=float(config.get("window_sec", 60)),
            subseq_len_m=int(config.get("subseq_len_m", 10)),
            seed=seed,
            is_flow_data=False
        )
        records.extend(b_res)

    df_detailed = pd.DataFrame(records)
    det_csv = os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_multiday_results.csv")
    det_json = os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_multiday_results.json")
    df_detailed.to_csv(det_csv, index=False)
    df_detailed.to_json(det_json, orient="records", indent=2)

    # Multi-day summary (Mean and Std across days)
    summary_rows = []
    for model_name, grp in df_detailed.groupby("Model"):
        summary_rows.append({
            "Model": model_name,
            "Type": grp["Type"].iloc[0],
            "F1_Mean": grp["F1"].mean(),
            "F1_Std": grp["F1"].std(),
            "ROC_AUC_Mean": grp["ROC_AUC"].dropna().mean(),
            "PR_AUC_Mean": grp["PR_AUC"].dropna().mean(),
            "Precision_Mean": grp["Precision"].mean(),
            "Recall_Mean": grp["Recall"].mean(),
            "FPR_Mean": grp["FPR"].mean(),
            "Campaign_Recall_Mean": grp["Campaign_Recall"].mean(),
            "MTTD_Detected_Sec_Mean": grp["MTTD_Detected_Sec"].dropna().mean(),
            "Total_Campaigns": int(grp["Total_Campaigns"].sum()),
            "Alerts_Per_1000_Windows_Mean": grp["Alerts_Per_1000_Windows"].mean(),
            "Alerts_Per_Hour_Mean": grp["Alerts_Per_Hour"].mean()
        })
    df_sum = pd.DataFrame(summary_rows)
    sum_csv = os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_multiday_summary.csv")
    sum_json = os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_multiday_summary.json")
    df_sum.to_csv(sum_csv, index=False)
    df_sum.to_json(sum_json, orient="records", indent=2)

    runtime_total = float(time.time() - start_time)
    manifest = {
        "dataset": "CSE-CIC-IDS2018",
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
            "detailed_csv": det_csv,
            "summary_csv": sum_csv
        }
    }
    man_path = os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_manifest.json")
    with open(man_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nExecution finished in {runtime_total:.2f}s.")
    print(f"Saved results to {det_csv} and manifest to {man_path}")
    return df_detailed, df_sum

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/v2/cse_cic_ids2018_multiday.json")
    args = parser.parse_args()
    run_cse_eval(args.config)

