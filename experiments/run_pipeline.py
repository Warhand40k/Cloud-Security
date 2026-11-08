"""
End-to-end experiment pipeline:
Executes Config A, B1, B2, C, Isolation Forest, and ARIMA-residual baselines
under a unified, strictly chronological, zero-leakage evaluation protocol.
Supports both 'flow' level (per-packet/flow records) and 'window' level (10-second aggregated windows).
"""

import os
import sys
import json
import time
import argparse
from typing import Optional, Dict, Any, List, Tuple
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor
from src.windowing import aggregate_time_windows
from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.adaptive_threshold import MADThreshold, EVTThreshold
from src.persistence_filter import PersistenceFilter
from src.baselines import IsolationForestBaseline, ARIMAResidualBaseline
from src.evaluation import compute_classification_metrics, compute_sre_operational_metrics, ResourceProfiler

OUTPUT_METRICS_DIR = "results/metrics"
OUTPUT_FIGURES_DIR = "results/figures"
PROCESSED_DATA_DIR = "data/processed"

def run_experiments(
    mode: str = "flow",
    n_samples: int = 8000,
    window_sec: int = 10,
    subseq_len_m: int = 50,
    seed: int = 42
):
    os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

    print("=" * 80)
    print(f"RUNNING EXPERIMENT PIPELINE [MODE: {mode.upper()}]")
    print(f"Samples: {n_samples:,d} | Matrix Profile subsequence length m: {subseq_len_m}")
    print("=" * 80)

    # 1. Load Data
    if mode == "window":
        processed_parquet = os.path.join(PROCESSED_DATA_DIR, f"unsw_nb15_{window_sec}s_windows.parquet")
        if os.path.exists(processed_parquet):
            print(f"Loading existing processed windowed data from {processed_parquet}...")
            df_full = pd.read_parquet(processed_parquet)
        else:
            print("Loading raw flows and sorting chronologically...")
            df_raw = load_and_sort_raw_unsw(file_indices=[1, 2, 3, 4])
            print(f"Aggregating {len(df_raw):,d} flows into {window_sec}s windows...")
            df_full = aggregate_time_windows(df_raw, window_sec=window_sec)
            df_full.to_parquet(processed_parquet)
        
        # Take representative slice containing both normal and attack periods
        df_eval = df_full.iloc[:n_samples].copy().reset_index(drop=True)
        time_col = "window_time"
        step_sec = float(window_sec)

    elif mode == "flow":
        print(f"Loading raw sorted flows (taking first {n_samples:,d} flows)...")
        # Load from file 1 which contains initial contiguous simulation session
        df_eval = load_and_sort_raw_unsw(file_indices=[1], nrows=n_samples)
        time_col = "Stime"
        step_sec = 1.0
    else:
        raise ValueError(f"Unknown mode: {mode}")

    total_instances = len(df_eval)
    n_attacks = int(df_eval["Label"].sum())
    attack_ratio = float(n_attacks / total_instances)
    print(f"Evaluation set: {total_instances:,d} instances | Attacks: {n_attacks:,d} ({attack_ratio*100:.2f}%)")

    # 2. Chronological Split (60% Train, 20% Val, 20% Test)
    train_df, val_df, test_df = split_chronological(df_eval, train_frac=0.60, val_frac=0.20, test_frac=0.20)
    print(f"Chronological Splits:")
    print(f"  Train: {len(train_df):,d} | Attacks: {train_df['Label'].sum():,d} ({train_df['Label'].mean()*100:.2f}%)")
    print(f"  Val:   {len(val_df):,d} | Attacks: {val_df['Label'].sum():,d} ({val_df['Label'].mean()*100:.2f}%)")
    print(f"  Test:  {len(test_df):,d} | Attacks: {test_df['Label'].sum():,d} ({test_df['Label'].mean()*100:.2f}%)")

    # 3. Fit Preprocessor on Train Only
    preprocessor = UNSWPreprocessor(scaler_type="standard")
    X_train, y_train = preprocessor.fit_transform(train_df)
    X_val, y_val = preprocessor.transform(val_df)
    X_test, y_test = preprocessor.transform(test_df)

    X_full = np.vstack([X_train, X_val, X_test])
    timestamps_full = df_eval[time_col].values

    n_train = len(train_df)
    n_val = len(val_df)
    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_instances)

    timestamps_test = timestamps_full[test_slice]

    results_table = []

    # =========================================================================
    # CONFIG A: Base Reproduction (mSTAMP + Kneedle)
    # =========================================================================
    print("\n--- Running Config A: Base Reproduction (mSTAMP + Kneedle) ---")
    with ResourceProfiler() as prof_a:
        mps, indices = compute_multidimensional_mp(X_full, m=subseq_len_m)
        knee_dim, knee_info = find_knee_dimension(mps, online=True, metric="max")
        scores_full = compute_point_anomaly_scores(mps, knee_dim=knee_dim, n_samples=total_instances, m=subseq_len_m)

    print(f"  Selected Knee Dimension: {knee_dim} / {X_full.shape[1]}")
    print(f"  Elapsed Time: {prof_a.elapsed_seconds:.2f}s | Peak RAM: {prof_a.peak_mem_mb:.1f} MB")

    scores_val = scores_full[val_slice]
    scores_test = scores_full[test_slice]

    # Baseline validation threshold search (finding optimal threshold on val)
    val_percentiles = np.linspace(80, 99.8, 100)
    best_thresh_a = float(np.median(scores_val))
    best_f1_val_a = -1.0
    for p in val_percentiles:
        th = float(np.percentile(scores_val, p))
        p_val = (scores_val >= th).astype(int)
        f1_v = compute_classification_metrics(y_val, p_val)["f1"]
        if f1_v > best_f1_val_a:
            best_f1_val_a = f1_v
            best_thresh_a = th

    pred_test_a = (scores_test >= best_thresh_a).astype(int)
    cls_a = compute_classification_metrics(y_test, pred_test_a, scores_test)
    sre_a = compute_sre_operational_metrics(y_test, pred_test_a, timestamps_test, default_step_sec=step_sec)

    results_table.append({
        "Configuration": "Config A (mSTAMP + Kneedle)",
        "Type": "Paper Reproduction",
        "Accuracy": cls_a["accuracy"],
        "Precision": cls_a["precision"],
        "Recall": cls_a["recall"],
        "F1": cls_a["f1"],
        "FPR": cls_a["fpr"],
        "PR_AUC": cls_a["pr_auc"],
        "Total_Alerts": sre_a["total_alerts"],
        "False_Alarms_Per_Day": sre_a["false_alarms_per_day"],
        "Episode_Recall": sre_a["episode_recall"],
        "MTTD_Delay_Sec": sre_a["mean_delay_sec"],
        "Runtime_Sec": prof_a.elapsed_seconds,
        "Peak_RAM_MB": prof_a.peak_mem_mb
    })

    # =========================================================================
    # CONFIG B1: Extension - Rolling MAD Adaptive Threshold
    # =========================================================================
    print("\n--- Running Config B1: Adaptive Threshold (Rolling MAD) ---")
    with ResourceProfiler() as prof_b1:
        val_normal_scores = scores_val[y_val == 0]
        if len(val_normal_scores) < 10:
            val_normal_scores = scores_val

        best_c = 3.0
        best_f1_b1 = -1.0
        for c_cand in [1.5, 2.0, 2.5, 3.0, 3.5, 4.0]:
            mad_cand = MADThreshold(c=c_cand, rolling_window=50)
            mad_cand.fit(val_normal_scores)
            pred_v = mad_cand.predict(scores_val)
            f1_v = compute_classification_metrics(y_val, pred_v)["f1"]
            if f1_v > best_f1_b1:
                best_f1_b1 = f1_v
                best_c = c_cand

        mad_model = MADThreshold(c=best_c, rolling_window=50)
        mad_model.fit(val_normal_scores)
        pred_test_b1 = mad_model.predict(scores_test)

    cls_b1 = compute_classification_metrics(y_test, pred_test_b1, scores_test)
    sre_b1 = compute_sre_operational_metrics(y_test, pred_test_b1, timestamps_test, default_step_sec=step_sec)

    results_table.append({
        "Configuration": "Config B1 (Adaptive MAD)",
        "Type": "Our Extension",
        "Accuracy": cls_b1["accuracy"],
        "Precision": cls_b1["precision"],
        "Recall": cls_b1["recall"],
        "F1": cls_b1["f1"],
        "FPR": cls_b1["fpr"],
        "PR_AUC": cls_b1["pr_auc"],
        "Total_Alerts": sre_b1["total_alerts"],
        "False_Alarms_Per_Day": sre_b1["false_alarms_per_day"],
        "Episode_Recall": sre_b1["episode_recall"],
        "MTTD_Delay_Sec": sre_b1["mean_delay_sec"],
        "Runtime_Sec": prof_b1.elapsed_seconds,
        "Peak_RAM_MB": prof_b1.peak_mem_mb
    })

    # =========================================================================
    # CONFIG B2: Extension - EVT Peaks-Over-Threshold (POT)
    # =========================================================================
    print("\n--- Running Config B2: Adaptive Threshold (EVT POT) ---")
    with ResourceProfiler() as prof_b2:
        val_normal_scores = scores_val[y_val == 0]
        if len(val_normal_scores) < 10:
            val_normal_scores = scores_val

        best_risk = 1e-3
        best_f1_b2 = -1.0
        for r_cand in [5e-2, 1e-2, 5e-3, 1e-3, 5e-4]:
            evt_cand = EVTThreshold(q=0.90, risk_p=r_cand)
            evt_cand.fit(val_normal_scores)
            pred_v = evt_cand.predict(scores_val)
            f1_v = compute_classification_metrics(y_val, pred_v)["f1"]
            if f1_v > best_f1_b2:
                best_f1_b2 = f1_v
                best_risk = r_cand

        evt_model = EVTThreshold(q=0.90, risk_p=best_risk)
        evt_model.fit(val_normal_scores)
        pred_test_b2 = evt_model.predict(scores_test)

    cls_b2 = compute_classification_metrics(y_test, pred_test_b2, scores_test)
    sre_b2 = compute_sre_operational_metrics(y_test, pred_test_b2, timestamps_test, default_step_sec=step_sec)

    results_table.append({
        "Configuration": "Config B2 (Adaptive EVT)",
        "Type": "Our Extension",
        "Accuracy": cls_b2["accuracy"],
        "Precision": cls_b2["precision"],
        "Recall": cls_b2["recall"],
        "F1": cls_b2["f1"],
        "FPR": cls_b2["fpr"],
        "PR_AUC": cls_b2["pr_auc"],
        "Total_Alerts": sre_b2["total_alerts"],
        "False_Alarms_Per_Day": sre_b2["false_alarms_per_day"],
        "Episode_Recall": sre_b2["episode_recall"],
        "MTTD_Delay_Sec": sre_b2["mean_delay_sec"],
        "Runtime_Sec": prof_b2.elapsed_seconds,
        "Peak_RAM_MB": prof_b2.peak_mem_mb
    })

    # =========================================================================
    # CONFIG C: Extension - Persistence Filter (k consecutive anomalies)
    # =========================================================================
    print("\n--- Running Config C: Persistence Filter (k consecutive) ---")
    with ResourceProfiler() as prof_c:
        base_val_alarms = mad_model.predict(scores_val) if best_f1_b1 >= best_f1_b2 else evt_model.predict(scores_val)
        base_test_alarms = pred_test_b1 if best_f1_b1 >= best_f1_b2 else pred_test_b2
        base_name = "MAD" if best_f1_b1 >= best_f1_b2 else "EVT"

        best_k = 2
        best_f1_c = -1.0
        for k_cand in [1, 2, 3, 4, 5]:
            pf_cand = PersistenceFilter(k=k_cand)
            filtered_val = pf_cand.filter(base_val_alarms)
            f1_v = compute_classification_metrics(y_val, filtered_val)["f1"]
            if f1_v > best_f1_c:
                best_f1_c = f1_v
                best_k = k_cand

        print(f"  Selected best persistence k={best_k} on validation (base={base_name})")
        pers_filter = PersistenceFilter(k=best_k)
        pred_test_c = pers_filter.filter(base_test_alarms)

    cls_c = compute_classification_metrics(y_test, pred_test_c, scores_test)
    sre_c = compute_sre_operational_metrics(y_test, pred_test_c, timestamps_test, default_step_sec=step_sec)

    results_table.append({
        "Configuration": f"Config C ({base_name} + Persistence k={best_k})",
        "Type": "Our Extension",
        "Accuracy": cls_c["accuracy"],
        "Precision": cls_c["precision"],
        "Recall": cls_c["recall"],
        "F1": cls_c["f1"],
        "FPR": cls_c["fpr"],
        "PR_AUC": cls_c["pr_auc"],
        "Total_Alerts": sre_c["total_alerts"],
        "False_Alarms_Per_Day": sre_c["false_alarms_per_day"],
        "Episode_Recall": sre_c["episode_recall"],
        "MTTD_Delay_Sec": sre_c["mean_delay_sec"],
        "Runtime_Sec": prof_c.elapsed_seconds,
        "Peak_RAM_MB": prof_c.peak_mem_mb
    })

    # =========================================================================
    # BASELINE 1: Isolation Forest
    # =========================================================================
    print("\n--- Running Baseline 1: Isolation Forest ---")
    with ResourceProfiler() as prof_if:
        if_model = IsolationForestBaseline(n_estimators=100, random_state=seed)
        if_model.fit(X_train)
        if_model.calibrate_threshold(X_val, y_val)
        pred_test_if = if_model.predict(X_test)
        scores_test_if = if_model.score_samples(X_test)

    cls_if = compute_classification_metrics(y_test, pred_test_if, scores_test_if)
    sre_if = compute_sre_operational_metrics(y_test, pred_test_if, timestamps_test, default_step_sec=step_sec)

    results_table.append({
        "Configuration": "Baseline: Isolation Forest",
        "Type": "Baseline",
        "Accuracy": cls_if["accuracy"],
        "Precision": cls_if["precision"],
        "Recall": cls_if["recall"],
        "F1": cls_if["f1"],
        "FPR": cls_if["fpr"],
        "PR_AUC": cls_if["pr_auc"],
        "Total_Alerts": sre_if["total_alerts"],
        "False_Alarms_Per_Day": sre_if["false_alarms_per_day"],
        "Episode_Recall": sre_if["episode_recall"],
        "MTTD_Delay_Sec": sre_if["mean_delay_sec"],
        "Runtime_Sec": prof_if.elapsed_seconds,
        "Peak_RAM_MB": prof_if.peak_mem_mb
    })

    # =========================================================================
    # BASELINE 2: ARIMA Residual
    # =========================================================================
    print("\n--- Running Baseline 2: ARIMA-Residual Detector ---")
    with ResourceProfiler() as prof_ar:
        ar_model = ARIMAResidualBaseline(order=(1, 0, 1))
        ar_model.fit(X_train)
        ar_model.calibrate_threshold(X_val, y_val)
        pred_test_ar = ar_model.predict(X_test)
        scores_test_ar = ar_model.score_samples(X_test)

    cls_ar = compute_classification_metrics(y_test, pred_test_ar, scores_test_ar)
    sre_ar = compute_sre_operational_metrics(y_test, pred_test_ar, timestamps_test, default_step_sec=step_sec)

    results_table.append({
        "Configuration": "Baseline: ARIMA Residual",
        "Type": "Baseline",
        "Accuracy": cls_ar["accuracy"],
        "Precision": cls_ar["precision"],
        "Recall": cls_ar["recall"],
        "F1": cls_ar["f1"],
        "FPR": cls_ar["fpr"],
        "PR_AUC": cls_ar["pr_auc"],
        "Total_Alerts": sre_ar["total_alerts"],
        "False_Alarms_Per_Day": sre_ar["false_alarms_per_day"],
        "Episode_Recall": sre_ar["episode_recall"],
        "MTTD_Delay_Sec": sre_ar["mean_delay_sec"],
        "Runtime_Sec": prof_ar.elapsed_seconds,
        "Peak_RAM_MB": prof_ar.peak_mem_mb
    })

    # =========================================================================
    # Output Results
    # =========================================================================
    results_df = pd.DataFrame(results_table)
    suffix = f"_{mode}"
    csv_path = os.path.join(OUTPUT_METRICS_DIR, f"comparison_table{suffix}.csv")
    json_path = os.path.join(OUTPUT_METRICS_DIR, f"comparison_table{suffix}.json")
    results_df.to_csv(csv_path, index=False)
    results_df.to_json(json_path, orient="records", indent=2)

    print("\n" + "=" * 80)
    print(f"EXPERIMENTAL EVALUATION RESULTS [{mode.upper()} MODE] (TEST SET)")
    print("=" * 80)
    print(results_df[[
        "Configuration", "F1", "Precision", "Recall", "FPR", "PR_AUC", "Total_Alerts", "False_Alarms_Per_Day", "MTTD_Delay_Sec"
    ]].to_string(index=False))

    # Generate Figures
    fig, ax1 = plt.subplots(figsize=(11, 6))
    x_positions = np.arange(len(results_df))
    width = 0.35

    ax1.bar(x_positions - width/2, results_df["F1"], width=width, color="#2b5c8f", alpha=0.85, label="F1-Score")
    ax1.bar(x_positions + width/2, results_df["Precision"], width=width, color="#41b6c4", alpha=0.85, label="Precision")
    ax1.set_ylabel("Score", fontsize=12)
    ax1.set_ylim(0, 1.05)
    ax1.set_xticks(x_positions)
    ax1.set_xticklabels(results_df["Configuration"], rotation=22, ha="right", fontsize=9.5)
    ax1.legend(loc="upper left")

    ax2 = ax1.twinx()
    ax2.plot(x_positions, results_df["Total_Alerts"], color="#d62728", marker="o", linewidth=2.2, label="Total Alerts")
    ax2.set_ylabel("Total Alert Volume", color="#d62728", fontsize=12)
    ax2.grid(False)

    plt.title(f"Ablation & Baseline Comparison [{mode.capitalize()} Level]: Detection vs Alert Volume", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig_path1 = os.path.join(OUTPUT_FIGURES_DIR, f"comparison_f1_alerts{suffix}.png")
    plt.savefig(fig_path1, dpi=300)
    plt.close()
    print(f"\nSaved comparison chart to {fig_path1}")

    # Figure 2: Kneedle Dimension Curve
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(knee_info["x"], knee_info["y"], marker="s", color="#1f77b4", linewidth=2, label="Max Profile Value")
    ax.axvline(knee_dim, color="crimson", linestyle="--", linewidth=2, label=f"Selected Knee (Dim = {knee_dim})")
    ax.scatter([knee_dim], [knee_info["y"][knee_dim - 1]], color="crimson", s=120, zorder=5)
    ax.set_xlabel("Number of Selected Dimensions (Subspace Size)", fontsize=11)
    ax.set_ylabel("Max Distance Profile", fontsize=11)
    ax.set_title(f"mSTAMP Dimension Selection via Kneedle [{mode.capitalize()} Level]", fontsize=12, fontweight="bold")
    ax.legend()
    fig_path2 = os.path.join(OUTPUT_FIGURES_DIR, f"kneedle_curve{suffix}.png")
    plt.savefig(fig_path2, dpi=300)
    plt.close()
    print(f"Saved Kneedle curve to {fig_path2}")

    return results_df

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", type=str, default="flow", choices=["flow", "window"])
    parser.add_argument("--samples", type=int, default=8000)
    parser.add_argument("--subseq-len", type=int, default=50)
    args = parser.parse_args()

    run_experiments(mode=args.mode, n_samples=args.samples, subseq_len_m=args.subseq_len)
