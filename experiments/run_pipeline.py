"""
Unified end-to-end experiment pipeline:
Executes:
- Config A (Base reproduction: mSTAMP + Kneedle)
- Config B1 (Adaptive MAD threshold)
- Config B2 (Adaptive EVT Peaks-Over-Threshold)
- Config C (Persistence Filter k-consecutive)
- Machine Learning Baselines: Isolation Forest (IF), ARIMA-Residual (AR)
- Trivial Baselines: All-Attack, All-Normal, Random-Uniform, Random-Stratified
Supports both UNSW-NB15 (flow and window modes) and CSE-CIC-IDS2018 (AWS cloud telemetry).
Fully reproducible from saved config files in configs/.
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
from src.windowing import aggregate_time_windows, aggregate_csecicids2018_windows
from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.adaptive_threshold import MADThreshold, EVTThreshold
from src.persistence_filter import PersistenceFilter
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline,
    RandomUniformBaseline, RandomStratifiedBaseline
)
from src.evaluation import (
    compute_classification_metrics,
    compute_sre_operational_metrics,
    compute_bootstrap_confidence_intervals,
    ResourceProfiler
)
from sklearn.preprocessing import StandardScaler

OUTPUT_METRICS_DIR = "results/metrics"
OUTPUT_FIGURES_DIR = "results/figures"
PROCESSED_DATA_DIR = "data/processed"

def run_from_config(config_path: str):
    with open(config_path, "r") as f:
        config = json.load(f)
    
    config_name = os.path.splitext(os.path.basename(config_path))[0]
    return run_pipeline(config, config_name)

def run_pipeline(config: Dict[str, Any], config_name: str):
    os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

    dataset_name = config.get("dataset", "UNSW-NB15")
    mode = config.get("mode", "window")
    subseq_len_m = config.get("subseq_len_m", 30)
    seed = config.get("random_seed", 42)
    np.random.seed(seed)

    print("=" * 80)
    print(f"RUNNING EXPERIMENT: {config_name.upper()} [DATASET: {dataset_name}]")
    print(f"Mode: {mode} | Window Length m: {subseq_len_m} | Seed: {seed}")
    print("=" * 80)

    # 1. Dataset Loading and Windowing
    if dataset_name == "UNSW-NB15":
        window_sec = config.get("window_sec", 10)
        label_rule = config.get("label_rule", "any_attack")
        batch_selection = config.get("batch_selection", "batch1_active")
        
        if mode == "window":
            processed_parquet = os.path.join(PROCESSED_DATA_DIR, f"unsw_nb15_{window_sec}s_{label_rule}.parquet")
            if os.path.exists(processed_parquet):
                print(f"Loading cached windowed dataset from {processed_parquet}...")
                df_win = pd.read_parquet(processed_parquet)
            else:
                print("Loading raw UNSW flows and sorting chronologically...")
                df_raw = load_and_sort_raw_unsw(file_indices=[1, 2, 3, 4])
                print(f"Aggregating {len(df_raw):,d} flows into {window_sec}s windows (rule={label_rule})...")
                df_win = aggregate_time_windows(df_raw, window_sec=window_sec, label_rule=label_rule)
                df_win.to_parquet(processed_parquet)

            time_col = "window_time"
            step_sec = float(window_sec)

            # Handle batch gap & partition strategy
            if "train_slice" in config and "val_slice" in config and "test_slice" in config:
                tr_s = config["train_slice"]
                val_s = config["val_slice"]
                te_s = config["test_slice"]
                train_df = df_win.iloc[tr_s[0]:tr_s[1]].copy().reset_index(drop=True)
                val_df = df_win.iloc[val_s[0]:val_s[1]].copy().reset_index(drop=True)
                test_df = df_win.iloc[te_s[0]:te_s[1]].copy().reset_index(drop=True)
                df_eval = pd.concat([train_df, val_df, test_df], ignore_index=True)
            elif batch_selection == "batch1_active":
                # Active transition period of Batch 1: first 2,000 windows (attacks + normal baseline)
                n_samples = config.get("n_samples", 2000)
                df_eval = df_win.iloc[:n_samples].copy().reset_index(drop=True)
                train_df, val_df, test_df = split_chronological(
                    df_eval,
                    train_frac=config.get("train_frac", 0.60),
                    val_frac=config.get("val_frac", 0.20),
                    test_frac=config.get("test_frac", 0.20)
                )

            elif batch_selection == "cross_batch_benign":
                # Cross-batch: Train on Batch 1 pure normal baseline, Val on Batch 1/2 transition, Test on Batch 2
                train_df = df_win.iloc[1000:3000].copy().reset_index(drop=True) # Pure normal
                val_df = df_win.iloc[3000:4500].copy().reset_index(drop=True)   # End Batch 1
                test_df = df_win.iloc[4500:6500].copy().reset_index(drop=True)  # Batch 2 attacks
                df_eval = pd.concat([train_df, val_df, test_df], ignore_index=True)

            else:
                n_samples = config.get("n_samples", len(df_win))
                df_eval = df_win.iloc[:n_samples].copy().reset_index(drop=True)
                train_df, val_df, test_df = split_chronological(df_eval, 0.6, 0.2, 0.2)

            feature_cols = ["sloss", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", "dloss", "service"]
            preprocessor = UNSWPreprocessor(scaler_type=config.get("scaler_type", "standard"))
            X_train, y_train = preprocessor.fit_transform(train_df)
            X_val, y_val = preprocessor.transform(val_df)
            X_test, y_test = preprocessor.transform(test_df)

        elif mode == "flow":
            n_samples = config.get("n_samples", 8000)
            print(f"Loading raw sorted flows ({n_samples:,d} flows)...")
            df_eval = load_and_sort_raw_unsw(file_indices=[1], nrows=n_samples)
            time_col = "Stime"
            step_sec = 1.0

            train_df, val_df, test_df = split_chronological(
                df_eval,
                train_frac=config.get("train_frac", 0.60),
                val_frac=config.get("val_frac", 0.20),
                test_frac=config.get("test_frac", 0.20)
            )

            preprocessor = UNSWPreprocessor(scaler_type=config.get("scaler_type", "standard"))
            X_train, y_train = preprocessor.fit_transform(train_df)
            X_val, y_val = preprocessor.transform(val_df)
            X_test, y_test = preprocessor.transform(test_df)

    elif dataset_name == "CSE-CIC-IDS2018":
        csv_file = config.get("csv_file", "data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv")
        window_sec = config.get("window_sec", 60)
        label_rule = config.get("label_rule", "any_attack")

        processed_parquet = os.path.join(PROCESSED_DATA_DIR, f"csecicids2018_{window_sec}s_{label_rule}.parquet")
        if os.path.exists(processed_parquet):
            print(f"Loading cached windowed dataset from {processed_parquet}...")
            df_win = pd.read_parquet(processed_parquet)
        else:
            df_win = aggregate_csecicids2018_windows(csv_file, window_sec=window_sec, label_rule=label_rule)
            df_win.to_parquet(processed_parquet)

        df_eval = df_win.copy()
        time_col = "window_time"
        step_sec = float(window_sec)

        if "train_slice" in config and "val_slice" in config and "test_slice" in config:
            tr_s = config["train_slice"]
            val_s = config["val_slice"]
            te_s = config["test_slice"]
            train_df = df_win.iloc[tr_s[0]:tr_s[1]].copy().reset_index(drop=True)
            val_df = df_win.iloc[val_s[0]:val_s[1]].copy().reset_index(drop=True)
            test_df = df_win.iloc[te_s[0]:te_s[1]].copy().reset_index(drop=True)
            df_eval = pd.concat([train_df, val_df, test_df], ignore_index=True)
        else:
            train_df, val_df, test_df = split_chronological(
                df_eval,
                train_frac=config.get("train_frac", 0.50),
                val_frac=config.get("val_frac", 0.25),
                test_frac=config.get("test_frac", 0.25)
            )

        csec_features = [
            "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
            "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
            "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
        ]
        scaler = StandardScaler()
        X_train = scaler.fit_transform(train_df[csec_features].fillna(0.0).values)
        X_val = scaler.transform(val_df[csec_features].fillna(0.0).values)
        X_test = scaler.transform(test_df[csec_features].fillna(0.0).values)
        
        y_train = train_df["Label"].values.astype(int)
        y_val = val_df["Label"].values.astype(int)
        y_test = test_df["Label"].values.astype(int)

    else:
        raise ValueError(f"Unsupported dataset: {dataset_name}")

    total_instances = len(df_eval)
    print(f"\nPartitions:")
    print(f"  Train: {len(train_df):5d} | Attacks: {y_train.sum():4d} ({y_train.mean()*100:5.2f}%)")
    print(f"  Val:   {len(val_df):5d} | Attacks: {y_val.sum():4d} ({y_val.mean()*100:5.2f}%)")
    print(f"  Test:  {len(test_df):5d} | Attacks: {y_test.sum():4d} ({y_test.mean()*100:5.2f}%)")

    # Full array for Matrix Profile stream
    X_full = np.vstack([X_train, X_val, X_test])
    timestamps_full = df_eval[time_col].values

    n_train = len(train_df)
    n_val = len(val_df)
    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_instances)
    timestamps_test = timestamps_full[test_slice]

    results_table = []

    def make_row(name, cfg_type, cls_m, sre_m, pred, scores, prof_runtime, prof_mem):
        boot = compute_bootstrap_confidence_intervals(
            y_test, pred, scores, timestamps_test, n_bootstraps=500, seed=seed, default_step_sec=step_sec
        )
        return {
            "Configuration": name,
            "Type": cfg_type,
            "Accuracy": cls_m["accuracy"],
            "Precision": cls_m["precision"],
            "Recall": cls_m["recall"],
            "F1": cls_m["f1"],
            "F1_CI_Low": boot.get("f1_ci", (0.0, 0.0))[0],
            "F1_CI_High": boot.get("f1_ci", (0.0, 0.0))[1],
            "FPR": cls_m["fpr"],
            "PR_AUC": cls_m["pr_auc"],
            "PR_AUC_CI_Low": boot.get("pr_auc_ci", (None, None))[0],
            "PR_AUC_CI_High": boot.get("pr_auc_ci", (None, None))[1],
            "Total_Alerts": sre_m["total_alerts"],
            "False_Alarms_Per_Day": sre_m["false_alarms_per_day"],
            "Episode_Recall": sre_m["episode_recall"],
            "MTTD_Delay_Sec": sre_m["mean_delay_sec"],
            "MTTD_CI_Low": boot.get("mttd_ci", (None, None))[0],
            "MTTD_CI_High": boot.get("mttd_ci", (None, None))[1],
            "Total_Episodes": sre_m["total_episodes"],
            "Runtime_Sec": prof_runtime,
            "Peak_RAM_MB": prof_mem
        }

    # =========================================================================
    # TRIVIAL BASELINES
    # =========================================================================
    print("\n--- Running Trivial Baselines ---")
    trivial_models = [
        ("Trivial: All-Attack", AllAttackBaseline()),
        ("Trivial: All-Normal", AllNormalBaseline()),
        ("Trivial: Random Uniform", RandomUniformBaseline(seed=seed)),
        ("Trivial: Random Stratified", RandomStratifiedBaseline(seed=seed))
    ]

    for name, model in trivial_models:
        model.fit(X_train, y_train)
        pred_te = model.predict(X_test)
        scores_te = model.score_samples(X_test)
        cls_m = compute_classification_metrics(y_test, pred_te, scores_te)
        sre_m = compute_sre_operational_metrics(y_test, pred_te, timestamps_test, default_step_sec=step_sec)
        results_table.append(make_row(name, "Trivial Baseline", cls_m, sre_m, pred_te, scores_te, 0.001, 0.0))

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

    # Baseline threshold calibrated on validation split
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

    results_table.append(
        make_row("Config A (mSTAMP + Kneedle)", "Paper Reproduction", cls_a, sre_a, pred_test_a, scores_test, prof_a.elapsed_seconds, prof_a.peak_mem_mb)
    )

    # =========================================================================
    # CONFIG B1: Adaptive Threshold (Rolling MAD)
    # =========================================================================
    print("\n--- Running Config B1: Adaptive Threshold (Rolling MAD) ---")
    with ResourceProfiler() as prof_b1:
        val_normal_scores = scores_val[y_val == 0]
        if len(val_normal_scores) < 5:
            val_normal_scores = scores_val

        roll_win = config.get("mad_rolling_window", 30)
        c_candidates = config.get("mad_c_candidates", [1.5, 2.0, 2.5, 3.0, 3.5, 4.0])
        best_c = 3.0
        best_f1_b1 = -1.0
        for c_cand in c_candidates:
            mad_cand = MADThreshold(c=c_cand, rolling_window=roll_win)
            mad_cand.fit(val_normal_scores)
            pred_v = mad_cand.predict(scores_val)
            f1_v = compute_classification_metrics(y_val, pred_v)["f1"]
            if f1_v > best_f1_b1:
                best_f1_b1 = f1_v
                best_c = c_cand

        mad_model = MADThreshold(c=best_c, rolling_window=roll_win)
        mad_model.fit(val_normal_scores)
        pred_test_b1 = mad_model.predict(scores_test)

    cls_b1 = compute_classification_metrics(y_test, pred_test_b1, scores_test)
    sre_b1 = compute_sre_operational_metrics(y_test, pred_test_b1, timestamps_test, default_step_sec=step_sec)

    results_table.append(
        make_row("Config B1 (Adaptive MAD)", "Our Extension", cls_b1, sre_b1, pred_test_b1, scores_test, prof_b1.elapsed_seconds, prof_b1.peak_mem_mb)
    )

    # =========================================================================
    # CONFIG B2: Adaptive Threshold (EVT POT)
    # =========================================================================
    print("\n--- Running Config B2: Adaptive Threshold (EVT POT) ---")
    with ResourceProfiler() as prof_b2:
        scores_train = scores_full[:n_train]
        train_normal = scores_train[y_train == 0]
        val_normal = scores_val[y_val == 0]
        if len(train_normal) > 0:
            history_normal_scores = np.concatenate([train_normal, val_normal])
        else:
            history_normal_scores = val_normal if len(val_normal) >= 5 else scores_val

        n_hist = len(history_normal_scores)
        evt_q = config.get("evt_q", 0.85)
        raw_risk_candidates = config.get("evt_risk_candidates", [0.05, 0.02, 0.01, 0.005, 0.001])
        min_p = max(1e-4, 1.0 / (2.0 * n_hist))
        supported_risks = [r for r in raw_risk_candidates if r >= min_p]
        if not supported_risks:
            supported_risks = [max(1e-3, 1.0 / n_hist), max(5e-3, 2.0 / n_hist), max(1e-2, 5.0 / n_hist)]

        best_risk = supported_risks[0]
        best_f1_b2 = -1.0
        for r_cand in supported_risks:
            evt_cand = EVTThreshold(q=evt_q, risk_p=r_cand)
            evt_cand.fit(history_normal_scores)
            pred_v = evt_cand.predict(scores_val)
            f1_v = compute_classification_metrics(y_val, pred_v)["f1"]
            if f1_v > best_f1_b2:
                best_f1_b2 = f1_v
                best_risk = r_cand

        evt_model = EVTThreshold(q=evt_q, risk_p=best_risk)
        evt_model.fit(history_normal_scores)
        pred_test_b2 = evt_model.predict(scores_test)

    cls_b2 = compute_classification_metrics(y_test, pred_test_b2, scores_test)
    sre_b2 = compute_sre_operational_metrics(y_test, pred_test_b2, timestamps_test, default_step_sec=step_sec)

    results_table.append(
        make_row("Config B2 (Adaptive EVT)", "Our Extension", cls_b2, sre_b2, pred_test_b2, scores_test, prof_b2.elapsed_seconds, prof_b2.peak_mem_mb)
    )

    # =========================================================================
    # CONFIG C: Persistence Filter (k consecutive)
    # =========================================================================
    print("\n--- Running Config C: Persistence Filter ---")
    with ResourceProfiler() as prof_c:
        base_val_alarms = mad_model.predict(scores_val) if best_f1_b1 >= best_f1_b2 else evt_model.predict(scores_val)
        base_test_alarms = pred_test_b1 if best_f1_b1 >= best_f1_b2 else pred_test_b2
        base_name = "MAD" if best_f1_b1 >= best_f1_b2 else "EVT"

        k_candidates = config.get("persistence_k_candidates", [1, 2, 3, 4, 5])
        best_k = 1
        best_f1_c = -1.0
        for k_cand in k_candidates:
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

    results_table.append(
        make_row(f"Config C ({base_name} + Persist k={best_k})", "Our Extension", cls_c, sre_c, pred_test_c, scores_test, prof_c.elapsed_seconds, prof_c.peak_mem_mb)
    )

    # =========================================================================
    # ML BASELINES: Isolation Forest & ARIMA Residual
    # =========================================================================
    print("\n--- Running ML Baselines (Isolation Forest & ARIMA) ---")
    with ResourceProfiler() as prof_if:
        if_model = IsolationForestBaseline(n_estimators=100, random_state=seed)
        if_model.fit(X_train)
        if_model.calibrate_threshold(X_val, y_val)
        pred_test_if = if_model.predict(X_test)
        scores_test_if = if_model.score_samples(X_test)

    cls_if = compute_classification_metrics(y_test, pred_test_if, scores_test_if)
    sre_if = compute_sre_operational_metrics(y_test, pred_test_if, timestamps_test, default_step_sec=step_sec)

    results_table.append(
        make_row("Baseline: Isolation Forest", "ML Baseline", cls_if, sre_if, pred_test_if, scores_test_if, prof_if.elapsed_seconds, prof_if.peak_mem_mb)
    )

    with ResourceProfiler() as prof_ar:
        ar_model = ARIMAResidualBaseline(order=(1, 0, 1))
        ar_model.fit(X_train)
        ar_model.calibrate_threshold(X_val, y_val)
        pred_test_ar = ar_model.predict(X_test)
        scores_test_ar = ar_model.score_samples(X_test)

    cls_ar = compute_classification_metrics(y_test, pred_test_ar, scores_test_ar)
    sre_ar = compute_sre_operational_metrics(y_test, pred_test_ar, timestamps_test, default_step_sec=step_sec)

    results_table.append(
        make_row("Baseline: ARIMA Residual", "ML Baseline", cls_ar, sre_ar, pred_test_ar, scores_test_ar, prof_ar.elapsed_seconds, prof_ar.peak_mem_mb)
    )

    # =========================================================================
    # Export Tables & Config Artifacts
    # =========================================================================
    results_df = pd.DataFrame(results_table)
    csv_path = os.path.join(OUTPUT_METRICS_DIR, f"{config_name}_results.csv")
    json_path = os.path.join(OUTPUT_METRICS_DIR, f"{config_name}_results.json")
    saved_cfg_path = os.path.join(OUTPUT_METRICS_DIR, f"{config_name}_config.json")

    results_df.to_csv(csv_path, index=False)
    results_df.to_json(json_path, orient="records", indent=2)
    with open(saved_cfg_path, "w") as f:
        json.dump(config, f, indent=2)

    print("\n" + "=" * 80)
    print(f"FINAL TEST SET RESULTS: {config_name.upper()}")
    print("=" * 80)
    print(results_df[[
        "Configuration", "Type", "F1", "Precision", "Recall", "FPR", "PR_AUC", "Total_Alerts", "False_Alarms_Per_Day", "MTTD_Delay_Sec"
    ]].to_string(index=False))

    # Generate Publication Figure
    fig, ax1 = plt.subplots(figsize=(12, 6))
    x_positions = np.arange(len(results_df))
    width = 0.35

    ax1.bar(x_positions - width/2, results_df["F1"], width=width, color="#2b5c8f", alpha=0.85, label="F1-Score")
    ax1.bar(x_positions + width/2, results_df["Precision"], width=width, color="#41b6c4", alpha=0.85, label="Precision")
    ax1.set_ylabel("Score", fontsize=12)
    ax1.set_ylim(0, 1.05)
    ax1.set_xticks(x_positions)
    ax1.set_xticklabels(results_df["Configuration"], rotation=28, ha="right", fontsize=9)
    ax1.legend(loc="upper left")

    ax2 = ax1.twinx()
    ax2.plot(x_positions, results_df["Total_Alerts"], color="#d62728", marker="o", linewidth=2.2, label="Total Alerts")
    ax2.set_ylabel("Total Alert Volume", color="#d62728", fontsize=12)
    ax2.grid(False)

    plt.title(f"Ablation, ML & Trivial Baselines: {config_name}", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig_path1 = os.path.join(OUTPUT_FIGURES_DIR, f"{config_name}_f1_alerts.png")
    plt.savefig(fig_path1, dpi=300)
    plt.close()

    print(f"\nSaved metrics table to: {csv_path}")
    print(f"Saved figure to: {fig_path1}")
    print(f"Saved reproducible config to: {saved_cfg_path}")
    return results_df

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, required=True, help="Path to config JSON")
    args = parser.parse_args()

    run_from_config(args.config)
