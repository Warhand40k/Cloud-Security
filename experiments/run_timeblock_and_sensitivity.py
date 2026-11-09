"""
Rolling-origin (time-block) evaluation and sensitivity analysis.
Implements:
1. Rolling-origin evaluation across multi-day CSE-CIC-IDS2018 blocks (Thursday, Friday, Wednesday)
   and UNSW-NB15 temporal blocks.
2. Reports mean and spread (std) across blocks for all models.
3. Bootstrap 95% confidence intervals for F1, PR-AUC, and MTTD (with explicit episode counts).
4. Sensitivity to subsequence length m in [5, 10, 20, 30, 50, 100].
5. Sensitivity to alternative temporal slice cuts.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.adaptive_threshold import MADThreshold, EVTThreshold
from src.persistence_filter import PersistenceFilter
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline, RandomUniformBaseline
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
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

FEATURE_COLS_UNSW = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "state", "service"
]

def evaluate_single_block(
    X_train, y_train,
    X_val, y_val,
    X_test, y_test,
    timestamps_test,
    subseq_len_m=10,
    step_sec=60.0,
    seed=42
):
    """
    Evaluates all configurations on a given (train, val, test) partition.
    Returns dictionary of results for each model.
    """
    n_train = len(X_train)
    n_val = len(X_val)
    n_test = len(X_test)
    total_len = n_train + n_val + n_test

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)

    X_full = np.vstack([X_train, X_val, X_test])

    block_results = {}

    def run_eval(name, model_type, pred_te, scores_te, runtime=0.0):
        cls_m = compute_classification_metrics(y_test, pred_te, scores_te)
        sre_m = compute_sre_operational_metrics(y_test, pred_te, timestamps_test, default_step_sec=step_sec)
        boot = compute_bootstrap_confidence_intervals(
            y_test, pred_te, scores_te, timestamps_test, n_bootstraps=300, seed=seed, default_step_sec=step_sec
        )
        return {
            "Model": name,
            "Type": model_type,
            "F1": cls_m["f1"],
            "F1_CI_Low": boot["f1_ci"][0],
            "F1_CI_High": boot["f1_ci"][1],
            "Precision": cls_m["precision"],
            "Recall": cls_m["recall"],
            "FPR": cls_m["fpr"],
            "PR_AUC": cls_m["pr_auc"],
            "PR_AUC_CI_Low": boot["pr_auc_ci"][0],
            "PR_AUC_CI_High": boot["pr_auc_ci"][1],
            "Total_Alerts": sre_m["total_alerts"],
            "False_Alarms_Per_Day": sre_m["false_alarms_per_day"],
            "Episode_Recall": sre_m["episode_recall"],
            "MTTD_Delay_Sec": sre_m["mean_delay_sec"],
            "MTTD_CI_Low": boot["mttd_ci"][0],
            "MTTD_CI_High": boot["mttd_ci"][1],
            "Episodes_Count": sre_m["total_episodes"],
            "Runtime_Sec": runtime
        }

    # Trivial Baselines
    all_atk = AllAttackBaseline()
    all_atk.fit(X_train, y_train)
    block_results["Trivial: All-Attack"] = run_eval(
        "Trivial: All-Attack", "Trivial", all_atk.predict(X_test), all_atk.score_samples(X_test)
    )

    all_norm = AllNormalBaseline()
    all_norm.fit(X_train, y_train)
    block_results["Trivial: All-Normal"] = run_eval(
        "Trivial: All-Normal", "Trivial", all_norm.predict(X_test), all_norm.score_samples(X_test)
    )

    rand_u = RandomUniformBaseline(seed=seed)
    rand_u.fit(X_train, y_train)
    block_results["Trivial: Random Uniform"] = run_eval(
        "Trivial: Random Uniform", "Trivial", rand_u.predict(X_test), rand_u.score_samples(X_test)
    )

    # Config A: mSTAMP + Kneedle
    with ResourceProfiler() as prof_a:
        effective_m = min(subseq_len_m, max(3, n_train // 4))
        mps, indices = compute_multidimensional_mp(X_full, m=effective_m)
        knee_dim, _ = find_knee_dimension(mps, online=True, metric="max")
        scores_full = compute_point_anomaly_scores(mps, knee_dim=knee_dim, n_samples=total_len, m=effective_m)

    scores_train = scores_full[:n_train]
    scores_val = scores_full[val_slice]
    scores_test = scores_full[test_slice]

    val_percentiles = np.linspace(80, 99.8, 80)
    best_thresh_a = float(np.median(scores_val))
    best_f1_val_a = -1.0
    for p in val_percentiles:
        th = float(np.percentile(scores_val, p))
        f1_v = compute_classification_metrics(y_val, (scores_val >= th).astype(int))["f1"]
        if f1_v > best_f1_val_a:
            best_f1_val_a = f1_v
            best_thresh_a = th

    pred_test_a = (scores_test >= best_thresh_a).astype(int)
    block_results["Config A (mSTAMP+Kneedle)"] = run_eval(
        "Config A (mSTAMP+Kneedle)", "Paper", pred_test_a, scores_test, prof_a.elapsed_seconds
    )

    # Config B1: MAD
    train_normal = scores_train[y_train == 0]
    val_normal = scores_val[y_val == 0]
    hist_normal = np.concatenate([train_normal, val_normal]) if len(train_normal) > 0 else (val_normal if len(val_normal) >= 5 else scores_val)

    best_c = 2.5
    best_f1_b1 = -1.0
    for c_cand in [1.5, 2.0, 2.5, 3.0, 3.5]:
        mad_cand = MADThreshold(c=c_cand, rolling_window=min(20, max(5, n_val // 2)))
        mad_cand.fit(hist_normal)
        f1_v = compute_classification_metrics(y_val, mad_cand.predict(scores_val))["f1"]
        if f1_v > best_f1_b1:
            best_f1_b1 = f1_v
            best_c = c_cand

    mad_m = MADThreshold(c=best_c, rolling_window=min(20, max(5, n_val // 2)))
    mad_m.fit(hist_normal)
    pred_test_b1 = mad_m.predict(scores_test)
    block_results["Config B1 (Adaptive MAD)"] = run_eval(
        "Config B1 (Adaptive MAD)", "Extension", pred_test_b1, scores_test
    )

    # Config B2: EVT
    n_h = len(hist_normal)
    min_p = max(1e-4, 1.0 / (2.0 * n_h))
    raw_risks = [0.05, 0.02, 0.01, 0.005, 0.001]
    supp_risks = [r for r in raw_risks if r >= min_p] or [max(1e-3, 1.0 / n_h)]

    best_r = supp_risks[0]
    best_f1_b2 = -1.0
    for r_cand in supp_risks:
        evt_cand = EVTThreshold(q=0.85, risk_p=r_cand)
        evt_cand.fit(hist_normal)
        f1_v = compute_classification_metrics(y_val, evt_cand.predict(scores_val))["f1"]
        if f1_v > best_f1_b2:
            best_f1_b2 = f1_v
            best_r = r_cand

    evt_m = EVTThreshold(q=0.85, risk_p=best_r)
    evt_m.fit(hist_normal)
    pred_test_b2 = evt_m.predict(scores_test)
    block_results["Config B2 (Adaptive EVT)"] = run_eval(
        "Config B2 (Adaptive EVT)", "Extension", pred_test_b2, scores_test
    )

    # Config C: Persistence Filter
    base_alarms_test = pred_test_b1 if best_f1_b1 >= best_f1_b2 else pred_test_b2
    base_alarms_val = mad_m.predict(scores_val) if best_f1_b1 >= best_f1_b2 else evt_m.predict(scores_val)
    best_k = 1
    best_f1_c = -1.0
    for k_cand in [1, 2, 3]:
        pf = PersistenceFilter(k=k_cand)
        f1_v = compute_classification_metrics(y_val, pf.filter(base_alarms_val))["f1"]
        if f1_v > best_f1_c:
            best_f1_c = f1_v
            best_k = k_cand

    pers_m = PersistenceFilter(k=best_k)
    pred_test_c = pers_m.filter(base_alarms_test)
    block_results["Config C (Persistence Filter)"] = run_eval(
        f"Config C (Persist k={best_k})", "Extension", pred_test_c, scores_test
    )

    # ML Baseline: Isolation Forest
    if_m = IsolationForestBaseline(n_estimators=100, random_state=seed)
    if_m.fit(X_train)
    if_m.calibrate_threshold(X_val, y_val)
    pred_test_if = if_m.predict(X_test)
    scores_test_if = if_m.score_samples(X_test)
    block_results["Baseline: Isolation Forest"] = run_eval(
        "Baseline: Isolation Forest", "ML Baseline", pred_test_if, scores_test_if
    )

    # ML Baseline: ARIMA Residual
    ar_m = ARIMAResidualBaseline(order=(1, 0, 1))
    ar_m.fit(X_train)
    ar_m.calibrate_threshold(X_val, y_val)
    pred_test_ar = ar_m.predict(X_test)
    scores_test_ar = ar_m.score_samples(X_test)
    block_results["Baseline: ARIMA Residual"] = run_eval(
        "Baseline: ARIMA Residual", "ML Baseline", pred_test_ar, scores_test_ar
    )

    return block_results

def run_rolling_origin_csecicids2018():
    """
    Multi-Day Rolling-Origin Evaluation over 3 days of CSE-CIC-IDS2018:
    Block 1: Thursday-15-02 (GoldenEye & Slowloris)
    Block 2: Friday-16-02 (Hulk & SlowHTTPTest)
    Block 3: Wednesday-21-02 (HOIC & LOIC-UDP)
    """
    print("\n" + "=" * 80)
    print("RUNNING MULTI-DAY ROLLING-ORIGIN EVALUATION (CSE-CIC-IDS2018)")
    print("=" * 80)

    day_files = [
        ("Thursday (GoldenEye/Slowloris)", "data/processed/csecicids2018_thursday_60s_any_attack.parquet", [0, 250], [250, 380], [380, 550]),
        ("Friday (Hulk/SlowHTTPTest)", "data/processed/csecicids2018_60s_any_attack.parquet", [0, 80], [80, 105], [105, 175]),
        ("Wednesday (HOIC/LOIC-UDP)", "data/processed/csecicids2018_wednesday_60s_any_attack.parquet", [0, 60], [60, 100], [100, 165])
    ]

    all_blocks_records = []

    for block_name, ppath, tr_sl, va_sl, te_sl in day_files:
        print(f"\nProcessing Block: {block_name}...")
        df = pd.read_parquet(ppath)
        
        train_df = df.iloc[tr_sl[0]:tr_sl[1]].copy()
        val_df = df.iloc[va_sl[0]:va_sl[1]].copy()
        test_df = df.iloc[te_sl[0]:te_sl[1]].copy()

        raw_tr = np.nan_to_num(train_df[FEATURE_COLS_CSE].values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
        raw_va = np.nan_to_num(val_df[FEATURE_COLS_CSE].values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
        raw_te = np.nan_to_num(test_df[FEATURE_COLS_CSE].values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)

        scaler = StandardScaler()
        X_train = scaler.fit_transform(raw_tr)
        X_val = scaler.transform(raw_va)
        X_test = scaler.transform(raw_te)

        y_train = train_df["Label"].values.astype(int)
        y_val = val_df["Label"].values.astype(int)
        y_test = test_df["Label"].values.astype(int)

        t_test = test_df["window_time"].values

        print(f"  Train: {len(X_train)} (Atk={y_train.sum()}) | Val: {len(X_val)} (Atk={y_val.sum()}) | Test: {len(X_test)} (Atk={y_test.sum()})")

        block_res = evaluate_single_block(
            X_train, y_train, X_val, y_val, X_test, y_test, t_test, subseq_len_m=10, step_sec=60.0
        )

        for m_name, res in block_res.items():
            res_entry = dict(res)
            res_entry["Block"] = block_name
            res_entry["Dataset"] = "CSE-CIC-IDS2018"
            all_blocks_records.append(res_entry)

    df_blocks = pd.DataFrame(all_blocks_records)
    
    # Compute Mean and Spread across blocks for each model
    summary_rows = []
    for model_name, grp in df_blocks.groupby("Model"):
        m_type = grp["Type"].iloc[0]
        mean_f1 = grp["F1"].mean()
        std_f1 = grp["F1"].std()
        mean_pr = grp["PR_AUC"].dropna().mean()
        std_pr = grp["PR_AUC"].dropna().std()
        mean_mttd = grp["MTTD_Delay_Sec"].dropna().mean()
        std_mttd = grp["MTTD_Delay_Sec"].dropna().std()
        mean_fapd = grp["False_Alarms_Per_Day"].mean()
        total_episodes = grp["Episodes_Count"].sum()

        summary_rows.append({
            "Model": model_name,
            "Type": m_type,
            "F1_Mean": mean_f1,
            "F1_Spread (Std)": std_f1,
            "F1_Min": grp["F1"].min(),
            "F1_Max": grp["F1"].max(),
            "PR_AUC_Mean": mean_pr,
            "PR_AUC_Spread": std_pr,
            "MTTD_Mean_Sec": mean_mttd,
            "MTTD_Spread_Sec": std_mttd,
            "False_Alarms_Per_Day_Mean": mean_fapd,
            "Total_Episodes_Across_Blocks": int(total_episodes)
        })

    summary_df = pd.DataFrame(summary_rows)
    print("\n--- SUMMARY ACROSS MULTI-DAY TIME BLOCKS ---")
    print(summary_df[[
        "Model", "Type", "F1_Mean", "F1_Spread (Std)", "PR_AUC_Mean", "MTTD_Mean_Sec", "Total_Episodes_Across_Blocks"
    ]].to_string(index=False))

    summary_csv = os.path.join(OUTPUT_METRICS_DIR, "rolling_timeblock_summary.csv")
    summary_json = os.path.join(OUTPUT_METRICS_DIR, "rolling_timeblock_summary.json")
    summary_df.to_csv(summary_csv, index=False)
    summary_df.to_json(summary_json, orient="records", indent=2)

    # Plot F1 spread across blocks
    plt.figure(figsize=(10, 5))
    plot_df = df_blocks[~df_blocks["Type"].isin(["Trivial"])]
    sns.barplot(data=plot_df, x="Model", y="F1", hue="Block", palette="Blues_d")
    plt.xticks(rotation=20, ha="right")
    plt.title("Rolling-Origin Time-Block Performance Across CSE-CIC-IDS2018 Days")
    plt.ylabel("F1 Score")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_FIGURES_DIR, "timeblock_f1_spread.png"), dpi=300)
    plt.close()

    return df_blocks, summary_df

def run_sensitivity_subsequence_m():
    """
    Subsequence length m sensitivity analysis:
    Sweep m in [5, 10, 20, 30, 50, 100] on UNSW-NB15 Flow telemetry.
    """
    print("\n" + "=" * 80)
    print("RUNNING SENSITIVITY ANALYSIS: SUBSEQUENCE LENGTH m")
    print("=" * 80)

    from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor

    df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=25000)
    df_eval = df_raw.iloc[:8000].copy()

    train_df, val_df, test_df = split_chronological(df_eval, train_frac=0.60, val_frac=0.20, test_frac=0.20)
    prep = UNSWPreprocessor(scaler_type="standard")
    prep.fit(train_df)

    X_train, y_train = prep.transform(train_df)
    X_val, y_val = prep.transform(val_df)
    X_test, y_test = prep.transform(test_df)

    time_col = "Stime" if "Stime" in test_df.columns else "stime"
    t_test = test_df[time_col].values

    X_full = np.vstack([X_train, X_val, X_test])
    n_train = len(X_train)
    n_val = len(X_val)
    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, len(X_full))

    m_values = [5, 10, 20, 30, 50, 75, 100]
    m_records = []

    for m_cand in m_values:
        print(f"Evaluating m = {m_cand}...")
        with ResourceProfiler() as prof:
            mps, indices = compute_multidimensional_mp(X_full, m=m_cand)
            knee_dim, _ = find_knee_dimension(mps, online=True, metric="max")
            scores_full = compute_point_anomaly_scores(mps, knee_dim=knee_dim, n_samples=len(X_full), m=m_cand)

        scores_val = scores_full[val_slice]
        scores_test = scores_full[test_slice]

        # Calibrate on validation
        val_percentiles = np.linspace(80, 99.8, 80)
        best_th = float(np.median(scores_val))
        best_f1_v = -1.0
        for p in val_percentiles:
            th = float(np.percentile(scores_val, p))
            f1_v = compute_classification_metrics(y_val, (scores_val >= th).astype(int))["f1"]
            if f1_v > best_f1_v:
                best_f1_v = f1_v
                best_th = th

        pred_te = (scores_test >= best_th).astype(int)
        cls_m = compute_classification_metrics(y_test, pred_te, scores_test)
        sre_m = compute_sre_operational_metrics(y_test, pred_te, timestamps=t_test, default_step_sec=1.0)
        boot = compute_bootstrap_confidence_intervals(y_test, pred_te, scores_test, timestamps=t_test, n_bootstraps=300)

        m_records.append({
            "m": m_cand,
            "Knee_Dimension": int(knee_dim),
            "F1": cls_m["f1"],
            "F1_CI_Low": boot["f1_ci"][0],
            "F1_CI_High": boot["f1_ci"][1],
            "Precision": cls_m["precision"],
            "Recall": cls_m["recall"],
            "FPR": cls_m["fpr"],
            "PR_AUC": cls_m["pr_auc"],
            "Total_Alerts": sre_m["total_alerts"],
            "MTTD_Sec": sre_m["mean_delay_sec"],
            "Runtime_Sec": prof.elapsed_seconds,
            "Peak_RAM_MB": prof.peak_mem_mb
        })

    m_df = pd.DataFrame(m_records)
    print("\n--- SENSITIVITY TO SUBSEQUENCE LENGTH m ---")
    print(m_df[["m", "Knee_Dimension", "F1", "F1_CI_Low", "F1_CI_High", "Precision", "Recall", "Runtime_Sec"]].to_string(index=False))

    m_csv = os.path.join(OUTPUT_METRICS_DIR, "sensitivity_m_results.csv")
    m_json = os.path.join(OUTPUT_METRICS_DIR, "sensitivity_m_results.json")
    m_df.to_csv(m_csv, index=False)
    m_df.to_json(m_json, orient="records", indent=2)

    # Plot sensitivity to m
    fig, ax1 = plt.subplots(figsize=(8, 5))
    ax2 = ax1.twinx()

    ax1.plot(m_df["m"], m_df["F1"], "o-", color="#2b5c8f", lw=2, label="F1-Score")
    ax1.fill_between(m_df["m"], m_df["F1_CI_Low"], m_df["F1_CI_High"], color="#2b5c8f", alpha=0.15)
    ax1.set_xlabel("Subsequence Length m", fontsize=11)
    ax1.set_ylabel("F1 Score", color="#2b5c8f", fontsize=11)
    ax1.set_ylim(0, 0.40)

    ax2.plot(m_df["m"], m_df["Runtime_Sec"], "s--", color="#d95f02", lw=2, label="Runtime (s)")
    ax2.set_ylabel("Execution Runtime (seconds)", color="#d95f02", fontsize=11)

    plt.title("mSTAMP Sensitivity to Subsequence Length m (UNSW-NB15 Flow)")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_FIGURES_DIR, "sensitivity_m.png"), dpi=300)
    plt.close()

    return m_df

def run_sensitivity_slices():
    """
    Sensitivity to alternative temporal slice cuts:
    Evaluates 4 different temporal slices of UNSW-NB15 Batch 1.
    """
    print("\n" + "=" * 80)
    print("RUNNING SENSITIVITY ANALYSIS: ALTERNATIVE TEMPORAL SLICES")
    print("=" * 80)

    from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor

    df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=25000)
    
    slices = [
        ("Slice 1 (Early Batch 1: [0:8000])", 0, 8000),
        ("Slice 2 (Shift +2000: [2000:10000])", 2000, 10000),
        ("Slice 3 (Shift +4000: [4000:12000])", 4000, 12000),
        ("Slice 4 (Shift +6000: [6000:14000])", 6000, 14000),
    ]

    slice_records = []
    for s_name, start_idx, end_idx in slices:
        print(f"Evaluating {s_name}...")
        df_sub = df_raw.iloc[start_idx:end_idx].copy()
        train_df, val_df, test_df = split_chronological(df_sub, train_frac=0.60, val_frac=0.20, test_frac=0.20)

        prep = UNSWPreprocessor(scaler_type="standard")
        prep.fit(train_df)

        X_train, y_train = prep.transform(train_df)
        X_val, y_val = prep.transform(val_df)
        X_test, y_test = prep.transform(test_df)

        time_col = "Stime" if "Stime" in test_df.columns else "stime"
        t_test = test_df[time_col].values

        b_res = evaluate_single_block(
            X_train, y_train, X_val, y_val, X_test, y_test, t_test, subseq_len_m=30, step_sec=1.0
        )

        for m_name in ["Config A (mSTAMP+Kneedle)", "Config B1 (Adaptive MAD)", "Baseline: Isolation Forest"]:
            if m_name in b_res:
                r = dict(b_res[m_name])
                r["Slice"] = s_name
                r["Test_Attack_Ratio"] = float(y_test.mean())
                slice_records.append(r)

    slice_df = pd.DataFrame(slice_records)
    print("\n--- SENSITIVITY TO TEMPORAL SLICES ---")
    print(slice_df[["Slice", "Model", "Test_Attack_Ratio", "F1", "Precision", "Recall", "Total_Alerts"]].to_string(index=False))

    s_csv = os.path.join(OUTPUT_METRICS_DIR, "sensitivity_slices_results.csv")
    s_json = os.path.join(OUTPUT_METRICS_DIR, "sensitivity_slices_results.json")
    slice_df.to_csv(s_csv, index=False)
    slice_df.to_json(s_json, orient="records", indent=2)

    # Plot slice comparison
    plt.figure(figsize=(10, 5))
    sns.barplot(data=slice_df, x="Slice", y="F1", hue="Model", palette="Set2")
    plt.xticks(rotation=15, ha="right")
    plt.title("Model Robustness Across Alternative Temporal Slices (UNSW-NB15)")
    plt.ylabel("F1 Score")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_FIGURES_DIR, "sensitivity_slices.png"), dpi=300)
    plt.close()

    return slice_df

if __name__ == "__main__":
    print("STARTING TIME-BLOCK & SENSITIVITY SUITE...")
    run_rolling_origin_csecicids2018()
    run_sensitivity_subsequence_m()
    run_sensitivity_slices()
    print("\nALL TIME-BLOCK AND SENSITIVITY EXPERIMENTS COMPLETE!")
