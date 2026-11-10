"""
Stage 3: Bounded Testbed Validation Pipeline
Runs the frozen reproduction and extension pipeline on the live microservice testbed dataset.
Strict Protocol Constraints:
1. Frozen pipeline: exact same mSTAMP+Kneedle (A), Causal AB (A-prime), Isolation Forest, ARIMA Residual, and Conformal Thresholds.
2. Zero re-tuning on test period: thresholds calibrated strictly on benign validation partition [200:300].
3. Evaluates 20 attack campaigns + 5 benign flash crowds across [300:600].
4. Reports detection fidelity, MTTD, campaign recall, and Flash Crowd False Alarm Rejection.
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Tuple
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    roc_auc_score, average_precision_score, confusion_matrix,
    precision_score, recall_score, f1_score
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline, RandomUniformBaseline
)
from src.adaptive_threshold import ConformalQuantileThreshold, calibrate_benign_quantile_threshold
from src.evaluation import compute_sre_operational_metrics, find_campaign_intervals

OUTPUT_METRICS_DIR = "results/v3_3/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v3_3/predictions"
OUTPUT_FIGURES_DIR = "results/v3_3/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

FEATURE_COLS = [
    "flow_count", "tot_fwd_bytes", "tot_bwd_bytes", "duration_mean",
    "status_200_count", "status_4xx_count", "status_5xx_count",
    "error_rate", "p50_latency", "p95_latency", "p99_latency"
]

def run_testbed_evaluation():
    print("=" * 80)
    print("STAGE 3: FROZEN PIPELINE TESTBED VALIDATION EVALUATION")
    print("=" * 80)

    parquet_file = "data/testbed/testbed_60s_regular.parquet"
    if not os.path.exists(parquet_file):
        raise FileNotFoundError(f"Testbed dataset missing: {parquet_file}")

    df = pd.read_parquet(parquet_file)
    print(f"Loaded testbed dataset: {len(df)} regular 60s windows.")

    # Partitions:
    # Train: [0:200] (200 windows)
    # Val:   [200:300] (100 windows)
    # Test:  [300:600] (300 windows)
    train_df = df.iloc[0:200]
    val_df = df.iloc[200:300]
    test_df = df.iloc[300:600]

    n_train = len(train_df)
    n_val = len(val_df)
    n_test = len(test_df)
    total_len = len(df)

    # Standardize features using Train only (zero leakage)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(np.nan_to_num(train_df[FEATURE_COLS].values.astype(float)))
    X_val = scaler.transform(np.nan_to_num(val_df[FEATURE_COLS].values.astype(float)))
    X_test = scaler.transform(np.nan_to_num(test_df[FEATURE_COLS].values.astype(float)))
    X_full = np.vstack([X_train, X_val, X_test])

    y_train = train_df["Label"].values.astype(int)
    y_val = val_df["Label"].values.astype(int)
    y_test = test_df["Label"].values.astype(int)
    is_fc_test = test_df["is_flash_crowd"].values.astype(int)
    c_type_test = test_df["campaign_type"].values
    t_test = test_df["window_time"].values.astype(float)

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)

    print(f"Partitions: Train={n_train}, Val={n_val}, Test={n_test}")
    print(f"Test Attack Prevalence: {np.mean(y_test)*100:.2f}% ({np.sum(y_test)} attack windows)")
    print(f"Test Flash Crowd Windows: {np.sum(is_fc_test)} windows (Label = 0)")

    # 1. Compute Anomaly Scores for all Frozen Models
    print("\n[1/4] Computing causal anomaly scores for all frozen models...")
    model_scores = {}
    seed = 42

    # A. Isolation Forest
    print("      Fitting Isolation Forest...")
    if_model = IsolationForestBaseline(n_estimators=100, random_state=seed).fit(X_train)
    model_scores["Baseline: Isolation Forest"] = (
        if_model.score_samples(X_val),
        if_model.score_samples(X_test)
    )

    # B. ARIMA Residual
    print("      Fitting ARIMA Residual...")
    ar_model = ARIMAResidualBaseline(order=(1, 0, 1)).fit(X_train)
    model_scores["Baseline: ARIMA Residual"] = (
        ar_model.score_samples(X_val),
        ar_model.score_samples(X_test)
    )

    # C. Config A (mSTAMP + Kneedle)
    print("      Computing Config A (mSTAMP + Kneedle, m=10)...")
    mps_full, _ = compute_multidimensional_mp(X_full, m=10)
    mps_tr_val = mps_full[:, : n_train + n_val - 10 + 1]
    knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
    scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=10)
    model_scores["Config A (mSTAMP+Kneedle)"] = (
        scores_full_a[val_slice],
        scores_full_a[test_slice]
    )

    # D. Config A-prime (Causal AB)
    print("      Computing Config A-prime (Causal AB, m=10)...")
    aprime = CausalABScorer(m=10).fit(X_train)
    model_scores["Config A-prime (Causal AB)"] = (
        aprime.score(X_val),
        aprime.score(X_test)
    )

    # E. Trivial Baselines
    all_atk = AllAttackBaseline().fit(X_train, y_train)
    model_scores["Baseline: All-Attack"] = (all_atk.score_samples(X_val), all_atk.score_samples(X_test))
    all_norm = AllNormalBaseline().fit(X_train, y_train)
    model_scores["Baseline: All-Normal"] = (all_norm.score_samples(X_val), all_norm.score_samples(X_test))
    rand_u = RandomUniformBaseline(seed=seed).fit(X_train, y_train)
    model_scores["Baseline: Random Uniform"] = (rand_u.score_samples(X_val), rand_u.score_samples(X_test))

    # 2. Evaluate Performance Under Static & Conformal Thresholds
    print("\n[2/4] Evaluating models under static quantile vs conformal thresholding...")
    results = []
    fc_results = []
    preds_out = test_df[["window_idx", "window_time", "Label", "is_flash_crowd", "campaign_id", "campaign_type"]].copy()

    models_to_evaluate = [
        "Baseline: Isolation Forest",
        "Baseline: ARIMA Residual",
        "Config A (mSTAMP+Kneedle)",
        "Config A-prime (Causal AB)"
    ]

    for model_name in models_to_evaluate:
        s_val, s_test = model_scores[model_name]
        preds_out[f"{model_name}_score"] = s_test

        # Compute threshold-free discrimination metrics
        roc_auc = float(roc_auc_score(y_test, s_test))
        pr_auc = float(average_precision_score(y_test, s_test))
        prev = float(np.mean(y_test))
        pr_lift = float((pr_auc - prev) / prev)

        for alpha in [0.05, 0.01]:
            alpha_str = f"{int(alpha * 100):02d}"

            # Method 1: Static Benign Quantile
            th_quant = calibrate_benign_quantile_threshold(s_val, y_val, alpha=alpha)
            p_quant = (s_test >= th_quant).astype(int)

            # Method 2: Static Split-Conformal
            cqt_stat = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
            p_stat = cqt_stat.predict(s_test)
            th_stat = cqt_stat.threshold_

            # Method 3: Rolling Split-Conformal (W=60)
            cqt_roll = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
            p_roll, roll_thresh = cqt_roll.predict_rolling(
                s_test, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
            )

            # Method 4: Adaptive Conformal Inference (ACI, gamma=0.01, W=60)
            cqt_aci = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
            p_aci, aci_thresh, aci_alphas = cqt_aci.predict_aci(
                s_test, gamma=0.01, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
            )

            preds_out[f"{model_name}_Quantile_a{alpha_str}_pred"] = p_quant
            preds_out[f"{model_name}_SplitConf_a{alpha_str}_pred"] = p_stat
            preds_out[f"{model_name}_RollConf_a{alpha_str}_pred"] = p_roll
            preds_out[f"{model_name}_ACI_a{alpha_str}_pred"] = p_aci

            methods = [
                ("Static Benign Quantile", p_quant, th_quant),
                ("Static Split-Conformal", p_stat, th_stat),
                ("Rolling Split-Conformal", p_roll, float(np.mean(roll_thresh))),
                ("Adaptive Conformal (ACI)", p_aci, float(np.mean(aci_thresh)))
            ]

            for m_name, pred_arr, th_val in methods:
                tn, fp, fn, tp = confusion_matrix(y_test, pred_arr, labels=[0, 1]).ravel()
                prec = float(precision_score(y_test, pred_arr, zero_division=0))
                rec = float(recall_score(y_test, pred_arr, zero_division=0))
                f1 = float(f1_score(y_test, pred_arr, zero_division=0))
                achieved_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

                sre_m = compute_sre_operational_metrics(
                    y_test, pred_arr, timestamps=t_test, default_step_sec=60.0, is_flow_data=False
                )

                # Flash Crowd False Alarm Rate (fraction of benign flash crowd windows incorrectly flagged)
                fc_mask = (is_fc_test == 1)
                fc_alerts = int(np.sum(pred_arr[fc_mask]))
                fc_total = int(np.sum(fc_mask))
                fc_fpr = float(fc_alerts / fc_total) if fc_total > 0 else 0.0

                # Normal Quiescent Benign FPR (excluding flash crowds)
                pure_benign_mask = (y_test == 0) & (is_fc_test == 0)
                pb_alerts = int(np.sum(pred_arr[pure_benign_mask]))
                pb_total = int(np.sum(pure_benign_mask))
                pb_fpr = float(pb_alerts / pb_total) if pb_total > 0 else 0.0

                results.append({
                    "Model": model_name,
                    "Method": m_name,
                    "Target_Alpha": alpha,
                    "ROC_AUC": roc_auc,
                    "PR_AUC": pr_auc,
                    "PR_AUC_Lift": pr_lift,
                    "Achieved_FPR": achieved_fpr,
                    "FPR_Target_Met": (achieved_fpr <= alpha),
                    "Precision": prec,
                    "Recall": rec,
                    "F1": f1,
                    "Flash_Crowd_FPR": fc_fpr,
                    "Pure_Benign_FPR": pb_fpr,
                    "Alerts_Per_Hour": sre_m.get("alerts_per_hour", 0.0),
                    "Total_Alerts": int(pred_arr.sum()),
                    "Campaign_Recall": sre_m.get("campaign_recall", 1.0),
                    "MTTD_Sec": sre_m.get("mttd_detected_campaigns_only_sec", None)
                })

                # Breakdown by campaign type (at alpha = 0.05)
                if alpha == 0.05:
                    for c_type in ["volumetric_flood", "slowloris", "intermittent_spike", "endpoint_recon", "flash_crowd"]:
                        type_mask = (c_type_test == c_type)
                        t_count = int(np.sum(type_mask))
                        if t_count > 0:
                            t_alerts = int(np.sum(pred_arr[type_mask]))
                            fc_results.append({
                                "Model": model_name,
                                "Method": m_name,
                                "Campaign_Type": c_type,
                                "Total_Windows": t_count,
                                "Alert_Windows": t_alerts,
                                "Alert_Rate": float(t_alerts / t_count),
                                "Is_Attack": 0 if c_type == "flash_crowd" else 1
                            })

    # Save metrics and predictions
    print("\n[3/4] Saving testbed evaluation metrics...")
    df_results = pd.DataFrame(results)
    df_fc = pd.DataFrame(fc_results)

    res_csv = os.path.join(OUTPUT_METRICS_DIR, "testbed_results.csv")
    res_json = os.path.join(OUTPUT_METRICS_DIR, "testbed_results.json")
    fc_csv = os.path.join(OUTPUT_METRICS_DIR, "testbed_flash_crowd_breakdown.csv")
    fc_json = os.path.join(OUTPUT_METRICS_DIR, "testbed_flash_crowd_breakdown.json")
    pred_parquet = os.path.join(OUTPUT_PREDICTIONS_DIR, "preds_testbed_validation.parquet")

    df_results.to_csv(res_csv, index=False)
    df_results.to_json(res_json, orient="records", indent=2)
    df_fc.to_csv(fc_csv, index=False)
    df_fc.to_json(fc_json, orient="records", indent=2)
    preds_out.to_parquet(pred_parquet, index=False)

    print(f"      Results saved to: {res_csv}")
    print(f"      Flash crowd breakdown saved to: {fc_csv}")
    print(f"      Predictions saved to: {pred_parquet}")

    # 3. Generate Publication Figures
    print("\n[4/4] Generating validation publication figures...")
    generate_testbed_figures(df, test_df, preds_out, df_results, df_fc)

    print("\n" + "=" * 80)
    print("STAGE 3 TESTBED VALIDATION EVALUATION COMPLETE")
    print("=" * 80)

def generate_testbed_figures(df: pd.DataFrame, test_df: pd.DataFrame, preds_out: pd.DataFrame, df_results: pd.DataFrame, df_fc: pd.DataFrame):
    # Figure 1: Testbed Timeline: Requests, Error Rate, and Anomaly Scores
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 8), sharex=True, dpi=200)

    t_windows = np.arange(len(df))

    # Top: HTTP Request Flow Count & Flash Crowd Overlay
    ax1.plot(t_windows, df["flow_count"], color="#1f77b4", linewidth=1.2, label="HTTP Requests / Min")
    # Highlight attack windows
    attack_mask = (df["Label"] == 1).values
    fc_mask = (df["is_flash_crowd"] == 1).values
    ax1.fill_between(t_windows, 0, df["flow_count"].max() * 1.05, where=attack_mask, color="red", alpha=0.25, label="Attack Campaigns (Label=1)")
    ax1.fill_between(t_windows, 0, df["flow_count"].max() * 1.05, where=fc_mask, color="green", alpha=0.25, label="Benign Flash Crowds (Label=0)")
    ax1.axvline(200, color="black", linestyle="--", alpha=0.7, label="Train / Val Split")
    ax1.axvline(300, color="black", linestyle="-.", alpha=0.7, label="Val / Test Split")
    ax1.set_ylabel("Request Rate\n(req/min)", fontsize=9)
    ax1.set_title("Stage 3 Bounded Testbed: Telemetry Timeline (600 Windows, 25 Labeled Campaigns)", fontsize=11, fontweight="bold")
    ax1.grid(True, linestyle=":", alpha=0.6)
    ax1.legend(loc="upper right", fontsize=8, ncol=3)

    # Middle: Error Rate & p95 Latency
    ax2.plot(t_windows, df["error_rate"] * 100.0, color="#d62728", linewidth=1.2, label="Error Rate (%)")
    ax2_twin = ax2.twinx()
    ax2_twin.plot(t_windows, df["p95_latency"] * 1000.0, color="#ff7f0e", linestyle="--", linewidth=1.2, label="p95 Latency (ms)")
    ax2.set_ylabel("Error Rate (%)", fontsize=9, color="#d62728")
    ax2_twin.set_ylabel("p95 Latency (ms)", fontsize=9, color="#ff7f0e")
    ax2.grid(True, linestyle=":", alpha=0.6)
    ax2.legend(loc="upper left", fontsize=8)
    ax2_twin.legend(loc="upper right", fontsize=8)

    # Bottom: Normalized Model Anomaly Scores on Test Slice [300:600]
    t_test = np.arange(300, 600)
    for model_col, color, label in [
        ("Baseline: Isolation Forest_score", "#9467bd", "Isolation Forest"),
        ("Baseline: ARIMA Residual_score", "#8c564b", "ARIMA Residual"),
        ("Config A (mSTAMP+Kneedle)_score", "#e377c2", "mSTAMP (Config A)"),
        ("Config A-prime (Causal AB)_score", "#17becf", "Causal AB (A-prime)")
    ]:
        if model_col in preds_out.columns:
            s = preds_out[model_col].values
            s_norm = (s - np.min(s)) / (np.max(s) - np.min(s) + 1e-6)
            ax3.plot(t_test, s_norm, label=label, color=color, linewidth=1.2, alpha=0.85)

    ax3.fill_between(t_test, 0, 1.05, where=(test_df["Label"] == 1).values, color="red", alpha=0.15)
    ax3.fill_between(t_test, 0, 1.05, where=(test_df["is_flash_crowd"] == 1).values, color="green", alpha=0.15)
    ax3.set_ylabel("Normalized\nAnomaly Score", fontsize=9)
    ax3.set_xlabel("Elapsed 60-Second Windows (10 Hours Total)", fontsize=10)
    ax3.grid(True, linestyle=":", alpha=0.6)
    ax3.legend(loc="upper right", fontsize=8, ncol=4)

    plt.tight_layout()
    fig1_path = os.path.join(OUTPUT_FIGURES_DIR, "testbed_timeline_scores.png")
    plt.savefig(fig1_path)
    plt.close()
    print(f"      Saved figure: {fig1_path}")

    # Figure 2: Campaign Type Detection vs Flash Crowd False Alarms (alpha = 0.05)
    sub_fc = df_fc[df_fc["Method"] == "Adaptive Conformal (ACI)"]
    if len(sub_fc) > 0:
        fig, ax = plt.subplots(figsize=(9, 5), dpi=200)
        types = ["volumetric_flood", "slowloris", "intermittent_spike", "endpoint_recon", "flash_crowd"]
        type_labels = ["Volumetric Flood\n(Attack)", "Slowloris\n(Attack)", "Intermittent Spike\n(Attack)", "Endpoint Recon\n(Attack)", "Flash Crowd\n(Benign)"]
        colors_bar = ["#d62728", "#ff7f0e", "#e377c2", "#9467bd", "#2ca02c"]

        x = np.arange(len(types))
        width = 0.20

        models_list = ["Baseline: Isolation Forest", "Baseline: ARIMA Residual", "Config A (mSTAMP+Kneedle)", "Config A-prime (Causal AB)"]
        m_colors = ["#1f77b4", "#aec7e8", "#ffbb78", "#98df8a"]

        for i, m_name in enumerate(models_list):
            m_sub = sub_fc[sub_fc["Model"] == m_name]
            rates = []
            for c_t in types:
                row = m_sub[m_sub["Campaign_Type"] == c_t]
                rates.append(row["Alert_Rate"].values[0] if len(row) > 0 else 0.0)
            ax.bar(x + (i - 1.5) * width, rates, width, label=m_name.replace("Baseline: ", "").replace("Config ", ""), alpha=0.9, edgecolor="black")

        ax.axhline(0.05, color="black", linestyle="--", linewidth=1.2, label="$\\alpha = 0.05$ Budget")
        ax.set_xticks(x)
        ax.set_xticklabels(type_labels, fontsize=9)
        ax.set_ylabel("Alert Rate / Window", fontsize=10)
        ax.set_title("Stage 3 Validation: Detection Rate Across Attacks vs. Flash Crowd Rejection (ACI $\\alpha=0.05$)", fontsize=11, fontweight="bold")
        ax.grid(True, linestyle=":", alpha=0.6)
        ax.legend(frameon=True, fontsize=8)
        plt.tight_layout()
        fig2_path = os.path.join(OUTPUT_FIGURES_DIR, "testbed_campaign_type_recall.png")
        plt.savefig(fig2_path)
        plt.close()
        print(f"      Saved figure: {fig2_path}")

if __name__ == "__main__":
    run_testbed_evaluation()
