"""
Stage 2 Step 3: Conformal Anomaly Threshold Evaluation and Benchmark Pipeline
Evaluates and compares 4 threshold calibration paradigms across target significance levels alpha in {0.05, 0.01}:
1. Static Benign Quantile (Stage 1.5 Baseline)
2. Static Split-Conformal
3. Rolling Split-Conformal (W = 60 windows)
4. Adaptive Conformal Inference (ACI; Gibbs & Candes 2021, gamma = 0.01, W = 60)

Outputs:
- Metrics: results/v3_2/metrics/conformal_comparison_results.csv & .json
- Summary: results/v3_2/metrics/conformal_summary_by_method.csv & .json
- Predictions: results/v3_2/predictions/preds_conformal_*.parquet
- Diagnostic Figures: results/v3_2/figures/conformal_fpr_control_*.png, etc.
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Tuple, Optional
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.adaptive_threshold import ConformalQuantileThreshold, calibrate_benign_quantile_threshold
from src.evaluation import compute_sre_operational_metrics, find_campaign_intervals

OUTPUT_METRICS_DIR = "results/v3_2/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v3_2/predictions"
OUTPUT_FIGURES_DIR = "results/v3_2/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

# Define evaluation blocks and their metadata
BLOCKS_CONFIG = [
    {
        "block": "Thursday-15-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Cross-Day_Primary",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_thursday_60s_regular.parquet",
        "test_slice": slice(558, 720),
        "test_pred_file": "results/v3_1/predictions/preds_Thursday-15-02-2018_Cross-Day_Primary.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Thursday-15-02-2018_Cross-Day_Primary.parquet"
    },
    {
        "block": "Friday-16-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Cross-Day_Primary",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_friday_60s_regular.parquet",
        "test_slice": slice(552, 719),
        "test_pred_file": "results/v3_1/predictions/preds_Friday-16-02-2018_Cross-Day_Primary.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Friday-16-02-2018_Cross-Day_Primary.parquet"
    },
    {
        "block": "Wednesday-21-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Cross-Day_Primary",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_wednesday_60s_regular.parquet",
        "test_slice": slice(459, 529),
        "test_pred_file": "results/v3_1/predictions/preds_Wednesday-21-02-2018_Cross-Day_Primary.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Wednesday-21-02-2018_Cross-Day_Primary.parquet"
    },
    {
        "block": "Friday-16-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Within-Day_Sensitivity",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_friday_60s_regular.parquet",
        "test_slice": slice(552, 719),
        "test_pred_file": "results/v3_1/predictions/preds_Friday-16-02-2018_Within-Day_Sensitivity.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Friday-16-02-2018_Within-Day_Sensitivity.parquet"
    },
    {
        "block": "Wednesday-21-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Within-Day_Sensitivity",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_wednesday_60s_regular.parquet",
        "test_slice": slice(459, 529),
        "test_pred_file": "results/v3_1/predictions/preds_Wednesday-21-02-2018_Within-Day_Sensitivity.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Wednesday-21-02-2018_Within-Day_Sensitivity.parquet"
    },
    {
        "block": "UNSW_Window_Small_Regime-Shift_Block",
        "dataset": "UNSW-NB15",
        "design": "Window_Block",
        "is_flow": False,
        "step_sec": 10.0,
        "raw_parquet": None,
        "test_slice": None,
        "test_pred_file": "results/v3_1/predictions/preds_UNSW_Window_Small_Regime-Shift_Block.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_UNSW_Window_Small_Regime-Shift_Block.parquet"
    },
    {
        "block": "UNSW_Window_Regime_Shift_Demonstration",
        "dataset": "UNSW-NB15",
        "design": "Window_Block",
        "is_flow": False,
        "step_sec": 10.0,
        "raw_parquet": None,
        "test_slice": None,
        "test_pred_file": "results/v3_1/predictions/preds_UNSW_Window_Regime_Shift_Demonstration.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_UNSW_Window_Regime_Shift_Demonstration.parquet"
    },
    {
        "block": "UNSW_Flow_Contiguous_Block",
        "dataset": "UNSW-NB15",
        "design": "Flow_Block",
        "is_flow": True,
        "step_sec": 1.0,
        "raw_parquet": None,
        "test_slice": None,
        "test_pred_file": "results/v3_1/predictions/preds_UNSW_Flow_Contiguous_Block.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_UNSW_Flow_Contiguous_Block.parquet"
    }
]

MODELS_TO_EVAL = [
    "Baseline: Isolation Forest",
    "Baseline: ARIMA Residual",
    "Config A (mSTAMP+Kneedle)",
    "Config A-prime (Causal AB)"
]

def run_conformal_evaluations():
    print("=" * 80)
    print("STAGE 2: CONFORMAL ANOMALY THRESHOLD BENCHMARK PIPELINE")
    print("=" * 80)

    all_records = []
    
    # Store rolling data for Friday to plot
    friday_diagnostic_data = {}

    for binfo in BLOCKS_CONFIG:
        block_name = binfo["block"]
        dataset_name = binfo["dataset"]
        design = binfo["design"]
        is_flow = binfo["is_flow"]
        step_sec = binfo["step_sec"]

        print(f"\n---> Evaluating Block: {block_name} ({design})")

        # Load predictions
        df_test = pd.read_parquet(binfo["test_pred_file"])
        df_val = pd.read_parquet(binfo["val_pred_file"])

        y_test = df_test["y_true"].values.astype(int)
        y_val = df_val["y_true"].values.astype(int)
        n_test = len(y_test)
        prevalence = float(np.mean(y_test))

        # Load timestamps for test
        if binfo["raw_parquet"] is not None and os.path.exists(binfo["raw_parquet"]):
            raw_df = pd.read_parquet(binfo["raw_parquet"])
            timestamps_test = raw_df["window_time"].values[binfo["test_slice"]].astype(float)
        else:
            timestamps_test = np.arange(n_test, dtype=float) * step_sec

        # New predictions dataframe for conformal outputs
        df_conformal_out = df_test[["y_true"]].copy()

        for model_name in MODELS_TO_EVAL:
            score_col = f"{model_name}_score"
            if score_col not in df_test.columns or score_col not in df_val.columns:
                print(f"     [SKIP] {score_col} missing")
                continue

            s_val = np.nan_to_num(df_val[score_col].values.astype(float))
            s_test = np.nan_to_num(df_test[score_col].values.astype(float))
            df_conformal_out[f"{model_name}_score"] = s_test

            for alpha in [0.05, 0.01]:
                alpha_str = f"{int(alpha * 100):02d}"

                # ---------------------------------------------------------
                # Method 1: Static Benign Quantile (Stage 1.5 Baseline)
                # ---------------------------------------------------------
                th_quantile = calibrate_benign_quantile_threshold(s_val, y_val, alpha=alpha)
                p_quantile = (s_test >= th_quantile).astype(int)
                df_conformal_out[f"{model_name}_Quantile_a{alpha_str}_pred"] = p_quantile

                # ---------------------------------------------------------
                # Method 2: Static Split-Conformal
                # ---------------------------------------------------------
                cqt_static = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
                p_static = cqt_static.predict(s_test)
                th_static = cqt_static.threshold_
                df_conformal_out[f"{model_name}_SplitConf_a{alpha_str}_pred"] = p_static

                # ---------------------------------------------------------
                # Method 3: Rolling Split-Conformal (W = 60)
                # ---------------------------------------------------------
                cqt_rolling = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
                p_rolling, roll_thresh = cqt_rolling.predict_rolling(
                    s_test, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
                )
                df_conformal_out[f"{model_name}_RollConf_a{alpha_str}_pred"] = p_rolling
                df_conformal_out[f"{model_name}_RollConf_a{alpha_str}_thresh"] = roll_thresh

                # ---------------------------------------------------------
                # Method 4: Adaptive Conformal Inference (ACI, gamma=0.01)
                # ---------------------------------------------------------
                cqt_aci = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
                p_aci, aci_thresh, aci_alphas = cqt_aci.predict_aci(
                    s_test, gamma=0.01, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
                )
                df_conformal_out[f"{model_name}_ACI_a{alpha_str}_pred"] = p_aci
                df_conformal_out[f"{model_name}_ACI_a{alpha_str}_thresh"] = aci_thresh
                df_conformal_out[f"{model_name}_ACI_a{alpha_str}_adapted_alpha"] = aci_alphas

                # Save diagnostic time series for Friday DoS-Hulk plot
                if block_name == "Friday-16-02-2018" and design == "Cross-Day_Primary" and alpha == 0.05:
                    friday_diagnostic_data[model_name] = {
                        "scores": s_test,
                        "y_true": y_test,
                        "th_static": th_static,
                        "roll_thresh": roll_thresh,
                        "aci_thresh": aci_thresh,
                        "aci_alphas": aci_alphas
                    }

                # Evaluate all 4 methods
                methods = [
                    ("Static Benign Quantile", p_quantile, th_quantile, "Static"),
                    ("Static Split-Conformal", p_static, th_static, "Static"),
                    ("Rolling Split-Conformal", p_rolling, float(np.mean(roll_thresh)), "Adaptive"),
                    ("Adaptive Conformal (ACI)", p_aci, float(np.mean(aci_thresh)), "Adaptive")
                ]

                for m_name, pred_arr, mean_th, m_cat in methods:
                    tn, fp, fn, tp = confusion_matrix(y_test, pred_arr, labels=[0, 1]).ravel()
                    prec = float(precision_score(y_test, pred_arr, zero_division=0))
                    rec = float(recall_score(y_test, pred_arr, zero_division=0))
                    f1 = float(f1_score(y_test, pred_arr, zero_division=0))
                    achieved_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                    fpr_excess = achieved_fpr - alpha
                    fpr_target_met = (achieved_fpr <= alpha)

                    sre_m = compute_sre_operational_metrics(
                        y_test, pred_arr, timestamps=timestamps_test, default_step_sec=step_sec, is_flow_data=is_flow
                    )

                    all_records.append({
                        "Block": block_name,
                        "Dataset": dataset_name,
                        "Design": design,
                        "Model": model_name,
                        "Method": m_name,
                        "Method_Category": m_cat,
                        "Target_Alpha": alpha,
                        "Mean_Threshold": mean_th,
                        "Achieved_FPR": achieved_fpr,
                        "FPR_Excess_Error": fpr_excess,
                        "FPR_Target_Met": fpr_target_met,
                        "Recall": rec,
                        "Precision": prec,
                        "F1": f1,
                        "Prevalence": prevalence,
                        "Total_Alerts": int(pred_arr.sum()),
                        "Alerts_Per_1000": sre_m.get("alerts_per_1000_windows", 0.0),
                        "Alerts_Per_Hour": sre_m.get("alerts_per_hour", None),
                        "Campaign_Recall": sre_m.get("campaign_recall", 1.0),
                        "MTTD_Sec": sre_m.get("mttd_detected_campaigns_only_sec", None)
                    })

        # Save parquet with conformal alert columns
        out_parquet_path = os.path.join(OUTPUT_PREDICTIONS_DIR, f"preds_conformal_{block_name}_{design}.parquet")
        df_conformal_out.to_parquet(out_parquet_path, index=False)
        print(f"     Saved conformal predictions: {out_parquet_path}")

    # Convert all records to DataFrame
    df_results = pd.DataFrame(all_records)
    csv_path = os.path.join(OUTPUT_METRICS_DIR, "conformal_comparison_results.csv")
    json_path = os.path.join(OUTPUT_METRICS_DIR, "conformal_comparison_results.json")
    df_results.to_csv(csv_path, index=False)
    with open(json_path, "w") as f:
        json.dump(all_records, f, indent=2)
    print(f"\nSaved detailed comparison metrics: {csv_path}")

    # Generate Summary aggregated by Method and Target_Alpha
    summary_rows = []
    for (m_name, target_a), group in df_results.groupby(["Method", "Target_Alpha"]):
        summary_rows.append({
            "Method": m_name,
            "Target_Alpha": target_a,
            "Mean_Achieved_FPR": float(group["Achieved_FPR"].mean()),
            "Std_Achieved_FPR": float(group["Achieved_FPR"].std()),
            "Mean_FPR_Excess": float(group["FPR_Excess_Error"].mean()),
            "FPR_Target_Met_Fraction": float(group["FPR_Target_Met"].mean()),
            "Mean_F1": float(group["F1"].mean()),
            "Std_F1": float(group["F1"].std()),
            "Mean_Recall": float(group["Recall"].mean()),
            "Mean_Precision": float(group["Precision"].mean()),
            "Evaluated_Configurations": int(len(group))
        })
    df_summary = pd.DataFrame(summary_rows).sort_values(["Target_Alpha", "Mean_Achieved_FPR"])
    sum_csv = os.path.join(OUTPUT_METRICS_DIR, "conformal_summary_by_method.csv")
    sum_json = os.path.join(OUTPUT_METRICS_DIR, "conformal_summary_by_method.json")
    df_summary.to_csv(sum_csv, index=False)
    with open(sum_json, "w") as f:
        json.dump(summary_rows, f, indent=2)
    print(f"Saved aggregated summary metrics: {sum_csv}")

    # Generate Publication Figures
    generate_conformal_figures(df_results, df_summary, friday_diagnostic_data)

    print("\n" + "=" * 80)
    print("CONFORMAL BENCHMARK EVALUATION COMPLETE")
    print("=" * 80)

def generate_conformal_figures(df_results: pd.DataFrame, df_summary: pd.DataFrame, friday_data: dict):
    print("\nGenerating publication figures...")

    # Figure 1: FPR Control Comparison across Primary CSE Blocks (Alpha = 0.05)
    cse_pri = df_results[
        (df_results["Dataset"] == "CSE-CIC-IDS2018") &
        (df_results["Design"] == "Cross-Day_Primary") &
        (df_results["Target_Alpha"] == 0.05)
    ]

    fig, ax = plt.subplots(figsize=(10, 5), dpi=200)
    methods = [
        "Static Benign Quantile",
        "Static Split-Conformal",
        "Rolling Split-Conformal",
        "Adaptive Conformal (ACI)"
    ]
    colors = ["#7f7f7f", "#1f77b4", "#2ca02c", "#d62728"]

    x = np.arange(len(cse_pri["Block"].unique()))
    width = 0.20

    for i, m_name in enumerate(methods):
        sub = cse_pri[cse_pri["Method"] == m_name]
        mean_fprs = sub.groupby("Block")["Achieved_FPR"].mean().values
        ax.bar(x + (i - 1.5) * width, mean_fprs, width, label=m_name, color=colors[i], alpha=0.9, edgecolor="black")

    ax.axhline(0.05, color="red", linestyle="--", linewidth=1.5, label="Nominal Budget $\\alpha = 0.05$")
    ax.set_xticks(x)
    ax.set_xticklabels(cse_pri["Block"].unique(), fontsize=10)
    ax.set_ylabel("Mean Achieved Test False Positive Rate (FPR)", fontsize=11)
    ax.set_title("Stage 2 Conformal Threshold Benchmark: False Alarm Control across Days ($\\alpha = 0.05$)", fontsize=12, fontweight="bold")
    ax.grid(True, linestyle=":", alpha=0.6)
    ax.legend(frameon=True, fontsize=9)
    plt.tight_layout()
    fig_path1 = os.path.join(OUTPUT_FIGURES_DIR, "conformal_fpr_control_alpha05.png")
    plt.savefig(fig_path1)
    plt.close()
    print(f"Saved figure: {fig_path1}")

    # Figure 2: Method Trade-Off: F1 vs Achieved FPR (All Primary CSE Models)
    fig, ax = plt.subplots(figsize=(8, 5), dpi=200)
    for i, m_name in enumerate(methods):
        sub = cse_pri[cse_pri["Method"] == m_name]
        ax.scatter(sub["Achieved_FPR"], sub["F1"], color=colors[i], label=m_name, s=80, alpha=0.85, edgecolors="black")

    ax.axvline(0.05, color="red", linestyle="--", linewidth=1.5, label="Nominal Budget $\\alpha = 0.05$")
    ax.set_xlabel("Achieved False Positive Rate (FPR)", fontsize=11)
    ax.set_ylabel("Test $F_1$ Score", fontsize=11)
    ax.set_title("Stage 2: $F_1$ vs False Alarm Rate Trade-Off on CSE Cross-Day Primary", fontsize=12, fontweight="bold")
    ax.grid(True, linestyle=":", alpha=0.6)
    ax.legend(frameon=True, fontsize=9)
    plt.tight_layout()
    fig_path2 = os.path.join(OUTPUT_FIGURES_DIR, "conformal_f1_vs_fpr.png")
    plt.savefig(fig_path2)
    plt.close()
    print(f"Saved figure: {fig_path2}")

    # Figure 3: Dynamic Threshold Tracking on Friday (Isolation Forest & A-prime)
    if "Baseline: Isolation Forest" in friday_data:
        if_data = friday_data["Baseline: Isolation Forest"]
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 6), sharex=True, dpi=200)

        n_steps = len(if_data["scores"])
        t_axis = np.arange(n_steps)

        # Plot scores and thresholds
        ax1.plot(t_axis, if_data["scores"], label="Isolation Forest Score", color="#333333", alpha=0.7, linewidth=1.2)
        ax1.axhline(if_data["th_static"], color="#7f7f7f", linestyle="--", linewidth=1.5, label=f"Static Conformal Threshold ({if_data['th_static']:.3f})")
        ax1.plot(t_axis, if_data["roll_thresh"], color="#2ca02c", linestyle="-", linewidth=1.8, label="Rolling Conformal Threshold (W=60)")
        ax1.plot(t_axis, if_data["aci_thresh"], color="#d62728", linestyle="-.", linewidth=1.8, label="ACI Threshold (\\gamma=0.01)")
        
        # Shade attack period
        attack_mask = (if_data["y_true"] == 1)
        ax1.fill_between(t_axis, 0, np.max(if_data["scores"]) * 1.1, where=attack_mask, color="orange", alpha=0.25, label="DoS-Hulk Attack Campaign")
        
        ax1.set_ylabel("Anomaly Score & Thresholds", fontsize=10)
        ax1.set_title("Friday-16-02-2018 (DoS-Hulk): Dynamic Threshold Tracking under Diurnal Shift", fontsize=11, fontweight="bold")
        ax1.grid(True, linestyle=":", alpha=0.6)
        ax1.legend(loc="upper left", fontsize=8, framealpha=0.9)

        # Plot adapted nominal risk alpha_t for ACI
        ax2.plot(t_axis, if_data["aci_alphas"], color="#d62728", linewidth=1.8, label="ACI Adapted Risk $\\alpha_t$ (Target 0.05)")
        ax2.axhline(0.05, color="black", linestyle=":", linewidth=1.2, label="Nominal Target $\\alpha = 0.05$")
        ax2.set_xlabel("Elapsed Minutes on Test Slice", fontsize=10)
        ax2.set_ylabel("Adapted Nominal $\\alpha_t$", fontsize=10)
        ax2.set_ylim(0.0, 0.10)
        ax2.grid(True, linestyle=":", alpha=0.6)
        ax2.legend(loc="upper left", fontsize=8, framealpha=0.9)

        plt.tight_layout()
        fig_path3 = os.path.join(OUTPUT_FIGURES_DIR, "conformal_rolling_thresholds_friday.png")
        plt.savefig(fig_path3)
        plt.close()
        print(f"Saved figure: {fig_path3}")

if __name__ == "__main__":
    run_conformal_evaluations()

