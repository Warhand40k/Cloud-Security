"""
Stage 4 Step 3: Conformal Comparison at Matched Operating Points
Verification and honest re-measurement of conformal thresholding claims.

Evaluates:
1. Static Benign Quantile across alpha grid {0.005, 0.01, 0.02, 0.05, 0.10}
2. Static Split-Conformal across alpha grid {0.005, 0.01, 0.02, 0.05, 0.10}
3. Rolling Split-Conformal (Label-Free Autonomous) across alpha grid
4. Adaptive Conformal Inference (ACI, Label-Free Autonomous) across alpha grid
5. Oracle-feedback variants as reference upper bounds

Deliverables:
- results/v4/metrics/matched_operating_points_comparison.csv
- results/v4/metrics/conformal_reachability_table.csv
- results/v4/metrics/conformal_fpr_control_summary.csv
- results/v4/metrics/conformal_paired_comparison.csv
- results/v4/metrics/conformal_configuration_changes.csv
- results/v4/figures/figure_recall_vs_fpr_cse_cross_day.png
- results/v4/figures/figure_recall_vs_fpr_unsw_and_sensitivity.png
- results/v4/figures/figure_recall_vs_fpr_paired_comparison.png
- results/v4/run_metadata_step3.json
"""

import os
import sys
import json
import time
import socket
import platform
import subprocess
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Tuple, Optional
from scipy.stats import beta
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.adaptive_threshold import ConformalQuantileThreshold, calibrate_benign_quantile_threshold
from experiments.run_stage4_step1_verification import BLOCKS_CONFIG, MODELS_TO_EVAL

OUTPUT_METRICS_DIR = "results/v4/metrics"
OUTPUT_FIGURES_DIR = "results/v4/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

ALPHA_GRID = [0.005, 0.01, 0.02, 0.05, 0.10]

def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Exact Clopper-Pearson 95% confidence interval for binomial success probability."""
    if n == 0:
        return 0.0, 0.0
    lower = 0.0 if k == 0 else float(beta.ppf(alpha / 2.0, k, n - k + 1))
    upper = 1.0 if k == n else float(beta.ppf(1.0 - alpha / 2.0, k + 1, n - k))
    return lower, upper

def mbb_recall_diff(
    y_true: np.ndarray,
    y_pred_adapt: np.ndarray,
    y_pred_static: np.ndarray,
    block_size: int = 10,
    n_bootstraps: int = 1000,
    seed: int = 42
) -> Tuple[float, float, float]:
    """
    Moving-Block Bootstrap (MBB) 95% confidence interval on paired recall difference:
    Delta Recall = Recall(adaptive) - Recall(static).
    Resamples contiguous time blocks of length B=block_size with replacement.
    """
    rng = np.random.default_rng(seed)
    n = len(y_true)
    if n == 0 or np.sum(y_true) == 0:
        return 0.0, 0.0, 0.0

    b_size = max(1, min(block_size, n // 2)) if n > 2 else 1
    num_blocks = int(np.ceil(n / b_size))
    max_start = max(1, n - b_size + 1)

    diffs = []
    for _ in range(n_bootstraps):
        starts = rng.integers(0, max_start, size=num_blocks)
        idx = np.concatenate([np.arange(s, s + b_size) for s in starts])[:n]
        yt_b = y_true[idx]
        if np.sum(yt_b) == 0:
            continue
        r_a = recall_score(yt_b, y_pred_adapt[idx], zero_division=0)
        r_s = recall_score(yt_b, y_pred_static[idx], zero_division=0)
        diffs.append(r_a - r_s)

    if len(diffs) == 0:
        return 0.0, 0.0, 0.0

    diffs = np.array(diffs)
    mean_diff = float(np.mean(diffs))
    ci_low = float(np.percentile(diffs, 2.5))
    ci_high = float(np.percentile(diffs, 97.5))
    return mean_diff, ci_low, ci_high

def save_run_metadata(step_name: str):
    try:
        git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    except Exception:
        git_commit = "unknown"

    meta = {
        "step": step_name,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit,
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "hostname": socket.gethostname(),
        "package_versions": {
            "numpy": np.__version__,
            "pandas": pd.__version__
        }
    }
    meta_path = os.path.join("results/v4", f"run_metadata_{step_name}.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Recorded run metadata to {meta_path}")

def run_step3_evaluation():
    print("=" * 80)
    print("STAGE 4 STEP 3: CONFORMAL COMPARISON AT MATCHED OPERATING POINTS")
    print("=" * 80)

    # 1. Evaluate all methods across the alpha grid
    raw_eval_records = []
    predictions_store = {}

    for binfo in BLOCKS_CONFIG:
        block_name = binfo["block"]
        design = binfo["design"]
        dataset = binfo["dataset"]

        df_test = pd.read_parquet(binfo["test_pred_file"])
        df_val = pd.read_parquet(binfo["val_pred_file"])
        y_test = df_test["y_true"].values.astype(int)
        y_val = df_val["y_true"].values.astype(int)
        prevalence = float(np.mean(y_test))

        for model_name in MODELS_TO_EVAL:
            score_col = f"{model_name}_score"
            if score_col not in df_test.columns or score_col not in df_val.columns:
                continue

            s_val = np.nan_to_num(df_val[score_col].values.astype(float))
            s_test = np.nan_to_num(df_test[score_col].values.astype(float))

            for alpha in ALPHA_GRID:
                # 1. Static Benign Quantile
                th_q = calibrate_benign_quantile_threshold(s_val, y_val, alpha=alpha)
                p_q = (s_test >= th_q).astype(int)

                # 2. Static Split-Conformal
                cqt = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
                p_c = cqt.predict(s_test)
                th_c = cqt.threshold_

                # 3. Rolling Conformal (Label-Free)
                p_r_lf, th_r_lf = cqt.predict_rolling_label_free(s_test, window_size=60, alpha=alpha)

                # 4. ACI (Label-Free)
                p_a_lf, th_a_lf, _ = cqt.predict_aci_label_free(s_test, gamma=0.01, window_size=60, alpha=alpha)

                # 5. Rolling Conformal (Oracle)
                p_r_orc, th_r_orc = cqt.predict_rolling_oracle(
                    s_test, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
                )

                # 6. ACI (Oracle)
                p_a_orc, th_a_orc, _ = cqt.predict_aci_oracle(
                    s_test, gamma=0.01, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
                )

                evaluated_items = [
                    ("Static Benign Quantile", p_q, th_q, "Static", "Baseline"),
                    ("Static Split-Conformal", p_c, th_c, "Static", "Baseline"),
                    ("Rolling Split-Conformal (Label-Free)", p_r_lf, float(np.mean(th_r_lf)), "Adaptive", "Label-Free Autonomous"),
                    ("Adaptive Conformal (ACI, Label-Free)", p_a_lf, float(np.mean(th_a_lf)), "Adaptive", "Label-Free Autonomous"),
                    ("Rolling Split-Conformal (Oracle)", p_r_orc, float(np.mean(th_r_orc)), "Adaptive", "Oracle-Feedback Upper Bound"),
                    ("Adaptive Conformal (ACI, Oracle)", p_a_orc, float(np.mean(th_a_orc)), "Adaptive", "Oracle-Feedback Upper Bound")
                ]

                for m_name, pred_arr, mean_th, m_cat, m_var in evaluated_items:
                    tn, fp, fn, tp = confusion_matrix(y_test, pred_arr, labels=[0, 1]).ravel()
                    prec = float(precision_score(y_test, pred_arr, zero_division=0))
                    rec = float(recall_score(y_test, pred_arr, zero_division=0))
                    f1 = float(f1_score(y_test, pred_arr, zero_division=0))
                    achieved_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                    fpr_target_met = (achieved_fpr <= alpha)

                    raw_eval_records.append({
                        "Block": block_name,
                        "Dataset": dataset,
                        "Design": design,
                        "Model": model_name,
                        "Method": m_name,
                        "Method_Category": m_cat,
                        "Variant": m_var,
                        "Target_Alpha": alpha,
                        "Mean_Threshold": mean_th,
                        "Achieved_FPR": achieved_fpr,
                        "FPR_Excess_Error": achieved_fpr - alpha,
                        "FPR_Target_Met": fpr_target_met,
                        "Recall": rec,
                        "Precision": prec,
                        "F1": f1,
                        "Prevalence": prevalence,
                        "Total_Alerts": int(np.sum(pred_arr))
                    })

                    # Store key predictions for paired comparisons
                    key = (block_name, design, model_name, m_name, alpha)
                    predictions_store[key] = pred_arr

    df_eval = pd.DataFrame(raw_eval_records)
    eval_csv_path = os.path.join(OUTPUT_METRICS_DIR, "matched_operating_points_comparison.csv")
    df_eval.to_csv(eval_csv_path, index=False)
    print(f"Saved full operating points comparison to {eval_csv_path} ({len(df_eval)} rows)")

    # -------------------------------------------------------------------------
    # 2. Reachability Table (Recall at Achieved FPR <= 0.01 and <= 0.05)
    # -------------------------------------------------------------------------
    def get_best_reachable(sub_df: pd.DataFrame, max_fpr: float) -> str:
        valid = sub_df[sub_df["Achieved_FPR"] <= max_fpr]
        if len(valid) == 0:
            return "not reachable"
        # Best recall subject to Achieved FPR <= max_fpr
        best = valid.sort_values(by=["Recall", "Achieved_FPR"], ascending=[False, True]).iloc[0]
        return f"{best['Recall']:.4f} (FPR={best['Achieved_FPR']:.4f}, a={best['Target_Alpha']})"

    reachability_records = []
    for (block, design, dataset, model), grp in df_eval.groupby(["Block", "Design", "Dataset", "Model"]):
        for method in [
            "Static Benign Quantile",
            "Static Split-Conformal",
            "Rolling Split-Conformal (Label-Free)",
            "Adaptive Conformal (ACI, Label-Free)",
            "Rolling Split-Conformal (Oracle)",
            "Adaptive Conformal (ACI, Oracle)"
        ]:
            m_sub = grp[grp["Method"] == method]
            r01 = get_best_reachable(m_sub, 0.01)
            r05 = get_best_reachable(m_sub, 0.05)
            reachability_records.append({
                "Block": block,
                "Dataset": dataset,
                "Design": design,
                "Model": model,
                "Method": method,
                "Best_Recall_at_FPR_le_0.01": r01,
                "Best_Recall_at_FPR_le_0.05": r05
            })

    df_reach = pd.DataFrame(reachability_records)
    reach_csv_path = os.path.join(OUTPUT_METRICS_DIR, "conformal_reachability_table.csv")
    df_reach.to_csv(reach_csv_path, index=False)
    print(f"Saved reachability table to {reach_csv_path}")

    # -------------------------------------------------------------------------
    # 3. FPR Control & Coverage Summary Table (Clopper-Pearson, Mean/Std, Max FPR)
    # -------------------------------------------------------------------------
    summary_records = []
    for alpha in [0.01, 0.05]:
        sub_a = df_eval[df_eval["Target_Alpha"] == alpha]
        for method in [
            "Static Benign Quantile",
            "Static Split-Conformal",
            "Rolling Split-Conformal (Label-Free)",
            "Adaptive Conformal (ACI, Label-Free)",
            "Rolling Split-Conformal (Oracle)",
            "Adaptive Conformal (ACI, Oracle)"
        ]:
            m_df = sub_a[sub_a["Method"] == method]
            n_total = len(m_df)
            k_met = int(m_df["FPR_Target_Met"].sum())
            frac_met = float(k_met / n_total) if n_total > 0 else 0.0
            ci_low, ci_high = clopper_pearson(k_met, n_total)

            all_mean_fpr = float(m_df["Achieved_FPR"].mean())
            all_std_fpr = float(m_df["Achieved_FPR"].std())
            max_fpr = float(m_df["Achieved_FPR"].max())

            # Cross-day primary subset (12 runs)
            cse_df = m_df[m_df["Design"] == "Cross-Day_Primary"]
            cse_mean_fpr = float(cse_df["Achieved_FPR"].mean())
            cse_std_fpr = float(cse_df["Achieved_FPR"].std())

            # Unreachability counts from df_reach
            m_reach = df_reach[df_reach["Method"] == method]
            unreachable_01 = int((m_reach["Best_Recall_at_FPR_le_0.01"] == "not reachable").sum())
            unreachable_05 = int((m_reach["Best_Recall_at_FPR_le_0.05"] == "not reachable").sum())

            summary_records.append({
                "Target_Alpha": alpha,
                "Method": method,
                "Variant": m_df["Variant"].iloc[0],
                "Total_Runs": n_total,
                "Runs_Meeting_Target": k_met,
                "Fraction_Meeting_Target": frac_met,
                "CP_95_CI_Lower": ci_low,
                "CP_95_CI_Upper": ci_high,
                "All_Runs_Mean_FPR": all_mean_fpr,
                "All_Runs_Std_FPR": all_std_fpr,
                "Max_Observed_FPR": max_fpr,
                "CSE_CrossDay_Mean_FPR": cse_mean_fpr,
                "CSE_CrossDay_Std_FPR": cse_std_fpr,
                "Runs_FPR_le_0.01_Unreachable": unreachable_01,
                "Runs_FPR_le_0.05_Unreachable": unreachable_05
            })

    df_summary = pd.DataFrame(summary_records)
    summary_csv_path = os.path.join(OUTPUT_METRICS_DIR, "conformal_fpr_control_summary.csv")
    df_summary.to_csv(summary_csv_path, index=False)
    print(f"Saved FPR control summary to {summary_csv_path}")

    # -------------------------------------------------------------------------
    # 4. Paired Comparison at Matched Operating Points (Win/Tie/Loss & MBB)
    # -------------------------------------------------------------------------
    # Determine the static quantile alpha matching mean achieved FPR
    # All 32 configurations:
    roll_lf_mean_fpr_all = float(df_eval[(df_eval["Method"] == "Rolling Split-Conformal (Label-Free)") & (df_eval["Target_Alpha"] == 0.05)]["Achieved_FPR"].mean())
    aci_lf_mean_fpr_all = float(df_eval[(df_eval["Method"] == "Adaptive Conformal (ACI, Label-Free)") & (df_eval["Target_Alpha"] == 0.05)]["Achieved_FPR"].mean())

    # CSE Cross-Day Primary (12 runs):
    roll_lf_mean_fpr_cse = float(df_eval[(df_eval["Method"] == "Rolling Split-Conformal (Label-Free)") & (df_eval["Design"] == "Cross-Day_Primary") & (df_eval["Target_Alpha"] == 0.05)]["Achieved_FPR"].mean())
    aci_lf_mean_fpr_cse = float(df_eval[(df_eval["Method"] == "Adaptive Conformal (ACI, Label-Free)") & (df_eval["Design"] == "Cross-Day_Primary") & (df_eval["Target_Alpha"] == 0.05)]["Achieved_FPR"].mean())

    print("\nMatched Mean Achieved FPR Targets:")
    print(f"  All 32 runs: Rolling LF mean FPR = {roll_lf_mean_fpr_all:.4f}, ACI LF mean FPR = {aci_lf_mean_fpr_all:.4f}")
    print(f"  CSE Cross-Day: Rolling LF mean FPR = {roll_lf_mean_fpr_cse:.4f}, ACI LF mean FPR = {aci_lf_mean_fpr_cse:.4f}")

    # Find matching static alpha by interpolation/calibration
    # We calibrate static quantile thresholds directly at alpha = target_mean_fpr for exact match,
    # and also compare against nominal alpha = 0.05.
    paired_records = []

    for binfo in BLOCKS_CONFIG:
        block_name = binfo["block"]
        design = binfo["design"]
        dataset = binfo["dataset"]

        df_test = pd.read_parquet(binfo["test_pred_file"])
        df_val = pd.read_parquet(binfo["val_pred_file"])
        y_test = df_test["y_true"].values.astype(int)
        y_val = df_val["y_true"].values.astype(int)

        for model_name in MODELS_TO_EVAL:
            score_col = f"{model_name}_score"
            if score_col not in df_test.columns:
                continue

            s_val = np.nan_to_num(df_val[score_col].values.astype(float))
            s_test = np.nan_to_num(df_test[score_col].values.astype(float))

            # Retrieve predictions from store
            p_q05 = predictions_store[(block_name, design, model_name, "Static Benign Quantile", 0.05)]
            p_roll_lf = predictions_store[(block_name, design, model_name, "Rolling Split-Conformal (Label-Free)", 0.05)]
            p_aci_lf = predictions_store[(block_name, design, model_name, "Adaptive Conformal (ACI, Label-Free)", 0.05)]

            # Static Quantile exactly calibrated at matched alpha
            # For all runs:
            th_q_matched_roll = calibrate_benign_quantile_threshold(s_val, y_val, alpha=roll_lf_mean_fpr_all)
            p_q_matched_roll = (s_test >= th_q_matched_roll).astype(int)

            th_q_matched_aci = calibrate_benign_quantile_threshold(s_val, y_val, alpha=aci_lf_mean_fpr_all)
            p_q_matched_aci = (s_test >= th_q_matched_aci).astype(int)

            # Metrics
            tn_q05, fp_q05, fn_q05, tp_q05 = confusion_matrix(y_test, p_q05, labels=[0, 1]).ravel()
            fpr_q05 = fp_q05 / (fp_q05 + tn_q05) if (fp_q05 + tn_q05) > 0 else 0.0
            rec_q05 = recall_score(y_test, p_q05, zero_division=0)
            f1_q05 = f1_score(y_test, p_q05, zero_division=0)

            tn_mr, fp_mr, _, _ = confusion_matrix(y_test, p_q_matched_roll, labels=[0, 1]).ravel()
            fpr_mr = fp_mr / (fp_mr + tn_mr) if (fp_mr + tn_mr) > 0 else 0.0
            rec_mr = recall_score(y_test, p_q_matched_roll, zero_division=0)
            f1_mr = f1_score(y_test, p_q_matched_roll, zero_division=0)

            tn_ma, fp_ma, _, _ = confusion_matrix(y_test, p_q_matched_aci, labels=[0, 1]).ravel()
            fpr_ma = fp_ma / (fp_ma + tn_ma) if (fp_ma + tn_ma) > 0 else 0.0
            rec_ma = recall_score(y_test, p_q_matched_aci, zero_division=0)
            f1_ma = f1_score(y_test, p_q_matched_aci, zero_division=0)

            tn_rl, fp_rl, _, _ = confusion_matrix(y_test, p_roll_lf, labels=[0, 1]).ravel()
            fpr_rl = fp_rl / (fp_rl + tn_rl) if (fp_rl + tn_rl) > 0 else 0.0
            rec_rl = recall_score(y_test, p_roll_lf, zero_division=0)
            f1_rl = f1_score(y_test, p_roll_lf, zero_division=0)

            tn_al, fp_al, _, _ = confusion_matrix(y_test, p_aci_lf, labels=[0, 1]).ravel()
            fpr_al = fp_al / (fp_al + tn_al) if (fp_al + tn_al) > 0 else 0.0
            rec_al = recall_score(y_test, p_aci_lf, zero_division=0)
            f1_al = f1_score(y_test, p_aci_lf, zero_division=0)

            # Paired comparisons:
            # 1. Rolling LF vs Matched Static Quantile
            delta_rec_roll_m = rec_rl - rec_mr
            mbb_mean_r_m, mbb_cil_r_m, mbb_cih_r_m = mbb_recall_diff(y_test, p_roll_lf, p_q_matched_roll, seed=42)
            outcome_roll_m = "Win" if delta_rec_roll_m > 1e-6 else ("Loss" if delta_rec_roll_m < -1e-6 else "Tie")
            sig_roll_m = "Significant Win" if mbb_cil_r_m > 0 else ("Significant Loss" if mbb_cih_r_m < 0 else "Inconclusive / Tie")

            # 2. Rolling LF vs Nominal Static Quantile (alpha=0.05)
            delta_rec_roll_nom = rec_rl - rec_q05
            mbb_mean_r_nom, mbb_cil_r_nom, mbb_cih_r_nom = mbb_recall_diff(y_test, p_roll_lf, p_q05, seed=42)
            outcome_roll_nom = "Win" if delta_rec_roll_nom > 1e-6 else ("Loss" if delta_rec_roll_nom < -1e-6 else "Tie")
            sig_roll_nom = "Significant Win" if mbb_cil_r_nom > 0 else ("Significant Loss" if mbb_cih_r_nom < 0 else "Inconclusive / Tie")

            # 3. ACI LF vs Matched Static Quantile
            delta_rec_aci_m = rec_al - rec_ma
            mbb_mean_a_m, mbb_cil_a_m, mbb_cih_a_m = mbb_recall_diff(y_test, p_aci_lf, p_q_matched_aci, seed=42)
            outcome_aci_m = "Win" if delta_rec_aci_m > 1e-6 else ("Loss" if delta_rec_aci_m < -1e-6 else "Tie")
            sig_aci_m = "Significant Win" if mbb_cil_a_m > 0 else ("Significant Loss" if mbb_cih_a_m < 0 else "Inconclusive / Tie")

            # 4. ACI LF vs Nominal Static Quantile (alpha=0.05)
            delta_rec_aci_nom = rec_al - rec_q05
            mbb_mean_a_nom, mbb_cil_a_nom, mbb_cih_a_nom = mbb_recall_diff(y_test, p_aci_lf, p_q05, seed=42)
            outcome_aci_nom = "Win" if delta_rec_aci_nom > 1e-6 else ("Loss" if delta_rec_aci_nom < -1e-6 else "Tie")
            sig_aci_nom = "Significant Win" if mbb_cil_a_nom > 0 else ("Significant Loss" if mbb_cih_a_nom < 0 else "Inconclusive / Tie")

            paired_records.append({
                "Block": block_name,
                "Dataset": dataset,
                "Design": design,
                "Model": model_name,
                # Static Nominal
                "Static_Nom_FPR": fpr_q05,
                "Static_Nom_Recall": rec_q05,
                "Static_Nom_F1": f1_q05,
                # Static Matched (Rolling)
                "Static_Matched_Roll_FPR": fpr_mr,
                "Static_Matched_Roll_Recall": rec_mr,
                "Static_Matched_Roll_F1": f1_mr,
                # Static Matched (ACI)
                "Static_Matched_ACI_FPR": fpr_ma,
                "Static_Matched_ACI_Recall": rec_ma,
                "Static_Matched_ACI_F1": f1_ma,
                # Rolling LF
                "Roll_LF_FPR": fpr_rl,
                "Roll_LF_Recall": rec_rl,
                "Roll_LF_F1": f1_rl,
                # ACI LF
                "ACI_LF_FPR": fpr_al,
                "ACI_LF_Recall": rec_al,
                "ACI_LF_F1": f1_al,
                # Rolling vs Matched Static
                "Delta_Recall_Roll_vs_Matched": delta_rec_roll_m,
                "MBB_Mean_Roll_vs_Matched": mbb_mean_r_m,
                "MBB_95_CI_Low_Roll_vs_Matched": mbb_cil_r_m,
                "MBB_95_CI_High_Roll_vs_Matched": mbb_cih_r_m,
                "Outcome_Roll_vs_Matched": outcome_roll_m,
                "Sig_Roll_vs_Matched": sig_roll_m,
                # Rolling vs Nominal Static
                "Delta_Recall_Roll_vs_Nominal": delta_rec_roll_nom,
                "MBB_Mean_Roll_vs_Nominal": mbb_mean_r_nom,
                "MBB_95_CI_Low_Roll_vs_Nominal": mbb_cil_r_nom,
                "MBB_95_CI_High_Roll_vs_Nominal": mbb_cih_r_nom,
                "Outcome_Roll_vs_Nominal": outcome_roll_nom,
                "Sig_Roll_vs_Nominal": sig_roll_nom,
                # ACI vs Matched Static
                "Delta_Recall_ACI_vs_Matched": delta_rec_aci_m,
                "MBB_Mean_ACI_vs_Matched": mbb_mean_a_m,
                "MBB_95_CI_Low_ACI_vs_Matched": mbb_cil_a_m,
                "MBB_95_CI_High_ACI_vs_Matched": mbb_cih_a_m,
                "Outcome_ACI_vs_Matched": outcome_aci_m,
                "Sig_ACI_vs_Matched": sig_aci_m,
                # ACI vs Nominal Static
                "Delta_Recall_ACI_vs_Nominal": delta_rec_aci_nom,
                "MBB_Mean_ACI_vs_Nominal": mbb_mean_a_nom,
                "MBB_95_CI_Low_ACI_vs_Nominal": mbb_cil_a_nom,
                "MBB_95_CI_High_ACI_vs_Nominal": mbb_cih_a_nom,
                "Outcome_ACI_vs_Nominal": outcome_aci_nom,
                "Sig_ACI_vs_Nominal": sig_aci_nom,
            })

    df_paired = pd.DataFrame(paired_records)
    paired_csv_path = os.path.join(OUTPUT_METRICS_DIR, "conformal_paired_comparison.csv")
    df_paired.to_csv(paired_csv_path, index=False)
    print(f"Saved paired comparison table to {paired_csv_path}")

    # Print summary win/tie/loss counts
    print("\n--- Paired Comparison Outcomes (32 Configurations) ---")
    for name, col_out, col_sig, col_diff in [
        ("Rolling LF vs Matched Static Quantile", "Outcome_Roll_vs_Matched", "Sig_Roll_vs_Matched", "Delta_Recall_Roll_vs_Matched"),
        ("Rolling LF vs Nominal Static Quantile", "Outcome_Roll_vs_Nominal", "Sig_Roll_vs_Nominal", "Delta_Recall_Roll_vs_Nominal"),
        ("ACI LF vs Matched Static Quantile", "Outcome_ACI_vs_Matched", "Sig_ACI_vs_Matched", "Delta_Recall_ACI_vs_Matched"),
        ("ACI LF vs Nominal Static Quantile", "Outcome_ACI_vs_Nominal", "Sig_ACI_vs_Nominal", "Delta_Recall_ACI_vs_Nominal"),
    ]:
        w = int((df_paired[col_out] == "Win").sum())
        t = int((df_paired[col_out] == "Tie").sum())
        l = int((df_paired[col_out] == "Loss").sum())
        sw = int((df_paired[col_sig] == "Significant Win").sum())
        sl = int((df_paired[col_sig] == "Significant Loss").sum())
        mean_d = float(df_paired[col_diff].mean())
        # Bootstrap across 32 pairs
        rng = np.random.default_rng(42)
        diff_arr = df_paired[col_diff].values
        boot_means = [np.mean(rng.choice(diff_arr, size=len(diff_arr), replace=True)) for _ in range(1000)]
        b_low, b_high = np.percentile(boot_means, 2.5), np.percentile(boot_means, 97.5)
        print(f"{name}:")
        print(f"  Wins = {w}, Ties = {t}, Losses = {l} (Significant Wins = {sw}, Significant Losses = {sl})")
        print(f"  Mean Delta Recall = {mean_d:+.4f}, 95% Bootstrap CI = [{b_low:+.4f}, {b_high:+.4f}]")

    # -------------------------------------------------------------------------
    # 5. Full Configuration Changes Table (Every Configuration Reported)
    # -------------------------------------------------------------------------
    change_records = []
    sub_05 = df_eval[df_eval["Target_Alpha"] == 0.05]

    for (block, design, dataset, model), grp in sub_05.groupby(["Block", "Design", "Dataset", "Model"]):
        st_row = grp[grp["Method"] == "Static Benign Quantile"].iloc[0]
        roll_lf_row = grp[grp["Method"] == "Rolling Split-Conformal (Label-Free)"].iloc[0]
        aci_lf_row = grp[grp["Method"] == "Adaptive Conformal (ACI, Label-Free)"].iloc[0]
        roll_orc_row = grp[grp["Method"] == "Rolling Split-Conformal (Oracle)"].iloc[0]
        aci_orc_row = grp[grp["Method"] == "Adaptive Conformal (ACI, Oracle)"].iloc[0]

        change_records.append({
            "Block": block,
            "Dataset": dataset,
            "Design": design,
            "Model": model,
            # Static Quantile Baseline
            "Static_FPR": st_row["Achieved_FPR"],
            "Static_Recall": st_row["Recall"],
            "Static_F1": st_row["F1"],
            # Rolling LF
            "Roll_LF_FPR": roll_lf_row["Achieved_FPR"],
            "Roll_LF_Recall": roll_lf_row["Recall"],
            "Roll_LF_F1": roll_lf_row["F1"],
            "Roll_LF_Delta_Recall": roll_lf_row["Recall"] - st_row["Recall"],
            "Roll_LF_Delta_F1": roll_lf_row["F1"] - st_row["F1"],
            "Roll_LF_Delta_FPR": roll_lf_row["Achieved_FPR"] - st_row["Achieved_FPR"],
            # ACI LF
            "ACI_LF_FPR": aci_lf_row["Achieved_FPR"],
            "ACI_LF_Recall": aci_lf_row["Recall"],
            "ACI_LF_F1": aci_lf_row["F1"],
            "ACI_LF_Delta_Recall": aci_lf_row["Recall"] - st_row["Recall"],
            "ACI_LF_Delta_F1": aci_lf_row["F1"] - st_row["F1"],
            "ACI_LF_Delta_FPR": aci_lf_row["Achieved_FPR"] - st_row["Achieved_FPR"],
            # Rolling Oracle (Reference)
            "Roll_Oracle_FPR": roll_orc_row["Achieved_FPR"],
            "Roll_Oracle_Recall": roll_orc_row["Recall"],
            "Roll_Oracle_F1": roll_orc_row["F1"],
            "Roll_Oracle_Delta_Recall": roll_orc_row["Recall"] - st_row["Recall"],
            "Roll_Oracle_Delta_F1": roll_orc_row["F1"] - st_row["F1"],
            # ACI Oracle (Reference)
            "ACI_Oracle_FPR": aci_orc_row["Achieved_FPR"],
            "ACI_Oracle_Recall": aci_orc_row["Recall"],
            "ACI_Oracle_F1": aci_orc_row["F1"],
            "ACI_Oracle_Delta_Recall": aci_orc_row["Recall"] - st_row["Recall"],
            "ACI_Oracle_Delta_F1": aci_orc_row["F1"] - st_row["F1"],
        })

    df_changes = pd.DataFrame(change_records)
    changes_csv_path = os.path.join(OUTPUT_METRICS_DIR, "conformal_configuration_changes.csv")
    df_changes.to_csv(changes_csv_path, index=False)
    print(f"Saved configuration changes table to {changes_csv_path}")

    # -------------------------------------------------------------------------
    # 6. Figures Generation
    # -------------------------------------------------------------------------
    print("\nGenerating figures...")

    # Figure 1: Recall vs Achieved FPR curves for Primary Cross-Day CSE-CIC-IDS2018 (3 days x 4 detectors)
    cse_days = ["Thursday-15-02-2018", "Friday-16-02-2018", "Wednesday-21-02-2018"]
    fig, axes = plt.subplots(3, 4, figsize=(18, 12), sharex=True, sharey=True)

    method_styles = {
        "Static Benign Quantile": ("#1f77b4", "o-", "Static Quantile"),
        "Static Split-Conformal": ("#2ca02c", "s--", "Static Split-Conf"),
        "Rolling Split-Conformal (Label-Free)": ("#d62728", "^-", "Rolling Conf (Label-Free)"),
        "Adaptive Conformal (ACI, Label-Free)": ("#9467bd", "v-", "ACI (Label-Free)"),
        "Rolling Split-Conformal (Oracle)": ("#8c564b", "x:", "Rolling Conf (Oracle Ref)"),
        "Adaptive Conformal (ACI, Oracle)": ("#e377c2", "+:", "ACI (Oracle Ref)")
    }

    for row_idx, day in enumerate(cse_days):
        for col_idx, model in enumerate(MODELS_TO_EVAL):
            ax = axes[row_idx, col_idx]
            sub = df_eval[(df_eval["Block"] == day) & (df_eval["Design"] == "Cross-Day_Primary") & (df_eval["Model"] == model)]

            for m_name, (color, fmt, label) in method_styles.items():
                m_sub = sub[sub["Method"] == m_name].sort_values("Achieved_FPR")
                if len(m_sub) > 0:
                    ax.plot(
                        m_sub["Achieved_FPR"], m_sub["Recall"],
                        fmt, color=color, label=label, linewidth=1.5, markersize=5, alpha=0.85
                    )

            # Target FPR lines at 0.01 and 0.05
            ax.axvline(0.01, color="gray", linestyle=":", alpha=0.5)
            ax.axvline(0.05, color="red", linestyle=":", alpha=0.5)
            ax.set_xlim(-0.01, 0.35)
            ax.set_ylim(-0.02, 1.05)
            ax.grid(True, linestyle="--", alpha=0.4)

            short_model = model.replace("Baseline: ", "").replace(" (mSTAMP+Kneedle)", "").replace(" (Causal AB)", "")
            short_day = day.split("-")[0]
            if row_idx == 0:
                ax.set_title(short_model, fontsize=11, fontweight="bold")
            if col_idx == 0:
                ax.set_ylabel(f"{short_day}\nRecall", fontsize=10, fontweight="bold")
            if row_idx == 2:
                ax.set_xlabel("Achieved Test FPR", fontsize=10)

    # Place legend on bottom
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=6, bbox_to_anchor=(0.5, 0.01), fontsize=9)
    plt.suptitle("Recall vs Achieved Test FPR across Operating Points: CSE-CIC-IDS2018 Cross-Day Deployment", fontsize=14, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0.05, 1, 0.96])
    fig1_path = os.path.join(OUTPUT_FIGURES_DIR, "figure_recall_vs_fpr_cse_cross_day.png")
    fig.savefig(fig1_path, dpi=200)
    plt.close(fig)
    print(f"Saved Figure 1 to {fig1_path}")

    # Figure 2: Remaining 5 evaluation blocks (Sensitivity & UNSW)
    other_blocks = [
        ("Friday-16-02-2018", "Within-Day_Sensitivity"),
        ("Wednesday-21-02-2018", "Within-Day_Sensitivity"),
        ("UNSW_Window_Small_Regime-Shift_Block", "Window_Block"),
        ("UNSW_Window_Regime_Shift_Demonstration", "Window_Block"),
        ("UNSW_Flow_Contiguous_Block", "Flow_Block")
    ]
    fig2, axes2 = plt.subplots(5, 4, figsize=(18, 18), sharex=True, sharey=True)

    for row_idx, (bname, bdesign) in enumerate(other_blocks):
        for col_idx, model in enumerate(MODELS_TO_EVAL):
            ax = axes2[row_idx, col_idx]
            sub = df_eval[(df_eval["Block"] == bname) & (df_eval["Design"] == bdesign) & (df_eval["Model"] == model)]

            for m_name, (color, fmt, label) in method_styles.items():
                m_sub = sub[sub["Method"] == m_name].sort_values("Achieved_FPR")
                if len(m_sub) > 0:
                    ax.plot(
                        m_sub["Achieved_FPR"], m_sub["Recall"],
                        fmt, color=color, label=label, linewidth=1.5, markersize=5, alpha=0.85
                    )

            ax.axvline(0.01, color="gray", linestyle=":", alpha=0.5)
            ax.axvline(0.05, color="red", linestyle=":", alpha=0.5)
            ax.set_xlim(-0.01, 0.55)
            ax.set_ylim(-0.02, 1.05)
            ax.grid(True, linestyle="--", alpha=0.4)

            short_model = model.replace("Baseline: ", "").replace(" (mSTAMP+Kneedle)", "").replace(" (Causal AB)", "")
            b_label = bname.replace("UNSW_Window_", "").replace("UNSW_Flow_", "").replace("-16-02-2018", " Within").replace("-21-02-2018", " Within")
            if row_idx == 0:
                ax.set_title(short_model, fontsize=11, fontweight="bold")
            if col_idx == 0:
                ax.set_ylabel(f"{b_label[:14]}\nRecall", fontsize=9, fontweight="bold")
            if row_idx == 4:
                ax.set_xlabel("Achieved Test FPR", fontsize=10)

    handles, labels = axes2[0, 0].get_legend_handles_labels()
    fig2.legend(handles, labels, loc="lower center", ncol=6, bbox_to_anchor=(0.5, 0.01), fontsize=9)
    plt.suptitle("Recall vs Achieved Test FPR across Operating Points: Sensitivity & UNSW Blocks", fontsize=14, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0.04, 1, 0.96])
    fig2_path = os.path.join(OUTPUT_FIGURES_DIR, "figure_recall_vs_fpr_unsw_and_sensitivity.png")
    fig2.savefig(fig2_path, dpi=200)
    plt.close(fig2)
    print(f"Saved Figure 2 to {fig2_path}")

    # Figure 3: Paired Comparison Forest Plot of Delta Recall with MBB Error Bars
    fig3, (ax3a, ax3b) = plt.subplots(1, 2, figsize=(16, 11), sharey=True)

    y_pos = np.arange(len(df_paired))
    labels_y = [f"{r['Block'][:10]} | {r['Model'].replace('Baseline: ', '').replace('Config ', '')}" for _, r in df_paired.iterrows()]

    # Left: Rolling LF vs Matched Static
    diff_r = df_paired["Delta_Recall_Roll_vs_Matched"].values
    err_low_r = diff_r - df_paired["MBB_95_CI_Low_Roll_vs_Matched"].values
    err_high_r = df_paired["MBB_95_CI_High_Roll_vs_Matched"].values - diff_r
    colors_r = ["#2ca02c" if d > 1e-6 else ("#d62728" if d < -1e-6 else "#7f7f7f") for d in diff_r]

    ax3a.errorbar(
        diff_r, y_pos, xerr=[err_low_r, err_high_r],
        fmt='none', ecolor='#666666', elinewidth=1.5, capsize=2.5
    )
    ax3a.scatter(diff_r, y_pos, c=colors_r, s=35, zorder=3, edgecolors='black', linewidth=0.5)
    ax3a.axvline(0.0, color="black", linestyle="--", linewidth=1.2)
    ax3a.set_yticks(y_pos)
    ax3a.set_yticklabels(labels_y, fontsize=8)
    ax3a.set_xlabel(r"$\Delta \mathrm{Recall}$ (Rolling LF $-$ Matched Static)", fontsize=10, fontweight="bold")
    ax3a.set_title("Rolling Split-Conformal (Label-Free)\nvs Matched-FPR Static Quantile", fontsize=11, fontweight="bold")
    ax3a.grid(True, linestyle="--", alpha=0.5)
    ax3a.set_xlim(-1.05, 1.05)

    # Right: ACI LF vs Matched Static
    diff_a = df_paired["Delta_Recall_ACI_vs_Matched"].values
    err_low_a = diff_a - df_paired["MBB_95_CI_Low_ACI_vs_Matched"].values
    err_high_a = df_paired["MBB_95_CI_High_ACI_vs_Matched"].values - diff_a
    colors_a = ["#2ca02c" if d > 1e-6 else ("#d62728" if d < -1e-6 else "#7f7f7f") for d in diff_a]

    ax3b.errorbar(
        diff_a, y_pos, xerr=[err_low_a, err_high_a],
        fmt='none', ecolor='#666666', elinewidth=1.5, capsize=2.5
    )
    ax3b.scatter(diff_a, y_pos, c=colors_a, s=35, zorder=3, marker='s', edgecolors='black', linewidth=0.5)
    ax3b.axvline(0.0, color="black", linestyle="--", linewidth=1.2)
    ax3b.set_xlabel(r"$\Delta \mathrm{Recall}$ (ACI LF $-$ Matched Static)", fontsize=10, fontweight="bold")
    ax3b.set_title("Adaptive Conformal Inference (Label-Free)\nvs Matched-FPR Static Quantile", fontsize=11, fontweight="bold")
    ax3b.grid(True, linestyle="--", alpha=0.5)
    ax3b.set_xlim(-1.05, 1.05)

    plt.suptitle("Paired Recall Difference with 95% Moving-Block Bootstrap Intervals (32 Configurations)", fontsize=13, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0.02, 1, 0.96])
    fig3_path = os.path.join(OUTPUT_FIGURES_DIR, "figure_recall_vs_fpr_paired_comparison.png")
    fig3.savefig(fig3_path, dpi=200)
    plt.close(fig3)
    print(f"Saved Figure 3 to {fig3_path}")

    # Save run metadata
    save_run_metadata("step3")
    print("Step 3 evaluation finished successfully.")

if __name__ == "__main__":
    run_step3_evaluation()

