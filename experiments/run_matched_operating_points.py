"""
Matched-Operating-Point Evaluation & Evaluation-Only Curves (Stage 1 Step 3):
Rebuilds the matched-operating-point comparison honestly with two clearly labeled variants:

Variant (a) VALIDATION-SELECTED:
- Choose each model's threshold on validation to hit target:
  - Fixed Recall = 0.80 and 0.50
  - Fixed FPR = 0.05 and 0.01
- Report what was ACTUALLY achieved on test data.
- Label row "matched" if test recall/FPR is within +/-0.05 of target;
  otherwise label "target not reached".
- If target FPR is unreachable due to score ties or saturation, explicitly record
  "target unreachable on validation (score ties)".

Variant (b) EVALUATION-ONLY CURVES:
- For each model, compute alerts per 1,000 windows (or flows) vs recall and vs FPR
  on test by sweeping score thresholds (labels used strictly for evaluation).
- Plot curves per dataset.

Operational rules:
- Alerts per hour is omitted (set to NaN / N/A) for flow-level blocks.
- Alerts per 1,000 events is reported for both windows and flows.
- Trivial baselines (All-Attack, All-Normal, Random Uniform, Random Stratified)
  are evaluated at every operating point.
- Also evaluates Persistence Filter k=2 on top of parent operating thresholds (Config C).
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Tuple, Optional
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.persistence_filter import PersistenceFilter
from src.evaluation import compute_clopper_pearson_ci, find_campaign_intervals

OUTPUT_METRICS_DIR = "results/v3/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v3/predictions"
OUTPUT_FIGURES_DIR = "results/v3/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

BLOCKS_METADATA = [
    {
        "block_name": "Thursday-15-02-2018",
        "clean_name": "Thursday-15-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "is_flow": False,
        "step_sec": 60.0
    },
    {
        "block_name": "Friday-16-02-2018",
        "clean_name": "Friday-16-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "is_flow": False,
        "step_sec": 60.0
    },
    {
        "block_name": "Wednesday-21-02-2018",
        "clean_name": "Wednesday-21-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "is_flow": False,
        "step_sec": 60.0
    },
    {
        "block_name": "UNSW Flow Contiguous Block",
        "clean_name": "UNSW_Flow_Contiguous_Block",
        "dataset": "UNSW-NB15",
        "is_flow": True,
        "step_sec": 1.0
    },
    {
        "block_name": "UNSW Window Small Regime-Shift Block",
        "clean_name": "UNSW_Window_Small_Regime-Shift_Block",
        "dataset": "UNSW-NB15",
        "is_flow": False,
        "step_sec": 10.0
    },
    {
        "block_name": "UNSW Window Regime Shift Demonstration",
        "clean_name": "UNSW_Window_Regime_Shift_Demonstration",
        "dataset": "UNSW-NB15",
        "is_flow": False,
        "step_sec": 10.0
    }
]

MODELS_TO_EVALUATE = [
    ("Baseline: All-Attack", "Baseline: All-Attack_score", False),
    ("Baseline: All-Normal", "Baseline: All-Normal_score", False),
    ("Baseline: Random Uniform", "Baseline: Random Uniform_score", False),
    ("Baseline: Random Stratified", "Baseline: Random Stratified_score", False),
    ("Baseline: Isolation Forest", "Baseline: Isolation Forest_score", False),
    ("Baseline: ARIMA Residual", "Baseline: ARIMA Residual_score", False),
    ("Config A (mSTAMP+Kneedle)", "Config A (mSTAMP+Kneedle)_score", False),
    ("Config A-prime (Causal AB)", "Config A-prime (Causal AB)_score", True),
    ("Config B1 (Adaptive MAD)", "Config B1 (Adaptive MAD)_score", True),
    ("Config B2 (Adaptive EVT)", "Config B2 (Adaptive EVT)_score", False)
]

OPERATING_TARGETS = [
    ("Fixed Recall = 0.80", "recall", 0.80),
    ("Fixed Recall = 0.50", "recall", 0.50),
    ("Fixed FPR = 0.05 (5%)", "fpr", 0.05),
    ("Fixed FPR = 0.01 (1%)", "fpr", 0.01)
]

def find_threshold_on_validation(
    s_val: np.ndarray,
    y_val: np.ndarray,
    target_type: str,
    target_val: float
) -> Tuple[Optional[float], str, float]:
    """
    Selects threshold strictly on validation data to hit target recall or FPR.
    Returns: (threshold, val_reachability_status, achieved_val_metric)
    """
    if target_type == "recall":
        pos_scores = s_val[y_val == 1]
        if len(pos_scores) == 0:
            return None, "unreachable (no validation attacks)", 0.0
        
        # Check if all positive scores are identical
        if np.all(pos_scores == pos_scores[0]):
            th = float(pos_scores[0])
            pred_val = (s_val >= th).astype(int)
            achieved_rec = float(recall_score(y_val, pred_val, zero_division=0))
            return th, "score ties on positive validation", achieved_rec

        # Empirical quantile threshold
        th = float(np.quantile(pos_scores, max(0.0, min(1.0, 1.0 - target_val))))
        pred_val = (s_val >= th).astype(int)
        achieved_rec = float(recall_score(y_val, pred_val, zero_division=0))
        return th, "calibrated", achieved_rec

    elif target_type == "fpr":
        neg_scores = s_val[y_val == 0]
        if len(neg_scores) == 0:
            return None, "unreachable (no validation benign samples)", 0.0

        if np.all(neg_scores == neg_scores[0]):
            # Saturated/constant scores: FPR is either 0 or 1
            th = float(neg_scores[0])
            pred_val = (s_val >= th).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_val, pred_val, labels=[0, 1]).ravel()
            achieved_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            return th, "target unreachable on validation (score ties)", achieved_fpr

        th = float(np.quantile(neg_scores, max(0.0, min(1.0, 1.0 - target_val))))
        pred_val = (s_val >= th).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_val, pred_val, labels=[0, 1]).ravel()
        achieved_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        return th, "calibrated", achieved_fpr

    else:
        raise ValueError(f"Unknown target_type: {target_type}")

def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    step_sec: float,
    is_flow: bool,
    all_attack_f1: float
) -> Dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    total_alerts = int(y_pred.sum())
    total_steps = len(y_true)
    total_hours = (total_steps * step_sec) / 3600.0

    alerts_per_1000 = float(total_alerts * 1000.0 / total_steps) if total_steps > 0 else 0.0
    alerts_per_hour = float(total_alerts / total_hours) if (total_hours > 0 and not is_flow) else None

    # Campaign metrics
    intervals = find_campaign_intervals(y_true, gap_tolerance=0)
    total_camp = len(intervals)
    camp_det = 0
    delays_sec = []
    for s, e in intervals:
        sub_pred = y_pred[s:e + 1]
        al_idx = np.where(sub_pred == 1)[0]
        if len(al_idx) > 0:
            camp_det += 1
            delays_sec.append(float(al_idx[0] * step_sec))

    camp_rec = float(camp_det / total_camp) if total_camp > 0 else 1.0
    cp_low, cp_high = compute_clopper_pearson_ci(camp_det, total_camp, 0.95)
    mttd_sec = float(np.mean(delays_sec)) if delays_sec else None

    return {
        "Precision": prec,
        "Recall": rec,
        "F1": f1,
        "FPR": fpr,
        "Total_Alerts": total_alerts,
        "Alerts_Per_1000_Events": alerts_per_1000,
        "Alerts_Per_Hour": alerts_per_hour,
        "Total_Campaigns": total_camp,
        "Campaigns_Detected": camp_det,
        "Campaign_Recall": camp_rec,
        "Campaign_Recall_CI_Low": cp_low,
        "Campaign_Recall_CI_High": cp_high,
        "Campaign_Recall_Ratio": f"{camp_det}/{total_camp}",
        "MTTD_Detected_Sec": mttd_sec,
        "Beats_All_Attack_F1": "yes" if f1 > all_attack_f1 else "no"
    }

def run_matched_evaluations():
    print("=" * 80)
    print("RUNNING HONEST MATCHED-OPERATING-POINT EVALUATION (PHASE 4 / STAGE 1 STEP 3)")
    print("=" * 80)

    matched_records = []

    for binfo in BLOCKSS_METADATA if "BLOCKSS_METADATA" in locals() else BLOCKS_METADATA:
        bname = binfo["block_name"]
        cname = binfo["clean_name"]
        dname = binfo["dataset"]
        is_flow = binfo["is_flow"]
        step_sec = binfo["step_sec"]

        val_path = os.path.join(OUTPUT_PREDICTIONS_DIR, f"preds_val_{cname}.parquet")
        test_path = os.path.join(OUTPUT_PREDICTIONS_DIR, f"preds_{cname}.parquet")

        if not os.path.exists(val_path) or not os.path.exists(test_path):
            print(f"Skipping {bname}: missing {val_path} or {test_path}")
            continue

        print(f"\nProcessing Block: {bname} (Dataset: {dname}, Flow: {is_flow})...")
        df_val = pd.read_parquet(val_path)
        df_test = pd.read_parquet(test_path)

        y_val = df_val["y_true"].values.astype(int)
        y_test = df_test["y_true"].values.astype(int)
        all_attack_f1 = float(f1_score(y_test, np.ones_like(y_test), zero_division=0))

        for model_label, score_col, supports_persistence in MODELS_TO_EVALUATE:
            if score_col not in df_val.columns or score_col not in df_test.columns:
                continue

            s_val = np.nan_to_num(df_val[score_col].values.astype(float))
            s_test = np.nan_to_num(df_test[score_col].values.astype(float))

            for target_name, target_type, target_val in OPERATING_TARGETS:
                th, val_status, ach_val = find_threshold_on_validation(
                    s_val, y_val, target_type, target_val
                )

                if th is None or np.isnan(th):
                    # Unreachable on validation
                    rec = {
                        "Block": bname,
                        "Dataset": dname,
                        "Is_Flow": is_flow,
                        "Model": model_label,
                        "Operating_Target": target_name,
                        "Target_Type": target_type,
                        "Target_Value": target_val,
                        "Threshold": np.nan,
                        "Validation_Status": val_status,
                        "Achieved_Val_Metric": ach_val,
                        "Status": "target unreachable on validation",
                        "Precision": 0.0,
                        "Recall": 0.0,
                        "F1": 0.0,
                        "FPR": 0.0,
                        "Total_Alerts": 0,
                        "Alerts_Per_1000_Events": 0.0,
                        "Alerts_Per_Hour": None if is_flow else 0.0,
                        "Total_Campaigns": 0,
                        "Campaigns_Detected": 0,
                        "Campaign_Recall": 0.0,
                        "Campaign_Recall_CI_Low": 0.0,
                        "Campaign_Recall_CI_High": 0.0,
                        "Campaign_Recall_Ratio": "0/0",
                        "MTTD_Detected_Sec": None,
                        "Beats_All_Attack_F1": "no"
                    }
                    matched_records.append(rec)
                    continue

                # Apply threshold to test data
                pred_test = (s_test >= th).astype(int)
                m = compute_metrics(y_test, pred_test, step_sec, is_flow, all_attack_f1)

                # Determine match status based on test performance within +/- 0.05
                if val_status.startswith("target unreachable"):
                    match_status = val_status
                else:
                    if target_type == "recall":
                        test_metric = m["Recall"]
                    else:
                        test_metric = m["FPR"]

                    if abs(test_metric - target_val) <= 0.05:
                        match_status = "matched"
                    else:
                        match_status = "target not reached"

                rec = {
                    "Block": bname,
                    "Dataset": dname,
                    "Is_Flow": is_flow,
                    "Model": model_label,
                    "Operating_Target": target_name,
                    "Target_Type": target_type,
                    "Target_Value": target_val,
                    "Threshold": float(th),
                    "Validation_Status": val_status,
                    "Achieved_Val_Metric": ach_val,
                    "Status": match_status,
                    **m
                }
                matched_records.append(rec)

                # If model supports persistence, also evaluate Config C (Parent, k=2)
                if supports_persistence:
                    parent_short = "A-prime" if "A-prime" in model_label else "B1"
                    pf = PersistenceFilter(k=2)
                    pred_pf = pf.filter(pred_test)
                    m_pf = compute_metrics(y_test, pred_pf, step_sec, is_flow, all_attack_f1)

                    if target_type == "recall":
                        pf_metric = m_pf["Recall"]
                    else:
                        pf_metric = m_pf["FPR"]

                    pf_match = "matched" if abs(pf_metric - target_val) <= 0.05 else "target not reached"
                    matched_records.append({
                        "Block": bname,
                        "Dataset": dname,
                        "Is_Flow": is_flow,
                        "Model": f"Config C ({parent_short}, k=2)",
                        "Operating_Target": target_name,
                        "Target_Type": target_type,
                        "Target_Value": target_val,
                        "Threshold": float(th),
                        "Validation_Status": f"applied k=2 on {val_status}",
                        "Achieved_Val_Metric": ach_val,
                        "Status": pf_match,
                        **m_pf
                    })

    df_matched = pd.DataFrame(matched_records)
    csv_out = os.path.join(OUTPUT_METRICS_DIR, "matched_operating_points.csv")
    json_out = os.path.join(OUTPUT_METRICS_DIR, "matched_operating_points.json")
    df_matched.to_csv(csv_out, index=False)
    df_matched.to_json(json_out, orient="records", indent=2)
    print(f"\nSaved matched-operating-point results to {csv_out} and {json_out}")

    # Generate Evaluation-Only Curves
    generate_evaluation_only_curves()

def generate_evaluation_only_curves():
    """
    Variant (b) EVALUATION-ONLY CURVES:
    Sweeps test threshold and plots Alerts per 1,000 events vs. Recall and vs. FPR.
    """
    print("\nGenerating evaluation-only operating curves...")

    curve_configs = [
        ("CSE-CIC-IDS2018 (Thursday 15)", "Thursday-15-02-2018", False, "matched_curves_cse_thursday.png"),
        ("CSE-CIC-IDS2018 (Friday 16)", "Friday-16-02-2018", False, "matched_curves_cse_friday.png"),
        ("UNSW-NB15 Flow Contiguous", "UNSW_Flow_Contiguous_Block", True, "matched_curves_unsw_flow.png"),
        ("UNSW-NB15 Regime Shift Demonstration", "UNSW_Window_Regime_Shift_Demonstration", False, "matched_curves_unsw_regime_shift.png")
    ]

    models_to_curve = [
        ("Config A (mSTAMP+Kneedle)", "Config A (mSTAMP+Kneedle)_score", "blue", "-"),
        ("Config A-prime (Causal AB)", "Config A-prime (Causal AB)_score", "crimson", "-"),
        ("Baseline: Isolation Forest", "Baseline: Isolation Forest_score", "green", "--"),
        ("Baseline: ARIMA Residual", "Baseline: ARIMA Residual_score", "purple", "-."),
        ("Baseline: Random Uniform", "Baseline: Random Uniform_score", "gray", ":")
    ]

    for title, cname, is_flow, fig_name in curve_configs:
        test_path = os.path.join(OUTPUT_PREDICTIONS_DIR, f"preds_{cname}.parquet")
        if not os.path.exists(test_path):
            continue

        df_test = pd.read_parquet(test_path)
        y_test = df_test["y_true"].values.astype(int)
        total_steps = len(y_test)
        if total_steps == 0 or (y_test == 1).sum() == 0:
            continue

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        quantiles = np.linspace(0.001, 0.999, 150)

        for model_name, score_col, color, ls in models_to_curve:
            if score_col not in df_test.columns:
                continue

            scores = np.nan_to_num(df_test[score_col].values.astype(float))
            # Candidate thresholds from quantiles of score distribution
            thresholds = np.unique(np.quantile(scores, quantiles))

            recalls = []
            fprs = []
            alerts_per_1000 = []

            for th in thresholds:
                pred = (scores >= th).astype(int)
                tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
                rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
                fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                al_1000 = float(pred.sum() * 1000.0 / total_steps)

                recalls.append(rec)
                fprs.append(fpr)
                alerts_per_1000.append(al_1000)

            event_unit = "Flows" if is_flow else "Windows"
            # Sort by recall for clean line plotting
            sorted_by_rec = sorted(zip(recalls, alerts_per_1000), key=lambda x: x[0])
            sorted_rec, sorted_al_rec = zip(*sorted_by_rec)
            ax1.plot(sorted_rec, sorted_al_rec, label=model_name, color=color, linestyle=ls, linewidth=1.8)

            # Sort by FPR for clean line plotting
            sorted_by_fpr = sorted(zip(fprs, alerts_per_1000), key=lambda x: x[0])
            sorted_fpr, sorted_al_fpr = zip(*sorted_by_fpr)
            ax2.plot(sorted_fpr, sorted_al_fpr, label=model_name, color=color, linestyle=ls, linewidth=1.8)

        event_unit = "Flows" if is_flow else "Windows"
        ax1.set_xlabel("Recall on Test Slice", fontsize=11)
        ax1.set_ylabel(f"Alerts per 1,000 {event_unit}", fontsize=11)
        ax1.set_title(f"{title}\nAlert Volume vs. Achieved Recall", fontsize=12)
        ax1.grid(True, linestyle="--", alpha=0.5)
        ax1.legend(loc="upper left", fontsize=8)

        ax2.set_xlabel("False Positive Rate (FPR) on Test Slice", fontsize=11)
        ax2.set_ylabel(f"Alerts per 1,000 {event_unit}", fontsize=11)
        ax2.set_title(f"{title}\nAlert Volume vs. Achieved FPR", fontsize=12)
        ax2.grid(True, linestyle="--", alpha=0.5)
        ax2.legend(loc="upper left", fontsize=8)

        plt.tight_layout()
        fig_path = os.path.join(OUTPUT_FIGURES_DIR, fig_name)
        plt.savefig(fig_path, dpi=200)
        plt.close()
        print(f"Saved evaluation curve plot to {fig_path}")

if __name__ == "__main__":
    run_matched_evaluations()
