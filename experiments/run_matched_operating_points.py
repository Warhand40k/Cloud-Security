"""
Matched-Operating-Point Evaluation (Phase 4):
Compares anomaly detection models at fixed operating points:
1. Fixed Recall = 0.50 and Recall = 0.80
2. Fixed FPR = 0.01 (1%) and FPR = 0.05 (5%)

Evaluates:
- Config A (Self-Join)
- Config A-prime (Causal AB Scorer)
- Config B1 (Adaptive MAD)
- Config B2 (Adaptive EVT)
- Config C (Persistence Filter)
- ML Baseline: Isolation Forest
- ML Baseline: ARIMA Residual
- Baselines: Random Uniform, Random Stratified

Reports:
- Precision, Recall, F1, FPR
- Alert Volume: Total alerts, Alerts per 1,000 windows, Alerts per hour at MATCHED recall!
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.persistence_filter import PersistenceFilter

OUTPUT_METRICS_DIR = "results/v2/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v2/predictions"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)

def find_threshold_at_recall(scores: np.ndarray, y_true: np.ndarray, target_recall: float) -> float:
    """Find threshold that achieves empirical recall closest to target_recall."""
    pos_scores = scores[y_true == 1]
    if len(pos_scores) == 0:
        return float(np.median(scores))
    # Threshold at (1 - target_recall) quantile of positive scores
    thresh = float(np.quantile(pos_scores, max(0.0, min(1.0, 1.0 - target_recall))))
    return thresh

def find_threshold_at_fpr(scores: np.ndarray, y_true: np.ndarray, target_fpr: float) -> float:
    """Find threshold that achieves empirical FPR closest to target_fpr."""
    neg_scores = scores[y_true == 0]
    if len(neg_scores) == 0:
        return float(np.median(scores))
    # Threshold at (1 - target_fpr) quantile of negative scores
    thresh = float(np.quantile(neg_scores, max(0.0, min(1.0, 1.0 - target_fpr))))
    return thresh

def compute_metrics_at_pred(y_true: np.ndarray, y_pred: np.ndarray, step_sec: float = 60.0) -> Dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    total_alerts = int(y_pred.sum())
    total_steps = len(y_true)
    total_hours = (total_steps * step_sec) / 3600.0

    alerts_per_1000 = float(total_alerts * 1000.0 / total_steps) if total_steps > 0 else 0.0
    alerts_per_hour = float(total_alerts / total_hours) if total_hours > 0 else 0.0

    return {
        "Precision": float(prec),
        "Recall": float(rec),
        "F1": float(f1),
        "FPR": float(fpr),
        "Total_Alerts": total_alerts,
        "Alerts_Per_1000_Windows": alerts_per_1000,
        "Alerts_Per_Hour": alerts_per_hour
    }

def run_matched_evaluations():
    print("=" * 80)
    print("RUNNING MATCHED-OPERATING-POINT EVALUATION (PHASE 4)")
    print("=" * 80)

    # We evaluate on saved test predictions across CSE-CIC days and UNSW blocks
    pred_files = [
        ("Thursday 15 (GoldenEye/Slowloris)", "results/v2/predictions/preds_Thursday_15_GoldenEye_Slowloris.parquet", 60.0),
        ("Friday 16 (Hulk/SlowHTTPTest)", "results/v2/predictions/preds_Friday_16_Hulk_SlowHTTPTest.parquet", 60.0),
        ("Wednesday 21 (HOIC/LOIC-UDP)", "results/v2/predictions/preds_Wednesday_21_HOIC_LOIC-UDP.parquet", 60.0),
        ("UNSW Window Realistic Proportion", "results/v2/predictions/preds_UNSW_Window_Realistic_Proportion.parquet", 10.0)
    ]

    models_to_evaluate = [
        ("Config A (mSTAMP+Kneedle)", "Config A (mSTAMP+Kneedle)_score"),
        ("Config A-prime (Causal AB)", "Config A-prime (Causal AB)_score"),
        ("Baseline: Isolation Forest", "Baseline: Isolation Forest_score"),
        ("Baseline: ARIMA Residual", "Baseline: ARIMA Residual_score"),
        ("Baseline: Random Uniform", "Baseline: Random Uniform_score")
    ]

    operating_targets = [
        ("Fixed Recall = 0.50", "recall", 0.50),
        ("Fixed Recall = 0.80", "recall", 0.80),
        ("Fixed FPR = 0.01 (1%)", "fpr", 0.01),
        ("Fixed FPR = 0.05 (5%)", "fpr", 0.05),
    ]

    matched_records = []

    for block_name, ppath, step_sec in pred_files:
        if not os.path.exists(ppath):
            print(f"Prediction file {ppath} not found. Skipping...")
            continue

        print(f"\nProcessing Matched Operating Points for Block: {block_name}...")
        df = pd.read_parquet(ppath)
        y_true = df["y_true"].values.astype(int)

        for model_label, score_col in models_to_evaluate:
            if score_col not in df.columns:
                continue
            scores = df[score_col].values.astype(float)
            if not np.all(np.isfinite(scores)):
                scores = np.nan_to_num(scores, nan=0.0)

            for target_name, target_type, target_val in operating_targets:
                if target_type == "recall":
                    th = find_threshold_at_recall(scores, y_true, target_val)
                    pred = (scores >= th).astype(int)
                else: # target_type == "fpr"
                    th = find_threshold_at_fpr(scores, y_true, target_val)
                    pred = (scores >= th).astype(int)

                m = compute_metrics_at_pred(y_true, pred, step_sec=step_sec)
                rec = {
                    "Block": block_name,
                    "Model": model_label,
                    "Operating_Target": target_name,
                    "Target_Type": target_type,
                    "Target_Value": target_val,
                    "Threshold": float(th),
                    **m
                }
                matched_records.append(rec)

                # Also evaluate Persistence Filter k=2 on top of matched prediction for Config A-prime
                if model_label == "Config A-prime (Causal AB)":
                    pf = PersistenceFilter(k=2)
                    pred_pf = pf.filter(pred)
                    m_pf = compute_metrics_at_pred(y_true, pred_pf, step_sec=step_sec)
                    matched_records.append({
                        "Block": block_name,
                        "Model": "Config C (A-prime, k=2)",
                        "Operating_Target": target_name,
                        "Target_Type": target_type,
                        "Target_Value": target_val,
                        "Threshold": float(th),
                        **m_pf
                    })

    df_matched = pd.DataFrame(matched_records)
    csv_out = os.path.join(OUTPUT_METRICS_DIR, "matched_operating_points.csv")
    json_out = os.path.join(OUTPUT_METRICS_DIR, "matched_operating_points.json")
    df_matched.to_csv(csv_out, index=False)
    df_matched.to_json(json_out, orient="records", indent=2)
    print(f"\nSaved matched-operating-point results to {csv_out} and {json_out}")

    # Print summary at Fixed Recall = 0.80
    rec80 = df_matched[df_matched["Operating_Target"] == "Fixed Recall = 0.80"]
    if len(rec80) > 0:
        print("\n--- COMPARISON AT MATCHED RECALL = 0.80 ---")
        summary_rec80 = rec80.groupby("Model")[["Precision", "Recall", "F1", "FPR", "Alerts_Per_1000_Windows", "Alerts_Per_Hour"]].mean()
        print(summary_rec80.to_string())

    # Print summary at Fixed FPR = 0.01 (1%)
    fpr01 = df_matched[df_matched["Operating_Target"] == "Fixed FPR = 0.01 (1%)"]
    if len(fpr01) > 0:
        print("\n--- COMPARISON AT MATCHED FPR = 0.01 (1%) ---")
        summary_fpr01 = fpr01.groupby("Model")[["Precision", "Recall", "F1", "FPR", "Alerts_Per_1000_Windows", "Alerts_Per_Hour"]].mean()
        print(summary_fpr01.to_string())

    return df_matched

if __name__ == "__main__":
    run_matched_evaluations()

