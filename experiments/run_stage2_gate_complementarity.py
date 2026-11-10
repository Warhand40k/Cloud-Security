"""
Stage 1.5 Step 7: Empirical Complementarity Analysis for Stage 2 Gate
Computes:
1. Spearman rank correlation between Config A-prime and ARIMA residual scores
2. Jaccard overlap between alert sets at alpha = 0.05
3. Oracle-OR recall gain over the better single detector
4. Oracle-OR test FPR
5. Gate Decision: GO / NO-GO based on pre-registered criterion
"""

import os
import json
import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from typing import Dict, Any, List

def compute_complementarity_analysis():
    # Load calibrated alpha=0.05 thresholds
    with open("results/v3_1/metrics/threshold_free_and_fixed_alpha_results.json") as f:
        tf_results = json.load(f)

    threshold_lookup = {}
    for r in tf_results:
        key = (r["Block"], r["Design"], r["Model"])
        threshold_lookup[key] = r["Threshold_05"]

    blocks = [
        {
            "name": "Thursday-15-02-2018",
            "design": "Cross-Day Primary",
            "parquet": "results/v3_1/predictions/preds_Thursday-15-02-2018_Cross-Day_Primary.parquet",
        },
        {
            "name": "Friday-16-02-2018",
            "design": "Cross-Day Primary",
            "parquet": "results/v3_1/predictions/preds_Friday-16-02-2018_Cross-Day_Primary.parquet",
        },
        {
            "name": "Wednesday-21-02-2018",
            "design": "Cross-Day Primary",
            "parquet": "results/v3_1/predictions/preds_Wednesday-21-02-2018_Cross-Day_Primary.parquet",
        },
        {
            "name": "UNSW Window Small Regime-Shift Block",
            "design": "Window Block",
            "parquet": "results/v3_1/predictions/preds_UNSW_Window_Small_Regime-Shift_Block.parquet",
        },
        {
            "name": "UNSW Window Regime Shift Demonstration",
            "design": "Window Block",
            "parquet": "results/v3_1/predictions/preds_UNSW_Window_Regime_Shift_Demonstration.parquet",
        },
    ]

    results = []

    for b in blocks:
        block_name = b["name"]
        design = b["design"]
        p_path = b["parquet"]

        df = pd.read_parquet(p_path)
        y_true = df["y_true"].values.astype(int)

        score_aprime = df["Config A-prime (Causal AB)_score"].values.astype(float)
        score_arima = df["Baseline: ARIMA Residual_score"].values.astype(float)

        # 1. Spearman Rank Correlation
        # Handle cases with zero variance or NaNs safely
        valid_mask = np.isfinite(score_aprime) & np.isfinite(score_arima)
        if np.std(score_aprime[valid_mask]) > 1e-12 and np.std(score_arima[valid_mask]) > 1e-12:
            rho, pval = spearmanr(score_aprime[valid_mask], score_arima[valid_mask])
        else:
            rho, pval = 0.0, 1.0

        # Retrieve thresholds
        thresh_aprime = threshold_lookup.get((block_name, design, "Config A-prime (Causal AB)"))
        thresh_arima = threshold_lookup.get((block_name, design, "Baseline: ARIMA Residual"))

        # Alerts at alpha = 0.05
        alerts_aprime = (score_aprime >= thresh_aprime).astype(int)
        alerts_arima = (score_arima >= thresh_arima).astype(int)

        # 2. Jaccard Overlap of Alert Sets
        union_alerts = np.sum((alerts_aprime == 1) | (alerts_arima == 1))
        intersect_alerts = np.sum((alerts_aprime == 1) & (alerts_arima == 1))
        jaccard = float(intersect_alerts / union_alerts) if union_alerts > 0 else 0.0

        # Individual detector metrics
        pos_mask = (y_true == 1)
        neg_mask = (y_true == 0)
        n_pos = np.sum(pos_mask)
        n_neg = np.sum(neg_mask)

        recall_aprime = float(np.sum(alerts_aprime[pos_mask])) / n_pos if n_pos > 0 else 0.0
        fpr_aprime = float(np.sum(alerts_aprime[neg_mask])) / n_neg if n_neg > 0 else 0.0

        recall_arima = float(np.sum(alerts_arima[pos_mask])) / n_pos if n_pos > 0 else 0.0
        fpr_arima = float(np.sum(alerts_arima[neg_mask])) / n_neg if n_neg > 0 else 0.0

        better_single_recall = max(recall_aprime, recall_arima)

        # 3. Oracle-OR Combiner
        alerts_oracle = ((alerts_aprime == 1) | (alerts_arima == 1)).astype(int)
        recall_oracle = float(np.sum(alerts_oracle[pos_mask])) / n_pos if n_pos > 0 else 0.0
        fpr_oracle = float(np.sum(alerts_oracle[neg_mask])) / n_neg if n_neg > 0 else 0.0

        delta_recall = recall_oracle - better_single_recall

        # Criterion: Delta_Recall >= 0.10 AND FPR_Oracle <= 0.05
        block_passed = (delta_recall >= 0.10) and (fpr_oracle <= 0.05)

        results.append({
            "Block": block_name,
            "Design": design,
            "N_Test_Windows": len(y_true),
            "N_Attack_Windows": int(n_pos),
            "Prevalence": float(n_pos / len(y_true)) if len(y_true) > 0 else 0.0,
            "Spearman_Rho": float(rho),
            "Spearman_PVal": float(pval),
            "Threshold_APrime_05": float(thresh_aprime) if thresh_aprime is not None else None,
            "Threshold_ARIMA_05": float(thresh_arima) if thresh_arima is not None else None,
            "Recall_APrime": recall_aprime,
            "FPR_APrime": fpr_aprime,
            "Recall_ARIMA": recall_arima,
            "FPR_ARIMA": fpr_arima,
            "Better_Single_Recall": better_single_recall,
            "Oracle_OR_Recall": recall_oracle,
            "Oracle_OR_FPR": fpr_oracle,
            "Delta_Recall": delta_recall,
            "Jaccard_Alert_Overlap": jaccard,
            "Meets_Criterion": bool(block_passed),
        })

    # Summary decision
    total_blocks = len(results)
    blocks_passed = sum(1 for r in results if r["Meets_Criterion"])
    pass_fraction = blocks_passed / total_blocks
    decision = "GO" if pass_fraction >= 0.50 else "NO-GO"

    summary = {
        "pre_registered_criterion": "Oracle-OR Delta_Recall >= +0.10 AND FPR <= 0.05 on >= 50% of blocks",
        "total_blocks": total_blocks,
        "blocks_passed": blocks_passed,
        "pass_fraction": pass_fraction,
        "decision": decision,
        "blocks": results,
    }

    # Save to metrics
    os.makedirs("results/v3_1/metrics", exist_ok=True)
    with open("results/v3_1/metrics/stage2_gate_complementarity.json", "w") as f:
        json.dump(summary, f, indent=2)

    df_out = pd.DataFrame(results)
    df_out.to_csv("results/v3_1/metrics/stage2_gate_complementarity.csv", index=False)

    print(f"Stage 2 Gate Complementarity Analysis Complete.")
    print(f"Blocks Meeting Criterion: {blocks_passed}/{total_blocks} ({pass_fraction*100:.1f}%)")
    print(f"Decision: {decision}")
    print("\nSummary Table:")
    print(df_out[["Block", "Spearman_Rho", "Jaccard_Alert_Overlap", "Recall_APrime", "Recall_ARIMA", "Oracle_OR_Recall", "Delta_Recall", "Oracle_OR_FPR", "Meets_Criterion"]].to_string())

if __name__ == "__main__":
    compute_complementarity_analysis()
