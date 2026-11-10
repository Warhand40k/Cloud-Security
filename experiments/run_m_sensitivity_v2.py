"""
Subsequence Length m Sensitivity Suite (Phase 4):
Evaluates m in [5, 10, 20, 30, 50, 75, 100].

Ground Rule:
- Choose m* on the VALIDATION split ONLY (not by best test F1).
- Report test results for ALL m, but explicitly mark the validation-selected one.
- Saves full metrics, bootstrap CIs, and figures.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor
from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.evaluation import (
    compute_classification_metrics,
    compute_sre_operational_metrics,
    compute_bootstrap_confidence_intervals,
    ResourceProfiler
)

OUTPUT_METRICS_DIR = "results/v3/metrics"
OUTPUT_FIGURES_DIR = "results/v3/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

def run_m_sensitivity():
    print("=" * 80)
    print("RUNNING SUBSEQUENCE LENGTH m SENSITIVITY (PHASE 4)")
    print("=" * 80)

    # UNSW Flow 8,000 flows
    df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=15000)
    df_eval = df_raw.iloc[:8000].copy().reset_index(drop=True)

    train_df, val_df, test_df = split_chronological(df_eval, train_frac=0.60, val_frac=0.20, test_frac=0.20)
    prep = UNSWPreprocessor(scaler_type="standard")
    prep.fit(train_df)

    X_train, y_train = prep.transform(train_df)
    X_val, y_val = prep.transform(val_df)
    X_test, y_test = prep.transform(test_df)

    time_col = "Stime" if "Stime" in test_df.columns else "stime"
    t_test = test_df[time_col].values

    n_train = len(X_train)
    n_val = len(X_val)
    n_test = len(X_test)
    total_len = n_train + n_val + n_test

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)

    X_full = np.vstack([X_train, X_val, X_test])

    m_values = [5, 10, 20, 30, 50, 75, 100]
    records = []

    print(f"Data split: Train={n_train} | Val={n_val} | Test={n_test}")

    # First pass: evaluate across all m and collect validation F1
    val_f1_dict = {}

    for m_cand in m_values:
        print(f"\nEvaluating m = {m_cand}...")
        with ResourceProfiler() as prof:
            mps_full, _ = compute_multidimensional_mp(X_full, m=m_cand)
            knee_dim, _ = find_knee_dimension(mps_full[:, : n_train + n_val], online=True, metric="max")
            scores_full = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim, n_samples=total_len, m=m_cand)

        scores_val = scores_full[val_slice]
        scores_test = scores_full[test_slice]

        # Threshold calibration strictly on validation split
        val_percentiles = np.linspace(80, 99.8, 80)
        best_th = float(np.median(scores_val))
        best_f1_v = -1.0
        for p in val_percentiles:
            th = float(np.percentile(scores_val, p))
            f1_v = compute_classification_metrics(y_val, (scores_val >= th).astype(int))["f1"]
            if f1_v > best_f1_v:
                best_f1_v = f1_v
                best_th = th

        val_f1_dict[m_cand] = (best_f1_v, best_th, scores_test, prof.elapsed_seconds, prof.peak_mem_mb, knee_dim)
        print(f"  m={m_cand} -> Val F1={best_f1_v:.4f} (Knee Dim={knee_dim}, Runtime={prof.elapsed_seconds:.2f}s)")

    # Select best m on validation ONLY
    best_m_val = max(val_f1_dict.keys(), key=lambda m: val_f1_dict[m][0])
    print(f"\n>>> VALIDATION-SELECTED OPTIMAL m*: m = {best_m_val} (Val F1 = {val_f1_dict[best_m_val][0]:.4f}) <<<")

    # Evaluate test performance for all m
    for m_cand in m_values:
        best_f1_v, best_th, scores_test, elapsed_sec, peak_mem, knee_dim = val_f1_dict[m_cand]
        pred_test = (scores_test >= best_th).astype(int)

        cls_m = compute_classification_metrics(y_test, pred_test, scores_test)
        sre_m = compute_sre_operational_metrics(y_test, pred_test, timestamps=t_test, default_step_sec=1.0, is_flow_data=True)
        boot = compute_bootstrap_confidence_intervals(
            y_test, pred_test, scores_test, timestamps=t_test, n_bootstraps=500, block_size=m_cand, default_step_sec=1.0
        )

        is_val_opt = (m_cand == best_m_val)

        records.append({
            "m": m_cand,
            "Validation_Selected": is_val_opt,
            "Knee_Dimension": int(knee_dim),
            "Val_F1": best_f1_v,
            "Test_F1": cls_m["f1"],
            "Test_F1_CI_Low": boot["f1_ci"][0],
            "Test_F1_CI_High": boot["f1_ci"][1],
            "Test_Precision": cls_m["precision"],
            "Test_Recall": cls_m["recall"],
            "Test_FPR": cls_m["fpr"],
            "Test_PR_AUC": cls_m["pr_auc"],
            "Test_ROC_AUC": cls_m["roc_auc"],
            "Prevalence": cls_m["prevalence"],
            "PR_AUC_Lift": cls_m.get("pr_auc_lift"),
            "Beats_All_Attack_F1": "yes" if cls_m["f1"] > 0.209289 else "no",
            "Test_Campaign_Recall": sre_m["campaign_recall"],
            "Campaign_Recall_Count": sre_m.get("campaign_recall_ratio", f"{sre_m['campaigns_detected']}/{sre_m['total_campaigns']}"),
            "Campaign_Recall_CI_Low": sre_m.get("campaign_recall_ci_low"),
            "Campaign_Recall_CI_High": sre_m.get("campaign_recall_ci_high"),
            "Test_Total_Alerts": sre_m["total_alerts"],
            "Alerts_Per_1000_Flows": sre_m["alerts_per_1000_windows"],
            "Runtime_Sec": elapsed_sec,
            "Peak_RAM_MB": peak_mem
        })
        print(f"  m={m_cand:3d}{'*' if is_val_opt else ' '} | Test F1={cls_m['f1']:.4f} [95% CI: {boot['f1_ci'][0]:.4f}, {boot['f1_ci'][1]:.4f}] | Prec={cls_m['precision']:.4f} | Rec={cls_m['recall']:.4f} | FPR={cls_m['fpr']:.4f}")

    df_m = pd.DataFrame(records)
    csv_out = os.path.join(OUTPUT_METRICS_DIR, "sensitivity_m.csv")
    json_out = os.path.join(OUTPUT_METRICS_DIR, "sensitivity_m.json")
    df_m.to_csv(csv_out, index=False)
    df_m.to_json(json_out, orient="records", indent=2)
    # Also save with v2 name for backward compatibility
    df_m.to_csv(os.path.join(OUTPUT_METRICS_DIR, "sensitivity_m_v2.csv"), index=False)
    df_m.to_json(os.path.join(OUTPUT_METRICS_DIR, "sensitivity_m_v2.json"), orient="records", indent=2)
    print(f"\nSaved sensitivity to m results to {csv_out} and {json_out}")

    # Plot Sensitivity to m: Val F1 vs Test F1 with CI and optimal marker
    fig, ax1 = plt.subplots(figsize=(9, 5))
    ax2 = ax1.twinx()

    # Val F1
    ax1.plot(df_m["m"], df_m["Val_F1"], "o--", color="#1b9e77", lw=2, label="Validation F1 (Tuned On)")
    # Test F1
    ax1.plot(df_m["m"], df_m["Test_F1"], "s-", color="#2b5c8f", lw=2.5, label="Test F1 (Unbiased)")
    ax1.fill_between(df_m["m"], df_m["Test_F1_CI_Low"], df_m["Test_F1_CI_High"], color="#2b5c8f", alpha=0.15, label="Test F1 95% MBB CI")

    # Mark validation selected m*
    opt_row = df_m[df_m["Validation_Selected"]]
    ax1.scatter(opt_row["m"], opt_row["Test_F1"], color="red", s=120, zorder=5, label=f"Selected m*={best_m_val} (Val-Only)")

    ax1.set_xlabel("Subsequence Length m (Flows)", fontsize=11)
    ax1.set_ylabel("F1 Score", fontsize=11)
    ax1.set_ylim(0, max(0.5, df_m["Test_F1"].max() + 0.1))

    # Runtime on secondary axis
    ax2.plot(df_m["m"], df_m["Runtime_Sec"], "^:", color="#d95f02", lw=1.5, label="STUMPY Runtime (s)")
    ax2.set_ylabel("Runtime (seconds)", color="#d95f02", fontsize=11)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right", frameon=True)

    plt.title("Subsequence Length m Sensitivity: Validation Selection vs Test Evaluation (UNSW Flow)", fontsize=12, fontweight="bold")
    plt.tight_layout()
    fig_out = os.path.join(OUTPUT_FIGURES_DIR, "sensitivity_m.png")
    plt.savefig(fig_out, dpi=300)
    plt.savefig(os.path.join(OUTPUT_FIGURES_DIR, "sensitivity_m_v2.png"), dpi=300)
    plt.close()
    print(f"Saved figure to {fig_out}")

    return df_m

if __name__ == "__main__":
    run_m_sensitivity()

