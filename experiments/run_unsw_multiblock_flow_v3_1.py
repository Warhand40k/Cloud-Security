"""
Stage 1.5 Step 6: Multi-Block Flow-Level Evaluation Pipeline
Replaces the single 107-second flow block with 10 contiguous 8,000-flow blocks
drawn from Batch 1 (file 1, first 80,000 flows).

Protocol:
- 10 contiguous blocks of 8,000 flows each.
- In each block: strictly chronological train (60% = 4,800), val (20% = 1,600), test (20% = 1,600).
- Pure benign flows from train used as reference library (N >= 4,300 >> 100).
- Decision threshold calibrated on benign validation scores to enforce FAR <= 0.05 (and 0.01).
- Evaluates whether ANY detector beats Baseline: All-Attack on flow data across the 10 blocks.
"""

import os
import sys
import time
import json
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, confusion_matrix, precision_score, recall_score, roc_auc_score, average_precision_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.adaptive_threshold import MADThreshold, EVTThreshold, calibrate_benign_quantile_threshold
from src.persistence_filter import PersistenceFilter
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline,
    RandomUniformBaseline, RandomStratifiedBaseline
)
from src.evaluation import compute_sre_operational_metrics
from src.preprocessing import load_and_sort_raw_unsw, UNSWPreprocessor

OUTPUT_METRICS_DIR = "results/v3_1/metrics"
OUTPUT_FIGURES_DIR = "results/v3_1/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

def evaluate_single_flow_block(
    block_id: int,
    df_block: pd.DataFrame,
    seed: int = 42,
    subseq_len_m: int = 5
) -> List[Dict[str, Any]]:
    n_total = len(df_block)
    n_tr = int(0.60 * n_total)
    n_va = int(0.20 * n_total)
    n_te = n_total - n_tr - n_va

    tr_df = df_block.iloc[:n_tr].copy().reset_index(drop=True)
    va_df = df_block.iloc[n_tr:n_tr+n_va].copy().reset_index(drop=True)
    te_df = df_block.iloc[n_tr+n_va:].copy().reset_index(drop=True)

    # Preprocessing & standard scaling fit strictly on training slice
    prep = UNSWPreprocessor(scaler_type="standard")
    prep.fit(tr_df)
    X_tr, y_tr = prep.transform(tr_df)
    X_va, y_val = prep.transform(va_df)
    X_te, y_test = prep.transform(te_df)

    time_col = "Stime" if "Stime" in te_df.columns else "stime"
    timestamps_test = te_df[time_col].values

    prevalence = float(np.mean(y_test))
    all_attack_f1 = float(f1_score(y_test, np.ones_like(y_test), zero_division=0))

    val_slice = slice(n_tr, n_tr + n_va)
    test_slice = slice(n_tr + n_va, n_total)
    X_full = np.vstack([X_tr, X_va, X_te])

    # 1. Trivial Baselines
    all_atk = AllAttackBaseline().fit(X_tr, y_tr)
    all_norm = AllNormalBaseline().fit(X_tr, y_tr)
    rand_u = RandomUniformBaseline(seed=seed).fit(X_tr, y_tr)
    rand_s = RandomStratifiedBaseline(seed=seed).fit(X_tr, y_tr)

    # 2. ML Baselines
    if_model = IsolationForestBaseline(n_estimators=100, random_state=seed).fit(X_tr)
    s_val_if = if_model.score_samples(X_va)
    s_test_if = if_model.score_samples(X_te)
    th_if = calibrate_benign_quantile_threshold(s_val_if, y_val, alpha=0.05)
    pred_test_if = (s_test_if >= th_if).astype(int)

    ar_model = ARIMAResidualBaseline(order=(1, 0, 1)).fit(X_tr)
    s_val_ar = ar_model.score_samples(X_va)
    s_test_ar = ar_model.score_samples(X_te)
    th_ar = calibrate_benign_quantile_threshold(s_val_ar, y_val, alpha=0.05)
    pred_test_ar = (s_test_ar >= th_ar).astype(int)

    # 3. Config A: mSTAMP + Kneedle
    mps_full, _ = compute_multidimensional_mp(X_full, m=subseq_len_m)
    mps_tr_val = mps_full[:, : n_tr + n_va - subseq_len_m + 1]
    knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
    scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=n_total, m=subseq_len_m)
    s_val_a = scores_full_a[val_slice]
    s_test_a = scores_full_a[test_slice]
    th_a = calibrate_benign_quantile_threshold(s_val_a, y_val, alpha=0.05)
    pred_test_a = (s_test_a >= th_a).astype(int)

    # 4. Config A-prime: Causal AB (benign reference)
    X_tr_benign = X_tr if np.all(y_tr == 0) else X_tr[y_tr == 0]
    if len(X_tr_benign) < subseq_len_m:
        X_tr_benign = X_tr[:subseq_len_m * 2]
    aprime = CausalABScorer(m=subseq_len_m)
    aprime.fit(X_tr_benign)
    s_val_aprime = aprime.score(X_va)
    s_test_aprime = aprime.score(X_te)
    th_aprime = calibrate_benign_quantile_threshold(s_val_aprime, y_val, alpha=0.05)
    pred_test_aprime = (s_test_aprime >= th_aprime).astype(int)

    # 5. Config B1: Adaptive MAD
    scores_train_a = scores_full_a[:n_tr]
    train_normal_scores = scores_train_a[y_tr == 0] if (y_tr == 0).sum() > 0 else scores_train_a
    val_normal_scores = s_val_a[y_val == 0] if (y_val == 0).sum() > 0 else s_val_a
    hist_normal = np.concatenate([train_normal_scores, val_normal_scores])

    benign_mask_val = (y_val == 0)
    rolling_w = min(20, max(5, n_va // 2))
    best_c = 3.0
    best_mad = None
    for c_cand in [1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]:
        mad_cand = MADThreshold(c=c_cand, rolling_window=rolling_w, eps=1e-6)
        mad_cand.fit(hist_normal)
        p_val = mad_cand.predict(s_val_a)
        emp_far = float(np.mean(p_val[benign_mask_val] == 1)) if np.any(benign_mask_val) else 0.0
        if emp_far <= 0.05:
            best_c = c_cand
            best_mad = mad_cand
            break
    if best_mad is None:
        best_mad = MADThreshold(c=5.0, rolling_window=rolling_w, eps=1e-6).fit(hist_normal)
    pred_test_b1 = best_mad.predict(s_test_a)

    # 6. Config B2: Adaptive EVT
    evt = EVTThreshold(q=0.80, risk_p=0.05, min_excesses=30).fit(hist_normal)
    pred_test_b2 = evt.predict(s_test_a)

    models = [
        ("Baseline: All-Attack", all_atk.predict(X_te), all_atk.score_samples(X_te)),
        ("Baseline: All-Normal", all_norm.predict(X_te), all_norm.score_samples(X_te)),
        ("Baseline: Random Uniform", (rand_u.score_samples(X_te) >= 0.95).astype(int), rand_u.score_samples(X_te)),
        ("Baseline: Random Stratified", (rand_s.score_samples(X_te) < np.mean(y_tr)).astype(int), rand_s.score_samples(X_te)),
        ("Baseline: Isolation Forest", pred_test_if, s_test_if),
        ("Baseline: ARIMA Residual", pred_test_ar, s_test_ar),
        ("Config A (mSTAMP+Kneedle)", pred_test_a, s_test_a),
        ("Config A-prime (Causal AB)", pred_test_aprime, s_test_aprime),
        ("Config B1 (Adaptive MAD)", pred_test_b1, s_test_a),
        ("Config B2 (Adaptive EVT)", pred_test_b2, s_test_a),
        ("Config C (B1, k=2)", PersistenceFilter(k=2).filter(pred_test_b1), s_test_a),
        ("Config C (B2, k=2)", PersistenceFilter(k=2).filter(pred_test_b2), s_test_a),
        ("Config C (A-prime, k=2)", PersistenceFilter(k=2).filter(pred_test_aprime), s_test_aprime)
    ]

    block_records = []
    for model_name, pred_t, s_t in models:
        clean_st = np.nan_to_num(s_t)
        if len(np.unique(y_test)) > 1 and not np.all(clean_st == clean_st[0]):
            try:
                roc_auc = float(roc_auc_score(y_test, clean_st))
            except Exception:
                roc_auc = None
            try:
                pr_auc = float(average_precision_score(y_test, clean_st))
            except Exception:
                pr_auc = None
        else:
            roc_auc = 0.5 if np.all(clean_st == clean_st[0]) else None
            pr_auc = prevalence

        pr_lift = float((pr_auc - prevalence) / prevalence) if (pr_auc is not None and prevalence > 0) else 0.0

        tn, fp, fn, tp = confusion_matrix(y_test, pred_t, labels=[0, 1]).ravel()
        prec = float(precision_score(y_test, pred_t, zero_division=0))
        rec = float(recall_score(y_test, pred_t, zero_division=0))
        f1 = float(f1_score(y_test, pred_t, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        sre_m = compute_sre_operational_metrics(y_test, pred_t, timestamps=timestamps_test, default_step_sec=1.0)

        beats_all_atk = (f1 > all_attack_f1)

        block_records.append({
            "Block_ID": block_id,
            "Block_Range": f"[{block_id*n_total}:{(block_id+1)*n_total}]",
            "Model": model_name,
            "Prevalence": prevalence,
            "All_Attack_F1": all_attack_f1,
            "Test_F1": f1,
            "Test_Recall": rec,
            "Test_Precision": prec,
            "Test_FPR": fpr,
            "ROC_AUC": roc_auc,
            "PR_AUC": pr_auc,
            "PR_AUC_Lift": pr_lift,
            "Total_Alerts": int(pred_t.sum()),
            "Alerts_Per_1000_Flows": sre_m["alerts_per_1000_windows"],
            "Campaign_Recall": sre_m["campaign_recall"],
            "MTTD_Sec": sre_m["mttd_detected_campaigns_only_sec"],
            "Beats_All_Attack_F1": "yes" if beats_all_atk else "no"
        })

    return block_records

def run_unsw_multiblock_evaluation():
    start_time = time.time()
    n_blocks = 10
    block_size = 8000
    total_needed = n_blocks * block_size

    print("=" * 80)
    print(f"STAGE 1.5 STEP 6: UNSW-NB15 MULTI-BLOCK FLOW EVALUATION ({n_blocks} Contiguous Blocks of {block_size} Flows)")
    print(f"Total Flows: {total_needed} from Batch 1 (File 1)")
    print("=" * 80)

    df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=total_needed)
    print(f"Loaded {len(df_raw)} raw flows from Batch 1.")
    print(f"Overall Attack Flows: {df_raw['Label'].sum()} ({df_raw['Label'].mean()*100:.2f}%)\n")

    all_block_records = []

    for b_idx in range(n_blocks):
        start_idx = b_idx * block_size
        end_idx = start_idx + block_size
        print(f"Evaluating Flow Block {b_idx:02d} (Flows [{start_idx}:{end_idx}])...")
        sub_df = df_raw.iloc[start_idx:end_idx].copy().reset_index(drop=True)
        recs = evaluate_single_flow_block(block_id=b_idx, df_block=sub_df, seed=42, subseq_len_m=5)
        all_block_records.extend(recs)

    df_detailed = pd.DataFrame(all_block_records)
    det_csv = os.path.join(OUTPUT_METRICS_DIR, "unsw_multiblock_flow_detailed.csv")
    det_json = os.path.join(OUTPUT_METRICS_DIR, "unsw_multiblock_flow_detailed.json")
    df_detailed.to_csv(det_csv, index=False)
    df_detailed.to_json(det_json, orient="records", indent=2)

    # Compute Summary Across 10 Blocks
    summary_records = []
    for model_name, grp in df_detailed.groupby("Model", sort=False):
        n_beats = int((grp["Beats_All_Attack_F1"] == "yes").sum())
        summary_records.append({
            "Model": model_name,
            "N_Blocks": len(grp),
            "F1_Mean": float(grp["Test_F1"].mean()),
            "F1_Std": float(grp["Test_F1"].std()),
            "Recall_Mean": float(grp["Test_Recall"].mean()),
            "Recall_Std": float(grp["Test_Recall"].std()),
            "Precision_Mean": float(grp["Test_Precision"].mean()),
            "Precision_Std": float(grp["Test_Precision"].std()),
            "FPR_Mean": float(grp["Test_FPR"].mean()),
            "FPR_Std": float(grp["Test_FPR"].std()),
            "ROC_AUC_Mean": float(grp["ROC_AUC"].dropna().mean()) if len(grp["ROC_AUC"].dropna()) > 0 else None,
            "PR_AUC_Mean": float(grp["PR_AUC"].dropna().mean()) if len(grp["PR_AUC"].dropna()) > 0 else None,
            "PR_AUC_Lift_Mean": float(grp["PR_AUC_Lift"].mean()),
            "All_Attack_F1_Mean": float(grp["All_Attack_F1"].mean()),
            "Blocks_Beating_All_Attack": f"{n_beats}/{len(grp)}",
            "Beats_All_Attack_Consistently": "YES" if n_beats == len(grp) else ("PARTIAL" if n_beats > 0 else "NO")
        })

    df_summary = pd.DataFrame(summary_records)
    sum_csv = os.path.join(OUTPUT_METRICS_DIR, "unsw_multiblock_flow_summary.csv")
    sum_json = os.path.join(OUTPUT_METRICS_DIR, "unsw_multiblock_flow_summary.json")
    df_summary.to_csv(sum_csv, index=False)
    df_summary.to_json(sum_json, orient="records", indent=2)

    # Plot Multi-Block F1 Distribution Across Models
    fig, ax = plt.subplots(figsize=(14, 6))
    non_trivial = df_detailed[~df_detailed["Model"].str.startswith("Baseline: All") & ~df_detailed["Model"].str.startswith("Baseline: Random")]
    order = df_summary[~df_summary["Model"].str.startswith("Baseline: All") & ~df_summary["Model"].str.startswith("Baseline: Random")].sort_values("F1_Mean", ascending=False)["Model"].tolist()

    data_to_plot = [non_trivial[non_trivial["Model"] == m]["Test_F1"].values for m in order]
    clean_labels = [m.replace("Baseline: ", "").replace("Config ", "") for m in order]

    ax.boxplot(data_to_plot, tick_labels=clean_labels, patch_artist=True, boxprops=dict(facecolor="#2b5c8f", alpha=0.6))
    all_atk_mean = df_summary[df_summary["Model"] == "Baseline: All-Attack"]["F1_Mean"].values[0]
    ax.axhline(all_atk_mean, color="red", linestyle="--", linewidth=1.8, label=f"Baseline: All-Attack Mean F1 ({all_atk_mean:.4f})")

    ax.set_title("UNSW-NB15 Flow-Level Performance Across 10 Contiguous 8k-Flow Blocks (Batch 1)", fontsize=12, fontweight="bold")
    ax.set_ylabel("Test F1-Score")
    ax.set_xticklabels(clean_labels, rotation=35, ha="right")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend(fontsize=10, loc="upper right")

    plt.tight_layout()
    fig_path = os.path.join(OUTPUT_FIGURES_DIR, "unsw_multiblock_flow_f1.png")
    fig.savefig(fig_path, dpi=200)
    plt.close(fig)

    print(f"\nSaved detailed flow results to {det_csv}")
    print(f"Saved flow summary table to {sum_csv}")
    print(f"Saved multi-block plot to {fig_path}")
    print(f"Total multi-block evaluation runtime: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    run_unsw_multiblock_evaluation()
