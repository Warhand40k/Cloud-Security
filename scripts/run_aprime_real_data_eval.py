"""
Phase 3.3: Real-Data Evaluation of Config A-prime vs Config A.
Evaluates:
1. UNSW-NB15 Flow (8,000 flows)
2. UNSW-NB15 Window (10-second intervals)
3. CSE-CIC-IDS2018 Friday (60-second intervals, full 191 windows)

For each dataset:
- Config A: Base paper reproduction (mSTAMP self-join on full series).
- Config A-prime: Causal benign-reference AB-join (stumpy.stump against training history B).
  - Selected k* with Kneedle on training/validation reference ONLY.
  - Threshold calibrated strictly on validation split.
  - Zero test label leakage.
  - Causal right alignment with zero future lookahead.

Outputs:
- results/v2/metrics/aprime_real_data_comparison.csv
- results/v2/metrics/aprime_real_data_comparison.json
- results/v2/predictions/<dataset>_aprime_predictions.parquet
- results/v2/figures/real_data_a_vs_aprime_scores.png
"""

import os
import sys
import json
import time
import subprocess
import platform
import psutil
import hashlib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import (
    compute_multidimensional_ab_profile,
    compute_causal_point_scores,
    CausalABScorer
)
from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor
from src.evaluation import (
    compute_classification_metrics,
    compute_sre_operational_metrics,
    compute_bootstrap_confidence_intervals
)

OUTPUT_CSV = "results/v2/metrics/aprime_real_data_comparison.csv"
OUTPUT_JSON = "results/v2/metrics/aprime_real_data_comparison.json"
PRED_DIR = "results/v2/predictions"
FIG_DIR = "results/v2/figures"

os.makedirs(PRED_DIR, exist_ok=True)
os.makedirs(FIG_DIR, exist_ok=True)

def get_environment_metadata(seed=42):
    try:
        commit_hash = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8").strip()
    except Exception:
        commit_hash = "unknown"
        
    return {
        "git_commit": commit_hash,
        "random_seed": seed,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": psutil.cpu_count(logical=True),
        "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__
    }

def run_real_data_benchmark():
    print("=" * 80)
    print("PHASE 3.3: CONFIG A-PRIME VS CONFIG A REAL DATA BENCHMARK")
    print("=" * 80)

    env_meta = get_environment_metadata(seed=42)
    comparison_rows = []
    
    # =========================================================================
    # 1. UNSW-NB15 Flow Telemetry
    # =========================================================================
    print("\n--- 1. Evaluating UNSW-NB15 Flow ---")
    raw_unsw = load_and_sort_raw_unsw("data/raw", file_indices=[1], nrows=25000).iloc[:8000].copy()
    tr_df, va_df, te_df = split_chronological(raw_unsw, 0.6, 0.2, 0.2)
    prep = UNSWPreprocessor("standard")
    prep.fit(tr_df)
    X_tr, y_tr = prep.transform(tr_df)
    X_va, y_va = prep.transform(va_df)
    X_te, y_te = prep.transform(te_df)
    
    time_col = "Stime" if "Stime" in te_df.columns else "stime"
    t_test_flow = te_df[time_col].values
    m_flow = 50
    
    # CONFIG A: Self-Join mSTAMP
    t0 = time.time()
    X_full_flow = np.vstack([X_tr, X_va, X_te])
    mps_a, _ = compute_multidimensional_mp(X_full_flow, m=m_flow)
    k_star_a, _ = find_knee_dimension(mps_a, online=True, metric="max")
    scores_full_a = compute_point_anomaly_scores(mps_a, knee_dim=k_star_a, n_samples=len(X_full_flow), m=m_flow)
    scores_val_a = scores_full_a[len(X_tr) : len(X_tr) + len(X_va)]
    scores_test_a = scores_full_a[len(X_tr) + len(X_va) :]
    
    # Calibrate threshold on validation only
    val_p_grid = np.linspace(80, 99.8, 80)
    best_th_a = float(np.median(scores_val_a))
    best_f1_va = -1.0
    for p in val_p_grid:
        th = float(np.percentile(scores_val_a, p))
        f1_v = compute_classification_metrics(y_va, (scores_val_a >= th).astype(int))["f1"]
        if f1_v > best_f1_va:
            best_f1_va = f1_v
            best_th_a = th
            
    pred_test_a = (scores_test_a >= best_th_a).astype(int)
    rt_a = time.time() - t0
    
    cls_a = compute_classification_metrics(y_te, pred_test_a, scores_test_a)
    sre_a = compute_sre_operational_metrics(y_te, pred_test_a, t_test_flow, default_step_sec=1.0)
    
    # CONFIG A-PRIME: Causal AB-Join against Benign Training Reference
    t0 = time.time()
    # Use benign training history B (strictly y_tr == 0)
    B_ref_flow = X_tr[y_tr == 0]
    
    # Choose k* on validation AB-profile against B_ref
    mps_va_ap, _ = compute_multidimensional_ab_profile(A=X_va, B=B_ref_flow, m=m_flow)
    k_star_ap, _ = find_knee_dimension(mps_va_ap, online=True, metric="max")
    scores_val_ap = compute_causal_point_scores(mps_va_ap, knee_dim=k_star_ap, n_samples=len(X_va), m=m_flow)
    
    # Calibrate threshold on validation AB-scores
    best_th_ap = float(np.median(scores_val_ap))
    best_f1_vap = -1.0
    for p in val_p_grid:
        th = float(np.percentile(scores_val_ap, p))
        f1_v = compute_classification_metrics(y_va, (scores_val_ap >= th).astype(int))["f1"]
        if f1_v > best_f1_vap:
            best_f1_vap = f1_v
            best_th_ap = th
            
    # Score test causally against B_ref
    mps_te_ap, _ = compute_multidimensional_ab_profile(A=X_te, B=B_ref_flow, m=m_flow)
    scores_test_ap = compute_causal_point_scores(mps_te_ap, knee_dim=k_star_ap, n_samples=len(X_te), m=m_flow)
    pred_test_ap = (scores_test_ap >= best_th_ap).astype(int)
    rt_ap = time.time() - t0
    
    cls_ap = compute_classification_metrics(y_te, pred_test_ap, scores_test_ap)
    sre_ap = compute_sre_operational_metrics(y_te, pred_test_ap, t_test_flow, default_step_sec=1.0)
    
    # Save predictions
    pd.DataFrame({
        "timestamp": t_test_flow,
        "y_true": y_te,
        "scores_A": scores_test_a,
        "pred_A": pred_test_a,
        "scores_A_prime": scores_test_ap,
        "pred_A_prime": pred_test_ap
    }).to_parquet(os.path.join(PRED_DIR, "unsw_flow_aprime_predictions.parquet"), index=False)

    def add_row(ds, model, cls_m, sre_m, k_val, th_val, rt):
        return {
            "Dataset": ds,
            "Model": model,
            "k_subspace": int(k_val),
            "Threshold": round(float(th_val), 4),
            "F1": round(float(cls_m["f1"]), 4),
            "Precision": round(float(cls_m["precision"]), 4),
            "Recall": round(float(cls_m["recall"]), 4),
            "FPR": round(float(cls_m["fpr"]), 4),
            "ROC_AUC": round(float(cls_m["roc_auc"]), 4) if cls_m["roc_auc"] is not None else np.nan,
            "PR_AUC": round(float(cls_m["pr_auc"]), 4) if cls_m["pr_auc"] is not None else np.nan,
            "Total_Alerts": int(sre_m["total_alerts"]),
            "Episode_Recall": round(float(sre_m["episode_recall"]), 4),
            "MTTD_Sec": round(float(sre_m["mean_delay_sec"]), 2) if sre_m["mean_delay_sec"] is not None else np.nan,
            "Runtime_Sec": round(float(rt), 2)
        }

    comparison_rows.append(add_row("UNSW-NB15 Flow", "Config A (Self-Join)", cls_a, sre_a, k_star_a, best_th_a, rt_a))
    comparison_rows.append(add_row("UNSW-NB15 Flow", "Config A-prime (Causal AB)", cls_ap, sre_ap, k_star_ap, best_th_ap, rt_ap))
    print(f"  Config A:       F1={cls_a['f1']:.4f} | PR-AUC={cls_a['pr_auc']:.4f} | ROC-AUC={cls_a['roc_auc']:.4f} | FPR={cls_a['fpr']*100:.2f}% | Alerts={sre_a['total_alerts']}")
    print(f"  Config A-prime: F1={cls_ap['f1']:.4f} | PR-AUC={cls_ap['pr_auc']:.4f} | ROC-AUC={cls_ap['roc_auc']:.4f} | FPR={cls_ap['fpr']*100:.2f}% | Alerts={sre_ap['total_alerts']}")

    # =========================================================================
    # 2. UNSW-NB15 Window Telemetry
    # =========================================================================
    print("\n--- 2. Evaluating UNSW-NB15 Window ---")
    df_win = pd.read_parquet("data/processed/unsw_nb15_10s_windows.parquet")
    feat_unsw_win = ["dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "state", "service"]
    tr_w = df_win.iloc[1200:3200]
    va_w = df_win.iloc[3200:4600]
    te_w = df_win.iloc[4600:5800]
    
    prep_w = UNSWPreprocessor("standard")
    X_tr_w, y_tr_w = prep_w.fit_transform(tr_w)
    X_va_w, y_va_w = prep_w.transform(va_w)
    X_te_w, y_te_w = prep_w.transform(te_w)
    t_test_w = te_w["window_time"].values if "window_time" in te_w.columns else np.arange(len(te_w))
    m_win = 50
    
    # Config A (Self-Join)
    t0 = time.time()
    X_full_w = np.vstack([X_tr_w, X_va_w, X_te_w])
    mps_w_a, _ = compute_multidimensional_mp(X_full_w, m=m_win)
    k_star_w_a, _ = find_knee_dimension(mps_w_a, online=True, metric="max")
    scores_full_w_a = compute_point_anomaly_scores(mps_w_a, knee_dim=k_star_w_a, n_samples=len(X_full_w), m=m_win)
    scores_va_w_a = scores_full_w_a[len(X_tr_w) : len(X_tr_w) + len(X_va_w)]
    scores_te_w_a = scores_full_w_a[len(X_tr_w) + len(X_va_w) :]
    
    best_th_wa = float(np.median(scores_va_w_a))
    best_f1_wva = -1.0
    for p in val_p_grid:
        th = float(np.percentile(scores_va_w_a, p))
        f1_v = compute_classification_metrics(y_va_w, (scores_va_w_a >= th).astype(int))["f1"]
        if f1_v > best_f1_wva:
            best_f1_wva = f1_v
            best_th_wa = th
    pred_te_w_a = (scores_te_w_a >= best_th_wa).astype(int)
    rt_wa = time.time() - t0
    cls_wa = compute_classification_metrics(y_te_w, pred_te_w_a, scores_te_w_a)
    sre_wa = compute_sre_operational_metrics(y_te_w, pred_te_w_a, t_test_w, default_step_sec=10.0)
    
    # Config A-prime (Causal AB-Join against pure benign training history [1200:3200])
    t0 = time.time()
    B_ref_w = X_tr_w # 100% pure benign baseline
    mps_va_wap, _ = compute_multidimensional_ab_profile(A=X_va_w, B=B_ref_w, m=m_win)
    k_star_wap, _ = find_knee_dimension(mps_va_wap, online=True, metric="max")
    scores_va_wap = compute_causal_point_scores(mps_va_wap, knee_dim=k_star_wap, n_samples=len(X_va_w), m=m_win)
    
    best_th_wap = float(np.median(scores_va_wap))
    best_f1_wvap = -1.0
    for p in val_p_grid:
        th = float(np.percentile(scores_va_wap, p))
        f1_v = compute_classification_metrics(y_va_w, (scores_va_wap >= th).astype(int))["f1"]
        if f1_v > best_f1_wvap:
            best_f1_wvap = f1_v
            best_th_wap = th
            
    mps_te_wap, _ = compute_multidimensional_ab_profile(A=X_te_w, B=B_ref_w, m=m_win)
    scores_te_wap = compute_causal_point_scores(mps_te_wap, knee_dim=k_star_wap, n_samples=len(X_te_w), m=m_win)
    pred_te_w_ap = (scores_te_wap >= best_th_wap).astype(int)
    rt_wap = time.time() - t0
    cls_wap = compute_classification_metrics(y_te_w, pred_te_w_ap, scores_te_wap)
    sre_wap = compute_sre_operational_metrics(y_te_w, pred_te_w_ap, t_test_w, default_step_sec=10.0)
    
    pd.DataFrame({
        "timestamp": t_test_w,
        "y_true": y_te_w,
        "scores_A": scores_te_w_a,
        "pred_A": pred_te_w_a,
        "scores_A_prime": scores_te_wap,
        "pred_A_prime": pred_te_w_ap
    }).to_parquet(os.path.join(PRED_DIR, "unsw_window_aprime_predictions.parquet"), index=False)

    comparison_rows.append(add_row("UNSW-NB15 Window", "Config A (Self-Join)", cls_wa, sre_wa, k_star_w_a, best_th_wa, rt_wa))
    comparison_rows.append(add_row("UNSW-NB15 Window", "Config A-prime (Causal AB)", cls_wap, sre_wap, k_star_wap, best_th_wap, rt_wap))
    print(f"  Config A:       F1={cls_wa['f1']:.4f} | PR-AUC={cls_wa['pr_auc']:.4f} | ROC-AUC={cls_wa['roc_auc']:.4f} | Recall={cls_wa['recall']*100:.2f}% | Alerts={sre_wa['total_alerts']}")
    print(f"  Config A-prime: F1={cls_wap['f1']:.4f} | PR-AUC={cls_wap['pr_auc']:.4f} | ROC-AUC={cls_wap['roc_auc']:.4f} | Recall={cls_wap['recall']*100:.2f}% | Alerts={sre_wap['total_alerts']}")

    # =========================================================================
    # 3. CSE-CIC-IDS2018 Friday Telemetry (All 191 Windows)
    # =========================================================================
    print("\n--- 3. Evaluating CSE-CIC-IDS2018 Friday (Full 191 Windows) ---")
    df_fri = pd.read_parquet("data/processed/csecicids2018_60s_any_attack.parquet")
    feat_cse = [
        "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
        "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
        "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
    ]
    tr_c = df_fri.iloc[0:80]
    va_c = df_fri.iloc[80:105]
    te_c = df_fri.iloc[105:191] # Full remaining test slice (86 windows)
    
    raw_tr_c = np.nan_to_num(tr_c[feat_cse].values.astype(float), nan=0.0)
    raw_va_c = np.nan_to_num(va_c[feat_cse].values.astype(float), nan=0.0)
    raw_te_c = np.nan_to_num(te_c[feat_cse].values.astype(float), nan=0.0)
    
    scaler_c = StandardScaler()
    X_tr_c = scaler_c.fit_transform(raw_tr_c)
    X_va_c = scaler_c.transform(raw_va_c)
    X_te_c = scaler_c.transform(raw_te_c)
    
    lbl_c = "Label" if "Label" in df_fri.columns else "Label_any"
    y_tr_c = tr_c[lbl_c].values.astype(int)
    y_va_c = va_c[lbl_c].values.astype(int)
    y_te_c = te_c[lbl_c].values.astype(int)
    t_test_c = te_c["window_time"].values
    m_cse = 10
    
    # Config A (Self-Join)
    t0 = time.time()
    X_full_c = np.vstack([X_tr_c, X_va_c, X_te_c])
    mps_c_a, _ = compute_multidimensional_mp(X_full_c, m=m_cse)
    k_star_c_a, _ = find_knee_dimension(mps_c_a, online=True, metric="max")
    scores_full_c_a = compute_point_anomaly_scores(mps_c_a, knee_dim=k_star_c_a, n_samples=len(X_full_c), m=m_cse)
    scores_va_c_a = scores_full_c_a[len(X_tr_c) : len(X_tr_c) + len(X_va_c)]
    scores_te_c_a = scores_full_c_a[len(X_tr_c) + len(X_va_c) :]
    
    best_th_ca = float(np.median(scores_va_c_a))
    best_f1_cva = -1.0
    for p in val_p_grid:
        th = float(np.percentile(scores_va_c_a, p))
        f1_v = compute_classification_metrics(y_va_c, (scores_va_c_a >= th).astype(int))["f1"]
        if f1_v > best_f1_cva:
            best_f1_cva = f1_v
            best_th_ca = th
    pred_te_c_a = (scores_te_c_a >= best_th_ca).astype(int)
    rt_ca = time.time() - t0
    cls_ca = compute_classification_metrics(y_te_c, pred_te_c_a, scores_te_c_a)
    sre_ca = compute_sre_operational_metrics(y_te_c, pred_te_c_a, t_test_c, default_step_sec=60.0)
    
    # Config A-prime (Causal AB-Join against Benign Training Reference)
    t0 = time.time()
    # Filter benign reference: strictly y_tr_c == 0 (76 windows)
    B_ref_c = X_tr_c[y_tr_c == 0]
    mps_va_cap, _ = compute_multidimensional_ab_profile(A=X_va_c, B=B_ref_c, m=m_cse)
    k_star_cap, _ = find_knee_dimension(mps_va_cap, online=True, metric="max")
    scores_va_cap = compute_causal_point_scores(mps_va_cap, knee_dim=k_star_cap, n_samples=len(X_va_c), m=m_cse)
    
    best_th_cap = float(np.median(scores_va_cap))
    best_f1_cvap = -1.0
    for p in val_p_grid:
        th = float(np.percentile(scores_va_cap, p))
        f1_v = compute_classification_metrics(y_va_c, (scores_va_cap >= th).astype(int))["f1"]
        if f1_v > best_f1_cvap:
            best_f1_cvap = f1_v
            best_th_cap = th
            
    mps_te_cap, _ = compute_multidimensional_ab_profile(A=X_te_c, B=B_ref_c, m=m_cse)
    scores_te_cap = compute_causal_point_scores(mps_te_cap, knee_dim=k_star_cap, n_samples=len(X_te_c), m=m_cse)
    pred_te_c_ap = (scores_te_cap >= best_th_cap).astype(int)
    rt_cap = time.time() - t0
    cls_cap = compute_classification_metrics(y_te_c, pred_te_c_ap, scores_te_cap)
    sre_cap = compute_sre_operational_metrics(y_te_c, pred_te_c_ap, t_test_c, default_step_sec=60.0)
    
    pd.DataFrame({
        "timestamp": t_test_c,
        "y_true": y_te_c,
        "scores_A": scores_te_c_a,
        "pred_A": pred_te_c_a,
        "scores_A_prime": scores_te_cap,
        "pred_A_prime": pred_te_c_ap
    }).to_parquet(os.path.join(PRED_DIR, "csecicids2018_friday_aprime_predictions.parquet"), index=False)

    comparison_rows.append(add_row("CSE-CIC-IDS2018 Friday", "Config A (Self-Join)", cls_ca, sre_ca, k_star_c_a, best_th_ca, rt_ca))
    comparison_rows.append(add_row("CSE-CIC-IDS2018 Friday", "Config A-prime (Causal AB)", cls_cap, sre_cap, k_star_cap, best_th_cap, rt_cap))
    print(f"  Config A:       F1={cls_ca['f1']:.4f} | PR-AUC={cls_ca['pr_auc']:.4f} | ROC-AUC={cls_ca['roc_auc']:.4f} | Recall={cls_ca['recall']*100:.2f}% | Alerts={sre_ca['total_alerts']}")
    print(f"  Config A-prime: F1={cls_cap['f1']:.4f} | PR-AUC={cls_cap['pr_auc']:.4f} | ROC-AUC={cls_cap['roc_auc']:.4f} | Recall={cls_cap['recall']*100:.2f}% | Alerts={sre_cap['total_alerts']}")

    # =========================================================================
    # Save Benchmark Artifacts
    # =========================================================================
    df_comp = pd.DataFrame(comparison_rows)
    df_comp.to_csv(OUTPUT_CSV, index=False)
    
    output_dict = {
        "metadata": env_meta,
        "results": comparison_rows
    }
    with open(OUTPUT_JSON, "w") as f:
        json.dump(output_dict, f, indent=2)
        
    print(f"\nSaved primary comparison table to {OUTPUT_CSV}")
    print(f"Saved JSON records to {OUTPUT_JSON}")
    
    # Visualization: Score traces of Config A vs A-prime
    fig, axes = plt.subplots(3, 1, figsize=(13, 9), sharex=False)
    
    # 1. UNSW Flow
    axes[0].plot(scores_test_a, label="Config A (Self-Join)", color="#1f77b4", lw=1.5, alpha=0.8)
    axes[0].plot(scores_test_ap, label="Config A-prime (Causal AB)", color="#2ca02c", lw=1.5, alpha=0.8)
    axes[0].scatter(np.where(y_te == 1)[0], scores_test_ap[y_te == 1], color="red", s=10, zorder=5, label="Attack Flows")
    axes[0].set_title("UNSW-NB15 Flow Telemetry: Config A vs. Config A-prime Anomaly Scores")
    axes[0].set_ylabel("Score")
    axes[0].legend(loc="upper right", fontsize=8)
    axes[0].grid(True, alpha=0.3)
    
    # 2. UNSW Window
    axes[1].plot(scores_te_w_a, label="Config A (Self-Join)", color="#1f77b4", lw=1.5, alpha=0.8)
    axes[1].plot(scores_te_wap, label="Config A-prime (Causal AB)", color="#2ca02c", lw=1.5, alpha=0.8)
    axes[1].axvspan(0, np.sum(y_te_w == 1), color="red", alpha=0.15, label="Attack Windows")
    axes[1].set_title("UNSW-NB15 Window Telemetry (Regime Shift): Config A vs. Config A-prime")
    axes[1].set_ylabel("Score")
    axes[1].legend(loc="upper right", fontsize=8)
    axes[1].grid(True, alpha=0.3)
    
    # 3. CSE-CIC-IDS2018 Friday
    axes[2].plot(scores_te_c_a, label="Config A (Self-Join)", color="#1f77b4", lw=1.5, alpha=0.8)
    axes[2].plot(scores_te_cap, label="Config A-prime (Causal AB)", color="#2ca02c", lw=1.5, alpha=0.8)
    axes[2].scatter(np.where(y_te_c == 1)[0], scores_te_cap[y_te_c == 1], color="red", s=15, zorder=5, label="Attack Windows")
    axes[2].set_title("CSE-CIC-IDS2018 Friday (DoS Flooding): Config A vs. Config A-prime")
    axes[2].set_xlabel("Test Window Index")
    axes[2].set_ylabel("Score")
    axes[2].legend(loc="upper right", fontsize=8)
    axes[2].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "real_data_a_vs_aprime_scores.png"), dpi=300)
    plt.close()
    print(f"Saved visualization to {os.path.join(FIG_DIR, 'real_data_a_vs_aprime_scores.png')}")

if __name__ == "__main__":
    run_real_data_benchmark()

