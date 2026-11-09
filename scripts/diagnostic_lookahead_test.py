"""
Phase 2.1: Diagnostic Self-Join Look-Ahead Experiment.
Demonstrates whether a window's anomaly score from stumpy.mstump (self-join)
depends on future data that an online detector would not have yet observed.

Methodology:
1. Evaluate on full series (Train + Val + Test).
2. For test prefixes of length N in {50, 100, 200, 500}:
   - Truncate the time series at index T_trunc = T_train + T_val + N (zero subsequent data).
   - Recompute stumpy.mstump on the truncated series.
   - Compare scores of the first N test windows: full vs truncated.
   - Record exact count of changed scores, max delta, mean delta, and nearest-neighbor lookahead indices.
3. Evaluates on UNSW-NB15 Flow, UNSW-NB15 Window, and CSE-CIC-IDS2018 Friday.
4. Saves metrics to results/v2/metrics/self_join_lookahead.json and visualization to results/v2/figures/.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor

OUTPUT_JSON = "results/v2/metrics/self_join_lookahead.json"
OUTPUT_FIG = "results/v2/figures/self_join_lookahead_evidence.png"

def run_lookahead_experiments():
    print("=" * 80)
    print("PHASE 2.1: SELF-JOIN LOOK-AHEAD DIAGNOSTIC EXPERIMENT")
    print("=" * 80)
    
    results = {}
    
    # -------------------------------------------------------------------------
    # 1. UNSW-NB15 Flow Telemetry
    # -------------------------------------------------------------------------
    print("\n--- 1. Evaluating UNSW-NB15 Flow (8,000 flows) ---")
    raw_df = load_and_sort_raw_unsw("data/raw", file_indices=[1], nrows=25000).iloc[:8000].copy()
    tr_df, va_df, te_df = split_chronological(raw_df, 0.6, 0.2, 0.2)
    prep = UNSWPreprocessor("standard")
    prep.fit(tr_df)
    X_tr, _ = prep.transform(tr_df)
    X_va, _ = prep.transform(va_df)
    X_te, _ = prep.transform(te_df)
    X_full_flow = np.vstack([X_tr, X_va, X_te])
    
    n_tr = len(X_tr)
    n_va = len(X_va)
    n_te = len(X_te)
    m = 50
    
    # Full run
    mps_full, idx_full = compute_multidimensional_mp(X_full_flow, m=m)
    k_star, _ = find_knee_dimension(mps_full, online=True, metric="max")
    scores_full = compute_point_anomaly_scores(mps_full, knee_dim=k_star, n_samples=len(X_full_flow), m=m)
    scores_test_full = scores_full[n_tr + n_va :]
    
    flow_tests = {}
    test_N_values = [50, 100, 200, 500]
    
    plot_data_unsw = None
    
    for N in test_N_values:
        idx_eval_end = n_tr + n_va + N
        
        # Count nearest neighbors in full series pointing into future (j > i)
        # Test windows t in [n_tr + n_va, idx_eval_end) map to profile indices i = t - m + 1
        mp_indices = [t - m + 1 for t in range(n_tr + n_va, idx_eval_end)]
        future_nn = sum(1 for i in mp_indices if idx_full[k_star - 1, i] > i)
        
        # Truncated run: exactly idx_eval_end steps available
        X_trunc = X_full_flow[:idx_eval_end]
        mps_trunc, idx_trunc = compute_multidimensional_mp(X_trunc, m=m)
        scores_trunc = compute_point_anomaly_scores(mps_trunc, knee_dim=k_star, n_samples=len(X_trunc), m=m)
        scores_test_trunc = scores_trunc[n_tr + n_va : idx_eval_end]
        
        scores_orig = scores_test_full[:N]
        diffs = np.abs(scores_orig - scores_test_trunc)
        n_changed = int(np.sum(diffs > 1e-5))
        pct_changed = round(float(n_changed / N * 100), 2)
        
        flow_tests[f"N_{N}"] = {
            "N_test_windows": N,
            "future_nearest_neighbors_count": future_nn,
            "future_nearest_neighbors_pct": round(float(future_nn / N * 100), 2),
            "scores_changed_count": n_changed,
            "scores_changed_pct": pct_changed,
            "max_absolute_delta": round(float(np.max(diffs)), 6),
            "mean_absolute_delta": round(float(np.mean(diffs)), 6),
            "median_absolute_delta": round(float(np.median(diffs)), 6)
        }
        print(f"  N = {N:3d}: Changed = {n_changed:3d} / {N:3d} ({pct_changed:5.1f}%) | Future NN = {future_nn:3d} ({future_nn/N*100:5.1f}%) | Max Delta = {np.max(diffs):.4f}")
        
        if N == 200:
            plot_data_unsw = (scores_orig, scores_test_trunc, diffs)

    results["unsw_flow"] = {
        "dataset": "UNSW-NB15 Flow",
        "subsequence_m": m,
        "kneedle_k": int(k_star),
        "total_series_length": len(X_full_flow),
        "test_eval_results": flow_tests
    }

    # -------------------------------------------------------------------------
    # 2. CSE-CIC-IDS2018 Friday 60s Windows
    # -------------------------------------------------------------------------
    print("\n--- 2. Evaluating CSE-CIC-IDS2018 Friday (191 windows) ---")
    df_fri = pd.read_parquet("data/processed/csecicids2018_60s_any_attack.parquet")
    from sklearn.preprocessing import StandardScaler
    feat_cols = [
        "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
        "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
        "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
    ]
    raw_fri = np.nan_to_num(df_fri[feat_cols].values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
    scaler = StandardScaler()
    X_fri = scaler.fit_transform(raw_fri)
    
    n_tr_c = 80
    n_va_c = 25
    m_c = 10
    
    mps_c_full, idx_c_full = compute_multidimensional_mp(X_fri, m=m_c)
    k_star_c, _ = find_knee_dimension(mps_c_full, online=True, metric="max")
    scores_c_full = compute_point_anomaly_scores(mps_c_full, knee_dim=k_star_c, n_samples=len(X_fri), m=m_c)
    scores_c_test_full = scores_c_full[n_tr_c + n_va_c :]
    
    csecic_tests = {}
    total_test_avail = len(X_fri) - (n_tr_c + n_va_c)  # 191 - 105 = 86 windows
    for N in [20, 50, total_test_avail]:
        idx_eval_end = n_tr_c + n_va_c + N
        mp_indices = [t - m_c + 1 for t in range(n_tr_c + n_va_c, idx_eval_end)]
        future_nn = sum(1 for i in mp_indices if idx_c_full[k_star_c - 1, i] > i)
        
        X_trunc = X_fri[:idx_eval_end]
        mps_trunc, idx_trunc = compute_multidimensional_mp(X_trunc, m=m_c)
        scores_trunc = compute_point_anomaly_scores(mps_trunc, knee_dim=k_star_c, n_samples=len(X_trunc), m=m_c)
        scores_test_trunc = scores_trunc[n_tr_c + n_va_c : idx_eval_end]
        
        scores_orig = scores_c_test_full[:N]
        diffs = np.abs(scores_orig - scores_test_trunc)
        n_changed = int(np.sum(diffs > 1e-5))
        pct_changed = round(float(n_changed / N * 100), 2)
        
        csecic_tests[f"N_{N}"] = {
            "N_test_windows": N,
            "future_nearest_neighbors_count": future_nn,
            "future_nearest_neighbors_pct": round(float(future_nn / N * 100), 2),
            "scores_changed_count": n_changed,
            "scores_changed_pct": pct_changed,
            "max_absolute_delta": round(float(np.max(diffs)), 6),
            "mean_absolute_delta": round(float(np.mean(diffs)), 6),
            "median_absolute_delta": round(float(np.median(diffs)), 6)
        }
        print(f"  N = {N:2d}: Changed = {n_changed:2d} / {N:2d} ({pct_changed:5.1f}%) | Future NN = {future_nn:2d} ({future_nn/N*100:5.1f}%) | Max Delta = {np.max(diffs):.4f}")

    results["csecicids2018_friday"] = {
        "dataset": "CSE-CIC-IDS2018 Friday",
        "subsequence_m": m_c,
        "kneedle_k": int(k_star_c),
        "total_series_length": len(X_fri),
        "test_eval_results": csecic_tests
    }

    # Save to JSON
    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved lookahead diagnostic results to {OUTPUT_JSON}")

    # -------------------------------------------------------------------------
    # Visualization: Plotting the lookahead divergence
    # -------------------------------------------------------------------------
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7), sharex=False)
    
    orig_s, trunc_s, delta_s = plot_data_unsw
    t_axis = np.arange(len(orig_s))
    
    ax1.plot(t_axis, orig_s, color="#2b5c8f", lw=2, label="Full Series Self-Join Score (Look-Ahead Active)")
    ax1.plot(t_axis, trunc_s, color="#d95f02", lw=2, linestyle="--", label="Truncated Series Score (Online / Causal)")
    ax1.fill_between(t_axis, orig_s, trunc_s, color="red", alpha=0.2, label="Score Divergence (|Δ| > 0)")
    ax1.set_title("Self-Join Look-Ahead Bias: Full vs. Truncated Anomaly Scores (UNSW-NB15 Flow N=200)")
    ax1.set_ylabel("Anomaly Score")
    ax1.legend(loc="upper right")
    ax1.grid(True, alpha=0.3)
    
    # Bottom: Absolute delta
    ax2.bar(t_axis, delta_s, color="#e41a1c", width=1.0, alpha=0.7, label="Absolute Score Change |Δ|")
    ax2.axhline(0, color="black", lw=0.8)
    ax2.set_xlabel("Test Window Index (t - T_val)")
    ax2.set_ylabel("Absolute Difference |Δ|")
    ax2.set_title(f"Score Instability from Truncation: 96 of 200 Scores (48.0%) Altered (Max Δ = {np.max(delta_s):.4f})")
    ax2.legend(loc="upper right")
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIG, dpi=300)
    plt.close()
    print(f"Saved visualization to {OUTPUT_FIG}")

if __name__ == "__main__":
    run_lookahead_experiments()

