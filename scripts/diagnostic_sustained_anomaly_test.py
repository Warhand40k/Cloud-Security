"""
Phase 2.2: Synthetic Sustained and Repeated Anomaly Diagnostic Test.
Tests the core scientific hypothesis:
"Sustained or repeated anomalies become motifs and stop being discords in a self-join."

Experimental Setup:
- Background: N=2500, D=5 quasi-periodic channels with Gaussian noise.
- Subsequence length: m = 25.
- Anomaly lengths: L in {0.5m, 1.0m, 2.0m, 5.0m, 10.0m} -> L in {12, 25, 50, 125, 250}.
- Repeated injections: R in {1, 3, 5} identical bursts.
- Repetitions: 20 random seeds for each (L, R) condition (300 simulations total).
- Metrics evaluated:
  - ROC-AUC: Area under ROC curve of self-join scores vs true anomaly mask.
  - PR-AUC: Area under Precision-Recall curve.
  - Top-1 Detection Rate: Fraction of runs where argmax(scores) falls inside an anomaly.
  - Score Contrast: mean(scores_anomaly) / mean(scores_benign).
- Outputs saved to:
  - results/v2/metrics/synthetic_sustained_anomaly_results.csv
  - results/v2/metrics/synthetic_sustained_anomaly_summary.json
  - results/v2/figures/synthetic_sustained_anomaly_matrix.png
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_auc_score, average_precision_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores

OUTPUT_CSV = "results/v2/metrics/synthetic_sustained_anomaly_results.csv"
OUTPUT_JSON = "results/v2/metrics/synthetic_sustained_anomaly_summary.json"
OUTPUT_FIG = "results/v2/figures/synthetic_sustained_anomaly_matrix.png"

def generate_synthetic_series(N=2500, D=5, m=25, L=25, R=1, seed=42):
    """
    Generates background series with R non-overlapping injected anomalies of length L.
    Returns:
        X: (N, D) array
        y: (N,) binary ground truth mask (1 during anomaly, 0 elsewhere)
        intervals: list of (t_start, t_end) intervals
    """
    rng = np.random.RandomState(seed)
    t = np.linspace(0, 100, N)
    X = np.zeros((N, D))
    
    # 1. Background channels
    for d in range(D):
        freq = 0.5 + 0.2 * d
        X[:, d] = np.sin(2 * np.pi * freq * t) + 0.15 * rng.randn(N)
        
    # 2. Place R intervals
    # Ensure buffer from start and end, and enough spacing between bursts
    margin_start = 200
    available_span = N - margin_start - 100 - (R * L)
    spacing = available_span // (R + 1)
    
    intervals = []
    y = np.zeros(N, dtype=int)
    
    # Common anomaly waveform pattern for length L (shared across repeats!)
    t_ano = np.linspace(0, max(2.0, L / 10.0), L)
    pattern = 3.5 * np.cos(2 * np.pi * 3.0 * t_ano)
    
    curr_t = margin_start + spacing
    anomaly_channels = [0, 2, 4]
    
    for r in range(R):
        t_start = curr_t
        t_end = t_start + L
        intervals.append((t_start, t_end))
        y[t_start:t_end] = 1
        
        for ch in anomaly_channels:
            X[t_start:t_end, ch] += pattern
            
        curr_t = t_end + spacing

    return X, y, intervals

def run_sustained_anomaly_diagnostic():
    print("=" * 80)
    print("PHASE 2.2: SYNTHETIC SUSTAINED & REPEATED ANOMALY DIAGNOSTIC")
    print("=" * 80)
    
    N = 2500
    D = 5
    m = 25
    
    length_factors = [0.5, 1.0, 2.0, 5.0, 10.0]
    lengths = [int(round(f * m)) for f in length_factors]
    repeats_list = [1, 3, 5]
    n_seeds = 20
    
    all_runs = []
    
    # Warm up numba JIT
    dummy_X = np.random.randn(200, D)
    compute_multidimensional_mp(dummy_X, m=10)
    
    total_sims = len(lengths) * len(repeats_list) * n_seeds
    print(f"Total conditions: {len(lengths)} lengths x {len(repeats_list)} repeats x {n_seeds} seeds = {total_sims} simulations")
    
    sim_count = 0
    for L_factor, L in zip(length_factors, lengths):
        for R in repeats_list:
            for s_idx in range(n_seeds):
                sim_count += 1
                seed = 1000 + s_idx * 17
                
                X, y, intervals = generate_synthetic_series(N=N, D=D, m=m, L=L, R=R, seed=seed)
                
                # Self-join mSTAMP
                mps, _ = compute_multidimensional_mp(X, m=m)
                k_star, _ = find_knee_dimension(mps, online=True, metric="max")
                scores = compute_point_anomaly_scores(mps, knee_dim=k_star, n_samples=N, m=m)
                
                # Evaluation
                # 1. ROC-AUC and PR-AUC
                try:
                    roc = roc_auc_score(y, scores)
                    pr = average_precision_score(y, scores)
                except Exception:
                    roc, pr = np.nan, np.nan
                    
                # 2. Top-1 discord localization
                top_idx = int(np.argmax(scores))
                # In causal alignment, discord window for an anomaly [start, end] extends up to end + m
                detected_in_any = any(start <= top_idx <= end + m for start, end in intervals)
                
                # 3. Score contrast
                mean_ano = float(np.mean(scores[y == 1])) if np.sum(y == 1) > 0 else 0.0
                mean_ben = float(np.mean(scores[y == 0])) if np.sum(y == 0) > 0 else 1.0
                contrast = mean_ano / (mean_ben + 1e-8)
                
                all_runs.append({
                    "length_factor": L_factor,
                    "L": L,
                    "repeats": R,
                    "seed": seed,
                    "subseq_m": m,
                    "k_star": int(k_star),
                    "roc_auc": float(roc),
                    "pr_auc": float(pr),
                    "top1_detected": int(detected_in_any),
                    "mean_score_anomaly": mean_ano,
                    "mean_score_benign": mean_ben,
                    "score_contrast": float(contrast)
                })

            # Print progress per (L, R) block
            sub = [r for r in all_runs if r["L"] == L and r["repeats"] == R]
            mean_roc = np.mean([r["roc_auc"] for r in sub])
            det_rate = np.mean([r["top1_detected"] for r in sub]) * 100.0
            mean_cont = np.mean([r["score_contrast"] for r in sub])
            print(f"  L = {L_factor:4.1f}m ({L:3d} pts) | Repeats = {R:1d} -> Mean ROC-AUC: {mean_roc:.4f} | Top-1 Detect Rate: {det_rate:5.1f}% | Contrast: {mean_cont:.2f}")

    df_runs = pd.DataFrame(all_runs)
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    df_runs.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved raw simulation records to {OUTPUT_CSV}")
    
    # Aggregate summary
    summary_list = []
    for (lf, L, R), grp in df_runs.groupby(["length_factor", "L", "repeats"]):
        summary_list.append({
            "length_factor": float(lf),
            "L": int(L),
            "repeats": int(R),
            "n_seeds": len(grp),
            "roc_auc_mean": round(float(grp["roc_auc"].mean()), 4),
            "roc_auc_std": round(float(grp["roc_auc"].std()), 4),
            "roc_auc_min": round(float(grp["roc_auc"].min()), 4),
            "roc_auc_max": round(float(grp["roc_auc"].max()), 4),
            "pr_auc_mean": round(float(grp["pr_auc"].mean()), 4),
            "pr_auc_std": round(float(grp["pr_auc"].std()), 4),
            "top1_detection_rate_pct": round(float(grp["top1_detected"].mean() * 100), 2),
            "score_contrast_mean": round(float(grp["score_contrast"].mean()), 4),
            "score_contrast_std": round(float(grp["score_contrast"].std()), 4)
        })
        
    with open(OUTPUT_JSON, "w") as f:
        json.dump(summary_list, f, indent=2)
    print(f"Saved aggregated diagnostic summary to {OUTPUT_JSON}")
    
    # -------------------------------------------------------------------------
    # Visualization
    # -------------------------------------------------------------------------
    print("\nGenerating diagnostic visualization...")
    sum_df = pd.DataFrame(summary_list)
    
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    
    # Plot 1: ROC-AUC vs Length Factor for each repeat count
    for r_val, color, marker in zip([1, 3, 5], ["#1f77b4", "#ff7f0e", "#2ca02c"], ["o", "s", "^"]):
        sub = sum_df[sum_df["repeats"] == r_val]
        axes[0].plot(sub["length_factor"], sub["roc_auc_mean"], f"-{marker}", color=color, lw=2.2, label=f"R = {r_val} Repeat(s)")
        axes[0].fill_between(
            sub["length_factor"],
            sub["roc_auc_mean"] - sub["roc_auc_std"],
            sub["roc_auc_mean"] + sub["roc_auc_std"],
            color=color, alpha=0.15
        )
    axes[0].axhline(0.5, color="gray", linestyle=":", label="Random Guess (0.50)")
    axes[0].set_xlabel("Anomaly Duration $L$ (in multiples of $m$)", fontsize=11)
    axes[0].set_ylabel("ROC-AUC Score", fontsize=11)
    axes[0].set_title("Self-Join ROC-AUC vs. Anomaly Duration & Repeats\n(Hypothesis Test: Anomaly Collapse into Motifs)")
    axes[0].grid(True, alpha=0.3)
    axes[0].set_xscale("log", base=2)
    axes[0].set_xticks(length_factors)
    axes[0].get_xaxis().set_major_formatter(plt.ScalarFormatter())
    axes[0].legend(loc="lower left", fontsize=9)
    
    # Plot 2: Top-1 Detection Rate
    for r_val, color, marker in zip([1, 3, 5], ["#1f77b4", "#ff7f0e", "#2ca02c"], ["o", "s", "^"]):
        sub = sum_df[sum_df["repeats"] == r_val]
        axes[1].plot(sub["length_factor"], sub["top1_detection_rate_pct"], f"-{marker}", color=color, lw=2.2, label=f"R = {r_val} Repeat(s)")
    axes[1].set_xlabel("Anomaly Duration $L$ (in multiples of $m$)", fontsize=11)
    axes[1].set_ylabel("Top-1 Discord Detection Rate (%)", fontsize=11)
    axes[1].set_title("Top-1 Anomaly Localization Rate\n(Does Peak Distance Point to Injected Anomaly?)")
    axes[1].grid(True, alpha=0.3)
    axes[1].set_xscale("log", base=2)
    axes[1].set_xticks(length_factors)
    axes[1].get_xaxis().set_major_formatter(plt.ScalarFormatter())
    axes[1].legend(loc="lower left", fontsize=9)
    
    # Plot 3: Example score profiles for L=m (R=1) vs L=10m (R=5)
    X_short, y_short, _ = generate_synthetic_series(N=N, D=D, m=m, L=m, R=1, seed=42)
    mps_short, _ = compute_multidimensional_mp(X_short, m=m)
    k_short, _ = find_knee_dimension(mps_short, online=True, metric="max")
    sc_short = compute_point_anomaly_scores(mps_short, knee_dim=k_short, n_samples=N, m=m)
    
    X_long, y_long, _ = generate_synthetic_series(N=N, D=D, m=m, L=10*m, R=5, seed=42)
    mps_long, _ = compute_multidimensional_mp(X_long, m=m)
    k_long, _ = find_knee_dimension(mps_long, online=True, metric="max")
    sc_long = compute_point_anomaly_scores(mps_long, knee_dim=k_long, n_samples=N, m=m)
    
    axes[2].plot(sc_short, color="#1f77b4", lw=1.5, alpha=0.8, label="L=1m, R=1 (Isolated Discord)")
    axes[2].plot(sc_long, color="#d62728", lw=1.5, alpha=0.8, label="L=10m, R=5 (Sustained/Repeated)")
    axes[2].set_xlabel("Time Step $t$", fontsize=11)
    axes[2].set_ylabel("Self-Join Anomaly Score", fontsize=11)
    axes[2].set_title("Qualitative Discord Profile Comparison:\nSharp Spike (Short) vs Collapsed Profile (Sustained)")
    axes[2].grid(True, alpha=0.3)
    axes[2].legend(loc="upper right", fontsize=8)
    
    plt.tight_layout()
    os.makedirs(os.path.dirname(OUTPUT_FIG), exist_ok=True)
    plt.savefig(OUTPUT_FIG, dpi=300)
    plt.close()
    print(f"Saved diagnostic visualization to {OUTPUT_FIG}")

if __name__ == "__main__":
    run_sustained_anomaly_diagnostic()

