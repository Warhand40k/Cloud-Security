"""
Phase 3.2: Synthetic Sustained & Repeated Anomaly Test for Config A-prime.
Evaluates the causal benign-reference scorer (CausalABScorer) across the identical
300 simulation conditions as Phase 2 (5 lengths x 3 repeats x 20 seeds).

Compares:
Config A (Self-Join): Anomalies collapse into motifs as duration & repeats increase.
Config A-prime (Causal AB-Join): Benign reference B ensures anomalies remain high-distance discords.

Outputs:
- results/v2/metrics/synthetic_sustained_anomaly_aprime_results.csv
- results/v2/metrics/synthetic_sustained_anomaly_aprime_summary.json
- results/v2/figures/synthetic_sustained_anomaly_comparison_a_vs_aprime.png
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import roc_auc_score, average_precision_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.causal_ab_scorer import CausalABScorer
from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from scripts.diagnostic_sustained_anomaly_test import generate_synthetic_series

OUTPUT_CSV = "results/v2/metrics/synthetic_sustained_anomaly_aprime_results.csv"
OUTPUT_JSON = "results/v2/metrics/synthetic_sustained_anomaly_aprime_summary.json"
OUTPUT_FIG = "results/v2/figures/synthetic_sustained_anomaly_comparison_a_vs_aprime.png"

def generate_clean_benign_reference(N_b=1500, D=5, seed=999):
    """Generates pure benign training history B."""
    rng = np.random.RandomState(seed)
    t = np.linspace(0, 60, N_b)
    B = np.zeros((N_b, D))
    for d in range(D):
        freq = 0.5 + 0.2 * d
        B[:, d] = np.sin(2 * np.pi * freq * t) + 0.15 * rng.randn(N_b)
    return B

def run_aprime_synthetic_suite():
    print("=" * 80)
    print("PHASE 3.2: SYNTHETIC SUSTAINED & REPEATED TEST (CONFIG A-PRIME)")
    print("=" * 80)

    N = 2500
    D = 5
    m = 25

    length_factors = [0.5, 1.0, 2.0, 5.0, 10.0]
    lengths = [int(round(f * m)) for f in length_factors]
    repeats_list = [1, 3, 5]
    n_seeds = 20

    # 1. Generate benign training reference B
    B_ref = generate_clean_benign_reference(N_b=1500, D=D, seed=999)
    # Find knee dimension on B reference
    mps_B, _ = compute_multidimensional_mp(B_ref, m=m)
    k_star_B, _ = find_knee_dimension(mps_B, online=True, metric="max")
    print(f"Benign Reference B: shape={B_ref.shape}, Kneedle selected k*={k_star_B}")

    # Initialize causal A-prime scorer
    scorer = CausalABScorer(m=m, knee_dim=k_star_B)
    scorer.fit(B_ref)

    all_aprime_runs = []
    sim_count = 0
    total_sims = len(lengths) * len(repeats_list) * n_seeds

    for L_factor, L in zip(length_factors, lengths):
        for R in repeats_list:
            for s_idx in range(n_seeds):
                sim_count += 1
                seed = 1000 + s_idx * 17
                X, y, intervals = generate_synthetic_series(N=N, D=D, m=m, L=L, R=R, seed=seed)

                # Score causally with A-prime (AB-join against B_ref)
                scores = scorer.score(X)

                try:
                    roc = roc_auc_score(y, scores)
                    pr = average_precision_score(y, scores)
                except Exception:
                    roc, pr = np.nan, np.nan

                top_idx = int(np.argmax(scores))
                detected_in_any = any(start <= top_idx <= end + m for start, end in intervals)

                mean_ano = float(np.mean(scores[y == 1])) if np.sum(y == 1) > 0 else 0.0
                mean_ben = float(np.mean(scores[y == 0])) if np.sum(y == 0) > 0 else 1.0
                contrast = mean_ano / (mean_ben + 1e-8)

                all_aprime_runs.append({
                    "length_factor": L_factor,
                    "L": L,
                    "repeats": R,
                    "seed": seed,
                    "subseq_m": m,
                    "k_star": int(k_star_B),
                    "roc_auc": float(roc),
                    "pr_auc": float(pr),
                    "top1_detected": int(detected_in_any),
                    "mean_score_anomaly": mean_ano,
                    "mean_score_benign": mean_ben,
                    "score_contrast": float(contrast)
                })

            sub = [r for r in all_aprime_runs if r["L"] == L and r["repeats"] == R]
            mean_roc = np.mean([r["roc_auc"] for r in sub])
            det_rate = np.mean([r["top1_detected"] for r in sub]) * 100.0
            mean_cont = np.mean([r["score_contrast"] for r in sub])
            print(f"  A-prime: L = {L_factor:4.1f}m ({L:3d} pts) | Repeats = {R:1d} -> Mean ROC-AUC: {mean_roc:.4f} | Top-1 Detect: {det_rate:5.1f}% | Contrast: {mean_cont:.2f}")

    df_aprime = pd.DataFrame(all_aprime_runs)
    df_aprime.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved A-prime raw simulation records to {OUTPUT_CSV}")

    summary_list = []
    for (lf, L, R), grp in df_aprime.groupby(["length_factor", "L", "repeats"]):
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
    print(f"Saved A-prime diagnostic summary to {OUTPUT_JSON}")

    # -------------------------------------------------------------------------
    # Comparison Visualization: Config A vs Config A-prime
    # -------------------------------------------------------------------------
    print("\nGenerating comparison visualization (Config A vs Config A-prime)...")
    config_a_json = "results/v2/metrics/synthetic_sustained_anomaly_summary.json"
    with open(config_a_json, "r") as f:
        sum_a = pd.DataFrame(json.load(f))
    sum_aprime = pd.DataFrame(summary_list)

    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=True)

    # Plot 1: Config A (Self-Join)
    for r_val, color, marker in zip([1, 3, 5], ["#1f77b4", "#ff7f0e", "#2ca02c"], ["o", "s", "^"]):
        sub_a = sum_a[sum_a["repeats"] == r_val]
        axes[0].plot(sub_a["length_factor"], sub_a["roc_auc_mean"], f"-{marker}", color=color, lw=2.2, label=f"R = {r_val} Repeat(s)")
        axes[0].fill_between(
            sub_a["length_factor"],
            sub_a["roc_auc_mean"] - sub_a["roc_auc_std"],
            sub_a["roc_auc_mean"] + sub_a["roc_auc_std"],
            color=color, alpha=0.15
        )
    axes[0].axhline(0.5, color="gray", linestyle=":", label="Random Guess (0.50)")
    axes[0].set_xlabel("Anomaly Duration $L$ (multiples of $m$)", fontsize=11)
    axes[0].set_ylabel("ROC-AUC Score", fontsize=11)
    axes[0].set_title("Config A: Self-Join mSTAMP\n(Severe Collapse: Anomalies Turn into Motifs)", fontsize=12)
    axes[0].grid(True, alpha=0.3)
    axes[0].set_xscale("log", base=2)
    axes[0].set_xticks(length_factors)
    axes[0].get_xaxis().set_major_formatter(plt.ScalarFormatter())
    axes[0].legend(loc="lower left", fontsize=9)
    axes[0].set_ylim(-0.05, 1.05)

    # Plot 2: Config A-prime (Causal AB-Join)
    for r_val, color, marker in zip([1, 3, 5], ["#1f77b4", "#ff7f0e", "#2ca02c"], ["o", "s", "^"]):
        sub_ap = sum_aprime[sum_aprime["repeats"] == r_val]
        axes[1].plot(sub_ap["length_factor"], sub_ap["roc_auc_mean"], f"-{marker}", color=color, lw=2.2, label=f"R = {r_val} Repeat(s)")
        axes[1].fill_between(
            sub_ap["length_factor"],
            sub_ap["roc_auc_mean"] - sub_ap["roc_auc_std"],
            sub_ap["roc_auc_mean"] + sub_ap["roc_auc_std"],
            color=color, alpha=0.15
        )
    axes[1].axhline(0.5, color="gray", linestyle=":", label="Random Guess (0.50)")
    axes[1].set_xlabel("Anomaly Duration $L$ (multiples of $m$)", fontsize=11)
    axes[1].set_ylabel("ROC-AUC Score", fontsize=11)
    axes[1].set_title("Config A-prime: Causal AB-Join (Benign Reference)\n(Robust: Consistent High ROC-AUC Across All L & R)", fontsize=12)
    axes[1].grid(True, alpha=0.3)
    axes[1].set_xscale("log", base=2)
    axes[1].set_xticks(length_factors)
    axes[1].get_xaxis().set_major_formatter(plt.ScalarFormatter())
    axes[1].legend(loc="lower left", fontsize=9)

    plt.tight_layout()
    plt.savefig(OUTPUT_FIG, dpi=300)
    plt.close()
    print(f"Saved comparison figure to {OUTPUT_FIG}")

if __name__ == "__main__":
    run_aprime_synthetic_suite()

