"""
EVT Calibration Experiment:
Evaluates whether EVT (Peaks-Over-Threshold with GPD) is well-calibrated on held-out benign data.
Fits POT on benign training history with >= 30 tail excesses and sweeps target risk p in [1e-3, 1e-1].
Measures empirical false-alarm rate (FAR) on held-out benign network traffic.
Generates calibration plot and saved metrics.
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
from src.causal_ab_scorer import CausalABScorer
from src.adaptive_threshold import EVTThreshold
from sklearn.preprocessing import StandardScaler

FIGURES_DIR = "results/v2/figures"
METRICS_DIR = "results/v2/metrics"
os.makedirs(FIGURES_DIR, exist_ok=True)
os.makedirs(METRICS_DIR, exist_ok=True)

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

def run_evt_calibration():
    print("=" * 80)
    print("RUNNING EVT CALIBRATION ON HELD-OUT BENIGN TELEMETRY")
    print("=" * 80)

    # Load CSE-CIC-IDS2018 Thursday windows [0:250] (pure benign)
    df_thu = pd.read_parquet("data/processed/csecicids2018_thursday_60s_any_attack.parquet")
    raw_benign = df_thu[FEATURE_COLS_CSE].iloc[:250].values.astype(float)
    raw_benign = np.nan_to_num(raw_benign)
    scaler = StandardScaler()
    X_benign = scaler.fit_transform(raw_benign)

    # 1. Config A (Self-Join Scorer):
    # Split into Fit (150 windows) and Held-out Benign (100 windows)
    X_fit_a = X_benign[:150]
    X_heldout_a = X_benign[150:250]

    mps_fit, _ = compute_multidimensional_mp(X_fit_a, m=10)
    knee_a, _ = find_knee_dimension(mps_fit, online=True, metric="max")
    scores_fit_a = compute_point_anomaly_scores(mps_fit, knee_dim=knee_a, n_samples=len(X_fit_a), m=10)

    mps_held, _ = compute_multidimensional_mp(X_heldout_a, m=10)
    scores_heldout_a = compute_point_anomaly_scores(mps_held, knee_dim=knee_a, n_samples=len(X_heldout_a), m=10)

    # 2. Config A-prime (Causal AB-Join Scorer):
    # Reference library: first 100 windows
    # Benign Fit set: windows 100 to 180 (80 windows scored against reference)
    # Benign Held-out set: windows 180 to 250 (70 windows scored against reference)
    scorer_aprime = CausalABScorer(m=10, knee_dim=3)
    scorer_aprime.fit(X_benign[:100])
    scores_fit_aprime = scorer_aprime.score(X_benign[100:180])
    scores_heldout_aprime = scorer_aprime.score(X_benign[180:250])

    risk_grid = [
        0.10, 0.08, 0.06, 0.05, 0.04, 0.03, 0.02, 0.015,
        0.01, 0.008, 0.005, 0.003, 0.002, 0.001
    ]

    records = []

    print("\nEvaluating Config A (Self-Join) EVT Calibration:")
    for p in risk_grid:
        evt = EVTThreshold(q=0.80, risk_p=p, min_excesses=30)
        evt.fit(scores_fit_a)
        emp_far = float((scores_heldout_a >= evt.threshold_).mean())
        records.append({
            "Config": "Config A (Self-Join)",
            "Target_Risk_p": p,
            "Fitted_Threshold": float(evt.threshold_),
            "Quantile_u": float(evt.u_),
            "Excesses_Count": int(evt.n_excesses_),
            "GPD_Gamma": float(evt.shape_gamma_),
            "GPD_Sigma": float(evt.scale_sigma_),
            "Empirical_FAR": emp_far,
            "Heldout_N": len(scores_heldout_a)
        })
        print(f"  Target p={p:6.4f} | Threshold={evt.threshold_:.4f} | Excesses={evt.n_excesses_} | Empirical FAR={emp_far:.4f}")

    print("\nEvaluating Config A-prime (Causal AB-Join) EVT Calibration:")
    for p in risk_grid:
        evt = EVTThreshold(q=0.60, risk_p=p, min_excesses=30)
        evt.fit(scores_fit_aprime)
        emp_far = float((scores_heldout_aprime >= evt.threshold_).mean())
        records.append({
            "Config": "Config A-prime (Causal AB-Join)",
            "Target_Risk_p": p,
            "Fitted_Threshold": float(evt.threshold_),
            "Quantile_u": float(evt.u_),
            "Excesses_Count": int(evt.n_excesses_),
            "GPD_Gamma": float(evt.shape_gamma_),
            "GPD_Sigma": float(evt.scale_sigma_),
            "Empirical_FAR": emp_far,
            "Heldout_N": len(scores_heldout_aprime)
        })
        print(f"  Target p={p:6.4f} | Threshold={evt.threshold_:.4f} | Excesses={evt.n_excesses_} | Empirical FAR={emp_far:.4f}")

    df_cal = pd.DataFrame(records)
    csv_out = os.path.join(METRICS_DIR, "evt_calibration.csv")
    json_out = os.path.join(METRICS_DIR, "evt_calibration.json")
    df_cal.to_csv(csv_out, index=False)
    df_cal.to_json(json_out, orient="records", indent=2)
    print(f"\nSaved calibration records to {csv_out} and {json_out}")

    # Generate Calibration Plot
    plt.figure(figsize=(8, 6))
    
    # Diagonal ideal line
    diag_vals = np.logspace(-3, -1, 100)
    plt.plot(diag_vals, diag_vals, "k--", lw=1.5, label="Perfect Calibration (y = x)")

    df_a = df_cal[df_cal["Config"] == "Config A (Self-Join)"]
    df_aprime = df_cal[df_cal["Config"] == "Config A-prime (Causal AB-Join)"]

    plt.plot(
        df_a["Target_Risk_p"], df_a["Empirical_FAR"],
        "o-", color="#d95f02", lw=2, ms=6, label=f"Config A (Self-Join, excesses={df_a['Excesses_Count'].iloc[0]})"
    )
    plt.plot(
        df_aprime["Target_Risk_p"], df_aprime["Empirical_FAR"],
        "s-", color="#2b5c8f", lw=2, ms=6, label=f"Config A-prime (Causal AB, excesses={df_aprime['Excesses_Count'].iloc[0]})"
    )

    plt.xscale("log")
    plt.yscale("log")
    plt.xlim(8e-4, 1.5e-1)
    plt.ylim(8e-4, 3e-1)
    plt.xlabel("Nominal Target Risk Probability p (Theoretical)", fontsize=11)
    plt.ylabel("Empirical False-Alarm Rate on Held-Out Benign Data", fontsize=11)
    plt.title("EVT (Peaks-Over-Threshold) Calibration Curve on Network Traffic", fontsize=12, fontweight="bold")
    plt.grid(True, which="both", ls=":", alpha=0.6)
    plt.legend(frameon=True, loc="upper left")
    plt.tight_layout()

    fig_out = os.path.join(FIGURES_DIR, "evt_calibration_plot.png")
    plt.savefig(fig_out, dpi=300)
    plt.close()
    print(f"Saved calibration figure to {fig_out}")

if __name__ == "__main__":
    run_evt_calibration()

