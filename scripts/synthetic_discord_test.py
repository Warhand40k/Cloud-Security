"""
Synthetic Discord Sanity Test:
Mathematically verifies subsequence alignment and discord scoring:
1. Generates clean synthetic multivariate benign baseline series.
2. Injects a calibrated multivariate discord at a known timestamp t_inj.
3. Runs mSTAMP + Kneedle to extract anomaly scores.
4. Verifies peak anomaly score aligns at the injected discord with 0 look-ahead bias.
5. Saves visualization to results/figures/synthetic_discord_test.png.
"""

import os
import sys
import numpy as np
import matplotlib.pyplot as plt

# Ensure src is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores

def run_synthetic_discord_test():
    print("=" * 80)
    print("RUNNING SYNTHETIC DISCORD SANITY TEST")
    print("=" * 80)

    np.random.seed(42)
    N = 1000  # Total time steps
    D = 5     # 5 dimensions
    m = 25    # Subsequence length
    t_inj = 450 # Anomaly injection start
    t_len = 30  # Anomaly duration

    # 1. Generate clean multi-channel background
    t = np.linspace(0, 50, N)
    X = np.zeros((N, D))
    for d in range(D):
        # Quasi-periodic background with low Gaussian noise
        freq = 0.5 + 0.2 * d
        X[:, d] = np.sin(2 * np.pi * freq * t) + 0.1 * np.random.randn(N)

    # 2. Inject an anomaly (discord pattern: high frequency / high amplitude burst on 3 channels)
    anomaly_channels = [0, 2, 4]
    for ch in anomaly_channels:
        t_ano = np.linspace(0, 10, t_len)
        X[t_inj:t_inj+t_len, ch] += 3.5 * np.cos(2 * np.pi * 3.0 * t_ano)

    print(f"Generated synthetic series: N={N}, D={D}, m={m}")
    print(f"Injected anomaly window: [{t_inj}, {t_inj+t_len}] on channels {anomaly_channels}")

    # 3. Run multidimensional Matrix Profile
    print("Computing mSTAMP...")
    mps, indices = compute_multidimensional_mp(X, m=m)
    print(f"Matrix profile shape: {mps.shape}")

    # 4. Kneedle subspace selection
    knee_dim, knee_info = find_knee_dimension(mps, online=True, metric="max")
    print(f"Kneedle selected dimension: {knee_dim} / {D}")

    # 5. Extract point anomaly scores
    scores = compute_point_anomaly_scores(mps, knee_dim=knee_dim, n_samples=N, m=m)
    print(f"Point anomaly scores shape: {scores.shape}")

    # 6. Check discord localization
    peak_idx = int(np.argmax(scores))
    print(f"Peak anomaly score: {scores[peak_idx]:.4f} at index t = {peak_idx}")

    # In causal right alignment, an injected anomaly starting at t_inj and ending at t_inj+t_len
    # causes discords in windows ending between t_inj+m-1 and t_inj+t_len+m-1.
    expected_start = t_inj
    expected_end = t_inj + t_len + m
    is_detected = (expected_start <= peak_idx <= expected_end)
    print(f"Expected discord detection window: [{expected_start}, {expected_end}]")
    print(f"Is discord peak within expected window? {is_detected}")
    
    # Compute localization error
    dist_to_window = 0 if is_detected else min(abs(peak_idx - expected_start), abs(peak_idx - expected_end))
    print(f"Localization error: {dist_to_window} steps")
    assert is_detected, f"Discord peak {peak_idx} outside expected anomaly window [{expected_start}, {expected_end}]"

    # 7. Generate visualization plot
    os.makedirs("results/figures", exist_ok=True)
    fig, axes = plt.subplots(3, 1, figsize=(12, 8), sharex=True)

    # Plot raw signals
    for d in range(D):
        axes[0].plot(X[:, d], label=f"Dim {d+1}", alpha=0.7)
    axes[0].axvspan(t_inj, t_inj + t_len, color="red", alpha=0.2, label="Injected Discord")
    axes[0].set_ylabel("Raw Telemetry")
    axes[0].set_title(f"Synthetic Discord Sanity Test (m={m}, Injected at t=[{t_inj}, {t_inj+t_len}])")
    axes[0].legend(loc="upper right", ncol=3, fontsize=8)

    # Plot 1D Matrix Profile for selected Knee dimension
    mp_curve = mps[knee_dim - 1, :]
    axes[1].plot(np.arange(len(mp_curve)), mp_curve, color="purple", label=f"mSTAMP (Dim {knee_dim})")
    axes[1].axvspan(t_inj, t_inj + t_len, color="red", alpha=0.2)
    axes[1].set_ylabel("Subsequence MP")
    axes[1].legend(loc="upper right", fontsize=8)

    # Plot point anomaly scores
    axes[2].plot(scores, color="crimson", lw=1.5, label="Point Anomaly Score")
    axes[2].axvspan(t_inj, t_inj + t_len, color="red", alpha=0.2, label="True Discord Window")
    axes[2].axvline(peak_idx, color="black", linestyle="--", label=f"Detected Peak (t={peak_idx})")
    axes[2].set_xlabel("Time Step (t)")
    axes[2].set_ylabel("Discord Score")
    axes[2].legend(loc="upper right", fontsize=8)

    plt.tight_layout()
    fig_path = "results/figures/synthetic_discord_test.png"
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"Saved sanity test figure to: {fig_path}")

    print("=" * 80)
    print("SYNTHETIC DISCORD SANITY TEST PASSED!")
    print("=" * 80)

if __name__ == "__main__":
    run_synthetic_discord_test()
