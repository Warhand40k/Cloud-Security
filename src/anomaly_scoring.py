"""
Anomaly scoring and alignment module.
Extracts discord scores from the matrix profile and aligns them to original time series points.
"""

import numpy as np
from typing import Tuple, Optional, Literal

AlignmentMethod = Literal["causal", "max_coverage", "mean_coverage", "start"]

def align_subsequence_scores(
    subseq_scores: np.ndarray,
    n_samples: int,
    m: int,
    method: AlignmentMethod = "causal"
) -> np.ndarray:
    """
    Align subsequence-level matrix profile scores of length L = n_samples - m + 1
    to full sequence of length n_samples.
    
    Args:
        subseq_scores: 1D array of length (n_samples - m + 1).
        n_samples: Total number of points/windows in the original sequence.
        m: Window length used for subsequence computation.
        method:
            - 'causal': Right-aligned (point t receives score of subsequence ending at t).
                        Strictly causal, zero look-ahead bias.
            - 'start': Left-aligned (point t receives score of subsequence starting at t).
            - 'max_coverage': Point t receives maximum score of all subsequences covering t.
            - 'mean_coverage': Point t receives average score of all subsequences covering t.
            
    Returns:
        point_scores: 1D array of length n_samples.
    """
    L = len(subseq_scores)
    expected_L = n_samples - m + 1
    if L != expected_L:
        raise ValueError(f"Expected subseq_scores length {expected_L}, got {L}")

    point_scores = np.zeros(n_samples, dtype=np.float64)

    if method == "causal":
        # Point t (where t >= m - 1) receives score of subsequence ending at t (start index t - m + 1)
        point_scores[m - 1:] = subseq_scores
        # Pad initial unobserved window points with the first available score
        point_scores[:m - 1] = subseq_scores[0]

    elif method == "start":
        point_scores[:L] = subseq_scores
        point_scores[L:] = subseq_scores[-1]

    elif method == "max_coverage":
        # For each point, max over all covering subsequences
        point_scores[:] = -np.inf
        for i, score in enumerate(subseq_scores):
            point_scores[i:i + m] = np.maximum(point_scores[i:i + m], score)

    elif method == "mean_coverage":
        counts = np.zeros(n_samples, dtype=np.float64)
        sums = np.zeros(n_samples, dtype=np.float64)
        for i, score in enumerate(subseq_scores):
            sums[i:i + m] += score
            counts[i:i + m] += 1.0
        point_scores = sums / np.maximum(counts, 1.0)

    else:
        raise ValueError(f"Unknown alignment method: {method}")

    return point_scores

def compute_point_anomaly_scores(
    mps: np.ndarray,
    knee_dim: int,
    n_samples: int,
    m: int,
    alignment: AlignmentMethod = "causal"
) -> np.ndarray:
    """
    Extract discord scores for the chosen knee dimension and align to original sequence.
    """
    k_idx = knee_dim - 1
    if k_idx < 0 or k_idx >= mps.shape[0]:
        raise IndexError(f"Knee dimension {knee_dim} out of bounds for mps shape {mps.shape}")
    
    subseq_scores = mps[k_idx]
    return align_subsequence_scores(subseq_scores, n_samples=n_samples, m=m, method=alignment)

