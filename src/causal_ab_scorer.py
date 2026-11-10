"""
Causal AB-Join Matrix Profile Scorer (Config A-prime).
Evaluates an incoming/evaluation time series A against a historical
benign reference time series B.

Properties:
1. Strictly causal: nearest neighbors are queried ONLY from B (the benign training history).
   No future data in A is ever accessed.
2. Multidimensional combination: Per-dimension 1D distances are computed via stumpy.stump(A, m, B).
   For each subsequence i, distances are sorted in ascending order and the mean of the k smallest
   is computed, exactly mirroring mSTAMP.
3. Subspace selection k*: Selected via Kneedle on training/validation reference data only.
"""

import numpy as np
import stumpy
from typing import Tuple, Optional, Dict
from src.kneedle import find_knee_dimension

def compute_multidimensional_ab_profile(
    A: np.ndarray,
    B: np.ndarray,
    m: int,
    normalize: bool = True
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Computes multidimensional Matrix Profile for series A with reference to B.
    
    Args:
        A: Evaluation series array of shape (T_A, D).
        B: Benign reference history array of shape (T_B, D).
        m: Subsequence window length.
        normalize: Whether to z-normalize subsequences.
        
    Returns:
        mps: Combined multidimensional matrix profile array of shape (D, L_A),
             where L_A = T_A - m + 1. mps[k-1, :] is the mean of the k smallest distances.
        per_dim_profiles: Raw 1D profile distances of shape (D, L_A).
    """
    T_A, D = A.shape
    T_B, D_B = B.shape
    assert D == D_B, f"Feature dimensions must match: A has {D}, B has {D_B}"
    assert T_A >= m and T_B >= m, f"Series lengths must be >= m: T_A={T_A}, T_B={T_B}, m={m}"
    
    L_A = T_A - m + 1
    per_dim_profiles = np.zeros((D, L_A), dtype=np.float64)
    
    for d in range(D):
        col_A = np.ascontiguousarray(A[:, d], dtype=np.float64)
        col_B = np.ascontiguousarray(B[:, d], dtype=np.float64)
        
        # stumpy.stump with T_B computes distance from each subsequence in A to its NN in B
        stump_out = stumpy.stump(T_A=col_A, m=m, T_B=col_B, ignore_trivial=False, normalize=normalize)
        per_dim_profiles[d, :] = stump_out[:, 0]
        
    # Multidimensional combination mirroring mSTAMP:
    # For each subsequence index i, sort per-dimension distances ascendingly
    # and compute cumulative mean for k = 1..D
    sorted_profiles = np.sort(per_dim_profiles, axis=0) # shape (D, L_A)
    mps = np.zeros((D, L_A), dtype=np.float64)
    for k in range(1, D + 1):
        mps[k - 1, :] = np.mean(sorted_profiles[:k, :], axis=0)
        
    return mps, per_dim_profiles

def compute_causal_point_scores(
    mps: np.ndarray,
    knee_dim: int,
    n_samples: int,
    m: int
) -> np.ndarray:
    """
    Computes causal point anomaly scores using right-alignment.
    For time step t >= m - 1, the anomaly score is mps[knee_dim - 1, t - m + 1].
    For t < m - 1, causally pads with the first available score.
    
    Args:
        mps: Multidimensional matrix profile of shape (D, L_A).
        knee_dim: Chosen subspace dimension k (1-indexed).
        n_samples: Total sample length T_A.
        m: Subsequence length.
        
    Returns:
        scores: 1D array of length n_samples with causal point anomaly scores.
    """
    L = mps.shape[1]
    target_profile = mps[knee_dim - 1, :]
    
    scores = np.zeros(n_samples, dtype=np.float64)
    # Pre-fill initial boundary steps before first complete window finishes
    scores[: m - 1] = target_profile[0]
    # Causal right alignment: window ending at t corresponds to profile index t - m + 1
    scores[m - 1 : m - 1 + L] = target_profile
    
    # If any trailing steps exist beyond m - 1 + L, pad with last score
    if m - 1 + L < n_samples:
        scores[m - 1 + L :] = target_profile[-1]
        
    return scores

class CausalABScorer:
    """
    Config A-prime Scorer.
    Maintains a benign reference history B (fitted on training data).
    Scores any evaluation stream A causally with zero look-ahead bias.
    """
    def __init__(self, m: int = 25, knee_dim: Optional[int] = None, normalize: bool = True):
        self.m = m
        self.knee_dim = knee_dim
        self.normalize = normalize
        self.B_ref_ = None
        
    def fit(self, B: np.ndarray, kneedle_mps: Optional[np.ndarray] = None):
        """
        Store benign reference history B.
        If knee_dim is not specified, finds k* on B reference data.
        """
        self.B_ref_ = np.ascontiguousarray(B, dtype=np.float64)
        if self.knee_dim is None:
            if kneedle_mps is not None:
                self.knee_dim, _ = find_knee_dimension(kneedle_mps, online=True, metric="max")
            else:
                # Find knee on self-join of B
                from src.matrix_profile import compute_multidimensional_mp
                mps_B, _ = compute_multidimensional_mp(self.B_ref_, m=self.m, normalize=self.normalize)
                self.knee_dim, _ = find_knee_dimension(mps_B, online=True, metric="max")
        return self

    def score(self, A: np.ndarray) -> np.ndarray:
        """
        Score evaluation series A against stored reference history B.
        Zero future data in A is used; each subsequence in A queries only B.
        """
        if self.B_ref_ is None:
            raise ValueError("CausalABScorer must be fitted with benign reference B before scoring.")
            
        A_arr = np.ascontiguousarray(A, dtype=np.float64)
        mps, _ = compute_multidimensional_ab_profile(A=A_arr, B=self.B_ref_, m=self.m, normalize=self.normalize)
        scores = compute_causal_point_scores(mps, knee_dim=self.knee_dim, n_samples=len(A_arr), m=self.m)
        return scores

