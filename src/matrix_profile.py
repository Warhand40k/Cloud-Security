"""
Multidimensional Matrix Profile module using STUMPY.
Computes mSTAMP matrix profiles across multidimensional feature streams.
"""

import numpy as np
import stumpy
from typing import Tuple, Optional

def compute_multidimensional_mp(
    X: np.ndarray,
    m: int,
    normalize: bool = True
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Compute multidimensional matrix profile using STUMPY mstump.
    
    Args:
        X: 2D array of shape (n_samples, n_features).
        m: Subsequence window length (must be >= 3 and < n_samples).
        normalize: Whether to z-normalize subsequences.
        
    Returns:
        mps: Multi-dimensional matrix profile array of shape (n_features, n_samples - m + 1).
             mps[k] represents the (k+1)-dimensional matrix profile.
        indices: Nearest neighbor indices of shape (n_features, n_samples - m + 1).
    """
    if X.ndim != 2:
        raise ValueError(f"Expected 2D array for X (n_samples, n_features), got shape {X.shape}")
    
    n_samples, n_features = X.shape
    if m < 3:
        raise ValueError(f"Window length m must be >= 3, got {m}")
    if m >= n_samples:
        raise ValueError(f"Window length m ({m}) must be smaller than sequence length ({n_samples})")

    # STUMPY expects shape (n_features, n_samples)
    T = X.T.astype(np.float64)
    
    # Check for NaN / Inf
    if not np.all(np.isfinite(T)):
        raise ValueError("Input time series contains NaN or infinite values")

    mps, indices = stumpy.mstump(T, m=m, normalize=normalize)
    return mps, indices

