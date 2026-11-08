"""
Kneedle dimension selection module.
Selects the optimal multidimensional subspace from the matrix profile curve.
Follows the paper's specification using kneed over per-dimension maximum profile values.
"""

import numpy as np
from kneed import KneeLocator
from typing import Tuple, List, Optional, Dict

def find_knee_dimension(
    mps: np.ndarray,
    online: bool = True,
    metric: str = "max",
    S: float = 1.0
) -> Tuple[int, Dict]:
    """
    Find optimal knee dimension from multidimensional matrix profile.
    
    Args:
        mps: Multi-dimensional matrix profile array of shape (n_features, L).
        online: Whether to use online mode in KneeLocator (as evaluated in paper).
        metric: Aggregation per dimension: 'max' (default in paper), 'mean', or 'median'.
        S: Sensitivity parameter for KneeLocator.
        
    Returns:
        k_star: Chosen dimension (1-indexed, between 1 and n_features).
        info: Dictionary containing x, y curve, detected knee, and curvature stats.
    """
    n_features, L = mps.shape
    x = list(range(1, n_features + 1))
    
    if metric == "max":
        y = [float(np.max(mps[k])) for k in range(n_features)]
    elif metric == "mean":
        y = [float(np.mean(mps[k])) for k in range(n_features)]
    elif metric == "median":
        y = [float(np.median(mps[k])) for k in range(n_features)]
    else:
        raise ValueError(f"Unknown metric: {metric}")

    # Distance in multidimensional matrix profile increases with dimension
    kneedle = KneeLocator(
        x,
        y,
        curve="concave",
        direction="increasing",
        online=online,
        S=S
    )

    knee = kneedle.knee
    if knee is None:
        # Fallback if no knee detected: choose dimension with max second derivative or middle
        knee = int(np.argmax(np.gradient(np.gradient(y))) + 1) if n_features > 2 else 1
        knee = max(1, min(knee, n_features))

    info = {
        "x": x,
        "y": y,
        "knee": knee,
        "online": online,
        "metric": metric,
        "all_knees": list(kneedle.all_knees) if hasattr(kneedle, "all_knees") and kneedle.all_knees else [knee]
    }
    return knee, info

