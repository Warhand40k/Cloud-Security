"""
Adaptive thresholding module for network anomaly detection.
Implements:
1. Rolling Median / MAD (Median Absolute Deviation) threshold (Config B1)
2. EVT Peaks-Over-Threshold (POT) extreme value theory threshold (Config B2)
"""

import numpy as np
import pandas as pd
from typing import Tuple, Optional, Dict, List
from scipy.stats import genpareto

class MADThreshold:
    """
    Config B1: Median Absolute Deviation (MAD) adaptive threshold.
    Threshold = median + c * (1.4826 * MAD)
    """
    def __init__(self, c: float = 3.0, rolling_window: Optional[int] = None):
        self.c = c
        self.rolling_window = rolling_window
        self.median_ = 0.0
        self.mad_ = 0.0
        self.threshold_ = 0.0

    def fit(self, scores: np.ndarray):
        """Fit static baseline threshold on normal / validation scores."""
        clean_scores = scores[np.isfinite(scores)]
        if len(clean_scores) == 0:
            self.threshold_ = 1.0
            return self
        self.median_ = float(np.median(clean_scores))
        deviations = np.abs(clean_scores - self.median_)
        self.mad_ = float(np.median(deviations))
        # 1.4826 makes MAD an asymptotically unbiased estimator of standard deviation
        sigma = 1.4826 * self.mad_
        if sigma < 1e-8:
            sigma = float(np.std(clean_scores)) + 1e-6
        self.threshold_ = self.median_ + self.c * sigma
        return self

    def predict(self, scores: np.ndarray) -> np.ndarray:
        """
        Produce binary predictions.
        If rolling_window is specified, computes causal rolling MAD.
        """
        if self.rolling_window is None:
            return (scores >= self.threshold_).astype(int)
        else:
            s_series = pd.Series(scores)
            roll_med = s_series.rolling(self.rolling_window, min_periods=1).median()
            roll_dev = (s_series - roll_med).abs()
            roll_mad = roll_dev.rolling(self.rolling_window, min_periods=1).median()
            roll_sigma = 1.4826 * roll_mad
            roll_thresh = roll_med + self.c * roll_sigma
            roll_thresh = roll_thresh.fillna(self.threshold_)
            return (scores >= roll_thresh.values).astype(int)

class EVTThreshold:
    """
    Config B2: Extreme Value Theory (EVT) Peaks-Over-Threshold (POT).
    Fits a Generalized Pareto Distribution (GPD) on extreme score excesses
    above a high quantile u to determine a calibrated threshold for target risk probability p.
    
    Robust enhancements:
    - Adaptive tail quantile selection if sample size is moderate/small.
    - Risk probability capped by sample size support (p >= 1 / (2*N)).
    - GPD shape parameter regularized to [-0.5, 0.5] for stable extrapolation.
    """
    def __init__(self, q: float = 0.85, risk_p: float = 1e-2, min_excesses: int = 30):
        self.q = q
        self.risk_p = risk_p
        self.min_excesses = min_excesses
        self.u_ = 0.0
        self.effective_q_ = q
        self.n_excesses_ = 0
        self.shape_gamma_ = 0.0
        self.scale_sigma_ = 0.0
        self.threshold_ = 0.0

    def fit(self, scores: np.ndarray):
        """
        Fit POT on benign history scores.
        Ensures >= min_excesses (default 30) for reliable GPD fitting.
        """
        clean_scores = scores[np.isfinite(scores)]
        n = len(clean_scores)
        if n == 0:
            self.threshold_ = 1.0
            return self

        # Cap risk probability by what the sample size can theoretically support
        min_supportable_p = max(1e-4, 1.0 / (2.0 * n))
        effective_p = max(self.risk_p, min_supportable_p)

        # Adaptively adjust quantile q if needed to ensure at least min_excesses (e.g. 30)
        effective_q = self.q
        self.u_ = float(np.quantile(clean_scores, effective_q))
        excesses = clean_scores[clean_scores > self.u_] - self.u_
        n_u = len(excesses)

        # If too few excesses, adjust q downwards step-by-step
        while n_u < self.min_excesses and effective_q > 0.50 and n >= self.min_excesses:
            effective_q -= 0.05
            self.u_ = float(np.quantile(clean_scores, effective_q))
            excesses = clean_scores[clean_scores > self.u_] - self.u_
            n_u = len(excesses)

        self.effective_q_ = effective_q
        self.n_excesses_ = n_u

        if n_u < 5:
            # Fallback to empirical quantile if sample is too tiny
            safe_q = min(1.0 - effective_p, 0.99)
            self.threshold_ = float(np.quantile(clean_scores, safe_q))
            return self

        # Fit GPD: genpareto(c, loc, scale) where c = gamma (shape)
        try:
            params = genpareto.fit(excesses, floc=0)
            shape_gamma, _, scale_sigma = params
            # Clamp shape to [-0.5, 0.5] for statistical stability
            self.shape_gamma_ = float(np.clip(shape_gamma, -0.5, 0.5))
            self.scale_sigma_ = max(1e-6, float(scale_sigma))

            # POT theoretical quantile formula
            # z_q = u + (sigma / gamma) * [ ( (n / n_u) * p )^(-gamma) - 1 ]
            if abs(self.shape_gamma_) < 1e-4:
                # Gumbel limit (gamma -> 0)
                arg = max(1e-6, (n * effective_p) / n_u)
                self.threshold_ = self.u_ - self.scale_sigma_ * np.log(arg)
            else:
                ratio = max(1e-4, (n_u / (n * effective_p)))
                extrapolation = (ratio ** self.shape_gamma_ - 1.0) / self.shape_gamma_
                self.threshold_ = self.u_ + self.scale_sigma_ * extrapolation

            # Guard against NaN/inf or threshold below quantile u
            if not np.isfinite(self.threshold_) or self.threshold_ < self.u_:
                self.threshold_ = self.u_ + self.scale_sigma_
            self.threshold_ = max(self.threshold_, self.u_)

        except Exception:
            # Robust fallback to empirical quantile
            self.threshold_ = float(np.quantile(clean_scores, 1.0 - effective_p))

        return self

    def predict(self, scores: np.ndarray) -> np.ndarray:
        return (scores >= self.threshold_).astype(int)
