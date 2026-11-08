"""
Adaptive thresholding module for network anomaly detection.
Implements:
1. Rolling Median / MAD (Median Absolute Deviation) threshold (Config B1)
2. EVT Peaks-Over-Threshold (POT) extreme value theory threshold (Config B2)
"""

import numpy as np
import pandas as pd
from typing import Tuple, Optional, Dict
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
            # Causal rolling median and MAD
            s_series = pd.Series(scores)
            roll_med = s_series.rolling(self.rolling_window, min_periods=1).median()
            roll_dev = (s_series - roll_med).abs()
            roll_mad = roll_dev.rolling(self.rolling_window, min_periods=1).median()
            roll_sigma = 1.4826 * roll_mad
            roll_thresh = roll_med + self.c * roll_sigma
            # Fill early points with fitted static threshold
            roll_thresh = roll_thresh.fillna(self.threshold_)
            return (scores >= roll_thresh.values).astype(int)

class EVTThreshold:
    """
    Config B2: Extreme Value Theory (EVT) Peaks-Over-Threshold (POT).
    Fits a Generalized Pareto Distribution (GPD) on extreme score excesses
    to determine a calibrated threshold for target risk probability p.
    """
    def __init__(self, q: float = 0.95, risk_p: float = 1e-3):
        self.q = q
        self.risk_p = risk_p
        self.u_ = 0.0
        self.shape_gamma_ = 0.0
        self.scale_sigma_ = 0.0
        self.threshold_ = 0.0

    def fit(self, scores: np.ndarray):
        """
        Fit POT on validation / benign scores.
        """
        clean_scores = scores[np.isfinite(scores)]
        n = len(clean_scores)
        self.u_ = float(np.quantile(clean_scores, self.q))
        
        excesses = clean_scores[clean_scores > self.u_] - self.u_
        n_u = len(excesses)

        if n_u < 5:
            # Fallback if too few excesses
            self.threshold_ = float(np.quantile(clean_scores, 1.0 - self.risk_p))
            return self

        # Fit GPD: scipy parameterization genpareto(c, loc, scale) where c = gamma
        params = genpareto.fit(excesses, floc=0)
        self.shape_gamma_, _, self.scale_sigma_ = params

        # Theoretical quantile formula for POT
        # z_q = u + (sigma / gamma) * [ ( (n / n_u) * risk_p )^(-gamma) - 1 ]
        if np.isclose(self.shape_gamma_, 0.0):
            # Gumbel domain (gamma -> 0): z_q = u - sigma * ln( (n * risk_p) / n_u )
            self.threshold_ = self.u_ - self.scale_sigma_ * np.log((n * self.risk_p) / n_u)
        else:
            ratio = (n_u / (n * self.risk_p))
            self.threshold_ = self.u_ + (self.scale_sigma_ / self.shape_gamma_) * (ratio ** self.shape_gamma_ - 1.0)

        # Sanity floor: threshold should never be below initial quantile u
        self.threshold_ = max(self.threshold_, self.u_)
        return self

    def predict(self, scores: np.ndarray) -> np.ndarray:
        return (scores >= self.threshold_).astype(int)

