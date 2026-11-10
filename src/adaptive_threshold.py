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
    def __init__(self, c: float = 3.0, rolling_window: Optional[int] = None, eps: float = 1e-6):
        self.c = c
        self.rolling_window = rolling_window
        self.eps = eps
        self.median_ = 0.0
        self.mad_ = 0.0
        self.threshold_ = 0.0
        self.zero_mad_fraction_ = 0.0

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
        sigma = 1.4826 * max(self.mad_, self.eps)
        if sigma < self.eps:
            sigma = float(np.std(clean_scores)) + self.eps
        self.threshold_ = self.median_ + self.c * sigma
        return self

    def predict(self, scores: np.ndarray) -> np.ndarray:
        """
        Produce binary predictions.
        If rolling_window is specified, computes causal rolling MAD.
        """
        if self.rolling_window is None:
            self.zero_mad_fraction_ = 1.0 if self.mad_ == 0.0 else 0.0
            return (scores >= self.threshold_).astype(int)
        else:
            s_series = pd.Series(scores)
            roll_med = s_series.rolling(self.rolling_window, min_periods=1).median()
            roll_dev = (s_series - roll_med).abs()
            roll_mad = roll_dev.rolling(self.rolling_window, min_periods=1).median()
            
            # Log fraction of windows where MAD == 0
            self.zero_mad_fraction_ = float(np.mean(roll_mad.values == 0.0))
            
            # Epsilon floor to prevent division/multiplication blow-ups on flat signals
            roll_mad_floored = np.maximum(roll_mad.values, self.eps)
            roll_sigma = 1.4826 * roll_mad_floored
            roll_thresh = roll_med.values + self.c * roll_sigma
            roll_thresh = np.where(np.isnan(roll_thresh), self.threshold_, roll_thresh)
            return (scores >= roll_thresh).astype(int)

def calibrate_benign_quantile_threshold(
    val_scores: np.ndarray,
    y_val: np.ndarray,
    alpha: float = 0.05
) -> float:
    """
    Primary threshold rule for score-based detectors:
    Chooses the decision threshold on BENIGN validation scores such that FAR <= alpha.
    No F1 optimization or attack labels are used.
    """
    benign_mask = (y_val == 0)
    benign_scores = val_scores[benign_mask] if np.any(benign_mask) else val_scores
    clean_scores = benign_scores[np.isfinite(benign_scores)]
    if len(clean_scores) == 0:
        return 0.0

    # Theoretical (1 - alpha) quantile
    th = float(np.quantile(clean_scores, 1.0 - alpha))
    
    # Check empirical FAR on benign validation
    emp_far = float(np.mean(clean_scores >= th))
    if emp_far > alpha:
        # Ties/point mass causing FAR to exceed alpha: step to next distinct score
        higher_scores = clean_scores[clean_scores > th]
        if len(higher_scores) > 0:
            th = float(np.min(higher_scores))
        else:
            th = th + 1e-6
    return th

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


class ConformalQuantileThreshold:
    """
    Stage 2: Split-Conformal Anomaly Threshold Calibrator.
    
    Provides finite-sample false alarm rate (FAR) guarantees under exchangeability:
        P(Score_test >= tau_alpha | Benign) <= alpha
        
    Implements:
    1. Static Split-Conformal:
       Calibrates threshold tau_alpha = Quantile(S_cal, ceil((n+1)*(1-alpha)) / n).
       Computes exact conformal p-values:
           p(s) = (1 + sum(S_cal >= s)) / (n + 1)
       Alert flagged if p(s) <= alpha.
       
    2. Rolling Split-Conformal:
       Maintains a causal sliding window of recent benign calibration scores of size W.
       Adapts dynamically to diurnal shifts and gradual drift.
       
    3. Adaptive Conformal Inference (ACI; Gibbs & Candès 2021):
       Dynamically updates the effective nominal risk level:
           alpha_{t+1} = alpha_t + gamma * (alpha - err_t)
       guaranteeing long-run average coverage even under arbitrary non-exchangeable drift.
       
    4. Point-mass tie adjustment:
       Ensures that empirical point masses (e.g. 0-inflated scores) do not violate FAR <= alpha.
    """
    def __init__(
        self,
        alpha: float = 0.05,
        eps: float = 1e-6
    ):
        self.alpha = alpha
        self.eps = eps
        self.cal_scores_: np.ndarray = np.array([])
        self.n_cal_: int = 0
        self.threshold_: float = 0.0
        self.nominal_q_: float = 1.0 - alpha

    def fit(self, cal_scores: np.ndarray, y_cal: Optional[np.ndarray] = None) -> "ConformalQuantileThreshold":
        """
        Fit split-conformal calibrator on calibration scores.
        If y_cal is provided, filters strictly to benign calibration instances (y_cal == 0).
        """
        if y_cal is not None:
            benign_mask = (y_cal == 0)
            clean = cal_scores[benign_mask] if np.any(benign_mask) else cal_scores
        else:
            clean = cal_scores

        clean = clean[np.isfinite(clean)]
        self.cal_scores_ = np.sort(clean)
        self.n_cal_ = len(self.cal_scores_)

        if self.n_cal_ == 0:
            self.threshold_ = 0.0
            return self

        # Finite-sample split-conformal quantile index: ceil((n + 1) * (1 - alpha)) / n
        q_idx = int(np.ceil((self.n_cal_ + 1) * (1.0 - self.alpha)))
        q_idx = max(1, min(self.n_cal_, q_idx))
        # Zero-indexed: element at q_idx - 1
        self.threshold_ = float(self.cal_scores_[q_idx - 1])

        # Point-mass tie adjustment: ensure empirical FAR <= alpha
        emp_far = float(np.mean(self.cal_scores_ >= self.threshold_))
        if emp_far > self.alpha:
            higher = self.cal_scores_[self.cal_scores_ > self.threshold_]
            if len(higher) > 0:
                self.threshold_ = float(np.min(higher))
            else:
                self.threshold_ = self.threshold_ + self.eps

        return self

    def compute_p_values(self, test_scores: np.ndarray) -> np.ndarray:
        """
        Compute conformal p-values for an array of test scores against the calibration set:
            p(s) = (1 + sum(S_cal >= s)) / (n_cal + 1)
        """
        if self.n_cal_ == 0:
            return np.ones_like(test_scores, dtype=float)

        # Using searchsorted for vectorized O((N + M) log N) computation
        # cal_scores_ is sorted in ascending order.
        # np.searchsorted(..., side='left') gives number of elements < s.
        # So elements >= s is n_cal - searchsorted(..., s, side='left').
        n_greater_equal = self.n_cal_ - np.searchsorted(self.cal_scores_, test_scores, side="left")
        p_vals = (1.0 + n_greater_equal) / (self.n_cal_ + 1.0)
        return p_vals

    def predict(self, test_scores: np.ndarray, alpha: Optional[float] = None) -> np.ndarray:
        """
        Predict binary alerts (1 = Anomaly, 0 = Normal) at significance level alpha.
        Alert when p-value <= alpha (or test_score >= threshold_).
        """
        target_alpha = self.alpha if alpha is None else alpha
        if self.n_cal_ == 0:
            return np.zeros_like(test_scores, dtype=int)

        if alpha is not None and alpha != self.alpha:
            # Recompute threshold for custom alpha
            q_idx = int(np.ceil((self.n_cal_ + 1) * (1.0 - target_alpha)))
            q_idx = max(1, min(self.n_cal_, q_idx))
            thresh = float(self.cal_scores_[q_idx - 1])
            emp_far = float(np.mean(self.cal_scores_ >= thresh))
            if emp_far > target_alpha:
                higher = self.cal_scores_[self.cal_scores_ > thresh]
                if len(higher) > 0:
                    thresh = float(np.min(higher))
                else:
                    thresh = thresh + self.eps
        else:
            thresh = self.threshold_

        return (test_scores >= thresh).astype(int)

    def predict_rolling(
        self,
        test_scores: np.ndarray,
        window_size: int = 60,
        alpha: Optional[float] = None,
        verified_benign_mask: Optional[np.ndarray] = None
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Causal Rolling Conformal Thresholding.
        At each time step t, threshold tau_t is calibrated on the most recent
        window of calibration scores (initially seeded from cal_scores_).
        
        If verified_benign_mask is provided, only verified benign test scores enter
        the rolling buffer (preventing attack poisoning).
        
        Returns:
            (predictions, rolling_thresholds)
        """
        target_alpha = self.alpha if alpha is None else alpha
        n_test = len(test_scores)
        preds = np.zeros(n_test, dtype=int)
        thresholds = np.zeros(n_test, dtype=float)

        # Initialize rolling buffer with initial calibration scores
        buffer = list(self.cal_scores_[-window_size:]) if self.n_cal_ > 0 else []

        for t in range(n_test):
            if len(buffer) < 10:
                cur_thresh = self.threshold_
            else:
                buf_arr = np.sort(np.array(buffer))
                n_b = len(buf_arr)
                q_idx = int(np.ceil((n_b + 1) * (1.0 - target_alpha)))
                q_idx = max(1, min(n_b, q_idx))
                cur_thresh = float(buf_arr[q_idx - 1])
                emp_far = float(np.mean(buf_arr >= cur_thresh))
                if emp_far > target_alpha:
                    higher = buf_arr[buf_arr > cur_thresh]
                    cur_thresh = float(np.min(higher)) if len(higher) > 0 else cur_thresh + self.eps

            thresholds[t] = cur_thresh
            score_t = test_scores[t]
            is_anomaly = int(score_t >= cur_thresh)
            preds[t] = is_anomaly

            # Buffer update logic:
            should_add = False
            if verified_benign_mask is not None:
                should_add = bool(verified_benign_mask[t])
            else:
                should_add = (is_anomaly == 0)

            if should_add:
                buffer.append(score_t)
                if len(buffer) > window_size:
                    buffer.pop(0)

        return preds, thresholds

    def predict_aci(
        self,
        test_scores: np.ndarray,
        gamma: float = 0.01,
        window_size: int = 60,
        alpha: Optional[float] = None,
        verified_benign_mask: Optional[np.ndarray] = None
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Adaptive Conformal Inference (ACI; Gibbs & Candès 2021).
        Dynamically adjusts the nominal risk alpha_t based on past coverage errors:
            alpha_{t+1} = alpha_t + gamma * (alpha - err_t)
        where err_t = 1 if false alarm, 0 otherwise (on benign points).
        
        Returns:
            (predictions, rolling_thresholds, adapted_alphas)
        """
        target_alpha = self.alpha if alpha is None else alpha
        n_test = len(test_scores)
        preds = np.zeros(n_test, dtype=int)
        thresholds = np.zeros(n_test, dtype=float)
        adapted_alphas = np.zeros(n_test, dtype=float)

        alpha_t = target_alpha
        buffer = list(self.cal_scores_[-window_size:]) if self.n_cal_ > 0 else []

        for t in range(n_test):
            adapted_alphas[t] = alpha_t

            if len(buffer) < 10:
                cur_thresh = self.threshold_
            else:
                buf_arr = np.sort(np.array(buffer))
                n_b = len(buf_arr)
                q_idx = int(np.ceil((n_b + 1) * (1.0 - alpha_t)))
                q_idx = max(1, min(n_b, q_idx))
                cur_thresh = float(buf_arr[q_idx - 1])
                emp_far = float(np.mean(buf_arr >= cur_thresh))
                if emp_far > alpha_t:
                    higher = buf_arr[buf_arr > cur_thresh]
                    cur_thresh = float(np.min(higher)) if len(higher) > 0 else cur_thresh + self.eps

            thresholds[t] = cur_thresh
            score_t = test_scores[t]
            is_anomaly = int(score_t >= cur_thresh)
            preds[t] = is_anomaly

            is_benign = True
            if verified_benign_mask is not None:
                is_benign = bool(verified_benign_mask[t])

            if is_benign:
                err_t = float(is_anomaly)
                alpha_t = float(np.clip(alpha_t + gamma * (target_alpha - err_t), 0.001, 0.50))
                buffer.append(score_t)
                if len(buffer) > window_size:
                    buffer.pop(0)

        return preds, thresholds, adapted_alphas
