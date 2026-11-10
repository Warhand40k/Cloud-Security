"""
Baseline anomaly detectors:
1. Isolation Forest (IF)
2. ARIMA-residual / Forecast-error detector (AR)
3. Trivial Baselines: All-Attack, All-Normal, Random-Uniform, Random-Stratified
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, List
from sklearn.ensemble import IsolationForest
from statsmodels.tsa.arima.model import ARIMA
from src.adaptive_threshold import calibrate_benign_quantile_threshold

class AllAttackBaseline:
    """Trivial baseline: predicts 1 (Attack) for all observations."""
    def fit(self, X_train: np.ndarray, y_train: Optional[np.ndarray] = None):
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return np.ones(len(X), dtype=float)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.ones(len(X), dtype=int)

class AllNormalBaseline:
    """Trivial baseline: predicts 0 (Normal) for all observations."""
    def fit(self, X_train: np.ndarray, y_train: Optional[np.ndarray] = None):
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return np.zeros(len(X), dtype=float)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.zeros(len(X), dtype=int)

class RandomUniformBaseline:
    """Trivial baseline: predicts 1 with uniform probability p=0.5."""
    def __init__(self, seed: int = 42):
        self.rng = np.random.default_rng(seed)

    def fit(self, X_train: np.ndarray, y_train: Optional[np.ndarray] = None):
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.rng.uniform(0.0, 1.0, size=len(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.score_samples(X) >= 0.5).astype(int)

class RandomStratifiedBaseline:
    """Trivial baseline: predicts 1 with probability equal to the training split attack prevalence."""
    def __init__(self, seed: int = 42):
        self.rng = np.random.default_rng(seed)
        self.prior_ = 0.5

    def fit(self, X_train: np.ndarray, y_train: np.ndarray):
        self.prior_ = float(np.mean(y_train))
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.rng.uniform(0.0, 1.0, size=len(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.rng.uniform(0.0, 1.0, size=len(X)) < self.prior_).astype(int)

class IsolationForestBaseline:
    """
    Isolation Forest baseline.
    Trained on the same permissible feature set under identical evaluation protocol.
    """
    def __init__(self, n_estimators: int = 100, contamination: str = "auto", random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.threshold_ = 0.0

    def fit(self, X_train: np.ndarray):
        """Fit model on training features."""
        self.model.fit(X_train)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Return anomaly score where higher values indicate greater anomaly.
        score_samples returns negative anomaly score (lower is more anomalous),
        so we negate it.
        """
        return -self.model.score_samples(X)

    def calibrate_threshold(self, X_val: np.ndarray, y_val: np.ndarray, alpha: float = 0.05):
        """
        Calibrate decision threshold on BENIGN validation samples to enforce FAR <= alpha.
        No F1 optimization or attack labels are used.
        """
        scores_val = self.score_samples(X_val)
        self.threshold_ = calibrate_benign_quantile_threshold(scores_val, y_val, alpha=alpha)
        return self.threshold_

    def predict(self, X: np.ndarray) -> np.ndarray:
        scores = self.score_samples(X)
        return (scores >= self.threshold_).astype(int)

class ARIMAResidualBaseline:
    """
    ARIMA-residual forecast baseline.
    Fits univariate ARIMA models on training time series, computes 1-step forecast errors,
    and flags anomalies based on standardized residual z-scores.
    """
    def __init__(self, order: tuple = (1, 0, 1)):
        self.order = order
        self.models_ = []
        self.residual_means_ = []
        self.residual_stds_ = []
        self.threshold_ = 3.0

    def fit(self, X_train: np.ndarray):
        """
        Fit ARIMA model on each feature stream of training data.
        """
        n_features = X_train.shape[1]
        self.models_ = []
        self.residual_means_ = []
        self.residual_stds_ = []

        for j in range(n_features):
            series = X_train[:, j]
            # Simple AR(1) or ARIMA(1,0,1)
            try:
                model = ARIMA(series, order=self.order)
                fitted = model.fit()
                resids = np.abs(fitted.resid)
                self.models_.append(fitted)
                self.residual_means_.append(float(np.mean(resids)))
                self.residual_stds_.append(float(np.std(resids)) + 1e-6)
            except Exception:
                # Fallback to rolling difference if ARIMA fails to converge
                diffs = np.abs(np.diff(series, prepend=series[0]))
                self.models_.append(None)
                self.residual_means_.append(float(np.mean(diffs)))
                self.residual_stds_.append(float(np.std(diffs)) + 1e-6)

        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Compute multi-channel residual z-scores.
        """
        n_samples, n_features = X.shape
        z_scores = np.zeros((n_samples, n_features))

        for j in range(n_features):
            series = X[:, j]
            model = self.models_[j]
            if model is not None:
                try:
                    # One-step ahead forecast error using fitted parameters
                    resids = np.abs(series - model.predict(start=0, end=n_samples - 1))
                except Exception:
                    resids = np.abs(np.diff(series, prepend=series[0]))
            else:
                resids = np.abs(np.diff(series, prepend=series[0]))

            z_scores[:, j] = (resids - self.residual_means_[j]) / self.residual_stds_[j]

        # Aggregate across features using L2 Euclidean norm
        aggregate_scores = np.sqrt(np.sum(np.maximum(0, z_scores) ** 2, axis=1))
        return aggregate_scores

    def calibrate_threshold(self, X_val: np.ndarray, y_val: np.ndarray, alpha: float = 0.05):
        """
        Calibrate decision threshold on BENIGN validation samples to enforce FAR <= alpha.
        No F1 optimization or attack labels are used.
        """
        scores_val = self.score_samples(X_val)
        self.threshold_ = calibrate_benign_quantile_threshold(scores_val, y_val, alpha=alpha)
        return self.threshold_

    def predict(self, X: np.ndarray) -> np.ndarray:
        scores = self.score_samples(X)
        return (scores >= self.threshold_).astype(int)

