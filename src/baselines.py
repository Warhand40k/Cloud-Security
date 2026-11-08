"""
Baseline anomaly detectors:
1. Isolation Forest (IF)
2. ARIMA-residual / Forecast-error detector (AR)
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, List
from sklearn.ensemble import IsolationForest
from statsmodels.tsa.arima.model import ARIMA

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

    def calibrate_threshold(self, X_val: np.ndarray, y_val: np.ndarray, metric: str = "f1"):
        """Calibrate decision threshold on validation set."""
        scores_val = self.score_samples(X_val)
        
        # Grid sweep over percentiles
        percentiles = np.linspace(80, 99.9, 100)
        best_thresh = float(np.median(scores_val))
        best_score = -1.0

        for p in percentiles:
            thresh = float(np.percentile(scores_val, p))
            pred = (scores_val >= thresh).astype(int)
            from sklearn.metrics import f1_score
            f1 = f1_score(y_val, pred, zero_division=0)
            if f1 > best_score:
                best_score = f1
                best_thresh = thresh

        self.threshold_ = best_thresh
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

    def calibrate_threshold(self, X_val: np.ndarray, y_val: np.ndarray):
        """Calibrate threshold on validation split."""
        scores_val = self.score_samples(X_val)
        percentiles = np.linspace(80, 99.9, 100)
        best_thresh = float(np.median(scores_val))
        best_score = -1.0

        for p in percentiles:
            thresh = float(np.percentile(scores_val, p))
            pred = (scores_val >= thresh).astype(int)
            from sklearn.metrics import f1_score
            f1 = f1_score(y_val, pred, zero_division=0)
            if f1 > best_score:
                best_score = f1
                best_thresh = thresh

        self.threshold_ = best_thresh
        return self.threshold_

    def predict(self, X: np.ndarray) -> np.ndarray:
        scores = self.score_samples(X)
        return (scores >= self.threshold_).astype(int)

