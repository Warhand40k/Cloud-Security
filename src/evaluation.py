"""
Evaluation module for cloud network anomaly detection.
Computes ML classification metrics, SRE operational metrics, and computational resource profiling.
"""

import os
import time
import psutil
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional, List
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    precision_recall_curve
)

def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_scores: Optional[np.ndarray] = None
) -> Dict[str, Any]:
    """
    Compute standard ML classification metrics.
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    metrics = {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "fpr": float(fpr),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "support_total": int(len(y_true)),
        "support_attacks": int(y_true.sum()),
        "support_normal": int((y_true == 0).sum())
    }

    if y_scores is not None and len(np.unique(y_true)) > 1:
        try:
            metrics["pr_auc"] = float(average_precision_score(y_true, y_scores))
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_scores))
        except Exception:
            metrics["pr_auc"] = None
            metrics["roc_auc"] = None
    else:
        metrics["pr_auc"] = None
        metrics["roc_auc"] = None

    return metrics

def compute_sre_operational_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    timestamps: Optional[np.ndarray] = None,
    default_step_sec: float = 10.0
) -> Dict[str, Any]:
    """
    Compute SRE operational metrics:
    - Detection delay (time/steps from start of attack episode to first alert)
    - False Alarms per Day (FAPD)
    - Total Alert Volume
    """
    total_steps = len(y_true)
    if total_steps == 0:
        return {}

    # Calculate total duration in seconds
    if timestamps is not None and len(timestamps) > 1:
        total_duration_sec = float(timestamps[-1] - timestamps[0])
        # Fallback if timestamps are identical or zero
        if total_duration_sec <= 0:
            total_duration_sec = total_steps * default_step_sec
    else:
        total_duration_sec = total_steps * default_step_sec

    total_days = total_duration_sec / 86400.0

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    total_alerts = int(y_pred.sum())
    fapd = float(fp / total_days) if total_days > 0 else 0.0

    # Episode-level detection delay
    # Identify contiguous attack episodes
    diffs = np.diff(y_true.astype(int))
    starts = np.where(diffs == 1)[0] + 1
    if y_true[0] == 1:
        starts = np.insert(starts, 0, 0)
        
    ends = np.where(diffs == -1)[0]
    if y_true[-1] == 1:
        ends = np.append(ends, total_steps - 1)

    delays_steps = []
    delays_sec = []
    episodes_detected = 0

    for s, e in zip(starts, ends):
        ep_pred = y_pred[s:e + 1]
        alert_indices = np.where(ep_pred == 1)[0]
        if len(alert_indices) > 0:
            episodes_detected += 1
            first_alert_step = alert_indices[0]
            delays_steps.append(first_alert_step)
            if timestamps is not None:
                first_alert_time = timestamps[s + first_alert_step] - timestamps[s]
                delays_sec.append(float(first_alert_time))
            else:
                delays_sec.append(float(first_alert_step * default_step_sec))

    total_episodes = len(starts)
    episode_recall = float(episodes_detected / total_episodes) if total_episodes > 0 else 1.0

    return {
        "total_alerts": total_alerts,
        "false_alarms": int(fp),
        "false_alarms_per_day": fapd,
        "total_episodes": total_episodes,
        "episodes_detected": episodes_detected,
        "episode_recall": episode_recall,
        "mean_delay_steps": float(np.mean(delays_steps)) if delays_steps else None,
        "median_delay_steps": float(np.median(delays_steps)) if delays_steps else None,
        "mean_delay_sec": float(np.mean(delays_sec)) if delays_sec else None,
        "median_delay_sec": float(np.median(delays_sec)) if delays_sec else None,
        "total_duration_hours": float(total_duration_sec / 3600.0)
    }

class ResourceProfiler:
    """Context manager for measuring runtime and peak memory usage."""
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.start_time = 0.0
        self.end_time = 0.0
        self.start_mem_bytes = 0
        self.peak_mem_mb = 0.0

    def __enter__(self):
        self.start_mem_bytes = self.process.memory_info().rss
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        end_mem_bytes = self.process.memory_info().rss
        self.peak_mem_mb = float(max(self.start_mem_bytes, end_mem_bytes) / (1024 * 1024))

    @property
    def elapsed_seconds(self) -> float:
        return self.end_time - self.start_time



def compute_bootstrap_confidence_intervals(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_scores: Optional[np.ndarray] = None,
    timestamps: Optional[np.ndarray] = None,
    n_bootstraps: int = 1000,
    alpha: float = 0.05,
    seed: int = 42,
    default_step_sec: float = 10.0
) -> Dict[str, Any]:
    """
    Computes bootstrap confidence intervals (95% CI by default) for:
    - F1 Score (instance/window resampling)
    - PR-AUC (instance/window resampling)
    - MTTD Delay (episode block resampling)
    """
    rng = np.random.default_rng(seed)
    n_samples = len(y_true)
    if n_samples == 0:
        return {}

    f1_boots = []
    pr_auc_boots = []

    # 1. Instance/Window Bootstrap for F1 and PR-AUC
    for _ in range(n_bootstraps):
        idx = rng.choice(n_samples, size=n_samples, replace=True)
        y_t_b = y_true[idx]
        y_p_b = y_pred[idx]

        # F1
        f1_b = f1_score(y_t_b, y_p_b, zero_division=0)
        f1_boots.append(float(f1_b))

        # PR-AUC
        if y_scores is not None and len(np.unique(y_t_b)) > 1:
            try:
                pr_b = average_precision_score(y_t_b, y_scores[idx])
                pr_auc_boots.append(float(pr_b))
            except Exception:
                pass

    # 2. Episode-Level Block Bootstrap for MTTD
    diffs = np.diff(y_true.astype(int))
    starts = np.where(diffs == 1)[0] + 1
    if y_true[0] == 1:
        starts = np.insert(starts, 0, 0)
    ends = np.where(diffs == -1)[0]
    if y_true[-1] == 1:
        ends = np.append(ends, n_samples - 1)

    episodes = list(zip(starts, ends))
    total_episodes = len(episodes)
    mttd_boots = []

    # Calculate empirical delay for each episode
    ep_delays = []
    for s, e in episodes:
        ep_pred = y_pred[s:e + 1]
        alert_idx = np.where(ep_pred == 1)[0]
        if len(alert_idx) > 0:
            first_step = alert_idx[0]
            if timestamps is not None and len(timestamps) > (s + first_step):
                delay_val = float(timestamps[s + first_step] - timestamps[s])
            else:
                delay_val = float(first_step * default_step_sec)
            ep_delays.append(delay_val)
        else:
            # Missed episode: penalty or NaN
            ep_delays.append(np.nan)

    if total_episodes > 0:
        ep_delays_arr = np.array(ep_delays)
        for _ in range(n_bootstraps):
            resamp_idx = rng.choice(total_episodes, size=total_episodes, replace=True)
            sampled_delays = ep_delays_arr[resamp_idx]
            valid_delays = sampled_delays[np.isfinite(sampled_delays)]
            if len(valid_delays) > 0:
                mttd_boots.append(float(np.mean(valid_delays)))

    lower_pct = 100.0 * (alpha / 2.0)
    upper_pct = 100.0 * (1.0 - alpha / 2.0)

    f1_ci = (float(np.percentile(f1_boots, lower_pct)), float(np.percentile(f1_boots, upper_pct))) if f1_boots else (0.0, 0.0)
    pr_auc_ci = (float(np.percentile(pr_auc_boots, lower_pct)), float(np.percentile(pr_auc_boots, upper_pct))) if pr_auc_boots else (None, None)
    mttd_ci = (float(np.percentile(mttd_boots, lower_pct)), float(np.percentile(mttd_boots, upper_pct))) if mttd_boots else (None, None)

    return {
        "n_episodes": total_episodes,
        "f1_ci": f1_ci,
        "f1_std": float(np.std(f1_boots)) if f1_boots else 0.0,
        "pr_auc_ci": pr_auc_ci,
        "pr_auc_std": float(np.std(pr_auc_boots)) if pr_auc_boots else None,
        "mttd_ci": mttd_ci,
        "mttd_std": float(np.std(mttd_boots)) if mttd_boots else None
    }
