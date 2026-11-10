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
import scipy.stats as stats
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    precision_recall_curve
)

def compute_clopper_pearson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Exact Clopper-Pearson binomial confidence interval for k successes out of n trials.
    """
    if n <= 0:
        return 0.0, 1.0
    alpha = 1.0 - confidence
    low = 0.0 if k == 0 else float(stats.beta.ppf(alpha / 2, k, n - k + 1))
    high = 1.0 if k == n else float(stats.beta.ppf(1 - alpha / 2, k + 1, n - k))
    return low, high

def find_campaign_intervals(y_true: np.ndarray, gap_tolerance: int = 0) -> List[Tuple[int, int]]:
    """
    Identifies attack campaign intervals [start, end] (inclusive) in a binary label sequence.
    
    Campaign Definition Policy:
    1. A campaign is strictly defined as a contiguous run of attack-positive windows/flows (Label == 1).
    2. Default gap_tolerance = 0: any intervening normal window/flow (Label == 0) terminates the campaign.
    3. Clipped to slice: campaigns are strictly evaluated within the boundaries of the given slice (y_true).
       Attack activity outside the evaluated slice is not bridged or counted.
    """
    atk_indices = np.where(y_true == 1)[0]
    if len(atk_indices) == 0:
        return []
    intervals = []
    curr_start = int(atk_indices[0])
    curr_end = int(atk_indices[0])
    for idx in atk_indices[1:]:
        idx = int(idx)
        if idx - curr_end - 1 <= gap_tolerance:
            curr_end = idx
        else:
            intervals.append((curr_start, curr_end))
            curr_start = idx
            curr_end = idx
    intervals.append((curr_start, curr_end))
    return intervals

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
    support_total = int(len(y_true))
    support_attacks = int(y_true.sum())
    support_normal = int((y_true == 0).sum())
    prevalence = float(support_attacks / support_total) if support_total > 0 else 0.0

    metrics = {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "fpr": float(fpr),
        "prevalence": prevalence,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "support_total": support_total,
        "support_attacks": support_attacks,
        "support_normal": support_normal
    }

    if y_scores is not None and len(np.unique(y_true)) > 1:
        try:
            pr_val = float(average_precision_score(y_true, y_scores))
            roc_val = float(roc_auc_score(y_true, y_scores))
            metrics["pr_auc"] = pr_val
            metrics["roc_auc"] = roc_val
            metrics["pr_auc_lift"] = float((pr_val - prevalence) / prevalence) if prevalence > 0 else 0.0
        except Exception:
            metrics["pr_auc"] = None
            metrics["roc_auc"] = None
            metrics["pr_auc_lift"] = None
    else:
        metrics["pr_auc"] = None
        metrics["roc_auc"] = None
        metrics["pr_auc_lift"] = None

    return metrics

def compute_sre_operational_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    timestamps: Optional[np.ndarray] = None,
    default_step_sec: float = 10.0,
    is_flow_data: bool = False
) -> Dict[str, Any]:
    """
    Compute SRE operational metrics:
    - Episode/campaign detection delay (MTTD computed strictly over detected campaigns)
    - Episode/campaign recall (detected campaigns / total campaigns)
    - Alerts per 1,000 windows (or per 1,000 flows)
    - Alerts per hour
    - False Alarms per Day (FAPD) (omitted for flow-level data)
    - Total Alert Volume
    """
    total_steps = len(y_true)
    if total_steps == 0:
        return {}

    # Calculate total duration in seconds
    if timestamps is not None and len(timestamps) > 1:
        if is_flow_data:
            total_duration_sec = float(timestamps[-1] - timestamps[0])
        else:
            total_duration_sec = float((timestamps[-1] - timestamps[0]) + default_step_sec)
        # Fallback if timestamps are identical or zero
        if total_duration_sec <= 0:
            total_duration_sec = total_steps * default_step_sec
    else:
        total_duration_sec = total_steps * default_step_sec

    total_days = total_duration_sec / 86400.0
    total_hours = total_duration_sec / 3600.0

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    total_alerts = int(y_pred.sum())
    fapd = float(fp / total_days) if (total_days > 0 and not is_flow_data) else None
    alerts_per_1000 = float(total_alerts * 1000.0 / total_steps) if total_steps > 0 else 0.0
    alerts_per_hour = float(total_alerts / total_hours) if (total_hours > 0 and not is_flow_data) else None

    # Episode/campaign-level detection delay
    # Identify attack campaigns (contiguous attack windows/flows)
    intervals = find_campaign_intervals(y_true, gap_tolerance=0)

    delays_steps = []
    delays_sec = []
    campaigns_detected = 0

    for s, e in intervals:
        ep_pred = y_pred[s:e + 1]
        alert_indices = np.where(ep_pred == 1)[0]
        if len(alert_indices) > 0:
            campaigns_detected += 1
            first_alert_step = alert_indices[0]
            delays_steps.append(first_alert_step)
            if timestamps is not None:
                first_alert_time = timestamps[s + first_alert_step] - timestamps[s]
                delays_sec.append(float(first_alert_time))
            else:
                delays_sec.append(float(first_alert_step * default_step_sec))

    total_campaigns = len(intervals)
    campaign_recall = float(campaigns_detected / total_campaigns) if total_campaigns > 0 else 1.0
    cp_low, cp_high = compute_clopper_pearson_ci(campaigns_detected, total_campaigns, confidence=0.95)

    return {
        "total_alerts": total_alerts,
        "false_alarms": int(fp),
        "false_alarms_per_day": fapd,
        "alerts_per_1000_windows": alerts_per_1000,
        "alerts_per_hour": alerts_per_hour,
        "total_episodes": total_campaigns,
        "total_campaigns": total_campaigns,
        "episodes_detected": campaigns_detected,
        "campaigns_detected": campaigns_detected,
        "episode_recall": campaign_recall,
        "campaign_recall": campaign_recall,
        "campaign_recall_ci_low": cp_low,
        "campaign_recall_ci_high": cp_high,
        "campaign_recall_ratio": f"{campaigns_detected}/{total_campaigns}",
        "mean_delay_steps": float(np.mean(delays_steps)) if delays_steps else None,
        "median_delay_steps": float(np.median(delays_steps)) if delays_steps else None,
        "mean_delay_sec": float(np.mean(delays_sec)) if delays_sec else None,
        "mttd_detected_campaigns_only_sec": float(np.mean(delays_sec)) if delays_sec else None,
        "median_delay_sec": float(np.median(delays_sec)) if delays_sec else None,
        "total_duration_hours": float(total_hours)
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
    n_bootstraps: int = 500,
    alpha: float = 0.05,
    seed: int = 42,
    default_step_sec: float = 10.0,
    block_size: int = 10
) -> Dict[str, Any]:
    """
    Computes Moving-Block Bootstrap (MBB) confidence intervals (95% CI by default) for:
    - F1 Score (moving-block resampling of contiguous length B=block_size)
    - PR-AUC (moving-block resampling of contiguous length B=block_size)
    - MTTD Delay (episode/campaign block resampling over detected campaigns)
    """
    rng = np.random.default_rng(seed)
    n_samples = len(y_true)
    if n_samples == 0:
        return {}

    b_size = max(1, min(block_size, n_samples // 2)) if n_samples > 2 else 1
    num_blocks = int(np.ceil(n_samples / b_size))
    max_start = max(1, n_samples - b_size + 1)

    f1_boots = []
    pr_auc_boots = []

    # 1. Moving-Block Bootstrap (MBB) for F1 and PR-AUC
    for _ in range(n_bootstraps):
        starts = rng.integers(0, max_start, size=num_blocks)
        indices = np.concatenate([np.arange(s, s + b_size) for s in starts])[:n_samples]
        
        y_t_b = y_true[indices]
        y_p_b = y_pred[indices]

        # F1
        f1_b = f1_score(y_t_b, y_p_b, zero_division=0)
        f1_boots.append(float(f1_b))

        # PR-AUC
        if y_scores is not None and len(np.unique(y_t_b)) > 1:
            try:
                pr_b = average_precision_score(y_t_b, y_scores[indices])
                pr_auc_boots.append(float(pr_b))
            except Exception:
                pass

    # 2. Episode/Campaign Block Bootstrap for MTTD (Unified campaign accounting, g=0)
    episodes = find_campaign_intervals(y_true, gap_tolerance=0)
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
            # Missed episode
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
        "total_campaigns": total_episodes,
        "f1_ci": f1_ci,
        "f1_std": float(np.std(f1_boots)) if f1_boots else 0.0,
        "pr_auc_ci": pr_auc_ci,
        "pr_auc_std": float(np.std(pr_auc_boots)) if pr_auc_boots else None,
        "mttd_ci": mttd_ci,
        "mttd_std": float(np.std(mttd_boots)) if mttd_boots else None
    }
