"""
Persistence filtering module (Config C).
Filters transient false-alarm spikes by requiring persistent anomalous observations.
"""

import numpy as np
import pandas as pd
from typing import Optional

class PersistenceFilter:
    """
    Config C: Persistence Filter.
    Suppresses transient false alarms by requiring k consecutive anomalous detections
    before an operational alert is raised.
    """
    def __init__(self, k: int = 3, sustain: bool = True):
        """
        Args:
            k: Number of consecutive anomalous observations required to trigger an alert.
            sustain: If True, once triggered after k consecutive anomalies, continues firing
                     for ongoing contiguous anomalies until the stream returns to normal.
        """
        self.k = max(1, int(k))
        self.sustain = sustain

    def filter(self, raw_alarms: np.ndarray) -> np.ndarray:
        """
        Apply causal persistence filtering to binary alarms.
        """
        if self.k == 1:
            return raw_alarms.astype(int)

        n = len(raw_alarms)
        filtered = np.zeros(n, dtype=int)
        consecutive_count = 0

        for t in range(n):
            if raw_alarms[t] == 1:
                consecutive_count += 1
                if consecutive_count >= self.k:
                    filtered[t] = 1
            else:
                consecutive_count = 0

        return filtered

def sweep_persistence_k(
    raw_alarms: np.ndarray,
    y_true: np.ndarray,
    k_values: Optional[list] = None
) -> pd.DataFrame:
    """
    Sweep different persistence thresholds k on validation set to evaluate
    the trade-off between false alarm reduction and recall.
    """
    if k_values is None:
        k_values = [1, 2, 3, 4, 5, 7, 10]

    from src.evaluation import compute_classification_metrics, compute_sre_operational_metrics

    records = []
    for k in k_values:
        p_filter = PersistenceFilter(k=k)
        filtered_pred = p_filter.filter(raw_alarms)
        
        cls_m = compute_classification_metrics(y_true, filtered_pred)
        sre_m = compute_sre_operational_metrics(y_true, filtered_pred)
        
        records.append({
            "k": k,
            "precision": cls_m["precision"],
            "recall": cls_m["recall"],
            "f1": cls_m["f1"],
            "fpr": cls_m["fpr"],
            "total_alerts": sre_m["total_alerts"],
            "false_alarms": sre_m["false_alarms"],
            "false_alarms_per_day": sre_m["false_alarms_per_day"],
            "episode_recall": sre_m["episode_recall"],
            "mean_delay_steps": sre_m["mean_delay_steps"]
        })

    return pd.DataFrame(records)

