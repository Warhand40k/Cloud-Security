"""
Time-window aggregation module for network flow data.
Groups flow records into fixed chronological windows (e.g., 5s, 10s, 15s, 20s).
Implements the paper's 10-second aggregation logic alongside operational flow statistics.
"""

import pandas as pd
import numpy as np
from typing import List, Optional, Tuple

PAPER_NUMERICS = ["sloss", "dur", "sbytes", "dbytes", "sttl", "dttl", "dloss"]
PAPER_CATEGORICALS = ["state", "service"]

def _mode_agg(series: pd.Series):
    """Return the most frequent value in the series (as described in the paper)."""
    m = series.mode()
    return m.iloc[0] if not m.empty else series.iloc[0]

def aggregate_time_windows(
    df: pd.DataFrame,
    window_sec: int = 10,
    stime_col: str = "Stime",
    label_col: str = "Label",
    attack_col: str = "attack_cat",
    mode_only: bool = True
) -> pd.DataFrame:
    """
    Aggregate flow records into discrete time windows of size `window_sec` seconds.
    
    Args:
        df: DataFrame containing flow records with timestamps and labels.
        window_sec: Window size in seconds (default 10s, as selected in paper).
        stime_col: Start time column name.
        label_col: Binary label column name.
        attack_col: Multi-class attack category column name.
        mode_only: If True, uses the paper's strategy (most frequent value per column).
                   If False, appends operational summary features (flow_count, sums, rates).
    
    Returns:
        DataFrame where each row represents a discrete time window.
    """
    df = df.copy()
    df["window_time"] = (df[stime_col] // window_sec) * window_sec

    # Prepare aggregation dictionary
    agg_dict = {}
    
    # 1. Paper features (mode aggregation)
    for col in PAPER_NUMERICS + PAPER_CATEGORICALS:
        if col in df.columns:
            agg_dict[col] = _mode_agg

    # 2. Labels & Ground Truth
    if label_col in df.columns:
        agg_dict[label_col] = lambda x: int((x > 0).any())  # Any attack in window

    if attack_col in df.columns:
        agg_dict[attack_col] = _mode_agg

    # Groupby window_time
    grouped = df.groupby("window_time", as_index=False)
    windowed_df = grouped.agg(agg_dict)

    # Additional operational/SRE telemetry metadata
    metadata = grouped.agg(
        flow_count=(stime_col, "count"),
        attack_flow_count=(label_col, "sum") if label_col in df.columns else (stime_col, "count")
    )
    windowed_df["flow_count"] = metadata["flow_count"]
    if label_col in df.columns:
        windowed_df["attack_ratio"] = metadata["attack_flow_count"] / metadata["flow_count"]

    # Sort strictly chronologically
    windowed_df = windowed_df.sort_values(by="window_time").reset_index(drop=True)
    return windowed_df

