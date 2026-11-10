"""
Time-window aggregation module for network flow data.
Supports:
1. UNSW-NB15 flow-to-window aggregation (10s intervals, mode pooling, and configurable label rules)
2. CSE-CIC-IDS2018 flow-to-window aggregation (60s and 10s intervals, DoS telemetry aggregations)
"""

import os
import pandas as pd
import numpy as np
from typing import List, Optional, Tuple, Literal

PAPER_NUMERICS = ["sloss", "dur", "sbytes", "dbytes", "sttl", "dttl", "dloss"]
PAPER_CATEGORICALS = ["state", "service"]

LabelRule = Literal["any_attack", "majority", "ratio_10"]

def _mode_agg(series: pd.Series):
    """Return the most frequent value in the series."""
    m = series.mode()
    return m.iloc[0] if not m.empty else series.iloc[0]

def aggregate_time_windows(
    df: pd.DataFrame,
    window_sec: int = 10,
    stime_col: str = "Stime",
    label_col: str = "Label",
    attack_col: str = "attack_cat",
    label_rule: LabelRule = "any_attack"
) -> pd.DataFrame:
    """
    Aggregate UNSW-NB15 flow records into discrete time windows of size `window_sec` seconds.
    
    Args:
        df: DataFrame containing flow records with timestamps and labels.
        window_sec: Window size in seconds (default 10s).
        stime_col: Start time column name.
        label_col: Binary label column name.
        attack_col: Multi-class attack category column name.
        label_rule: 
            - 'any_attack': Window is Attack (1) if at least 1 attack flow occurs.
            - 'majority': Window is Attack (1) if >50% of flows are attacks.
            - 'ratio_10': Window is Attack (1) if >10% of flows are attacks.
            
    Returns:
        DataFrame where each row represents a discrete time window.
    """
    df = df.copy()
    df["window_time"] = (df[stime_col] // window_sec) * window_sec

    agg_dict = {}
    for col in PAPER_NUMERICS + PAPER_CATEGORICALS:
        if col in df.columns:
            agg_dict[col] = _mode_agg

    if attack_col in df.columns:
        agg_dict[attack_col] = _mode_agg

    grouped = df.groupby("window_time", as_index=False)
    windowed_df = grouped.agg(agg_dict)

    # Compute operational telemetry counts
    metadata = grouped.agg(
        flow_count=(stime_col, "count"),
        attack_flow_count=(label_col, "sum") if label_col in df.columns else (stime_col, "count")
    )
    windowed_df["flow_count"] = metadata["flow_count"]
    if label_col in df.columns:
        windowed_df["attack_flow_count"] = metadata["attack_flow_count"]
        windowed_df["attack_ratio"] = metadata["attack_flow_count"] / metadata["flow_count"]
        
        # Ground truth window labels under different decision rules
        windowed_df["Label_any"] = (windowed_df["attack_flow_count"] > 0).astype(int)
        windowed_df["Label_majority"] = (windowed_df["attack_ratio"] > 0.5).astype(int)
        windowed_df["Label_ratio10"] = (windowed_df["attack_ratio"] >= 0.10).astype(int)

        if label_rule == "any_attack":
            windowed_df[label_col] = windowed_df["Label_any"]
        elif label_rule == "majority":
            windowed_df[label_col] = windowed_df["Label_majority"]
        elif label_rule == "ratio_10":
            windowed_df[label_col] = windowed_df["Label_ratio10"]
        else:
            raise ValueError(f"Unknown label_rule: {label_rule}")

    windowed_df["window_dt"] = pd.to_datetime(windowed_df["window_time"], unit="s").astype(str)
    windowed_df = windowed_df.sort_values(by="window_time").reset_index(drop=True)
    return windowed_df

def aggregate_csecicids2018_windows(
    csv_path: str,
    window_sec: int = 60,
    label_rule: LabelRule = "any_attack",
    fill_empty_windows: bool = True
) -> pd.DataFrame:
    """
    Aggregate CSE-CIC-IDS2018 flow records into fixed time windows.
    Computes cloud network SRE telemetry: rates, volumes, flag counts, and port diversity.
    If fill_empty_windows is True, generates a complete regular time grid filling quiescent
    windows with zero-count telemetry and benign label (0).
    """
    print(f"Reading CSE-CIC-IDS2018 from {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    
    # Prune embedded header rows if any
    header_mask = df["Timestamp"] == "Timestamp"
    if header_mask.any():
        df = df[~header_mask].copy().reset_index(drop=True)

    # Parse timestamps
    df["dt"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.dropna(subset=["dt"]).copy()
    
    # Second epoch
    epoch_sec = (df["dt"] - pd.Timestamp("1970-01-01")) // pd.Timedelta("1s")
    df["window_time"] = (epoch_sec // window_sec) * window_sec

    # Coerce numerics
    numeric_cols = [
        "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
        "Flow Byts/s", "Flow Pkts/s", "SYN Flag Cnt", "RST Flag Cnt", "ACK Flag Cnt", "Pkt Len Mean"
    ]
    for c in numeric_cols:
        if c in df.columns:
            s = pd.to_numeric(df[c], errors="coerce")
            s = s.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            df[c] = s

    # Binary label (0 = Benign, 1 = Attack)
    df["is_attack"] = (df["Label"] != "Benign").astype(int)

    # Window aggregations
    grouped = df.groupby("window_time", as_index=False)
    
    win_features = grouped.agg(
        flow_count=("is_attack", "count"),
        attack_count=("is_attack", "sum"),
        tot_fwd_pkts=("Tot Fwd Pkts", "sum"),
        tot_bwd_pkts=("Tot Bwd Pkts", "sum"),
        tot_fwd_bytes=("TotLen Fwd Pkts", "sum"),
        tot_bwd_bytes=("TotLen Bwd Pkts", "sum"),
        flow_duration_mean=("Flow Duration", "mean"),
        flow_byts_s_mean=("Flow Byts/s", "mean"),
        flow_pkts_s_mean=("Flow Pkts/s", "mean"),
        syn_flags_total=("SYN Flag Cnt", "sum"),
        rst_flags_total=("RST Flag Cnt", "sum"),
        ack_flags_total=("ACK Flag Cnt", "sum"),
        pkt_len_mean=("Pkt Len Mean", "mean"),
        unique_dst_ports=("Dst Port", "nunique")
    )

    win_features["attack_ratio"] = win_features["attack_count"] / win_features["flow_count"]
    win_features["Label_any"] = (win_features["attack_count"] > 0).astype(int)
    win_features["Label_majority"] = (win_features["attack_ratio"] > 0.5).astype(int)
    win_features["Label_ratio10"] = (win_features["attack_ratio"] >= 0.10).astype(int)

    if label_rule == "any_attack":
        win_features["Label"] = win_features["Label_any"]
    elif label_rule == "majority":
        win_features["Label"] = win_features["Label_majority"]
    elif label_rule == "ratio_10":
        win_features["Label"] = win_features["Label_ratio10"]
    else:
        raise ValueError(f"Unknown label_rule: {label_rule}")

    if fill_empty_windows and not win_features.empty:
        t_min = int(win_features["window_time"].min())
        t_max = int(win_features["window_time"].max())
        full_grid = pd.DataFrame({"window_time": np.arange(t_min, t_max + window_sec, window_sec, dtype=np.int64)})
        win_features = pd.merge(full_grid, win_features, on="window_time", how="left")
        
        int_cols = [
            "flow_count", "attack_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
            "syn_flags_total", "rst_flags_total", "ack_flags_total", "unique_dst_ports",
            "Label_any", "Label_majority", "Label_ratio10", "Label"
        ]
        for c in int_cols:
            if c in win_features.columns:
                win_features[c] = win_features[c].fillna(0).astype(int)
                
        float_cols = [
            "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean", "pkt_len_mean", "attack_ratio"
        ]
        for c in float_cols:
            if c in win_features.columns:
                win_features[c] = win_features[c].fillna(0.0).astype(float)

    win_features["window_dt"] = pd.to_datetime(win_features["window_time"], unit="s").astype(str)
    win_features = win_features.sort_values(by="window_time").reset_index(drop=True)
    return win_features
