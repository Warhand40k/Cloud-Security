"""
Preprocessing module for network flow data.
Enforces strict chronological ordering and zero data leakage.
"""

import os
import pickle
import pandas as pd
import numpy as np
from typing import Tuple, List, Optional, Dict
from sklearn.preprocessing import StandardScaler, RobustScaler

DEFAULT_RAW_DIR = "data/raw"
PAPER_FEATURES = ["sloss", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", "dloss", "service"]
CATEGORICAL_FEATURES = ["state", "service"]
NUMERIC_FEATURES = ["sloss", "dur", "sbytes", "dbytes", "sttl", "dttl", "dloss"]

def get_schema_columns(raw_dir: str = DEFAULT_RAW_DIR) -> List[str]:
    """Load column names from schema definition."""
    feat_path = os.path.join(raw_dir, "NUSW-NB15_features.csv")
    df_feat = pd.read_csv(feat_path, encoding="latin-1")
    return df_feat["Name"].str.strip().tolist()

def load_and_sort_raw_unsw(
    raw_dir: str = DEFAULT_RAW_DIR,
    file_indices: Optional[List[int]] = None,
    nrows: Optional[int] = None,
    selected_cols: Optional[List[str]] = None
) -> pd.DataFrame:
    """
    Load raw UNSW-NB15 CSV files and strictly sort by chronological timestamps.
    """
    col_names = get_schema_columns(raw_dir)
    col_map = {c.lower(): c for c in col_names}
    
    stime_col = col_map.get("stime", "Stime")
    ltime_col = col_map.get("ltime", "Ltime")
    label_col = col_map.get("label", "Label")
    attack_col = col_map.get("attack_cat", "attack_cat")

    if selected_cols is None:
        target_cols = [stime_col, ltime_col, label_col, attack_col]
        for pf in PAPER_FEATURES:
            actual = col_map[pf]
            if actual not in target_cols:
                target_cols.append(actual)
    else:
        target_cols = selected_cols

    if file_indices is None:
        file_indices = [1, 2, 3, 4]

    dfs = []
    for idx in file_indices:
        fpath = os.path.join(raw_dir, f"UNSW-NB15_{idx}.csv")
        if not os.path.exists(fpath):
            raise FileNotFoundError(f"Raw data file not found: {fpath}")
        df_chunk = pd.read_csv(
            fpath,
            header=None,
            names=col_names,
            usecols=target_cols,
            nrows=nrows,
            low_memory=False,
            encoding="latin-1"
        )
        dfs.append(df_chunk)

    df_full = pd.concat(dfs, ignore_index=True)

    # Clean missing/whitespace markers
    for cat_col in CATEGORICAL_FEATURES:
        if cat_col in df_full.columns:
            df_full[cat_col] = df_full[cat_col].astype(str).str.strip()
            # Standardize empty or missing markers
            df_full[cat_col] = df_full[cat_col].replace({"": "-", "?": "-", "#DIV/0!": "-"})

    # Sort strictly chronologically by Stime, then Ltime
    df_sorted = df_full.sort_values(by=[stime_col, ltime_col]).reset_index(drop=True)
    return df_sorted

def split_chronological(
    df: pd.DataFrame,
    train_frac: float = 0.60,
    val_frac: float = 0.20,
    test_frac: float = 0.20
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Strict chronological split without shuffling.
    Train: [0 : N_train]
    Val:   [N_train : N_train + N_val]
    Test:  [N_train + N_val : N]
    """
    assert np.isclose(train_frac + val_frac + test_frac, 1.0), "Fractions must sum to 1.0"
    n = len(df)
    n_train = int(n * train_frac)
    n_val = int(n * val_frac)
    
    train_df = df.iloc[:n_train].copy().reset_index(drop=True)
    val_df = df.iloc[n_train:n_train + n_val].copy().reset_index(drop=True)
    test_df = df.iloc[n_train + n_val:].copy().reset_index(drop=True)
    
    return train_df, val_df, test_df

class UNSWPreprocessor:
    """
    Preprocessor fitted strictly on training data to prevent data leakage.
    Encodes categoricals and scales numeric features.
    """
    def __init__(self, scaler_type: str = "standard"):
        self.scaler_type = scaler_type
        self.scaler = StandardScaler() if scaler_type == "standard" else RobustScaler()
        self.cat_mappings: Dict[str, Dict[str, int]] = {}
        self.numeric_modes: Dict[str, float] = {}
        self.feature_columns = PAPER_FEATURES.copy()

    def fit(self, train_df: pd.DataFrame):
        """Fit encodings and scalers on training split only."""
        # Categorical mappings
        for col in CATEGORICAL_FEATURES:
            if col in train_df.columns:
                unique_vals = sorted(train_df[col].dropna().unique().tolist())
                # Reserve 0 for unknown/unseen
                mapping = {val: idx + 1 for idx, val in enumerate(unique_vals)}
                mapping["<UNK>"] = 0
                self.cat_mappings[col] = mapping

        # Numeric statistics for missing replacement and scaling
        for col in NUMERIC_FEATURES:
            if col in train_df.columns:
                self.numeric_modes[col] = float(train_df[col].mode().iloc[0])

        num_vals = train_df[NUMERIC_FEATURES].fillna(self.numeric_modes).values
        self.scaler.fit(num_vals)
        return self

    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Transform features and return (X, y) array tuple.
        Labels are returned separately and never touch feature transformations.
        """
        df_copy = df.copy()
        
        # Categorical encoding with UNK fallback
        cat_encoded_cols = []
        for col in CATEGORICAL_FEATURES:
            if col in df_copy.columns:
                mapping = self.cat_mappings.get(col, {})
                encoded = df_copy[col].map(lambda x: mapping.get(x, 0)).values
                cat_encoded_cols.append(encoded.reshape(-1, 1))

        # Numeric imputation & scaling
        for col in NUMERIC_FEATURES:
            if col in df_copy.columns:
                df_copy[col] = df_copy[col].fillna(self.numeric_modes.get(col, 0.0))

        num_scaled = self.scaler.transform(df_copy[NUMERIC_FEATURES].values)

        if cat_encoded_cols:
            cats = np.hstack(cat_encoded_cols)
            X = np.hstack([num_scaled, cats])
        else:
            X = num_scaled

        # Separate labels
        if "Label" in df_copy.columns:
            y = df_copy["Label"].values.astype(int)
        elif "label" in df_copy.columns:
            y = df_copy["label"].values.astype(int)
        else:
            y = np.zeros(len(df_copy), dtype=int)

        return X, y

    def fit_transform(self, train_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        return self.fit(train_df).transform(train_df)

    def save(self, filepath: str):
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, filepath: str) -> "UNSWPreprocessor":
        with open(filepath, "rb") as f:
            return pickle.load(f)

