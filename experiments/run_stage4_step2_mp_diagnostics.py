"""
Stage 4 Step 2: Matrix Profile Score Degeneracy and Diagnostic Audit Pipeline
Analyzes:
1. Score Degeneracy for Config A and Config A-prime across:
   (a) Testbed
   (b) UNSW Flow Contiguous Block
   (c) CSE-CIC-IDS2018 days (Thursday, Friday Cross-Day & Within-Day, Wednesday Cross-Day & Within-Day)
   Reports: Unique scores count, zero fraction, NaN/inf fraction, ROC-AUC, PR-AUC vs prevalence.
2. Per-feature channel analysis: variance in train, fraction of constant subsequences of length m.
3. Diagnostic variants (labeled "diagnostic variant"):
   (i) Drop zero-variance channels
   (ii) Smooth count features with rolling mean (w=3)
   (iii) Non-z-normalized distance (normalize=False)
   (iv) Larger m
   Reports: ROC-AUC, PR-AUC, achieved FPR and recall at alpha=0.05 and alpha=0.01.
4. Comprehensive audit of the "Saturation Cure" (benign quantile rule + epsilon floor on MAD):
   Reports recall, FPR, F1, ROC-AUC on UNSW Flow and Regime-Shift blocks.

Outputs saved strictly to results/v4/metrics/
"""

import os
import sys
import json
import time
import socket
import platform
import subprocess
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score, confusion_matrix, precision_score, recall_score, f1_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.adaptive_threshold import MADThreshold, calibrate_benign_quantile_threshold
from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor

OUTPUT_METRICS_DIR = "results/v4/metrics"
OUTPUT_FIGURES_DIR = "results/v4/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

FEATURE_COLS_UNSW_WINDOW = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss"
]

FEATURE_COLS_TESTBED = [
    "flow_count", "tot_fwd_bytes", "tot_bwd_bytes", "duration_mean",
    "status_200_count", "status_4xx_count", "status_5xx_count",
    "error_rate", "p50_latency", "p95_latency", "p99_latency"
]

def save_run_metadata(step_name: str):
    try:
        git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    except Exception:
        git_commit = "unknown"

    meta = {
        "step": step_name,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit,
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "hostname": socket.gethostname(),
        "package_versions": {
            "numpy": np.__version__,
            "pandas": pd.__version__
        }
    }
    meta_path = os.path.join("results/v4", f"run_metadata_{step_name}.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Recorded run metadata to {meta_path}")

def fraction_constant_subsequences(series: np.ndarray, m: int, eps: float = 1e-10) -> float:
    """Fraction of sliding subsequences of length m that have standard deviation < eps."""
    n = len(series)
    if n < m:
        return 0.0
    # Rolling standard deviation
    s = pd.Series(series)
    roll_std = s.rolling(m).std().dropna().values
    return float(np.mean(roll_std < eps))

def load_all_datasets():
    print("Loading all evaluation datasets...")
    datasets = {}

    # 1. Testbed
    tb_df = pd.read_parquet("data/testbed/testbed_60s_regular.parquet")
    tr_tb = tb_df.iloc[0:200]
    va_tb = tb_df.iloc[200:300]
    te_tb = tb_df.iloc[300:600]
    sc_tb = StandardScaler()
    X_tr_tb = sc_tb.fit_transform(np.nan_to_num(tr_tb[FEATURE_COLS_TESTBED].values.astype(float)))
    X_va_tb = sc_tb.transform(np.nan_to_num(va_tb[FEATURE_COLS_TESTBED].values.astype(float)))
    X_te_tb = sc_tb.transform(np.nan_to_num(te_tb[FEATURE_COLS_TESTBED].values.astype(float)))
    datasets["Testbed"] = {
        "dataset_name": "Testbed",
        "block_name": "Microservice_Live_Testbed",
        "design": "Testbed",
        "X_train": X_tr_tb, "y_train": tr_tb["Label"].values.astype(int),
        "X_val": X_va_tb, "y_val": va_tb["Label"].values.astype(int),
        "X_test": X_te_tb, "y_test": te_tb["Label"].values.astype(int),
        "feature_names": FEATURE_COLS_TESTBED,
        "raw_train": tr_tb[FEATURE_COLS_TESTBED].values.astype(float),
        "default_m": 10,
        "count_features": ["flow_count", "tot_fwd_bytes", "tot_bwd_bytes", "status_200_count", "status_4xx_count", "status_5xx_count"]
    }

    # 2. UNSW Flow Contiguous Block
    df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=15000)
    df_flow = df_raw.iloc[:8000].copy().reset_index(drop=True)
    tr_fl, va_fl, te_fl = split_chronological(df_flow, train_frac=0.60, val_frac=0.20, test_frac=0.20)
    prep_fl = UNSWPreprocessor(scaler_type="standard")
    prep_fl.fit(tr_fl)
    X_tr_fl, y_tr_fl = prep_fl.transform(tr_fl)
    X_va_fl, y_va_fl = prep_fl.transform(va_fl)
    X_te_fl, y_te_fl = prep_fl.transform(te_fl)
    flow_feat_names = ["sloss", "dur", "sbytes", "dbytes", "sttl", "dttl", "dloss", "state", "service"]
    datasets["UNSW_Flow"] = {
        "dataset_name": "UNSW-NB15",
        "block_name": "UNSW_Flow_Contiguous_Block",
        "design": "Flow_Block",
        "X_train": X_tr_fl, "y_train": y_tr_fl,
        "X_val": X_va_fl, "y_val": y_va_fl,
        "X_test": X_te_fl, "y_test": y_te_fl,
        "feature_names": flow_feat_names,
        "raw_train": X_tr_fl, # already numeric
        "default_m": 5,
        "count_features": ["sloss", "sbytes", "dbytes", "dloss"]
    }

    # 3. CSE-CIC-IDS2018 Cross-Day Primary
    with open("configs/v3_1/cse_cic_ids2018_cross_day.json") as f:
        cse_cross_cfg = json.load(f)

    for b in cse_cross_cfg["blocks"]:
        day = b["day"]
        df_ref = pd.read_parquet(b["reference_file"])
        df_val = pd.read_parquet(b["val_file"])
        df_test = pd.read_parquet(b["test_file"])

        ref_sub = df_ref.iloc[b["reference_slice"][0]:b["reference_slice"][1]]
        val_sub = df_val.iloc[b["val_slice"][0]:b["val_slice"][1]]
        test_sub = df_test.iloc[b["test_slice"][0]:b["test_slice"][1]]

        scaler = StandardScaler()
        X_tr = scaler.fit_transform(np.nan_to_num(ref_sub[FEATURE_COLS_CSE].values.astype(float)))
        X_va = scaler.transform(np.nan_to_num(val_sub[FEATURE_COLS_CSE].values.astype(float)))
        X_te = scaler.transform(np.nan_to_num(test_sub[FEATURE_COLS_CSE].values.astype(float)))

        key = f"CSE_{day}_Cross-Day"
        datasets[key] = {
            "dataset_name": "CSE-CIC-IDS2018",
            "block_name": day,
            "design": "Cross-Day_Primary",
            "X_train": X_tr, "y_train": ref_sub["Label"].values.astype(int),
            "X_val": X_va, "y_val": val_sub["Label"].values.astype(int),
            "X_test": X_te, "y_test": test_sub["Label"].values.astype(int),
            "feature_names": FEATURE_COLS_CSE,
            "raw_train": ref_sub[FEATURE_COLS_CSE].values.astype(float),
            "default_m": 10,
            "count_features": ["flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes", "syn_flags_total", "rst_flags_total", "ack_flags_total"]
        }

    # 4. CSE-CIC-IDS2018 Within-Day Sensitivity (Friday and Wednesday)
    with open("configs/v3_1/cse_cic_ids2018_within_day.json") as f:
        cse_within_cfg = json.load(f)

    for b in cse_within_cfg["blocks"]:
        day = b["day"]
        if day == "Thursday-15-02-2018":
            continue # identical to cross-day
        df_day = pd.read_parquet(b["file"])
        tr_sub = df_day.iloc[b["train_slice"][0]:b["train_slice"][1]]
        va_sub = df_day.iloc[b["val_slice"][0]:b["val_slice"][1]]
        te_sub = df_day.iloc[b["test_slice"][0]:b["test_slice"][1]]

        scaler = StandardScaler()
        X_tr = scaler.fit_transform(np.nan_to_num(tr_sub[FEATURE_COLS_CSE].values.astype(float)))
        X_va = scaler.transform(np.nan_to_num(va_sub[FEATURE_COLS_CSE].values.astype(float)))
        X_te = scaler.transform(np.nan_to_num(te_sub[FEATURE_COLS_CSE].values.astype(float)))

        key = f"CSE_{day}_Within-Day"
        datasets[key] = {
            "dataset_name": "CSE-CIC-IDS2018",
            "block_name": day,
            "design": "Within-Day_Sensitivity",
            "X_train": X_tr, "y_train": tr_sub["Label"].values.astype(int),
            "X_val": X_va, "y_val": va_sub["Label"].values.astype(int),
            "X_test": X_te, "y_test": te_sub["Label"].values.astype(int),
            "feature_names": FEATURE_COLS_CSE,
            "raw_train": tr_sub[FEATURE_COLS_CSE].values.astype(float),
            "default_m": 10,
            "count_features": ["flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes", "syn_flags_total", "rst_flags_total", "ack_flags_total"]
        }

    # 5. UNSW Window Regime Shift Demonstration & Small Regime Shift
    df_unsw_win = pd.read_parquet("data/processed/unsw_nb15_10s_any_attack.parquet")
    # Small Regime-Shift
    tr_srs = df_unsw_win.iloc[2000:4000]
    va_srs = df_unsw_win.iloc[4000:4470]
    te_srs = df_unsw_win.iloc[4470:4535]
    sc_srs = StandardScaler()
    X_tr_srs = sc_srs.fit_transform(np.nan_to_num(tr_srs[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
    X_va_srs = sc_srs.transform(np.nan_to_num(va_srs[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
    X_te_srs = sc_srs.transform(np.nan_to_num(te_srs[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
    datasets["UNSW_Window_Small_Regime_Shift"] = {
        "dataset_name": "UNSW-NB15",
        "block_name": "UNSW_Window_Small_Regime-Shift_Block",
        "design": "Window_Block",
        "X_train": X_tr_srs, "y_train": tr_srs["Label"].values.astype(int),
        "X_val": X_va_srs, "y_val": va_srs["Label"].values.astype(int),
        "X_test": X_te_srs, "y_test": te_srs["Label"].values.astype(int),
        "feature_names": FEATURE_COLS_UNSW_WINDOW,
        "raw_train": tr_srs[FEATURE_COLS_UNSW_WINDOW].values.astype(float),
        "default_m": 10,
        "count_features": ["sbytes", "dbytes", "sloss", "dloss"]
    }

    # Regime Shift Demo
    tr_rsd = df_unsw_win.iloc[1200:3200]
    va_rsd = df_unsw_win.iloc[3200:4600]
    te_rsd = df_unsw_win.iloc[4600:5800]
    sc_rsd = StandardScaler()
    X_tr_rsd = sc_rsd.fit_transform(np.nan_to_num(tr_rsd[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
    X_va_rsd = sc_rsd.transform(np.nan_to_num(va_rsd[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
    X_te_rsd = sc_rsd.transform(np.nan_to_num(te_rsd[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
    datasets["UNSW_Window_Regime_Shift_Demo"] = {
        "dataset_name": "UNSW-NB15",
        "block_name": "UNSW_Window_Regime_Shift_Demonstration",
        "design": "Window_Block",
        "X_train": X_tr_rsd, "y_train": tr_rsd["Label"].values.astype(int),
        "X_val": X_va_rsd, "y_val": va_rsd["Label"].values.astype(int),
        "X_test": X_te_rsd, "y_test": te_rsd["Label"].values.astype(int),
        "feature_names": FEATURE_COLS_UNSW_WINDOW,
        "raw_train": tr_rsd[FEATURE_COLS_UNSW_WINDOW].values.astype(float),
        "default_m": 10,
        "count_features": ["sbytes", "dbytes", "sloss", "dloss"]
    }

    return datasets

def run_step2_analysis():
    datasets = load_all_datasets()

    # =========================================================================
    # PART 1: SCORE DEGENERACY AUDIT (Unique values, % Zero, NaN/Inf, ROC/PR)
    # =========================================================================
    print("\n" + "=" * 80)
    print("STEP 2.1: MATRIX PROFILE SCORE DEGENERACY AUDIT")
    print("=" * 80)

    degeneracy_records = []

    for key, dinfo in datasets.items():
        block_name = dinfo["block_name"]
        design = dinfo["design"]
        dataset_name = dinfo["dataset_name"]
        m = dinfo["default_m"]
        X_tr = dinfo["X_train"]
        y_tr = dinfo["y_train"]
        X_va = dinfo["X_val"]
        y_va = dinfo["y_val"]
        X_te = dinfo["X_test"]
        y_te = dinfo["y_test"]

        n_train, n_val, n_test = len(X_tr), len(X_va), len(X_te)
        total_len = n_train + n_val + n_test
        val_slice = slice(n_train, n_train + n_val)
        test_slice = slice(n_train + n_val, total_len)
        X_full = np.vstack([X_tr, X_va, X_te])

        prevalence = float(np.mean(y_te))

        print(f"\n---> Analyzing Score Degeneracy for: {key} (m={m})")

        # 1. Config A: mSTAMP + Kneedle
        mps_full, _ = compute_multidimensional_mp(X_full, m=m)
        mps_tr_val = mps_full[:, : n_train + n_val - m + 1]
        knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
        scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=m)
        scores_test_a = scores_full_a[test_slice]
        scores_val_a = scores_full_a[val_slice]

        # 2. Config A-prime: Causal AB
        X_tr_benign = X_tr[y_tr == 0] if (y_tr == 0).sum() > 0 else X_tr
        if len(X_tr_benign) < m:
            X_tr_benign = X_tr[:m * 2]
        aprime_scorer = CausalABScorer(m=m).fit(X_tr_benign)
        scores_test_aprime = aprime_scorer.score(X_te)
        scores_val_aprime = aprime_scorer.score(X_va)

        models = [
            ("Config A (mSTAMP+Kneedle)", scores_test_a, scores_val_a),
            ("Config A-prime (Causal AB)", scores_test_aprime, scores_val_aprime)
        ]

        for m_name, s_test, s_val in models:
            n_unique = int(len(np.unique(s_test)))
            frac_unique = float(n_unique / len(s_test))
            frac_zero_test = float(np.mean(s_test == 0.0))
            frac_zero_val = float(np.mean(s_val == 0.0))
            frac_nan_inf = float(np.mean(~np.isfinite(s_test)))

            # ROC & PR
            clean_mask = np.isfinite(s_test)
            if np.unique(y_te[clean_mask]).size > 1:
                roc_auc = float(roc_auc_score(y_te[clean_mask], s_test[clean_mask]))
                pr_auc = float(average_precision_score(y_te[clean_mask], s_test[clean_mask]))
                pr_lift = float((pr_auc - prevalence) / prevalence) if prevalence > 0 else 0.0
            else:
                roc_auc = 0.50
                pr_auc = prevalence
                pr_lift = 0.0

            # Tie fraction: top 1 most frequent score frequency
            vals, counts = np.unique(s_test, return_counts=True)
            max_tie_frac = float(np.max(counts) / len(s_test))

            degeneracy_records.append({
                "Dataset": dataset_name,
                "Block": block_name,
                "Design": design,
                "Model": m_name,
                "Subsequence_m": m,
                "Test_Samples": len(s_test),
                "Unique_Scores_Count": n_unique,
                "Unique_Score_Fraction": frac_unique,
                "Max_Tie_Fraction": max_tie_frac,
                "Fraction_Exactly_Zero_Test": frac_zero_test,
                "Fraction_Exactly_Zero_Val": frac_zero_val,
                "Fraction_NaN_Inf": frac_nan_inf,
                "Prevalence": prevalence,
                "ROC_AUC": roc_auc,
                "PR_AUC": pr_auc,
                "PR_AUC_Lift": pr_lift
            })

    df_degen = pd.DataFrame(degeneracy_records)
    degen_csv = os.path.join(OUTPUT_METRICS_DIR, "matrix_profile_score_degeneracy.csv")
    df_degen.to_csv(degen_csv, index=False)
    print(f"\nSaved matrix profile score degeneracy report to {degen_csv}")

    # =========================================================================
    # PART 2: PER-FEATURE CHANNEL VARIANCE AND CONSTANT SUBSEQUENCES
    # =========================================================================
    print("\n" + "=" * 80)
    print("STEP 2.2: PER-FEATURE CHANNEL VARIANCE & CONSTANCY ANALYSIS")
    print("=" * 80)

    channel_records = []

    for key, dinfo in datasets.items():
        block_name = dinfo["block_name"]
        design = dinfo["design"]
        dataset_name = dinfo["dataset_name"]
        m = dinfo["default_m"]
        raw_tr = dinfo["raw_train"]
        feat_names = dinfo["feature_names"]

        for idx, col_name in enumerate(feat_names):
            series_tr = raw_tr[:, idx]
            var_tr = float(np.var(series_tr))
            std_tr = float(np.std(series_tr))
            frac_const_subseq = fraction_constant_subsequences(series_tr, m=m)
            is_zero_variance = bool(var_tr < 1e-12)
            is_constant_benign = bool(frac_const_subseq > 0.90)

            channel_records.append({
                "Dataset": dataset_name,
                "Block": block_name,
                "Design": design,
                "Feature_Index": idx,
                "Feature_Name": col_name,
                "Subsequence_m": m,
                "Train_Variance": var_tr,
                "Train_Std": std_tr,
                "Frac_Constant_Subsequences_m": frac_const_subseq,
                "Is_Zero_Variance": is_zero_variance,
                "Is_Constant_Benign_90pct": is_constant_benign
            })

    df_channels = pd.DataFrame(channel_records)
    chan_csv = os.path.join(OUTPUT_METRICS_DIR, "feature_channel_variance_and_constancy.csv")
    df_channels.to_csv(chan_csv, index=False)
    print(f"Saved feature channel constancy report to {chan_csv}")

    # Print channels that are constant in benign data
    constant_channels = df_channels[df_channels["Is_Constant_Benign_90pct"]][["Block", "Design", "Feature_Name", "Train_Variance", "Frac_Constant_Subsequences_m"]]
    print("\nChannels with >90% constant subsequences in training data:")
    print(constant_channels.to_string(index=False))

    # =========================================================================
    # PART 3: DIAGNOSTIC VARIANTS (Drop zero-var, Smooth counts, Non-z-norm, Larger m)
    # =========================================================================
    print("\n" + "=" * 80)
    print("STEP 2.3: DIAGNOSTIC VARIANTS EVALUATION")
    print("=" * 80)

    variant_records = []

    target_blocks = [
        "Testbed", "UNSW_Flow", "CSE_Thursday-15-02-2018_Cross-Day",
        "CSE_Friday-16-02-2018_Cross-Day", "CSE_Wednesday-21-02-2018_Cross-Day"
    ]

    for key in target_blocks:
        dinfo = datasets[key]
        block_name = dinfo["block_name"]
        design = dinfo["design"]
        dataset_name = dinfo["dataset_name"]
        m_base = dinfo["default_m"]
        feat_names = dinfo["feature_names"]
        raw_tr = dinfo["raw_train"].copy()

        # Identify zero-variance or >90% constant channels in train
        zero_var_cols = [
            i for i, f in enumerate(feat_names)
            if fraction_constant_subsequences(raw_tr[:, i], m=m_base) > 0.90 or np.var(raw_tr[:, i]) < 1e-12
        ]
        non_zero_cols = [i for i in range(len(feat_names)) if i not in zero_var_cols]

        # Count features for smoothing
        count_feat_names = dinfo.get("count_features", [])
        count_indices = [i for i, f in enumerate(feat_names) if f in count_feat_names]

        # Define diagnostic variants
        variants = []

        # 0. Baseline (frozen reproduction)
        variants.append(("Baseline Reproduction", dinfo["X_train"], dinfo["X_val"], dinfo["X_test"], m_base, True))

        # (i) Drop zero-variance channels (if any exist)
        if len(zero_var_cols) > 0 and len(non_zero_cols) >= 2:
            sc_drop = StandardScaler()
            X_tr_drop = sc_drop.fit_transform(dinfo["raw_train"][:, non_zero_cols])
            X_va_drop = sc_drop.transform(dinfo["X_val"][:, non_zero_cols]) if dinfo["raw_train"].shape == dinfo["X_val"].shape else dinfo["X_val"][:, non_zero_cols]
            X_te_drop = sc_drop.transform(dinfo["X_test"][:, non_zero_cols]) if dinfo["raw_train"].shape == dinfo["X_test"].shape else dinfo["X_test"][:, non_zero_cols]
            variants.append((f"diagnostic variant: drop {len(zero_var_cols)} constant channels", X_tr_drop, X_va_drop, X_te_drop, m_base, True))
        else:
            variants.append(("diagnostic variant: drop constant channels (none qualified)", dinfo["X_train"], dinfo["X_val"], dinfo["X_test"], m_base, True))

        # (ii) Smooth count features with rolling mean (w=3)
        raw_tr_smooth = dinfo["raw_train"].copy()
        raw_va_smooth = dinfo["X_val"].copy()
        raw_te_smooth = dinfo["X_test"].copy()
        for c_idx in count_indices:
            raw_tr_smooth[:, c_idx] = pd.Series(raw_tr_smooth[:, c_idx]).rolling(3, min_periods=1).mean().values
            raw_va_smooth[:, c_idx] = pd.Series(raw_va_smooth[:, c_idx]).rolling(3, min_periods=1).mean().values
            raw_te_smooth[:, c_idx] = pd.Series(raw_te_smooth[:, c_idx]).rolling(3, min_periods=1).mean().values
        sc_sm = StandardScaler()
        X_tr_sm = sc_sm.fit_transform(raw_tr_smooth)
        X_va_sm = sc_sm.transform(raw_va_smooth)
        X_te_sm = sc_sm.transform(raw_te_smooth)
        variants.append(("diagnostic variant: smooth count features (w=3)", X_tr_sm, X_va_sm, X_te_sm, m_base, True))

        # (iii) Non-z-normalized distance (STUMPY normalize=False)
        variants.append(("diagnostic variant: non-z-normalized distance", dinfo["X_train"], dinfo["X_val"], dinfo["X_test"], m_base, False))

        # (iv) Larger m
        larger_m = m_base * 2
        variants.append((f"diagnostic variant: larger m ({larger_m})", dinfo["X_train"], dinfo["X_val"], dinfo["X_test"], larger_m, True))

        y_tr = dinfo["y_train"]
        y_va = dinfo["y_val"]
        y_te = dinfo["y_test"]
        prevalence = float(np.mean(y_te))

        print(f"\n---> Evaluating Diagnostic Variants for {key}:")

        for v_name, X_tr_v, X_va_v, X_te_v, m_v, norm_flag in variants:
            n_tr, n_va, n_te = len(X_tr_v), len(X_va_v), len(X_te_v)
            tot_len = n_tr + n_va + n_te
            va_sl = slice(n_tr, n_tr + n_va)
            te_sl = slice(n_tr + n_va, tot_len)
            X_full_v = np.vstack([X_tr_v, X_va_v, X_te_v])

            # Config A
            try:
                mps_full, _ = compute_multidimensional_mp(X_full_v, m=m_v, normalize=norm_flag)
                mps_tr_va = mps_full[:, : n_tr + n_va - m_v + 1]
                knee_a, _ = find_knee_dimension(mps_tr_va, online=True, metric="max")
                scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_a, n_samples=tot_len, m=m_v)
                s_te_a = scores_full_a[te_sl]
                s_va_a = scores_full_a[va_sl]
            except Exception as e:
                s_te_a = np.zeros(n_te)
                s_va_a = np.zeros(n_va)

            # Config A-prime
            try:
                X_tr_b = X_tr_v[y_tr == 0] if (y_tr == 0).sum() > 0 else X_tr_v
                if len(X_tr_b) < m_v:
                    X_tr_b = X_tr_v[:m_v * 2]
                apr = CausalABScorer(m=m_v, normalize=norm_flag).fit(X_tr_b)
                s_te_apr = apr.score(X_te_v)
                s_va_apr = apr.score(X_va_v)
            except Exception as e:
                s_te_apr = np.zeros(n_te)
                s_va_apr = np.zeros(n_va)

            models = [
                ("Config A (mSTAMP+Kneedle)", s_te_a, s_va_a),
                ("Config A-prime (Causal AB)", s_te_apr, s_va_apr)
            ]

            for m_name, s_test, s_val in models:
                # Discrim metrics
                clean_mask = np.isfinite(s_test)
                if np.unique(y_te[clean_mask]).size > 1:
                    roc_auc = float(roc_auc_score(y_te[clean_mask], s_test[clean_mask]))
                    pr_auc = float(average_precision_score(y_te[clean_mask], s_test[clean_mask]))
                else:
                    roc_auc = 0.50
                    pr_auc = prevalence

                # Threshold calibration at alpha=0.05 and alpha=0.01
                th_05 = calibrate_benign_quantile_threshold(s_val, y_va, alpha=0.05)
                pred_05 = (s_test >= th_05).astype(int)
                rec_05 = float(recall_score(y_te, pred_05, zero_division=0))
                tn, fp, fn, tp = confusion_matrix(y_te, pred_05, labels=[0, 1]).ravel()
                fpr_05 = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

                th_01 = calibrate_benign_quantile_threshold(s_val, y_va, alpha=0.01)
                pred_01 = (s_test >= th_01).astype(int)
                rec_01 = float(recall_score(y_te, pred_01, zero_division=0))
                tn, fp, fn, tp = confusion_matrix(y_te, pred_01, labels=[0, 1]).ravel()
                fpr_01 = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

                variant_records.append({
                    "Dataset": dataset_name,
                    "Block": block_name,
                    "Design": design,
                    "Model": m_name,
                    "Variant_Type": v_name,
                    "Subsequence_m": m_v,
                    "Normalized": norm_flag,
                    "ROC_AUC": roc_auc,
                    "PR_AUC": pr_auc,
                    "Prevalence": prevalence,
                    "Achieved_FPR_a05": fpr_05,
                    "Recall_a05": rec_05,
                    "Achieved_FPR_a01": fpr_01,
                    "Recall_a01": rec_01
                })

    df_variants = pd.DataFrame(variant_records)
    var_csv = os.path.join(OUTPUT_METRICS_DIR, "matrix_profile_diagnostic_variants.csv")
    df_variants.to_csv(var_csv, index=False)
    print(f"\nSaved matrix profile diagnostic variants to {var_csv}")

    # =========================================================================
    # PART 4: COMPREHENSIVE AUDIT OF THE "SATURATION CURE"
    # =========================================================================
    print("\n" + "=" * 80)
    print("STEP 2.4: SATURATION CURE COMPREHENSIVE AUDIT (RECALL, FPR, ROC-AUC)")
    print("=" * 80)

    saturation_targets = [
        "UNSW_Flow", "UNSW_Window_Small_Regime_Shift", "UNSW_Window_Regime_Shift_Demo"
    ]

    sat_records = []

    for key in saturation_targets:
        dinfo = datasets[key]
        block_name = dinfo["block_name"]
        design = dinfo["design"]
        dataset_name = dinfo["dataset_name"]
        m = dinfo["default_m"]
        X_tr = dinfo["X_train"]
        y_tr = dinfo["y_train"]
        X_va = dinfo["X_val"]
        y_va = dinfo["y_val"]
        X_te = dinfo["X_test"]
        y_te = dinfo["y_test"]

        n_train, n_val, n_test = len(X_tr), len(X_va), len(X_te)
        total_len = n_train + n_val + n_test
        val_slice = slice(n_train, n_train + n_val)
        test_slice = slice(n_train + n_val, total_len)
        X_full = np.vstack([X_tr, X_va, X_te])
        prevalence = float(np.mean(y_te))

        # Config A
        mps_full, _ = compute_multidimensional_mp(X_full, m=m)
        mps_tr_val = mps_full[:, : n_train + n_val - m + 1]
        knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
        scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=m)
        s_te_a = scores_full_a[test_slice]
        s_va_a = scores_full_a[val_slice]

        # Config A-prime
        X_tr_b = X_tr[y_tr == 0] if (y_tr == 0).sum() > 0 else X_tr
        if len(X_tr_b) < m:
            X_tr_b = X_tr[:m * 2]
        aprime_scorer = CausalABScorer(m=m).fit(X_tr_b)
        s_te_apr = aprime_scorer.score(X_te)
        s_va_apr = aprime_scorer.score(X_va)

        models = [
            ("Config A (mSTAMP+Kneedle)", s_te_a, s_va_a),
            ("Config A-prime (Causal AB)", s_te_apr, s_va_apr)
        ]

        for m_name, s_test, s_val in models:
            roc_auc = float(roc_auc_score(y_te, s_test)) if len(np.unique(y_te)) > 1 else 0.50
            pr_auc = float(average_precision_score(y_te, s_test)) if len(np.unique(y_te)) > 1 else prevalence

            for alpha in [0.05, 0.01]:
                # 1. Benign Quantile Rule (with point-mass tie handling)
                th_quant = calibrate_benign_quantile_threshold(s_val, y_va, alpha=alpha)
                p_quant = (s_test >= th_quant).astype(int)
                tn, fp, fn, tp = confusion_matrix(y_te, p_quant, labels=[0, 1]).ravel()
                fpr_quant = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                rec_quant = float(recall_score(y_te, p_quant, zero_division=0))
                f1_quant = float(f1_score(y_te, p_quant, zero_division=0))

                # 2. Config B1: Rolling MAD with Epsilon Floor (c=3.0, eps=1e-6)
                mad_model = MADThreshold(c=3.0, rolling_window=min(60, max(10, len(s_val) // 4)), eps=1e-6)
                clean_va = s_val[y_va == 0] if (y_va == 0).sum() > 0 else s_val
                mad_model.fit(clean_va)
                p_mad = mad_model.predict(s_test)
                tn, fp, fn, tp = confusion_matrix(y_te, p_mad, labels=[0, 1]).ravel()
                fpr_mad = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                rec_mad = float(recall_score(y_te, p_mad, zero_division=0))
                f1_mad = float(f1_score(y_te, p_mad, zero_division=0))

                sat_records.append({
                    "Dataset": dataset_name,
                    "Block": block_name,
                    "Design": design,
                    "Model": m_name,
                    "Rule_Applied": f"Benign Quantile (alpha={alpha})",
                    "Threshold_Value": th_quant,
                    "Test_FPR": fpr_quant,
                    "Test_Recall": rec_quant,
                    "Test_F1": f1_quant,
                    "ROC_AUC": roc_auc,
                    "PR_AUC": pr_auc,
                    "Prevalence": prevalence
                })

                if alpha == 0.05:
                    sat_records.append({
                        "Dataset": dataset_name,
                        "Block": block_name,
                        "Design": design,
                        "Model": m_name,
                        "Rule_Applied": "MAD Threshold (c=3.0, eps=1e-6)",
                        "Threshold_Value": mad_model.threshold_,
                        "Test_FPR": fpr_mad,
                        "Test_Recall": rec_mad,
                        "Test_F1": f1_mad,
                        "ROC_AUC": roc_auc,
                        "PR_AUC": pr_auc,
                        "Prevalence": prevalence
                    })

    df_sat = pd.DataFrame(sat_records)
    sat_csv = os.path.join(OUTPUT_METRICS_DIR, "saturation_cure_comprehensive_audit.csv")
    df_sat.to_csv(sat_csv, index=False)
    print(f"Saved saturation cure comprehensive audit to {sat_csv}")

if __name__ == "__main__":
    save_run_metadata("step2")
    run_step2_analysis()

