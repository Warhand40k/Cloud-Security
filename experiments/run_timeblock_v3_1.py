"""
Comprehensive Rolling-Origin Time-Block Evaluation (Stage 1.5 - Phase 5):
Evaluates:
- CSE-CIC-IDS2018 Multi-Day Blocks (Thursday 15, Friday 16, Wednesday 21) on regular 60s grid
- UNSW-NB15 Small Regime-Shift Block (Batch 1 -> Batch 2, explicitly labeled, no conclusions drawn)
- UNSW-NB15 Regime Shift Demonstration (explicitly labeled Batch 2 saturation)
- UNSW-NB15 Flow Contiguous Block (Batch 1 flows)

Models Evaluated:
- Trivial Baselines: All-Attack, All-Normal, Random-Uniform, Random-Stratified
- ML Baselines: Isolation Forest (IF), ARIMA Residual (AR)
- Config A: mSTAMP + Kneedle (paper reproduction self-join)
- Config A-prime: Causal AB-join Scorer (benign reference)
- Config B1: Adaptive MAD Threshold
- Config B2: Adaptive EVT Peaks-Over-Threshold
- Config C: Persistence Filter named by parent: C(B1, k), C(B2, k), C(A-prime, k)

Outputs:
- Strictly to results/v3_1/ (metrics/, predictions/, figures/)
- Records full provenance: git commit, config hash, package versions, hardware, seed
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import platform
from typing import Optional, Dict, Any, List, Tuple
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.adaptive_threshold import MADThreshold, EVTThreshold
from src.persistence_filter import PersistenceFilter
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline,
    RandomUniformBaseline, RandomStratifiedBaseline
)
from src.evaluation import (
    compute_classification_metrics,
    compute_sre_operational_metrics,
    compute_bootstrap_confidence_intervals,
    find_campaign_intervals,
    ResourceProfiler
)
from src.preprocessing import load_and_sort_raw_unsw, split_chronological, UNSWPreprocessor

OUTPUT_METRICS_DIR = "results/v3_1/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v3_1/predictions"
OUTPUT_FIGURES_DIR = "results/v3_1/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

FEATURE_COLS_UNSW_WINDOW = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss"
]

def get_git_commit():
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return "unknown"

def hash_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def evaluate_partition(
    block_name: str,
    dataset_name: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    timestamps_test: Optional[np.ndarray],
    step_sec: float = 60.0,
    subseq_len_m: int = 10,
    seed: int = 42,
    is_flow_data: bool = False,
    output_predictions_dir: str = OUTPUT_PREDICTIONS_DIR
):
    """
    Evaluates all models on a single time block with strictly causal, leakage-free validation selection.
    """
    n_train = len(X_train)
    n_val = len(X_val)
    n_test = len(X_test)
    total_len = n_train + n_val + n_test

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)

    # Full series for Config A self-join (paper reproduction)
    X_full = np.vstack([X_train, X_val, X_test])

    results = []
    predictions_dict = {"y_true": y_test}
    val_predictions_dict = {"y_true": y_val}

    all_attack_f1 = float(f1_score(y_test, np.ones_like(y_test), zero_division=0))

    def record_metrics(
        model_name: str,
        model_type: str,
        pred_test: np.ndarray,
        scores_test: Optional[np.ndarray],
        runtime: float = 0.0,
        pred_val: Optional[np.ndarray] = None,
        scores_val: Optional[np.ndarray] = None
    ):
        predictions_dict[f"{model_name}_pred"] = pred_test
        if scores_test is not None:
            predictions_dict[f"{model_name}_score"] = scores_test
        if pred_val is not None:
            val_predictions_dict[f"{model_name}_pred"] = pred_val
        if scores_val is not None:
            val_predictions_dict[f"{model_name}_score"] = scores_val

        cls_m = compute_classification_metrics(y_test, pred_test, scores_test)
        sre_m = compute_sre_operational_metrics(
            y_test, pred_test, timestamps_test, default_step_sec=step_sec, is_flow_data=is_flow_data
        )
        boot = compute_bootstrap_confidence_intervals(
            y_test, pred_test, scores_test, timestamps_test,
            n_bootstraps=500, seed=seed, default_step_sec=step_sec, block_size=subseq_len_m
        )

        record = {
            "Block": block_name,
            "Dataset": dataset_name,
            "Model": model_name,
            "Type": model_type,
            "ROC_AUC": cls_m["roc_auc"],
            "PR_AUC": cls_m["pr_auc"],
            "PR_AUC_CI_Low": boot["pr_auc_ci"][0],
            "PR_AUC_CI_High": boot["pr_auc_ci"][1],
            "Prevalence": cls_m["prevalence"],
            "PR_AUC_Lift": cls_m["pr_auc_lift"],
            "Precision": cls_m["precision"],
            "Recall": cls_m["recall"],
            "F1": cls_m["f1"],
            "F1_CI_Low": boot["f1_ci"][0],
            "F1_CI_High": boot["f1_ci"][1],
            "FPR": cls_m["fpr"],
            "Total_Campaigns": sre_m["total_campaigns"],
            "Campaigns_Detected": sre_m["campaigns_detected"],
            "Campaign_Recall": sre_m["campaign_recall"],
            "Campaign_Recall_CI_Low": sre_m.get("campaign_recall_ci_low"),
            "Campaign_Recall_CI_High": sre_m.get("campaign_recall_ci_high"),
            "Campaign_Recall_Ratio": sre_m.get("campaign_recall_ratio", f"{sre_m['campaigns_detected']}/{sre_m['total_campaigns']}"),
            "MTTD_Detected_Sec": sre_m["mttd_detected_campaigns_only_sec"],
            "MTTD_CI_Low": boot["mttd_ci"][0],
            "MTTD_CI_High": boot["mttd_ci"][1],
            "Total_Alerts": sre_m["total_alerts"],
            "Alerts_Per_1000_Windows": sre_m["alerts_per_1000_windows"],
            "Alerts_Per_Hour": sre_m["alerts_per_hour"],
            "Runtime_Sec": runtime,
            "Test_Samples": n_test,
            "Val_Samples": n_val,
            "Train_Samples": n_train,
            "Beats_All_Attack_F1": "yes" if cls_m["f1"] > all_attack_f1 else "no"
        }
        results.append(record)
        return record

    # 1. TRIVIAL BASELINES
    all_atk = AllAttackBaseline().fit(X_train, y_train)
    record_metrics("Baseline: All-Attack", "Trivial", all_atk.predict(X_test), all_atk.score_samples(X_test), 0.0, all_atk.predict(X_val), all_atk.score_samples(X_val))

    all_norm = AllNormalBaseline().fit(X_train, y_train)
    record_metrics("Baseline: All-Normal", "Trivial", all_norm.predict(X_test), all_norm.score_samples(X_test), 0.0, all_norm.predict(X_val), all_norm.score_samples(X_val))

    rand_u = RandomUniformBaseline(seed=seed).fit(X_train, y_train)
    record_metrics("Baseline: Random Uniform", "Trivial", rand_u.predict(X_test), rand_u.score_samples(X_test), 0.0, rand_u.predict(X_val), rand_u.score_samples(X_val))

    rand_s = RandomStratifiedBaseline(seed=seed).fit(X_train, y_train)
    record_metrics("Baseline: Random Stratified", "Trivial", rand_s.predict(X_test), rand_s.score_samples(X_test), 0.0, rand_s.predict(X_val), rand_s.score_samples(X_val))

    # 2. MACHINE LEARNING BASELINES
    with ResourceProfiler() as prof_if:
        if_model = IsolationForestBaseline(n_estimators=100, random_state=seed)
        if_model.fit(X_train)
        if_model.calibrate_threshold(X_val, y_val)
    record_metrics(
        "Baseline: Isolation Forest", "ML Baseline",
        if_model.predict(X_test), if_model.score_samples(X_test), prof_if.elapsed_seconds,
        if_model.predict(X_val), if_model.score_samples(X_val)
    )

    with ResourceProfiler() as prof_ar:
        ar_model = ARIMAResidualBaseline(order=(1, 0, 1))
        ar_model.fit(X_train)
        ar_model.calibrate_threshold(X_val, y_val)
    record_metrics(
        "Baseline: ARIMA Residual", "ML Baseline",
        ar_model.predict(X_test), ar_model.score_samples(X_test), prof_ar.elapsed_seconds,
        ar_model.predict(X_val), ar_model.score_samples(X_val)
    )

    # 3. CONFIG A: mSTAMP + Kneedle (Paper reproduction self-join)
    effective_m = max(3, min(subseq_len_m, n_train - 1))
    with ResourceProfiler() as prof_a:
        mps_full, _ = compute_multidimensional_mp(X_full, m=effective_m)
        mps_tr_val = mps_full[:, : n_train + n_val - effective_m + 1]
        knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
        scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=effective_m)

    scores_val_a = scores_full_a[val_slice]
    scores_test_a = scores_full_a[test_slice]

    val_percentiles = np.linspace(80, 99.8, 80)
    best_thresh_a = float(np.median(scores_val_a))
    best_f1_val_a = -1.0
    for p in val_percentiles:
        th = float(np.percentile(scores_val_a, p))
        f1_v = compute_classification_metrics(y_val, (scores_val_a >= th).astype(int))["f1"]
        if f1_v > best_f1_val_a:
            best_f1_val_a = f1_v
            best_thresh_a = th

    pred_test_a = (scores_test_a >= best_thresh_a).astype(int)
    pred_val_a = (scores_val_a >= best_thresh_a).astype(int)
    record_metrics("Config A (mSTAMP+Kneedle)", "Paper Reproduction", pred_test_a, scores_test_a, prof_a.elapsed_seconds, pred_val_a, scores_val_a)

    # 4. CONFIG A-PRIME: Causal AB-Join Scorer (Benign reference history)
    if np.all(y_train == 0):
        X_train_benign = X_train
    else:
        X_train_benign = X_train[y_train == 0]
        if len(X_train_benign) < effective_m:
            X_train_benign = X_train[:effective_m * 2]

    with ResourceProfiler() as prof_aprime:
        aprime_scorer = CausalABScorer(m=effective_m)
        aprime_scorer.fit(X_train_benign)
        scores_val_aprime = aprime_scorer.score(X_val)
        scores_test_aprime = aprime_scorer.score(X_test)

    best_thresh_aprime = float(np.median(scores_val_aprime))
    best_f1_val_aprime = -1.0
    for p in val_percentiles:
        th = float(np.percentile(scores_val_aprime, p))
        f1_v = compute_classification_metrics(y_val, (scores_val_aprime >= th).astype(int))["f1"]
        if f1_v > best_f1_val_aprime:
            best_f1_val_aprime = f1_v
            best_thresh_aprime = th

    pred_test_aprime = (scores_test_aprime >= best_thresh_aprime).astype(int)
    pred_val_aprime = (scores_val_aprime >= best_thresh_aprime).astype(int)
    record_metrics("Config A-prime (Causal AB)", "Causal Extension", pred_test_aprime, scores_test_aprime, prof_aprime.elapsed_seconds, pred_val_aprime, scores_val_aprime)

    # 5. CONFIG B1: Adaptive MAD Threshold
    scores_train_a = scores_full_a[:n_train]
    train_normal_scores = scores_train_a[y_train == 0] if (y_train == 0).sum() > 0 else scores_train_a
    val_normal_scores = scores_val_a[y_val == 0] if (y_val == 0).sum() > 0 else scores_val_a
    hist_normal = np.concatenate([train_normal_scores, val_normal_scores])

    best_c = 2.5
    best_f1_b1 = -1.0
    for c_cand in [1.5, 2.0, 2.5, 3.0, 3.5]:
        mad_cand = MADThreshold(c=c_cand, rolling_window=min(20, max(5, n_val // 2)))
        mad_cand.fit(hist_normal)
        f1_v = compute_classification_metrics(y_val, mad_cand.predict(scores_val_a))["f1"]
        if f1_v > best_f1_b1:
            best_f1_b1 = f1_v
            best_c = c_cand

    mad_model = MADThreshold(c=best_c, rolling_window=min(20, max(5, n_val // 2)))
    mad_model.fit(hist_normal)
    pred_test_b1 = mad_model.predict(scores_test_a)
    record_metrics("Config B1 (Adaptive MAD)", "Extension", pred_test_b1, scores_test_a, 0.0, mad_model.predict(scores_val_a), scores_val_a)

    # 6. CONFIG B2: Adaptive EVT Peaks-Over-Threshold
    raw_risks = [0.10, 0.05, 0.02, 0.01, 0.005, 0.001]
    best_risk = 0.01
    best_f1_b2 = -1.0
    for r_cand in raw_risks:
        evt_cand = EVTThreshold(q=0.80, risk_p=r_cand, min_excesses=30)
        evt_cand.fit(hist_normal)
        f1_v = compute_classification_metrics(y_val, evt_cand.predict(scores_val_a))["f1"]
        if f1_v > best_f1_b2:
            best_f1_b2 = f1_v
            best_risk = r_cand

    evt_model = EVTThreshold(q=0.80, risk_p=best_risk, min_excesses=30)
    evt_model.fit(hist_normal)
    pred_test_b2 = evt_model.predict(scores_test_a)
    record_metrics("Config B2 (Adaptive EVT)", "Extension", pred_test_b2, scores_test_a, 0.0, evt_model.predict(scores_val_a), scores_val_a)

    # 7. CONFIG C: Persistence Filters Named by Parent C(B1, k), C(B2, k), C(A-prime, k)
    # C(B1, k)
    base_val_alarms_b1 = mad_model.predict(scores_val_a)
    best_k_b1 = 1
    best_f1_c_b1 = -1.0
    for k_cand in [1, 2, 3, 4, 5]:
        pf_cand = PersistenceFilter(k=k_cand)
        f1_v = compute_classification_metrics(y_val, pf_cand.filter(base_val_alarms_b1))["f1"]
        if f1_v > best_f1_c_b1:
            best_f1_c_b1 = f1_v
            best_k_b1 = k_cand
    pers_model_b1 = PersistenceFilter(k=best_k_b1)
    pred_test_c_b1 = pers_model_b1.filter(pred_test_b1)
    record_metrics(f"Config C (B1, k={best_k_b1})", "Extension", pred_test_c_b1, scores_test_a, 0.0, pers_model_b1.filter(base_val_alarms_b1), scores_val_a)

    # C(B2, k)
    base_val_alarms_b2 = evt_model.predict(scores_val_a)
    best_k_b2 = 1
    best_f1_c_b2 = -1.0
    for k_cand in [1, 2, 3, 4, 5]:
        pf_cand = PersistenceFilter(k=k_cand)
        f1_v = compute_classification_metrics(y_val, pf_cand.filter(base_val_alarms_b2))["f1"]
        if f1_v > best_f1_c_b2:
            best_f1_c_b2 = f1_v
            best_k_b2 = k_cand
    pers_model_b2 = PersistenceFilter(k=best_k_b2)
    pred_test_c_b2 = pers_model_b2.filter(pred_test_b2)
    record_metrics(f"Config C (B2, k={best_k_b2})", "Extension", pred_test_c_b2, scores_test_a, 0.0, pers_model_b2.filter(base_val_alarms_b2), scores_val_a)

    # C(A-prime, k)
    base_val_alarms_ap = (scores_val_aprime >= best_thresh_aprime).astype(int)
    best_k_ap = 1
    best_f1_c_ap = -1.0
    for k_cand in [1, 2, 3, 4, 5]:
        pf_cand = PersistenceFilter(k=k_cand)
        f1_v = compute_classification_metrics(y_val, pf_cand.filter(base_val_alarms_ap))["f1"]
        if f1_v > best_f1_c_ap:
            best_f1_c_ap = f1_v
            best_k_ap = k_cand
    pers_model_ap = PersistenceFilter(k=best_k_ap)
    pred_test_c_ap = pers_model_ap.filter(pred_test_aprime)
    record_metrics(f"Config C (A-prime, k={best_k_ap})", "Extension", pred_test_c_ap, scores_test_aprime, 0.0, pers_model_ap.filter(base_val_alarms_ap), scores_val_aprime)

    # Save predictions
    pred_df = pd.DataFrame(predictions_dict)
    clean_block_name = block_name.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
    os.makedirs(output_predictions_dir, exist_ok=True)
    pred_df.to_parquet(os.path.join(output_predictions_dir, f"preds_{clean_block_name}.parquet"))

    val_pred_df = pd.DataFrame(val_predictions_dict)
    val_pred_df.to_parquet(os.path.join(output_predictions_dir, f"preds_val_{clean_block_name}.parquet"))

    return results

def run_all_timeblock_evaluations():
    print("=" * 80)
    print("STARTING STAGE 1.5 ROLLING-ORIGIN TIME-BLOCK EVALUATION (v3_1)")
    print("=" * 80)

    start_time = time.time()
    git_hash = get_git_commit()
    seed = 42

    all_records = []

    # 1. CSE-CIC-IDS2018 Multi-Day Blocks (Regular 60s grid)
    with open("configs/v3_1/cse_cic_ids2018_multiday.json") as f:
        cse_cfg = json.load(f)

    for b in cse_cfg["blocks"]:
        day_name = b["day"]
        print(f"\nEvaluating CSE-CIC Block: {day_name}...")
        df = pd.read_parquet(b["file"])
        train_df = df.iloc[b["train_slice"][0]:b["train_slice"][1]]
        val_df = df.iloc[b["val_slice"][0]:b["val_slice"][1]]
        test_df = df.iloc[b["test_slice"][0]:b["test_slice"][1]]

        raw_tr = np.nan_to_num(train_df[FEATURE_COLS_CSE].values.astype(float))
        raw_va = np.nan_to_num(val_df[FEATURE_COLS_CSE].values.astype(float))
        raw_te = np.nan_to_num(test_df[FEATURE_COLS_CSE].values.astype(float))

        scaler = StandardScaler()
        X_train = scaler.fit_transform(raw_tr)
        X_val = scaler.transform(raw_va)
        X_test = scaler.transform(raw_te)

        y_train = train_df["Label"].values.astype(int)
        y_val = val_df["Label"].values.astype(int)
        y_test = test_df["Label"].values.astype(int)

        t_test = test_df["window_time"].values

        print(f"  Train: N={len(X_train)} (attacks={y_train.sum()}, {y_train.mean()*100:.1f}%)")
        print(f"  Val:   N={len(X_val)} (attacks={y_val.sum()}, {y_val.mean()*100:.1f}%)")
        print(f"  Test:  N={len(X_test)} (attacks={y_test.sum()}, {y_test.mean()*100:.1f}%)")

        res = evaluate_partition(
            block_name=day_name,
            dataset_name="CSE-CIC-IDS2018",
            X_train=X_train, y_train=y_train,
            X_val=X_val, y_val=y_val,
            X_test=X_test, y_test=y_test,
            timestamps_test=t_test,
            step_sec=60.0,
            subseq_len_m=10,
            seed=seed,
            is_flow_data=False
        )
        all_records.extend(res)

    # 2. UNSW-NB15 Blocks
    with open("configs/v3_1/unsw_nb15.json") as f:
        unsw_cfg = json.load(f)

    for b in unsw_cfg["blocks"]:
        name = b["name"]
        is_flow = b.get("is_flow_data", False)
        print(f"\nEvaluating UNSW Block: {name}...")

        if not is_flow:
            df_unsw_win = pd.read_parquet(b["file"])
            tr_win = df_unsw_win.iloc[b["train_slice"][0]:b["train_slice"][1]]
            va_win = df_unsw_win.iloc[b["val_slice"][0]:b["val_slice"][1]]
            te_win = df_unsw_win.iloc[b["test_slice"][0]:b["test_slice"][1]]

            scaler_w = StandardScaler()
            X_tr_w = scaler_w.fit_transform(np.nan_to_num(tr_win[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
            X_va_w = scaler_w.transform(np.nan_to_num(va_win[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
            X_te_w = scaler_w.transform(np.nan_to_num(te_win[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))

            y_tr_w = tr_win["Label"].values.astype(int)
            y_va_w = va_win["Label"].values.astype(int)
            y_te_w = te_win["Label"].values.astype(int)
            t_te_w = te_win["window_time"].values

            print(f"  Train: N={len(X_tr_w)} (attacks={y_tr_w.sum()}, {y_tr_w.mean()*100:.1f}%)")
            print(f"  Val:   N={len(X_va_w)} (attacks={y_va_w.sum()}, {y_va_w.mean()*100:.1f}%)")
            print(f"  Test:  N={len(X_te_w)} (attacks={y_te_w.sum()}, {y_te_w.mean()*100:.1f}%)")

            res_unsw = evaluate_partition(
                block_name=name,
                dataset_name="UNSW-NB15",
                X_train=X_tr_w, y_train=y_tr_w,
                X_val=X_va_w, y_val=y_va_w,
                X_test=X_te_w, y_test=y_te_w,
                timestamps_test=t_te_w,
                step_sec=10.0,
                subseq_len_m=10,
                seed=seed,
                is_flow_data=False
            )
            all_records.extend(res_unsw)
        else:
            df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=15000)
            df_flow = df_raw.iloc[:b["n_samples"]].copy().reset_index(drop=True)
            n_tr = int(b["train_frac"] * len(df_flow))
            n_va = int(b["val_frac"] * len(df_flow))
            tr_fl = df_flow.iloc[0:n_tr]
            va_fl = df_flow.iloc[n_tr:n_tr+n_va]
            te_fl = df_flow.iloc[n_tr+n_va:len(df_flow)]

            prep_fl = UNSWPreprocessor(scaler_type="standard")
            prep_fl.fit(tr_fl)
            X_tr_fl, y_tr_fl = prep_fl.transform(tr_fl)
            X_va_fl, y_va_fl = prep_fl.transform(va_fl)
            X_te_fl, y_te_fl = prep_fl.transform(te_fl)

            time_col = "Stime" if "Stime" in te_fl.columns else "stime"
            t_te_fl = te_fl[time_col].values

            print(f"  Train: N={len(X_tr_fl)} (attacks={y_tr_fl.sum()}, {y_tr_fl.mean()*100:.1f}%)")
            print(f"  Val:   N={len(X_va_fl)} (attacks={y_va_fl.sum()}, {y_va_fl.mean()*100:.1f}%)")
            print(f"  Test:  N={len(X_te_fl)} (attacks={y_te_fl.sum()}, {y_te_fl.mean()*100:.1f}%)")

            res_unsw_fl = evaluate_partition(
                block_name=name,
                dataset_name="UNSW-NB15",
                X_train=X_tr_fl, y_train=y_tr_fl,
                X_val=X_va_fl, y_val=y_va_fl,
                X_test=X_te_fl, y_test=y_te_fl,
                timestamps_test=t_te_fl,
                step_sec=1.0,
                subseq_len_m=5,
                seed=seed,
                is_flow_data=True
            )
            all_records.extend(res_unsw_fl)

    # 3. Save Summary and Detailed Files
    res_df = pd.DataFrame(all_records)
    detailed_csv = os.path.join(OUTPUT_METRICS_DIR, "timeblock_v3_1_detailed.csv")
    detailed_json = os.path.join(OUTPUT_METRICS_DIR, "timeblock_v3_1_detailed.json")
    res_df.to_csv(detailed_csv, index=False)
    res_df.to_json(detailed_json, orient="records", indent=2)

    # Per-dataset tables
    cse_results = res_df[res_df["Dataset"] == "CSE-CIC-IDS2018"].copy()
    cse_results.to_csv(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_multiday_results.csv"), index=False)
    cse_results.to_json(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_multiday_results.json"), orient="records", indent=2)

    unsw_results = res_df[res_df["Dataset"] == "UNSW-NB15"].copy()
    unsw_results.to_csv(os.path.join(OUTPUT_METRICS_DIR, "unsw_nb15_results.csv"), index=False)
    unsw_results.to_json(os.path.join(OUTPUT_METRICS_DIR, "unsw_nb15_results.json"), orient="records", indent=2)

    # CSE Summary across days
    cse_summary = cse_results.groupby(["Model", "Type"]).agg({
        "F1": ["mean", "std"],
        "PR_AUC": ["mean", "std"],
        "ROC_AUC": ["mean", "std"],
        "Recall": "mean",
        "Precision": "mean",
        "FPR": "mean",
        "Campaign_Recall": "mean",
        "Alerts_Per_1000_Windows": "mean",
        "Alerts_Per_Hour": "mean",
        "MTTD_Detected_Sec": "mean",
        "Runtime_Sec": "mean"
    }).reset_index()
    cse_summary.columns = [f"{col[0]}_{col[1]}" if col[1] else col[0] for col in cse_summary.columns]
    summary_csv = os.path.join(OUTPUT_METRICS_DIR, "timeblock_v3_1_cse_summary.csv")
    summary_json = os.path.join(OUTPUT_METRICS_DIR, "timeblock_v3_1_cse_summary.json")
    cse_summary.to_csv(summary_csv, index=False)
    cse_summary.to_json(summary_json, orient="records", indent=2)

    # Manifest
    manifest = {
        "git_commit": git_hash,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "random_seed": seed,
        "runtime_total_seconds": float(time.time() - start_time),
        "configs": {
            "cse_cic_ids2018_multiday": "configs/v3_1/cse_cic_ids2018_multiday.json",
            "cse_cic_ids2018_hash": hash_file("configs/v3_1/cse_cic_ids2018_multiday.json"),
            "unsw_nb15": "configs/v3_1/unsw_nb15.json",
            "unsw_nb15_hash": hash_file("configs/v3_1/unsw_nb15.json")
        },
        "environment": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count()
        },
        "package_versions": {
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scipy": sys.modules.get("scipy", type(sys)) .__version__ if "scipy" in sys.modules else "unknown",
            "sklearn": sys.modules.get("sklearn", type(sys)).__version__ if "sklearn" in sys.modules else "unknown"
        }
    }
    manifest_path = os.path.join(OUTPUT_METRICS_DIR, "timeblock_v3_1_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nAll results saved to {OUTPUT_METRICS_DIR} and {OUTPUT_PREDICTIONS_DIR}")
    print(f"Total evaluation runtime: {manifest['runtime_total_seconds']:.2f} seconds")

if __name__ == "__main__":
    run_all_timeblock_evaluations()

