"""
Stage 1.5 Step 4: Primary Shared Threshold Rule & Threshold-Free Evaluation Pipeline
Implements:
1. Primary threshold rule for ALL score-based methods (A, A-prime, ARIMA residual, Isolation Forest):
   Threshold calibrated on BENIGN validation scores such that FAR <= alpha for alpha in {0.01, 0.05}.
   Zero F1 optimization, zero attack label leakage.
2. Reports threshold-free metrics FIRST: ROC-AUC, PR-AUC, Prevalence, PR-AUC Lift over prevalence.
   Followed by fixed-alpha operating points (alpha = 0.05, 0.01) with achieved test FPR, Recall, F1, SRE metrics.
3. Config B1 (Adaptive MAD): Epsilon floor (1e-6) added, zero_mad_fraction logged.
4. Matched-operating-point comparison: honest one-sided FPR rule (FPR <= alpha) with zero-recall audit.
"""

import os
import sys
import time
import json
import hashlib
import platform
import warnings
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score, confusion_matrix, precision_score, recall_score, f1_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.adaptive_threshold import MADThreshold, EVTThreshold, calibrate_benign_quantile_threshold
from src.persistence_filter import PersistenceFilter
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline,
    RandomUniformBaseline, RandomStratifiedBaseline
)
from src.evaluation import (
    compute_classification_metrics,
    compute_sre_operational_metrics,
    compute_clopper_pearson_ci,
    find_campaign_intervals
)
from src.preprocessing import load_and_sort_raw_unsw, UNSWPreprocessor

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

FEATURE_COLS_UNSW_WINDOW = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss"
]

OUTPUT_METRICS_DIR = "results/v3_1/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v3_1/predictions"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)

class ResourceProfiler:
    def __enter__(self):
        self.start_time = time.time()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed_seconds = time.time() - self.start_time

def evaluate_block_under_shared_threshold(
    block_name: str,
    dataset_name: str,
    design_type: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    timestamps_test: np.ndarray,
    step_sec: float = 60.0,
    subseq_len_m: int = 10,
    seed: int = 42,
    is_flow_data: bool = False
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    n_train = len(X_train)
    n_val = len(X_val)
    n_test = len(X_test)
    total_len = n_train + n_val + n_test

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)
    X_full = np.vstack([X_train, X_val, X_test])

    prevalence = float(np.mean(y_test))
    all_attack_f1 = float(f1_score(y_test, np.ones_like(y_test), zero_division=0))

    # Pre-compute anomaly scores for all models
    model_scores = {}

    # 1. Trivial baselines
    all_atk = AllAttackBaseline().fit(X_train, y_train)
    model_scores["Baseline: All-Attack"] = (all_atk.score_samples(X_val), all_atk.score_samples(X_test))

    all_norm = AllNormalBaseline().fit(X_train, y_train)
    model_scores["Baseline: All-Normal"] = (all_norm.score_samples(X_val), all_norm.score_samples(X_test))

    rand_u = RandomUniformBaseline(seed=seed).fit(X_train, y_train)
    model_scores["Baseline: Random Uniform"] = (rand_u.score_samples(X_val), rand_u.score_samples(X_test))

    rand_s = RandomStratifiedBaseline(seed=seed).fit(X_train, y_train)
    model_scores["Baseline: Random Stratified"] = (rand_s.score_samples(X_val), rand_s.score_samples(X_test))

    # 2. ML Baselines
    if_model = IsolationForestBaseline(n_estimators=100, random_state=seed)
    if_model.fit(X_train)
    model_scores["Baseline: Isolation Forest"] = (if_model.score_samples(X_val), if_model.score_samples(X_test))

    ar_model = ARIMAResidualBaseline(order=(1, 0, 1))
    ar_model.fit(X_train)
    model_scores["Baseline: ARIMA Residual"] = (ar_model.score_samples(X_val), ar_model.score_samples(X_test))

    # 3. Config A: mSTAMP + Kneedle
    effective_m = max(3, min(subseq_len_m, n_train - 1))
    mps_full, _ = compute_multidimensional_mp(X_full, m=effective_m)
    mps_tr_val = mps_full[:, : n_train + n_val - effective_m + 1]
    knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
    scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=effective_m)
    scores_val_a = scores_full_a[val_slice]
    scores_test_a = scores_full_a[test_slice]
    model_scores["Config A (mSTAMP+Kneedle)"] = (scores_val_a, scores_test_a)

    # 4. Config A-prime: Causal AB
    X_train_benign = X_train if np.all(y_train == 0) else X_train[y_train == 0]
    if len(X_train_benign) < effective_m:
        X_train_benign = X_train[:effective_m * 2]
    aprime_scorer = CausalABScorer(m=effective_m)
    aprime_scorer.fit(X_train_benign)
    scores_val_aprime = aprime_scorer.score(X_val)
    scores_test_aprime = aprime_scorer.score(X_test)
    model_scores["Config A-prime (Causal AB)"] = (scores_val_aprime, scores_test_aprime)

    # Normal history for B1 and B2
    scores_train_a = scores_full_a[:n_train]
    train_normal_scores = scores_train_a[y_train == 0] if (y_train == 0).sum() > 0 else scores_train_a
    val_normal_scores = scores_val_a[y_val == 0] if (y_val == 0).sum() > 0 else scores_val_a
    hist_normal = np.concatenate([train_normal_scores, val_normal_scores])

    # Now evaluate every model
    results = []
    mad_logs = []

    # Map of models
    models_list = [
        "Baseline: Isolation Forest",
        "Baseline: ARIMA Residual",
        "Config A (mSTAMP+Kneedle)",
        "Config A-prime (Causal AB)",
        "Config B1 (Adaptive MAD)",
        "Config B2 (Adaptive EVT)",
        "Config C (A-prime, k=2)",
        "Config C (B1, k=2)",
        "Config C (B2, k=2)",
        "Baseline: All-Attack",
        "Baseline: All-Normal",
        "Baseline: Random Uniform",
        "Baseline: Random Stratified"
    ]

    for model_name in models_list:
        # Determine threshold-free metrics
        if model_name in model_scores:
            s_val, s_test = model_scores[model_name]
            clean_test = np.nan_to_num(s_test)
            if len(np.unique(y_test)) > 1 and not np.all(clean_test == clean_test[0]):
                try:
                    roc_auc = float(roc_auc_score(y_test, clean_test))
                except Exception:
                    roc_auc = None
                try:
                    pr_auc = float(average_precision_score(y_test, clean_test))
                except Exception:
                    pr_auc = None
            else:
                roc_auc = 0.5 if np.all(clean_test == clean_test[0]) else None
                pr_auc = prevalence
            pr_lift = float((pr_auc - prevalence) / prevalence) if (pr_auc is not None and prevalence > 0) else 0.0
        elif "B1" in model_name or "B2" in model_name:
            # Operates on Config A scores
            s_val, s_test = model_scores["Config A (mSTAMP+Kneedle)"]
            roc_auc = float(roc_auc_score(y_test, s_test)) if len(np.unique(y_test)) > 1 else None
            pr_auc = float(average_precision_score(y_test, s_test)) if len(np.unique(y_test)) > 1 else None
            pr_lift = float((pr_auc - prevalence) / prevalence) if (pr_auc is not None and prevalence > 0) else 0.0
        elif "A-prime" in model_name:
            s_val, s_test = model_scores["Config A-prime (Causal AB)"]
            roc_auc = float(roc_auc_score(y_test, s_test)) if len(np.unique(y_test)) > 1 else None
            pr_auc = float(average_precision_score(y_test, s_test)) if len(np.unique(y_test)) > 1 else None
            pr_lift = float((pr_auc - prevalence) / prevalence) if (pr_auc is not None and prevalence > 0) else 0.0
        else:
            roc_auc = None
            pr_auc = None
            pr_lift = None

        record = {
            "Block": block_name,
            "Dataset": dataset_name,
            "Design": design_type,
            "Model": model_name,
            "Prevalence": prevalence,
            "ROC_AUC": roc_auc,
            "PR_AUC": pr_auc,
            "PR_AUC_Lift": pr_lift
        }

        # Evaluate at fixed alpha = 0.05 and alpha = 0.01
        for alpha in [0.05, 0.01]:
            alpha_tag = f"{int(alpha*100):02d}"

            if model_name == "Baseline: All-Attack":
                pred_test = np.ones(n_test, dtype=int)
                thresh_val = 1.0
            elif model_name == "Baseline: All-Normal":
                pred_test = np.zeros(n_test, dtype=int)
                thresh_val = 1.0
            elif model_name == "Baseline: Random Uniform":
                np.random.seed(seed)
                pred_test = (np.random.uniform(0, 1, size=n_test) >= (1.0 - alpha)).astype(int)
                thresh_val = 1.0 - alpha
            elif model_name == "Baseline: Random Stratified":
                np.random.seed(seed)
                pred_test = (np.random.uniform(0, 1, size=n_test) < np.mean(y_train)).astype(int)
                thresh_val = 0.5
            elif model_name in ["Baseline: Isolation Forest", "Baseline: ARIMA Residual", "Config A (mSTAMP+Kneedle)", "Config A-prime (Causal AB)"]:
                s_val_m, s_test_m = model_scores[model_name]
                thresh_val = calibrate_benign_quantile_threshold(s_val_m, y_val, alpha=alpha)
                pred_test = (s_test_m >= thresh_val).astype(int)
            elif model_name == "Config B1 (Adaptive MAD)":
                # Find multiplier c on benign validation scores to enforce FAR <= alpha
                benign_mask_val = (y_val == 0)
                rolling_w = min(20, max(5, n_val // 2))
                best_c = 3.0
                best_mad = None
                for c_cand in [1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]:
                    mad_cand = MADThreshold(c=c_cand, rolling_window=rolling_w, eps=1e-6)
                    mad_cand.fit(hist_normal)
                    p_val = mad_cand.predict(scores_val_a)
                    emp_far = float(np.mean(p_val[benign_mask_val] == 1)) if np.any(benign_mask_val) else 0.0
                    if emp_far <= alpha:
                        best_c = c_cand
                        best_mad = mad_cand
                        break
                if best_mad is None:
                    best_c = 5.0
                    best_mad = MADThreshold(c=5.0, rolling_window=rolling_w, eps=1e-6).fit(hist_normal)

                pred_test = best_mad.predict(scores_test_a)
                thresh_val = best_c

                mad_logs.append({
                    "Block": block_name,
                    "Design": design_type,
                    "Alpha": alpha,
                    "Chosen_Multiplier_C": best_c,
                    "Zero_MAD_Fraction": best_mad.zero_mad_fraction_
                })
            elif model_name == "Config B2 (Adaptive EVT)":
                evt = EVTThreshold(q=0.80, risk_p=alpha, min_excesses=30)
                evt.fit(hist_normal)
                pred_test = evt.predict(scores_test_a)
                thresh_val = evt.threshold_
            elif model_name == "Config C (A-prime, k=2)":
                s_val_aprime, s_test_aprime = model_scores["Config A-prime (Causal AB)"]
                th_aprime = calibrate_benign_quantile_threshold(s_val_aprime, y_val, alpha=alpha)
                raw_pred = (s_test_aprime >= th_aprime).astype(int)
                pred_test = PersistenceFilter(k=2).filter(raw_pred)
                thresh_val = th_aprime
            elif model_name == "Config C (B1, k=2)":
                benign_mask_val = (y_val == 0)
                rolling_w = min(20, max(5, n_val // 2))
                best_c = 3.0
                best_mad = None
                for c_cand in [1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]:
                    mad_cand = MADThreshold(c=c_cand, rolling_window=rolling_w, eps=1e-6)
                    mad_cand.fit(hist_normal)
                    p_val = mad_cand.predict(scores_val_a)
                    emp_far = float(np.mean(p_val[benign_mask_val] == 1)) if np.any(benign_mask_val) else 0.0
                    if emp_far <= alpha:
                        best_c = c_cand
                        best_mad = mad_cand
                        break
                if best_mad is None:
                    best_c = 5.0
                    best_mad = MADThreshold(c=5.0, rolling_window=rolling_w, eps=1e-6).fit(hist_normal)
                raw_pred = best_mad.predict(scores_test_a)
                pred_test = PersistenceFilter(k=2).filter(raw_pred)
                thresh_val = best_c
            elif model_name == "Config C (B2, k=2)":
                evt = EVTThreshold(q=0.80, risk_p=alpha, min_excesses=30).fit(hist_normal)
                raw_pred = evt.predict(scores_test_a)
                pred_test = PersistenceFilter(k=2).filter(raw_pred)
                thresh_val = evt.threshold_
            else:
                pred_test = np.zeros(n_test, dtype=int)
                thresh_val = 0.0

            # Classification metrics
            tn, fp, fn, tp = confusion_matrix(y_test, pred_test, labels=[0, 1]).ravel()
            prec = float(precision_score(y_test, pred_test, zero_division=0))
            rec = float(recall_score(y_test, pred_test, zero_division=0))
            f1 = float(f1_score(y_test, pred_test, zero_division=0))
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

            # SRE operational metrics
            sre_m = compute_sre_operational_metrics(y_test, pred_test, timestamps=timestamps_test, default_step_sec=step_sec)

            # Honest one-sided matched status with zero-recall audit
            if rec == 0.0 or (fpr == 0.0 and rec == 0.0):
                match_status = "unmatched (zero recall)"
            elif fpr <= alpha:
                match_status = "target met"
            else:
                match_status = "target not reached"

            record[f"Threshold_{alpha_tag}"] = thresh_val
            record[f"Achieved_FPR_{alpha_tag}"] = fpr
            record[f"Achieved_Recall_{alpha_tag}"] = rec
            record[f"Precision_{alpha_tag}"] = prec
            record[f"F1_{alpha_tag}"] = f1
            record[f"Alerts_Per_1000_{alpha_tag}"] = sre_m["alerts_per_1000_windows"]
            record[f"Alerts_Per_Hour_{alpha_tag}"] = sre_m["alerts_per_hour"] if not is_flow_data else None
            record[f"Campaign_Recall_{alpha_tag}"] = sre_m["campaign_recall"]
            record[f"MTTD_{alpha_tag}"] = sre_m["mttd_detected_campaigns_only_sec"]
            record[f"Match_Status_{alpha_tag}"] = match_status

        results.append(record)

    return results, mad_logs

def run_all_shared_threshold_evaluations():
    start_time = time.time()
    seed = 42

    print("=" * 80)
    print("STAGE 1.5 STEP 4: PRIMARY SHARED THRESHOLD RULE EVALUATION")
    print("FAR <= alpha (alpha in {0.05, 0.01}) on Benign Validation Scores")
    print("=" * 80)

    all_results = []
    all_mad_logs = []

    # 1. CSE-CIC-IDS2018 Cross-Day (Primary Design)
    with open("configs/v3_1/cse_cic_ids2018_cross_day.json") as f:
        cross_day_cfg = json.load(f)

    for b in cross_day_cfg["blocks"]:
        name = b.get("name", b.get("day"))
        print(f"\nEvaluating CSE Cross-Day Primary: {name}...")
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

        y_tr = ref_sub["Label"].values.astype(int)
        y_va = val_sub["Label"].values.astype(int)
        y_te = test_sub["Label"].values.astype(int)
        t_te = test_sub["window_time"].values

        res, mad_log = evaluate_block_under_shared_threshold(
            block_name=name,
            dataset_name="CSE-CIC-IDS2018",
            design_type="Cross-Day Primary",
            X_train=X_tr, y_train=y_tr,
            X_val=X_va, y_val=y_va,
            X_test=X_te, y_test=y_te,
            timestamps_test=t_te,
            step_sec=60.0,
            subseq_len_m=10,
            seed=seed,
            is_flow_data=False
        )
        all_results.extend(res)
        all_mad_logs.extend(mad_log)

    # 2. CSE-CIC-IDS2018 Within-Day (Sensitivity Design)
    with open("configs/v3_1/cse_cic_ids2018_within_day.json") as f:
        within_day_cfg = json.load(f)

    for b in within_day_cfg["blocks"]:
        name = b.get("name", b.get("day"))
        print(f"\nEvaluating CSE Within-Day Sensitivity: {name}...")
        df_day = pd.read_parquet(b["file"])
        tr_sub = df_day.iloc[b["train_slice"][0]:b["train_slice"][1]]
        va_sub = df_day.iloc[b["val_slice"][0]:b["val_slice"][1]]
        te_sub = df_day.iloc[b["test_slice"][0]:b["test_slice"][1]]

        scaler = StandardScaler()
        X_tr = scaler.fit_transform(np.nan_to_num(tr_sub[FEATURE_COLS_CSE].values.astype(float)))
        X_va = scaler.transform(np.nan_to_num(va_sub[FEATURE_COLS_CSE].values.astype(float)))
        X_te = scaler.transform(np.nan_to_num(te_sub[FEATURE_COLS_CSE].values.astype(float)))

        y_tr = tr_sub["Label"].values.astype(int)
        y_va = va_sub["Label"].values.astype(int)
        y_te = te_sub["Label"].values.astype(int)
        t_te = te_sub["window_time"].values

        res, mad_log = evaluate_block_under_shared_threshold(
            block_name=name,
            dataset_name="CSE-CIC-IDS2018",
            design_type="Within-Day Sensitivity",
            X_train=X_tr, y_train=y_tr,
            X_val=X_va, y_val=y_va,
            X_test=X_te, y_test=y_te,
            timestamps_test=t_te,
            step_sec=60.0,
            subseq_len_m=10,
            seed=seed,
            is_flow_data=False
        )
        all_results.extend(res)
        all_mad_logs.extend(mad_log)

    # 3. UNSW-NB15 Blocks
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

            res, mad_log = evaluate_block_under_shared_threshold(
                block_name=name,
                dataset_name="UNSW-NB15",
                design_type="Window Block",
                X_train=X_tr_w, y_train=y_tr_w,
                X_val=X_va_w, y_val=y_va_w,
                X_test=X_te_w, y_test=y_te_w,
                timestamps_test=t_te_w,
                step_sec=10.0,
                subseq_len_m=10,
                seed=seed,
                is_flow_data=False
            )
            all_results.extend(res)
            all_mad_logs.extend(mad_log)
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

            res, mad_log = evaluate_block_under_shared_threshold(
                block_name=name,
                dataset_name="UNSW-NB15",
                design_type="Flow Block",
                X_train=X_tr_fl, y_train=y_tr_fl,
                X_val=X_va_fl, y_val=y_va_fl,
                X_test=X_te_fl, y_test=y_te_fl,
                timestamps_test=t_te_fl,
                step_sec=1.0,
                subseq_len_m=5,
                seed=seed,
                is_flow_data=True
            )
            all_results.extend(res)
            all_mad_logs.extend(mad_log)

    # 4. Save results to results/v3_1/metrics/
    df_results = pd.DataFrame(all_results)
    out_csv = os.path.join(OUTPUT_METRICS_DIR, "threshold_free_and_fixed_alpha_results.csv")
    out_json = os.path.join(OUTPUT_METRICS_DIR, "threshold_free_and_fixed_alpha_results.json")
    df_results.to_csv(out_csv, index=False)
    df_results.to_json(out_json, orient="records", indent=2)

    df_mad = pd.DataFrame(all_mad_logs)
    mad_csv = os.path.join(OUTPUT_METRICS_DIR, "mad_zero_fraction_log.csv")
    mad_json = os.path.join(OUTPUT_METRICS_DIR, "mad_zero_fraction_log.json")
    df_mad.to_csv(mad_csv, index=False)
    df_mad.to_json(mad_json, orient="records", indent=2)

    print(f"\nSaved primary threshold rule results to {out_csv} and {mad_csv}")
    print(f"Total elapsed time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    run_all_shared_threshold_evaluations()
