"""
Cross-Day Primary Design vs Within-Day Sensitivity Analysis (Stage 1.5 Step 3):
Evaluates CSE-CIC-IDS2018 under:
1. Primary Cross-Day Design: Benign reference/training from earlier days (Thursday 15 pure benign).
   Enforces >= 100 training windows, >= 10*m library subsequences, ARIMA >= 100 points.
2. Secondary Within-Day Design: Morning pre-attack slice within same day (sensitivity analysis).
   Documents sample starvation when N < 100.
3. Produces side-by-side comparison table and evaluates ranking agreement among non-trivial models.
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

OUTPUT_METRICS_DIR = "results/v3_1/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v3_1/predictions"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

def get_git_commit():
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except Exception:
        return "unknown"

def evaluate_models_on_split(
    block_name: str,
    design_name: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    timestamps_test: np.ndarray,
    subseq_len_m: int = 10,
    seed: int = 42,
    output_predictions_dir: str = OUTPUT_PREDICTIONS_DIR
) -> List[Dict[str, Any]]:
    n_train = len(X_train)
    n_val = len(X_val)
    n_test = len(X_test)
    total_len = n_train + n_val + n_test

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)

    # Verification of training size constraint
    meets_size_constraint = (n_train >= 100) and (n_train - subseq_len_m + 1 >= 10 * subseq_len_m)
    size_status = "PASS" if meets_size_constraint else f"FAIL (< 100: N={n_train})"

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
            y_test, pred_test, timestamps_test, default_step_sec=60.0, is_flow_data=False
        )
        boot = compute_bootstrap_confidence_intervals(
            y_test, pred_test, scores_test, timestamps_test,
            n_bootstraps=500, seed=seed, default_step_sec=60.0, block_size=subseq_len_m
        )

        record = {
            "Block": block_name,
            "Design": design_name,
            "Training_Size_Status": size_status,
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
            "Train_Samples": n_train,
            "Val_Samples": n_val,
            "Test_Samples": n_test,
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

    # 2. ML BASELINES
    with ResourceProfiler() as prof_if:
        if_model = IsolationForestBaseline(n_estimators=100, random_state=seed)
        if_model.fit(X_train)
        if_model.calibrate_threshold(X_val, y_val)
    record_metrics("Baseline: Isolation Forest", "ML Baseline", if_model.predict(X_test), if_model.score_samples(X_test), prof_if.elapsed_seconds, if_model.predict(X_val), if_model.score_samples(X_val))

    with ResourceProfiler() as prof_ar:
        ar_model = ARIMAResidualBaseline(order=(1, 0, 1))
        ar_model.fit(X_train)
        ar_model.calibrate_threshold(X_val, y_val)
    record_metrics("Baseline: ARIMA Residual", "ML Baseline", ar_model.predict(X_test), ar_model.score_samples(X_test), prof_ar.elapsed_seconds, ar_model.predict(X_val), ar_model.score_samples(X_val))

    # 3. CONFIG A (mSTAMP + Kneedle)
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

    # 4. CONFIG A-PRIME (Causal AB)
    X_train_benign = X_train if np.all(y_train == 0) else X_train[y_train == 0]
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

    # 5. CONFIG B1 (Adaptive MAD)
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

    # 6. CONFIG B2 (Adaptive EVT)
    best_risk = 0.01
    best_f1_b2 = -1.0
    for r_cand in [0.10, 0.05, 0.02, 0.01, 0.005, 0.001]:
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

    # 7. CONFIG C VARIANTS
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
    record_metrics(f"Config C (B1, k={best_k_b1})", "Extension", pers_model_b1.filter(pred_test_b1), scores_test_a, 0.0, pers_model_b1.filter(base_val_alarms_b1), scores_val_a)

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
    record_metrics(f"Config C (B2, k={best_k_b2})", "Extension", pers_model_b2.filter(pred_test_b2), scores_test_a, 0.0, pers_model_b2.filter(base_val_alarms_b2), scores_val_a)

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
    record_metrics(f"Config C (A-prime, k={best_k_ap})", "Extension", pers_model_ap.filter(pred_test_aprime), scores_test_aprime, 0.0, pers_model_ap.filter(base_val_alarms_ap), scores_val_aprime)

    # Save predictions
    clean_name = f"{block_name}_{design_name}".replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
    pd.DataFrame(predictions_dict).to_parquet(os.path.join(output_predictions_dir, f"preds_{clean_name}.parquet"))
    pd.DataFrame(val_predictions_dict).to_parquet(os.path.join(output_predictions_dir, f"preds_val_{clean_name}.parquet"))

    return results

def run_evaluation():
    print("=" * 80)
    print("STAGE 1.5 STEP 3: CROSS-DAY PRIMARY vs WITHIN-DAY SENSITIVITY EVALUATION")
    print("=" * 80)
    start_time = time.time()
    all_results = []

    # 1. PRIMARY DESIGN: CROSS-DAY
    with open("configs/v3_1/cse_cic_ids2018_cross_day.json") as f:
        cross_cfg = json.load(f)

    print("\n--- RUNNING PRIMARY DESIGN: CROSS-DAY ---")
    for b in cross_cfg["blocks"]:
        day = b["day"]
        print(f"\nEvaluating Cross-Day Block: {day} (Ref: {b['reference_source']})...")
        df_ref = pd.read_parquet(b["reference_file"])
        df_val = pd.read_parquet(b["val_file"])
        df_test = pd.read_parquet(b["test_file"])

        ref_sub = df_ref.iloc[b["reference_slice"][0]:b["reference_slice"][1]]
        val_sub = df_val.iloc[b["val_slice"][0]:b["val_slice"][1]]
        test_sub = df_test.iloc[b["test_slice"][0]:b["test_slice"][1]]

        raw_tr = np.nan_to_num(ref_sub[FEATURE_COLS_CSE].values.astype(float))
        raw_va = np.nan_to_num(val_sub[FEATURE_COLS_CSE].values.astype(float))
        raw_te = np.nan_to_num(test_sub[FEATURE_COLS_CSE].values.astype(float))

        y_tr = ref_sub["Label"].values.astype(int)
        y_va = val_sub["Label"].values.astype(int)
        y_te = test_sub["Label"].values.astype(int)
        t_te = test_sub["window_time"].values

        # Enforce minimum training size assertion for primary design
        assert len(raw_tr) >= 100, f"Cross-day training windows ({len(raw_tr)}) must be >= 100!"
        assert (len(raw_tr) - 10 + 1) >= 100, f"Cross-day benign subsequences must be >= 10*m!"
        assert y_tr.sum() == 0, f"Cross-day reference must be strictly pure benign (found {y_tr.sum()} attacks)!"

        # Fit scaler exclusively on training/reference data
        scaler = StandardScaler()
        X_tr = scaler.fit_transform(raw_tr)
        X_va = scaler.transform(raw_va)
        X_te = scaler.transform(raw_te)

        print(f"  Reference: N={len(X_tr)} (attacks={y_tr.sum()}, {y_tr.mean()*100:.1f}%) [ENFORCED >= 100]")
        print(f"  Val:       N={len(X_va)} (attacks={y_va.sum()}, {y_va.mean()*100:.1f}%)")
        print(f"  Test:      N={len(X_te)} (attacks={y_te.sum()}, {y_te.mean()*100:.1f}%)")

        res = evaluate_models_on_split(
            block_name=day,
            design_name="Cross-Day (Primary)",
            X_train=X_tr, y_train=y_tr,
            X_val=X_va, y_val=y_va,
            X_test=X_te, y_test=y_te,
            timestamps_test=t_te,
            subseq_len_m=10,
            seed=42
        )
        all_results.extend(res)

    # 2. SECONDARY DESIGN: WITHIN-DAY (SENSITIVITY ANALYSIS)
    with open("configs/v3_1/cse_cic_ids2018_within_day.json") as f:
        within_cfg = json.load(f)

    print("\n--- RUNNING SECONDARY DESIGN: WITHIN-DAY SENSITIVITY ---")
    for b in within_cfg["blocks"]:
        day = b["day"]
        print(f"\nEvaluating Within-Day Sensitivity Block: {day}...")
        df = pd.read_parquet(b["file"])

        tr_sub = df.iloc[b["train_slice"][0]:b["train_slice"][1]]
        va_sub = df.iloc[b["val_slice"][0]:b["val_slice"][1]]
        te_sub = df.iloc[b["test_slice"][0]:b["test_slice"][1]]

        raw_tr = np.nan_to_num(tr_sub[FEATURE_COLS_CSE].values.astype(float))
        raw_va = np.nan_to_num(va_sub[FEATURE_COLS_CSE].values.astype(float))
        raw_te = np.nan_to_num(te_sub[FEATURE_COLS_CSE].values.astype(float))

        y_tr = tr_sub["Label"].values.astype(int)
        y_va = va_sub["Label"].values.astype(int)
        y_te = te_sub["Label"].values.astype(int)
        t_te = te_sub["window_time"].values

        # Document whether training size constraint is met
        starved = len(raw_tr) < 100
        print(f"  Train: N={len(raw_tr)} (attacks={y_tr.sum()}, {y_tr.mean()*100:.1f}%) -> Starved (<100)? {starved}")
        print(f"  Val:   N={len(raw_va)} (attacks={y_va.sum()}, {y_va.mean()*100:.1f}%)")
        print(f"  Test:  N={len(raw_te)} (attacks={y_te.sum()}, {y_te.mean()*100:.1f}%)")

        scaler = StandardScaler()
        X_tr = scaler.fit_transform(raw_tr)
        X_va = scaler.transform(raw_va)
        X_te = scaler.transform(raw_te)

        res = evaluate_models_on_split(
            block_name=day,
            design_name="Within-Day (Sensitivity)",
            X_train=X_tr, y_train=y_tr,
            X_val=X_va, y_val=y_va,
            X_test=X_te, y_test=y_te,
            timestamps_test=t_te,
            subseq_len_m=10,
            seed=42
        )
        all_results.extend(res)

    res_df = pd.DataFrame(all_results)

    # Save dedicated cross-day and within-day CSVs
    cross_df = res_df[res_df["Design"] == "Cross-Day (Primary)"].copy()
    within_df = res_df[res_df["Design"] == "Within-Day (Sensitivity)"].copy()

    cross_df.to_csv(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_cross_day_results.csv"), index=False)
    cross_df.to_json(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_cross_day_results.json"), orient="records", indent=2)

    within_df.to_csv(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_within_day_results.csv"), index=False)
    within_df.to_json(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_within_day_results.json"), orient="records", indent=2)

    # 3. SIDE-BY-SIDE COMPARISON TABLE
    pvt_f1 = res_df.pivot_table(index=["Block", "Model"], columns="Design", values="F1").reset_index()
    pvt_rec = res_df.pivot_table(index=["Block", "Model"], columns="Design", values="Recall").reset_index()
    pvt_fpr = res_df.pivot_table(index=["Block", "Model"], columns="Design", values="FPR").reset_index()
    pvt_mttd = res_df.pivot_table(index=["Block", "Model"], columns="Design", values="MTTD_Detected_Sec").reset_index()
    pvt_train = res_df.pivot_table(index=["Block", "Model"], columns="Design", values="Train_Samples").reset_index()

    side_by_side = pd.DataFrame({
        "Block": pvt_f1["Block"],
        "Model": pvt_f1["Model"],
        "Train_N_CrossDay": pvt_train["Cross-Day (Primary)"],
        "Train_N_WithinDay": pvt_train["Within-Day (Sensitivity)"],
        "F1_CrossDay": pvt_f1["Cross-Day (Primary)"],
        "F1_WithinDay": pvt_f1["Within-Day (Sensitivity)"],
        "Recall_CrossDay": pvt_rec["Cross-Day (Primary)"],
        "Recall_WithinDay": pvt_rec["Within-Day (Sensitivity)"],
        "FPR_CrossDay": pvt_fpr["Cross-Day (Primary)"],
        "FPR_WithinDay": pvt_fpr["Within-Day (Sensitivity)"],
        "MTTD_CrossDay": pvt_mttd["Cross-Day (Primary)"],
        "MTTD_WithinDay": pvt_mttd["Within-Day (Sensitivity)"]
    })
    side_by_side_csv = os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_design_comparison.csv")
    side_by_side.to_csv(side_by_side_csv, index=False)
    side_by_side.to_json(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_design_comparison.json"), orient="records", indent=2)

    # 4. RANKING COMPARISON AMONG NON-TRIVIAL METHODS
    non_trivial_models = [
        "Baseline: Isolation Forest", "Baseline: ARIMA Residual",
        "Config A (mSTAMP+Kneedle)", "Config A-prime (Causal AB)",
        "Config B1 (Adaptive MAD)", "Config B2 (Adaptive EVT)"
    ]
    ranking_records = []
    for day in ["Thursday-15-02-2018", "Friday-16-02-2018", "Wednesday-21-02-2018"]:
        sub_c = cross_df[(cross_df["Block"] == day) & (cross_df["Model"].isin(non_trivial_models))].copy()
        sub_w = within_df[(within_df["Block"] == day) & (within_df["Model"].isin(non_trivial_models))].copy()

        sub_c["Rank_CrossDay"] = sub_c["F1"].rank(ascending=False, method="min").astype(int)
        sub_w["Rank_WithinDay"] = sub_w["F1"].rank(ascending=False, method="min").astype(int)

        merged_ranks = pd.merge(
            sub_c[["Model", "F1", "Rank_CrossDay"]].rename(columns={"F1": "F1_CrossDay"}),
            sub_w[["Model", "F1", "Rank_WithinDay"]].rename(columns={"F1": "F1_WithinDay"}),
            on="Model"
        )
        merged_ranks["Block"] = day
        ranking_records.append(merged_ranks)

    ranking_df = pd.concat(ranking_records, ignore_index=True)
    ranking_csv = os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_ranking_comparison.csv")
    ranking_df.to_csv(ranking_csv, index=False)
    ranking_df.to_json(os.path.join(OUTPUT_METRICS_DIR, "csecicids2018_ranking_comparison.json"), orient="records", indent=2)

    print(f"\nAll Step 3 outputs successfully written to {OUTPUT_METRICS_DIR}")
    print(f"Total runtime: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    run_evaluation()
