"""
Stage 1.5 Step 6: Paired Persistence Analysis
Evaluates the effect of the temporal persistence filter (k in {1, 2, 3, 4, 5})
across ALL 4 parent detectors:
1. Config A (mSTAMP + Kneedle)
2. Config A-prime (Causal AB)
3. Config B1 (Adaptive MAD)
4. Config B2 (Adaptive EVT)

Protocol:
- Evaluated on the SAME parent score and threshold (Step-4 primary rule: FAR <= 0.05 on benign validation).
- k* is selected strictly on the VALIDATION split by filtering parent validation alerts to maximize validation F1.
- Evaluates test performance for k=1 (unfiltered parent), k in {2, 3, 4, 5}, and validation-selected k*.
- Records whether k* == 1 everywhere on real data and quantifies recall/F1 degradation from persistence.
"""

import os
import sys
import json
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, confusion_matrix, precision_score, recall_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.adaptive_threshold import MADThreshold, EVTThreshold, calibrate_benign_quantile_threshold
from src.persistence_filter import PersistenceFilter
from src.evaluation import compute_sre_operational_metrics
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
OUTPUT_FIGURES_DIR = "results/v3_1/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

def evaluate_block_persistence(
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
    is_flow: bool = False
) -> List[Dict[str, Any]]:
    n_train = len(X_train)
    n_val = len(X_val)
    n_test = len(X_test)
    total_len = n_train + n_val + n_test

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)
    X_full = np.vstack([X_train, X_val, X_test])

    # 1. Config A: mSTAMP + Kneedle
    effective_m = max(3, min(subseq_len_m, n_train - 1))
    mps_full, _ = compute_multidimensional_mp(X_full, m=effective_m)
    mps_tr_val = mps_full[:, : n_train + n_val - effective_m + 1]
    knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
    scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=effective_m)
    scores_val_a = scores_full_a[val_slice]
    scores_test_a = scores_full_a[test_slice]

    th_a = calibrate_benign_quantile_threshold(scores_val_a, y_val, alpha=0.05)
    raw_val_a = (scores_val_a >= th_a).astype(int)
    raw_test_a = (scores_test_a >= th_a).astype(int)

    # 2. Config A-prime: Causal AB
    X_train_benign = X_train if np.all(y_train == 0) else X_train[y_train == 0]
    if len(X_train_benign) < effective_m:
        X_train_benign = X_train[:effective_m * 2]
    aprime = CausalABScorer(m=effective_m)
    aprime.fit(X_train_benign)
    scores_val_aprime = aprime.score(X_val)
    scores_test_aprime = aprime.score(X_test)

    th_aprime = calibrate_benign_quantile_threshold(scores_val_aprime, y_val, alpha=0.05)
    raw_val_aprime = (scores_val_aprime >= th_aprime).astype(int)
    raw_test_aprime = (scores_test_aprime >= th_aprime).astype(int)

    # 3. Config B1: Adaptive MAD
    scores_train_a = scores_full_a[:n_train]
    train_normal_scores = scores_train_a[y_train == 0] if (y_train == 0).sum() > 0 else scores_train_a
    val_normal_scores = scores_val_a[y_val == 0] if (y_val == 0).sum() > 0 else scores_val_a
    hist_normal = np.concatenate([train_normal_scores, val_normal_scores])

    benign_mask_val = (y_val == 0)
    rolling_w = min(20, max(5, n_val // 2))
    best_c = 3.0
    best_mad = None
    for c_cand in [1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]:
        mad_cand = MADThreshold(c=c_cand, rolling_window=rolling_w, eps=1e-6)
        mad_cand.fit(hist_normal)
        p_val = mad_cand.predict(scores_val_a)
        emp_far = float(np.mean(p_val[benign_mask_val] == 1)) if np.any(benign_mask_val) else 0.0
        if emp_far <= 0.05:
            best_c = c_cand
            best_mad = mad_cand
            break
    if best_mad is None:
        best_mad = MADThreshold(c=5.0, rolling_window=rolling_w, eps=1e-6).fit(hist_normal)

    raw_val_b1 = best_mad.predict(scores_val_a)
    raw_test_b1 = best_mad.predict(scores_test_a)

    # 4. Config B2: Adaptive EVT
    evt = EVTThreshold(q=0.80, risk_p=0.05, min_excesses=30)
    evt.fit(hist_normal)
    raw_val_b2 = evt.predict(scores_val_a)
    raw_test_b2 = evt.predict(scores_test_a)

    parents = [
        ("Config A (mSTAMP+Kneedle)", "Config A", raw_val_a, raw_test_a, th_a),
        ("Config A-prime (Causal AB)", "Config A-prime", raw_val_aprime, raw_test_aprime, th_aprime),
        ("Config B1 (Adaptive MAD)", "Config B1", raw_val_b1, raw_test_b1, best_c),
        ("Config B2 (Adaptive EVT)", "Config B2", raw_val_b2, raw_test_b2, evt.threshold_)
    ]

    records = []

    for parent_full_name, parent_short, val_alerts, test_alerts, p_thresh in parents:
        # Sweep k in [1..5] on validation to select k*
        val_f1s = {}
        for k in [1, 2, 3, 4, 5]:
            filt_val = PersistenceFilter(k=k).filter(val_alerts)
            f1_v = float(f1_score(y_val, filt_val, zero_division=0))
            val_f1s[k] = f1_v

        # Select k* maximizing validation F1 (tie-break prefer smaller k for lower latency)
        best_k = 1
        best_val_f1 = -1.0
        for k in [1, 2, 3, 4, 5]:
            if val_f1s[k] > best_val_f1:
                best_val_f1 = val_f1s[k]
                best_k = k

        # Baseline performance at k=1 (unfiltered parent)
        filt_test_k1 = PersistenceFilter(k=1).filter(test_alerts)
        tn1, fp1, fn1, tp1 = confusion_matrix(y_test, filt_test_k1, labels=[0, 1]).ravel()
        f1_k1 = float(f1_score(y_test, filt_test_k1, zero_division=0))
        rec_k1 = float(recall_score(y_test, filt_test_k1, zero_division=0))
        prec_k1 = float(precision_score(y_test, filt_test_k1, zero_division=0))
        fpr_k1 = float(fp1 / (fp1 + tn1)) if (fp1 + tn1) > 0 else 0.0
        sre_k1 = compute_sre_operational_metrics(y_test, filt_test_k1, timestamps=timestamps_test, default_step_sec=step_sec)

        # Evaluate all k in [1..5] on test
        for k in [1, 2, 3, 4, 5]:
            filt_test = PersistenceFilter(k=k).filter(test_alerts)
            tn, fp, fn, tp = confusion_matrix(y_test, filt_test, labels=[0, 1]).ravel()
            f1_k = float(f1_score(y_test, filt_test, zero_division=0))
            rec_k = float(recall_score(y_test, filt_test, zero_division=0))
            prec_k = float(precision_score(y_test, filt_test, zero_division=0))
            fpr_k = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            sre_k = compute_sre_operational_metrics(y_test, filt_test, timestamps=timestamps_test, default_step_sec=step_sec)

            # Changes relative to k=1
            delta_f1 = f1_k - f1_k1
            delta_rec = rec_k - rec_k1
            delta_fpr = fpr_k - fpr_k1
            fpr_reduction_pct = ((fpr_k1 - fpr_k) / fpr_k1 * 100.0) if fpr_k1 > 0 else 0.0

            variant_name = parent_full_name if k == 1 else f"Config C ({parent_short}, k={k})"

            records.append({
                "Block": block_name,
                "Dataset": dataset_name,
                "Design": design_type,
                "Parent_Detector": parent_full_name,
                "Variant_Name": variant_name,
                "k": k,
                "Validation_Selected_k_star": best_k,
                "Is_Validation_Selected": (k == best_k),
                "Val_F1": val_f1s[k],
                "Val_F1_k_star": best_val_f1,
                "Test_F1": f1_k,
                "Test_Recall": rec_k,
                "Test_Precision": prec_k,
                "Test_FPR": fpr_k,
                "Total_Alerts": int(filt_test.sum()),
                "Alerts_Per_1000": sre_k["alerts_per_1000_windows"],
                "Alerts_Per_Hour": sre_k["alerts_per_hour"] if not is_flow else None,
                "MTTD_Sec": sre_k["mttd_detected_campaigns_only_sec"],
                "Campaign_Recall": sre_k["campaign_recall"],
                "Delta_F1_vs_k1": delta_f1,
                "Delta_Recall_vs_k1": delta_rec,
                "Delta_FPR_vs_k1": delta_fpr,
                "FPR_Reduction_Percent": fpr_reduction_pct,
                "Persistence_Helped_F1": "yes" if delta_f1 > 0.005 else ("hurt" if delta_f1 < -0.005 else "neutral")
            })

    return records

def run_all_paired_persistence():
    print("=" * 80)
    print("STAGE 1.5 STEP 6: PAIRED PERSISTENCE ANALYSIS ACROSS ALL PARENTS & BLOCKS")
    print("=" * 80)

    all_records = []

    # 1. CSE Cross-Day Primary
    with open("configs/v3_1/cse_cic_ids2018_cross_day.json") as f:
        cross_cfg = json.load(f)

    for b in cross_cfg["blocks"]:
        name = b.get("name", b.get("day"))
        print(f"Evaluating Persistence on CSE Cross-Day Primary: {name}...")
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

        recs = evaluate_block_persistence(
            block_name=name,
            dataset_name="CSE-CIC-IDS2018",
            design_type="Cross-Day Primary",
            X_train=X_tr, y_train=y_tr,
            X_val=X_va, y_val=y_va,
            X_test=X_te, y_test=y_te,
            timestamps_test=t_te,
            step_sec=60.0,
            subseq_len_m=10,
            seed=42,
            is_flow=False
        )
        all_records.extend(recs)

    # 2. UNSW Window Regime Shift Blocks
    with open("configs/v3_1/unsw_nb15.json") as f:
        unsw_cfg = json.load(f)

    for b in unsw_cfg["blocks"]:
        name = b["name"]
        if b.get("is_flow_data", False):
            continue
        print(f"Evaluating Persistence on UNSW Window: {name}...")
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

        recs = evaluate_block_persistence(
            block_name=name,
            dataset_name="UNSW-NB15",
            design_type="Window Block",
            X_train=X_tr_w, y_train=y_tr_w,
            X_val=X_va_w, y_val=y_va_w,
            X_test=X_te_w, y_test=y_te_w,
            timestamps_test=t_te_w,
            step_sec=10.0,
            subseq_len_m=10,
            seed=42,
            is_flow=False
        )
        all_records.extend(recs)

    # 3. Save paired persistence table
    df_p = pd.DataFrame(all_records)
    out_csv = os.path.join(OUTPUT_METRICS_DIR, "paired_persistence_analysis.csv")
    out_json = os.path.join(OUTPUT_METRICS_DIR, "paired_persistence_analysis.json")
    df_p.to_csv(out_csv, index=False)
    df_p.to_json(out_json, orient="records", indent=2)

    # Generate Paired Persistence Figure: F1 change vs k across parents
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    cse_cross = df_p[df_p["Design"] == "Cross-Day Primary"]
    days = ["Thursday-15-02-2018", "Friday-16-02-2018", "Wednesday-21-02-2018"]

    colors = {
        "Config A (mSTAMP+Kneedle)": "#1f77b4",
        "Config A-prime (Causal AB)": "#d62728",
        "Config B1 (Adaptive MAD)": "#ff7f0e",
        "Config B2 (Adaptive EVT)": "#2ca02c"
    }

    for i, day in enumerate(days):
        ax = axes[i]
        day_df = cse_cross[cse_cross["Block"] == day]
        for parent in colors:
            p_df = day_df[day_df["Parent_Detector"] == parent].sort_values("k")
            if len(p_df) > 0:
                ax.plot(p_df["k"], p_df["Test_F1"], marker="o", label=parent.split("(")[0].strip(), color=colors[parent], linewidth=2.0)
                # Mark k* with a star
                k_star_row = p_df[p_df["Is_Validation_Selected"]]
                if len(k_star_row) > 0:
                    ax.scatter(k_star_row["k"].values[0], k_star_row["Test_F1"].values[0], color="gold", s=180, marker="*", edgecolor="black", zorder=5)
        ax.set_title(f"{day}\nTest F1 vs Persistence k", fontsize=11, fontweight="bold")
        ax.set_xlabel("Persistence Filter Parameter k")
        ax.set_ylabel("Test F1-Score")
        ax.set_xticks([1, 2, 3, 4, 5])
        ax.grid(True, linestyle="--", alpha=0.5)
        if i == 0:
            ax.legend(fontsize=9, loc="upper right")

    plt.tight_layout()
    fig_path = os.path.join(OUTPUT_FIGURES_DIR, "paired_persistence_effect.png")
    fig.savefig(fig_path, dpi=200)
    plt.close(fig)

    print(f"\nSaved paired persistence metrics to {out_csv}")
    print(f"Saved paired persistence plot to {fig_path}")

if __name__ == "__main__":
    run_all_paired_persistence()
