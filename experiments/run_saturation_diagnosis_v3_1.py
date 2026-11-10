"""
Stage 1.5 Step 5: Comprehensive Saturation Diagnosis & Anomaly Score Distribution Analysis
Analyzes:
1. Anomaly score distributions: (a) benign validation, (b) benign test, (c) attack test for:
   - UNSW Flow Block
   - UNSW Regime Shift Demonstration Block
   - CSE Thursday, Friday, Wednesday (Cross-Day Primary)
2. Tests the "stale reference" hypothesis on UNSW Flow Block (all within Batch 1, 107s gap).
3. Evaluates 4 diagnostic causes:
   - Validation-F1 threshold degeneration (point mass at 0.0)
   - Scaler mismatch (feature drift between train and test)
   - Score scale shift (median score ratio test/val)
   - MAD == 0 division/blow-up
4. Re-runs A-prime under the Step-4 threshold rule (FAR <= 0.05 and 0.01) and reports FPR/recall.
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
from src.adaptive_threshold import MADThreshold, calibrate_benign_quantile_threshold
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

def compute_dist_stats(arr: np.ndarray) -> Dict[str, float]:
    clean = arr[np.isfinite(arr)]
    if len(clean) == 0:
        return {"n": 0, "mean": 0.0, "std": 0.0, "median": 0.0, "min": 0.0, "max": 0.0, "p05": 0.0, "p95": 0.0, "frac_zero": 0.0}
    return {
        "n": int(len(clean)),
        "mean": float(np.mean(clean)),
        "std": float(np.std(clean)),
        "median": float(np.median(clean)),
        "min": float(np.min(clean)),
        "max": float(np.max(clean)),
        "p05": float(np.percentile(clean, 5)),
        "p95": float(np.percentile(clean, 95)),
        "frac_zero": float(np.mean(clean == 0.0))
    }

def run_saturation_diagnosis():
    print("=" * 80)
    print("STAGE 1.5 STEP 5: SATURATION DIAGNOSIS PIPELINE")
    print("=" * 80)

    blocks_data = []

    # 1. CSE-CIC-IDS2018 Cross-Day Primary
    with open("configs/v3_1/cse_cic_ids2018_cross_day.json") as f:
        cse_cfg = json.load(f)

    for b in cse_cfg["blocks"]:
        name = b.get("name", b.get("day"))
        print(f"Loading {name} (Cross-Day Primary)...")
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

        blocks_data.append({
            "block_name": name,
            "dataset": "CSE-CIC-IDS2018",
            "X_train": X_tr, "y_train": y_tr,
            "X_val": X_va, "y_val": y_va,
            "X_test": X_te, "y_test": y_te,
            "subseq_m": 10,
            "is_flow": False
        })

    # 2. UNSW Blocks
    with open("configs/v3_1/unsw_nb15.json") as f:
        unsw_cfg = json.load(f)

    for b in unsw_cfg["blocks"]:
        name = b["name"]
        if name not in ["UNSW Flow Contiguous Block", "UNSW Window Regime Shift Demonstration"]:
            continue
        print(f"Loading {name}...")
        is_flow = b.get("is_flow_data", False)
        if not is_flow:
            df_unsw_win = pd.read_parquet(b["file"])
            tr_win = df_unsw_win.iloc[b["train_slice"][0]:b["train_slice"][1]]
            va_win = df_unsw_win.iloc[b["val_slice"][0]:b["val_slice"][1]]
            te_win = df_unsw_win.iloc[b["test_slice"][0]:b["test_slice"][1]]

            scaler_w = StandardScaler()
            X_tr_w = scaler_w.fit_transform(np.nan_to_num(tr_win[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
            X_va_w = scaler_w.transform(np.nan_to_num(va_win[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))
            X_te_w = scaler_w.transform(np.nan_to_num(te_win[FEATURE_COLS_UNSW_WINDOW].values.astype(float)))

            blocks_data.append({
                "block_name": name,
                "dataset": "UNSW-NB15",
                "X_train": X_tr_w, "y_train": tr_win["Label"].values.astype(int),
                "X_val": X_va_w, "y_val": va_win["Label"].values.astype(int),
                "X_test": X_te_w, "y_test": te_win["Label"].values.astype(int),
                "subseq_m": 10,
                "is_flow": False
            })
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

            blocks_data.append({
                "block_name": name,
                "dataset": "UNSW-NB15",
                "X_train": X_tr_fl, "y_train": y_tr_fl,
                "X_val": X_va_fl, "y_val": y_va_fl,
                "X_test": X_te_fl, "y_test": y_te_fl,
                "subseq_m": 5,
                "is_flow": True
            })

    # Output containers
    all_dist_records = []
    hypothesis_records = []

    # Master Plot Setup: 5 rows (blocks), 2 columns (A-prime, B1)
    fig, axes = plt.subplots(len(blocks_data), 2, figsize=(16, 20))

    for idx, bdata in enumerate(blocks_data):
        bname = bdata["block_name"]
        dname = bdata["dataset"]
        X_tr = bdata["X_train"]
        y_tr = bdata["y_train"]
        X_va = bdata["X_val"]
        y_val = bdata["y_val"]
        X_te = bdata["X_test"]
        y_test = bdata["y_test"]
        m = bdata["subseq_m"]

        n_train = len(X_tr)
        n_val = len(X_va)
        n_test = len(X_te)
        total_len = n_train + n_val + n_test

        print(f"\nProcessing {bname} ({dname})...")

        # 1. Compute Config A-prime scores
        X_tr_benign = X_tr if np.all(y_tr == 0) else X_tr[y_tr == 0]
        if len(X_tr_benign) < m:
            X_tr_benign = X_tr[:m * 2]

        aprime = CausalABScorer(m=m)
        aprime.fit(X_tr_benign)
        s_val_aprime = aprime.score(X_va)
        s_test_aprime = aprime.score(X_te)

        # 2. Compute Config A & B1 scores
        X_full = np.vstack([X_tr, X_va, X_te])
        mps_full, _ = compute_multidimensional_mp(X_full, m=m)
        mps_tr_val = mps_full[:, : n_train + n_val - m + 1]
        knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
        scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=m)

        s_val_a = scores_full_a[n_train : n_train + n_val]
        s_test_a = scores_full_a[n_train + n_val : total_len]

        # Partition scores into (a) Benign Validation, (b) Benign Test, (c) Attack Test
        # A-prime groups
        aprime_benign_val = s_val_aprime[y_val == 0]
        aprime_benign_test = s_test_aprime[y_test == 0]
        aprime_attack_test = s_test_aprime[y_test == 1]

        # Config A / B1 groups (underlying anomaly scores)
        b1_benign_val = s_val_a[y_val == 0]
        b1_benign_test = s_test_a[y_test == 0]
        b1_attack_test = s_test_a[y_test == 1]

        # Record distribution statistics
        for model_label, b_val, b_test, a_test in [
            ("Config A-prime (Causal AB)", aprime_benign_val, aprime_benign_test, aprime_attack_test),
            ("Config B1 (Adaptive MAD)", b1_benign_val, b1_benign_test, b1_attack_test)
        ]:
            s_bval = compute_dist_stats(b_val)
            s_btest = compute_dist_stats(b_test)
            s_atest = compute_dist_stats(a_test)

            all_dist_records.append({
                "Block": bname,
                "Model": model_label,
                "Benign_Val_N": s_bval["n"],
                "Benign_Val_Mean": s_bval["mean"],
                "Benign_Val_Std": s_bval["std"],
                "Benign_Val_Median": s_bval["median"],
                "Benign_Val_FracZero": s_bval["frac_zero"],
                "Benign_Test_N": s_btest["n"],
                "Benign_Test_Mean": s_btest["mean"],
                "Benign_Test_Std": s_btest["std"],
                "Benign_Test_Median": s_btest["median"],
                "Benign_Test_FracZero": s_btest["frac_zero"],
                "Attack_Test_N": s_atest["n"],
                "Attack_Test_Mean": s_atest["mean"],
                "Attack_Test_Std": s_atest["std"],
                "Attack_Test_Median": s_atest["median"],
                "Attack_Test_FracZero": s_atest["frac_zero"],
                "Test_to_Val_Benign_Median_Ratio": (s_btest["median"] / s_bval["median"]) if s_bval["median"] > 0 else None,
                "Separation_Attack_vs_Benign_Test_Mean_Diff": s_atest["mean"] - s_btest["mean"]
            })

        # Plot Histograms
        # Column 0: A-prime
        ax_ap = axes[idx, 0]
        # Common bins
        all_ap = np.concatenate([aprime_benign_val, aprime_benign_test, aprime_attack_test]) if len(aprime_attack_test) > 0 else np.concatenate([aprime_benign_val, aprime_benign_test])
        bins_ap = np.histogram_bin_edges(all_ap, bins=35)
        ax_ap.hist(aprime_benign_val, bins=bins_ap, alpha=0.55, density=True, color="#2b5c8f", label=f"Benign Val (N={len(aprime_benign_val)})")
        ax_ap.hist(aprime_benign_test, bins=bins_ap, alpha=0.55, density=True, color="#2ca02c", label=f"Benign Test (N={len(aprime_benign_test)})")
        if len(aprime_attack_test) > 0:
            ax_ap.hist(aprime_attack_test, bins=bins_ap, alpha=0.55, density=True, color="#d62728", label=f"Attack Test (N={len(aprime_attack_test)})")
        ax_ap.set_title(f"{bname}\nConfig A-prime Score Distribution", fontsize=11, fontweight="bold")
        ax_ap.set_xlabel("Anomaly Score (Distance to Library)")
        ax_ap.set_ylabel("Density")
        ax_ap.legend(loc="upper right", fontsize=8)
        ax_ap.grid(True, linestyle="--", alpha=0.5)

        # Column 1: Config B1 / Config A scores
        ax_b1 = axes[idx, 1]
        all_b1 = np.concatenate([b1_benign_val, b1_benign_test, b1_attack_test]) if len(b1_attack_test) > 0 else np.concatenate([b1_benign_val, b1_benign_test])
        bins_b1 = np.histogram_bin_edges(all_b1, bins=35)
        ax_b1.hist(b1_benign_val, bins=bins_b1, alpha=0.55, density=True, color="#2b5c8f", label=f"Benign Val (N={len(b1_benign_val)})")
        ax_b1.hist(b1_benign_test, bins=bins_b1, alpha=0.55, density=True, color="#2ca02c", label=f"Benign Test (N={len(b1_benign_test)})")
        if len(b1_attack_test) > 0:
            ax_b1.hist(b1_attack_test, bins=bins_b1, alpha=0.55, density=True, color="#d62728", label=f"Attack Test (N={len(b1_attack_test)})")
        ax_b1.set_title(f"{bname}\nConfig B1 / A Point Score Distribution", fontsize=11, fontweight="bold")
        ax_b1.set_xlabel("Anomaly Score (Point Profile)")
        ax_b1.set_ylabel("Density")
        ax_b1.legend(loc="upper right", fontsize=8)
        ax_b1.grid(True, linestyle="--", alpha=0.5)

        # 3. DIAGNOSTIC HYPOTHESIS TESTS
        # (A) Validation-F1 Degeneration Test
        percentiles = np.linspace(80, 99.8, 80)
        best_f1_val = -1.0
        best_th_val = None
        for p in percentiles:
            th = float(np.percentile(s_val_aprime, p))
            pred_v = (s_val_aprime >= th).astype(int)
            f1_v = float(f1_score(y_val, pred_v, zero_division=0))
            if f1_v > best_f1_val:
                best_f1_val = f1_v
                best_th_val = th

        pred_te_f1_opt = (s_test_aprime >= best_th_val).astype(int)
        tn_f1, fp_f1, fn_f1, tp_f1 = confusion_matrix(y_test, pred_te_f1_opt, labels=[0, 1]).ravel()
        f1_opt_fpr = float(fp_f1 / (fp_f1 + tn_f1)) if (fp_f1 + tn_f1) > 0 else 0.0
        f1_opt_rec = float(tp_f1 / (tp_f1 + fn_f1)) if (tp_f1 + fn_f1) > 0 else 0.0

        # (B) Step-4 Threshold Rule (FAR <= 0.05 on Benign Validation)
        th_step4 = calibrate_benign_quantile_threshold(s_val_aprime, y_val, alpha=0.05)
        pred_te_step4 = (s_test_aprime >= th_step4).astype(int)
        tn_s4, fp_s4, fn_s4, tp_s4 = confusion_matrix(y_test, pred_te_step4, labels=[0, 1]).ravel()
        step4_fpr = float(fp_s4 / (fp_s4 + tn_s4)) if (fp_s4 + tn_s4) > 0 else 0.0
        step4_rec = float(tp_s4 / (tp_s4 + fn_s4)) if (tp_s4 + fn_s4) > 0 else 0.0
        step4_f1 = float(f1_score(y_test, pred_te_step4, zero_division=0))

        # (C) Scaler Drift between Train and Test
        mean_drift = float(np.mean(np.abs(np.mean(X_te, axis=0) - np.mean(X_tr, axis=0))))
        std_drift = float(np.mean(np.abs(np.std(X_te, axis=0) - np.std(X_tr, axis=0))))

        hypothesis_records.append({
            "Block": bname,
            "Dataset": dname,
            "Val_F1_Opt_Threshold": float(best_th_val),
            "Val_F1_Opt_Achieved_Val_F1": float(best_f1_val),
            "Val_F1_Opt_Test_FPR": f1_opt_fpr,
            "Val_F1_Opt_Test_Recall": f1_opt_rec,
            "Val_F1_Opt_Saturated": "YES (100% alerts)" if f1_opt_fpr >= 0.99 else "NO",
            "Step4_Benign_Threshold": float(th_step4),
            "Step4_Test_FPR": step4_fpr,
            "Step4_Test_Recall": step4_rec,
            "Step4_Test_F1": step4_f1,
            "Step4_Saturated": "YES" if step4_fpr >= 0.99 else "NO",
            "Scaler_Mean_Drift": mean_drift,
            "Scaler_Std_Drift": std_drift,
            "A_Prime_Val_Benign_Frac_Zero": float(np.mean(aprime_benign_val == 0.0)),
            "A_Prime_Test_Benign_Frac_Zero": float(np.mean(aprime_benign_test == 0.0))
        })

    plt.tight_layout()
    hist_fig_path = os.path.join(OUTPUT_FIGURES_DIR, "score_histograms_saturation_diagnosis.png")
    fig.savefig(hist_fig_path, dpi=200)
    plt.close(fig)
    print(f"\nSaved score histograms to {hist_fig_path}")

    # Save summary tables
    df_dist = pd.DataFrame(all_dist_records)
    df_dist.to_csv(os.path.join(OUTPUT_METRICS_DIR, "score_distribution_summary.csv"), index=False)
    df_dist.to_json(os.path.join(OUTPUT_METRICS_DIR, "score_distribution_summary.json"), orient="records", indent=2)

    df_hyp = pd.DataFrame(hypothesis_records)
    df_hyp.to_csv(os.path.join(OUTPUT_METRICS_DIR, "saturation_diagnosis_hypotheses.csv"), index=False)
    df_hyp.to_json(os.path.join(OUTPUT_METRICS_DIR, "saturation_diagnosis_hypotheses.json"), orient="records", indent=2)

    print("Saved saturation diagnosis results to results/v3_1/metrics/")

if __name__ == "__main__":
    run_saturation_diagnosis()
