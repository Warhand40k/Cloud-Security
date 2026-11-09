"""
Persistence Filter Sensitivity and k Sweep (Phase 4):
Evaluates Persistence Filter over the full range k in [1, 2, 3, 4, 5]
for both adaptive threshold variants (Config B1: MAD and Config B2: EVT).

Ground Rule:
- k is chosen strictly on the VALIDATION split.
- Test performance is reported for all k in [1..5], with the validation-selected k* marked explicitly.
- Models named explicitly by threshold and k: e.g. C(B1, k=2) or C(B2, k=3).
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.adaptive_threshold import MADThreshold, EVTThreshold
from src.persistence_filter import PersistenceFilter
from src.evaluation import compute_classification_metrics, compute_sre_operational_metrics

OUTPUT_METRICS_DIR = "results/v2/metrics"
OUTPUT_FIGURES_DIR = "results/v2/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

def run_persistence_k_sweep():
    print("=" * 80)
    print("RUNNING PERSISTENCE FILTER k SWEEP (k in 1..5) (PHASE 4)")
    print("=" * 80)

    # We evaluate on CSE-CIC Thursday and Friday
    datasets = [
        ("Thursday 15 (GoldenEye/Slowloris)", "data/processed/csecicids2018_thursday_60s_any_attack.parquet", [0, 250], [250, 410], [410, 572], 60.0),
        ("Friday 16 (Hulk/SlowHTTPTest)", "data/processed/csecicids2018_60s_any_attack.parquet", [30, 85], [0, 30], [85, 191], 60.0)
    ]

    records = []

    for block_name, ppath, tr_s, va_s, te_s, step_sec in datasets:
        print(f"\nEvaluating Persistence Sweep for Block: {block_name}...")
        df = pd.read_parquet(ppath)
        
        train_df = df.iloc[tr_s[0]:tr_s[1]]
        val_df = df.iloc[va_s[0]:va_s[1]]
        test_df = df.iloc[te_s[0]:te_s[1]]

        scaler = StandardScaler()
        X_train = scaler.fit_transform(np.nan_to_num(train_df[FEATURE_COLS_CSE].values.astype(float)))
        X_val = scaler.transform(np.nan_to_num(val_df[FEATURE_COLS_CSE].values.astype(float)))
        X_test = scaler.transform(np.nan_to_num(test_df[FEATURE_COLS_CSE].values.astype(float)))

        y_train = train_df["Label"].values.astype(int)
        y_val = val_df["Label"].values.astype(int)
        y_test = test_df["Label"].values.astype(int)

        t_test = test_df["window_time"].values

        n_train = len(X_train)
        n_val = len(X_val)
        n_test = len(X_test)
        total_len = n_train + n_val + n_test
        val_slice = slice(n_train, n_train + n_val)
        test_slice = slice(n_train + n_val, total_len)

        X_full = np.vstack([X_train, X_val, X_test])
        mps_full, _ = compute_multidimensional_mp(X_full, m=10)
        knee_dim, _ = find_knee_dimension(mps_full[:, : n_train + n_val], online=True, metric="max")
        scores_full = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim, n_samples=total_len, m=10)

        scores_tr = scores_full[:n_train]
        scores_va = scores_full[val_slice]
        scores_te = scores_full[test_slice]

        # Normal history for fitting thresholds
        norm_tr = scores_tr[y_train == 0] if (y_train == 0).sum() > 0 else scores_tr
        norm_va = scores_va[y_val == 0] if (y_val == 0).sum() > 0 else scores_va
        hist_norm = np.concatenate([norm_tr, norm_va])

        # 1. Fit B1 (MAD)
        mad = MADThreshold(c=2.5, rolling_window=min(20, max(5, n_val // 2))).fit(hist_norm)
        alarms_val_b1 = mad.predict(scores_va)
        alarms_test_b1 = mad.predict(scores_te)

        # 2. Fit B2 (EVT)
        evt = EVTThreshold(q=0.80, risk_p=0.01, min_excesses=30).fit(hist_norm)
        alarms_val_b2 = evt.predict(scores_va)
        alarms_test_b2 = evt.predict(scores_te)

        variants = [
            ("B1", "Adaptive MAD", alarms_val_b1, alarms_test_b1),
            ("B2", "Adaptive EVT", alarms_val_b2, alarms_test_b2)
        ]

        for b_code, b_name, val_base, test_base in variants:
            # Sweep k in 1..5 on validation
            val_f1_list = []
            for k in [1, 2, 3, 4, 5]:
                pf = PersistenceFilter(k=k)
                f1_v = compute_classification_metrics(y_val, pf.filter(val_base))["f1"]
                val_f1_list.append((k, f1_v))

            # Select best k on validation only!
            val_f1_list.sort(key=lambda x: x[1], reverse=True)
            best_k_val = val_f1_list[0][0]

            for k in [1, 2, 3, 4, 5]:
                pf = PersistenceFilter(k=k)
                pred_val_k = pf.filter(val_base)
                pred_test_k = pf.filter(test_base)

                cls_val = compute_classification_metrics(y_val, pred_val_k)
                cls_test = compute_classification_metrics(y_test, pred_test_k, scores_te)
                sre_test = compute_sre_operational_metrics(y_test, pred_test_k, t_test, default_step_sec=step_sec)

                model_name = f"C({b_code}, k={k})"
                is_val_selected = (k == best_k_val)

                records.append({
                    "Block": block_name,
                    "Base_Threshold": b_code,
                    "Base_Threshold_Name": b_name,
                    "k": k,
                    "Model": model_name,
                    "Validation_Selected": is_val_selected,
                    "Val_F1": cls_val["f1"],
                    "Val_Precision": cls_val["precision"],
                    "Val_Recall": cls_val["recall"],
                    "Test_F1": cls_test["f1"],
                    "Test_Precision": cls_test["precision"],
                    "Test_Recall": cls_test["recall"],
                    "Test_FPR": cls_test["fpr"],
                    "Test_PR_AUC": cls_test["pr_auc"],
                    "Test_Campaign_Recall": sre_test["campaign_recall"],
                    "Test_MTTD_Detected_Sec": sre_test["mttd_detected_campaigns_only_sec"],
                    "Total_Alerts": sre_test["total_alerts"],
                    "Alerts_Per_1000_Windows": sre_test["alerts_per_1000_windows"],
                    "Alerts_Per_Hour": sre_test["alerts_per_hour"]
                })
                print(f"  {model_name}{'*' if is_val_selected else ' '} | Val F1={cls_val['f1']:.4f} | Test F1={cls_test['f1']:.4f} | Alerts={sre_test['total_alerts']} | MTTD={sre_test['mttd_detected_campaigns_only_sec']}")

    df_sweep = pd.DataFrame(records)
    csv_out = os.path.join(OUTPUT_METRICS_DIR, "persistence_k_sweep.csv")
    json_out = os.path.join(OUTPUT_METRICS_DIR, "persistence_k_sweep.json")
    df_sweep.to_csv(csv_out, index=False)
    df_sweep.to_json(json_out, orient="records", indent=2)
    print(f"\nSaved persistence k sweep to {csv_out} and {json_out}")

    # Generate Figure: k vs Test F1 and Alert Volume
    plt.figure(figsize=(10, 5))
    sns.lineplot(
        data=df_sweep, x="k", y="Test_F1", hue="Model", style="Block", markers=True, dashes=False
    )
    plt.title("Persistence Filter: Test F1 across k in [1..5]", fontsize=12, fontweight="bold")
    plt.xlabel("Persistence Parameter k (Consecutive Detections)", fontsize=11)
    plt.ylabel("Test F1 Score", fontsize=11)
    plt.xticks([1, 2, 3, 4, 5])
    plt.grid(True, ls=":", alpha=0.6)
    plt.tight_layout()
    fig_out = os.path.join(OUTPUT_FIGURES_DIR, "persistence_k_sweep.png")
    plt.savefig(fig_out, dpi=300)
    plt.close()
    print(f"Saved persistence figure to {fig_out}")

    return df_sweep

if __name__ == "__main__":
    run_persistence_k_sweep()

