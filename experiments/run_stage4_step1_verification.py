"""
Stage 4 Step 1: Label-Feedback Audit and Side-by-Side Benchmark Verification
Evaluates Conformal Anomaly Calibrators across:
1. Stage 2 Benchmark (32 configurations across CSE-CIC-IDS2018 and UNSW-NB15)
2. Stage 3 Testbed (Live Microservice Telemetry under 25 campaigns)

Compares:
- Static Benign Quantile (Stage 1.5 baseline)
- Static Split-Conformal
- Rolling Split-Conformal (Oracle-Feedback Upper Bound, verified_benign_mask = y_test == 0)
- Adaptive Conformal (ACI, Oracle-Feedback Upper Bound, verified_benign_mask = y_test == 0)
- Rolling Split-Conformal (Label-Free Autonomous, unflagged only, zero test labels)
- Adaptive Conformal (ACI, Label-Free Autonomous, alerts only, zero test labels)

Outputs written strictly to results/v4/
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
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.adaptive_threshold import ConformalQuantileThreshold, calibrate_benign_quantile_threshold
from src.evaluation import compute_sre_operational_metrics
from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline, RandomUniformBaseline
)

OUTPUT_METRICS_DIR = "results/v4/metrics"
OUTPUT_PREDICTIONS_DIR = "results/v4/predictions"
OUTPUT_FIGURES_DIR = "results/v4/figures"
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_PREDICTIONS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

BLOCKS_CONFIG = [
    {
        "block": "Thursday-15-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Cross-Day_Primary",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_thursday_60s_regular.parquet",
        "test_slice": slice(558, 720),
        "test_pred_file": "results/v3_1/predictions/preds_Thursday-15-02-2018_Cross-Day_Primary.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Thursday-15-02-2018_Cross-Day_Primary.parquet"
    },
    {
        "block": "Friday-16-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Cross-Day_Primary",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_friday_60s_regular.parquet",
        "test_slice": slice(552, 719),
        "test_pred_file": "results/v3_1/predictions/preds_Friday-16-02-2018_Cross-Day_Primary.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Friday-16-02-2018_Cross-Day_Primary.parquet"
    },
    {
        "block": "Wednesday-21-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Cross-Day_Primary",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_wednesday_60s_regular.parquet",
        "test_slice": slice(459, 529),
        "test_pred_file": "results/v3_1/predictions/preds_Wednesday-21-02-2018_Cross-Day_Primary.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Wednesday-21-02-2018_Cross-Day_Primary.parquet"
    },
    {
        "block": "Friday-16-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Within-Day_Sensitivity",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_friday_60s_regular.parquet",
        "test_slice": slice(552, 719),
        "test_pred_file": "results/v3_1/predictions/preds_Friday-16-02-2018_Within-Day_Sensitivity.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Friday-16-02-2018_Within-Day_Sensitivity.parquet"
    },
    {
        "block": "Wednesday-21-02-2018",
        "dataset": "CSE-CIC-IDS2018",
        "design": "Within-Day_Sensitivity",
        "is_flow": False,
        "step_sec": 60.0,
        "raw_parquet": "data/processed/csecicids2018_wednesday_60s_regular.parquet",
        "test_slice": slice(459, 529),
        "test_pred_file": "results/v3_1/predictions/preds_Wednesday-21-02-2018_Within-Day_Sensitivity.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_Wednesday-21-02-2018_Within-Day_Sensitivity.parquet"
    },
    {
        "block": "UNSW_Window_Small_Regime-Shift_Block",
        "dataset": "UNSW-NB15",
        "design": "Window_Block",
        "is_flow": False,
        "step_sec": 10.0,
        "raw_parquet": None,
        "test_slice": None,
        "test_pred_file": "results/v3_1/predictions/preds_UNSW_Window_Small_Regime-Shift_Block.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_UNSW_Window_Small_Regime-Shift_Block.parquet"
    },
    {
        "block": "UNSW_Window_Regime_Shift_Demonstration",
        "dataset": "UNSW-NB15",
        "design": "Window_Block",
        "is_flow": False,
        "step_sec": 10.0,
        "raw_parquet": None,
        "test_slice": None,
        "test_pred_file": "results/v3_1/predictions/preds_UNSW_Window_Regime_Shift_Demonstration.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_UNSW_Window_Regime_Shift_Demonstration.parquet"
    },
    {
        "block": "UNSW_Flow_Contiguous_Block",
        "dataset": "UNSW-NB15",
        "design": "Flow_Block",
        "is_flow": True,
        "step_sec": 1.0,
        "raw_parquet": None,
        "test_slice": None,
        "test_pred_file": "results/v3_1/predictions/preds_UNSW_Flow_Contiguous_Block.parquet",
        "val_pred_file": "results/v3_1/predictions/preds_val_UNSW_Flow_Contiguous_Block.parquet"
    }
]

MODELS_TO_EVAL = [
    "Baseline: Isolation Forest",
    "Baseline: ARIMA Residual",
    "Config A (mSTAMP+Kneedle)",
    "Config A-prime (Causal AB)"
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

def run_stage2_side_by_side():
    print("=" * 80)
    print("STAGE 4 STEP 1: STAGE 2 BENCHMARK RE-RUN (ORACLE VS LABEL-FREE)")
    print("=" * 80)

    all_records = []

    for binfo in BLOCKS_CONFIG:
        block_name = binfo["block"]
        dataset_name = binfo["dataset"]
        design = binfo["design"]
        is_flow = binfo["is_flow"]
        step_sec = binfo["step_sec"]

        print(f"\n---> Evaluating Block: {block_name} ({design})")

        df_test = pd.read_parquet(binfo["test_pred_file"])
        df_val = pd.read_parquet(binfo["val_pred_file"])

        y_test = df_test["y_true"].values.astype(int)
        y_val = df_val["y_true"].values.astype(int)
        n_test = len(y_test)
        prevalence = float(np.mean(y_test))

        if binfo["raw_parquet"] is not None and os.path.exists(binfo["raw_parquet"]):
            raw_df = pd.read_parquet(binfo["raw_parquet"])
            timestamps_test = raw_df["window_time"].values[binfo["test_slice"]].astype(float)
        else:
            timestamps_test = np.arange(n_test, dtype=float) * step_sec

        df_out = df_test[["y_true"]].copy()

        for model_name in MODELS_TO_EVAL:
            score_col = f"{model_name}_score"
            if score_col not in df_test.columns or score_col not in df_val.columns:
                continue

            s_val = np.nan_to_num(df_val[score_col].values.astype(float))
            s_test = np.nan_to_num(df_test[score_col].values.astype(float))
            df_out[score_col] = s_test

            for alpha in [0.05, 0.01]:
                alpha_str = f"{int(alpha * 100):02d}"

                # 1. Static Benign Quantile
                th_quantile = calibrate_benign_quantile_threshold(s_val, y_val, alpha=alpha)
                p_quantile = (s_test >= th_quantile).astype(int)

                # 2. Static Split-Conformal
                cqt = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
                p_static = cqt.predict(s_test)
                th_static = cqt.threshold_

                # 3. Rolling Conformal - Oracle
                p_roll_oracle, th_roll_oracle = cqt.predict_rolling_oracle(
                    s_test, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
                )

                # 4. ACI - Oracle
                p_aci_oracle, th_aci_oracle, alphas_aci_oracle = cqt.predict_aci_oracle(
                    s_test, gamma=0.01, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
                )

                # 5. Rolling Conformal - Label-Free Autonomous
                p_roll_lf, th_roll_lf = cqt.predict_rolling_label_free(
                    s_test, window_size=60, alpha=alpha
                )

                # 6. ACI - Label-Free Autonomous
                p_aci_lf, th_aci_lf, alphas_aci_lf = cqt.predict_aci_label_free(
                    s_test, gamma=0.01, window_size=60, alpha=alpha
                )

                # Save predictions to dataframe
                df_out[f"{model_name}_Quantile_a{alpha_str}_pred"] = p_quantile
                df_out[f"{model_name}_SplitConf_a{alpha_str}_pred"] = p_static
                df_out[f"{model_name}_RollConf_Oracle_a{alpha_str}_pred"] = p_roll_oracle
                df_out[f"{model_name}_ACI_Oracle_a{alpha_str}_pred"] = p_aci_oracle
                df_out[f"{model_name}_RollConf_LabelFree_a{alpha_str}_pred"] = p_roll_lf
                df_out[f"{model_name}_ACI_LabelFree_a{alpha_str}_pred"] = p_aci_lf

                evaluated_methods = [
                    ("Static Benign Quantile", p_quantile, th_quantile, "Static", "Baseline"),
                    ("Static Split-Conformal", p_static, th_static, "Static", "Baseline"),
                    ("Rolling Split-Conformal (Oracle)", p_roll_oracle, float(np.mean(th_roll_oracle)), "Adaptive", "Oracle-Feedback Upper Bound"),
                    ("Adaptive Conformal (ACI, Oracle)", p_aci_oracle, float(np.mean(th_aci_oracle)), "Adaptive", "Oracle-Feedback Upper Bound"),
                    ("Rolling Split-Conformal (Label-Free)", p_roll_lf, float(np.mean(th_roll_lf)), "Adaptive", "Label-Free Autonomous"),
                    ("Adaptive Conformal (ACI, Label-Free)", p_aci_lf, float(np.mean(th_aci_lf)), "Adaptive", "Label-Free Autonomous")
                ]

                for m_name, pred_arr, mean_th, m_cat, m_variant in evaluated_methods:
                    tn, fp, fn, tp = confusion_matrix(y_test, pred_arr, labels=[0, 1]).ravel()
                    prec = float(precision_score(y_test, pred_arr, zero_division=0))
                    rec = float(recall_score(y_test, pred_arr, zero_division=0))
                    f1 = float(f1_score(y_test, pred_arr, zero_division=0))
                    achieved_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                    fpr_excess = achieved_fpr - alpha
                    fpr_target_met = (achieved_fpr <= alpha)

                    sre_m = compute_sre_operational_metrics(
                        y_test, pred_arr, timestamps=timestamps_test, default_step_sec=step_sec, is_flow_data=is_flow
                    )

                    all_records.append({
                        "Block": block_name,
                        "Dataset": dataset_name,
                        "Design": design,
                        "Model": model_name,
                        "Method": m_name,
                        "Method_Category": m_cat,
                        "Variant": m_variant,
                        "Target_Alpha": alpha,
                        "Mean_Threshold": mean_th,
                        "Achieved_FPR": achieved_fpr,
                        "FPR_Excess_Error": fpr_excess,
                        "FPR_Target_Met": fpr_target_met,
                        "Recall": rec,
                        "Precision": prec,
                        "F1": f1,
                        "Prevalence": prevalence,
                        "Total_Alerts": int(pred_arr.sum()),
                        "Alerts_Per_1000": sre_m.get("alerts_per_1000_windows", 0.0),
                        "Alerts_Per_Hour": sre_m.get("alerts_per_hour", None),
                        "Campaign_Recall": sre_m.get("campaign_recall", 1.0),
                        "MTTD_Sec": sre_m.get("mttd_detected_campaigns_only_sec", None)
                    })

        out_parquet_path = os.path.join(OUTPUT_PREDICTIONS_DIR, f"preds_stage4_conformal_{block_name}_{design}.parquet")
        df_out.to_parquet(out_parquet_path, index=False)

    df_results = pd.DataFrame(all_records)
    csv_path = os.path.join(OUTPUT_METRICS_DIR, "stage4_conformal_comparison_results.csv")
    df_results.to_csv(csv_path, index=False)

    summary_rows = []
    for (m_name, target_a), group in df_results.groupby(["Method", "Target_Alpha"]):
        summary_rows.append({
            "Method": m_name,
            "Variant": group["Variant"].iloc[0],
            "Target_Alpha": target_a,
            "Mean_Achieved_FPR": float(group["Achieved_FPR"].mean()),
            "Std_Achieved_FPR": float(group["Achieved_FPR"].std()),
            "Mean_FPR_Excess": float(group["FPR_Excess_Error"].mean()),
            "FPR_Target_Met_Fraction": float(group["FPR_Target_Met"].mean()),
            "Mean_F1": float(group["F1"].mean()),
            "Std_F1": float(group["F1"].std()),
            "Mean_Recall": float(group["Recall"].mean()),
            "Mean_Precision": float(group["Precision"].mean()),
            "Evaluated_Configurations": int(len(group))
        })
    df_summary = pd.DataFrame(summary_rows).sort_values(["Target_Alpha", "Variant", "Mean_Achieved_FPR"])
    sum_csv = os.path.join(OUTPUT_METRICS_DIR, "stage4_conformal_summary_by_method.csv")
    df_summary.to_csv(sum_csv, index=False)

    print(f"\nSaved stage 4 benchmark metrics to {csv_path} and {sum_csv}")
    return df_results, df_summary

def run_testbed_side_by_side():
    print("\n" + "=" * 80)
    print("STAGE 4 STEP 1: TESTBED RE-RUN (ORACLE VS LABEL-FREE & FLASH CROWD AUDIT)")
    print("=" * 80)

    parquet_file = "data/testbed/testbed_60s_regular.parquet"
    df = pd.read_parquet(parquet_file)

    train_df = df.iloc[0:200]
    val_df = df.iloc[200:300]
    test_df = df.iloc[300:600]

    n_train = len(train_df)
    n_val = len(val_df)
    n_test = len(test_df)
    total_len = len(df)

    feature_cols = [
        "flow_count", "tot_fwd_bytes", "tot_bwd_bytes", "duration_mean",
        "status_200_count", "status_4xx_count", "status_5xx_count",
        "error_rate", "p50_latency", "p95_latency", "p99_latency"
    ]

    scaler = StandardScaler()
    X_train = scaler.fit_transform(np.nan_to_num(train_df[feature_cols].values.astype(float)))
    X_val = scaler.transform(np.nan_to_num(val_df[feature_cols].values.astype(float)))
    X_test = scaler.transform(np.nan_to_num(test_df[feature_cols].values.astype(float)))
    X_full = np.vstack([X_train, X_val, X_test])

    y_train = train_df["Label"].values.astype(int)
    y_val = val_df["Label"].values.astype(int)
    y_test = test_df["Label"].values.astype(int)
    is_fc_test = test_df["is_flash_crowd"].values.astype(int)
    t_test = test_df["window_time"].values.astype(float)

    val_slice = slice(n_train, n_train + n_val)
    test_slice = slice(n_train + n_val, total_len)

    model_scores = {}
    seed = 42

    # Fit frozen models
    if_model = IsolationForestBaseline(n_estimators=100, random_state=seed).fit(X_train)
    model_scores["Baseline: Isolation Forest"] = (if_model.score_samples(X_val), if_model.score_samples(X_test))

    ar_model = ARIMAResidualBaseline(order=(1, 0, 1)).fit(X_train)
    model_scores["Baseline: ARIMA Residual"] = (ar_model.score_samples(X_val), ar_model.score_samples(X_test))

    mps_full, _ = compute_multidimensional_mp(X_full, m=10)
    mps_tr_val = mps_full[:, : n_train + n_val - 10 + 1]
    knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
    scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=10)
    model_scores["Config A (mSTAMP+Kneedle)"] = (scores_full_a[val_slice], scores_full_a[test_slice])

    aprime = CausalABScorer(m=10).fit(X_train)
    model_scores["Config A-prime (Causal AB)"] = (aprime.score(X_val), aprime.score(X_test))

    testbed_records = []
    fc_records = []
    diagnostic_series = {}

    for model_name, (s_val, s_test) in model_scores.items():
        roc_auc = float(roc_auc_score(y_test, s_test))
        pr_auc = float(average_precision_score(y_test, s_test))

        for alpha in [0.05, 0.01]:
            alpha_str = f"{int(alpha * 100):02d}"

            th_quant = calibrate_benign_quantile_threshold(s_val, y_val, alpha=alpha)
            p_quant = (s_test >= th_quant).astype(int)

            cqt = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val)
            p_stat = cqt.predict(s_test)
            th_stat = cqt.threshold_

            p_roll_oracle, th_roll_oracle = cqt.predict_rolling_oracle(
                s_test, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
            )
            p_aci_oracle, th_aci_oracle, alphas_aci_oracle = cqt.predict_aci_oracle(
                s_test, gamma=0.01, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0)
            )

            p_roll_lf, th_roll_lf = cqt.predict_rolling_label_free(
                s_test, window_size=60, alpha=alpha
            )
            p_aci_lf, th_aci_lf, alphas_aci_lf = cqt.predict_aci_label_free(
                s_test, gamma=0.01, window_size=60, alpha=alpha
            )

            if model_name == "Baseline: Isolation Forest" and alpha == 0.05:
                diagnostic_series = {
                    "scores": s_test,
                    "y_true": y_test,
                    "is_flash_crowd": is_fc_test,
                    "th_stat": th_stat,
                    "th_roll_oracle": th_roll_oracle,
                    "th_aci_oracle": th_aci_oracle,
                    "th_roll_lf": th_roll_lf,
                    "th_aci_lf": th_aci_lf,
                    "p_roll_oracle": p_roll_oracle,
                    "p_roll_lf": p_roll_lf,
                    "p_quant": p_quant
                }

            methods = [
                ("Static Benign Quantile", p_quant, th_quant, "Baseline"),
                ("Static Split-Conformal", p_stat, th_stat, "Baseline"),
                ("Rolling Split-Conformal (Oracle)", p_roll_oracle, float(np.mean(th_roll_oracle)), "Oracle-Feedback Upper Bound"),
                ("Adaptive Conformal (ACI, Oracle)", p_aci_oracle, float(np.mean(th_aci_oracle)), "Oracle-Feedback Upper Bound"),
                ("Rolling Split-Conformal (Label-Free)", p_roll_lf, float(np.mean(th_roll_lf)), "Label-Free Autonomous"),
                ("Adaptive Conformal (ACI, Label-Free)", p_aci_lf, float(np.mean(th_aci_lf)), "Label-Free Autonomous")
            ]

            for m_name, pred_arr, mean_th, m_variant in methods:
                tn, fp, fn, tp = confusion_matrix(y_test, pred_arr, labels=[0, 1]).ravel()
                prec = float(precision_score(y_test, pred_arr, zero_division=0))
                rec = float(recall_score(y_test, pred_arr, zero_division=0))
                f1 = float(f1_score(y_test, pred_arr, zero_division=0))
                achieved_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

                sre_m = compute_sre_operational_metrics(
                    y_test, pred_arr, timestamps=t_test, default_step_sec=60.0, is_flow_data=False
                )

                # Flash crowd false alarm rate (Label == 0 and is_flash_crowd == 1)
                fc_mask = (is_fc_test == 1)
                fc_total = int(np.sum(fc_mask))
                fc_alerts = int(np.sum(pred_arr[fc_mask]))
                fc_fpr = float(fc_alerts / fc_total) if fc_total > 0 else 0.0

                testbed_records.append({
                    "Model": model_name,
                    "Method": m_name,
                    "Variant": m_variant,
                    "Target_Alpha": alpha,
                    "ROC_AUC": roc_auc,
                    "PR_AUC": pr_auc,
                    "Mean_Threshold": mean_th,
                    "Test_FPR": achieved_fpr,
                    "Recall": rec,
                    "Precision": prec,
                    "F1": f1,
                    "Flash_Crowd_FPR": fc_fpr,
                    "Flash_Crowd_Alerts": fc_alerts,
                    "Flash_Crowd_Total": fc_total,
                    "Alerts_Per_Hour": sre_m.get("alerts_per_hour", None),
                    "Campaign_Recall": sre_m.get("campaign_recall", 1.0),
                    "MTTD_Sec": sre_m.get("mttd_detected_campaigns_only_sec", None)
                })

    df_tb = pd.DataFrame(testbed_records)
    tb_csv = os.path.join(OUTPUT_METRICS_DIR, "stage4_testbed_results.csv")
    df_tb.to_csv(tb_csv, index=False)
    print(f"Saved testbed side-by-side results to {tb_csv}")

    # Plot Flash Crowd Diagnostic Figure
    generate_flash_crowd_diagnostic_figure(diagnostic_series)

    return df_tb

def generate_flash_crowd_diagnostic_figure(diag: dict):
    if not diag:
        return

    print("\nGenerating Figure: Flash crowd threshold behavior under label-free vs oracle rule...")
    scores = diag["scores"]
    y_true = diag["y_true"]
    is_fc = diag["is_flash_crowd"]
    n_steps = len(scores)
    t_axis = np.arange(n_steps)

    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 9), sharex=True, dpi=200)

    # Panel 1: Scores and Thresholds
    ax1.plot(t_axis, scores, color="#222222", alpha=0.6, linewidth=1.2, label="Isolation Forest Anomaly Score")
    ax1.axhline(diag["th_stat"], color="#7f7f7f", linestyle=":", linewidth=1.5, label=f"Static Conformal ({diag['th_stat']:.3f})")
    ax1.plot(t_axis, diag["th_roll_oracle"], color="#1f77b4", linestyle="--", linewidth=1.8, label=r"Rolling Conformal (Oracle, $y_{\mathrm{test}}=0$)")
    ax1.plot(t_axis, diag["th_roll_lf"], color="#d62728", linestyle="-", linewidth=2.0, label="Rolling Conformal (Label-Free Autonomous)")

    # Highlight Flash Crowds and Attack periods
    fc_mask = (is_fc == 1)
    attack_mask = (y_true == 1)
    ax1.fill_between(t_axis, 0, np.max(scores)*1.1, where=attack_mask, color="orange", alpha=0.2, label="Attack Campaigns (Label=1)")
    ax1.fill_between(t_axis, 0, np.max(scores)*1.1, where=fc_mask, color="cyan", alpha=0.3, label="Benign Flash Crowds (Label=0)")

    ax1.set_ylabel("Score & Thresholds", fontsize=10)
    ax1.set_title("Flash Crowd Threshold Behavior: Oracle-Feedback vs Label-Free Autonomous Rule", fontsize=12, fontweight="bold")
    ax1.legend(loc="upper left", fontsize=8, framealpha=0.9, ncol=2)
    ax1.grid(True, linestyle=":", alpha=0.5)

    # Panel 2: Simulation of Buffer Content over time (Oracle vs Label-Free)
    # We trace buffer mean score under both rules
    # Oracle buffer
    buf_oracle = []
    buf_lf = []
    # Seed
    buf_mean_oracle = np.zeros(n_steps)
    buf_mean_lf = np.zeros(n_steps)

    # Re-simulate buffer contents for visualization
    for t in range(n_steps):
        s_t = scores[t]
        # Oracle adds if y_true == 0
        if y_true[t] == 0:
            buf_oracle.append(s_t)
            if len(buf_oracle) > 60:
                buf_oracle.pop(0)
        buf_mean_oracle[t] = np.mean(buf_oracle) if len(buf_oracle) > 0 else 0.0

        # Label-free adds if unflagged (score < th_roll_lf[t])
        if diag["p_roll_lf"][t] == 0:
            buf_lf.append(s_t)
            if len(buf_lf) > 60:
                buf_lf.pop(0)
        buf_mean_lf[t] = np.mean(buf_lf) if len(buf_lf) > 0 else 0.0

    ax2.plot(t_axis, buf_mean_oracle, color="#1f77b4", linestyle="--", linewidth=1.8, label="Mean Buffer Score (Oracle Feedback)")
    ax2.plot(t_axis, buf_mean_lf, color="#d62728", linestyle="-", linewidth=2.0, label="Mean Buffer Score (Label-Free Autonomous)")
    ax2.fill_between(t_axis, 0, np.max(buf_mean_oracle)*1.2, where=fc_mask, color="cyan", alpha=0.3)
    ax2.set_ylabel("Buffer Mean Score", fontsize=10)
    ax2.set_title("Rolling Buffer Content Dynamics: Oracle Admits High Flash-Crowd Scores; Label-Free Excludes Flagged Windows", fontsize=10, fontweight="bold")
    ax2.legend(loc="upper left", fontsize=8, framealpha=0.9)
    ax2.grid(True, linestyle=":", alpha=0.5)

    # Panel 3: Alerts per window (Cumulative False Alarms on Flash Crowds)
    cum_fc_stat = np.cumsum(diag["p_quant"] * fc_mask)
    cum_fc_oracle = np.cumsum(diag["p_roll_oracle"] * fc_mask)
    cum_fc_lf = np.cumsum(diag["p_roll_lf"] * fc_mask)

    ax3.plot(t_axis, cum_fc_stat, color="#7f7f7f", linestyle=":", linewidth=1.8, label="Static Quantile Flash Crowd Alerts")
    ax3.plot(t_axis, cum_fc_oracle, color="#1f77b4", linestyle="--", linewidth=1.8, label="Rolling Conformal (Oracle) Flash Crowd Alerts")
    ax3.plot(t_axis, cum_fc_lf, color="#d62728", linestyle="-", linewidth=2.0, label="Rolling Conformal (Label-Free) Flash Crowd Alerts")
    ax3.fill_between(t_axis, 0, np.max(cum_fc_stat)*1.1, where=fc_mask, color="cyan", alpha=0.3)
    ax3.set_xlabel("Elapsed Minutes on Test Slice", fontsize=10)
    ax3.set_ylabel("Cumulative Flash Crowd Alerts", fontsize=10)
    ax3.set_title("Cumulative False Alarms on Benign Flash Crowd Windows", fontsize=10, fontweight="bold")
    ax3.legend(loc="upper left", fontsize=8, framealpha=0.9)
    ax3.grid(True, linestyle=":", alpha=0.5)

    plt.tight_layout()
    fig_path = os.path.join(OUTPUT_FIGURES_DIR, "figure_flash_crowd_label_free_behavior.png")
    plt.savefig(fig_path)
    plt.close()
    print(f"Saved diagnostic figure to {fig_path}")

if __name__ == "__main__":
    save_run_metadata("step1")
    run_stage2_side_by_side()
    run_testbed_side_by_side()

