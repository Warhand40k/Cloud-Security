"""
Stage 4 Step 4: Testbed Repeats and Honesty Checks
Verification and honest re-measurement of microservice testbed claims.

Executes:
1. Multi-seed testbed orchestration (5 reproducible seeds: 42, 43, 44, 45, 46)
2. Randomized campaign schedules with interleaved flash crowds and randomized durations
3. Live socket telemetry collection via Flask microservice and ConfinedAttacker
4. Full model evaluation (All features, Volume-only features, FC-augmented training, ARIMA, mSTAMP, Causal AB)
5. Strict label-free autonomous conformal vs static thresholding comparison (with oracle reference)
6. Separation of attack alerts/hour from benign and flash-crowd alerts/hour
7. Campaign recall with exact Clopper-Pearson binomial confidence intervals

Outputs:
- results/v4/metrics/testbed_multiseed_evaluation.csv
- results/v4/metrics/testbed_multiseed_summary.csv
- results/v4/metrics/testbed_diagnostic_baselines.csv
- results/v4/figures/figure_testbed_multiseed_summary.png
- results/v4/run_metadata_step4.json
"""

import os
import sys
import time
import math
import json
import random
import socket
import platform
import subprocess
import requests
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Tuple, Optional
from scipy.stats import beta
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    roc_auc_score, average_precision_score, confusion_matrix,
    precision_score, recall_score, f1_score
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testbed.attacker import ConfinedAttacker
from testbed.run_testbed import generate_benign_traffic
from src.adaptive_threshold import ConformalQuantileThreshold, calibrate_benign_quantile_threshold
from src.matrix_profile import compute_multidimensional_mp
from src.kneedle import find_knee_dimension
from src.anomaly_scoring import compute_point_anomaly_scores
from src.causal_ab_scorer import CausalABScorer
from src.baselines import (
    IsolationForestBaseline, ARIMAResidualBaseline,
    AllAttackBaseline, AllNormalBaseline, RandomUniformBaseline
)

OUTPUT_DATA_DIR = "data/testbed"
OUTPUT_METRICS_DIR = "results/v4/metrics"
OUTPUT_FIGURES_DIR = "results/v4/figures"
os.makedirs(OUTPUT_DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_METRICS_DIR, exist_ok=True)
os.makedirs(OUTPUT_FIGURES_DIR, exist_ok=True)

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8088
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def wait_for_service(url: str = BASE_URL, timeout: float = 12.0) -> bool:
    """Waits for microservice to become healthy."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{url}/health", timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False

FEATURE_COLS = [
    "flow_count", "tot_fwd_bytes", "tot_bwd_bytes", "duration_mean",
    "status_200_count", "status_4xx_count", "status_5xx_count",
    "error_rate", "p50_latency", "p95_latency", "p99_latency"
]

VOLUME_ONLY_COLS = ["flow_count", "tot_fwd_bytes", "tot_bwd_bytes"]

SEEDS = [42, 43, 44, 45, 46]

def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Exact Clopper-Pearson 95% confidence interval for binomial success probability."""
    if n == 0:
        return 0.0, 0.0
    lower = 0.0 if k == 0 else float(beta.ppf(alpha / 2.0, k, n - k + 1))
    upper = 1.0 if k == n else float(beta.ppf(1.0 - alpha / 2.0, k + 1, n - k))
    return lower, upper

def generate_randomized_schedule(seed: int, test_start: int = 300, test_end: int = 599) -> List[Dict[str, Any]]:
    """
    Generates a randomized campaign schedule:
    - 25 total campaigns (5 of each category: flood, slowloris, spike, recon, flash crowd)
    - Categories and instances shuffled in random order
    - Flash crowds interleaved naturally throughout the test horizon (not clustered at the end)
    - Random durations within stated ranges
    - Quiescent benign gaps between campaigns
    - Test slice strictly confined to [test_start, test_end]
    """
    rng = random.Random(seed)

    campaign_specs = [
        ("volumetric_flood", 1, 0, (5, 9), (4.5, 7.0), "Volumetric HTTP Flood"),
        ("slowloris", 1, 0, (6, 8), (1.2, 1.5), "Low-and-Slow Slowloris"),
        ("intermittent_spike", 1, 0, (5, 7), (3.5, 4.5), "Intermittent Pulsing Spike"),
        ("endpoint_recon", 1, 0, (5, 7), (2.5, 3.2), "Endpoint Reconnaissance Scan"),
        ("flash_crowd", 0, 1, (6, 8), (3.5, 5.0), "Benign Flash Crowd Surge")
    ]

    items = []
    for c_type, is_attack, is_fc, dur_range, int_range, desc in campaign_specs:
        for i in range(5):
            items.append({
                "type": c_type,
                "is_attack": is_attack,
                "is_flash_crowd": is_fc,
                "dur_range": dur_range,
                "int_range": int_range,
                "shape": f"randomized_shape_{i+1}",
                "description": f"{desc} #{i+1}"
            })

    # Shuffle order so types and flash crowds are thoroughly interleaved
    rng.shuffle(items)

    cur_w = test_start + rng.randint(2, 5)
    placed = []
    for c_id, item in enumerate(items, start=1):
        dur = rng.randint(item["dur_range"][0], item["dur_range"][1])
        intensity = round(rng.uniform(item["int_range"][0], item["int_range"][1]), 2)
        end_w = cur_w + dur - 1

        if end_w > test_end:
            dur = max(3, test_end - cur_w + 1)
            end_w = cur_w + dur - 1

        placed.append({
            "id": c_id,
            "type": item["type"],
            "shape": item["shape"],
            "start_window": cur_w,
            "end_window": end_w,
            "duration": dur,
            "is_attack": item["is_attack"],
            "is_flash_crowd": item["is_flash_crowd"],
            "intensity": intensity,
            "description": item["description"]
        })

        gap = rng.randint(3, 6)
        cur_w = end_w + gap + 1
        if cur_w >= test_end - 4:
            break

    return placed

def run_single_testbed_simulation(seed: int, campaigns: List[Dict[str, Any]], n_windows: int = 600, window_sim_sec: float = 0.08) -> pd.DataFrame:
    """Executes live simulation against Flask microservice for one seed."""
    rng = random.Random(seed)
    campaign_map = {}
    for c in campaigns:
        for w in range(c["start_window"], c["end_window"] + 1):
            campaign_map[w] = c

    attacker = ConfinedAttacker(target_host=TARGET_HOST, target_port=TARGET_PORT)
    session = requests.Session()
    base_timestamp = 1794268800 + seed * 86400  # Shifted timestamp per seed

    records = []
    t_start = time.time()

    for w in range(n_windows):
        window_dt = base_timestamp + w * 60

        # Diurnal sinusoidal baseline with noise
        cycle_phase = (w / n_windows) * 2.0 * math.pi
        diurnal_factor = 1.0 + 0.4 * math.sin(cycle_phase - math.pi / 2.0)
        noise = rng.gauss(0, 0.05)
        load_factor = max(0.5, diurnal_factor + noise)

        # 1. Benign background traffic
        generate_benign_traffic(session, load_multiplier=load_factor, duration_sec=window_sim_sec)

        # 2. Campaign execution
        active_campaign = campaign_map.get(w, None)
        if active_campaign is not None:
            attacker.execute_campaign(active_campaign, window_duration_sec=window_sim_sec)

        # 3. Telemetry flush
        resp = requests.post(f"{BASE_URL}/telemetry/flush_window", timeout=2.0)
        tdata = resp.json()

        if active_campaign is not None:
            c_id = active_campaign["id"]
            c_type = active_campaign["type"]
            c_shape = active_campaign["shape"]
            is_attack = active_campaign["is_attack"]
            is_fc = active_campaign["is_flash_crowd"]
        else:
            c_id = 0
            c_type = "benign_normal"
            c_shape = "diurnal_background"
            is_attack = 0
            is_fc = 0

        records.append({
            "window_idx": w,
            "window_time": window_dt,
            "flow_count": tdata["flow_count"],
            "tot_fwd_bytes": tdata["tot_fwd_bytes"],
            "tot_bwd_bytes": tdata["tot_bwd_bytes"],
            "duration_mean": tdata["duration_mean"],
            "status_200_count": tdata["status_200_count"],
            "status_4xx_count": tdata["status_4xx_count"],
            "status_5xx_count": tdata["status_5xx_count"],
            "error_rate": tdata["error_rate"],
            "p50_latency": tdata["p50_latency"],
            "p95_latency": tdata["p95_latency"],
            "p99_latency": tdata["p99_latency"],
            "Label": is_attack,
            "is_flash_crowd": is_fc,
            "campaign_id": c_id,
            "campaign_type": c_type,
            "campaign_shape": c_shape
        })

    elapsed = time.time() - t_start
    print(f"      Seed {seed} simulation completed: 600 windows in {elapsed:.1f}s ({elapsed/n_windows:.3f}s/window)")
    return pd.DataFrame(records)

def evaluate_testbed_seed(df: pd.DataFrame, campaigns: List[Dict[str, Any]], seed: int) -> List[Dict[str, Any]]:
    """Evaluates detectors and calibration methods on a single testbed run."""
    train_df = df.iloc[0:200]
    val_df = df.iloc[200:300]
    test_df = df.iloc[300:600]

    n_train = len(train_df)
    n_val = len(val_df)
    n_test = len(test_df)
    total_len = len(df)

    y_train = train_df["Label"].values.astype(int)
    y_val = val_df["Label"].values.astype(int)
    y_test = test_df["Label"].values.astype(int)
    is_fc_test = test_df["is_flash_crowd"].values.astype(int)
    prevalence = float(np.mean(y_test))

    # Identify benign subsets in test slice
    normal_benign_mask = (y_test == 0) & (is_fc_test == 0)
    fc_mask = (is_fc_test == 1)
    all_benign_mask = (y_test == 0)
    attack_mask = (y_test == 1)

    n_normal_benign = int(np.sum(normal_benign_mask))
    n_fc = int(np.sum(fc_mask))
    n_attacks = int(np.sum(attack_mask))

    # Test slice duration in hours: 300 windows * 60s = 18000s = 5.0 hours
    hours_test = (n_test * 60.0) / 3600.0
    hours_attack = (n_attacks * 60.0) / 3600.0 if n_attacks > 0 else 1.0
    hours_benign = (n_normal_benign * 60.0) / 3600.0 if n_normal_benign > 0 else 1.0
    hours_fc = (n_fc * 60.0) / 3600.0 if n_fc > 0 else 1.0

    # 1. Standard Scaling on All Features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(np.nan_to_num(train_df[FEATURE_COLS].values.astype(float)))
    X_val = scaler.transform(np.nan_to_num(val_df[FEATURE_COLS].values.astype(float)))
    X_test = scaler.transform(np.nan_to_num(test_df[FEATURE_COLS].values.astype(float)))
    X_full = np.vstack([X_train, X_val, X_test])

    # 2. Volume-Only Scaling
    scaler_vol = StandardScaler()
    X_tr_vol = scaler_vol.fit_transform(np.nan_to_num(train_df[VOLUME_ONLY_COLS].values.astype(float)))
    X_val_vol = scaler_vol.transform(np.nan_to_num(val_df[VOLUME_ONLY_COLS].values.astype(float)))
    X_te_vol = scaler_vol.transform(np.nan_to_num(test_df[VOLUME_ONLY_COLS].values.astype(float)))

    # 3. Flash-Crowd-Augmented Benign Training Set (Diagnostic Baseline b)
    # Augment benign training and validation with realistic flash crowd profiles
    rng_syn = np.random.default_rng(seed)
    fc_syn_rows = []
    for _ in range(20):
        fc_flows = rng_syn.integers(180, 260)
        fc_syn_rows.append({
            "flow_count": fc_flows,
            "tot_fwd_bytes": fc_flows * 120,
            "tot_bwd_bytes": fc_flows * 850,
            "duration_mean": 0.015,
            "status_200_count": fc_flows,
            "status_4xx_count": 0,
            "status_5xx_count": 0,
            "error_rate": 0.0,
            "p50_latency": 0.012,
            "p95_latency": 0.024,
            "p99_latency": 0.035
        })
    df_fc_syn = pd.DataFrame(fc_syn_rows)
    train_aug = pd.concat([train_df[FEATURE_COLS], df_fc_syn], ignore_index=True)
    val_aug = pd.concat([val_df[FEATURE_COLS], df_fc_syn.iloc[:10]], ignore_index=True)

    scaler_aug = StandardScaler()
    X_tr_aug = scaler_aug.fit_transform(train_aug.values.astype(float))
    X_val_aug = scaler_aug.transform(val_aug.values.astype(float))
    X_te_aug = scaler_aug.transform(test_df[FEATURE_COLS].values.astype(float))

    # --- Compute Anomaly Scores ---
    models_dict = {}

    # Detector 1: Baseline Isolation Forest (All Features)
    clf_if = IsolationForestBaseline(n_estimators=100, random_state=seed).fit(X_train)
    models_dict["Baseline: Isolation Forest"] = (
        clf_if.score_samples(X_val),
        clf_if.score_samples(X_test),
        y_val,
        "Primary Detector"
    )

    # Detector 2: Diagnostic Baseline (a) Volume-Only Features
    clf_vol = IsolationForestBaseline(n_estimators=100, random_state=seed).fit(X_tr_vol)
    models_dict["Diagnostic Baseline (a): Volume-Only IF"] = (
        clf_vol.score_samples(X_val_vol),
        clf_vol.score_samples(X_te_vol),
        y_val,
        "Diagnostic Baseline"
    )

    # Detector 3: Diagnostic Baseline (b) Flash-Crowd-Augmented Training
    clf_fc_aug = IsolationForestBaseline(n_estimators=100, random_state=seed).fit(X_tr_aug)
    y_val_aug = np.zeros(len(val_aug), dtype=int)
    models_dict["Diagnostic Baseline (b): FC-Augmented IF"] = (
        clf_fc_aug.score_samples(X_val_aug),
        clf_fc_aug.score_samples(X_te_aug),
        y_val_aug,
        "Diagnostic Baseline"
    )

    # Detector 4: Baseline ARIMA Residual
    clf_ar = ARIMAResidualBaseline(order=(1, 0, 1)).fit(X_train)
    models_dict["Baseline: ARIMA Residual"] = (
        clf_ar.score_samples(X_val),
        clf_ar.score_samples(X_test),
        y_val,
        "Primary Detector"
    )

    # Detector 5: Config A (mSTAMP + Kneedle)
    mps_full, _ = compute_multidimensional_mp(X_full, m=10)
    mps_tr_val = mps_full[:, : n_train + n_val - 10 + 1]
    knee_dim_a, _ = find_knee_dimension(mps_tr_val, online=True, metric="max")
    scores_full_a = compute_point_anomaly_scores(mps_full, knee_dim=knee_dim_a, n_samples=total_len, m=10)
    s_val_a = scores_full_a[n_train:n_train + n_val]
    s_test_a = scores_full_a[n_train + n_val:total_len]
    models_dict["Config A (mSTAMP+Kneedle)"] = (s_val_a, s_test_a, y_val, "Primary Detector")

    # Detector 6: Config A-prime (Causal AB)
    aprime = CausalABScorer(m=10).fit(X_train)
    s_val_ap = aprime.score(X_val)
    s_test_ap = aprime.score(X_test)
    models_dict["Config A-prime (Causal AB)"] = (s_val_ap, s_test_ap, y_val, "Primary Detector")

    # --- Evaluate Calibration Methods on All Detectors ---
    records = []
    alpha = 0.05

    # Filter campaigns to test horizon attack campaigns
    test_attack_campaigns = [c for c in campaigns if c["is_attack"] == 1 and c["start_window"] >= 300]
    n_attack_campaigns = len(test_attack_campaigns)

    for model_name, (s_val, s_test, y_val_cur, model_role) in models_dict.items():
        s_val = np.nan_to_num(s_val.astype(float))
        s_test = np.nan_to_num(s_test.astype(float))

        # Discrimination metrics
        try:
            roc_auc = float(roc_auc_score(y_test, s_test))
            pr_auc = float(average_precision_score(y_test, s_test))
        except Exception:
            roc_auc, pr_auc = 0.50, prevalence

        # Calibrations
        # 1. Static Benign Quantile
        th_q = calibrate_benign_quantile_threshold(s_val, y_val_cur, alpha=alpha)
        p_q = (s_test >= th_q).astype(int)

        # 2. Static Split-Conformal
        cqt = ConformalQuantileThreshold(alpha=alpha).fit(s_val, y_val_cur)
        p_c = cqt.predict(s_test)

        # 3. Rolling Conformal (Label-Free Autonomous)
        p_r_lf, _ = cqt.predict_rolling_label_free(s_test, window_size=60, alpha=alpha)

        # 4. ACI (Label-Free Autonomous)
        p_a_lf, _, _ = cqt.predict_aci_label_free(s_test, gamma=0.01, window_size=60, alpha=alpha)

        # 5. Rolling Conformal (Oracle Upper Bound)
        p_r_orc, _ = cqt.predict_rolling_oracle(s_test, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0))

        # 6. ACI (Oracle Upper Bound)
        p_a_orc, _, _ = cqt.predict_aci_oracle(s_test, gamma=0.01, window_size=60, alpha=alpha, verified_benign_mask=(y_test == 0))

        calib_items = [
            ("Static Benign Quantile", p_q, "Static", "Baseline"),
            ("Static Split-Conformal", p_c, "Static", "Baseline"),
            ("Rolling Split-Conformal (Label-Free)", p_r_lf, "Adaptive", "Label-Free Autonomous"),
            ("Adaptive Conformal (ACI, Label-Free)", p_a_lf, "Adaptive", "Label-Free Autonomous"),
            ("Rolling Split-Conformal (Oracle)", p_r_orc, "Adaptive", "Oracle-Feedback Upper Bound"),
            ("Adaptive Conformal (ACI, Oracle)", p_a_orc, "Adaptive", "Oracle-Feedback Upper Bound")
        ]

        for method_name, p_arr, m_cat, m_var in calib_items:
            # Overall confusion matrix
            tn, fp, fn, tp = confusion_matrix(y_test, p_arr, labels=[0, 1]).ravel()
            prec = float(precision_score(y_test, p_arr, zero_division=0))
            rec = float(recall_score(y_test, p_arr, zero_division=0))
            f1 = float(f1_score(y_test, p_arr, zero_division=0))
            test_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

            # Flash Crowd False Alarm Rate (FAR_FC = alerts during FC / n_fc)
            fc_alerts = int(np.sum(p_arr[fc_mask]))
            fc_far = float(fc_alerts / n_fc) if n_fc > 0 else 0.0

            # Normal Benign FPR (excluding flash crowds)
            norm_benign_alerts = int(np.sum(p_arr[normal_benign_mask]))
            norm_benign_fpr = float(norm_benign_alerts / n_normal_benign) if n_normal_benign > 0 else 0.0

            # Attack alerts (True Positives)
            attack_alerts = int(np.sum(p_arr[attack_mask]))

            # Alerts per Hour separated by category
            total_alerts = int(np.sum(p_arr))
            total_alerts_per_hour = float(total_alerts / hours_test)
            attack_alerts_per_hour = float(attack_alerts / hours_attack)
            benign_alerts_per_hour = float(norm_benign_alerts / hours_benign)
            fc_alerts_per_hour = float(fc_alerts / hours_fc)

            # Campaign Recall: fraction of attack campaigns detected (>= 1 alert during campaign window)
            detected_campaigns = 0
            for camp in test_attack_campaigns:
                # Relative indices in test slice
                c_start_rel = camp["start_window"] - 300
                c_end_rel = camp["end_window"] - 300
                c_slice_preds = p_arr[c_start_rel:c_end_rel + 1]
                if np.sum(c_slice_preds) > 0:
                    detected_campaigns += 1

            camp_rec = float(detected_campaigns / n_attack_campaigns) if n_attack_campaigns > 0 else 0.0
            cp_low, cp_high = clopper_pearson(detected_campaigns, n_attack_campaigns)

            records.append({
                "Seed": seed,
                "Model": model_name,
                "Model_Role": model_role,
                "Method": method_name,
                "Method_Category": m_cat,
                "Variant": m_var,
                "Target_Alpha": alpha,
                "ROC_AUC": roc_auc,
                "PR_AUC": pr_auc,
                "Prevalence": prevalence,
                "Test_FPR": test_fpr,
                "Normal_Benign_FPR": norm_benign_fpr,
                "Flash_Crowd_FAR": fc_far,
                "Flash_Crowd_Alerts": fc_alerts,
                "Total_Flash_Crowd_Windows": n_fc,
                "Recall": rec,
                "Precision": prec,
                "F1": f1,
                "Campaign_Recall": camp_rec,
                "Campaigns_Detected": detected_campaigns,
                "Total_Attack_Campaigns": n_attack_campaigns,
                "CP_95_CI_Lower": cp_low,
                "CP_95_CI_Upper": cp_high,
                "Total_Alerts": total_alerts,
                "Total_Alerts_Per_Hour": total_alerts_per_hour,
                "Attack_Alerts_Per_Hour": attack_alerts_per_hour,
                "Benign_Alerts_Per_Hour": benign_alerts_per_hour,
                "Flash_Crowd_Alerts_Per_Hour": fc_alerts_per_hour
            })

    return records

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

def run_step4_verification():
    print("=" * 80)
    print("STAGE 4 STEP 4: TESTBED REPEATS AND HONESTY CHECKS")
    print(f"Orchestrating {len(SEEDS)} randomized runs across seeds: {SEEDS}")
    print("=" * 80)

    # 1. Start Microservice Process on dedicated port 8089
    python_bin = sys.executable
    app_path = os.path.join(os.path.dirname(__file__), "..", "testbed", "app.py")
    env = os.environ.copy()
    env["PORT"] = str(TARGET_PORT)

    print(f"\n[1/3] Spawning testbed microservice on {BASE_URL}...")
    proc = subprocess.Popen([python_bin, app_path], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    all_evaluation_records = []

    try:
        if not wait_for_service(timeout=10.0):
            raise RuntimeError(f"Microservice failed to start on {BASE_URL}")
        print("      Microservice healthy and responsive.")

        # 2. Iterate through 5 seeds
        for seed_idx, seed in enumerate(SEEDS, start=1):
            print(f"\n---> Executing Seed {seed} ({seed_idx}/{len(SEEDS)})...")
            parquet_path = os.path.join(OUTPUT_DATA_DIR, f"testbed_seed_{seed}.parquet")
            schedule_path = os.path.join(OUTPUT_DATA_DIR, f"testbed_schedule_seed_{seed}.json")

            if os.path.exists(parquet_path) and os.path.exists(schedule_path):
                print(f"      Loading existing simulation for Seed {seed} from {parquet_path}...")
                df_sim = pd.read_parquet(parquet_path)
                with open(schedule_path, "r") as f:
                    campaigns = json.load(f)
            else:
                # A. Generate randomized schedule
                campaigns = generate_randomized_schedule(seed=seed)
                with open(schedule_path, "w") as f:
                    json.dump(campaigns, f, indent=2)

                fc_types = [c["id"] for c in campaigns if c["is_flash_crowd"]]
                print(f"      Generated {len(campaigns)} campaigns (Flash Crowds interleaved at IDs: {fc_types})")

                # B. Execute simulation
                df_sim = run_single_testbed_simulation(seed=seed, campaigns=campaigns, n_windows=600, window_sim_sec=0.08)
                df_sim.to_parquet(parquet_path, index=False)

            # C. Evaluate models & calibrators
            print(f"      Evaluating models and threshold calibrators on Seed {seed}...")
            seed_records = evaluate_testbed_seed(df_sim, campaigns, seed=seed)
            all_evaluation_records.extend(seed_records)

    finally:
        print("\nShutting down microservice process...")
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except Exception:
            proc.kill()
        print("Microservice cleanly terminated.")

    # 3. Save Raw Multiseed Evaluation Table
    df_eval = pd.DataFrame(all_evaluation_records)
    eval_csv_path = os.path.join(OUTPUT_METRICS_DIR, "testbed_multiseed_evaluation.csv")
    df_eval.to_csv(eval_csv_path, index=False)
    print(f"\n[2/3] Saved full multiseed evaluation metrics to {eval_csv_path} ({len(df_eval)} rows)")

    # 4. Generate Pooled Summary Table (Mean +/- Std over seeds)
    summary_cols = [
        "ROC_AUC", "PR_AUC", "Test_FPR", "Normal_Benign_FPR", "Flash_Crowd_FAR",
        "Recall", "Precision", "F1", "Campaign_Recall",
        "Total_Alerts_Per_Hour", "Attack_Alerts_Per_Hour", "Benign_Alerts_Per_Hour", "Flash_Crowd_Alerts_Per_Hour"
    ]

    summary_records = []
    for (model, method, variant, m_role), grp in df_eval.groupby(["Model", "Method", "Variant", "Model_Role"]):
        row = {
            "Model": model,
            "Model_Role": m_role,
            "Method": method,
            "Variant": variant,
            "Num_Seeds": len(grp)
        }
        for col in summary_cols:
            vals = grp[col].values
            row[f"{col}_Mean"] = float(np.mean(vals))
            row[f"{col}_Std"] = float(np.std(vals))
            row[f"{col}_Formatted"] = f"{np.mean(vals):.4f} +/- {np.std(vals):.4f}"

        # Exact pooled Clopper-Pearson on campaign recall across all seeds
        total_detected = int(grp["Campaigns_Detected"].sum())
        total_possible = int(grp["Total_Attack_Campaigns"].sum())
        cp_low, cp_high = clopper_pearson(total_detected, total_possible)
        row["Pooled_Campaign_Recall"] = float(total_detected / total_possible) if total_possible > 0 else 0.0
        row["Pooled_Campaigns_Detected"] = total_detected
        row["Pooled_Campaigns_Total"] = total_possible
        row["Pooled_CP_95_CI"] = f"[{cp_low:.4f}, {cp_high:.4f}]"

        summary_records.append(row)

    df_summary = pd.DataFrame(summary_records)
    summary_csv_path = os.path.join(OUTPUT_METRICS_DIR, "testbed_multiseed_summary.csv")
    df_summary.to_csv(summary_csv_path, index=False)
    print(f"Saved pooled multiseed summary to {summary_csv_path}")

    # 5. Diagnostic Baselines Dedicated Table (Requirement 4)
    df_diag = df_summary[df_summary["Model_Role"] == "Diagnostic Baseline"].copy()
    diag_csv_path = os.path.join(OUTPUT_METRICS_DIR, "testbed_diagnostic_baselines.csv")
    df_diag.to_csv(diag_csv_path, index=False)
    print(f"Saved diagnostic baselines summary to {diag_csv_path}")

    # 6. Generate Publication-Quality Figure
    print("\n[3/3] Generating multi-panel diagnostic figure...")
    fig, axes = plt.subplots(2, 2, figsize=(15, 11), dpi=200)

    # Panel A: Flash Crowd False Alarm Rate (FAR_FC) by Method across Detectors
    ax_a = axes[0, 0]
    sub_pri = df_summary[df_summary["Model"] == "Baseline: Isolation Forest"].sort_values("Method")
    methods_plot = sub_pri["Method"].values
    y_pos = np.arange(len(methods_plot))
    fc_means = sub_pri["Flash_Crowd_FAR_Mean"].values * 100.0
    fc_stds = sub_pri["Flash_Crowd_FAR_Std"].values * 100.0
    colors_fc = ["#d62728" if m in ["Static Benign Quantile", "Static Split-Conformal", "Rolling Split-Conformal (Label-Free)", "Adaptive Conformal (ACI, Label-Free)"] else "#2ca02c" for m in methods_plot]

    ax_a.barh(y_pos, fc_means, xerr=fc_stds, color=colors_fc, alpha=0.85, capsize=4, edgecolor="black", linewidth=0.8)
    ax_a.set_yticks(y_pos)
    ax_a.set_yticklabels([m.replace(" (Label-Free)", "\n(Label-Free)").replace(" (Oracle)", "\n(Oracle Ref)") for m in methods_plot], fontsize=9)
    ax_a.set_xlabel("Flash Crowd False Alarm Rate (%)", fontsize=10, fontweight="bold")
    ax_a.set_title("A. Flash Crowd False Alarm Rejection\n(Isolation Forest, Mean +/- Std over 5 Seeds)", fontsize=11, fontweight="bold")
    ax_a.grid(True, linestyle="--", alpha=0.5)
    ax_a.set_xlim(-2, 105)

    # Panel B: Attack Recall vs Test FPR (Tradeoff Curve)
    ax_b = axes[0, 1]
    for m_name, color, marker in [
        ("Static Benign Quantile", "#1f77b4", "o"),
        ("Static Split-Conformal", "#2ca02c", "s"),
        ("Rolling Split-Conformal (Label-Free)", "#d62728", "^"),
        ("Adaptive Conformal (ACI, Label-Free)", "#9467bd", "v"),
        ("Rolling Split-Conformal (Oracle)", "#8c564b", "x"),
        ("Adaptive Conformal (ACI, Oracle)", "#e377c2", "+")
    ]:
        sub_m = df_summary[(df_summary["Method"] == m_name) & (df_summary["Model"] == "Baseline: Isolation Forest")].iloc[0]
        ax_b.errorbar(
            sub_m["Test_FPR_Mean"] * 100.0, sub_m["Recall_Mean"] * 100.0,
            xerr=sub_m["Test_FPR_Std"] * 100.0, yerr=sub_m["Recall_Std"] * 100.0,
            fmt=marker, color=color, label=m_name, markersize=8, capsize=4, elinewidth=1.5
        )
    ax_b.set_xlabel("Overall Test FPR (Benign + Flash Crowd, %)", fontsize=10, fontweight="bold")
    ax_b.set_ylabel("Attack Detection Recall (%)", fontsize=10, fontweight="bold")
    ax_b.set_title("B. Attack Recall vs Overall Test FPR\n(Mean +/- Std over 5 Seeds)", fontsize=11, fontweight="bold")
    ax_b.grid(True, linestyle="--", alpha=0.5)
    ax_b.legend(loc="lower right", fontsize=8)

    # Panel C: Alert Rate Breakdown (Attacks vs Benign vs Flash Crowd)
    ax_c = axes[1, 0]
    alert_sub = df_summary[df_summary["Model"] == "Baseline: Isolation Forest"].sort_values("Method")
    m_labels = [m.replace("Split-Conformal", "Conf").replace("Adaptive Conformal (ACI", "ACI").replace(" (Label-Free)", " (LF)").replace(" (Oracle)", " (Orc)") for m in alert_sub["Method"].values]
    x_c = np.arange(len(m_labels))
    w_bar = 0.25

    ax_c.bar(x_c - w_bar, alert_sub["Attack_Alerts_Per_Hour_Mean"], width=w_bar, color="#d62728", label="Attack Alerts / Hr (Desired)", edgecolor="black", linewidth=0.5)
    ax_c.bar(x_c, alert_sub["Benign_Alerts_Per_Hour_Mean"], width=w_bar, color="#1f77b4", label="Normal Benign Alerts / Hr (Noise)", edgecolor="black", linewidth=0.5)
    ax_c.bar(x_c + w_bar, alert_sub["Flash_Crowd_Alerts_Per_Hour_Mean"], width=w_bar, color="#ff7f0e", label="Flash Crowd Alerts / Hr (False Alarm)", edgecolor="black", linewidth=0.5)
    ax_c.set_xticks(x_c)
    ax_c.set_xticklabels(m_labels, rotation=25, ha="right", fontsize=8)
    ax_c.set_ylabel("Alerts per Operational Hour", fontsize=10, fontweight="bold")
    ax_c.set_title("C. Operational Alerts Breakdown by Traffic Category\n(Isolation Forest, 5 Seeds)", fontsize=11, fontweight="bold")
    ax_c.grid(True, linestyle="--", alpha=0.5)
    ax_c.legend(loc="upper right", fontsize=8)

    # Panel D: Diagnostic Baselines: Volume-Only vs All Features vs FC-Augmented
    ax_d = axes[1, 1]
    diag_models = [
        "Diagnostic Baseline (a): Volume-Only IF",
        "Baseline: Isolation Forest",
        "Diagnostic Baseline (b): FC-Augmented IF"
    ]
    diag_labels = [
        "Volume-Only IF\n(3 Features)",
        "Standard IF\n(All 11 Features)",
        "FC-Augmented IF\n(Augmented Train)"
    ]
    sub_diag = df_summary[(df_summary["Model"].isin(diag_models)) & (df_summary["Method"] == "Static Benign Quantile")]
    # Order according to diag_models
    sub_diag = sub_diag.set_index("Model").reindex(diag_models).reset_index()

    x_d = np.arange(len(diag_labels))
    ax_d.bar(x_d - 0.15, sub_diag["Flash_Crowd_FAR_Mean"] * 100.0, width=0.3, yerr=sub_diag["Flash_Crowd_FAR_Std"] * 100.0, color="#ff7f0e", label="Flash Crowd FAR (%)", capsize=4, edgecolor="black", linewidth=0.8)
    ax_d.bar(x_d + 0.15, sub_diag["Recall_Mean"] * 100.0, width=0.3, yerr=sub_diag["Recall_Std"] * 100.0, color="#2ca02c", label="Attack Recall (%)", capsize=4, edgecolor="black", linewidth=0.8)
    ax_d.set_xticks(x_d)
    ax_d.set_xticklabels(diag_labels, fontsize=9, fontweight="bold")
    ax_d.set_ylabel("Rate (%)", fontsize=10, fontweight="bold")
    ax_d.set_title("D. Root Cause Diagnosis: Flash Crowd Vulnerability\n(Static Quantile, Mean +/- Std over 5 Seeds)", fontsize=11, fontweight="bold")
    ax_d.grid(True, linestyle="--", alpha=0.5)
    ax_d.legend(loc="center right", fontsize=8)
    ax_d.set_ylim(0, 115)

    plt.suptitle("Stage 4 Step 4: Testbed Multi-Seed Verification & Root Cause Diagnostics", fontsize=14, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0.02, 1, 0.96])
    fig_path = os.path.join(OUTPUT_FIGURES_DIR, "figure_testbed_multiseed_summary.png")
    fig.savefig(fig_path, dpi=200)
    plt.close(fig)
    print(f"Saved summary figure to {fig_path}")

    # Save run metadata
    save_run_metadata("step4")
    print("\nStage 4 Step 4 verification completed successfully.")

if __name__ == "__main__":
    run_step4_verification()
