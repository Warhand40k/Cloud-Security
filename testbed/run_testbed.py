"""
Stage 3 Testbed Runner: Live Microservice Telemetry & Campaign Generation
Runs:
1. Microservice app (Flask + Prometheus metrics) on 127.0.0.1:8088
2. Benign diurnal traffic generator with sinusoidal user load and Poisson arrivals
3. Confined attacker executing 25 labeled campaigns (floods, slowloris, spikes, recon, flash crowds)
4. Collects 60-second regular windowed telemetry (flow metrics + Prometheus service metrics)
5. Saves to data/testbed/testbed_60s_regular.parquet & data/testbed/testbed_campaign_schedule.json
"""

import os
import sys
import time
import math
import random
import socket
import subprocess
import requests
import numpy as np
import pandas as pd
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testbed.campaign_schedule import get_campaign_schedule
from testbed.attacker import ConfinedAttacker

OUTPUT_DATA_DIR = "data/testbed"
os.makedirs(OUTPUT_DATA_DIR, exist_ok=True)

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8088
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def wait_for_service(timeout: float = 10.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{BASE_URL}/health", timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False

def generate_benign_traffic(session: requests.Session, load_multiplier: float, duration_sec: float = 0.15):
    """Generates benign background e-commerce traffic for one simulated window slice."""
    stop_time = time.time() + duration_sec
    n_reqs = max(5, int(15 * load_multiplier))

    endpoints = [
        ("/api/catalog?limit=20", "GET", None),
        ("/api/catalog/12", "GET", None),
        ("/api/catalog/45", "GET", None),
        ("/api/search?q=Cloud", "GET", None),
        ("/api/search?q=Component", "GET", None),
        ("/api/checkout", "POST", {"cart_id": "CART-1234", "items": [{"id": 1, "qty": 1}]}),
        ("/health", "GET", None)
    ]

    for _ in range(n_reqs):
        if time.time() >= stop_time:
            break
        ep, method, payload = random.choice(endpoints)
        try:
            if method == "POST":
                session.post(f"{BASE_URL}{ep}", json=payload, timeout=0.4)
            else:
                session.get(f"{BASE_URL}{ep}", timeout=0.4)
        except Exception:
            pass

def run_testbed_simulation(n_windows: int = 600, window_sim_sec: float = 0.15):
    print("=" * 80)
    print("STAGE 3 TESTBED: LIVE MICROSERVICE & CAMPAIGN ORCHESTRATION")
    print(f"Target: {n_windows} regular 60-second windows (10 hours simulated time)")
    print("=" * 80)

    # 1. Start Microservice Process
    python_bin = sys.executable
    app_path = os.path.join(os.path.dirname(__file__), "app.py")
    env = os.environ.copy()
    env["PORT"] = str(TARGET_PORT)

    print(f"\n[1/4] Spawning testbed microservice on {BASE_URL}...")
    proc = subprocess.Popen([python_bin, app_path], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        if not wait_for_service(timeout=10.0):
            raise RuntimeError(f"Microservice failed to start on {BASE_URL}")
        print("      Microservice healthy and responsive.")

        # 2. Initialize Attacker and Schedule
        attacker = ConfinedAttacker(target_host=TARGET_HOST, target_port=TARGET_PORT)
        campaigns = get_campaign_schedule()
        campaign_map = {}
        for c in campaigns:
            for w in range(c["start_window"], c["end_window"] + 1):
                campaign_map[w] = c

        print(f"[2/4] Loaded {len(campaigns)} labeled campaigns across test horizon (windows 300 - 599).")

        # 3. Execution Loop
        print(f"[3/4] Running {n_windows} simulated windows (accelerated real socket traffic)...")
        records = []
        session = requests.Session()

        # Simulated base timestamp: 2026-11-10 00:00:00 UTC
        base_timestamp = 1794268800  # Unix timestamp

        t_start = time.time()
        for w in range(n_windows):
            window_dt = base_timestamp + w * 60

            # Diurnal sinusoidal traffic intensity
            # Daytime peak at w=300 (noon), lull at w=0 and w=600 (midnight)
            cycle_phase = (w / n_windows) * 2.0 * math.pi
            diurnal_factor = 1.0 + 0.4 * math.sin(cycle_phase - math.pi / 2.0)
            noise = random.gauss(0, 0.05)
            load_factor = max(0.5, diurnal_factor + noise)

            # Generate benign traffic
            generate_benign_traffic(session, load_multiplier=load_factor, duration_sec=window_sim_sec)

            # Check if an attack campaign is active
            active_campaign = campaign_map.get(w, None)
            if active_campaign is not None:
                attacker.execute_campaign(active_campaign, window_duration_sec=window_sim_sec)

            # Flush telemetry from microservice
            flush_resp = requests.post(f"{BASE_URL}/telemetry/flush_window", timeout=2.0)
            tdata = flush_resp.json()

            # Assign labels
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

            record = {
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
            }
            records.append(record)

            if (w + 1) % 100 == 0 or w == n_windows - 1:
                elapsed = time.time() - t_start
                print(f"      Progress: {w + 1}/{n_windows} windows completed ({elapsed:.1f}s elapsed, {record['flow_count']} flows in window {w})")

        # 4. Save Telemetry Dataset
        print("\n[4/4] Saving collected telemetry and manifests...")
        df_telemetry = pd.DataFrame(records)
        parquet_path = os.path.join(OUTPUT_DATA_DIR, "testbed_60s_regular.parquet")
        schedule_path = os.path.join(OUTPUT_DATA_DIR, "testbed_campaign_schedule.json")
        csv_path = os.path.join(OUTPUT_DATA_DIR, "testbed_60s_regular.csv")

        df_telemetry.to_parquet(parquet_path, index=False)
        df_telemetry.to_csv(csv_path, index=False)

        import json
        with open(schedule_path, "w") as f:
            json.dump(campaigns, f, indent=2)

        print(f"      Parquet dataset: {parquet_path} ({len(df_telemetry)} rows)")
        print(f"      Schedule JSON: {schedule_path}")

        # Summary statistics
        n_attacks = int(df_telemetry["Label"].sum())
        n_fc = int(df_telemetry["is_flash_crowd"].sum())
        print(f"\nTelemetry Composition:")
        print(f"  Total Windows:        {len(df_telemetry)}")
        print(f"  Train Slice [0:200]:  200 windows (0 attacks, 0.0% prev)")
        print(f"  Val Slice [200:300]:  100 windows (0 attacks, 0.0% prev)")
        print(f"  Test Slice [300:600]: 300 windows ({n_attacks} attack windows, {n_attacks/300*100:.1f}% attack prevalence)")
        print(f"  Benign Flash Crowds:  {n_fc} windows in Test slice (Label = 0)")

    finally:
        print("\nShutting down microservice process...")
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except Exception:
            proc.kill()
        print("Microservice cleanly terminated.")

if __name__ == "__main__":
    run_testbed_simulation(n_windows=600, window_sim_sec=0.15)
