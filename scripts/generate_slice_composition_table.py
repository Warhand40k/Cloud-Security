"""
Generate Slice Composition Table & Verify Partition Integrity (Stage 1.5 Step 1 & 2)

Generates exact metrics, timestamps, and campaign counts (clipped to slice, g=0)
for every block in configs/v3_1/.
Asserts train_end < val_start and val_end < test_start.
Saves to results/v3_1/metrics/slice_composition.csv and .json.
"""

import os
import sys
import json
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.evaluation import find_campaign_intervals
from src.preprocessing import load_and_sort_raw_unsw, split_chronological

def main():
    os.makedirs("results/v3_1/metrics", exist_ok=True)
    records = []

    # 1. CSE-CIC-IDS2018 Blocks
    with open("configs/v3_1/cse_cic_ids2018_multiday.json") as f:
        cse_cfg = json.load(f)

    for b in cse_cfg["blocks"]:
        day = b["day"]
        df = pd.read_parquet(b["file"])
        slices = [
            ("Train", b["train_slice"], "Pure Benign Reference" if df.iloc[b["train_slice"][0]:b["train_slice"][1]]["Label"].sum() == 0 else "Benign Ref (Filtered)"),
            ("Val", b["val_slice"], "Threshold Calibration"),
            ("Test", b["test_slice"], "Held-Out Test Evaluation")
        ]
        
        # Verify chronological order
        tr_end = df.iloc[b["train_slice"][1] - 1]["window_time"]
        va_start = df.iloc[b["val_slice"][0]]["window_time"]
        va_end = df.iloc[b["val_slice"][1] - 1]["window_time"]
        te_start = df.iloc[b["test_slice"][0]]["window_time"]
        assert tr_end < va_start, f"[{day}] Train end ({tr_end}) must precede Val start ({va_start})"
        assert va_end < te_start, f"[{day}] Val end ({va_end}) must precede Test start ({te_start})"

        for part_name, (s_idx, e_idx), role in slices:
            sub = df.iloc[s_idx:e_idx]
            n_units = len(sub)
            y_arr = sub["Label"].values.astype(int)
            n_atk = int(y_arr.sum())
            prev = float(n_atk / n_units) if n_units > 0 else 0.0
            intervals = find_campaign_intervals(y_arr, gap_tolerance=0)
            n_camp = len(intervals)
            t_start = pd.to_datetime(sub["window_time"].iloc[0], unit="s")
            t_end = pd.to_datetime(sub["window_time"].iloc[-1], unit="s")
            elapsed_sec = float((sub["window_time"].iloc[-1] - sub["window_time"].iloc[0]) + 60.0)

            records.append({
                "Dataset": "CSE-CIC-IDS2018",
                "Block": day,
                "Partition": part_name,
                "Index_Range": f"[{s_idx}, {e_idx}]",
                "Start_Timestamp": str(t_start),
                "End_Timestamp": str(t_end),
                "Elapsed_Hours": round(elapsed_sec / 3600.0, 2),
                "Total_Units": n_units,
                "Unit_Type": "windows (60s)",
                "Attack_Units": n_atk,
                "Prevalence": round(prev * 100.0, 2),
                "Campaigns": n_camp,
                "Role": role
            })

    # 2. UNSW-NB15 Blocks
    with open("configs/v3_1/unsw_nb15.json") as f:
        unsw_cfg = json.load(f)

    for b in unsw_cfg["blocks"]:
        name = b["name"]
        is_flow = b.get("is_flow_data", False)
        if not is_flow:
            df = pd.read_parquet(b["file"])
            slices = [
                ("Train", b["train_slice"], "Filtered Benign Reference" if df.iloc[b["train_slice"][0]:b["train_slice"][1]]["Label"].sum() > 0 else "Pure Benign Reference"),
                ("Val", b["val_slice"], "Threshold Calibration (Straddles Boundary)" if "Regime" in name else "Threshold Calibration"),
                ("Test", b["test_slice"], "Held-Out Test (Regime-Shift)" if "Regime" in name else "Held-Out Test Evaluation")
            ]
            
            tr_end = df.iloc[b["train_slice"][1] - 1]["window_time"]
            va_start = df.iloc[b["val_slice"][0]]["window_time"]
            va_end = df.iloc[b["val_slice"][1] - 1]["window_time"]
            te_start = df.iloc[b["test_slice"][0]]["window_time"]
            assert tr_end < va_start, f"[{name}] Train end must precede Val start"
            assert va_end < te_start, f"[{name}] Val end must precede Test start"

            for part_name, (s_idx, e_idx), role in slices:
                sub = df.iloc[s_idx:e_idx]
                n_units = len(sub)
                y_arr = sub["Label"].values.astype(int)
                n_atk = int(y_arr.sum())
                prev = float(n_atk / n_units) if n_units > 0 else 0.0
                intervals = find_campaign_intervals(y_arr, gap_tolerance=0)
                n_camp = len(intervals)
                t_start = pd.to_datetime(sub["window_time"].iloc[0], unit="s")
                t_end = pd.to_datetime(sub["window_time"].iloc[-1], unit="s")
                elapsed_sec = float((sub["window_time"].iloc[-1] - sub["window_time"].iloc[0]) + 10.0)

                records.append({
                    "Dataset": "UNSW-NB15",
                    "Block": name,
                    "Partition": part_name,
                    "Index_Range": f"[{s_idx}, {e_idx}]",
                    "Start_Timestamp": str(t_start),
                    "End_Timestamp": str(t_end),
                    "Elapsed_Hours": round(elapsed_sec / 3600.0, 2),
                    "Total_Units": n_units,
                    "Unit_Type": "windows (10s)",
                    "Attack_Units": n_atk,
                    "Prevalence": round(prev * 100.0, 2),
                    "Campaigns": n_camp,
                    "Role": role
                })
        else:
            # Flow block
            df_raw = load_and_sort_raw_unsw(file_indices=[1], nrows=15000)
            df_flow = df_raw.iloc[:b["n_samples"]].copy().reset_index(drop=True)
            n_tr = int(b["train_frac"] * len(df_flow))
            n_va = int(b["val_frac"] * len(df_flow))
            n_te = len(df_flow) - n_tr - n_va
            tr_df = df_flow.iloc[0:n_tr]
            va_df = df_flow.iloc[n_tr:n_tr+n_va]
            te_df = df_flow.iloc[n_tr+n_va:len(df_flow)]
            time_col = "Stime" if "Stime" in df_flow.columns else "stime"

            flow_slices = [
                ("Train", 0, n_tr, tr_df, "Filtered Benign Reference (4,616 Normal)"),
                ("Val", n_tr, n_tr+n_va, va_df, "Threshold Calibration"),
                ("Test", n_tr+n_va, len(df_flow), te_df, "Held-Out Test Evaluation")
            ]

            tr_end = tr_df[time_col].iloc[-1]
            va_start = va_df[time_col].iloc[0]
            va_end = va_df[time_col].iloc[-1]
            te_start = te_df[time_col].iloc[0]
            assert tr_end <= va_start, f"[{name}] Flow train end must precede or equal val start"
            assert va_end <= te_start, f"[{name}] Flow val end must precede or equal test start"

            for part_name, s_idx, e_idx, sub, role in flow_slices:
                n_units = len(sub)
                y_arr = sub["Label"].values.astype(int)
                n_atk = int(y_arr.sum())
                prev = float(n_atk / n_units) if n_units > 0 else 0.0
                intervals = find_campaign_intervals(y_arr, gap_tolerance=0)
                n_camp = len(intervals)
                t_start = pd.to_datetime(sub[time_col].iloc[0], unit="s")
                t_end = pd.to_datetime(sub[time_col].iloc[-1], unit="s")
                elapsed_sec = float(sub[time_col].iloc[-1] - sub[time_col].iloc[0])

                records.append({
                    "Dataset": "UNSW-NB15",
                    "Block": name,
                    "Partition": part_name,
                    "Index_Range": f"[{s_idx}, {e_idx}]",
                    "Start_Timestamp": str(t_start),
                    "End_Timestamp": str(t_end),
                    "Elapsed_Hours": round(elapsed_sec / 3600.0, 4),
                    "Total_Units": n_units,
                    "Unit_Type": "flows",
                    "Attack_Units": n_atk,
                    "Prevalence": round(prev * 100.0, 2),
                    "Campaigns": n_camp,
                    "Role": role
                })

    res_df = pd.DataFrame(records)
    csv_path = "results/v3_1/metrics/slice_composition.csv"
    json_path = "results/v3_1/metrics/slice_composition.json"
    res_df.to_csv(csv_path, index=False)
    res_df.to_json(json_path, orient="records", indent=2)
    print(f"Saved slice composition to {csv_path} and {json_path}")
    print("\n" + res_df.to_string())

if __name__ == "__main__":
    main()

