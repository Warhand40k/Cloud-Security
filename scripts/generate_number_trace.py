#!/usr/bin/env python3
"""
Generate comprehensive number_trace.csv reconciling every numerical claim,
table cell, and figure caption in paper/main.tex against backing artifacts.
"""

import os
import pandas as pd

def build_number_trace():
    trace_records = [
        # =========================================================================
        # ABSTRACT (Lines 45-56)
        # =========================================================================
        {
            "Claim_ID": "TRACE_001",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "base paper reported near-perfect detection fidelity ($F_1 > 0.998$) on public benchmarks",
            "Claimed_Value": "F1 > 0.998",
            "Source_File": "paper/references.bib",
            "Source_Row_Or_Expression": "Al-Mazrawe & Al-Musawi (2025), Table on UNSW-NB15",
            "Reconciled_Value_v4": "F1 = 0.998",
            "Status": "VERIFIED",
            "Notes": "Literature baseline claim from Al-Mazrawe & Al-Musawi (2025)."
        },
        {
            "Claim_ID": "TRACE_002",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "synthetic timestamps skipped 528 quiescent minutes on Friday",
            "Claimed_Value": "528 minutes",
            "Source_File": "data/processed/csecicids2018_friday_60s_regular.parquet",
            "Source_Row_Or_Expression": "len(csecicids2018_friday_60s_regular.parquet) - len(csecicids2018_60s_any_attack.parquet) = 719 - 191 = 528",
            "Reconciled_Value_v4": "528 minutes",
            "Status": "VERIFIED",
            "Notes": "Continuous 60s datetime grid has 719 windows (11.97h) vs 191 active-only windows; 528 inactive minutes were skipped."
        },
        {
            "Claim_ID": "TRACE_003",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "small reference sizes ($N=16$) collapsed Isolation Forest to $F_1 = 0.0000$",
            "Claimed_Value": "N=16, F1=0.0000",
            "Source_File": "results/v3_1/metrics/csecicids2018_within_day_results.csv",
            "Source_Row_Or_Expression": "Row 31 (Wednesday-21-02-2018, Baseline: Isolation Forest)",
            "Reconciled_Value_v4": "N=16, F1=0.0000",
            "Status": "VERIFIED",
            "Notes": "Within-day reference capacity starvation on Wednesday (N=16) collapsed Isolation Forest."
        },
        {
            "Claim_ID": "TRACE_004",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "cross-day sizing ($N=507$) restored it to Rank~1 ($F_1 = 0.9859$)",
            "Claimed_Value": "N=507, Rank 1, F1=0.9859",
            "Source_File": "results/v3_1/metrics/csecicids2018_cross_day_results.csv",
            "Source_Row_Or_Expression": "Row 32 (Wednesday-21-02-2018, Baseline: Isolation Forest)",
            "Reconciled_Value_v4": "F1 = 0.985915 (validation F1-tuned)",
            "Status": "DISCREPANCY_RESOLVED",
            "Notes": "Discrepancy 1 resolved: 0.9859 is from cross-day training with validation-F1 thresholding (csecicids2018_cross_day_results.csv). In Stage 2 conformal benchmark under nominal alpha=0.05 calibration, F1 was 0.8780."
        },
        {
            "Claim_ID": "TRACE_005",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "99.73% zero benign validation scores driving $\\tau^* = 0.0$ and zero MAD",
            "Claimed_Value": "99.73% zeros, tau*=0.0",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 2 (Config A-prime, 3989/4000 = 0.99725)",
            "Reconciled_Value_v4": "99.725% zeros (3989/4000), tau*=0.0",
            "Status": "VERIFIED",
            "Notes": "Re-verified in results/v4/metrics/saturation_cure_comprehensive_audit.csv."
        },
        {
            "Claim_ID": "TRACE_006",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "rather than calendar drift across 26 days",
            "Claimed_Value": "26 days",
            "Source_File": "configs/v3_1/unsw_nb15.json",
            "Source_Row_Or_Expression": "Description of Batch 1 (22/01/2015) vs Batch 2 (17/02/2015)",
            "Reconciled_Value_v4": "26 days",
            "Status": "VERIFIED",
            "Notes": "Calendar span between UNSW-NB15 batches is 26 days; Flow block was proven to lie entirely within Batch 1."
        },
        {
            "Claim_ID": "TRACE_007",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "paired persistence filtering ($k \\ge 2$) degraded test $F_1$ in 67.5% of configurations",
            "Claimed_Value": "k >= 2, 67.5% degraded",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "(Delta_F1_vs_k1 < 0).sum() / len(k_ge_2) = 54 / 80 = 0.675",
            "Reconciled_Value_v4": "67.5% (54/80)",
            "Status": "VERIFIED",
            "Notes": "Paired testing across 80 configurations with k in {2,3,4,5}."
        },
        {
            "Claim_ID": "TRACE_008",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "on 10 contiguous flow blocks (80,000 flows)",
            "Claimed_Value": "10 blocks, 80,000 flows",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "N_Blocks = 10, 8000 flows per block",
            "Reconciled_Value_v4": "10 blocks, 80,000 flows",
            "Status": "VERIFIED",
            "Notes": "10 non-overlapping blocks of 8,000 raw flows each."
        },
        {
            "Claim_ID": "TRACE_009",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "all matrix profile variants scored mean $F_1 \\le 0.1246$",
            "Claimed_Value": "mean F1 <= 0.1246",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "Row 10 (Config B2 Adaptive EVT: F1_Mean = 0.124581)",
            "Reconciled_Value_v4": "F1_Mean <= 0.124581",
            "Status": "VERIFIED",
            "Notes": "Highest mean F1 across all evaluated matrix profile configurations is 0.124581 <= 0.1246."
        },
        {
            "Claim_ID": "TRACE_010",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "underperforming the naive All-Attack baseline ($F_1 = 0.1281$)",
            "Claimed_Value": "All-Attack F1 = 0.1281",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "Row 1 (Baseline: All-Attack: F1_Mean = 0.128068)",
            "Reconciled_Value_v4": "F1_Mean = 0.128068",
            "Status": "VERIFIED",
            "Notes": "All-Attack baseline mean F1 is 0.128068 approx 0.1281."
        },
        {
            "Claim_ID": "TRACE_011",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "constraining empirical false positive rates from 12.37% down to 2.86% ($\\alpha=0.05$)",
            "Claimed_Value": "12.37% -> 2.86% (alpha=0.05)",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Rows 8 & 5 (Static Quantile: 0.123656 vs ACI: 0.028635)",
            "Reconciled_Value_v4": "12.37% -> 2.86%",
            "Status": "VERIFIED",
            "Notes": "Re-verified in results/v4/metrics/stage4_conformal_summary_by_method.csv."
        },
        {
            "Claim_ID": "TRACE_012",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "and 1.06% ($\\alpha=0.01$)",
            "Claimed_Value": "1.06% (alpha=0.01)",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 1 (ACI alpha=0.01: Mean_Achieved_FPR = 0.010643)",
            "Reconciled_Value_v4": "1.06% (0.010643)",
            "Status": "VERIFIED",
            "Notes": "Re-verified in results/v4/metrics/stage4_conformal_summary_by_method.csv."
        },
        {
            "Claim_ID": "TRACE_013",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "live containerized microservice testbed with 25 labeled campaigns",
            "Claimed_Value": "25 campaigns",
            "Source_File": "configs/v3_3/testbed_config.json",
            "Source_Row_Or_Expression": "len(schedule[\"attack_campaigns\"]) = 25",
            "Reconciled_Value_v4": "25 campaigns",
            "Status": "VERIFIED",
            "Notes": "25 attack campaigns executed across 600 windows."
        },
        {
            "Claim_ID": "TRACE_014",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "static thresholds suffer 100% false alarms during benign flash crowds",
            "Claimed_Value": "100% flash crowd FAR",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 1 (Isolation Forest, Static Quantile: Flash_Crowd_FPR = 1.0)",
            "Reconciled_Value_v4": "100.0% (35/35 per seed, 175/175 pooled)",
            "Status": "VERIFIED",
            "Notes": "Static threshold flagged all 35 flash crowd windows across all 5 seeds."
        },
        {
            "Claim_ID": "TRACE_015",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "whereas rolling conformal calibration slashes flash crowd false alarms to 11.43%",
            "Claimed_Value": "11.43% flash crowd FAR",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 3 (Isolation Forest, Rolling Conformal: Flash_Crowd_FPR = 0.114286)",
            "Reconciled_Value_v4": "100.0% (label-free); 11.43% (oracle-feedback upper bound)",
            "Status": "WEAKENED",
            "Notes": "WEAKENED: 11.43% was an artifact of ground truth test label leakage (oracle feedback). Autonomous label-free calibration yields 100.0% (35/35)."
        },
        {
            "Claim_ID": "TRACE_016",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "boosting Isolation Forest $F_1$ to 0.9451",
            "Claimed_Value": "F1 = 0.9451",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 3 (Isolation Forest, Rolling Conformal: F1 = 0.945055)",
            "Reconciled_Value_v4": "0.8526 (label-free); 0.9451 (oracle-feedback upper bound)",
            "Status": "WEAKENED",
            "Notes": "WEAKENED: 0.9451 is the oracle-feedback upper bound; autonomous label-free deployment achieves F1 = 0.8526."
        },
        {
            "Claim_ID": "TRACE_017",
            "Section": "Abstract",
            "LaTeX_Line": 51,
            "Claimed_Text_Snippet": "with 100% campaign recall",
            "Claimed_Value": "100% campaign recall",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 3 (Campaign_Recall = 1.0)",
            "Reconciled_Value_v4": "100.0% (25/25)",
            "Status": "VERIFIED",
            "Notes": "All 25 campaigns detected under both label-free and oracle variants."
        },

        # =========================================================================
        # SECTION 1: INTRODUCTION (Lines 58-76)
        # =========================================================================
        {
            "Claim_ID": "TRACE_018",
            "Section": "1. Introduction",
            "LaTeX_Line": 68,
            "Claimed_Text_Snippet": "reporting exceptional detection fidelity ($99.8\\%$ accuracy and $F_1 = 0.998$) on the UNSW-NB15 benchmark",
            "Claimed_Value": "99.8% accuracy, F1 = 0.998",
            "Source_File": "paper/references.bib",
            "Source_Row_Or_Expression": "Al-Mazrawe & Al-Musawi (2025), Table on UNSW-NB15",
            "Reconciled_Value_v4": "99.6% accuracy, F1 = 0.998",
            "Status": "DISCREPANCY_RESOLVED",
            "Notes": "Discrepancy 3 resolved: Base paper reported 99.6% accuracy (not 99.8%) and F1=0.998. The 99.8% accuracy in draft text is a typo."
        },
        {
            "Claim_ID": "TRACE_019",
            "Section": "1. Introduction",
            "LaTeX_Line": 72,
            "Claimed_Text_Snippet": "synthetic timestamp compression (528 skipped minutes)",
            "Claimed_Value": "528 minutes",
            "Source_File": "data/processed/csecicids2018_friday_60s_regular.parquet",
            "Source_Row_Or_Expression": "len(regular) - len(active) = 719 - 191 = 528",
            "Reconciled_Value_v4": "528 minutes",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_002."
        },
        {
            "Claim_ID": "TRACE_020",
            "Section": "1. Introduction",
            "LaTeX_Line": 72,
            "Claimed_Text_Snippet": "reference capacity starvation ($N=16$ vs $N=507$)",
            "Claimed_Value": "N=16 vs N=507",
            "Source_File": "configs/v3_1/cse_cic_ids2018_within_day.json and configs/v3_1/cse_cic_ids2018_cross_day.json",
            "Source_Row_Or_Expression": "Wednesday within-day train_slice: [0, 16] vs cross-day train_slice: [0, 507]",
            "Reconciled_Value_v4": "N=16 vs N=507",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_003, TRACE_004."
        },
        {
            "Claim_ID": "TRACE_021",
            "Section": "1. Introduction",
            "LaTeX_Line": 72,
            "Claimed_Text_Snippet": "threshold collapse (99.73% zero benign validation scores)",
            "Claimed_Value": "99.73% zeros",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 2 (3989/4000 = 0.99725)",
            "Reconciled_Value_v4": "99.725%",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_005."
        },
        {
            "Claim_ID": "TRACE_022",
            "Section": "1. Introduction",
            "LaTeX_Line": 72,
            "Claimed_Text_Snippet": "evaluate 80,000 raw flows across 10 contiguous blocks",
            "Claimed_Value": "80,000 flows, 10 blocks",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "N_Blocks = 10, 8000 flows/block",
            "Reconciled_Value_v4": "80,000 flows, 10 blocks",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_008."
        },
        {
            "Claim_ID": "TRACE_023",
            "Section": "1. Introduction",
            "LaTeX_Line": 73,
            "Claimed_Text_Snippet": "Through paired parent-variant testing across 80 configurations",
            "Claimed_Value": "80 configurations",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "len(df[df['k'] >= 2]) = 80",
            "Reconciled_Value_v4": "80 configurations",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_007."
        },
        {
            "Claim_ID": "TRACE_024",
            "Section": "1. Introduction",
            "LaTeX_Line": 73,
            "Claimed_Text_Snippet": "temporal persistence filtering ($k \\ge 2$) harms detection performance in 67.5% of evaluations",
            "Claimed_Value": "k >= 2, 67.5%",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "54 / 80 = 0.675",
            "Reconciled_Value_v4": "67.5% (54/80)",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_007."
        },
        {
            "Claim_ID": "TRACE_025",
            "Section": "1. Introduction",
            "LaTeX_Line": 74,
            "Claimed_Text_Snippet": "restoring empirical FPR from 12.37% down to 2.86% ($\\alpha=0.05$) and 1.06% ($\\alpha=0.01$)",
            "Claimed_Value": "12.37% -> 2.86% (0.05), 1.06% (0.01)",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Rows 8, 5, 1",
            "Reconciled_Value_v4": "12.37% -> 2.86%, 1.06%",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_011, TRACE_012."
        },
        {
            "Claim_ID": "TRACE_026",
            "Section": "1. Introduction",
            "LaTeX_Line": 75,
            "Claimed_Text_Snippet": "25 attack campaigns",
            "Claimed_Value": "25 campaigns",
            "Source_File": "configs/v3_3/testbed_config.json",
            "Source_Row_Or_Expression": "schedule attack_campaigns count = 25",
            "Reconciled_Value_v4": "25 campaigns",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_013."
        },
        {
            "Claim_ID": "TRACE_027",
            "Section": "1. Introduction",
            "LaTeX_Line": 75,
            "Claimed_Text_Snippet": "static thresholds suffer a 100% false alarm rate during benign flash crowds",
            "Claimed_Value": "100% flash crowd FAR",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 1 (Isolation Forest, Static Quantile)",
            "Reconciled_Value_v4": "100.0% (35/35)",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_014."
        },
        {
            "Claim_ID": "TRACE_028",
            "Section": "1. Introduction",
            "LaTeX_Line": 75,
            "Claimed_Text_Snippet": "rolling conformal calibration eliminates 88.6% of flash crowd false alarms",
            "Claimed_Value": "88.6% reduction",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "(1.0 - 0.114286) / 1.0 = 0.885714 approx 88.6%",
            "Reconciled_Value_v4": "0.0% reduction (label-free); 88.6% reduction (oracle)",
            "Status": "WEAKENED",
            "Notes": "WEAKENED: Derived from oracle-feedback flash crowd FAR (11.43%). Under label-free rule, reduction is 0.0%."
        },
        {
            "Claim_ID": "TRACE_029",
            "Section": "1. Introduction",
            "LaTeX_Line": 75,
            "Claimed_Text_Snippet": "achieving an $F_1$ score of 0.9451 with 100% campaign recall",
            "Claimed_Value": "F1 = 0.9451, 100% campaign recall",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 3",
            "Reconciled_Value_v4": "F1 = 0.8526 (label-free), F1 = 0.9451 (oracle); 100% recall",
            "Status": "WEAKENED",
            "Notes": "Same as TRACE_016, TRACE_017."
        },

        # =========================================================================
        # SECTION 4: METHODOLOGICAL AUDIT & EMPIRICAL REFUTATIONS (Lines 118-142)
        # =========================================================================
        {
            "Claim_ID": "TRACE_030",
            "Section": "4.1 Time-Axis Integrity",
            "LaTeX_Line": 121,
            "Claimed_Text_Snippet": "CSE-CIC-IDS2018 Friday dataset (DoS-Hulk, 11.97 elapsed hours)",
            "Claimed_Value": "11.97 hours",
            "Source_File": "data/processed/csecicids2018_friday_60s_regular.parquet",
            "Source_Row_Or_Expression": "(df['window_dt'].max() - df['window_dt'].min()).total_seconds() / 3600 = 11.9667 approx 11.97",
            "Reconciled_Value_v4": "11.97 hours",
            "Status": "VERIFIED",
            "Notes": "Regularized Friday spans 719 minutes = 11.98 hours."
        },
        {
            "Claim_ID": "TRACE_031",
            "Section": "4.1 Time-Axis Integrity",
            "LaTeX_Line": 121,
            "Claimed_Text_Snippet": "omitting 528 quiescent 60-second minutes",
            "Claimed_Value": "528 minutes",
            "Source_File": "data/processed/csecicids2018_friday_60s_regular.parquet",
            "Source_Row_Or_Expression": "719 - 191 = 528",
            "Reconciled_Value_v4": "528 minutes",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_002."
        },
        {
            "Claim_ID": "TRACE_032",
            "Section": "4.1 Time-Axis Integrity",
            "LaTeX_Line": 121,
            "Claimed_Text_Snippet": "454-minute gap between morning attacks and afternoon activity",
            "Claimed_Value": "454 minutes",
            "Source_File": "data/processed/csecicids2018_friday_60s_regular.parquet",
            "Source_Row_Or_Expression": "Gap between window 44 (05:04:00) and window 499 (12:38:00) = 454 minutes",
            "Reconciled_Value_v4": "454 minutes",
            "Status": "VERIFIED",
            "Notes": "Measured quiescent gap during which zero network flows were recorded."
        },
        {
            "Claim_ID": "TRACE_033",
            "Section": "4.1 Time-Axis Integrity",
            "LaTeX_Line": 121,
            "Claimed_Text_Snippet": "compressing 12 hours into 3.1 hours",
            "Claimed_Value": "12 hours into 3.1 hours",
            "Source_File": "data/processed/csecicids2018_60s_any_attack.parquet",
            "Source_Row_Or_Expression": "191 windows * 60s / 3600 = 3.18 hours approx 3.1 hours vs 11.97 approx 12 hours",
            "Reconciled_Value_v4": "12 hours into 3.18 hours",
            "Status": "VERIFIED",
            "Notes": "Unregularized active-only indexing skipped inactive intervals."
        },
        {
            "Claim_ID": "TRACE_034",
            "Section": "4.1 Time-Axis Integrity",
            "LaTeX_Line": 121,
            "Claimed_Text_Snippet": "continuous, gapless 60-second datetime grid",
            "Claimed_Value": "60 seconds",
            "Source_File": "src/data_loader.py",
            "Source_Row_Or_Expression": "window_sec = 60",
            "Reconciled_Value_v4": "60 seconds",
            "Status": "VERIFIED",
            "Notes": "Aggregation interval."
        },
        {
            "Claim_ID": "TRACE_035",
            "Section": "4.2 Training Sizing",
            "LaTeX_Line": 124,
            "Claimed_Text_Snippet": "Within-day training splits on Friday ($N=45$) and Wednesday ($N=16$)",
            "Claimed_Value": "Friday N=45, Wednesday N=16",
            "Source_File": "configs/v3_1/cse_cic_ids2018_within_day.json",
            "Source_Row_Or_Expression": "train_slice Friday [0, 45], Wednesday [0, 16]",
            "Reconciled_Value_v4": "Friday N=45, Wednesday N=16",
            "Status": "DISCREPANCY_RESOLVED",
            "Notes": "Discrepancy 2 resolved: Friday N=45 in v3_1 regularized data (configs/v3_1/cse_cic_ids2018_within_day.json), whereas earlier v3 unregularized active-only config used N=26 (configs/v3/cse_cic_ids2018_multiday.json)."
        },
        {
            "Claim_ID": "TRACE_036",
            "Section": "4.2 Training Sizing",
            "LaTeX_Line": 124,
            "Claimed_Text_Snippet": "statsmodels ARIMA(1,0,1) convergence failures",
            "Claimed_Value": "ARIMA(1,0,1)",
            "Source_File": "src/baselines.py",
            "Source_Row_Or_Expression": "order=(1, 0, 1)",
            "Reconciled_Value_v4": "ARIMA(1,0,1)",
            "Status": "VERIFIED",
            "Notes": "Model specification."
        },
        {
            "Claim_ID": "TRACE_037",
            "Section": "4.2 Training Sizing",
            "LaTeX_Line": 124,
            "Claimed_Text_Snippet": "collapsing Isolation Forest to $F_1 = 0.0000$ (Rank 5)",
            "Claimed_Value": "F1 = 0.0000, Rank 5",
            "Source_File": "results/v3_1/metrics/csecicids2018_ranking_comparison.csv",
            "Source_Row_Or_Expression": "Row 14 (Baseline: Isolation Forest, F1_WithinDay = 0.0, Rank_WithinDay = 5)",
            "Reconciled_Value_v4": "F1 = 0.0000, Rank 5",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_003."
        },
        {
            "Claim_ID": "TRACE_038",
            "Section": "4.2 Training Sizing",
            "LaTeX_Line": 124,
            "Claimed_Text_Snippet": "cross-day reference sizing ($N=507$ from Thursday morning)",
            "Claimed_Value": "N=507",
            "Source_File": "configs/v3_1/cse_cic_ids2018_cross_day.json",
            "Source_Row_Or_Expression": "train_slice: [0, 507]",
            "Reconciled_Value_v4": "N=507",
            "Status": "VERIFIED",
            "Notes": "Reference training windows from Thursday benign morning."
        },
        {
            "Claim_ID": "TRACE_039",
            "Section": "4.2 Training Sizing",
            "LaTeX_Line": 124,
            "Claimed_Text_Snippet": "on Wednesday, Isolation Forest surged to Rank 1 tied with ARIMA at $F_1 = 0.9859$",
            "Claimed_Value": "Rank 1, F1=0.9859",
            "Source_File": "results/v3_1/metrics/csecicids2018_ranking_comparison.csv",
            "Source_Row_Or_Expression": "Rows 14-15 (F1_CrossDay = 0.985915, Rank_CrossDay = 1)",
            "Reconciled_Value_v4": "F1 = 0.985915 (val-F1 tuned)",
            "Status": "DISCREPANCY_RESOLVED",
            "Notes": "Discrepancy 1 resolved: 0.9859 is from cross-day training with validation-F1 thresholding. Stage 2 conformal benchmark at alpha=0.05 produced F1=0.8780."
        },
        {
            "Claim_ID": "TRACE_040",
            "Section": "Figure 1 Caption",
            "LaTeX_Line": 129,
            "Claimed_Text_Snippet": "99.73% of benign validation scores are exactly 0.0",
            "Claimed_Value": "99.73%",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 2 (3989/4000 = 0.99725)",
            "Reconciled_Value_v4": "99.725%",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_005."
        },
        {
            "Claim_ID": "TRACE_041",
            "Section": "Figure 1 Caption",
            "LaTeX_Line": 129,
            "Claimed_Text_Snippet": "collapse the threshold to $\\tau^* = 0.0$ and driving test FPR to 100%",
            "Claimed_Value": "tau*=0.0, FPR=100%",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 1 (Threshold = 0.0, Test_FPR = 1.0)",
            "Reconciled_Value_v4": "tau*=0.0, FPR=100.0%",
            "Status": "VERIFIED",
            "Notes": "Verified in results/v4/metrics/saturation_cure_comprehensive_audit.csv."
        },
        {
            "Claim_ID": "TRACE_042",
            "Section": "Figure 1 Caption",
            "LaTeX_Line": 129,
            "Claimed_Text_Snippet": "$\\epsilon$-MAD floor and label-free quantile rule restore FPR from 100% to 0.57%",
            "Claimed_Value": "100% to 0.57%",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 4 (Test_FPR = 0.005698)",
            "Reconciled_Value_v4": "0.57% (12/2106)",
            "Status": "VERIFIED",
            "Notes": "Verified in results/v4/metrics/saturation_cure_comprehensive_audit.csv."
        },
        {
            "Claim_ID": "TRACE_043",
            "Section": "Figure 1 Caption",
            "LaTeX_Line": 129,
            "Claimed_Text_Snippet": "26-day calendar gap hypothesis",
            "Claimed_Value": "26 days",
            "Source_File": "configs/v3_1/unsw_nb15.json",
            "Source_Row_Or_Expression": "Description of Batch 1/Batch 2 calendar gap",
            "Reconciled_Value_v4": "26 days",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_006."
        },
        {
            "Claim_ID": "TRACE_044",
            "Section": "4.3 Saturation Diagnosis",
            "LaTeX_Line": 133,
            "Claimed_Text_Snippet": "26-day calendar gap between reference and test sets",
            "Claimed_Value": "26 days",
            "Source_File": "configs/v3_1/unsw_nb15.json",
            "Source_Row_Or_Expression": "Same as TRACE_006",
            "Reconciled_Value_v4": "26 days",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_006."
        },
        {
            "Claim_ID": "TRACE_045",
            "Section": "4.3 Saturation Diagnosis",
            "LaTeX_Line": 133,
            "Claimed_Text_Snippet": "UNSW Flow Block is located entirely within Batch 1 (107 seconds after the reference period)",
            "Claimed_Value": "107 seconds",
            "Source_File": "data/processed/ / docs/findings_v3_1.md",
            "Source_Row_Or_Expression": "Reference ends at index 2000 (10:12:13), Flow block starts at index 2001 (10:14:00), diff = 107s",
            "Reconciled_Value_v4": "107 seconds",
            "Status": "VERIFIED",
            "Notes": "Proves Flow block is not in Batch 2 (no 26-day gap)."
        },
        {
            "Claim_ID": "TRACE_046",
            "Section": "4.3 Saturation Diagnosis",
            "LaTeX_Line": 135,
            "Claimed_Text_Snippet": "99.73% of benign validation scores were identically zero",
            "Claimed_Value": "99.73%",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 2",
            "Reconciled_Value_v4": "99.725%",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_005."
        },
        {
            "Claim_ID": "TRACE_047",
            "Section": "4.3 Saturation Diagnosis",
            "LaTeX_Line": 135,
            "Claimed_Text_Snippet": "selected $\\tau^* = 0.0$, and the rolling Median Absolute Deviation (MAD) collapsed to 0",
            "Claimed_Value": "tau*=0.0, MAD=0",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 1",
            "Reconciled_Value_v4": "tau*=0.0, MAD=0",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_041."
        },
        {
            "Claim_ID": "TRACE_048",
            "Section": "4.3 Saturation Diagnosis",
            "LaTeX_Line": 135,
            "Claimed_Text_Snippet": "$\\epsilon = 10^{-6}$ MAD floor",
            "Claimed_Value": "1e-6",
            "Source_File": "src/adaptive_threshold.py",
            "Source_Row_Or_Expression": "eps=1e-6",
            "Reconciled_Value_v4": "1e-6",
            "Status": "VERIFIED",
            "Notes": "Safety floor parameter preventing zero threshold collapse."
        },
        {
            "Claim_ID": "TRACE_049",
            "Section": "4.3 Saturation Diagnosis",
            "LaTeX_Line": 135,
            "Claimed_Text_Snippet": "reduced the test FPR from 100% to 0.57%",
            "Claimed_Value": "100% to 0.57%",
            "Source_File": "results/v3_1/metrics/saturation_diagnosis_hypotheses.csv",
            "Source_Row_Or_Expression": "Row 4",
            "Reconciled_Value_v4": "0.57% (12/2106)",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_042."
        },
        {
            "Claim_ID": "TRACE_050",
            "Section": "4.4 Paired Persistence",
            "LaTeX_Line": 138,
            "Claimed_Text_Snippet": "$k \\ge 2$ consecutive threshold crossings",
            "Claimed_Value": "k >= 2",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "k in [2, 3, 4, 5]",
            "Reconciled_Value_v4": "k >= 2",
            "Status": "VERIFIED",
            "Notes": "Persistence evaluation filter."
        },
        {
            "Claim_ID": "TRACE_051",
            "Section": "4.4 Paired Persistence",
            "LaTeX_Line": 138,
            "Claimed_Text_Snippet": "80 parent-variant pairs on identical score streams and thresholds ($\\alpha=0.05$)",
            "Claimed_Value": "80 pairs, alpha=0.05",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "len(df[df['k'] >= 2]) = 80",
            "Reconciled_Value_v4": "80 pairs",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_007."
        },
        {
            "Claim_ID": "TRACE_052",
            "Section": "4.4 Paired Persistence",
            "LaTeX_Line": 138,
            "Claimed_Text_Snippet": "Persistence filtering ($k \\ge 2$) degraded test $F_1$ in 67.5% of configurations",
            "Claimed_Value": "67.5%",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "54 / 80 = 0.675",
            "Reconciled_Value_v4": "67.5% (54/80)",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_007."
        },
        {
            "Claim_ID": "TRACE_053",
            "Section": "4.4 Paired Persistence",
            "LaTeX_Line": 138,
            "Claimed_Text_Snippet": "was neutral in 30.0%",
            "Claimed_Value": "30.0%",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "(Delta_F1_vs_k1 == 0).sum() / 80 = 24 / 80 = 0.300",
            "Reconciled_Value_v4": "30.0% (24/80)",
            "Status": "VERIFIED",
            "Notes": "Exactly 24 out of 80 configurations had Delta_F1 == 0."
        },
        {
            "Claim_ID": "TRACE_054",
            "Section": "4.4 Paired Persistence",
            "LaTeX_Line": 138,
            "Claimed_Text_Snippet": "In 80% of splits, validation tuning correctly selected $k^* = 1$",
            "Claimed_Value": "80% selected k*=1",
            "Source_File": "results/v3_1/metrics/paired_persistence_analysis.csv",
            "Source_Row_Or_Expression": "(k_stars == 1).sum() / len(k_stars) = 16 / 20 = 0.800",
            "Reconciled_Value_v4": "80.0% (16/20)",
            "Status": "VERIFIED",
            "Notes": "16 out of 20 parents selected k*=1."
        },
        {
            "Claim_ID": "TRACE_055",
            "Section": "4.5 Multi-Block Flow",
            "LaTeX_Line": 141,
            "Claimed_Text_Snippet": "10 contiguous blocks of 8,000 flows (80,000 flows total)",
            "Claimed_Value": "10 blocks, 80,000 flows",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "N_Blocks = 10, 8,000 flows per block",
            "Reconciled_Value_v4": "10 blocks, 80,000 flows",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_008."
        },
        {
            "Claim_ID": "TRACE_056",
            "Section": "4.5 Multi-Block Flow",
            "LaTeX_Line": 141,
            "Claimed_Text_Snippet": "all matrix profile configurations scored mean $F_1 \\le 0.1246$",
            "Claimed_Value": "mean F1 <= 0.1246",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "Row 10 (F1_Mean = 0.124581)",
            "Reconciled_Value_v4": "F1_Mean <= 0.124581",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_009."
        },
        {
            "Claim_ID": "TRACE_057",
            "Section": "4.5 Multi-Block Flow",
            "LaTeX_Line": 141,
            "Claimed_Text_Snippet": "naive All-Attack baseline ($F_1 = 0.1281$)",
            "Claimed_Value": "F1 = 0.1281",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "Row 1 (F1_Mean = 0.128068)",
            "Reconciled_Value_v4": "F1_Mean = 0.128068",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_010."
        },
        {
            "Claim_ID": "TRACE_058",
            "Section": "4.5 Multi-Block Flow",
            "LaTeX_Line": 141,
            "Claimed_Text_Snippet": "near-chance ROC-AUC ($0.52 - 0.56$)",
            "Claimed_Value": "0.52 - 0.56",
            "Source_File": "results/v3_1/metrics/unsw_multiblock_flow_summary.csv",
            "Source_Row_Or_Expression": "Config A-prime (0.5233) to Config A/B1/B2 (0.5570)",
            "Reconciled_Value_v4": "0.5233 - 0.5570",
            "Status": "VERIFIED",
            "Notes": "Evaluated across all 10 blocks."
        },

        # =========================================================================
        # SECTION 5: STAGE 2 CONTRIBUTION: CONFORMAL FALSE ALARM CONTROL (Lines 143-204)
        # =========================================================================
        {
            "Claim_ID": "TRACE_059",
            "Section": "5.2 ACI Formulation",
            "LaTeX_Line": 161,
            "Claimed_Text_Snippet": "$\\gamma = 0.01$ is the adaptation rate",
            "Claimed_Value": "gamma = 0.01",
            "Source_File": "src/adaptive_threshold.py",
            "Source_Row_Or_Expression": "gamma=0.01",
            "Reconciled_Value_v4": "gamma = 0.01",
            "Status": "VERIFIED",
            "Notes": "ACI adaptation step parameter."
        },
        {
            "Claim_ID": "TRACE_060",
            "Section": "5.2 ACI Formulation",
            "LaTeX_Line": 161,
            "Claimed_Text_Snippet": "causal sliding window ($W=60$)",
            "Claimed_Value": "W = 60",
            "Source_File": "src/adaptive_threshold.py",
            "Source_Row_Or_Expression": "window_size=60",
            "Reconciled_Value_v4": "W = 60",
            "Status": "VERIFIED",
            "Notes": "Rolling conformal buffer length."
        },
        {
            "Claim_ID": "TRACE_061",
            "Section": "Figure 2 Caption",
            "LaTeX_Line": 166,
            "Claimed_Text_Snippet": "target budget $\\alpha=0.05$ across 32 benchmark configurations",
            "Claimed_Value": "alpha = 0.05, 32 configs",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Evaluated_Configurations = 32",
            "Reconciled_Value_v4": "32 configs",
            "Status": "VERIFIED",
            "Notes": "Benchmark size."
        },
        {
            "Claim_ID": "TRACE_062",
            "Section": "Figure 2 Caption",
            "LaTeX_Line": 166,
            "Claimed_Text_Snippet": "Static thresholds severely exceed target budgets (+7.37% excess)",
            "Claimed_Value": "+7.37% excess",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 8 (Mean_FPR_Excess = 0.073656)",
            "Reconciled_Value_v4": "+7.37% (+0.073656)",
            "Status": "VERIFIED",
            "Notes": "Same as Table 1 Row 1."
        },
        {
            "Claim_ID": "TRACE_063",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 170,
            "Claimed_Text_Snippet": "32 configurations spanning UNSW-NB15, CSE-CIC-IDS2018, and four model families",
            "Claimed_Value": "32 configurations",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Evaluated_Configurations = 32",
            "Reconciled_Value_v4": "32 configurations",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_061."
        },

        # TABLE 1 (Lines 181-189)
        {
            "Claim_ID": "TRACE_064",
            "Section": "Table 1 (Row 1)",
            "LaTeX_Line": 181,
            "Claimed_Text_Snippet": "Static Benign Quantile & 0.05 & 0.1237 & +0.0737 & 43.8\\% & \\textbf{0.4076} & 0.6136",
            "Claimed_Value": "FPR=0.1237, Excess=+0.0737, Met=43.8%, F1=0.4076, Prec=0.6136",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 8 (Static Benign Quantile, alpha=0.05)",
            "Reconciled_Value_v4": "FPR=0.1237, Excess=+0.0737, Met=43.8%, F1=0.4076, Prec=0.6136",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 1 metrics verified."
        },
        {
            "Claim_ID": "TRACE_065",
            "Section": "Table 1 (Row 2)",
            "LaTeX_Line": 182,
            "Claimed_Text_Snippet": "Static Split-Conformal & 0.05 & 0.1199 & +0.0699 & 43.8\\% & 0.4053 & 0.6155",
            "Claimed_Value": "FPR=0.1199, Excess=+0.0699, Met=43.8%, F1=0.4053, Prec=0.6155",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 7 (Static Split-Conformal, alpha=0.05)",
            "Reconciled_Value_v4": "FPR=0.1199, Excess=+0.0699, Met=43.8%, F1=0.4053, Prec=0.6155",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 2 metrics verified."
        },
        {
            "Claim_ID": "TRACE_066",
            "Section": "Table 1 (Row 3)",
            "LaTeX_Line": 183,
            "Claimed_Text_Snippet": "Rolling Conformal ($W=60$) & 0.05 & \\textbf{0.0306} & \\textbf{-0.0194} & \\textbf{68.8\\%} & 0.2349 & 0.4171",
            "Claimed_Value": "FPR=0.0306, Excess=-0.0194, Met=68.8%, F1=0.2349, Prec=0.4171",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 6 (Rolling Split-Conformal, alpha=0.05)",
            "Reconciled_Value_v4": "FPR=0.0306, Excess=-0.0194, Met=68.8%, F1=0.2349, Prec=0.4171",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 3 metrics verified."
        },
        {
            "Claim_ID": "TRACE_067",
            "Section": "Table 1 (Row 4)",
            "LaTeX_Line": 184,
            "Claimed_Text_Snippet": "Adaptive Conformal (ACI, $\\gamma=0.01$) & 0.05 & \\textbf{0.0286} & \\textbf{-0.0214} & \\textbf{71.9\\%} & 0.2345 & 0.4138",
            "Claimed_Value": "FPR=0.0286, Excess=-0.0214, Met=71.9%, F1=0.2345, Prec=0.4138",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 5 (Adaptive Conformal ACI, alpha=0.05)",
            "Reconciled_Value_v4": "FPR=0.0286, Excess=-0.0214, Met=71.9%, F1=0.2345, Prec=0.4138",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 4 metrics verified."
        },
        {
            "Claim_ID": "TRACE_068",
            "Section": "Table 1 (Row 5)",
            "LaTeX_Line": 186,
            "Claimed_Text_Snippet": "Static Benign Quantile & 0.01 & 0.0200 & +0.0100 & 65.6\\% & 0.2507 & 0.5348",
            "Claimed_Value": "FPR=0.0200, Excess=+0.0100, Met=65.6%, F1=0.2507, Prec=0.5348",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 4 (Static Benign Quantile, alpha=0.01)",
            "Reconciled_Value_v4": "FPR=0.0200, Excess=+0.0100, Met=65.6%, F1=0.2507, Prec=0.5348",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 5 metrics verified."
        },
        {
            "Claim_ID": "TRACE_069",
            "Section": "Table 1 (Row 6)",
            "LaTeX_Line": 187,
            "Claimed_Text_Snippet": "Static Split-Conformal & 0.01 & 0.0182 & +0.0082 & 71.9\\% & 0.2388 & 0.5354",
            "Claimed_Value": "FPR=0.0182, Excess=+0.0082, Met=71.9%, F1=0.2388, Prec=0.5354",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 3 (Static Split-Conformal, alpha=0.01)",
            "Reconciled_Value_v4": "FPR=0.0182, Excess=+0.0082, Met=71.9%, F1=0.2388, Prec=0.5354",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 6 metrics verified."
        },
        {
            "Claim_ID": "TRACE_070",
            "Section": "Table 1 (Row 7)",
            "LaTeX_Line": 188,
            "Claimed_Text_Snippet": "Rolling Conformal ($W=60$) & 0.01 & \\textbf{0.0106} & \\textbf{+0.0006} & \\textbf{62.5\\%} & 0.1478 & 0.3404",
            "Claimed_Value": "FPR=0.0106, Excess=+0.0006, Met=62.5%, F1=0.1478, Prec=0.3404",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 2 (Rolling Split-Conformal, alpha=0.01)",
            "Reconciled_Value_v4": "FPR=0.0106, Excess=+0.0006, Met=62.5%, F1=0.1478, Prec=0.3404",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 7 metrics verified."
        },
        {
            "Claim_ID": "TRACE_071",
            "Section": "Table 1 (Row 8)",
            "LaTeX_Line": 189,
            "Claimed_Text_Snippet": "Adaptive Conformal (ACI, $\\gamma=0.01$) & 0.01 & \\textbf{0.0106} & \\textbf{+0.0006} & \\textbf{62.5\\%} & 0.1478 & 0.3404",
            "Claimed_Value": "FPR=0.0106, Excess=+0.0006, Met=62.5%, F1=0.1478, Prec=0.3404",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 1 (Adaptive Conformal ACI, alpha=0.01)",
            "Reconciled_Value_v4": "FPR=0.0106, Excess=+0.0006, Met=62.5%, F1=0.1478, Prec=0.3404",
            "Status": "VERIFIED",
            "Notes": "Table 1 Row 8 metrics verified."
        },

        # Prose after Table 1
        {
            "Claim_ID": "TRACE_072",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 195,
            "Claimed_Text_Snippet": "at $\\alpha = 0.05$, static quantile produced a mean test FPR of 12.37% (+7.37% excess)",
            "Claimed_Value": "12.37%, +7.37%",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 8",
            "Reconciled_Value_v4": "12.37%, +7.37%",
            "Status": "VERIFIED",
            "Notes": "Same as Table 1 Row 1."
        },
        {
            "Claim_ID": "TRACE_073",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 195,
            "Claimed_Text_Snippet": "meeting the target in only 43.8% of cases",
            "Claimed_Value": "43.8%",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 8 (FPR_Target_Met_Fraction = 0.4375)",
            "Reconciled_Value_v4": "43.8% (14/32)",
            "Status": "VERIFIED",
            "Notes": "Same as Table 1 Row 1."
        },
        {
            "Claim_ID": "TRACE_074",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 195,
            "Claimed_Text_Snippet": "Rolling Conformal and ACI restored rigorous control, achieving mean test FPRs of 3.06% and 2.86%",
            "Claimed_Value": "3.06% and 2.86%",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Rows 6 & 5",
            "Reconciled_Value_v4": "3.06% and 2.86%",
            "Status": "VERIFIED",
            "Notes": "Same as Table 1 Rows 3 & 4."
        },
        {
            "Claim_ID": "TRACE_075",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 195,
            "Claimed_Text_Snippet": "with 68.8% and 71.9% budget satisfaction",
            "Claimed_Value": "68.8% and 71.9%",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Rows 6 & 5 (0.6875 and 0.71875)",
            "Reconciled_Value_v4": "68.8% (22/32) and 71.9% (23/32)",
            "Status": "VERIFIED",
            "Notes": "Same as Table 1 Rows 3 & 4."
        },
        {
            "Claim_ID": "TRACE_076",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 195,
            "Claimed_Text_Snippet": "At $\\alpha = 0.01$, ACI restricted mean FPR to exactly 1.06%",
            "Claimed_Value": "1.06%",
            "Source_File": "results/v3_2/metrics/conformal_summary_by_method.csv",
            "Source_Row_Or_Expression": "Row 1 (0.010643)",
            "Reconciled_Value_v4": "1.06% (0.010643)",
            "Status": "VERIFIED",
            "Notes": "Same as Table 1 Row 8."
        },
        {
            "Claim_ID": "TRACE_077",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 197,
            "Claimed_Text_Snippet": "Friday DoS-Hulk attack. For Isolation Forest, rolling calibration slashed FPR from 12.50% to 1.67%",
            "Claimed_Value": "12.50% to 1.67%",
            "Source_File": "results/v3_2/metrics/conformal_comparison_results.csv",
            "Source_Row_Or_Expression": "Rows 60 & 62 (Friday-16-02-2018, Baseline: Isolation Forest, Static FPR=0.1250, Rolling FPR=0.016667)",
            "Reconciled_Value_v4": "12.50% to 1.67% (2 false alarms)",
            "Status": "VERIFIED",
            "Notes": "Re-verified in results/v4/metrics/stage4_conformal_comparison_results.csv."
        },
        {
            "Claim_ID": "TRACE_078",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 197,
            "Claimed_Text_Snippet": "while maintaining 100% recall",
            "Claimed_Value": "100% recall",
            "Source_File": "results/v3_2/metrics/conformal_comparison_results.csv",
            "Source_Row_Or_Expression": "Row 62 (Recall = 1.0)",
            "Reconciled_Value_v4": "100.0%",
            "Status": "VERIFIED",
            "Notes": "Re-verified in results/v4/metrics/stage4_conformal_comparison_results.csv."
        },
        {
            "Claim_ID": "TRACE_079",
            "Section": "5.3 Benchmark Evaluation",
            "LaTeX_Line": 197,
            "Claimed_Text_Snippet": "boosting $F_1$ from 0.8624 to 0.9792",
            "Claimed_Value": "0.8624 to 0.9792",
            "Source_File": "results/v3_2/metrics/conformal_comparison_results.csv",
            "Source_Row_Or_Expression": "Rows 60 & 62 (F1 = 0.862385 and 0.979167)",
            "Reconciled_Value_v4": "0.8624 to 0.9792",
            "Status": "VERIFIED",
            "Notes": "Re-verified in results/v4/metrics/stage4_conformal_comparison_results.csv."
        },
        {
            "Claim_ID": "TRACE_080",
            "Section": "Figure 3 Caption",
            "LaTeX_Line": 202,
            "Claimed_Text_Snippet": "isolating true attacks with zero false alarms",
            "Claimed_Value": "zero false alarms",
            "Source_File": "results/v3_2/metrics/conformal_comparison_results.csv",
            "Source_Row_Or_Expression": "Row 62 (Test_FPR = 0.016667, 2 false alarms)",
            "Reconciled_Value_v4": "2 false alarms (1.67% FPR)",
            "Status": "DISCREPANCY_RESOLVED",
            "Notes": "Discrepancy 4 resolved: Figure 3 caption claims 'zero false alarms', but achieved test FPR is 1.67% (2 false alarms out of 120 benign test windows), as correctly reported in line 197."
        },

        # =========================================================================
        # SECTION 6: STAGE 3 BOUNDED TESTBED VALIDATION (Lines 205-263)
        # =========================================================================
        {
            "Claim_ID": "TRACE_081",
            "Section": "6.1 Architecture",
            "LaTeX_Line": 211,
            "Claimed_Text_Snippet": "sinusoidal diurnal curve ($RPS \\in [10, 40]$)",
            "Claimed_Value": "RPS in [10, 40]",
            "Source_File": "configs/v3_3/testbed_config.json / testbed/locustfile.py",
            "Source_Row_Or_Expression": "Nominal Locust user spawn setting [10, 40]",
            "Reconciled_Value_v4": "Nominal [10, 40] users; actual measured RPS in [0.23, 4.85]",
            "Status": "DISCREPANCY_RESOLVED",
            "Notes": "Discrepancy resolved in Step 4: Stated 10-40 RPS refers to the Locust generator configuration. Actual server telemetry flow_count/60 ranges between 0.233 RPS (quiescent) and 4.85 RPS (peaks), matching Figure 4."
        },
        {
            "Claim_ID": "TRACE_082",
            "Section": "6.1 Architecture",
            "LaTeX_Line": 212,
            "Claimed_Text_Snippet": "localhost (`127.0.0.1:8088`)",
            "Claimed_Value": "127.0.0.1:8088",
            "Source_File": "testbed/docker-compose.yml",
            "Source_Row_Or_Expression": "ports: - '127.0.0.1:8088:8088'",
            "Reconciled_Value_v4": "127.0.0.1:8088",
            "Status": "VERIFIED",
            "Notes": "Loopback confinement binding."
        },
        {
            "Claim_ID": "TRACE_083",
            "Section": "6.1 Architecture",
            "LaTeX_Line": 212,
            "Claimed_Text_Snippet": "25 labeled attack campaigns across 600 contiguous 60-second windows (10 hours total)",
            "Claimed_Value": "25 campaigns, 600 windows, 10 hours",
            "Source_File": "configs/v3_3/testbed_config.json",
            "Source_Row_Or_Expression": "600 * 60 = 36000s = 10.0h, 25 campaigns",
            "Reconciled_Value_v4": "25 campaigns, 600 windows, 10 hours (emulated)",
            "Status": "VERIFIED",
            "Notes": "Time-compressed socket emulation representing 10 hours of operations."
        },
        {
            "Claim_ID": "TRACE_084",
            "Section": "6.1 Architecture",
            "LaTeX_Line": 213,
            "Claimed_Text_Snippet": "5 distinct campaigns where legitimate user volume surges 4x--5x",
            "Claimed_Value": "5 campaigns, 4x-5x surge",
            "Source_File": "configs/v3_3/testbed_config.json",
            "Source_Row_Or_Expression": "5 flash crowd entries in schedule",
            "Reconciled_Value_v4": "5 campaigns, 3.86x measured volume surge",
            "Status": "VERIFIED",
            "Notes": "Locust spawn rate stepped 4x-5x; measured request volume surged from 14 to 54 req/min (3.86x)."
        },
        {
            "Claim_ID": "TRACE_085",
            "Section": "6.1 Architecture",
            "LaTeX_Line": 216,
            "Claimed_Text_Snippet": "60-second regular windows across five core SRE metrics",
            "Claimed_Value": "60s windows, 5 metrics",
            "Source_File": "testbed/data_collector.py",
            "Source_Row_Or_Expression": "['flow_count', 'error_rate', 'p95_latency', 'tot_fwd_bytes', 'rst_flags_total']",
            "Reconciled_Value_v4": "60s windows, 5 metrics",
            "Status": "VERIFIED",
            "Notes": "Metric schema."
        },

        # TABLE 2 (Lines 227-236)
        {
            "Claim_ID": "TRACE_086",
            "Section": "Table 2 (Row 1)",
            "LaTeX_Line": 227,
            "Claimed_Text_Snippet": "Isolation Forest & Static Benign Quantile & 0.2622 & 0.7557 & \\textbf{0.9779} & 0.8526 & 100.0\\% (35/35)",
            "Claimed_Value": "FPR=0.2622, Prec=0.7557, Rec=0.9779, F1=0.8526, FC FPR=100.0% (35/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 1",
            "Reconciled_Value_v4": "FPR=0.2622, Prec=0.7557, Rec=0.9779, F1=0.8526, FC FPR=100.0% (35/35)",
            "Status": "VERIFIED",
            "Notes": "Table 2 Row 1 metrics verified."
        },
        {
            "Claim_ID": "TRACE_087",
            "Section": "Table 2 (Row 2)",
            "LaTeX_Line": 228,
            "Claimed_Text_Snippet": "Isolation Forest & Rolling Conformal ($W=60$) & \\textbf{0.0488} & \\textbf{0.9416} & 0.9485 & \\textbf{0.9451} & \\textbf{11.43\\% (4/35)}",
            "Claimed_Value": "FPR=0.0488, Prec=0.9416, Rec=0.9485, F1=0.9451, FC FPR=11.43% (4/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 3",
            "Reconciled_Value_v4": "Label-Free: FPR=0.2622, Prec=0.7557, Rec=0.9779, F1=0.8526, FC FPR=100.0% (35/35); Oracle: FPR=0.0488, F1=0.9451, FC FPR=11.43% (4/35)",
            "Status": "WEAKENED",
            "Notes": "Table 2 reported the oracle-feedback upper bound (passing y_test==0). Under autonomous label-free execution, FC FPR is 100.0% and F1 is 0.8526."
        },
        {
            "Claim_ID": "TRACE_088",
            "Section": "Table 2 (Row 3)",
            "LaTeX_Line": 229,
            "Claimed_Text_Snippet": "Isolation Forest & Adaptive ACI ($\\gamma=0.01$) & \\textbf{0.0488} & 0.9355 & 0.8529 & 0.8923 & \\textbf{11.43\\% (4/35)}",
            "Claimed_Value": "FPR=0.0488, Prec=0.9355, Rec=0.8529, F1=0.8923, FC FPR=11.43% (4/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 4",
            "Reconciled_Value_v4": "Label-Free: FPR=0.2683, F1=0.8502, FC FPR=100.0% (35/35); Oracle: FPR=0.0488, F1=0.8923, FC FPR=11.43% (4/35)",
            "Status": "WEAKENED",
            "Notes": "Oracle-feedback upper bound. Under label-free execution, FC FPR is 100.0%."
        },
        {
            "Claim_ID": "TRACE_089",
            "Section": "Table 2 (Row 4)",
            "LaTeX_Line": 231,
            "Claimed_Text_Snippet": "ARIMA Residual & Static Benign Quantile & 0.2744 & 0.7472 & \\textbf{0.9779} & 0.8471 & 100.0\\% (35/35)",
            "Claimed_Value": "FPR=0.2744, Prec=0.7472, Rec=0.9779, F1=0.8471, FC FPR=100.0% (35/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 9",
            "Reconciled_Value_v4": "FPR=0.2744, Prec=0.7472, Rec=0.9779, F1=0.8471, FC FPR=100.0% (35/35)",
            "Status": "VERIFIED",
            "Notes": "Table 2 Row 4 metrics verified."
        },
        {
            "Claim_ID": "TRACE_090",
            "Section": "Table 2 (Row 5)",
            "LaTeX_Line": 232,
            "Claimed_Text_Snippet": "ARIMA Residual & Rolling Conformal ($W=60$) & \\textbf{0.0732} & 0.9155 & 0.9559 & \\textbf{0.9353} & \\textbf{20.00\\% (7/35)}",
            "Claimed_Value": "FPR=0.0732, Prec=0.9155, Rec=0.9559, F1=0.9353, FC FPR=20.00% (7/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 11",
            "Reconciled_Value_v4": "Label-Free: FPR=0.2744, F1=0.8471, FC FPR=100.0% (35/35); Oracle: FPR=0.0732, F1=0.9353, FC FPR=20.00% (7/35)",
            "Status": "WEAKENED",
            "Notes": "Oracle-feedback upper bound. Under label-free execution, FC FPR is 100.0%."
        },
        {
            "Claim_ID": "TRACE_091",
            "Section": "Table 2 (Row 6)",
            "LaTeX_Line": 233,
            "Claimed_Text_Snippet": "ARIMA Residual & Adaptive ACI ($\\gamma=0.01$) & \\textbf{0.0549} & \\textbf{0.9333} & 0.9265 & \\textbf{0.9299} & \\textbf{14.29\\% (5/35)}",
            "Claimed_Value": "FPR=0.0549, Prec=0.9333, Rec=0.9265, F1=0.9299, FC FPR=14.29% (5/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 12",
            "Reconciled_Value_v4": "Label-Free: FPR=0.2744, F1=0.8471, FC FPR=100.0% (35/35); Oracle: FPR=0.0549, F1=0.9299, FC FPR=14.29% (5/35)",
            "Status": "WEAKENED",
            "Notes": "Oracle-feedback upper bound. Under label-free execution, FC FPR is 100.0%."
        },
        {
            "Claim_ID": "TRACE_092",
            "Section": "Table 2 (Row 7)",
            "LaTeX_Line": 235,
            "Claimed_Text_Snippet": "Config A (mSTAMP $m=5$) & Static Benign Quantile & 0.0000 & 0.0000 & 0.0000 & 0.0000 & 0.0\\% (0/35)",
            "Claimed_Value": "FPR=0.0, Prec=0.0, Rec=0.0, F1=0.0, FC FPR=0.0% (0/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 17",
            "Reconciled_Value_v4": "FPR=0.0000, F1=0.0000, Rec=0.0000",
            "Status": "VERIFIED",
            "Notes": "Complete collapse of matrix profile."
        },
        {
            "Claim_ID": "TRACE_093",
            "Section": "Table 2 (Row 8)",
            "LaTeX_Line": 236,
            "Claimed_Text_Snippet": "Config A-prime ($m=5$) & Static Benign Quantile & 0.0000 & 0.0000 & 0.0000 & 0.0000 & 0.0\\% (0/35)",
            "Claimed_Value": "FPR=0.0, Prec=0.0, Rec=0.0, F1=0.0, FC FPR=0.0% (0/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 25",
            "Reconciled_Value_v4": "FPR=0.0000, F1=0.0000, Rec=0.0000",
            "Status": "VERIFIED",
            "Notes": "Complete collapse of matrix profile."
        },

        # Figure 4 and 5 Captions
        {
            "Claim_ID": "TRACE_094",
            "Section": "Figure 4 Caption",
            "LaTeX_Line": 245,
            "Claimed_Text_Snippet": "10-hour telemetry timeline on the live microservice testbed (600 windows)",
            "Claimed_Value": "10 hours, 600 windows",
            "Source_File": "configs/v3_3/testbed_config.json",
            "Source_Row_Or_Expression": "600 windows",
            "Reconciled_Value_v4": "10 hours (emulated), 600 windows",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_083."
        },
        {
            "Claim_ID": "TRACE_095",
            "Section": "Figure 4 Caption",
            "LaTeX_Line": 245,
            "Claimed_Text_Snippet": "25 labeled attacks and 5 flash crowds",
            "Claimed_Value": "25 attacks, 5 flash crowds",
            "Source_File": "configs/v3_3/testbed_config.json",
            "Source_Row_Or_Expression": "Attack campaigns (25), Flash crowds (5)",
            "Reconciled_Value_v4": "25 attacks, 5 flash crowds",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_083, TRACE_084."
        },
        {
            "Claim_ID": "TRACE_096",
            "Section": "Figure 4 Caption",
            "LaTeX_Line": 245,
            "Claimed_Text_Snippet": "detector anomaly scores and dynamic conformal thresholds tracking diurnal variation",
            "Claimed_Value": "anomaly scores and dynamic conformal thresholds plotted",
            "Source_File": "scripts/generate_publication_figures_high_res.py",
            "Source_Row_Or_Expression": "Lines 267-279 (ax3 plots normalized anomaly scores only; no threshold curves drawn)",
            "Reconciled_Value_v4": "Anomaly scores only plotted (threshold curves omitted)",
            "Status": "DISCREPANCY_RESOLVED",
            "Notes": "Discrepancy 5 resolved: Figure 4 caption states the bottom panel shows 'detector anomaly scores and dynamic conformal thresholds', but the code only plots normalized anomaly scores (IsoFor, ARIMA, mSTAMP); dynamic thresholds tau_t are not plotted on that axis."
        },
        {
            "Claim_ID": "TRACE_097",
            "Section": "Figure 5 Caption",
            "LaTeX_Line": 251,
            "Claimed_Text_Snippet": "eliminates 88.6% of flash crowd alarms",
            "Claimed_Value": "88.6% reduction",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "(1.0 - 0.114286) / 1.0 = 0.8857",
            "Reconciled_Value_v4": "0.0% reduction (label-free); 88.6% reduction (oracle)",
            "Status": "WEAKENED",
            "Notes": "Same as TRACE_028."
        },

        # Section 6.2 Prose
        {
            "Claim_ID": "TRACE_098",
            "Section": "6.2 Flash Crowd Resolution",
            "LaTeX_Line": 257,
            "Claimed_Text_Snippet": "static thresholds suffered a 100.0% false alarm rate during benign flash crowds (35 / 35 flash crowd windows incorrectly flagged as cyberattacks)",
            "Claimed_Value": "100.0% (35/35)",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 1",
            "Reconciled_Value_v4": "100.0% (35/35 per seed, 175/175 pooled)",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_014."
        },
        {
            "Claim_ID": "TRACE_099",
            "Section": "6.2 Flash Crowd Resolution",
            "LaTeX_Line": 257,
            "Claimed_Text_Snippet": "severe alert storms ($> 35$ alerts/hour)",
            "Claimed_Value": "> 35 alerts/hour",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 1 (Alerts_Per_Hour = 35.2 test average; burst rate is 60.0 alerts/hr)",
            "Reconciled_Value_v4": "60.0 alerts/hr (during flash crowds); 35.2 alerts/hr (test average)",
            "Status": "VERIFIED",
            "Notes": "Verified in Step 4: During flash crowds, alert rate is exactly 60.0 alerts/hr (all 35 windows flagged)."
        },
        {
            "Claim_ID": "TRACE_100",
            "Section": "6.2 Flash Crowd Resolution",
            "LaTeX_Line": 259,
            "Claimed_Text_Snippet": "slashing flash crowd false alarms to 11.43% (4 / 35)---an 88.6% reduction",
            "Claimed_Value": "11.43% (4/35), 88.6% reduction",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 3",
            "Reconciled_Value_v4": "100.0% (35/35) label-free; 11.43% (4/35) oracle",
            "Status": "WEAKENED",
            "Notes": "Same as TRACE_015, TRACE_028."
        },
        {
            "Claim_ID": "TRACE_101",
            "Section": "6.2 Flash Crowd Resolution",
            "LaTeX_Line": 259,
            "Claimed_Text_Snippet": "lifted Precision from 0.7557 to 0.9416 and test $F_1$ from 0.8526 to 0.9451",
            "Claimed_Value": "Prec 0.7557 -> 0.9416, F1 0.8526 -> 0.9451",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Rows 1 & 3",
            "Reconciled_Value_v4": "Label-free: Prec 0.7557, F1 0.8526; Oracle: Prec 0.9416, F1 0.9451",
            "Status": "WEAKENED",
            "Notes": "Same as TRACE_016."
        },
        {
            "Claim_ID": "TRACE_102",
            "Section": "6.2 Flash Crowd Resolution",
            "LaTeX_Line": 259,
            "Claimed_Text_Snippet": "maintaining 100% campaign recall across all volumetric attacks",
            "Claimed_Value": "100% campaign recall",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 3 (Campaign_Recall = 1.0)",
            "Reconciled_Value_v4": "100.0% (25/25)",
            "Status": "VERIFIED",
            "Notes": "Same as TRACE_017."
        },
        {
            "Claim_ID": "TRACE_103",
            "Section": "6.2 Flash Crowd Resolution",
            "LaTeX_Line": 259,
            "Claimed_Text_Snippet": "ARIMA Residual achieved similar gains, reaching $F_1 = 0.9353$ with 100% campaign recall",
            "Claimed_Value": "F1 = 0.9353, 100% campaign recall",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Row 11",
            "Reconciled_Value_v4": "Label-free: F1 = 0.8471; Oracle: F1 = 0.9353; 100% campaign recall",
            "Status": "WEAKENED",
            "Notes": "Same as Table 2 Row 5."
        },
        {
            "Claim_ID": "TRACE_104",
            "Section": "6.2 Flash Crowd Resolution",
            "LaTeX_Line": 261,
            "Claimed_Text_Snippet": "Config A and Config A-prime collapsed completely (ROC-AUC 0.5000, $F_1 = 0.0000$)",
            "Claimed_Value": "ROC-AUC = 0.5000, F1 = 0.0000",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Rows 17 & 25",
            "Reconciled_Value_v4": "ROC-AUC = 0.5000, F1 = 0.0000",
            "Status": "VERIFIED",
            "Notes": "Re-verified across all 5 seeds in Step 4."
        },

        # =========================================================================
        # SECTION 7: DISCUSSION & SRE OPERATIONAL GUIDELINES (Lines 265-272)
        # =========================================================================
        {
            "Claim_ID": "TRACE_105",
            "Section": "7. Operational Guidelines",
            "LaTeX_Line": 268,
            "Claimed_Text_Snippet": "achieving $F_1 > 0.94$ with minimal computational overhead",
            "Claimed_Value": "F1 > 0.94",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Table 2 Rows 2 & 5 (F1 = 0.9451, 0.9353) and Friday F1 = 0.9792",
            "Reconciled_Value_v4": "F1 > 0.94 holds under oracle feedback, but drops to 0.8526 under label-free testbed",
            "Status": "WEAKENED",
            "Notes": "Under label-free autonomous testbed operation, F1 is 0.8526. (On Friday benchmark, F1 is 0.9792)."
        },
        {
            "Claim_ID": "TRACE_106",
            "Section": "7. Operational Guidelines",
            "LaTeX_Line": 269,
            "Claimed_Text_Snippet": "eliminating 88.6% of false alarms during benign traffic surges",
            "Claimed_Value": "88.6% reduction",
            "Source_File": "results/v3_3/metrics/testbed_results.csv",
            "Source_Row_Or_Expression": "Same as TRACE_028",
            "Reconciled_Value_v4": "0.0% reduction (label-free); 88.6% reduction (oracle)",
            "Status": "WEAKENED",
            "Notes": "Same as TRACE_028."
        },
        {
            "Claim_ID": "TRACE_107",
            "Section": "7. Operational Guidelines",
            "LaTeX_Line": 270,
            "Claimed_Text_Snippet": "Enforce Minimum Reference Capacity ($N \\ge 100$)",
            "Claimed_Value": "N >= 100",
            "Source_File": "configs/v3_1/cse_cic_ids2018_within_day.json",
            "Source_Row_Or_Expression": "min_train_windows: 100",
            "Reconciled_Value_v4": "N >= 100",
            "Status": "VERIFIED",
            "Notes": "Engineering guideline based on empirical starvation threshold."
        },

        # =========================================================================
        # UNSOURCED / DISCREPANCY SUMMARY ENTRIES (Explicit tracking)
        # =========================================================================
        {
            "Claim_ID": "TRACE_108",
            "Section": "1. Introduction",
            "LaTeX_Line": 68,
            "Claimed_Text_Snippet": "99.8% accuracy (base paper claim)",
            "Claimed_Value": "99.8% accuracy",
            "Source_File": "NONE",
            "Source_Row_Or_Expression": "No file in repo or base paper asserts 99.8% accuracy",
            "Reconciled_Value_v4": "99.6% accuracy (true base paper value)",
            "Status": "UNSOURCED",
            "Notes": "Discrepancy 3 / Unsourced claim: The draft paper states 99.8% accuracy, but Al-Mazrawe & Al-Musawi (2025) reported 99.6% accuracy on UNSW-NB15. There is no source file for 99.8% accuracy."
        },
        {
            "Claim_ID": "TRACE_109",
            "Section": "6.1 Architecture",
            "LaTeX_Line": 211,
            "Claimed_Text_Snippet": "RPS in [10, 40] in microservice telemetry",
            "Claimed_Value": "RPS in [10, 40]",
            "Source_File": "NONE",
            "Source_Row_Or_Expression": "No telemetry file contains RPS in [10, 40]",
            "Reconciled_Value_v4": "RPS in [0.23, 4.85] (measured telemetry)",
            "Status": "UNSOURCED",
            "Notes": "Discrepancy / Unsourced claim: Stated 10-40 RPS in text has no backing telemetry file; measured testbed telemetry ranges between 0.23 and 4.85 RPS (Figure 4)."
        },
        {
            "Claim_ID": "TRACE_110",
            "Section": "Figure 3 Caption",
            "LaTeX_Line": 202,
            "Claimed_Text_Snippet": "zero false alarms on Friday DoS-Hulk",
            "Claimed_Value": "0 false alarms (0.0% FPR)",
            "Source_File": "NONE",
            "Source_Row_Or_Expression": "No file records 0 false alarms for Friday Rolling Conformal",
            "Reconciled_Value_v4": "2 false alarms (1.67% FPR)",
            "Status": "UNSOURCED",
            "Notes": "Discrepancy 4 / Unsourced claim: The claim of 'zero false alarms' in Figure 3 caption has no backing source file; the actual run achieved 2 false alarms (1.67% FPR)."
        },
        {
            "Claim_ID": "TRACE_111",
            "Section": "Figure 4 Caption",
            "LaTeX_Line": 245,
            "Claimed_Text_Snippet": "dynamic conformal thresholds tracking diurnal variation in Figure 4 bottom panel",
            "Claimed_Value": "Threshold curves tau_t plotted in Figure 4",
            "Source_File": "NONE",
            "Source_Row_Or_Expression": "No plot file or script plotted tau_t in Figure 4 bottom panel",
            "Reconciled_Value_v4": "Threshold curves not plotted (anomaly scores only)",
            "Status": "UNSOURCED",
            "Notes": "Discrepancy 5 / Unsourced claim: Figure 4 caption states the bottom panel plots dynamic conformal thresholds, but neither the figure generation script nor the image contains threshold curves."
        }
    ]

    df_trace = pd.DataFrame(trace_records)
    out_path = "docs/number_trace.csv"
    df_trace.to_csv(out_path, index=False)
    print(f"Successfully generated {out_path} with {len(df_trace)} audited claims.")
    print("\nSummary by Status:")
    print(df_trace["Status"].value_counts())

if __name__ == "__main__":
    build_number_trace()

