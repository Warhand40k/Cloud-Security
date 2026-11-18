# Project Structure & Repository Layout

This document details the modular layout of the Cloud Network Anomaly Detection reproducibility repository.

```text
.
├── configs/                     # Experiment configurations (cross-day, within-day, unsw, testbed)
│   ├── cse_cic_ids2018.json
│   ├── unsw_nb15_flow.json
│   ├── unsw_nb15_window.json
│   ├── v2/
│   │   ├── cse_cic_ids2018_multiday.json
│   │   └── unsw_nb15.json
│   ├── v3/
│   │   ├── cse_cic_ids2018_multiday.json
│   │   └── unsw_nb15.json
│   └── v3_1/
│       ├── cse_cic_ids2018_cross_day.json
│       ├── cse_cic_ids2018_multiday.json
│       ├── cse_cic_ids2018_within_day.json
│       └── unsw_nb15.json
│
├── data/                        # Datasets (gitignored raw/processed; download script provided)
│   ├── processed/               # Aggregated continuous 60s/10s regular time windows (*.parquet)
│   ├── raw/                     # Original CSV dumps (UNSW-NB15 and CSE-CIC-IDS2018)
│   └── testbed/                 # Containerized testbed campaign schedules and collected telemetry
│       ├── testbed_campaign_schedule.json
│       ├── testbed_schedule_seed_42.json ... 46.json
│       └── testbed_seed_42.parquet ... 46.parquet
│
├── docs/                        # Formal audit reports and claim trace
│   ├── config_definitions.md    # Configuration registry for models and benchmarks
│   ├── conformal_definitions.md # Formal split-conformal and adaptive conformal formulations
│   ├── findings_v4.md           # Stage 4 audit, verification, and discrepancy reconciliation report
│   └── number_trace.csv         # Itemized audit reconciling all 111 claims to backing artifacts
│
├── experiments/                 # Standalone, reproducible experiment runners
│   ├── run_cross_day_and_sensitivity_v3_1.py
│   ├── run_matched_operating_points.py
│   ├── run_m_sensitivity_v2.py
│   ├── run_paired_persistence_analysis_v3_1.py
│   ├── run_persistence_sweep.py
│   ├── run_pipeline.py
│   ├── run_saturation_diagnosis_v3_1.py
│   ├── run_shared_threshold_evaluations_v3_1.py
│   ├── run_stage2_conformal_evaluations.py
│   ├── run_stage2_gate_complementarity.py
│   ├── run_stage3_testbed_evaluation.py
│   ├── run_stage4_step1_verification.py
│   ├── run_stage4_step2_mp_diagnostics.py
│   ├── run_stage4_step3_matched_conformal.py
│   ├── run_stage4_step4_testbed_verification.py
│   ├── run_timeblock_and_sensitivity.py
│   ├── run_timeblock_v2.py
│   ├── run_timeblock_v3_1.py
│   └── run_unsw_multiblock_flow_v3_1.py
│
├── results/                     # Experimental metrics and publication-ready figures
│   ├── figures/                 # Stage 1 & high-res figures
│   ├── metrics/                 # Stage 1 tabular metric summaries
│   ├── v2/                      # Stage 2 look-ahead bias and synthetic diagnostics
│   ├── v3/                      # Stage 2.5 intermediate multi-day evaluations
│   ├── v3_1/                    # Stage 1.5 saturation diagnosis and cross-day sizing
│   ├── v3_2/                    # Stage 2 conformal calibration benchmarks
│   ├── v3_3/                    # Stage 3 testbed initial validation
│   └── v4/                      # Canonical Stage 4 verified audit outputs (matching paper Tables 1-3)
│       ├── figures/
│       ├── metrics/
│       └── predictions/
│
├── scripts/                     # Preprocessing, verification, and figure generation utilities
│   ├── download_datasets.py     # Download and verify raw benchmark datasets
│   ├── generate_number_trace.py # Re-computes and audits docs/number_trace.csv
│   ├── generate_publication_figures_high_res.py # Generates publication plots
│   ├── generate_v3_1_regular_windows.py         # Regularizes 60s continuous grids
│   ├── run_aprime_real_data_eval.py             # Evaluates causal Config A-prime
│   ├── verify_csecicids2018.py                  # Telemetry integrity checks
│   └── verify_unsw_nb15.py                      # UNSW flow verification
│
├── src/                         # Core algorithmic library
│   ├── adaptive_threshold.py    # Conformal calibrators (Split-Conformal, Rolling, ACI)
│   ├── anomaly_scoring.py       # Distance profile to discord score converters
│   ├── baselines.py             # Isolation Forest, ARIMA(1,0,1) residual detectors
│   ├── causal_ab_scorer.py      # Non-look-ahead causal streaming mSTAMP AB-join
│   ├── evaluation.py            # Classification & SRE operational metrics (ROC-AUC, MTTD, FAR)
│   ├── kneedle.py               # Kneedle dimensional subspace selection algorithm
│   ├── matrix_profile.py        # Multidimensional Matrix Profile (mSTAMP wrapper)
│   ├── persistence_filter.py    # Temporal persistence filter (k >= 2 crossings)
│   ├── preprocessing.py         # Leakage-free categorical encoding & robust scaling
│   └── windowing.py             # Regularized gapless time-window aggregation
│
├── testbed/                     # Live Dockerized microservice testbed
│   ├── app.py                   # Instrumented Flask application with Prometheus metrics
│   ├── attacker.py              # Confined attacker container generating 25 campaigns
│   ├── campaign_schedule.py     # Randomized multi-seed schedule generator
│   ├── docker-compose.yml       # Testbed orchestration with isolated internal bridge
│   ├── Dockerfile.app           # App container specification
│   ├── Dockerfile.attacker      # Attacker container specification
│   ├── Dockerfile.locust        # Locust load-generator specification
│   ├── locustfile.py            # Diurnal sinusoidal benign transaction generator
│   └── run_testbed.py           # Multi-seed testbed execution harness
│
├── tests/                       # Complete unit and regression test suite (29 tests)
│   ├── test_campaign_accounting_consistency.py
│   ├── test_causal_ab_scorer.py
│   ├── test_chronological_time_integrity.py
│   ├── test_conformal_no_label_leakage.py
│   ├── test_conformal_threshold.py
│   ├── test_kneedle.py
│   ├── test_no_label_leakage.py
│   ├── test_persistence_filter.py
│   ├── test_scaler_leakage.py
│   └── test_threshold_rule.py
│
├── .gitignore                   # Comprehensive ignore rules (data, large files, hidden assets)
├── README.md                    # Research overview, numerical findings, and reproduction guide
└── requirements.txt             # Pinned Python package dependencies
```
