# Project Structure

This document outlines the folder structure of the project located at `cloudSRE&Security/project/`.

```text
cloudSRE&Security/project/
├── .git/
├── .pytest_cache/
├── .venv/
├── configs/
│   ├── v2/
│   │   ├── cse_cic_ids2018_multiday.json
│   │   └── unsw_nb15.json
│   ├── v3/
│   │   ├── cse_cic_ids2018_multiday.json
│   │   └── unsw_nb15.json
│   ├── v3_1/
│   │   ├── cse_cic_ids2018_cross_day.json
│   │   ├── cse_cic_ids2018_multiday.json
│   │   ├── cse_cic_ids2018_within_day.json
│   │   └── unsw_nb15.json
│   ├── cse_cic_ids2018.json
│   ├── unsw_nb15_flow.json
│   └── unsw_nb15_window.json
├── data/
│   ├── processed/
│   │   ├── csecicids2018_60s_any_attack.parquet
│   │   ├── csecicids2018_friday_60s_regular.parquet
│   │   ├── csecicids2018_thursday_60s_any_attack.parquet
│   │   ├── csecicids2018_thursday_60s_regular.parquet
│   │   ├── csecicids2018_wednesday_60s_any_attack.parquet
│   │   ├── csecicids2018_wednesday_60s_regular.parquet
│   │   ├── unsw_nb15_10s_any_attack.parquet
│   │   └── unsw_nb15_10s_windows.parquet
│   ├── raw/
│   │   ├── Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
│   │   ├── NUSW-NB15_features.csv
│   │   ├── Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
│   │   ├── UNSW-NB15_1.csv
│   │   ├── UNSW-NB15_2.csv
│   │   ├── UNSW-NB15_3.csv
│   │   ├── UNSW-NB15_4.csv
│   │   ├── UNSW-NB15_features.csv
│   │   ├── UNSW-NB15_LIST_EVENTS.csv
│   │   ├── UNSW-NB15_testing-set.csv
│   │   ├── UNSW-NB15_training-set.csv
│   │   └── Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
│   └── testbed/
│       ├── testbed_60s_regular.csv
│       ├── testbed_60s_regular.parquet
│       ├── testbed_campaign_schedule.json
│       ├── testbed_schedule_seed_42.json
│       ├── testbed_schedule_seed_43.json
│       ├── testbed_schedule_seed_44.json
│       ├── testbed_schedule_seed_45.json
│       ├── testbed_schedule_seed_46.json
│       ├── testbed_seed_42.parquet
│       ├── testbed_seed_43.parquet
│       ├── testbed_seed_44.parquet
│       ├── testbed_seed_45.parquet
│       └── testbed_seed_46.parquet
├── docs/
│   ├── 1-s2.0-S2214212620307560-main.pdf
│   ├── 3064814.3064831.pdf
│   ├── 4768-Article Text-25473-1-10-20250203.pdf
│   ├── CHANGELOG_v3.md
│   ├── CHANGELOG_v3_1.md
│   ├── comprehensive_findings_report.md
│   ├── config_definitions.md
│   ├── conformal_definitions.md
│   ├── day1_csecicids2018_report.md
│   ├── day1_unsw_nb15_report.md
│   ├── findings_v2.md
│   ├── findings_v3.md
│   ├── findings_v3_1.md
│   ├── findings_v4.md
│   ├── number_trace.csv
│   ├── research_paper.md
│   ├── s10207-024-00921-0.pdf
│   ├── stage2_candidates.md
│   ├── stage2_conformal_results.md
│   ├── stage2_gate.md
│   └── stage3_testbed_validation.md
├── experiments/
│   ├── __pycache__/
│   ├── run_cross_day_and_sensitivity_v3_1.py
│   ├── run_matched_operating_points.py
│   ├── run_m_sensitivity_v2.py
│   ├── run_paired_persistence_analysis_v3_1.py
│   ├── run_persistence_sweep.py
│   ├── run_pipeline.py
│   ├── run_stage2_conformal_evaluations.py
│   ├── run_saturation_diagnosis_v3_1.py
│   ├── run_shared_threshold_evaluations_v3_1.py
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
├── notebooks/            (empty)
├── paper/
│   ├── assets/
│   │   ├── comparison_f1_alerts_flow.png
│   │   ├── conformal_f1_vs_fpr.png
│   │   ├── conformal_fpr_control_alpha05.png
│   │   ├── conformal_rolling_thresholds_friday.png
│   │   ├── cse_cic_ids2018_f1_alerts.png
│   │   ├── f1_vs_false_alarms.png
│   │   ├── kneedle_curve_flow.png
│   │   ├── kneedle_selection_curve.png
│   │   ├── matched_curves_cse_friday.png
│   │   ├── matched_curves_cse_thursday.png
│   │   ├── matched_curves_unsw_flow.png
│   │   ├── matched_curves_unsw_regime_shift.png
│   │   ├── paired_persistence_effect.png
│   │   ├── score_histograms_saturation_diagnosis.png
│   │   ├── sensitivity_m.png
│   │   ├── sensitivity_slices.png
│   │   ├── synthetic_discord_test.png
│   │   ├── testbed_campaign_type_recall.png
│   │   ├── testbed_timeline_scores.png
│   │   ├── timeblock_f1_spread.png
│   │   ├── unsw_multiblock_flow_f1.png
│   │   ├── unsw_nb15_flow_f1_alerts.png
│   │   └── unsw_nb15_window_f1_alerts.png
│   ├── figures/
│   │   ├── comparison_f1_alerts_flow.png
│   │   ├── conformal_f1_vs_fpr.png
│   │   ├── conformal_fpr_control_alpha05.png
│   │   ├── conformal_rolling_thresholds_friday.png
│   │   ├── cse_cic_ids2018_f1_alerts.png
│   │   ├── f1_vs_false_alarms.png
│   │   ├── kneedle_curve_flow.png
│   │   ├── kneedle_selection_curve.png
│   │   ├── matched_curves_cse_friday.png
│   │   ├── matched_curves_cse_thursday.png
│   │   ├── matched_curves_unsw_flow.png
│   │   ├── matched_curves_unsw_regime_shift.png
│   │   ├── paired_persistence_effect.png
│   │   ├── score_histograms_saturation_diagnosis.png
│   │   ├── sensitivity_m.png
│   │   ├── sensitivity_slices.png
│   │   ├── synthetic_discord_test.png
│   │   ├── testbed_campaign_type_recall.png
│   │   ├── testbed_timeline_scores.png
│   │   ├── timeblock_f1_spread.png
│   │   ├── unsw_multiblock_flow_f1.png
│   │   ├── unsw_nb15_flow_f1_alerts.png
│   │   └── unsw_nb15_window_f1_alerts.png
│   ├── main.tex
│   └── references.bib
├── results/
│   ├── archive/
│   │   ├── figures/
│   │   └── metrics/
│   ├── archive_v2/
│   │   ├── figures/
│   │   ├── metrics/
│   │   └── predictions/
│   ├── figures/
│   │   ├── .gitkeep
│   │   ├── comparison_f1_alerts_flow.png
│   │   ├── cse_cic_ids2018_f1_alerts.png
│   │   ├── f1_vs_false_alarms.png
│   │   ├── kneedle_curve_flow.png
│   │   ├── kneedle_selection_curve.png
│   │   ├── sensitivity_m.png
│   │   ├── sensitivity_slices.png
│   │   ├── synthetic_discord_test.png
│   │   ├── timeblock_f1_spread.png
│   │   ├── unsw_nb15_flow_f1_alerts.png
│   │   └── unsw_nb15_window_f1_alerts.png
│   ├── metrics/
│   │   ├── .gitkeep
│   │   ├── comparison_table.csv
│   │   ├── comparison_table.json
│   │   ├── comparison_table_flow.csv
│   │   ├── comparison_table_flow.json
│   │   ├── cse_cic_ids2018_config.json
│   │   ├── cse_cic_ids2018_results.csv
│   │   ├── cse_cic_ids2018_results.json
│   │   ├── rolling_timeblock_summary.csv
│   │   ├── rolling_timeblock_summary.json
│   │   ├── sensitivity_m_results.csv
│   │   ├── sensitivity_m_results.json
│   │   ├── sensitivity_slices_results.csv
│   │   ├── sensitivity_slices_results.json
│   │   ├── unsw_nb15_flow_config.json
│   │   ├── unsw_nb15_flow_results.csv
│   │   ├── unsw_nb15_flow_results.json
│   │   ├── unsw_nb15_window_config.json
│   │   ├── unsw_nb15_window_results.csv
│   │   └── unsw_nb15_window_results.json
│   ├── predictions/
│   │   └── .gitkeep
│   ├── v2/
│   │   ├── figures/
│   │   ├── metrics/
│   │   └── predictions/
│   ├── v3/
│   │   ├── figures/
│   │   ├── metrics/
│   │   └── predictions/
│   ├── v3_1/
│   │   ├── figures/
│   │   ├── metrics/
│   │   └── predictions/
│   ├── v3_2/
│   │   ├── figures/
│   │   ├── metrics/
│   │   └── predictions/
│   ├── v3_3/
│   │   ├── figures/
│   │   ├── metrics/
│   │   └── predictions/
│   └── v4/
│       ├── figures/
│       ├── metrics/
│       ├── predictions/
│       ├── run_metadata_step1.json
│       ├── run_metadata_step2.json
│       ├── run_metadata_step3.json
│       ├── run_metadata_step4.json
│       └── run_metadata_step5.json
├── scripts/
│   ├── __pycache__/
│   ├── aggregate_all_csecicids2018_days.py
│   ├── diagnostic_lookahead_test.py
│   ├── diagnostic_sustained_anomaly_aprime_test.py
│   ├── diagnostic_sustained_anomaly_test.py
│   ├── generate_evt_calibration.py
│   ├── generate_number_trace.py
│   ├── generate_phase1_facts.py
│   ├── generate_publication_figures_high_res.py
│   ├── generate_slice_composition_table.py
│   ├── generate_v3_1_regular_windows.py
│   ├── inspect_csecicids2018_days.py
│   ├── run_aprime_real_data_eval.py
│   ├── run_csecicids2018_eval.py
│   ├── run_determinism_test.py
│   ├── run_unsw_eval.py
│   ├── synthetic_discord_test.py
│   ├── verify_csecicids2018.py
│   └── verify_unsw_nb15.py
├── src/
│   ├── __pycache__/
│   ├── adaptive_threshold.py
│   ├── anomaly_scoring.py
│   ├── baselines.py
│   ├── causal_ab_scorer.py
│   ├── evaluation.py
│   ├── kneedle.py
│   ├── matrix_profile.py
│   ├── persistence_filter.py
│   ├── preprocessing.py
│   └── windowing.py
├── testbed/
│   ├── __pycache__/
│   ├── app.py
│   ├── attacker.py
│   ├── campaign_schedule.py
│   ├── docker-compose.yml
│   ├── Dockerfile.app
│   ├── Dockerfile.attacker
│   ├── Dockerfile.locust
│   ├── locustfile.py
│   └── run_testbed.py
├── tests/
│   ├── __pycache__/
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
├── .gitignore
├── CHANGELOG.md
├── README.md
├── requirements.txt
└── tracker.md
```

## Directory Overview

| Directory | Purpose |
|-----------|---------|
| `configs/` | JSON configuration files for different experiment versions (v2, v3, v3_1) |
| `data/` | Raw CSV datasets, processed Parquet files, and testbed data |
| `docs/` | Research findings, changelogs, config/conformance definitions, and PDF papers |
| `experiments/` | Python scripts for running experiments and analyses |
| `notebooks/` | Empty directory reserved for Jupyter notebooks |
| `paper/` | LaTeX paper source (`main.tex`), references, and figure assets |
| `results/` | Versioned experiment outputs (figures, metrics, predictions) and archives |
| `scripts/` | Utility scripts for data generation, evaluation, and verification |
| `src/` | Core source modules (scoring, preprocessing, windowing, evaluation, etc.) |
| `testbed/` | Dockerized testbed application, attacker, campaign scheduler, and Locust load tests |
| `tests/` | Unit tests for the project components |
| `.venv/` | Python virtual environment |
| `.gitignore`, `README.md`, `requirements.txt`, `tracker.md`, `CHANGELOG.md` | Project root metadata files |
