# Project Progress Tracker

> **Project:** Reproduction and Extension of mSTAMP + Kneedle for Cloud Network Anomaly Detection  
> **Course:** Cloud SRE and Security  
> **Base Paper:** Al-Mazrawe & Al-Musawi (2025), *Enhancing Cloud Network Security with Innovative Time Series Analysis*, JISA.  
> **Last Updated:** 2026-11-09

---

## 📊 Summary of Progress

| Phase | Description | Status | Progress |
|---|---|:---:|:---:|
| **Phase 1** | Environment Setup, Scaffolding & Raw Data Acquisition | ✅ Completed | 100% |
| **Phase 2** | Preprocessing, Feature Extraction & Chronological Splitting | ✅ Completed | 100% |
| **Phase 3** | Config A: Base Reproduction (mSTAMP + Kneedle) | ✅ Completed | 100% |
| **Phase 4** | Config B1/B2/C: Extensions (MAD, EVT, Persistence Filter) | ✅ Completed | 100% |
| **Phase 5** | Baselines (Isolation Forest, ARIMA-Residual Detector) | ✅ Completed | 100% |
| **Phase 6** | Comprehensive Evaluation (ML, SRE & Resource Metrics) | ✅ Completed | 100% |
| **Phase 7** | Research Paper Draft & Presentation Deliverables | 🔄 In Progress | 25% |

---

## Detailed Task Checklist

### Phase 1: Environment, Scaffolding & Raw Data Verification
- [x] Create core repository directory structure (`src/`, `data/raw/`, `data/processed/`, `experiments/`, `notebooks/`, `results/`)
- [x] Configure `.gitignore` to protect raw/processed data and results
- [x] Set up Python 3.12 virtual environment (`.venv`) and core dependencies (`stumpy`, `kneed`, `pandas`, `scipy`, `statsmodels`, `scikit-learn`, `matplotlib`, `seaborn`, `psutil`)
- [x] Export pinned environment to `requirements.txt`
- [x] Download raw UNSW-NB15 files (`UNSW-NB15_1.csv` ... `4.csv`, `NUSW-NB15_features.csv`, `UNSW-NB15_LIST_EVENTS.csv`)
- [x] **UNSW-NB15 Day-1 Verification Checks (Section 4.1):**
  - [x] Check 1: Verify presence and consistency of timestamp columns (`Stime`, `Ltime`) across all 2.54M records (0 nulls, valid timestamps)
  - [x] Check 2: Check duplicate/invalid timestamps and monotonic chronological ordering (raw CSV concatenation has 345,831 backwards jumps; chronological sorting strictly required)
  - [x] Check 3: Check missing values, markers (`-`, `?`, `#DIV/0!`), and class balance (`label` & `attack_cat`: 87.35% normal, 12.65% attack, 0 label mismatches)
  - [x] Check 4: Confirm existence and formatting of paper's 9 features (`sloss, state, dur, sbytes, dbytes, sttl, dttl, dloss, service` all verified)
  - [x] Check 5: Measure temporal attack distribution (validated interleaving: 51.84% of attack runs are single isolated flows; 76.3% are $\le 5$ flows)
  - [x] Compiled comprehensive Day-1 report in `docs/day1_unsw_nb15_report.md`

---

### Phase 2: Data Preprocessing, Windowing & Chronological Splitting
- [x] Build preprocessing pipeline in `src/preprocessing.py`:
  - [x] Strict chronological sorting by `['Stime', 'Ltime']`
  - [x] Categorical encoding (`state`, `service`) fitted strictly on training split only (with `<UNK>` handling)
  - [x] Missing marker handling (`#DIV/0!`, `?`, `-`) with train-fitted statistics
  - [x] Train/validation/test chronological partition (no shuffling, zero leakage: 60% / 20% / 20%)
- [x] Build time-windowing aggregation in `src/windowing.py`:
  - [x] Window-based grouping (10s intervals as in base paper)
  - [x] Mode aggregation for categoricals and ground truth labeling (`any_attack` and `attack_ratio`)
  - [x] Export processed dataset to Parquet (`data/processed/unsw_nb15_10s_windows.parquet`)

---

### Phase 3: Config A — Base Reproduction Pipeline
- [x] Implement multidimensional Matrix Profile wrapper in `src/matrix_profile.py` using STUMPY (`stumpy.mstump`)
- [x] Implement Kneedle dimension selector in `src/kneedle.py` with `kneed` (supporting online mode and curvature inspection)
- [x] Implement anomaly scoring and alignment in `src/anomaly_scoring.py` (causal right-alignment with zero look-ahead bias)
- [x] Documented all paper ambiguities (score threshold, alignment, window size $m$) as project decisions

---

### Phase 4: Extensions — Adaptive Thresholds & Persistence Filtering
- [x] Implement adaptive thresholding in `src/adaptive_threshold.py`:
  - [x] **Config B1:** Rolling Median / MAD adaptive threshold ($T_t = \text{Med}_t + c \times 1.4826 \cdot \text{MAD}_t$)
  - [x] **Config B2:** EVT Peaks-Over-Threshold (POT) using Generalized Pareto Distribution (`genpareto`) calibrated to target false-alarm probability $p$
- [x] Implement persistence filter in `src/persistence_filter.py`:
  - [x] **Config C:** $k$-consecutive anomaly requirement to suppress transient alert bursts
  - [x] Sweep persistence $k$ on validation split

---

### Phase 5: Baselines Implementation
- [x] Implement Isolation Forest baseline in `src/baselines.py` (fitted on train, validation-calibrated threshold)
- [x] Implement ARIMA-residual / CUSUM baseline in `src/baselines.py` (univariate one-step forecast errors aggregated across features)

---

### Phase 6: Evaluation & SRE Metrics
- [x] Implement evaluation harness in `src/evaluation.py`:
  - [x] Classification metrics: Accuracy, Precision, Recall, F1, FPR, PR-AUC, ROC-AUC, Confusion Matrix
  - [x] SRE operational metrics: Detection delay (MTTD / Mean Time to Detect), False Alarms per Day (FAPD), Total Alert Volume, Episode Recall
  - [x] Computational resource profiling: Execution time, peak memory usage via `psutil`
- [x] Build end-to-end pipeline script `experiments/run_pipeline.py` supporting both flow-level and window-level modes
- [x] Export structured metrics to `results/metrics/comparison_table_flow.csv` and `results/metrics/comparison_table_flow.json`
- [x] Generate publication figures in `results/figures/comparison_f1_alerts_flow.png` and `results/figures/kneedle_curve_flow.png`

---

### Phase 7: Academic Paper & Presentation
- [x] Initial outline drafted in `README.md`
- [ ] Compile experimental tables and comparison plots
- [ ] Draft Paper sections:
  1. Abstract & Introduction (Cloud SRE context)
  2. Related Work & Background (Matrix Profile, mSTAMP, Kneedle)
  3. Original Pipeline & Ambiguities Resolved
  4. Proposed Extensions (MAD, EVT, Persistence)
  5. Experimental Setup & Datasets
  6. Results & Discussion (Ablation, Baselines, SRE metrics)
  7. Threats to Validity & Limitations
  8. Conclusion & Future Work
- [ ] Prepare presentation slides and reproducible run instructions
