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
| **Phase 4b** | Dataset 2: CSE-CIC-IDS2018 (AWS Cloud Telemetry & Flooding) | ✅ Completed | 100% |
| **Phase 5** | Baselines (Isolation Forest, ARIMA, Trivial Baselines) | ✅ Completed | 100% |
| **Phase 6** | Comprehensive Evaluation (ML, SRE, Configs & Gap Decision) | ✅ Completed | 100% |
| **Stage 1.5** | Foundation Repairs (Time-Axis, Reference Sizing, Saturation Diagnosis) | ✅ Completed | 100% |
| **Stage 2** | Positive Contribution: Split-Conformal & Adaptive Thresholding | ✅ Completed | 100% |
| **Stage 3** | Bounded Testbed Validation (Live Microservice, 25 Campaigns, Flash Crowds) | ✅ Completed | 100% |
| **Phase 7** | Research Paper (LaTeX & Markdown Manuscripts with Assets, Literature Survey & Clean Tables) | ✅ Completed | 100% |

---

## Detailed Task Checklist

### Phase 1: Environment, Scaffolding & Raw Data Verification
- [x] Create core repository directory structure (`src/`, `data/raw/`, `data/processed/`, `experiments/`, `notebooks/`, `results/`, `configs/`)
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
  - [x] Window-based grouping (10s intervals as in base paper; configurable window lengths)
  - [x] Mode aggregation for categoricals and ground truth labeling (`any_attack` and `attack_ratio`)
  - [x] Export processed dataset to Parquet (`data/processed/unsw_nb15_10s_windows.parquet`)
- [x] **UNSW Window Label Definition & Batch Gap Decision:**
  - [x] Compared `any_attack` vs. `majority_attack` (>0.5 ratio) on validation data; fixed `any_attack` as primary security ground-truth rule (strict majority masks 98.3% of attack windows).
  - [x] Formulated batch gap strategy:
    - Flow-level contiguous evaluation: 8,000 flows from Batch 1 (rare anomaly setting: 3.8% train, 6.7% val, 11.7% test).
    - Window-level cross-batch evaluation: Train on pure benign baseline [1200:3200], Val on transition [3200:4600], Test on held-out attack campaign [4600:5800].
  - [x] Implemented trivial baselines (All-Attack, All-Normal, Random-Uniform, Random-Stratified) and recomputed results across all configurations.

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

### Phase 4b: Dataset 2: CSE-CIC-IDS2018 (AWS Cloud Telemetry & Flooding)
- [x] Downloaded and verified multiple days from AWS S3 Open Data:
  - [x] `Friday-16-02-2018` (DoS-Hulk & DoS-SlowHTTPTest, 318.26 MB)
  - [x] `Thursday-15-02-2018` (DoS-GoldenEye & DoS-Slowloris, 358.53 MB)
  - [x] `Wednesday-21-02-2018` (DDOS-HOIC & DDOS-LOIC-UDP, 313.66 MB)
- [x] **File Truncation Analysis:** Formally verified the Excel $2^{20} = 1,048,576$ rows truncation across all daily CSV files originating from CICFlowMeter exports.
- [x] Day-1 verification report compiled in `docs/day1_csecicids2018_report.md`:
  - [x] Verified timestamps (0 unparseable values, sorted chronologically)
  - [x] Checked attack block contiguity: discovered massive sustained flooding bursts (up to 55,777 contiguous attack flows per block)
  - [x] Verified 80 telemetry features and class balance across days
- [x] Built windowing feature extraction in `src/windowing.py` (`aggregate_csecicids2018_windows` for 60s windows, computing flow counts, packet rates, byte volumes, and TCP flag sums)
- [x] Executed full pipeline (Config A, B1, B2, C, IF, AR, Trivial) on CSE-CIC-IDS2018
- [x] Measured MTTD detection delay and persistence filtering ($k \ge 1$) on contiguous flooding episodes

---

### Phase 5: Baselines Implementation
- [x] Implement Isolation Forest baseline in `src/baselines.py` (fitted on train, validation-calibrated threshold)
- [x] Implement ARIMA-residual / CUSUM baseline in `src/baselines.py` (univariate one-step forecast errors aggregated across features)
- [x] Implement Trivial Baselines in `src/baselines.py`:
  - [x] `All-Attack` (predict 1 everywhere)
  - [x] `All-Normal` (predict 0 everywhere)
  - [x] `Random-Uniform` ($p = 0.5$)
  - [x] `Random-Stratified` ($p = \text{training attack prior}$)

---

### Phase 6: Evaluation, Robustness & Saved Configs
- [x] Implement evaluation harness in `src/evaluation.py`:
  - [x] Classification metrics: Accuracy, Precision, Recall, F1, FPR, PR-AUC, ROC-AUC, Confusion Matrix
  - [x] SRE operational metrics: Detection delay (MTTD / Mean Time to Detect), False Alarms per Day (FAPD), Total Alert Volume, Episode Recall
  - [x] Bootstrap 95% Confidence Intervals for F1, PR-AUC, and episode-level block MTTD with explicit ground-truth episode counts
  - [x] Computational resource profiling: Execution time, peak memory usage via `psutil`
- [x] **Verification & Calibration Enhancements:**
  - [x] Synthetic-discord sanity test (`scripts/synthetic_discord_test.py`): verified 0 localization error and zero look-ahead bias on injected discords.
  - [x] EVT POT calibration fix: fitted on extended benign history, adaptive tail quantile, and risk grid support capping ($p \ge 1/(2N)$).
- [x] **Rolling-Origin Time-Block Evaluation (`experiments/run_timeblock_and_sensitivity.py`):**
  - [x] Multi-day temporal blocks over CSE-CIC-IDS2018 (Thursday, Friday, Wednesday); reported Mean $\pm$ Spread (Std) across blocks.
- [x] **Sensitivity Analysis:**
  - [x] Sensitivity to subsequence length $m \in [5, 10, 20, 30, 50, 75, 100]$ (demonstrated constant STUMPY runtime and effect on transient exploit detection).
  - [x] Sensitivity to 4 alternative chronological slice cuts across UNSW-NB15 Batch 1.
- [x] **Saved Configs & Deterministic Reproducibility:**
  - [x] Created `configs/unsw_nb15_flow.json`, `configs/unsw_nb15_window.json`, and `configs/cse_cic_ids2018.json`
  - [x] Tested deterministic regeneration: every result table and figure is regenerated via `python experiments/run_pipeline.py --config configs/<name>.json`
- [x] Recomputed full benchmark table on UNSW-NB15 with fixed label definition and trivial baselines

---

### Stage 1.5: Evaluation Foundations & Diagnostic Audit
- [x] Regular 60-second gapless time series with real UTC timestamps (`src/windowing.py`)
- [x] Chronological split integrity assertion ($\text{Train} < \text{Val} < \text{Test}$, `tests/test_chronological_time_integrity.py`)
- [x] Standardized campaign accounting ($g=0$ clipped to slice, `tests/test_campaign_accounting_consistency.py`)
- [x] Enforced minimum reference sizing ($N \ge 100$) and demonstrated ranking sensitivity (`results/v3_1/metrics/csecicids2018_ranking_comparison.csv`)
- [x] Unified label-free threshold rule ($\text{FAR} \le \alpha$ on held-out benign scores with tie adjustment, `src/adaptive_threshold.py`)
- [x] Mathematical diagnosis of saturation (refuted stale reference hypothesis, fixed zero scores and zero-MAD collapse)
- [x] Paired persistence analysis ($k \in \{1..5\}$ on identical scores/thresholds; refuted Claim #8)
- [x] Multi-block flow evaluation (10 contiguous blocks of 8,000 flows, proving matrix profile unsuited for flow data)
- [x] Pre-registered Stage 2 Fusion Gate outcome (`NO-GO` due to zero orthogonal recall gain and FPR inflation)

---

### Stage 2: One Positive Contribution (Split-Conformal & Adaptive Thresholding)
- [x] Implemented `ConformalQuantileThreshold` in `src/adaptive_threshold.py`:
  - [x] Static Split-Conformal with exact p-values and point-mass tie adjustment
  - [x] Causal Rolling Split-Conformal ($W = 60$) with anti-poisoning self-filtering
  - [x] Adaptive Conformal Inference (ACI; Gibbs & Candès 2021) with dynamic nominal risk tracking
- [x] Created unit tests in `tests/test_conformal_threshold.py` (6/6 tests passing; 27/27 total suite passing)
- [x] Built and executed benchmark evaluation in `experiments/run_stage2_conformal_evaluations.py` across CSE-CIC-IDS2018 and UNSW-NB15
- [x] Proved FPR control: ACI reduced test FPR from 12.37% down to 2.86% ($\alpha=0.05$) and 1.06% ($\alpha=0.01$)
- [x] Demonstrated boost in top detectors ($F_1: 0.8624 \to 0.9792$ on Friday Hulk; $F_1: 0.9863 \to 1.0000$ on Wednesday LOIC)
- [x] Generated publication figures in `results/v3_2/figures/`
- [x] Compiled comprehensive Stage 2 report in `docs/stage2_conformal_results.md`

---

### Stage 3: Bounded Testbed Validation (Live Microservice, Diurnal Load & Flash Crowds)
- [x] Implemented live e-commerce microservice with Prometheus `/metrics` exposition (`testbed/app.py`)
- [x] Built Locust benign load generator with diurnal sinusoidal traffic shape (`testbed/locustfile.py`)
- [x] Implemented strictly confined local attacker targeting `127.0.0.1` (`testbed/attacker.py`)
- [x] Created Docker Compose multi-container setup with isolated internal bridge network (`testbed/docker-compose.yml`)
- [x] Scheduled 25 labeled operational campaigns (floods, slowloris, pulsing spikes, recon scans, and benign flash crowds) across 600 windows (10h simulated)
- [x] Collected and persisted 60-second window telemetry to `data/testbed/testbed_60s_regular.parquet`
- [x] Executed frozen detection pipeline (Config A, A-prime, Isolation Forest, ARIMA, Conformal Thresholds) on testbed data (`experiments/run_stage3_testbed_evaluation.py`)
- [x] Evaluated flash crowd discrimination: proved rolling conformal calibration slashed flash crowd false alarms from 100% to 11.4%
- [x] Replicated matrix profile collapse on live microservice telemetry (reproducing Stage 1.5 findings)
- [x] Generated publication validation figures in `results/v3_3/figures/`
- [x] Compiled comprehensive Stage 3 validation report in `docs/stage3_testbed_validation.md`

---

### Phase 7: Academic Paper & Presentation
- [x] Initial outline drafted in `README.md`
- [x] Compiled comprehensive findings and progress report into [`docs/comprehensive_findings_report.md`](docs/comprehensive_findings_report.md)
- [x] Compile experimental tables and comparison plots (11 figures in `results/figures/` and `paper/figures/`)
- [x] Drafted complete Academic Research Paper in Markdown (`docs/research_paper.md`) across 12 full sections with KaTeX math, empirical tables, and citations
- [x] Drafted IEEE conference-formatted LaTeX manuscript (`paper/main.tex`) and BibTeX library (`paper/references.bib`)
- [x] Copied all publication figures into `paper/figures/`
- [x] Tagged final frozen commits: `stage1.5-complete`, `stage2-complete`, `stage3-complete`, `stage4-paper-complete`
