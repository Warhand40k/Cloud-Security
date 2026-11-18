# Matrix Profiles for Cloud Network Anomaly Detection: A Reproducibility and Calibration Study

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-29%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Authors:** Aalok Kumar, Aditya Sahrawat, Amal Mohanan  
> **Affiliation:** Department of Computer Science and Engineering, Indian Institute of Information Technology (IIIT) Dharwad, Karnataka, India  
> **Course:** Cloud SRE and Security  
> **Base Paper:** Amer Al-Mazrawe and Bahaa Al-Musawi (2025), *Enhancing Cloud Network Security with Innovative Time Series Analysis*, Journal of Internet Services and Applications (JISA), DOI: [10.5753/jisa.2025.4768](https://doi.org/10.5753/jisa.2025.4768).

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [The Cloud SRE Trilemma & Base Paper Gaps](#the-cloud-sre-trilemma--base-paper-gaps)
3. [Five Methodological Pathologies](#five-methodological-pathologies)
4. [Causal Alignment: Config A vs. Config A-prime](#causal-alignment-config-a-vs-config-a-prime)
5. [Key Empirical Results (from Research Paper)](#key-empirical-results-from-research-paper)
   - [Table 1: Matrix Profile Diagnostic Variants](#table-1-roc-auc-of-diagnostic-variants-of-matrix-profile)
   - [Table 2: Conformal Benchmark Across 32 Configurations](#table-2-conformal-threshold-benchmark-summary-across-32-configurations)
   - [Table 3: Multi-Seed Containerized Testbed Results](#table-3-multi-seed-testbed-results-alpha--005)
6. [Datasets & Provenance](#datasets--provenance)
7. [Repository Layout](#repository-layout)
8. [Reproducibility Guide](#reproducibility-guide)
   - [1. Environment Setup](#1-environment-setup)
   - [2. Verification & Test Suite](#2-verification--test-suite)
   - [3. Data Preprocessing & Grid Regularization](#3-data-preprocessing--grid-regularization)
   - [4. Running Experiments & Audits](#4-running-experiments--audits)
   - [5. Regenerating Figures & Claim Trace](#5-regenerating-figures--claim-trace)
9. [Citation & License](#citation--license)

---

## Executive Summary

Detecting anomalies in cloud network telemetry is difficult because attacks are rare, nominal workloads drift, and false alarms lead to operator alert fatigue. A recent pipeline combining multidimensional Matrix Profile (**mSTAMP**) with **Kneedle** dimension selection reported near-perfect detection fidelity ($99.6\%$ accuracy, $F_1 = 0.998$) on UNSW-NB15, but left critical operational primitives unspecified:
- Mathematical scoring semantics and score-to-alarm conversions.
- Calibrated decision thresholds under non-stationary traffic.
- Causal subsequence alignment (preventing look-ahead into future telemetry).
- Non-overlapping chronological partitioning.

This repository hosts a rigorous, leakage-free reproduction, causal extension, and root-cause audit of that pipeline on **UNSW-NB15**, **CSE-CIC-IDS2018** (AWS telemetry), and a live containerized microservice testbed. 

> [!IMPORTANT]
> **Governing Numerical Baseline:** The numerical results reported in the final research paper override all earlier preliminary stage documents. All numbers below are audited against `docs/number_trace.csv` and verified against the canonical evaluation artifacts in `results/v4/`.

---

## The Cloud SRE Trilemma & Base Paper Gaps

Modern cloud platforms balance three conflicting operational demands:
1. **Sensitivity:** Short Mean Time to Detect (MTTD) before service degradation occurs.
2. **Alert Budget:** Holding False Positive Rate (FPR) strictly within budget ($\alpha \le 0.05$) to avoid alert fatigue.
3. **Non-Stationary Robustness:** Distinguishing true volumetric attacks from benign traffic shifts (diurnal seasonality, flash crowds, promotions).

Moving the mSTAMP + Kneedle pipeline from curated static datasets to streaming telemetry exposed significant specification gaps:
- **Look-Ahead Contamination:** Standard all-pairs distance joins compute subsequences against both past and future observations.
- **Reference Starvation:** Within-day training partitions provided as few as $N=16$ benign windows, starving non-parametric baselines.
- **Benign Score Degeneracy:** On flow summaries, $99.73\%$ of benign validation subsequences yielded identical zero scores, collapsing quantile and median absolute deviation (MAD) thresholds to $0.0$.

---

## Five Methodological Pathologies

Our methodological audit diagnosed five root-cause pathologies:

1. **Pathology 1: Time-Axis Integrity & Compression**
   - Evaluating CSE-CIC-IDS2018 Friday DoS-Hulk data ($11.97$ elapsed hours) revealed that raw flow captures omitted **528 quiescent 60-second minutes**, including a **454-minute quiescent gap** between morning attacks and afternoon activity.
   - Sequential indexing compressed 12 hours into 3.1 hours, inflating attack prevalence and distorting wall-clock MTTD.
   - *Fix:* Project raw telemetry onto a continuous, gapless 60-second datetime grid with explicit chronological partitions.

2. **Pathology 2: Training Sizing & Ranking Reversals**
   - Within-day training on Friday ($N=45$) and Wednesday ($N=16$) starved non-parametric detectors, collapsing Isolation Forest to $F_1 = 0.0000$ (Rank 5).
   - Cross-day reference sizing ($N=507$ from Thursday morning) resolved starvation: on Wednesday, Isolation Forest reached **$F_1 = 0.9859$ (Rank 1)**.
   - Initial detector rankings were artifacts of sample starvation, not algorithmic superiority.

3. **Pathology 3: Mathematical Threshold Collapse**
   - On UNSW flow telemetry, $99.73\%$ of benign validation anomaly scores were exactly $0.0$, collapsing $\tau^* = 0.0$ and $\text{MAD} = 0$.
   - The detector raised $100\%$ false alarms not because of calendar drift across 26 days, but because of score point-mass degeneracy.

4. **Pathology 4: Persistence Filter Negative Result**
   - A temporal persistence filter requiring $k \ge 2$ consecutive threshold crossings degraded test $F_1$ in **$67.5\%$** of 80 paired configurations (and was neutral in $30.0\%$).
   - On bursty network attacks, persistence acts as an unhelpful delay that lowers recall.

5. **Pathology 5: Multi-Block Flow Evaluation**
   - Across 10 contiguous blocks of 8,000 flows (80,000 flows total) on UNSW-NB15, all matrix profile configurations scored a mean $F_1 \le 0.1246$, failing to beat a naive All-Attack baseline ($F_1 = 0.1281$), with near-chance ROC-AUC between $0.52$ and $0.56$.
   - Euclidean subsequence distance fails to capture transactional, point-in-time network flow semantics.

---

## Causal Alignment: Config A vs. Config A-prime

- **Config A (Base Paper mSTAMP):** Performs all-pairs similarity search across the entire time series. In streaming telemetry, this introduces severe look-ahead bias: **$50\%$ of validation windows and $48\%$ of test windows** matched nearest neighbors located in the future.
- **Config A-prime (Our Causal Streaming Variant):** Restricts the AB-join nearest-neighbor search strictly to observations up to time $t$:
  $$S(t) = P_{t-m+1}^{(k^*)}(\text{AB-join against } \mathcal{R}, \ t \ge m-1)$$
  This guarantees zero look-ahead bias while preserving the exact multidimensional distance profile semantics.

---

## Key Empirical Results (from Research Paper)

### Table 1: ROC-AUC of Diagnostic Variants of Matrix Profile
Evaluated on the live microservice testbed to isolate score degeneracy:

| Variant | Config A | Config A-prime |
| :--- | :---: | :---: |
| Drop 3 constant channels (`status_4xx`, `status_5xx`, `error_rate`) | 0.5013 | 0.4580 |
| Smooth count features ($w = 3$) | 0.5000 | 0.5000 |
| Non-$z$-normalized distance | 0.5000 | 0.5000 |
| Longer subsequence ($m = 20$) | 0.5000 | 0.4557 |

*Finding: Beyond mathematical degeneracy from zero-variance channels, HTTP request telemetry lacks discriminative temporal subsequence motifs for Euclidean distance joins. Standard tabular baselines on the same data reach ROC-AUC $> 0.90$.*

---

### Table 2: Conformal Threshold Benchmark Summary Across 32 Configurations
Comparison of static split-conformal, label-free autonomous adaptive calibration, and oracle feedback upper bounds:

| Calibration Method | Target $\alpha$ | Mean FPR | Std FPR | Target Met ($\text{FPR} \le \alpha$) | Mean $F_1$ | Mean Recall | Mean Precision |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Benign Quantile** | 0.05 | 0.1237 | 0.1958 | 43.8% (14/32) | **0.4076** | **0.3943** | 0.6136 |
| **Static Split-Conformal** | 0.05 | 0.1199 | 0.1956 | 43.8% (14/32) | 0.4053 | 0.3890 | 0.6155 |
| **Rolling Conformal (LF, $W=60$)** | 0.05 | 0.1203 | 0.1617 | 56.2% (18/32) | 0.3181 | 0.3362 | --- |
| **Adaptive ACI (LF, $\gamma=0.01$)** | 0.05 | 0.1003 | 0.1337 | 53.1% (17/32) | 0.2675 | 0.2606 | --- |
| *Rolling Conformal (Oracle)\** | *0.05* | *0.0306* | *0.0300* | *68.8% (22/32)* | *0.2349* | *0.2093* | *0.4171* |
| *Adaptive ACI (Oracle)\** | *0.05* | *0.0286* | *0.0243* | *71.9% (23/32)* | *0.2345* | *0.2075* | *0.4138* |
| **Static Benign Quantile** | 0.01 | 0.0200 | 0.0391 | 65.6% (21/32) | 0.2507 | 0.2280 | 0.5348 |
| **Static Split-Conformal** | 0.01 | **0.0182** | **0.0387** | **71.9% (23/32)** | 0.2388 | 0.2280 | 0.5354 |
| **Rolling Conformal (LF, $W=60$)** | 0.01 | 0.0570 | 0.1068 | 53.1% (17/32) | 0.1478 | --- | 0.3404 |
| **Adaptive ACI (LF, $\gamma=0.01$)** | 0.01 | 0.0570 | 0.1068 | 53.1% (17/32) | 0.1478 | --- | 0.3404 |
| *Rolling Conformal (Oracle)\** | *0.01* | *0.0106* | *0.0122* | *62.5% (20/32)* | *0.1478* | *---* | *0.3404* |
| *Adaptive ACI (Oracle)\** | *0.01* | *0.0106* | *0.0122* | *62.5% (20/32)* | *0.1478* | *---* | *0.3404* |

*\*Oracle rows denote leaked ground-truth label feedback (`verified_benign_mask = y_test == 0`) shown for reference.*

---

### Table 3: Multi-Seed Testbed Results ($\alpha = 0.05$)
Evaluated across 5 randomized seeds ($42, 43, 44, 45, 46$), each with 25 attack campaigns and 5 benign flash crowds:

| Model | Calibration | ROC-AUC | Test FPR (%) | Flash Crowd FAR (%) | Recall (%) | $F_1$ | Campaign Recall | 95% Clopper-Pearson CI |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | Static Quantile | $0.942 \pm 0.009$ | $26.85 \pm 1.79$ | $100.0 \pm 0.0$ | $98.14 \pm 0.80$ | $0.841 \pm 0.009$ | **100/100** | [0.964, 1.000] |
| | Static Split-Conf | $0.942 \pm 0.009$ | $25.91 \pm 1.70$ | $100.0 \pm 0.0$ | $97.99 \pm 0.79$ | **0.844 $\pm$ 0.009** | **100/100** | [0.964, 1.000] |
| | Rolling LF | $0.942 \pm 0.009$ | $26.50 \pm 2.19$ | $100.0 \pm 0.0$ | $97.99 \pm 1.27$ | $0.842 \pm 0.011$ | **100/100** | [0.964, 1.000] |
| | ACI LF | $0.942 \pm 0.009$ | $7.89 \pm 7.73$ | $26.1 \pm 37.3$ | $74.43 \pm 14.30$ | $0.799 \pm 0.072$ | 88/100 | [0.800, 0.936] |
| | *Rolling (Oracle)\** | $0.942 \pm 0.009$ | $5.28 \pm 1.23$ | $13.3 \pm 7.6$ | $75.56 \pm 9.52$ | $0.825 \pm 0.063$ | 89/100 | [0.812, 0.944] |
| **ARIMA Residual** | Static Quantile | $0.906 \pm 0.006$ | $25.67 \pm 0.63$ | $100.0 \pm 0.0$ | $98.14 \pm 0.80$ | $0.846 \pm 0.006$ | **100/100** | [0.964, 1.000] |
| | Rolling LF | $0.906 \pm 0.006$ | $26.73 \pm 1.77$ | $100.0 \pm 0.0$ | $98.15 \pm 1.05$ | $0.841 \pm 0.008$ | **100/100** | [0.964, 1.000] |
| | ACI LF | $0.906 \pm 0.006$ | $22.86 \pm 0.89$ | $100.0 \pm 0.0$ | $97.68 \pm 0.85$ | **0.858 $\pm$ 0.006** | **100/100** | [0.964, 1.000] |
| **Config A (mSTAMP)** | All Methods | $0.500 \pm 0.000$ | $24.8 \pm 0.0$ | $82.0 \pm 0.8$ | $35.60 \pm 0.70$ | 0.356 | 65/100 | [0.398, 0.492] |
| **Config A-prime** | All Methods | $0.500 \pm 0.000$ | $21.6 \pm 0.0$ | $76.0 \pm 0.0$ | $40.12 \pm 0.60$ | 0.445 | 75/100 | [0.421, 0.516] |

*Key Testbed Finding: Static and autonomous adaptive calibration flag 100% of benign flash crowd windows because volume spikes are out-of-distribution. Training data augmentation with benign flash crowd examples slashes flash crowd false alarms to **$10.16\% \pm 7.78\%$** while preserving attack recall above **$95.98\%$**.*

---

## Datasets & Provenance

The evaluation relies on two public intrusion detection benchmarks and one live microservice testbed:

| Dataset | Telemetry Type | Primary Files / Partitions | Direct Source Links |
| :--- | :--- | :--- | :--- |
| **UNSW-NB15** | Flow records & 10s windows | 10 contiguous blocks of 8,000 flows from Batch 1 (`UNSW-NB15_1.csv`) | [ADFA Official](https://research.unsw.edu.au/projects/unsw-nb15-dataset) · [Kaggle Dataset](https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15) |
| **CSE-CIC-IDS2018** | AWS network telemetry | Friday-16-02-2018 (DoS-Hulk), Thursday-15-02-2018 (DoS-GoldenEye), Wednesday-21-02-2018 (DDoS-HOIC) | [UNB Dataset Hub](https://www.unb.ca/cic/datasets/ids-2018.html) · [AWS Open Data](https://registry.opendata.aws/cse-cic-ids2018/) |
| **Live Testbed** | HTTP request metrics & Prometheus | 10-hour telemetry timeline (600 regular 60s windows), 5 randomized seeds | Containerized in `testbed/` |

### Automated Dataset Download
Use the included utility `scripts/download_datasets.py` to check local availability or download datasets:
```bash
# Verify which datasets are present locally in data/raw/
python scripts/download_datasets.py --verify-only

# Print direct download links and CLI instructions
python scripts/download_datasets.py --instructions

# Download via automated fetchers (Kaggle CLI / AWS S3)
python scripts/download_datasets.py --dataset all
```

---

## Repository Layout

```text
├── configs/                     # Experiment configurations (cross-day, within-day, unsw, testbed)
├── data/                        # Local data directory (raw & processed datasets gitignored)
│   ├── processed/               # Continuous regularized 60s/10s parquet files
│   ├── raw/                     # Raw CSV benchmark downloads
│   └── testbed/                 # Testbed schedules and multi-seed collected telemetry
├── docs/                        # Formal audit reports and claim trace
│   ├── config_definitions.md    # Configuration registry
│   ├── conformal_definitions.md # Formal split-conformal equations
│   ├── findings_v4.md           # Stage 4 audit, verification, and discrepancy report
│   └── number_trace.csv         # Reconciled trace for all 111 claims in the paper
├── experiments/                 # Standalone, runnable experiment pipelines
│   ├── run_stage4_step1_verification.py       # Conformal benchmark verification
│   ├── run_stage4_step2_mp_diagnostics.py     # Matrix Profile degeneracy audit
│   ├── run_stage4_step3_matched_conformal.py  # Matched-FPR bootstrap evaluation
│   └── run_stage4_step4_testbed_verification.py # 5-seed testbed verification
├── results/                     # Experimental outputs and verified metrics
│   ├── figures/                 # High-res publication plots
│   ├── metrics/                 # CSV and JSON tabular metrics
│   ├── v3_1/                    # Cross-day reference sizing & saturation audit
│   └── v4/                      # Canonical Stage 4 verified outputs (Tables 1-3)
├── scripts/                     # Preprocessing, verification, and figure scripts
│   ├── download_datasets.py     # Automated dataset fetcher
│   ├── generate_number_trace.py # Re-computes docs/number_trace.csv
│   └── generate_publication_figures_high_res.py # Generates paper figures
├── src/                         # Core modular library
│   ├── adaptive_threshold.py    # Conformal anomaly calibrators (Split, Rolling, ACI)
│   ├── anomaly_scoring.py       # Distance profile to discord score converters
│   ├── baselines.py             # Isolation Forest & ARIMA(1,0,1) residual baselines
│   ├── causal_ab_scorer.py      # Non-look-ahead streaming mSTAMP AB-join
│   ├── evaluation.py            # Classification & SRE operational metrics
│   ├── kneedle.py               # Kneedle subspace dimension selection
│   ├── matrix_profile.py        # Multidimensional Matrix Profile routines
│   ├── persistence_filter.py    # Temporal persistence filter
│   ├── preprocessing.py         # Leakage-free feature scaling and encoding
│   └── windowing.py             # Continuous datetime grid aggregation
├── testbed/                     # Dockerized microservice testbed
│   ├── app.py                   # Flask target instrumented with Prometheus
│   ├── attacker.py              # Confined attacker container generating 25 campaigns
│   ├── campaign_schedule.py     # Randomized multi-seed schedule generator
│   ├── docker-compose.yml       # Isolated bridge network testbed configuration
│   ├── locustfile.py            # Diurnal sinusoidal benign transaction generator
│   └── run_testbed.py           # Multi-seed testbed orchestration script
└── tests/                       # Complete pytest unit & regression test suite (29 tests)
```

---

## Reproducibility Guide

### 1. Environment Setup
The codebase requires Python 3.12. Install dependencies within a virtual environment:

```bash
# Clone the repository
git clone https://github.com/Warhand40k/Cloud-Security.git
cd Cloud-Security

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Verification & Test Suite
Run the 29 regression unit tests to verify no-label-leakage, time-axis integrity, campaign accounting consistency, causal AB scoring, and conformal prediction guarantees:

```bash
pytest tests/ -v
```

### 3. Data Preprocessing & Grid Regularization
If raw datasets are downloaded into `data/raw/`, run grid regularization to generate continuous gapless 60s windows for CSE-CIC-IDS2018:

```bash
python scripts/generate_v3_1_regular_windows.py
```

### 4. Running Experiments & Audits

#### Replicate Table 2 (Conformal Benchmark Across 32 Configurations):
```bash
python experiments/run_stage4_step1_verification.py
```
Outputs saved to `results/v4/metrics/stage4_conformal_comparison_results.csv` and `stage4_conformal_summary_by_method.csv`.

#### Replicate Table 1 (Matrix Profile Diagnostic Variants):
```bash
python experiments/run_stage4_step2_mp_diagnostics.py
```
Outputs saved to `results/v4/metrics/matrix_profile_diagnostic_variants.csv` and `matrix_profile_score_degeneracy.csv`.

#### Replicate Matched-FPR Comparison with Bootstrap Intervals:
```bash
python experiments/run_stage4_step3_matched_conformal.py
```
Outputs saved to `results/v4/metrics/matched_operating_points_comparison.csv`.

#### Replicate Table 3 (5-Seed Live Testbed Multi-Seed Verification):
```bash
python experiments/run_stage4_step4_testbed_verification.py
```
Outputs saved to `results/v4/metrics/testbed_multiseed_summary.csv` and `testbed_multiseed_evaluation.csv`.

### 5. Regenerating Figures & Claim Trace
Re-generate all high-resolution figures:
```bash
python scripts/generate_publication_figures_high_res.py
```
Re-verify all 111 claims against backing artifacts:
```bash
python scripts/generate_number_trace.py
```

---

## Citation & License

This repository is distributed under the [MIT License](LICENSE).

```bibtex
@article{kumar2026matrix,
  author    = {Kumar, Aalok and Sahrawat, Aditya and Mohanan, Amal},
  title     = {Matrix Profiles for Cloud Network Anomaly Detection: A Reproducibility and Calibration Study},
  journal   = {Department of Computer Science and Engineering, IIIT Dharwad},
  year      = {2026}
}
```
