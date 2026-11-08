# Reproduction and Extension of mSTAMP + Kneedle for Cloud Network Anomaly Detection

> Course: Cloud SRE and Security | Individual project | 21-day target (14-day compressed option)
> Base paper: Al-Mazrawe & Al-Musawi (2025), *Enhancing Cloud Network Security with Innovative Time Series Analysis*, JISA. DOI: 10.5753/jisa.2025.4768
> This document merges the original CloudSentinel plan (structure, discipline, ablation design) with four additions: a second cloud-origin dataset, an EVT threshold variant, an ARIMA-residual baseline, and SRE metrics. Items marked **[verify]** are assumptions to confirm during Day 1-2 data inspection.

---

## 1. Core idea in one paragraph

Reproduce the paper's pipeline (multidimensional Matrix Profile via mSTAMP, with Kneedle dimension selection) as faithfully as the published description allows. Then extend it with a calibrated alert layer (adaptive thresholds and persistence filtering) and evaluate everything under one leakage-free, time-ordered protocol on two datasets, using both classification metrics and SRE-style operational metrics.

**What is a reproduction, what is ours:**

| Element | Origin |
|---|---|
| mSTAMP + Kneedle detection pipeline | Paper (re-implemented; interpretations documented) |
| Adaptive threshold (MAD, EVT) | Our extension |
| Persistence filtering | Our extension |
| ARIMA-residual baseline | Our baseline (from the time-series literature) |
| Isolation Forest baseline | Our baseline |

Never present extensions as part of the paper, and never present the paper's reported scores (99.6% accuracy / 99.8% F1 on UNSW-NB15; 98% / 99.9% on CICIoT2023) as results of this project.

---

## 2. Research questions

- **RQ1.** Can the paper's mSTAMP + Kneedle pipeline be implemented from its published description, and what must be assumed?
- **RQ2.** Do adaptive thresholding (rolling median/MAD, and EVT peaks-over-threshold) and persistence filtering reduce false alarms while preserving detection capability?
- **RQ3.** What do these layers cost in detection delay, runtime, throughput and memory?
- **RQ4.** How does the matrix-profile approach compare with an Isolation Forest and an ARIMA-residual detector under the same protocol?
- **RQ5.** Do the findings hold on a second dataset whose attacks form contiguous episodes (needed for delay and alert-volume metrics)?

---

## 3. Cloud framing for the paper

- Threat: availability and integrity attacks on cloud-hosted services (flooding, DoS/DDoS, scanning).
- Telemetry: network flow records, equivalent to cloud flow logs.
- SRE relevance: alert fatigue, time to detect, false alarms per day, and cost of running the detector.
- Dataset provenance: CSE-CIC-IDS2018 was generated on AWS infrastructure **[verify against the dataset documentation]**. UNSW-NB15 comes from a laboratory testbed; say so plainly and justify it as the paper's own benchmark.
- Limitation to state: both are offline public datasets, not live cloud telemetry. Live cloud-native testing is future work (see Section 13).

---

## 4. Datasets

### 4.1 Dataset 1: UNSW-NB15 (reproduction dataset)
Purpose: compare against the base paper's setup.

Day-1 checks **[verify]**:
1. Download the **original raw CSV files**, not only the commonly distributed train/test partition files, which may lack timestamp fields.
2. Confirm timestamp columns (for example start/last time) exist, parse consistently and give a defensible chronological order.
3. Check duplicate/invalid timestamps, missing values, and the meaning of `label` and `attack_cat`.
4. Confirm the paper's nine features exist: `Sloss, State, Dur, Sbytes, Dbytes, Sttl, Dttl, Dloss, Service`.
5. **Measure how attack records are distributed in time.** If attacks are interleaved with normal traffic rather than arriving as contiguous episodes, then detection delay and persistence effects are hard to interpret on this dataset. Report that finding in the paper rather than hiding it.
6. Record class balance. The method assumes anomalies are rare; if attacks are a large fraction, say so and discuss it.

### 4.2 Dataset 2: CSE-CIC-IDS2018 (operational-metrics dataset)
Purpose: contiguous attack episodes for detection delay, persistence and alerts-per-day; cloud-origin framing.

- Use **one or two days only** (one DoS/DDoS-heavy day plus benign context) to stay within time and disk limits **[verify file sizes and availability]**. Fallback: CIC-IDS2017.
- Convert flow records into fixed time windows (primary 60 s; sensitivity at 10 s) and compute window-level features: unique source IPs, normalized unique destination IPs, packets, flows, bytes, SYN count/rate, source-IP entropy. Choose the exact set after inspecting available columns.
- Ground truth: use the dataset's documented attack schedule and flow labels. Define window label rule (any-attack vs. majority) **on validation data**, document it, and keep it fixed.

### 4.3 Fallback
CICIoT2023 (no timestamps; index-based, as in the paper) only if both datasets above fail. Index order is not chronological time; say so if used.

### 4.4 Data handling rules
- Raw files stay unchanged in `data/raw/`; processed data goes in `data/processed/`.
- Labels are stored separately and never enter the detector.
- Chronological train / validation / test partitions; no shuffling.
- Any data-dependent step (scaling, thresholds, window-size choice) is fitted on train/validation only.
- Record row counts, feature names, missing-value handling, class distribution and split boundaries.
- Explain precisely what each partition is for, since Matrix Profile is unsupervised: train = reference/benign history and scaling state; validation = window size, threshold and persistence selection; test = final evaluation only.

---

## 5. Methods

### 5.1 Original pipeline (Configuration A)
1. Preprocess: encode categoricals, handle missing markers, normalize with train-fitted statistics.
2. Feature subset: the paper's nine features for UNSW-NB15 (FSR/BER selection details are underspecified; use the paper's reported subset and document that choice).
3. mSTAMP (STUMPY multidimensional routines) to compute the multidimensional matrix profile.
4. Kneedle (`kneed`) over per-dimension maximum profile values to select the dimensional subspace.
5. Discord score per subsequence, then conversion to binary predictions.

**Explicitly document as project decisions** (the paper does not fully specify them):
- score-to-label conversion rule,
- alignment of subsequence scores to per-record or per-window labels (and how overlapping subsequences are handled),
- window length `m` and subset size selection (on validation only),
- the exact STUMPY routine used, and how it differs from the paper's description if at all.

### 5.2 Extensions
| Config | Description | Purpose |
|---|---|---|
| A | Original mSTAMP + Kneedle with the base decision rule | Reference |
| B1 | A + rolling median/MAD adaptive threshold | Robust adaptive threshold |
| B2 | A + EVT (peaks-over-threshold) threshold calibrated to a target false-alarm rate | Principled calibration |
| C | Best of B1/B2 (chosen on validation) + persistence filter (k consecutive anomalous observations) | Alert-volume reduction |

- Thresholds are fitted on train/validation scores only; the test set is never used for tuning.
- Persistence values k are swept on validation, with delay and recall reported for each.
- Each stage is independently switchable and runnable.

### 5.3 Baselines
| ID | Method | Notes |
|---|---|---|
| IF | Isolation Forest | Same permissible features, validation-set decision threshold |
| AR | ARIMA-residual detector | One-step forecast per feature (statsmodels), residual z-score or CUSUM, validation-set threshold |
| Optional | A second extra baseline | Only if time remains |

---

## 6. Evaluation protocol

### 6.1 Metrics
- **Classification:** precision, recall, F1, false-positive rate, PR-AUC, confusion matrix. Accuracy is reported for comparability with the paper but never alone.
- **SRE/operational (primarily Dataset 2):** detection delay (time from episode start to first alert), false alarms per day, total alerts before and after persistence filtering.
- **Computational:** execution time, throughput (records or windows per second), peak memory (psutil).
- Define the unit of evaluation explicitly (row vs. window) and use the same unit for every method.

### 6.2 Experimental rules
- Same data, split and evaluation rules for all methods.
- Fix and record random seeds; record Python and package versions and hardware.
- Save predictions, scores, configs and metrics to disk, not just plots.
- Repeat runs where runtime or randomness varies; report spread.
- Report negative and inconclusive results honestly.

### 6.3 Analyses
- Ablation A vs. B1 vs. B2 vs. C.
- Sensitivity to window size `m`, to threshold parameters and to persistence k.
- Kneedle stability (how often the selected subspace changes).
- Error analysis: inspect false positives and false negatives; look at which attack types are missed.
- Comparison with the paper's reported numbers is **contextual only**, because data preparation and splits differ.

---

## 7. Technology stack

Python, pandas, NumPy, SciPy, STUMPY, `kneed`, scikit-learn, statsmodels (ARIMA baseline and EVT fitting via SciPy's generalized Pareto), matplotlib/seaborn, psutil, Jupyter. Streamlit is optional and last.

Environment (Arch Linux):
```bash
mkdir cloud-sentinel && cd cloud-sentinel
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
pip install numpy pandas pyarrow scipy statsmodels scikit-learn
pip install stumpy kneed matplotlib seaborn psutil jupyter
pip freeze > requirements.txt
```
Check the STUMPY documentation for the exact multidimensional routine before describing it as equivalent to the paper's mSTAMP.

---

## 8. Schedule (21 days)

### Week 1: Understand, prepare, reproduce
| Days | Work | Output |
|---|---|---|
| 1-2 | Read the paper's methodology; understand MP, mSTAMP, Kneedle; download UNSW-NB15 raw files; run Section 4.1 checks; set up environment | Dataset inspection report |
| 3-4 | Preprocessing and chronological partitions for UNSW-NB15; download one or two days of CSE-CIC-IDS2018 and inspect schema | Processed Parquet files, split record |
| 5-7 | Implement Configuration A; document score-to-label and alignment decisions; first plots on a small sample | Working prototype |

**Exit criteria:** an executable original pipeline on a small sample, producing scores and aligned predictions.

### Week 2: Extend and evaluate
| Days | Work | Output |
|---|---|---|
| 8-9 | Window features for Dataset 2; MAD threshold (B1); EVT threshold (B2) | Threshold modules, validation comparison |
| 10-11 | Persistence filter (C); sweep k on validation; delay measurement | Delay vs. false-alarm trade-off |
| 12-14 | Isolation Forest and ARIMA baselines; run A/B1/B2/C and baselines on both datasets; runtime and memory measurement | Result tables, saved predictions |

**Exit criteria:** reproducible comparison on held-out data for both datasets, with classification, operational and computational metrics.

### Week 3: Analyse and write
| Days | Work |
|---|---|
| 15-16 | Error analysis, sensitivity analyses, final figures and tables, limitations |
| 17-18 | Write the paper (Section 11); start writing earlier in drafts during Weeks 1-2 |
| 19-21 | Clean code and README, verify the experiments rerun from scratch, prepare slides, rehearse explaining the algorithm and design choices |

**Compressed 14-day option:** drop Dataset 2 aside from one day of data, drop B2 (EVT) or the ARIMA baseline (keep one), skip sensitivity sweeps beyond window size and persistence.

---

## 9. Priority order (cut line)

1. **Must have:** Dataset 1 pipeline, Configuration A, Config B1 and C, Isolation Forest baseline, evaluation harness, paper.
2. **Should have:** Dataset 2 with SRE metrics, B2 (EVT), ARIMA-residual baseline.
3. **Nice to have:** extra sensitivity analyses, live testbed demo, dashboard.

Drop from the bottom up when time runs short. Never drop the leakage controls or the written limitations.

---

## 10. Repository structure

```text
project/
  data/
    raw/                  # unchanged downloads (git-ignored)
    processed/            # parquet tables, split manifests
  notebooks/
    01_dataset_analysis.ipynb
    02_experimental_analysis.ipynb
  src/
    preprocessing.py
    windowing.py          # window/feature extraction for flow data
    feature_selection.py
    matrix_profile.py
    kneedle.py
    anomaly_scoring.py
    adaptive_threshold.py # MAD and EVT variants
    persistence_filter.py
    evaluation.py         # metrics, delay, alerts/day, resource usage
    baselines.py          # Isolation Forest, ARIMA residual
  experiments/
    run_original.py
    run_extended.py
    run_baselines.py
    compare_results.py
  results/
    metrics/
    predictions/
    figures/
  docs/
  requirements.txt
  README.md
```

---

## 11. Paper outline

1. Abstract
2. Introduction: cloud network security, anomaly detection, SRE relevance, contributions
3. Related work: base paper, matrix-profile and network anomaly-detection literature, time-series approaches (ARIMA/forecast residual, exponential smoothing), the Landauer et al. review as a map of the field
4. Background: Matrix Profile, mSTAMP, Kneedle
5. Original methodology: faithful account plus our interpretations of underspecified steps
6. Proposed extension: adaptive thresholds (MAD, EVT) and persistence filtering
7. Experimental setup: datasets, preprocessing, partitions, baselines, parameters, hardware, metrics
8. Results: A vs. B1/B2/C, baselines, both datasets, operational and computational metrics
9. Discussion: what helped, trade-offs (delay vs. false alarms), where methods fail
10. Threats to validity and limitations: dataset realism, interleaved attacks, label alignment, parameter selection, offline evaluation
11. Conclusion and future work: live cloud-native telemetry evaluation
12. References

**Contributions to state:**
1. A documented, leakage-free reproduction of mSTAMP + Kneedle with identified ambiguities.
2. Calibrated alert layers (MAD, EVT thresholds and persistence filtering) with measured trade-offs.
3. An SRE-oriented evaluation (alerts per day, detection delay, resource cost) on two datasets.
4. Comparison against Isolation Forest and ARIMA-residual baselines.

---

## 12. Risks and mitigations

| Risk | Response |
|---|---|
| UNSW-NB15 raw files lack usable timestamps | Verify schema early; use another ordering only if justified and documented; or move Dataset 1 duties to CIC-IDS2018/2017 |
| Attacks interleaved in UNSW-NB15 (delay metric ill-defined) | Report delay and alerts-per-day on Dataset 2 only; discuss the issue in limitations |
| Dataset too large for 16 GB RAM | Subsample by day, process in chunks, profile memory early |
| Kneedle selection unstable | Test sensitivity; report how often selection changes |
| Paper details cannot be inferred | Record each interpretation as a project decision; do not claim exact reproduction |
| Window-to-label alignment unclear | Fix one rule on validation data; use the same unit for every method |
| Adaptive threshold raises missed attacks | Report the trade-off; tune on validation only |
| Persistence filter delays alerts or hides short attacks | Measure delay; sweep several k |
| Time overruns | Follow the cut line in Section 9 |

---

## 13. Future work (not in scope unless time remains)

- **Live cloud-native demo:** a local `kind` Kubernetes cluster running a microservice demo app, benign load generation, an isolated attacker container on the same local network only, and flow-style capture fed to the detector with an automated block rule. This would be the strongest evidence of cloud relevance; treat it as an optional single-scenario demo after the core evaluation is complete.
- Streaming (online) implementation of the matrix profile.
- Additional datasets and attack types.

### Safety note
Any attack traffic must stay between your own containers on an isolated local network. Never target external systems or anything you do not own.

---

## 14. Working principles

- Understand the algorithm before implementing it; reproduce before extending.
- Keep original and extended configurations independently executable.
- Never fabricate or assume results; report negative results.
- Do not tune on the test set; keep labels out of the detector.
- Distinguish what the paper states, what we assumed, and what we contribute.
- Prefer a smaller, rigorous experiment over a larger unreliable one.
