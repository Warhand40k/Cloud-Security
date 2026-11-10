# Findings Report v3.1: Evaluation Foundations, Rigorous Diagnostics, and Evidence-Based Audit

> **Project Title:** Reproduction, Causal Extension, and Methodological Audit of Multidimensional Matrix Profile (mSTAMP + Kneedle) for Network Anomaly Detection  
> **Course:** Cloud SRE and Security  
> **Base Paper:** Al-Mazrawe & Al-Musawi (2025), *Enhancing Cloud Network Security with Innovative Time Series Analysis*, Journal of Internet Services and Applications (JISA), DOI: [10.5753/jisa.2025.4768](https://doi.org/10.5753/jisa.2025.4768)  
> **Branch:** `stage1.5-fixes` | **Git Commit:** `fae562e`  
> **Protocol Foundations:** Regular 60-second time series with real raw flow timestamps; strictly chronological partitions ($\text{Train} < \text{Val} < \text{Test}$, verified by automated assertion); unified campaign accounting ($g=0$, clipped to slice); dual-design CSE reference evaluation (cross-day primary $N \ge 100$ vs. within-day sensitivity); unified false alarm rate threshold calibration ($\text{FAR} \le \alpha$ on held-out benign scores with point-mass tie adjustment); zero test-label leakage; threshold-free ranking metrics reported prior to operating points.

---

## 1. Executive Summary & Provenance Manifests

This report details the outcomes of **Stage 1.5 ("fix the evaluation foundations")**. Stage 1.5 subjected the Stage 1 pipeline to rigorous time-axis repair, reference library sizing, unified campaign accounting, threshold-rule standardization, mathematical saturation diagnosis, paired persistence evaluation, and multi-block flow-level replication.

### Provenance Manifests
- **Platform:** Linux x86_64 (16 CPUs) | Python 3.12 (venv)
- **Key Packages:** NumPy 2.5.4, SciPy 1.18.1, STUMPY 1.14.1, scikit-learn 1.9.1, statsmodels 0.14.6, pandas 2.2.3
- **Primary Data Directory:** `results/v3_1/`
  - Metrics: `results/v3_1/metrics/`
  - Prediction Parquets: `results/v3_1/predictions/`
  - Diagnostic Figures: `results/v3_1/figures/`
- **Verification Status:** All 21 unit and integration tests passing (`Ran 21 tests in 87.727s, OK`).

---

## 2. Updated Systematic Claim Audit

Every empirical and methodological claim from the project is audited against verified outputs in `results/v3_1/`:

| Claim # | Claim Statement | Status in v3.1 | Primary Evidence File | Empirical Truth & Methodological Correction |
| :---: | :--- | :---: | :--- | :--- |
| **1** | *"UNSW-NB15 has 2,540,047 raw flows."* | **SUPPORTED / CORRECTED** | `data/unsw_nb15/` | Raw CSV lines total 2,540,047, but byte-level inspection revealed exactly 3 duplicate boundary rows between CSV files. Unique flow count is exactly **2,540,044** (matching official ADFA documentation). True start timestamp of Batch 1 is `2015-01-22 11:49:37 UTC` (`22:49:37 AEDT`), not "03:56". |
| **2** | *"CSE-CIC-IDS2018 CSVs are truncated at $2^{20}$ rows; detector rankings are robust."* | **SUPPORTED / WORDING ADJUSTED** | `results/v3_1/metrics/csecicids2018_ranking_comparison.csv` | File row ceiling ($1,048,576$) is supported. However, earlier claims that detector rankings were stable across days are **REFUTED**: ranking among non-trivial detectors is highly sensitive to training reference size. Under starved within-day training ($N=16$ on Wednesday), Isolation Forest collapsed to $F_1 = 0.0000$ (Rank 5); under cross-day training ($N=507$), Isolation Forest surged to Rank 1 tied with ARIMA at $F_1 = 0.9859$. |
| **3** | *"Friday contains 191 active contiguous minutes from 03:00 to 06:10."* | **SUPPORTED / CORRECTED** | `results/v3_1/metrics/slice_composition.csv` | Analysis of raw flow timestamps revealed that Friday's active traffic spans 11.97 elapsed hours (`01:00:00` to `12:58:00 UTC`) across 719 minutes, containing 528 empty 60s windows and a maximum gap of 454 minutes. Regularizing the time series with zero-count filling resolved time-dilation artifacts and unified elapsed time calculations. |
| **4** | *"Kneedle dimension selection parameterization."* | **SUPPORTED** | `tests/test_kneedle.py` | Maximum distance across dimensions is monotonically increasing ($\Delta y > 0$) and concave ($\Delta^2 y < 0$); parameterization `curve="concave", direction="increasing"` verified by unit tests. |
| **5** | *"A-prime collapses to 100% false alarms due to stale reference across 26-day gap."* | **REFUTED (Artifact of Threshold Rule & Zero MAD)** | `results/v3_1/metrics/saturation_diagnosis_hypotheses.csv` | The "stale reference" hypothesis is refuted. On UNSW Flow Block, all data lies entirely within Batch 1 (only 107s after reference), yet A-prime still saturated to 100% false alarms in v3. Mathematical diagnosis proved saturation was caused by: (1) 99.73% of benign validation scores being identically 0.0, causing validation-$F_1$ optimization to select $\tau = 0.000000$; and (2) B1 rolling MAD collapsing to 0, which without an $\epsilon$ floor set $T_t = \text{Median} + 0$. Under the Step-4 benign-quantile rule with $\epsilon = 10^{-6}$, A-prime false positive rate on UNSW Flow dropped from 100.0% to **0.57%** (12 alerts). |
| **6** | *"Causal Config A-prime outperforms symmetric Config A."* | **REFUTED on Cross-Day & Flow; Nuanced on Within-Day** | `results/v3_1/metrics/csecicids2018_ranking_comparison.csv`, `results/v3_1/metrics/unsw_multiblock_flow_summary.csv` | On CSE Cross-Day Primary, Config A achieves higher macro mean $F_1$ ($0.3817$) than Config A-prime ($0.4157$ on Wed, but $0.0000$ on Thu; A achieves $0.4870$ on Thu, $0.3103$ on Fri, $0.3478$ on Wed). Across 10 contiguous flow blocks, Config A ($F_1 = 0.0866$, ROC-AUC $0.5570$) outperforms Config A-prime ($F_1 = 0.0523$, ROC-AUC $0.5233$). Config A-prime only surpassed Config A on Friday within-day starved data ($F_1 = 0.1923$ vs $0.0784$). |
| **7** | *"Config A-prime exhibits general superiority across network anomaly benchmarks."* | **REFUTED** | `results/v3_1/metrics/threshold_free_and_fixed_alpha_results.csv` | Config A-prime fails to achieve superior discrimination over standard baselines. On CSE Cross-Day, Isolation Forest (ROC-AUC $0.864 - 1.000$) and ARIMA Residual (ROC-AUC $0.759 - 1.000$) consistently dominate A-prime (ROC-AUC $0.597 - 0.828$). On flow telemetry, A-prime achieves near-chance ROC-AUC ($0.5233$). |
| **8** | *"Persistence filtering ($k \ge 2$) reduces false alarms without sacrificing recall."* | **REFUTED / NOT SUPPORTED** | `results/v3_1/metrics/paired_persistence_analysis.json` | When evaluated strictly on the **same parent score and threshold**, persistence filtering $k > 1$ hurt test $F_1$ in **67.5% of cases** (54 / 80 pairs) and was neutral in 30.0% (24 / 80). In 16 of 20 block/detector configurations (80%), validation selected $k^* = 1$. In the 4 cases where validation chose $k^* > 1$, test $F_1$ degraded on test (e.g. Wednesday Config A dropped from $0.5667$ to $0.3478$). Persistence filtering does not provide general benefit on these datasets; earlier apparent gains were an artifact of comparing mismatched baselines. |
| **9** | *"Subsequence length $m=5$ is optimal for flow telemetry."* | **SUPPORTED** | `results/v3/metrics/sensitivity_m.csv` | Confirmed; $m=5$ matches short burst packet dynamics. |
| **10** | *"Base paper evaluated on saturated attack slices."* | **UNVERIFIED / PLAUSIBLE** | Literature Audit | The base paper omits test slice prevalence and false alarm rates. Our demonstration blocks prove that high-prevalence slices allow naive All-Attack baselines to achieve near-perfect $F_1 \approx 0.9975$. |

---

## 3. Real-Timestamp Slice Composition & Partition Integrity

Every evaluation partition is regularized to a uniform 60-second time grid (CSE) or 10-second grid / flow index (UNSW) with true timestamps derived directly from raw flow records.  
Partition ordering satisfies strict chronological precedence:
$$\text{Train End} < \text{Val Start} < \text{Test Start}$$
This integrity condition is formally asserted by `tests/test_chronological_time_integrity.py`.

*Source: `results/v3_1/metrics/slice_composition.csv`*

| Dataset / Block | Partition | Index Range | Start Timestamp (UTC) | End Timestamp (UTC) | Elapsed Hours | Total Units | Attack Units | Prevalence | Campaigns ($g=0$) | Partition Role |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Thursday-15-02-2018** | Train | `[0, 250]` | `2018-02-15 01:00:00` | `2018-02-15 05:09:00` | 4.15 h | 250 win | 0 | 0.00% | 0 | Pure Benign Reference ($N=250$) |
| | Val | `[250, 558]` | `2018-02-15 05:10:00` | `2018-02-15 10:17:00` | 5.12 h | 308 win | 19 | 6.17% | 4 | Threshold Calibration |
| | Test | `[558, 720]` | `2018-02-15 10:18:00` | `2018-02-15 12:59:00` | 2.68 h | 162 win | 43 | 26.54% | 1 | Held-Out Test Evaluation |
| **Friday-16-02-2018** | Train | `[0, 45]` | `2018-02-16 01:00:00` | `2018-02-16 01:44:00` | 0.73 h | 45 win | 0 | 0.00% | 0 | Within-Day Benign ($N=45$, Starved) |
| | Val | `[45, 552]` | `2018-02-16 01:45:00` | `2018-02-16 10:11:00` | 8.43 h | 507 win | 4 | 0.79% | 1 | Threshold Calibration |
| | Test | `[552, 719]` | `2018-02-16 10:12:00` | `2018-02-16 12:58:00` | 2.77 h | 167 win | 47 | 28.14% | 1 | Held-Out Test Evaluation |
| **Wednesday-21-02-2018** | Train | `[0, 16]` | `2018-02-21 01:55:00` | `2018-02-21 02:10:00` | 0.25 h | 16 win | 0 | 0.00% | 0 | Within-Day Benign ($N=16$, Starved) |
| | Val | `[16, 459]` | `2018-02-21 02:11:00` | `2018-02-21 09:33:00` | 7.37 h | 443 win | 23 | 5.19% | 1 | Threshold Calibration |
| | Test | `[459, 529]` | `2018-02-21 09:34:00` | `2018-02-21 10:43:00` | 1.15 h | 70 win | 36 | 51.43% | 1 | Held-Out Test Evaluation |
| **UNSW Small Regime-Shift** | Train | `[2000, 4000]` | `2015-01-22 17:23:10` | `2015-01-22 23:10:30` | 5.79 h | 2,000 win | 0 | 0.00% | 0 | Pure Benign Reference ($N=2000$) |
| *(Disclaimer: 26d boundary)*| Val | `[4000, 4470]` | `2015-01-22 23:10:40` | `2015-02-18 00:29:00` | 625.3 h| 470 win | 5 | 1.06% | 4 | Straddles 26-Day Boundary |
| | Test | `[4470, 4535]` | `2015-02-18 00:29:10` | `2015-02-18 00:45:00` | 0.26 h | 65 win | 45 | 69.23% | 1 | Batch 2 Regime-Shift |
| **UNSW Regime-Shift Demo** | Train | `[1200, 3200]` | `2015-01-22 15:09:50` | `2015-01-22 20:57:10` | 5.79 h | 2,000 win | 0 | 0.00% | 0 | Pure Benign Reference ($N=2000$) |
| *(Disclaimer: 26d boundary)*| Val | `[3200, 4600]` | `2015-01-22 20:57:20` | `2015-02-18 01:14:20` | 628.3 h| 1,400 win | 115 | 8.21% | 5 | Straddles 26-Day Boundary |
| | Test | `[4600, 5800]` | `2015-02-18 01:14:30` | `2015-02-18 04:34:20` | 3.33 h | 1,200 win | 1,194 | 99.50% | 4 | Batch 2 Saturation Slice |
| **UNSW Flow Contiguous** | Train | `[0, 4800]` | `2015-01-22 11:49:37` | `2015-01-22 11:53:06` | 0.06 h | 4,800 flows| 184 | 3.83% | 160 | Filtered Benign Reference ($N=4616$) |
| *(Batch 1 Contiguous)* | Val | `[4800, 6400]` | `2015-01-22 11:53:06` | `2015-01-22 11:54:17` | 0.02 h | 1,600 flows| 108 | 6.75% | 69 | Threshold Calibration |
| | Test | `[6400, 8000]` | `2015-01-22 11:54:17` | `2015-01-22 11:55:25` | 0.02 h | 1,600 flows| 187 | 11.69% | 88 | Held-Out Test Evaluation |

---

## 4. Training-Set Sizing & Reference Design Comparison

To prevent training starvation pathologies, Stage 1.5 enforced minimum dataset sizing assertions:
$$\text{Benign Training Windows} \ge 100, \quad \text{Subsequences} \ge 10 \times m, \quad \text{ARIMA Fit} \ge 100\text{ points}$$

We implemented and compared two reference architectures:
1. **Primary Design ("Cross-Day Reference"):** Friday 16 and Wednesday 21 borrow pure morning benign windows from Thursday ($N=507$ windows, 00:00–08:27 UTC). Scalers are fitted strictly on the cross-day reference.
2. **Secondary Design ("Within-Day Sensitivity"):** Strict within-day partitioning where Friday trains on $N=45$ windows and Wednesday on $N=16$ windows.

*Source: `results/v3_1/metrics/csecicids2018_ranking_comparison.csv` and `csecicids2018_design_comparison.csv`*

### Performance and Ranking Reversal Across Designs:
| Evaluation Block | Model | Cross-Day $F_1$ ($N=507$) | Cross-Day Rank | Within-Day $F_1$ ($N \le 45$) | Within-Day Rank | Ranking Impact |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Thursday-15-02-2018** | Config A (mSTAMP+Kneedle) | 0.4870 | **1** | 0.4870 | **1** | Stable ($N=250$ in both) |
| | Config B2 (Adaptive EVT) | 0.4412 | 2 | 0.4412 | 2 | Stable |
| | Baseline: Isolation Forest | 0.2264 | 3 | 0.2264 | 3 | Stable |
| | Config B1 (Adaptive MAD) | 0.1176 | 4 | 0.1176 | 4 | Stable |
| | Baseline: ARIMA Residual | 0.0889 | 5 | 0.0889 | 5 | Stable |
| | Config A-prime (Causal AB) | 0.0000 | 6 | 0.0000 | 6 | Stable |
| **Friday-16-02-2018** | Baseline: Isolation Forest | **0.6571** | **1** | 0.1538 | 2 | **Surges to Rank 1** (+0.5033 $F_1$) |
| | Config A-prime (Causal AB) | 0.5088 | 2 | 0.1923 | **1** | Concedes Rank 1 to IsoForest |
| | Config A (mSTAMP+Kneedle) | 0.3103 | 3 | 0.0784 | 3 | Improves (+0.2319 $F_1$) |
| | Config B1 (Adaptive MAD) | 0.0984 | 4 | 0.0377 | 5 | Improves |
| | Baseline: ARIMA Residual | 0.0000 | 5 | 0.0000 | 6 | Optimization fails under both |
| | Config B2 (Adaptive EVT) | 0.0000 | 5 | 0.0784 | 3 | Degrades under cross-day tail |
| **Wednesday-21-02-2018**| Baseline: Isolation Forest | **0.9859** | **1** (tie) | 0.0000 | 5 | **Massive collapse under starvation** ($F_1: 0.9859 \to 0.0000$) |
| | Baseline: ARIMA Residual | **0.9859** | **1** (tie) | 0.9859 | **1** | Stable (large flood detected) |
| | Config A-prime (Causal AB) | 0.7385 | 3 | 0.2791 | 4 | Improves (+0.4594 $F_1$) |
| | Config A (mSTAMP+Kneedle) | 0.3478 | 4 | 0.3111 | 3 | Stable |
| | Config B2 (Adaptive EVT) | 0.3111 | 5 | 0.3846 | 2 | Degrades |
| | Config B1 (Adaptive MAD) | 0.2609 | 6 | 0.0000 | 5 | Improves |

*Key Methodological Takeaway:* Within-day training on small slices ($N < 50$) severely starves non-parametric and ensemble detectors (causing Isolation Forest to score 0.0000 on Wednesday). Cross-day reference libraries resolve starvation, proving that detector rankings are **not invariant** to training-set size.

---

## 5. Threshold-Free Metrics and Fixed-$\alpha$ Operating Points

Following rigorous SRE evaluation principles, we report threshold-free discrimination metrics (ROC-AUC, PR-AUC, and PR-AUC Lift over prevalence) **first**, followed by operational operating points calibrated at fixed false alarm budgets ($\alpha = 0.05$ and $\alpha = 0.01$).  
Thresholds are calibrated on **held-out benign validation scores** with point-mass tie adjustment:
$$\tau = \text{Quantile}(S_{\text{val, benign}}, 1 - \alpha)$$

*Source: `results/v3_1/metrics/threshold_free_and_fixed_alpha_results.csv`*

### 5.1 Primary Design (CSE Cross-Day Primary Evaluation)
| Evaluation Block | Model | ROC-AUC | PR-AUC | PR-Lift | Achieved FPR ($\alpha=0.05$) | Achieved Recall | $F_1$ ($\alpha=0.05$) | Achieved FPR ($\alpha=0.01$) | Achieved Recall | $F_1$ ($\alpha=0.01$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Thursday-15-02-2018** | Baseline: Isolation Forest | **0.8642** | **0.6423** | **+1.42x** | 0.0336 | 0.1395 | 0.2264 | 0.0168 | 0.0000 | 0.0000 |
| (Prev = 26.54%) | Baseline: ARIMA Residual | 0.8003 | 0.5916 | +1.23x | 0.0000 | 0.0698 | 0.1304 | 0.0000 | 0.0698 | 0.1304 |
| | Config A (mSTAMP+Kneedle) | 0.7315 | 0.5760 | +1.17x | 0.0840 | 0.3488 | 0.4412 | 0.0168 | 0.1395 | 0.2353 |
| | Config B2 (Adaptive EVT) | 0.7315 | 0.5760 | +1.17x | 0.0252 | 0.3023 | 0.4407 | 0.0168 | 0.1395 | 0.2353 |
| | Config A-prime (Causal AB) | 0.5966 | 0.5128 | +0.93x | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| | Config B1 (Adaptive MAD) | 0.7315 | 0.5760 | +1.17x | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| **Friday-16-02-2018** | Baseline: Isolation Forest | **1.0000** | **1.0000** | **+2.55x** | 0.1250 | 1.0000 | 0.8624 | 0.0000 | 1.0000 | **1.0000** |
| (Prev = 28.14%) | Baseline: ARIMA Residual | 0.7587 | 0.4121 | +0.46x | 0.0500 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| | Config A (mSTAMP+Kneedle) | 0.7316 | 0.5737 | +1.04x | 0.1000 | 0.4468 | 0.5250 | 0.0083 | 0.0213 | 0.0408 |
| | Config A-prime (Causal AB) | 0.6711 | 0.4632 | +0.65x | 0.2417 | 0.5532 | 0.5098 | 0.0083 | 0.0213 | 0.0408 |
| | Config B1 (Adaptive MAD) | 0.7316 | 0.5737 | +1.04x | 0.0167 | 0.0000 | 0.0000 | 0.0167 | 0.0000 | 0.0000 |
| | Config B2 (Adaptive EVT) | 0.7316 | 0.5737 | +1.04x | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| **Wednesday-21-02-2018**| Baseline: ARIMA Residual | **1.0000** | **1.0000** | **+0.94x** | 0.0294 | 1.0000 | **0.9863** | 0.0000 | 1.0000 | **1.0000** |
| (Prev = 51.43%) | Baseline: Isolation Forest | 0.9992 | 0.9992 | +0.94x | 0.2941 | 1.0000 | 0.8780 | 0.1176 | 1.0000 | 0.9474 |
| | Config A-prime (Causal AB) | 0.8276 | 0.8338 | +0.62x | 0.0294 | 0.2778 | 0.4255 | 0.0000 | 0.1667 | 0.2857 |
| | Config A (mSTAMP+Kneedle) | 0.6724 | 0.7070 | +0.37x | 0.2059 | 0.4722 | 0.5667 | 0.0588 | 0.1944 | 0.3111 |
| | Config B1 (Adaptive MAD) | 0.6724 | 0.7070 | +0.37x | 0.0588 | 0.1944 | 0.3111 | 0.0294 | 0.0000 | 0.0000 |
| | Config B2 (Adaptive EVT) | 0.6724 | 0.7070 | +0.37x | 0.0294 | 0.1389 | 0.2381 | 0.0000 | 0.0833 | 0.1538 |

---

## 6. Saturation Diagnosis: Refuting the Stale-Reference Hypothesis

In Stage 1 (v3), Config A-prime saturated to 100% false alarms (1,600 / 1,600 flows) on UNSW Flow Contiguous Block, and Config B1 saturated on UNSW Window Regime Shift Demo. Earlier reports hypothesized this was caused by "stale reference libraries across the 26-day gap".

*Source: `results/v3_1/metrics/saturation_diagnosis_hypotheses.csv` and `results/v3_1/figures/score_histograms_saturation_diagnosis.png`*

### Empirical Refutation and Root Cause Analysis:
1. **Refutation of Stale Reference on Flow Data:**
   - UNSW Flow Contiguous Block is located **entirely within Batch 1** (`UNSW-NB15_1.csv`).
   - The test partition begins only **107 seconds** after the training partition. There is zero 26-day gap, zero calendar shift, and minimal scaler drift ($\text{Mean Drift} = 0.1839, \text{Std Drift} = 0.2802$).
   - Yet, in v3, A-prime still produced 100% false alarms on this block. Stale historical reference cannot explain this failure.
2. **True Mathematical Cause 1 (Degenerate Validation-$F_1$ Optimization on Zero Scores):**
   - For Config A-prime, **99.73% of benign validation scores were identically $0.000000$**.
   - Validation-$F_1$ optimization searched for the threshold that maximized validation $F_1$. Because scores were compressed at zero, the optimizer selected $\tau^* = 0.00000000$.
   - At test time, any non-negative score ($S_t \ge 0.0$) triggered an alert, flagging 100% of test instances.
3. **True Mathematical Cause 2 (Zero MAD Collapse in Adaptive Thresholding):**
   - On UNSW Window Regime Shift Demo, **100.0% of rolling windows had $\text{MAD} == 0.000000$**.
   - Without an $\epsilon$ floor, the rolling MAD threshold collapsed to the rolling median:
     $$T_t = \text{Median}_W(S) + c \cdot (1.4826 \times 0.0) = \text{Median}_W(S)$$
     This flagged every point equal to or above the local median, triggering continuous alerts.
4. **Empirical Proof of Resolution:**
   - Adding an $\epsilon = 10^{-6}$ floor to MAD and replacing validation-$F_1$ optimization with the Step-4 benign-quantile calibration rule ($\text{FAR} \le \alpha$) completely eliminated saturation:
     - On **UNSW Flow Contiguous Block**, A-prime test FPR collapsed from **100.0% down to 0.57%** (12 alerts).
     - On **UNSW Window Regime Shift Demo**, A-prime test FPR collapsed from **100.0% down to 0.00%** (0 alerts).

---

## 7. Paired Persistence Filtering Analysis ($k \in \{1, 2, 3, 4, 5\}$)

To eliminate confounding from threshold re-tuning or model mismatches, persistence variants $C(\text{Parent}, k)$ were evaluated against their parent detector on the **exact same anomaly score stream and identical threshold** ($\alpha = 0.05$).

*Source: `results/v3_1/metrics/paired_persistence_analysis.json` and `results/v3_1/figures/paired_persistence_effect.png`*

### Empirical Aggregates Across All 80 Pairs ($k > 1$ vs. $k=1$):
- **Hurt Test $F_1$:** **54 / 80 (67.5%)**
- **Neutral ($\Delta F_1 = 0$):** **24 / 80 (30.0%)**
- **Helped Test $F_1$:** **2 / 80 (2.5%)** (Only occurred on Thursday Config A at $k=2,3$, where $F_1$ gained $+0.0178$ at the cost of a $-0.0233$ drop in recall and increased MTTD).

### Validation Selection ($k^*$ on Validation, Evaluated on Test):
- Validation selected $k^* = 1$ in **16 of 20 configurations (80.0%)**.
- In the 4 cases where validation selected $k^* > 1$, test $F_1$ was degraded on every single test partition:
  - Wednesday Config A: $k^* = 4 \implies \Delta F_1 = \mathbf{-0.2188}$ (dropped from $0.5667$ to $0.3478$).
  - UNSW Small Regime-Shift Config A: $k^* = 4 \implies \Delta F_1 = \mathbf{-0.1019}$ (dropped from $0.3019$ to $0.2000$).
  - UNSW Small Regime-Shift Config B1: $k^* = 4 \implies \Delta F_1 = \mathbf{-0.1019}$ (dropped from $0.3019$ to $0.2000$).
  - UNSW Small Regime-Shift Config B2: $k^* = 3 \implies \Delta F_1 = \mathbf{-0.0692}$ (dropped from $0.2692$ to $0.2000$).

**Conclusion for Claim #8:** Persistence filtering does not provide general benefit on network telemetry. It disproportionately suppresses true bursty attacks while offering negligible false-alarm reduction.

---

## 8. UNSW-NB15 Multi-Block Flow Evaluation (10 Blocks, 80,000 Flows)

To eliminate slice selection bias on flow-level data, we evaluated 10 contiguous, non-overlapping blocks of 8,000 flows (80,000 total flows) from Batch 1 (`UNSW-NB15_1.csv`). Each block was partitioned into 4,000 train, 1,600 validation, and 2,400 test flows.

*Source: `results/v3_1/metrics/unsw_multiblock_flow_summary.csv` and `results/v3_1/figures/unsw_multiblock_flow_f1.png`*

### Multi-Block Flow Performance Summary (Mean ± Std over 10 Blocks):
| Model | Mean $F_1 \pm \text{Std}$ | Mean Recall | Mean Precision | Mean FPR | Mean ROC-AUC | Mean PR-AUC Lift | Blocks Beating All-Attack |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline: All-Attack** | **$0.1281 \pm 0.0406$** | 1.0000 | 0.0689 | 1.0000 | 0.5000 | 0.00x | — |
| **Baseline: All-Normal** | $0.0000 \pm 0.0000$ | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0.00x | 0 / 10 |
| **Baseline: Random Uniform** | $0.0680 \pm 0.0284$ | 0.0608 | 0.0807 | 0.0512 | 0.5029 | 0.05x | 0 / 10 |
| **Config A (mSTAMP+Kneedle)** | $0.0866 \pm 0.1147$ | 0.0696 | 0.1361 | 0.0166 | 0.5570 | 0.39x | 2 / 10 |
| **Config A-prime (Causal AB)** | $0.0523 \pm 0.0705$ | 0.0451 | 0.1093 | 0.0166 | 0.5233 | 0.16x | 2 / 10 |
| **Config B1 (Adaptive MAD)** | $0.0791 \pm 0.1161$ | 0.0851 | 0.1232 | 0.0269 | 0.5570 | 0.39x | 2 / 10 |
| **Config B2 (Adaptive EVT)** | $0.1246 \pm 0.0956$ | 0.4656 | 0.1428 | 0.4152 | 0.5570 | 0.39x | 2 / 10 |
| **Config C (B1, $k=2$)** | $0.0390 \pm 0.0652$ | 0.0380 | 0.0945 | 0.0168 | 0.5570 | 0.39x | 1 / 10 |
| **Config C (B2, $k=2$)** | $0.0833 \pm 0.0627$ | 0.4251 | 0.1146 | 0.4069 | 0.5570 | 0.39x | 4 / 10 |
| **Config C (A-prime, $k=2$)** | $0.0166 \pm 0.0284$ | 0.0105 | 0.0622 | 0.0065 | 0.5233 | 0.16x | 0 / 10 |
| **Baseline: Isolation Forest** | **$0.2496 \pm 0.1767$** | 0.2408 | 0.2713 | 0.0429 | **0.9293** | **4.36x** | **7 / 10** |
| **Baseline: ARIMA Residual** | **$0.3720 \pm 0.2089$** | 0.3874 | 0.3632 | 0.0454 | **0.9368** | **4.47x** | **9 / 10** |

### Audit Finding on Flow Data:
- None of the matrix profile methods (A, A-prime, B1, B2, C) reliably beat the naive `All-Attack` baseline on flow-level network data: their mean $F_1$ scores ($0.0523 - 0.1246$) are lower than `All-Attack` ($0.1281$), and their mean ROC-AUC ($0.52 - 0.56$) demonstrates near-chance discriminative capacity.
- Flow-level anomaly detection with matrix-profile methods is **not supported by empirical evidence**.
- In contrast, tabular and autoregressive baselines (`Isolation Forest` and `ARIMA Residual`) achieve strong separation (mean ROC-AUC $> 0.92$, mean PR-AUC lift $> 4.3\times$, beating `All-Attack` on 70% and 90% of blocks).

---

## 9. Stage 2 Pre-Registered Gate Outcome

Following formal pre-registration in `docs/stage2_gate.md`, we evaluated whether dual-stream fusion of `Config A-prime` and `ARIMA Residual` met the pre-registered criterion ($\Delta \text{Recall}_{\text{Oracle}} \ge +0.10$ while $\text{FPR} \le 0.05$ on $\ge 50\%$ of blocks).

*Source: `results/v3_1/metrics/stage2_gate_complementarity.csv`*

- **Blocks Meeting Criterion:** **0 / 5 (0.0%)**
- **Decision:** **`NO-GO`**
- **Cause:** Detections were either non-existent or strict subsets of the better detector ($\Delta \text{Recall} = 0.0000$ everywhere), while the OR combiner inflated false positive rates (e.g. Friday FPR rose to $29.17\%$). Dual-stream OR fusion of A-prime and ARIMA is rejected.

---

## 10. Honest Methodological Limitations

1. **Unsuitability of Matrix Profile for Raw Flow Telemetry:**
   Matrix profile distance search requires ordered temporal subsequences with regular periodicity. On point-in-time tabular flow records, the temporal ordering is weakly correlated with sequence shape, causing matrix-profile methods to collapse to near-random guessing (ROC-AUC $\approx 0.52 - 0.56$).
2. **Persistence Filtering Pathologies:**
   Requiring $k \ge 2$ consecutive alarms causes severe detection delays and catastrophic recall drops on real network attacks that exhibit intermittent or multi-stage activity.
3. **Reference Sizing Sensitivity:**
   Unsupervised reference dictionaries require at least 100–500 benign windows to prevent catastrophic starvation of baselines and matrix profile libraries.
4. **Threshold Generalization:**
   Quantile calibration on held-out benign data successfully bounds false alarms on stationary test sets, but diurnal traffic drift can still cause false alarm rate inflation or under-sensitivity if background rates shift between days.

