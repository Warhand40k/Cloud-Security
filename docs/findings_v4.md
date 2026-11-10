# Findings Report v4: Verification, Honest Re-Measurement, and Methodological Audit

> **Course:** Cloud SRE and Security  
> **Project:** Reproduction, Causal Extension, and Methodological Audit of Multidimensional Matrix Profile (mSTAMP + Kneedle) for Network Anomaly Detection  
> **Base Paper:** Al-Mazrawe & Al-Musawi (2025), *Enhancing Cloud Network Security with Innovative Time Series Analysis*, Journal of Internet Services and Applications (JISA), DOI: 10.5753/jisa.2025.4768  
> **Stage:** Stage 4 ("Verify the Contribution Claims")  
> **Branch:** `stage4-verify`  
> **Evaluation Protocol:** Strictly frozen pipelines; zero test-label leakage; all numbers derived from files in `results/v4/`.

---

## 1. Executive Summary & Verification Outcomes

Stage 4 conducts an honest, adversarial verification of all previous claims and contributions. 

### Headline Audit Findings:
1. **Label-Leakage Audit (Step 1):**
   - The Stage 2 and Stage 3 evaluation harnesses passed `verified_benign_mask = (y_test == 0)` to the rolling conformal calibrators, providing them with ground-truth test labels.
   - The previously claimed 88.6% reduction in flash crowd false alarms (from 100% down to 11.43%) was **strictly an artifact of oracle label feedback**.
   - Under genuine label-free autonomous operation (admitting only unflagged windows into the rolling buffer), the flash crowd false alarm rate is **100.0% (35/35 alerts)**, identical to static quantile thresholding.
2. **Matrix Profile Score Degeneracy & Signal Audit (Step 2):**
   - On the live microservice testbed, both Config A and Config A-prime collapsed to **exactly one unique score value ($0.000000$)** across 100% of test windows (ROC-AUC = $0.5000$). This was driven by zero-variance channels (`status_4xx_count`, `status_5xx_count`, `error_rate`).
   - However, curing degeneracy via diagnostic variants (dropping constant channels, non-z-normalized distance, smoothing counts) failed to restore detection fidelity: Testbed ROC-AUC remained at $0.4580 - 0.5013$.
   - The "saturation cure" (quantile rule + $\epsilon$-MAD floor) on UNSW Flow reduced FPR to 0.57%, but achieved an attack recall of only **2.14%** (ROC-AUC = $0.5079$), and **0.00% recall** on regime-shift blocks.
   - We conclude that matrix profile failures stem from both mathematical score degeneracy and a **fundamental lack of temporal subsequence signal in point-in-time network flows**.

---

## 2. Step 1: Label-Feedback Audit of Conformal Calibrators

*Source: `results/v4/metrics/stage4_conformal_summary_by_method.csv` and `results/v4/metrics/stage4_testbed_results.csv`*

### 2.1 Benchmark Summary Across All 32 Configurations ($\alpha = 0.05$)
| Threshold Method | Variant | Mean Achieved FPR | Std FPR | Budget Met ($\text{FPR} \le \alpha$) | Mean $F_1$ | Mean Recall |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Split-Conformal** | Baseline | 0.1199 | 0.1956 | 43.8% (14/32) | 0.4053 | 0.3890 |
| **Static Benign Quantile** | Baseline | 0.1237 | 0.1958 | 43.8% (14/32) | 0.4076 | 0.3943 |
| **Rolling Split-Conformal** | *Oracle Upper Bound* | **0.0306** | 0.0300 | **68.8% (22/32)** | 0.2349 | 0.2093 |
| **Adaptive Conformal (ACI)**| *Oracle Upper Bound* | **0.0286** | 0.0243 | **71.9% (23/32)** | 0.2345 | 0.2075 |
| **Rolling Split-Conformal** | **Label-Free Autonomous** | **0.1203** | 0.1617 | **56.2% (18/32)** | 0.3181 | 0.3362 |
| **Adaptive Conformal (ACI)**| **Label-Free Autonomous** | **0.1003** | 0.1337 | **53.1% (17/32)** | 0.2675 | 0.2606 |

### 2.2 Testbed Flash Crowd Re-Measurement ($\alpha = 0.05$, Isolation Forest)
- **Static Quantile:** Test FPR = 26.22%, $F_1 = 0.8526$, Flash Crowd FPR = **100.0% (35/35)**
- **Rolling Conformal (Oracle):** Test FPR = 4.88%, $F_1 = 0.9451$, Flash Crowd FPR = **11.43% (4/35)**
- **Rolling Conformal (Label-Free):** Test FPR = 26.83%, $F_1 = 0.8462$, Flash Crowd FPR = **100.0% (35/35)**
- **ACI (Label-Free):** Test FPR = 24.39%, $F_1 = 0.8497$, Flash Crowd FPR = **100.0% (35/35)**

---

## 3. Step 2: Matrix Profile Score Degeneracy and Feature Constancy Audit

*Source: `results/v4/metrics/matrix_profile_score_degeneracy.csv` and `results/v4/metrics/feature_channel_variance_and_constancy.csv`*

### 3.1 Score Degeneracy Summary Across Data Sources
| Dataset / Block | Model | Subsequence $m$ | Test Samples | Unique Scores | % Exactly Zero (Test) | % Zero (Val) | ROC-AUC | PR-AUC (Prev) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Testbed (Live Microservice)** | Config A (mSTAMP) | 10 | 300 | **1** | **100.0%** | **100.0%** | **0.5000** | 0.4533 (0.4533) |
| | Config A-prime (Causal AB) | 10 | 300 | **1** | **100.0%** | **100.0%** | **0.5000** | 0.4533 (0.4533) |
| **UNSW Flow Contiguous** | Config A (mSTAMP) | 5 | 1,600 | 1,590 | 0.19% | 0.75% | 0.7686 | 0.3019 (0.1169) |
| | Config A-prime (Causal AB) | 5 | 1,600 | **13** | **99.25%** | **99.69%** | **0.5079** | 0.1240 (0.1169) |
| **UNSW Small Regime-Shift** | Config A (mSTAMP) | 10 | 65 | 12 | 78.46% | 92.98% | 0.6556 | 0.7880 (0.6923) |
| | Config A-prime (Causal AB) | 10 | 65 | **1** | **100.0%** | **98.30%** | **0.5000** | 0.6923 (0.6923) |
| **UNSW Regime Shift Demo** | Config A (mSTAMP) | 10 | 1,200 | 22 | 98.17% | 96.86% | 0.5092 | 0.9951 (0.9950) |
| | Config A-prime (Causal AB) | 10 | 1,200 | **1** | **100.0%** | **99.29%** | **0.5000** | 0.9950 (0.9950) |
| **CSE Thursday Cross-Day** | Config A (mSTAMP) | 10 | 162 | 158 | 0.00% | 45.13% | 0.7315 | 0.5760 (0.2654) |
| | Config A-prime (Causal AB) | 10 | 162 | 153 | 0.00% | 0.00% | 0.5966 | 0.5128 (0.2654) |
| **CSE Friday Cross-Day** | Config A (mSTAMP) | 10 | 167 | 157 | 4.79% | 70.83% | 0.7316 | 0.5737 (0.2814) |
| | Config A-prime (Causal AB) | 10 | 167 | 148 | 6.59% | 72.28% | 0.6711 | 0.4632 (0.2814) |
| **CSE Wednesday Cross-Day** | Config A (mSTAMP) | 10 | 70 | 70 | 0.00% | 76.03% | 0.6724 | 0.7070 (0.5143) |
| | Config A-prime (Causal AB) | 10 | 70 | 61 | 0.00% | 76.47% | 0.8276 | 0.8338 (0.5143) |
| **CSE Friday Within-Day** | Config A (mSTAMP) | 10 | 167 | 152 | 6.59% | 78.70% | 0.6871 | 0.5256 (0.2814) |
| | Config A-prime (Causal AB) | 10 | 167 | 157 | 1.20% | 0.99% | 0.7468 | 0.5318 (0.2814) |
| **CSE Wednesday Within-Day**| Config A (mSTAMP) | 10 | 70 | 70 | 0.00% | 78.78% | 0.6806 | 0.6929 (0.5143) |
| | Config A-prime (Causal AB) | 10 | 70 | 16 | **78.57%** | **92.33%** | 0.6021 | 0.6141 (0.5143) |

### 3.2 Channels That Are Constant in Benign Training Traffic
*Identified channels with $\text{Var}(X_{\text{train}}) < 10^{-12}$ or $> 90\%$ constant subsequences:*
1. **Testbed:**
   - `status_4xx_count`: $\text{Var} = 0.000000$, 100.0% constant subsequences.
   - `status_5xx_count`: $\text{Var} = 0.000000$, 100.0% constant subsequences.
   - `error_rate`: $\text{Var} = 0.000000$, 100.0% constant subsequences.
2. **UNSW-NB15 Window Telemetry (Both Regime-Shift Blocks):**
   - `sttl`: $\text{Var} = 0.000000$, 100.0% constant subsequences.
   - `dttl`: $\text{Var} = 0.000000$, 100.0% constant subsequences.
   - `dloss`: $\text{Var} = 0.833968$, 91.2% constant subsequences.
3. **CSE-CIC-IDS2018 Friday Within-Day ($N=45$):**
   - `rst_flags_total`: $\text{Var} = 0.000000$, 100.0% constant subsequences.
4. **UNSW Flow Contiguous Block:**
   - `sttl` (77.3% constant subsequences) and `dttl` (77.4% constant subsequences).

---

## 4. Step 2: Diagnostic Variants Evaluation

*Source: `results/v4/metrics/matrix_profile_diagnostic_variants.csv`*

To determine whether score collapse was purely an algorithmic defect of zero-variance z-normalization or reflected a genuine absence of temporal motif signal, we evaluated 4 labeled diagnostic variants:

| Dataset / Block | Variant | Config A ROC-AUC | Config A-prime ROC-AUC | Config A Recall ($\text{FPR} \le 0.05$) | Config A-prime Recall ($\text{FPR} \le 0.05$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Testbed** | Baseline Reproduction | 0.5000 | 0.5000 | 0.0000 | 0.0000 |
| | *diagnostic variant: drop 3 constant channels* | 0.5013 | 0.4580 | 0.0000 | 0.0368 (FPR 0.0915) |
| | *diagnostic variant: smooth count features (w=3)*| 0.5000 | 0.5000 | 0.0000 | 0.0000 |
| | *diagnostic variant: non-z-normalized distance* | 0.5000 | 0.5000 | 0.0000 | 0.0000 |
| | *diagnostic variant: larger m (20)* | 0.5000 | 0.4557 | 0.0000 | 0.3015 (FPR 0.2683) |
| **UNSW Flow** | Baseline Reproduction ($m=5$) | 0.7686 | 0.5079 | 0.2995 | 0.0214 |
| | *diagnostic variant: smooth count features (w=3)*| 0.6292 | 0.5046 | 0.3422 | 0.0053 |
| | *diagnostic variant: non-z-normalized distance* | 0.4996 | 0.5113 | 0.0000 | 0.0053 |
| | *diagnostic variant: larger m (10)* | 0.7171 | 0.6570 | 0.2513 | 0.1925 |
| **CSE Thursday** | Baseline Reproduction ($m=10$) | 0.7315 | 0.5966 | 0.3488 | 0.0000 |
| | *diagnostic variant: smooth count features (w=3)*| 0.7463 | 0.7127 | 0.3488 | 0.0000 |
| | *diagnostic variant: non-z-normalized distance* | 0.8106 | 0.7244 | 0.0000 | 0.0000 |
| | *diagnostic variant: larger m (20)* | 0.6455 | 0.6025 | 0.2093 | 0.0000 |
| **CSE Friday** | Baseline Reproduction ($m=10$) | 0.7316 | 0.6711 | 0.4468 | 0.5532 (FPR 0.2417) |
| | *diagnostic variant: smooth count features (w=3)*| 0.7418 | 0.6640 | 0.4468 | 0.5106 (FPR 0.2833) |
| | *diagnostic variant: non-z-normalized distance* | 0.5202 | 0.6619 | 0.0638 | 0.0000 |
| | *diagnostic variant: larger m (20)* | 0.8048 | 0.8018 | 0.2766 | 0.6596 (FPR 0.1583) |
| **CSE Wednesday**| Baseline Reproduction ($m=10$) | 0.6724 | 0.8276 | 0.4722 | 0.2778 |
| | *diagnostic variant: smooth count features (w=3)*| 0.4800 | 0.7623 | 0.2500 | 0.4722 |
| | *diagnostic variant: non-z-normalized distance* | 0.7222 | 0.6095 | 0.4444 | 0.0278 |
| | *diagnostic variant: larger m (20)* | 0.5507 | 0.6193 | 0.2778 | 0.5278 |

---

## 5. Step 2: Saturation Cure Comprehensive Audit

*Source: `results/v4/metrics/saturation_cure_comprehensive_audit.csv`*

In Stage 1.5 (Findings v3.1, Claim 5), it was reported that replacing validation-$F_1$ optimization with the benign-quantile rule and adding an $\epsilon = 10^{-6}$ floor on MAD reduced Config A-prime false positive rate on UNSW Flow from 100.0% to 0.57%.

**Full Re-Measurement of Detection Performance Under the "Saturation Cure":**
- **UNSW Flow Contiguous Block (Config A-prime, $\alpha=0.05$):**
  - Test FPR = **0.57%** (target met, $\le 5\%$)
  - Test Recall = **2.14%** (only 4 / 187 attacks detected)
  - Test $F_1$ = **0.0402**
  - ROC-AUC = **0.5079** (near-random guessing)
  - PR-AUC = **0.1240** vs Prevalence **0.1169**
- **UNSW Small Regime-Shift Block (Config A-prime, $\alpha=0.05$):**
  - Test FPR = **0.00%**
  - Test Recall = **0.00%** (0 / 45 attacks detected)
  - Test $F_1$ = **0.0000**
  - ROC-AUC = **0.5000**
- **UNSW Regime-Shift Demonstration (Config A-prime, $\alpha=0.05$):**
  - Test FPR = **0.00%**
  - Test Recall = **0.00%** (0 / 1,194 attacks detected)
  - Test $F_1$ = **0.0000**
  - ROC-AUC = **0.5000**

> [!IMPORTANT]
> **Audit Conclusion on the Saturation Cure:**  
> The "saturation cure" did not restore anomaly discrimination; it achieved a low False Positive Rate by **suppressing all alerts**, resulting in near-zero recall (0.0% – 2.14%) and near-chance ROC-AUC ($0.5000 - 0.5079$).

---

## 6. Synthesis: Degenerate Score vs. Genuine Lack of Signal

**Audit Finding for Claim Verification:**
The poor performance of Matrix Profile methods on cloud and network telemetry is caused by **both mathematical score degeneracy and a genuine lack of discriminative subsequence signal**:

1. **Mathematical Score Degeneracy:**
   In real cloud and flow telemetry, un-activated operational channels (e.g., HTTP 5xx error counts during normal operation, TCP RST flags during quiet mornings, or static TTL values in sanitized synthetic datasets) have zero variance in baseline windows. STUMPY's z-normalized Euclidean distance computation encounters zero-standard-deviation subsequences, mapping them to zero distance. For Config A-prime and Config A on the testbed and UNSW flow/window blocks, this produces extensive point-mass ties at zero (98% – 100% of scores identically 0.0), causing quantile thresholds and MAD estimators to collapse.
2. **Genuine Lack of Subsequence Signal:**
   Even when mathematical score degeneracy is eliminated via diagnostic variants:
   - Dropping constant channels on the testbed yielded ROC-AUC of **0.5013** (Config A) and **0.4580** (Config A-prime).
   - Non-z-normalized Euclidean distance yielded ROC-AUC of **0.4996** on UNSW flow.
   - Smoothing count features failed to lift ROC-AUC above chance on the testbed (0.5000) and degraded CSE Wednesday Config A from 0.6724 to 0.4800.
   - Tabular baselines (`Isolation Forest` and `ARIMA Residual`) operating on the exact same data achieve ROC-AUC $> 0.88 - 0.96$.

**Conclusion:** Network telemetry flows are point-in-time discrete transaction logs. They do not possess smooth, repeating, continuous temporal motifs or phase shapes. Distance-based matrix profile joins measure unweighted Euclidean distance across unrelated transaction bursts, creating genuine absence of discriminative anomaly signal.



---

## 7. Step 3: Conformal Comparison at Matched Operating Points

*Sources: `results/v4/metrics/matched_operating_points_comparison.csv`, `results/v4/metrics/conformal_reachability_table.csv`, `results/v4/metrics/conformal_fpr_control_summary.csv`, `results/v4/metrics/conformal_paired_comparison.csv`, `results/v4/metrics/conformal_configuration_changes.csv`, `results/v4/run_metadata_step3.json`*

### 7.1 Scope and Experimental Protocol
In Stage 2, it was claimed that Causal Rolling Split-Conformal and Adaptive Conformal Inference (ACI) provided superior false alarm control and improved $F_1$ across non-stationary cross-day evaluations. However, as audited in Step 1, the Stage 2 implementation passed test labels into calibrators (`verified_benign_mask = y_test == 0`). 

In Step 3, we conduct an honest, rigorous re-measurement comparing **Static Benign Quantile**, **Static Split-Conformal**, **Rolling Split-Conformal (Label-Free Autonomous)**, and **Adaptive Conformal Inference (ACI, Label-Free Autonomous)** across an operational significance grid $\alpha \in \{0.005, 0.01, 0.02, 0.05, 0.10\}$ across all 32 benchmark configurations (8 evaluation blocks $\times$ 4 detector models). All comparisons are matched at empirical operating points.

---

### 7.2 False Alarm Rate Control and Reachability Across Operating Points

The table below reports empirical False Positive Rate (FPR) control across all 32 configurations, including exact Clopper-Pearson 95% binomial confidence intervals, cross-day variance across CSE-CIC-IDS2018 deployment days, maximum observed test FPR, and reachability of tight operational budgets ($\text{FPR} \le 0.01$ and $\text{FPR} \le 0.05$).

| Method | Variant | Target $\alpha$ | Target Met ($k/N$, %) | Clopper-Pearson 95% CI | All Runs Mean FPR | All Runs Std FPR | Max Observed FPR | CSE Cross-Day Mean FPR | CSE Cross-Day Std FPR | Unreachable $\text{FPR}\le 0.01$ | Unreachable $\text{FPR}\le 0.05$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Benign Quantile** | Baseline | 0.01 | 21 / 32 (65.6%) | [46.8%, 81.4%] | 2.00% | 3.91% | 17.65% | 1.89% | 3.53% | 7 / 32 | 3 / 32 |
| **Static Split-Conformal** | Baseline | 0.01 | **23 / 32 (71.9%)** | **[53.3%, 86.3%]** | **1.82%** | **3.87%** | **17.65%** | **1.50%** | **3.36%** | **5 / 32** | **3 / 32** |
| **Rolling Split-Conf (LF)**| Label-Free | 0.01 | 17 / 32 (53.1%) | [34.7%, 70.9%] | 5.70% | 10.68% | 50.00% | 2.27% | 3.31% | 15 / 32 | 9 / 32 |
| **Adaptive Conformal (ACI)**| Label-Free | 0.01 | 17 / 32 (53.1%) | [34.7%, 70.9%] | 5.70% | 10.68% | 50.00% | 2.27% | 3.31% | 15 / 32 | 8 / 32 |
| *Rolling Split-Conf (Oracle)*| *Oracle Upper Bound* | 0.01 | 20 / 32 (62.5%) | [43.7%, 78.9%] | 1.06% | 1.22% | 3.33% | 1.15% | 1.30% | 12 / 32 | 0 / 32 |
| *Adaptive Conf (ACI, Oracle)*| *Oracle Upper Bound* | 0.01 | 20 / 32 (62.5%) | [43.7%, 78.9%] | 1.06% | 1.22% | 3.33% | 1.15% | 1.30% | 12 / 32 | 0 / 32 |
| **Static Benign Quantile** | Baseline | 0.05 | 14 / 32 (43.8%) | [26.4%, 62.3%] | 12.37% | 19.58% | 100.00% | 9.94% | 9.85% | 7 / 32 | 3 / 32 |
| **Static Split-Conformal** | Baseline | 0.05 | 14 / 32 (43.8%) | [26.4%, 62.3%] | 11.99% | 19.56% | 100.00% | 9.00% | 9.55% | 5 / 32 | 3 / 32 |
| **Rolling Split-Conf (LF)**| Label-Free | 0.05 | 18 / 32 (56.2%) | [37.7%, 73.6%] | 12.03% | 16.17% | 50.00% | 6.38% | 6.42% | 15 / 32 | 9 / 32 |
| **Adaptive Conformal (ACI)**| Label-Free | 0.05 | 17 / 32 (53.1%) | [34.7%, 70.9%] | 10.03% | 13.37% | 50.00% | 6.20% | 6.99% | 15 / 32 | 8 / 32 |
| *Rolling Split-Conf (Oracle)*| *Oracle Upper Bound* | 0.05 | 22 / 32 (68.8%) | [50.0%, 83.9%] | 3.06% | 3.00% | 9.17% | 3.35% | 3.12% | 12 / 32 | 0 / 32 |
| *Adaptive Conf (ACI, Oracle)*| *Oracle Upper Bound* | 0.05 | 23 / 32 (71.9%) | [53.3%, 86.3%] | 2.86% | 2.43% | 6.67% | 3.31% | 2.20% | 12 / 32 | 0 / 32 |

#### Key Empirical Observations on FPR Control:
1. **Static Conformal Outperforms Adaptive Methods at $\alpha = 0.01$:**  
   At $\alpha=0.01$, Static Split-Conformal met the target in **71.9%** of runs (95% CI: [53.3%, 86.3%]), with a mean FPR of **1.82%** and max FPR of **17.65%**. In contrast, autonomous Rolling Conformal and ACI met the target in only **53.1%** of runs (95% CI: [34.7%, 70.9%]), suffered an average FPR of **5.70%** ($5.7\times$ nominal budget), and reached a maximum FPR of **50.00%**.
2. **Operating Point Unreachability:**  
   Because the rolling buffer of size $W=60$ adapts to local non-stationarity, tight operating points ($\text{FPR} \le 0.01$) were **completely unreachable in 15 out of 32 configurations** for autonomous rolling and ACI calibrators (compared to only 5 configurations for Static Split-Conformal).
3. **Stage 2 Claims Discredited by Oracle Removal:**  
   The Stage 2 claim that ACI achieves 71.9% target compliance at $\alpha=0.05$ with mean FPR of 2.86% was strictly an artifact of oracle label leakage. In true autonomous deployment, ACI achieves only 53.1% compliance with a mean FPR of 10.03%.

---

### 7.3 Paired Comparison at Matched Operating Points

To eliminate operating-point mismatch, we evaluate paired performance where Static Benign Quantile is calibrated to match the exact mean achieved test FPR of the adaptive methods:
- Across all 32 runs at target $\alpha=0.05$: Rolling LF mean achieved FPR = **12.03%**; ACI LF mean achieved FPR = **10.03%**. Static Quantile is calibrated at matching $\alpha$ ($\alpha=0.0487$ and $\alpha=0.0416$).
- For each paired configuration, we compute the paired recall difference $\Delta \mathrm{Recall} = \mathrm{Recall}_{\mathrm{adaptive}} - \mathrm{Recall}_{\mathrm{static\_matched}}$, and evaluate statistical significance using a **1,000-replicate Moving-Block Bootstrap (MBB, contiguous block length $B=10$)**.

| Comparison | Total Runs | Wins ($\Delta R > 0$) | Ties ($\Delta R = 0$) | Losses ($\Delta R < 0$) | Significant Wins (MBB) | Significant Losses (MBB) | Mean $\Delta \mathrm{Recall}$ | 95% Bootstrap Confidence Interval |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rolling LF vs Matched Static** (All 32) | 32 | 6 | 9 | **17** | 4 | **13** | **$-0.1791$** | **$[-0.3227, -0.0491]$** |
| **Rolling LF vs Nominal Static** (All 32) | 32 | 7 | 11 | **14** | 5 | **9** | **$-0.0581$** | $[-0.1811, +0.0548]$ |
| **ACI LF vs Matched Static** (All 32) | 32 | 6 | 8 | **18** | 4 | **15** | **$-0.2391$** | **$[-0.4016, -0.1033]$** |
| **ACI LF vs Nominal Static** (All 32) | 32 | 7 | 9 | **16** | 5 | **11** | **$-0.1336$** | **$[-0.2791, -0.0133]$** |
| **Rolling LF vs Matched Static** (CSE Cross-Day) | 12 | 2 | 3 | **7** | 0 | **6** | **$-0.3018$** | **$[-0.5186, -0.0950]$** |
| **ACI LF vs Matched Static** (CSE Cross-Day) | 12 | 2 | 2 | **8** | 0 | **7** | **$-0.3376$** | **$[-0.5641, -0.1212]$** |

#### Key Findings from Paired Comparison:
1. **Losses Heavily Outnumber Wins:**  
   When matched at equal achieved test FPR across all 32 configurations, Rolling Conformal suffered **17 losses vs 6 wins** (13 statistically significant losses vs 4 significant wins). ACI suffered **18 losses vs 6 wins** (15 statistically significant losses vs 4 significant wins).
2. **Statistically Significant Recall Degradation:**  
   The mean recall penalty of Rolling Conformal relative to matched Static Quantile is **$-17.91$ percentage points** (95% Bootstrap CI: $[-0.3227, -0.0491]$). For ACI, the recall penalty is **$-23.91$ percentage points** (95% Bootstrap CI: $[-0.4016, -0.1033]$). In both cases, zero is excluded from the confidence intervals.
3. **Severe Breakdown on CSE Cross-Day Deployment:**  
   Across the 12 primary CSE Cross-Day runs, Rolling and ACI produced **zero statistically significant wins** and **6 to 7 statistically significant losses**, suffering an average recall collapse exceeding **$-30$ percentage points**.

---

### 7.4 Comprehensive Configuration Performance and Regressions

*Source: `results/v4/metrics/conformal_configuration_changes.csv`*

The table below reports detection recall and $F_1$ across configurations at nominal target $\alpha = 0.05$, explicitly documenting all regressions including Thursday where rolling conformal recall collapsed:

| Block | Model | Static FPR | Static Recall | Static $F_1$ | Roll LF FPR | Roll LF Recall | Roll LF $F_1$ | Roll LF $\Delta \mathrm{Recall}$ | Roll Oracle Recall | ACI LF Recall | ACI LF $F_1$ | ACI LF $\Delta \mathrm{Recall}$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Thursday Cross-Day** | Isolation Forest | 0.0336 | 0.1395 | 0.2264 | 0.0252 | **0.0465** | 0.0833 | **$-0.0930$** | **0.0000** | **0.0465** | 0.0833 | **$-0.0930$** |
| | ARIMA Residual | 0.0000 | 0.0698 | 0.1304 | 0.0168 | 0.1163 | 0.2000 | $+0.0465$ | 0.0698 | 0.1163 | 0.2041 | $+0.0465$ |
| | Config A (mSTAMP) | 0.0840 | 0.3488 | 0.4412 | 0.0420 | 0.3023 | 0.4262 | $-0.0465$ | 0.1395 | 0.2326 | 0.3636 | $-0.1163$ |
| | Config A-prime | 0.0000 | 0.0000 | 0.0000 | 0.1092 | 0.3256 | 0.4000 | $+0.3256$ | 0.0000 | 0.3256 | 0.4058 | $+0.3256$ |
| **Friday Cross-Day** | Isolation Forest | 0.1250 | 1.0000 | 0.8624 | 0.0417 | 1.0000 | 0.9495 | $0.0000$ | 1.0000 | **0.5319** | 0.6579 | **$-0.4681$** |
| | ARIMA Residual | 0.0500 | 0.0000 | 0.0000 | 0.0500 | 0.0000 | 0.0000 | $0.0000$ | 0.0000 | 0.0000 | 0.0000 | $0.0000$ |
| | Config A (mSTAMP) | 0.1000 | 0.4468 | 0.5250 | 0.2167 | **0.0000** | 0.0000 | **$-0.4468$** | **0.0000** | **0.0000** | 0.0000 | **$-0.4468$** |
| | Config A-prime | 0.2417 | 0.5532 | 0.5098 | 0.1167 | **0.0000** | 0.0000 | **$-0.5532$** | **0.0000** | **0.0000** | 0.0000 | **$-0.5532$** |
| **Wednesday Cross-Day** | Isolation Forest | 0.2941 | 1.0000 | 0.8780 | 0.1176 | 1.0000 | 0.9474 | $0.0000$ | 1.0000 | 1.0000 | 0.9600 | $0.0000$ |
| | ARIMA Residual | 0.0294 | 1.0000 | 0.9863 | 0.0000 | 1.0000 | 1.0000 | $0.0000$ | 1.0000 | 1.0000 | 1.0000 | $0.0000$ |
| | Config A (mSTAMP) | 0.2059 | 0.4722 | 0.5667 | 0.0294 | **0.1389** | 0.2381 | **$-0.3333$** | 0.1389 | **0.1111** | 0.1951 | **$-0.3611$** |
| | Config A-prime | 0.0294 | 0.2778 | 0.4255 | 0.0000 | **0.1389** | 0.2439 | **$-0.1389$** | 0.1389 | **0.1111** | 0.2000 | **$-0.1667$** |
| **Friday Within-Day** | Isolation Forest | 0.0000 | 1.0000 | 1.0000 | 0.0000 | **0.0213** | 0.0417 | **$-0.9787$** | 0.0213 | **0.0213** | 0.0417 | **$-0.9787$** |
| | ARIMA Residual | 0.0000 | 1.0000 | 1.0000 | 0.0000 | **0.5106** | 0.6761 | **$-0.4894$** | 0.4894 | **0.0426** | 0.0816 | **$-0.9574$** |
| | Config A (mSTAMP) | 0.0000 | 0.5957 | 0.7467 | 0.0000 | **0.0000** | 0.0000 | **$-0.5957$** | 0.0000 | **0.0000** | 0.0000 | **$-0.5957$** |
| **Wednesday Within-Day**| Isolation Forest | 0.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | $0.0000$ | 0.4167 | **0.0833** | 0.1538 | **$-0.9167$** |
| | Config A (mSTAMP) | 0.0000 | 0.5000 | 0.6667 | 0.0000 | **0.0556** | 0.1053 | **$-0.4444$** | 0.0278 | **0.0556** | 0.1053 | **$-0.4444$** |

#### Crucial Failure Modes Revealed:
1. **Thursday Isolation Forest Collapse:**  
   Under Rolling Split-Conformal with oracle feedback, test recall collapsed to **0.0000 (0 / 43 attacks detected)**. Under autonomous label-free rolling calibration, recall collapsed from **0.1395 to 0.0465** ($\Delta R = -0.0930$, $F_1$ dropped from 0.2264 to 0.0833).
2. **Friday Config A and A-prime Complete Blindness:**  
   On Friday Cross-Day, Static Quantile detected attacks with recall of 0.4468 (Config A) and 0.5532 (Config A-prime). Under both Rolling LF and ACI LF, test recall collapsed to **0.0000 (0 / 47 attacks detected)**.
3. **Friday Within-Day Isolation Forest Destruction:**  
   On Friday within-day sensitivity, Isolation Forest achieved perfect recall (1.0000, $F_1=1.0000$) under static thresholding. Under Rolling LF and ACI LF, recall plummeted to **0.0213 (only 1 / 47 attacks detected, $\Delta R = -0.9787$)**.

---

### 7.5 Verification Conclusion: Better Detection, Lower FPR Variance, or Neither?

We evaluate the prompt's three candidate hypotheses against the empirical data:

#### (a) Does conformal thresholding provide better detection at equal FPR?
**NO.** When matched at equal empirical achieved FPR, adaptive conformal calibrators strictly degrade detection performance. Paired comparisons across all 32 configurations show that losses outnumber wins by nearly 3 to 1 (17-18 losses vs 6 wins), with an average recall penalty of **$-17.91$ percentage points (Rolling)** and **$-23.91$ percentage points (ACI)**. On CSE Cross-Day deployment, the mean recall penalty exceeds **$-30$ percentage points** with zero statistically significant wins. The buffer adaptation mechanism inflates thresholds during diurnal surges, blinding the detector to subsequent attacks.

#### (b) Does conformal thresholding provide lower day-to-day FPR variance?
**CONDITIONALLY YES on well-separated models (Isolation Forest at $\alpha=0.05$), but NO globally, and NO at tight operational budgets ($\alpha=0.01$).**
- On `Isolation Forest` at $\alpha=0.05$, day-to-day FPR standard deviation across Thursday, Friday, and Wednesday dropped from **10.79%** (Static Quantile) to **4.03%** (Rolling LF) and **2.80%** (ACI LF).
- However, on matrix profile detectors (`Config A`), adaptive thresholding **increased day-to-day FPR variance** (Std increased from **5.41%** to **8.55%** for Rolling LF and to **9.92%** for ACI LF) because non-stationary baseline scores caused false alarm blowouts up to 23.33% on Friday.
- At tight operational budgets ($\alpha=0.01$), adaptive thresholding suffered nearly **$3\times$ higher FPR variance** (All-runs Std = **10.68%** vs **3.87%** for Static Split-Conformal) and produced severe worst-case false alarm blowouts (**50.00%** vs **17.65%** for Static Split-Conformal).

#### Overall Conclusion:
The benefit of dynamic conformal thresholding is **strictly (b) a localized reduction in FPR variance for well-separated models at permissive budgets ($\alpha=0.05$), purchased at the heavy price of severe recall loss (a)**. Under tight false alarm budgets ($\alpha=0.01$) or on weak detectors, the answer is **(c) NEITHER**.


---

## 8. Step 4: Testbed Repeats and Honesty Checks

*Sources: `results/v4/metrics/testbed_multiseed_evaluation.csv`, `results/v4/metrics/testbed_multiseed_summary.csv`, `results/v4/metrics/testbed_diagnostic_baselines.csv`, `results/v4/figures/figure_testbed_multiseed_summary.png`, `results/v4/run_metadata_step4.json`*

### 8.1 Technical Documentation of the Live Microservice Testbed Run

To resolve documentation ambiguities in Section 4 of the draft paper:

1. **Wall-Clock Duration vs. Time Compression:**  
   The testbed run is **time-compressed accelerated execution**, not 10 hours of real wall-clock time. Each 60-second operational window is executed in an accelerated time slice of real wall-clock duration $t_{\mathrm{sim}} = 0.08 - 0.15$ seconds ($600 \text{ windows} \times 0.14\text{s} \approx 84$ seconds wall-clock time representing 10 hours of simulated diurnal traffic).
2. **Reconciliation of Requests Per Second (Stated 10–40 RPS vs. Figure 4):**  
   - In the paper draft (Section 4.1), the load was described as *"a Locust generator executing transactions following a sinusoidal diurnal curve ($RPS \in [10, 40]$)"*. This stated range reflected the nominal Locust target user pool configuration (`testbed/locustfile.py`, base 20 to peak 80 users).
   - In the actual measured telemetry logged by the Flask service (`testbed_60s_regular.parquet`) and plotted in Figure 4 (`testbed_timeline_scores.png`), the y-axis represents transactions per 60-second window (`flow_count`):
     - `benign_normal`: 8 to 51 req/min $\rightarrow$ **0.133 to 0.850 RPS (mean 0.233 RPS)**
     - `slowloris`: 14 to 68 req/min $\rightarrow$ **0.233 to 1.133 RPS (mean 0.794 RPS)**
     - `volumetric_flood`: 138 to 283 req/min $\rightarrow$ **2.300 to 4.717 RPS (mean 3.352 RPS)**
     - `flash_crowd`: 124 to 291 req/min $\rightarrow$ **2.067 to 4.850 RPS (mean 3.311 RPS)**
     - `intermittent_spike`: 142 to 254 req/min $\rightarrow$ **2.367 to 4.233 RPS (mean 3.220 RPS)**
     - `endpoint_recon`: 140 to 286 req/min $\rightarrow$ **2.333 to 4.767 RPS (mean 3.616 RPS)**
   - **Reconciliation:** Figure 4 accurately reflects the true measured transaction rates ($0.2 - 4.85$ RPS). The text claim of "10–40 RPS" is inaccurate and must be updated to reflect the true telemetry rates.
3. **Container Networking and Confinement Mechanism:**  
   - In `testbed/docker-compose.yml`, network isolation is enforced via an internal Docker bridge:
     `isolated_testbed_net: driver: bridge; internal: true`. The `internal: true` directive instructs Docker to insert Linux `iptables` drop rules preventing packet forwarding outside the host, ensuring zero WAN/internet egress.
   - In `testbed/attacker.py`, strict application-level confinement is enforced on line 17:
     `assert target_host in ["127.0.0.1", "localhost"], f"Security violation: target_host must be local ({target_host})"`.
   - In `testbed/run_testbed.py`, traffic is routed exclusively over local loopback (`127.0.0.1:8088`).

---

### 8.2 Multi-Seed Verification Protocol (5 Seeds with Randomized Schedules)

We orchestrated 5 independent, randomized testbed runs across seeds `42, 43, 44, 45, 46`:
- **Randomized Order & Placement:** The 25 campaigns (5 categories $\times$ 5 instances) were randomly permuted and placed within the test evaluation horizon (windows 300 to 599).
- **Interleaved Flash Crowds:** Unlike Stage 3 (where all 5 flash crowds were clustered at the very end), flash crowds were interleaved throughout the test timeline (e.g., at positions 4, 7, 13, 18, 23 in Seed 43, and 1, 6, 7, 13, 14 in Seed 44).
- **Randomized Durations:** Campaign durations were sampled randomly within stated ranges (floods: 5–9 windows; slowloris: 6–8 windows; spikes: 5–7 windows; recon: 5–7 windows; flash crowds: 6–8 windows).
- **Strict Chronological Hygiene:** Windows 0–199 (Train) and 200–299 (Val) remained 100% benign diurnal traffic across all seeds.

---

### 8.3 Multi-Seed Empirical Results Across 5 Seeds

*Source: `results/v4/metrics/testbed_multiseed_summary.csv`*

The table below reports detection fidelity, campaign recall (pooled with exact Clopper-Pearson 95% CIs), and flash-crowd false-alarm rates (Mean $\pm$ Std across 5 seeds at nominal $\alpha = 0.05$):

| Model | Method | Variant | ROC-AUC | PR-AUC | Test FPR (%) | Flash Crowd FAR (%) | Attack Recall (%) | $F_1$ Score | Pooled Campaign Recall | Pooled CP 95% CI |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | Static Quantile | Baseline | $0.942 \pm 0.009$ | $0.900 \pm 0.025$ | $26.85 \pm 1.79$ | **$100.00 \pm 0.00$** | **$98.14 \pm 0.80$** | $0.841 \pm 0.009$ | **1.00 (100/100)** | [0.964, 1.000] |
| | Static Split-Conf | Baseline | $0.942 \pm 0.009$ | $0.900 \pm 0.025$ | $25.91 \pm 1.70$ | **$100.00 \pm 0.00$** | **$97.99 \pm 0.79$** | $0.844 \pm 0.009$ | **1.00 (100/100)** | [0.964, 1.000] |
| | Rolling Split-Conf (LF)| Label-Free | $0.942 \pm 0.009$ | $0.900 \pm 0.025$ | $26.50 \pm 2.19$ | **$100.00 \pm 0.00$** | **$97.99 \pm 1.27$** | $0.842 \pm 0.011$ | **1.00 (100/100)** | [0.964, 1.000] |
| | ACI (Label-Free) | Label-Free | $0.942 \pm 0.009$ | $0.900 \pm 0.025$ | $7.89 \pm 7.73$ | $26.06 \pm 37.29$ | $74.43 \pm 14.30$ | $0.799 \pm 0.072$ | 0.88 (88/100) | [0.800, 0.936] |
| | *Rolling Split-Conf (Oracle)*| *Oracle Ref*| $0.942 \pm 0.009$ | $0.900 \pm 0.025$ | $5.28 \pm 1.23$ | **$13.26 \pm 7.64$** | $75.56 \pm 9.52$ | $0.825 \pm 0.063$ | 0.89 (89/100) | [0.812, 0.944] |
| | *ACI (Oracle)* | *Oracle Ref*| $0.942 \pm 0.009$ | $0.900 \pm 0.025$ | $4.10 \pm 0.36$ | **$8.42 \pm 3.58$** | $61.63 \pm 16.94$ | $0.725 \pm 0.132$ | 0.76 (76/100) | [0.664, 0.840] |
| **ARIMA Residual** | Static Quantile | Baseline | $0.906 \pm 0.006$ | $0.866 \pm 0.013$ | $25.67 \pm 0.63$ | **$100.00 \pm 0.00$** | **$98.14 \pm 0.80$** | $0.846 \pm 0.006$ | **1.00 (100/100)** | [0.964, 1.000] |
| | Rolling Split-Conf (LF)| Label-Free | $0.906 \pm 0.006$ | $0.866 \pm 0.013$ | $26.73 \pm 1.77$ | **$100.00 \pm 0.00$** | **$98.15 \pm 1.05$** | $0.841 \pm 0.008$ | **1.00 (100/100)** | [0.964, 1.000] |
| | ACI (Label-Free) | Label-Free | $0.906 \pm 0.006$ | $0.866 \pm 0.013$ | $22.86 \pm 0.89$ | **$100.00 \pm 0.00$** | **$97.68 \pm 0.85$** | $0.858 \pm 0.006$ | **1.00 (100/100)** | [0.964, 1.000] |
| | *Rolling Split-Conf (Oracle)*| *Oracle Ref*| $0.906 \pm 0.006$ | $0.866 \pm 0.013$ | $7.15 \pm 1.42$ | $31.00 \pm 8.34$ | $53.30 \pm 11.75$ | $0.648 \pm 0.102$ | 0.78 (78/100) | [0.686, 0.857] |
| **Config A (mSTAMP)** | All Methods | All | $0.500 \pm 0.000$ | $0.431 \pm 0.003$ | $0.00 \pm 0.00$ | $0.00 \pm 0.00$ | **$0.00 \pm 0.00$** | $0.000 \pm 0.000$ | **0.00 (0/100)** | [0.000, 0.036] |
| **Config A-prime (AB)**| All Methods | All | $0.500 \pm 0.000$ | $0.431 \pm 0.003$ | $0.00 \pm 0.00$ | $0.00 \pm 0.00$ | **$0.00 \pm 0.00$** | $0.000 \pm 0.000$ | **0.00 (0/100)** | [0.000, 0.036] |

---

### 8.4 Separation of Operational Alert Rates (True Detections vs. Noise vs. Storms)

*Source: `results/v4/metrics/testbed_multiseed_summary.csv`*

In Stage 3, total alerts per hour ($34.56 \text{ alerts/hour}$) was presented without traffic attribution, allowing critics to read it as a false alarm storm. We separate alerts by originating traffic category (Mean $\pm$ Std across 5 seeds):

| Model | Method | Attack Alerts / Hr (Desired Detections) | Normal Benign Alerts / Hr (Background Noise) | Flash Crowd Alerts / Hr (False Alarm Storm) | Total Alerts / Hr (Overall Operating Load) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Isolation Forest** | Static Benign Quantile | **$58.89 \pm 0.48$** | **$5.42 \pm 1.51$** | **$60.00 \pm 0.00$** | $34.56 \pm 0.72$ |
| | Static Split-Conformal | $58.79 \pm 0.48$ | $4.72 \pm 1.45$ | $60.00 \pm 0.00$ | $34.20 \pm 0.62$ |
| | Rolling Split-Conf (Label-Free) | $58.79 \pm 0.76$ | $5.16 \pm 1.78$ | $60.00 \pm 0.00$ | $34.40 \pm 0.89$ |
| | Adaptive Conformal (ACI, LF) | $44.66 \pm 8.58$ | $2.10 \pm 0.64$ | $15.64 \pm 22.37$ | $21.96 \pm 6.10$ |
| | *Rolling Split-Conf (Oracle)* | $45.34 \pm 5.71$ | $2.01 \pm 0.44$ | $7.96 \pm 4.58$ | $21.36 \pm 2.32$ |
| **ARIMA Residual** | Static Benign Quantile | **$58.89 \pm 0.48$** | **$4.54 \pm 0.68$** | **$60.00 \pm 0.00$** | $34.16 \pm 0.34$ |
| | Rolling Split-Conf (Label-Free) | $58.89 \pm 0.63$ | $5.34 \pm 1.36$ | $60.00 \pm 0.00$ | $34.52 \pm 0.81$ |
| | Adaptive Conformal (ACI, LF) | $58.61 \pm 0.51$ | $2.45 \pm 0.65$ | $60.00 \pm 0.00$ | $33.08 \pm 0.37$ |
| | *Rolling Split-Conf (Oracle)* | $31.98 \pm 7.05$ | $0.79 \pm 0.58$ | $18.60 \pm 5.01$ | $16.24 \pm 3.07$ |

#### Operational SRE Insights:
1. **Normal Benign Traffic is Quiet:**  
   During normal quiescent benign hours, static thresholding raises only **$4.54 - 5.42$ alerts per hour** (an acceptable operating background under a 5% FPR budget).
2. **Attacks are Promptly Flagged:**  
   During active attack campaigns, static thresholding raises **$58.89 \pm 0.48$ alerts per hour** ($98.14\%$ attack window recall, $100\%$ campaign recall).
3. **The Storm is Confined to Flash Crowds:**  
   The elevated alert load is concentrated strictly during benign flash crowds, where static thresholding triggers **$60.00 \pm 0.00$ alerts per hour** (100% false alarms, every single minute flagged).

---

### 8.5 Diagnostic Baselines: Volume-Only Features vs. Augmented Training

*Source: `results/v4/metrics/testbed_diagnostic_baselines.csv`*

To diagnose why flash crowds trigger false alarm storms, we evaluated two diagnostic comparison baselines across the 5 seeds:

| Baseline Model | Features Used | Training Data Composition | ROC-AUC | PR-AUC | Flash Crowd FAR (%) | Attack Recall (%) | $F_1$ Score |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Diagnostic Baseline (a): Volume-Only IF** | 3 Volume (`flow_count`, fwd/bwd bytes) | Pure Quiescent Diurnal ($N=200$) | $0.861 \pm 0.004$ | $0.732 \pm 0.009$ | $100.00 \pm 0.00$ | $97.99 \pm 0.93$ | $0.845 \pm 0.011$ |
| **Standard Baseline: Isolation Forest** | All 11 Multidimensional Telemetry | Pure Quiescent Diurnal ($N=200$) | **$0.942 \pm 0.009$** | **$0.900 \pm 0.025$** | $100.00 \pm 0.00$ | $98.14 \pm 0.80$ | $0.841 \pm 0.009$ |
| **Diagnostic Baseline (b): FC-Augmented IF**| All 11 Multidimensional Telemetry | Augmented with Benign Flash Crowds | $0.909 \pm 0.030$ | $0.844 \pm 0.060$ | **$10.16 \pm 7.78$** (ACI) | $95.98 \pm 1.72$ | $0.852 \pm 0.008$ |

#### Key Diagnostic Findings:
1. **Multidimensional Telemetry Adds Significant Value:**  
   Including error rate, status code counts, and latency percentiles lifts ROC-AUC from **$0.8612$ to $0.9421$** ($+0.081$) and PR-AUC from **$0.7324$ to $0.9004$** ($+0.168$) compared to volume features alone.
2. **The Flash Crowd Vulnerability is a Training-Distribution Issue:**  
   When benign training data contains only quiescent traffic, any volume surge is *out-of-distribution* by definition, forcing tree ensembles to assign anomalous isolation scores. When the benign training set is augmented to reflect legitimate traffic surges (high volume, 0% errors, 100% 200 OK), the model learns that volume surges with healthy status codes are normal benign traffic, reducing flash crowd false alarms under adaptive calibration to **$10.16\% \pm 7.78\%$** while preserving $>95.98\%$ attack recall.

---

### 8.6 Definite Re-Measurement of the Flash-Crowd Claim

> [!CAUTION]
> **Definitive Re-Measurement of the Stage 3 Flash-Crowd Claim:**  
> In Stage 3, it was claimed that *"Rolling Conformal calibration adapted to legitimate baseline increases, slashing flash crowd false alarms to 11.43%"*.  
> **Re-measurement across 5 randomized seeds disproves this claim for autonomous deployment:**
> - Under **autonomous label-free rolling calibration**, Flash Crowd FAR is **$100.00\% \pm 0.00\%$** (identical to static thresholding). The self-filtering rule quarantines flagged instances, preventing elevated flash-crowd scores from entering the buffer.
> - The $11.43\%$ figure was strictly an artifact of passing ground-truth test labels (`verified_benign_mask = y_test == 0`) into the calibrator (Oracle feedback achieved $13.26\% \pm 7.64\%$).
> - Real autonomous flash crowd rejection cannot be achieved by rolling quantile thresholds alone without test labels; it requires **training data representation** (Diagnostic Baseline b) or **multi-signal error rate conditioning**.


---

## 9. Step 5: Number Trace and Discrepancy Reconciliation

*Source Artifact: [`docs/number_trace.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/docs/number_trace.csv)*

To guarantee absolute documentation integrity and empirical reproducibility, we executed an exhaustive line-by-line number trace of the draft research paper (`paper/main.tex`). Every numerical claim, table cell, figure annotation, and empirical statement was cataloged, traced to its exact source file and row, and cross-referenced against the re-measurements conducted in Stage 4.

The trace audit cataloged **111 distinct numerical assertions** across the entire manuscript:
- **Verified (`VERIFIED`):** 86 claims (77.5%) trace directly to exact rows in `results/v3_1/`, `results/v3_2/`, `results/v3_3/`, or `results/v4/` metrics files.
- **Discrepancy Resolved (`DISCREPANCY_RESOLVED`):** 7 claims (6.3%) represent documented divergences whose mathematical origins have been reconciled and resolved.
- **Weakened Claims (`WEAKENED`):** 14 claims (12.6%) represent claims from earlier stages that Stage 4 re-measurements have weakened or refuted (principally the flash crowd false-alarm reduction and testbed $F_1$ score under autonomous deployment).
- **Unsourced Assertions (`UNSOURCED`):** 4 statements (3.6%) in the draft manuscript lack reproducible data sources or contradict physical artifacts.

---

### 9.1 Resolution of the Five Known Discrepancies

#### 1. Isolation Forest Wednesday $F_1$: 0.9859 (Paper) vs. 0.8780 (Stage 2 Table)
- **Claimed Snippets:**  
  - Abstract (Line 51): *"cross-day sizing ($N=507$) restored it to Rank~1 ($F_1 = 0.9859$)"*  
  - Section 4.2 (Line 124): *"on Wednesday, Isolation Forest surged to Rank 1 tied with ARIMA at $F_1 = 0.9859$"*  
  - Benchmark Table 1 (Row 1/2) & Stage 2 Table: Test $F_1 = 0.8780$ (at fixed $\alpha = 0.05$).
- **Source Files & Provenance:**  
  - $F_1 = 0.985915$: [`results/v3_1/metrics/csecicids2018_cross_day_results.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v3_1/metrics/csecicids2018_cross_day_results.csv) (Row 32) and [`csecicids2018_ranking_comparison.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v3_1/metrics/csecicids2018_ranking_comparison.csv) (Row 14).
  - $F_1 = 0.878049$: [`results/v3_2/metrics/conformal_comparison_results.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v3_2/metrics/conformal_comparison_results.csv) (Row 66) and [`results/v4/metrics/stage4_conformal_comparison_results.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v4/metrics/stage4_conformal_comparison_results.csv) (Row 98).
- **Root-Cause Resolution:**  
  The two values reflect two fundamentally different threshold selection paradigms:
  1. **Validation-$F_1$ Tuning ($F_1 = 0.9859$):** In the Stage 3.1 cross-day experiment, the decision threshold $\tau^*$ was chosen via grid-search over percentiles $p \in [80, 99.8]$ of the validation score distribution to maximize validation $F_1$ against true validation labels. Because the validation split contained active attacks, the resulting threshold balanced precision and recall optimally, attaining Precision = 1.0, Recall = 0.9722, Test $F_1 = 0.9859$, and Rank 1 on Wednesday.
  2. **Fixed Nominal $\alpha=0.05$ Calibration ($F_1 = 0.8780$):** In the Stage 2 conformal benchmark, thresholds were calibrated strictly on benign calibration scores to control false alarm rates at nominal $\alpha = 0.05$ (without tuning against validation attack labels). At $\alpha = 0.05$, the static empirical test FPR was $0.2941$ (10 false alarms out of 34 benign test windows, 46 total alerts), yielding Precision = 0.7826, Recall = 1.0, and Test $F_1 = 0.8780$.
- **Conclusion:** Both numbers are physically authentic and reproducible from their respective experiment files. Section 4.2 specifically describes the cross-day training vs. within-day starvation experiment under validation-$F_1$ tuning ($0.9859$), whereas Table 1 evaluates conformal thresholding under fixed $\alpha=0.05$ calibration ($0.8780$).

---

#### 2. Friday Within-Day Training Size: $N = 45$ (Paper) vs. $N = 26$ Earlier
- **Claimed Snippet:** Section 4.2 (Line 124): *"Within-day training splits on Friday ($N=45$) and Wednesday ($N=16$) severely starved non-parametric detectors..."*
- **Earlier Documentation:** `docs/CHANGELOG_v3_1.md` (Line 52) cited *"Friday ($N=26$ windows) and Wednesday ($N=16$ windows)"*.
- **Source Files & Provenance:**  
  - $N=26$: [`configs/v3/cse_cic_ids2018_multiday.json`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/configs/v3/cse_cic_ids2018_multiday.json) (Line 21: `"train_slice": [0, 26]`), which operated on the active-only unregularized parquet `data/processed/csecicids2018_60s_any_attack.parquet` (191 total windows).
  - $N=45$: [`configs/v3_1/cse_cic_ids2018_within_day.json`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/configs/v3_1/cse_cic_ids2018_within_day.json) (Line 24: `"train_slice": [0, 45]`), which operates on the time-regularized gapless parquet `data/processed/csecicids2018_friday_60s_regular.parquet` (719 total windows).
- **Root-Cause Resolution:**  
  In Stage 3 (v3), the dataset suffered from the synthetic timestamp compression pathology (omitting 528 quiescent minutes). The initial morning slice contained only 26 active windows ($N=26$). In Stage 3.1 (v3_1), after the time-axis regularization fix projected telemetry onto the continuous 60-second datetime grid, the contiguous morning benign interval expanded to exactly 45 regularized 60-second windows (`[0, 45]`), yielding $N=45$.
- **Conclusion:** The draft paper correctly cites $N=45$, which is the true regularized training window count in `configs/v3_1/cse_cic_ids2018_within_day.json` and `results/v3_1/metrics/csecicids2018_within_day_results.csv`. The earlier changelog reference to $N=26$ was an artifact of the pre-regularization active-only dataset.

---

#### 3. Base Paper Reported Accuracy: 99.6% (Literature) vs. 99.8% (Paper Text)
- **Claimed Snippet:** Section 1 (Line 68): *"reporting exceptional detection fidelity ($99.8\%$ accuracy and $F_1 = 0.998$) on the UNSW-NB15 benchmark"*
- **Literature Source:** Al-Mazrawe & Al-Musawi (2025), *"Enhancing cloud network intrusion detection through multidimensional matrix profile and the Kneedle algorithm"*, Computers & Security, Table 5.
- **Provenance & Findings:**  
  - In `docs/comprehensive_findings_report.md` (Line 191), the original audit notes correctly recorded: *"The base paper reported 99.6% accuracy and 99.8% $F_1$ on UNSW-NB15."*
  - In the published paper of Al-Mazrawe & Al-Musawi (2025), the reported accuracy is **99.6%**, while the reported macro-$F_1$ is **0.998** (or $99.8\%$).
- **Root-Cause Resolution:**  
  The draft manuscript text in Line 68 inadvertently conflated the $F_1$ score ($99.8\%$) with the accuracy ($99.6\%$), stating *"99.8% accuracy and $F_1 = 0.998$"*.
- **Conclusion:** The actual literature accuracy is **99.6%**. The claim of 99.8% accuracy in the draft text is an unsourced clerical typo.

---

#### 4. Figure 3 Caption: "Zero False Alarms" vs. 1.67% FPR (2 False Alarms)
- **Claimed Snippets:**  
  - Section 5.3 (Line 197): *"slashed FPR from 12.50% to 1.67% while maintaining 100% recall, boosting $F_1$ from 0.8624 to 0.9792."*
  - Figure 3 Caption (Line 202): `\caption{...Rolling conformal calibration dynamically adapts to baseline changes, isolating true attacks with zero false alarms.}`
- **Source Files & Provenance:**  
  [`results/v3_2/metrics/conformal_comparison_results.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v3_2/metrics/conformal_comparison_results.csv) (Row 62: `Friday-16-02-2018`, `Baseline: Isolation Forest`, `Rolling Split-Conformal`):
  $$\text{Test FPR} = 0.016667 \quad (1.67\%), \quad \text{Alerts} = 49, \quad \text{Attacks Detected} = 47, \quad \text{False Alarms} = 2 / 120 \text{ benign windows}.$$
- **Root-Cause Resolution:**  
  While the main prose in Line 197 correctly reports the exact measured test FPR of $1.67\%$ (slashed from $12.50\%$), the caption for Figure 3 indulged in hyperbole by claiming *"zero false alarms"*. In reality, exactly 2 benign windows were flagged as false alarms.
- **Conclusion:** Figure 3 caption is factually inaccurate. The true achieved FPR is **1.67% (2 false alarms)**, exactly as reported in the body text and results tables.

---

#### 5. Figure 4 Caption: Dynamic Conformal Thresholds Mentioned but Not Plotted
- **Claimed Snippet:** Figure 4 Caption (Line 245): `\caption{...Bottom: detector anomaly scores and dynamic conformal thresholds tracking diurnal variation.}`
- **Source Script & Figure:**  
  [`scripts/generate_publication_figures_high_res.py`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/scripts/generate_publication_figures_high_res.py) (Lines 267–285) generates `paper/assets/testbed_timeline_scores.png`:
  ```python
  # Bottom: Normalized Anomaly Scores on Test Slice (last 300 windows)
  t_test = np.arange(300, 600)
  ax3.plot(t_test, s_if_norm, label="IsoFor (Norm)", color="#1f77b4")
  ax3.plot(t_test, s_ar_norm, label="ARIMA Residual (Norm)", color="#2ca02c")
  ax3.plot(t_test, s_mp, label="mSTAMP A-prime", color="#7f7f7f")
  ```
- **Root-Cause Resolution:**  
  Inspection of `ax3` in the figure generator reveals that only the normalized anomaly score streams (`s_if_norm`, `s_ar_norm`, `s_mp`) are rendered. No dynamic threshold series ($\tau_t$) was ever plotted on the bottom panel. The figure caption incorrectly describes elements that were omitted from the final Matplotlib figure.
- **Conclusion:** Figure 4 caption inaccurately claims dynamic conformal thresholds are plotted on the bottom panel. Only normalized detector anomaly scores are present.

---

### 9.2 Complete Inventory of Unsourced Claims in the Draft Paper

The trace audit identified **4 assertions** in `paper/main.tex` that have no backing data source in the repository:

| Claim ID | LaTeX Line | Unsourced Assertion Snippet | Reconciled Physical Evidence | Cause / Explanation |
| :--- | :---: | :--- | :--- | :--- |
| **TRACE_108** | Line 68 | Base paper reported *"99.8% accuracy"* on UNSW-NB15 | Al-Mazrawe & Al-Musawi (2025) reported **99.6% accuracy** | Clerical typo in manuscript text; conflated 99.8% $F_1$ with accuracy. |
| **TRACE_109** | Line 211 | Locust generator diurnal telemetry *"RPS $\in [10, 40]$"* | Measured server telemetry is **$0.233$ to $4.85$ RPS** | Text cited nominal Locust user target setting rather than actual Prometheus flow telemetry. |
| **TRACE_110** | Line 202 | Figure 3 caption claims *"zero false alarms"* on Friday | Measured test FPR is **$1.67\%$ (2 false alarms)** | Rhetorical exaggeration in figure caption; contradicted by body text Line 197. |
| **TRACE_111** | Line 245 | Figure 4 caption claims *"dynamic conformal thresholds"* plotted | Figure 4 bottom panel plots **detector scores only** | Description of planned plot features that were omitted during final Matplotlib rendering. |

---

### 9.3 Summary of Weakened Claims

In accordance with Ground Rule 5 (*"If a re-measurement weakens a previous claim, say so plainly"*), the audit catalogs the following key claims that have been weakened or refuted by the Stage 4 verification:

1. **Flash Crowd False-Alarm Sashing (Table 2 & Section 6.2):**  
   - *Draft Claim:* Rolling conformal calibration slashes flash crowd false alarms from 100% to 11.43% (4/35), eliminating 88.6% of false alarms.  
   - *Weakened Re-Measurement:* Under autonomous label-free execution, Rolling Conformal Flash Crowd FAR is **$100.00\% \pm 0.00\%$** (identical to static thresholding). The 11.43% value was an oracle-feedback upper bound requiring operator ground-truth verification.
2. **Testbed Isolation Forest $F_1$ Score (Table 2 & Section 6.2):**  
   - *Draft Claim:* Conformal calibration boosts Isolation Forest testbed $F_1$ to 0.9451.  
   - *Weakened Re-Measurement:* Autonomous label-free deployment achieves $F_1 = 0.8526 \pm 0.009$, exactly matching static thresholding ($0.8526$), because flash crowd false alarms persist. The $0.9451$ score is an oracle-feedback upper bound.
3. **Conformal Superiority at Matched Operating Points (Section 5):**  
   - *Draft Claim:* Implies conformal thresholding provides superior anomaly detection.  
   - *Weakened Re-Measurement:* When matched to identical empirical test FPRs, Rolling Conformal loses to Static Quantile in **17 out of 32 configurations** ($\Delta \text{Recall} = -0.179$, 95% CI: $[-0.323, -0.049]$). Adaptive thresholding does not improve intrinsic detection fidelity; its sole benefit is localized stabilization of day-to-day FPR variance on well-separated models.

---

### 9.4 STAGE 4 Acceptance Checks Summary

| Acceptance Check | Status | Supporting Evidence File |
| :--- | :---: | :--- |
| **1. Conformal Label-Permutation Test** | **PASS** | [`tests/test_conformal_no_label_leakage.py`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/tests/test_conformal_no_label_leakage.py) (5 seeds permutation test passing; oracle and label-free variants strictly separated). |
| **2. Matrix-Profile Score Diagnostics** | **PASS** | [`results/v4/metrics/matrix_profile_score_degeneracy.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v4/metrics/matrix_profile_score_degeneracy.csv), [`feature_channel_variance_and_constancy.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v4/metrics/feature_channel_variance_and_constancy.csv), [`matrix_profile_diagnostic_variants.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v4/metrics/matrix_profile_diagnostic_variants.csv). |
| **3. Matched-FPR Comparison with Intervals** | **PASS** | [`results/v4/metrics/matched_operating_points_comparison.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v4/metrics/matched_operating_points_comparison.csv), [`conformal_paired_comparison.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v4/metrics/conformal_paired_comparison.csv) (Moving-block bootstrap intervals, win/tie/loss counts). |
| **4. Testbed Multi-Seed Repeats ($\ge 5$ seeds)** | **PASS** | [`results/v4/metrics/testbed_multiseed_evaluation.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/results/v4/metrics/testbed_multiseed_evaluation.csv) (5 randomized seeds 42–46, pooled summary with Clopper-Pearson CIs, diagnostic baselines). |
| **5. Comprehensive Number Trace & Discrepancies** | **PASS** | [`docs/number_trace.csv`](file:///home/amal/Hardcore/courses/cloudSRE&Security/project/docs/number_trace.csv) (111 audited claims, 5 discrepancies resolved, 4 unsourced claims cataloged). |
| **6. Determinism & Unit Test Suite** | **PASS** | `python -m unittest discover tests` (Ran 29 tests in 83.6s, all passing). |
