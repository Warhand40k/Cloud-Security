# CHANGELOG v3.1: Protocol Foundations, Diagnostic Audits, and Rigorous Evaluation Repairs

This document details every mathematical, architectural, and methodological modification introduced in **Stage 1.5 ("fix the evaluation foundations")** of the project:  
*Reproduction, Causal Extension, and Methodological Audit of Multidimensional Matrix Profile (mSTAMP + Kneedle) for Network Anomaly Detection.*

This changelog records the precise rationale, implementation, and empirical consequences of each repair relative to Stage 1 (`v3`).

---

### 1. Time-Axis Integrity & Regular 60-Second Resampling Grid
- **Problem Identified in v3:**  
  Timestamps in v3 were derived synthetically as `"slice start + index minutes"`, which erroneously assumed that network traffic was continuous. In reality, CSE-CIC-IDS2018 contains extensive quiescent periods:
  - On Friday-16-02-2018, the 191 active windows spanned **11.97 elapsed hours** (`01:00:00` to `12:58:00 UTC`), containing **528 empty 60-second windows** and a maximum gap of **454 minutes**.
  - Deriving timestamps by window index artificially compressed 12 hours into 3.1 hours, distorting operational rates (Alerts per Hour) and Mean Time to Detect (MTTD).
- **Protocol Repair (Stage 1.5 Step 1):**
  1. Updated `src/windowing.py` with `fill_empty_windows=True` to project all raw flows onto an explicit, gapless 60-second datetime grid (`window_dt` in ISO format). Quiescent minutes are populated with zero-count flow features.
  2. Stored the true UTC start timestamp from raw flow records in all windowed parquets:
     - `data/processed/csecicids2018_thursday_60s_regular.parquet` (720 windows, 12.0 hours)
     - `data/processed/csecicids2018_friday_60s_regular.parquet` (719 windows, 11.97 hours)
     - `data/processed/csecicids2018_wednesday_60s_regular.parquet` (529 windows, 8.8 hours)
  3. Recomputed MTTD (elapsed seconds from true campaign start to first true alert) and Alerts per Hour using true elapsed wall-clock time. Flow-level blocks omit Alerts per Hour and report strictly Alerts per 1,000 flows.

---

### 2. Chronological Ordering Assertion & Timestamp Repair
- **Problem Identified in v3:**  
  In Wednesday's slice composition in v3, the test time range (`04:40` to `05:49`) sat inside the validation time range (`04:40` to `06:03`), violating non-overlapping chronological ordering.
- **Protocol Repair (Stage 1.5 Step 1):**
  1. Redesigned all partitions on the regularized 60-second grid to guarantee strict temporal ordering:
     $$\text{Train End} < \text{Val Start} \quad \text{and} \quad \text{Val End} < \text{Test Start}$$
     - **Thursday:** Train `[0:250]` (`01:00`–`05:09`), Val `[250:558]` (`05:10`–`10:17`), Test `[558:720]` (`10:18`–`12:59`).
     - **Friday:** Train `[0:45]` (`01:00`–`01:44`), Val `[45:552]` (`01:45`–`10:11`), Test `[552:719]` (`10:12`–`12:58`).
     - **Wednesday:** Train `[0:16]` (`01:55`–`02:10`), Val `[16:459]` (`02:11`–`09:33`), Test `[459:529]` (`09:34`–`10:43`).
  2. Implemented `tests/test_chronological_time_integrity.py` which formally asserts $\text{train\_end} < \text{val\_start} < \text{test\_start}$ across all datasets and blocks.

---

### 3. Unified Campaign Accounting
- **Problem Identified in v3:**  
  Campaign counts disagreed between slice composition tables ($n=2$ per CSE day) and performance tables ($n=1$). Furthermore, CHANGELOG v3 stated Friday contained 2 campaigns in total.
- **Protocol Repair (Stage 1.5 Step 2):**
  1. Standardized on a single, shared implementation: `find_campaign_intervals(labels, g=0, clip_to_slice=True)` in `src/evaluation.py`.
  2. Clarified campaign accounting:
     - Friday contains 2 distinct campaigns in total: **SlowHTTPTest** (occurs in the Validation slice) and **Hulk** (occurs in the Test slice).
     - Because campaigns are strictly clipped to slices, the Thursday, Friday, and Wednesday test slices each contain exactly **1 attack campaign**.
  3. Added `tests/test_campaign_accounting_consistency.py` asserting bitwise equality between the campaign counts reported in `slice_composition.json` and those reported in every detector performance row.

---

### 4. Training-Set Sizing & Cross-Day Reference Design
- **Problem Identified in v3:**  
  Within-day chronological training severely starved Friday ($N=26$ windows) and Wednesday ($N=16$ windows). For subsequence length $m=10$, an $N=16$ history contains only 7 subsequences, starving matrix profile libraries and causing statsmodels ARIMA(1,0,1) optimization to fail with numerical convergence warnings. Consequently, detector rankings flipped radically between splits.
- **Protocol Repair (Stage 1.5 Step 3):**
  1. Enforced minimum training dataset constraints via automated assertions:
     $$\text{Benign Training Windows} \ge 100, \quad \text{Subsequences} \ge 10 \times m, \quad \text{ARIMA Fit} \ge 100\text{ points}$$
  2. Introduced the **Primary Design ("Cross-Day Reference")**:
     - Friday 16 and Wednesday 21 use Thursday 15 pure morning benign traffic ($N=507$ windows, 00:00–08:27 UTC) as their training/reference library.
     - Thursday 15 uses its own morning benign traffic ($N=250$ windows).
     - Scalers are fitted strictly on the reference data (`tests/test_scaler_leakage.py` asserts zero leakage).
  3. Retained the **Secondary Design ("Within-Day Sensitivity")** ($N=45$ for Friday, $N=16$ for Wednesday) as a sensitivity analysis.
  4. Demonstrated ranking reversals: Under within-day starvation, Isolation Forest scored $F_1 = 0.0000$ on Wednesday (Rank 5); under cross-day reference ($N=507$), it surged to Rank 1 tied with ARIMA at $F_1 = 0.9859$. Rankings among non-trivial detectors are sensitive to reference sizing.

---

### 5. One Shared Threshold Rule & Elimination of Label-Tuned Thresholds
- **Problem Identified in v3:**  
  In v3, thresholds were calibrated to maximize validation $F_1$. When validation prevalence was low and scores compressed at zero, validation-$F_1$ optimization degenerated into a flag-everything rule ($\tau^* = 0.0$). Furthermore, optimizing validation $F_1$ leaked ground-truth attack labels into the threshold calibration phase.
- **Protocol Repair (Stage 1.5 Step 4):**
  1. Standardized all detectors on a single, shared, label-free calibration rule: `calibrate_benign_quantile_threshold` in `src/adaptive_threshold.py`.
  2. Calibrated decision thresholds strictly on **held-out benign validation scores** to enforce a pre-specified False Alarm Rate $\alpha \in \{0.05, 0.01\}$:
     $$\tau = \text{Quantile}(S_{\text{val, benign}}, 1 - \alpha)$$
  3. Implemented a **point-mass tie adjustment**: when an empirical score point mass (e.g., zeros) causes $\text{Quantile}(1-\alpha)$ to flag $> \alpha$ benign instances, the threshold steps up to $\tau + 10^{-6}$ to strictly enforce $\text{FAR} \le \alpha$.
  4. Standardized reporting order: **Threshold-free metrics (ROC-AUC, PR-AUC, PR-AUC Lift) are reported first**, followed by fixed-$\alpha$ operating points.
  5. Added an $\epsilon = 10^{-6}$ floor to `MADThreshold` ($T_t = \text{Median} + c \cdot \max(\text{MAD}, 10^{-6})$) to prevent collapse when local MAD is zero.
  6. Updated `experiments/run_matched_operating_points.py` with one-sided FPR matching and audited zero-recall detectors as `"unmatched (zero recall)"`, eliminating 58 vacuous matches.

---

### 6. Mathematical Saturation Diagnosis & Refutation of Stale Reference Hypothesis
- **Problem Identified in v3:**  
  Earlier reports asserted that Config A-prime and B1 collapsed to 100% false alarms on UNSW Flow Contiguous Block and Regime Shift Demo because of "stale reference libraries across the 26-day batch boundary".
- **Empirical Refutation & True Root Causes (Stage 1.5 Step 5):**
  1. Evaluated `experiments/run_saturation_diagnosis_v3_1.py`:
     - UNSW Flow Contiguous Block is located **entirely within Batch 1**, only 107 seconds after the training data (zero 26-day gap, minimal scaler drift). Yet A-prime still saturated to 100% false alarms in v3. The "stale reference" hypothesis is refuted.
  2. Proved true mathematical causes:
     - Config A-prime had **99.73% zero scores** in benign validation. Validation-$F_1$ optimization selected $\tau = 0.000000$, flagging all test flows.
     - Config B1 had **100.0% zero MAD** on UNSW Regime Shift Demo, causing threshold collapse to the local median ($T_t = \text{Median} + 0$).
  3. Demonstrated empirical cure: Under the Step-4 benign quantile rule with $\epsilon = 10^{-6}$ MAD floor, saturation completely disappeared:
     - UNSW Flow Block A-prime FPR dropped from 100.0% to **0.57%** (12 alerts).
     - UNSW Regime Shift Demo A-prime FPR dropped from 100.0% to **0.00%** (0 alerts).

---

### 7. Paired Persistence Filtering Protocol & Refutation of Claim #8
- **Problem Identified in v3:**  
  Earlier claims suggested that persistence filtering ($k \ge 2$) reduced alert volume without operational penalty, but variants were evaluated under differing thresholds and across different parent models.
- **Protocol Repair & Empirical Truth (Stage 1.5 Step 6):**
  1. Implemented `experiments/run_paired_persistence_analysis_v3_1.py`:
     - Evaluated all 4 parents (A, A-prime, B1, B2) across all 5 evaluation blocks and all $k \in \{1, 2, 3, 4, 5\}$ on the **exact same parent score stream and identical threshold** ($\alpha = 0.05$).
  2. Evaluated 80 pairs where $k > 1$:
     - **Hurt Test $F_1$:** 54 / 80 (67.5%)
     - **Neutral:** 24 / 80 (30.0%)
     - **Helped:** 2 / 80 (2.5%) (marginal $+0.0178$ on Thursday Config A, accompanied by recall drop and MTTD increase).
  3. Validation selected $k^* = 1$ in **16 of 20 configurations (80.0%)**. In all 4 cases where validation chose $k^* > 1$, test $F_1$ degraded on test.
  4. Formally rewrote Claim #8: *"Persistence filtering does not provide general benefit on these datasets; it was an artifact of comparing mismatched baselines."*

---

### 8. Multi-Block Flow Evaluation Protocol
- **Problem Identified in v3:**  
  Flow-level performance in v3 was based on a single 8,000-flow slice of Batch 1 where prevalence was 11.69% and the naive All-Attack baseline scored $F_1 = 0.2093$.
- **Protocol Repair (Stage 1.5 Step 6):**
  1. Implemented `experiments/run_unsw_multiblock_flow_v3_1.py`:
     - Evaluated **10 contiguous, non-overlapping blocks of 8,000 flows** (80,000 flows total) across Batch 1 (`UNSW-NB15_1.csv`).
     - Evaluated each detector across all 10 blocks (4,000 train, 1,600 val, 2,400 test flows per block).
  2. Empirical Outcomes:
     - Baseline All-Attack mean $F_1 = 0.1281 \pm 0.0406$.
     - Config A mean $F_1 = 0.0866$, Config A-prime mean $F_1 = 0.0523$, Config B1 mean $F_1 = 0.0791$, Config B2 mean $F_1 = 0.1246$. All matrix profile methods beat All-Attack on at most 2 of 10 blocks.
     - Baseline ARIMA Residual (mean $F_1 = 0.3720$, ROC-AUC $0.9368$) and Isolation Forest (mean $F_1 = 0.2496$, ROC-AUC $0.9293$) beat All-Attack on 9/10 and 7/10 blocks.
  3. Methodological Finding: Flow-level network anomaly detection using matrix-profile methods is **not supported by empirical evidence**.

---

### 9. Pre-Registered Stage 2 Fusion Gate Outcome
- **Pre-Registration (Stage 1.5 Step 7):**  
  Pre-registered in `docs/stage2_gate.md` prior to computation: Dual-stream fusion of A-prime and ARIMA is justified if an oracle-OR combiner raises recall by $\ge +0.10$ absolute over the better single detector while keeping $\text{FPR} \le 0.05$ on $\ge 50\%$ of benchmark blocks.
- **Empirical Computation:**  
  Across all 5 benchmark blocks, oracle-OR combiner achieved **0 / 5 blocks (0.0%)** meeting the criterion. Detections were non-overlapping subsets ($\Delta \text{Recall} = 0.0000$ everywhere), and the OR combiner amplified false alarms (e.g. Friday FPR inflated to 29.17%).
- **Decision:** **`NO-GO`**. Dual-stream OR fusion of A-prime and ARIMA is rejected.

