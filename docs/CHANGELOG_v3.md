# CHANGELOG v3: Methodological Decisions, Audit Findings & Protocol Fixes

This document details every mathematical, algorithmic, and evaluation decision in this project that differs from, audits, or repairs the protocol of the base paper:  
*Al-Mazrawe & Al-Musawi (2025), "Enhancing Cloud Network Security with Innovative Time Series Analysis", Journal of Internet Services and Applications (JISA).*

This v3 changelog supersedes the v2 notes and reflects the full core repair implemented in Stage 1.

---

### 1. Subsequence Alignment & Causal Indexing
- **Base Paper Description:** The paper's description is consistent with an underspecified subsequence alignment. Subsequences of length $m$ span $[t, t+m-1]$. Centered or left-aligned indexing accesses future observations within the sliding window, introducing look-ahead data leakage.
- **Our Decision (Stage 1):** Implemented strict **causal right-alignment** ($t_{\text{score}} = t_{\text{end}} = i + m - 1$). An anomaly score assigned to time $t$ uses exclusively observations up to and including $t$. Boundary prefix steps ($t < m - 1$) are causally padded with the first available valid window score. Unit tests in `tests/test_causal_ab_scorer.py` verify that scores at time $t$ do not change when future samples $t' > t$ are truncated or modified.

---

### 2. Causal Benign-Reference Scorer (Config A-prime) vs. Symmetric Self-Join (Config A)
- **Base Paper Description:** The paper's description is consistent with computing symmetric self-join matrix profiles (`stumpy.mstump`) across the evaluation stream.
- **Our Audit & Discovery:** Diagnostic testing proved that in symmetric self-joins over a stream containing test data:
  1. **50.0% of nearest-neighbor indices in test data point to future time steps**, and **48.0% of test scores change** when future data is truncated.
  2. Sustained or repeated attacks match themselves, causing **motif collapse** (anomalous distances drop toward zero as attacks repeat; ROC-AUC collapses from 0.74 to 0.02).
- **Our Decision (Stage 1):** We designed and implemented **Config A-prime (`src/causal_ab_scorer.py`)**, which computes 1D AB-joins (`stumpy.stump(A, m, B)`) against a static benign training library $B$, sorting and averaging the $k$ smallest dimensions to mirror mSTAMP without future dependence.
- **Critical Limitation Identified in v3:** When deployed across long time horizons or non-stationary data (e.g. UNSW Batch 2, recorded 26 days after Batch 1), Config A-prime flags 100% of windows as discords against the stale Batch 1 reference, matching the trivial All-Attack baseline ($F_1 = 0.9975$). Furthermore, on real flow data with high natural variance, Config A-prime saturates without beating Config A. Config A-prime provides true causal ranking quality but requires dynamic reference updating (Stage 2) to prevent saturation.

---

### 3. Threshold Calibration, Anti-Self-Matching & Anti-Leakage Protocol
- **Base Paper Description:** The paper's description is consistent with unspecified threshold selection (it does not document threshold formulas, calibration data, or operating trade-offs).
- **Our Decision (Stage 1):**
  1. **Strict Held-Out Calibration:** Decision thresholds are **strictly forbidden from reading test labels or test data**.
  2. **Anti-Self-Matching Fix for A-prime:** Training windows scored against their own library ($A=B$) yield near-zero distances (100% zero scores with STUMPY `ignore_trivial=False`). We audited and enforced that Config A-prime thresholds are fitted exclusively on **held-out benign validation scores** ($A \neq B$), preventing threshold collapse.
  3. **Leakage Verification:** Implemented `tests/test_no_label_leakage.py` asserting bit-identical scores, thresholds, and alert sequences under 5 random test-label permutations.

---

### 4. Partition Chronology & Non-Overlapping Repair
- **Prior Flaw in v2:** Slices for Friday-16-02-2018 (`val [0, 30] / train [30, 85]`) and Wednesday-21-02-2018 (`val [0, 39] / train [39, 100]`) reversed chronological order (validation occurred before training).
- **Our Repair (Stage 1 Step 1):** Redesigned all partitions to be strictly chronological: $\text{Train} < \text{Val} < \text{Test}$, with zero overlap:
  - **Thursday-15-02-2018:** Train `[0, 250]`, Val `[250, 410]`, Test `[410, 572]`.
  - **Friday-16-02-2018:** Train `[0, 26]`, Val `[26, 85]`, Test `[85, 191]`.
  - **Wednesday-21-02-2018:** Train `[0, 16]`, Val `[16, 100]`, Test `[100, 170]`.
  - **UNSW Flow Block:** Train `[0, 4800]`, Val `[4800, 6400]`, Test `[6400, 8000]`.
  - **Correction Regarding Friday Slice:** The earlier 175-vs-191 Friday window discrepancy was our own hard-coded slice in early v2 configs, not an upstream data truncation. The full 191-window sequence is now fully utilized.

---

### 5. UNSW Batch 1 / Batch 2 Boundary & Slice Renaming
- **Audit Findings:** Audited the exact boundary between UNSW-NB15 Batch 1 and Batch 2 in the 10-second window dataset. The boundary falls precisely between window index 4443 (`2015-01-22 23:32:00 UTC`) and 4444 (`2015-02-18 00:23:20 UTC`), an unrecorded 26.0-day gap.
- **Protocol Repair:**
  - Renamed the block formerly called "Realistic Proportion" to **"UNSW Window Small Regime-Shift Block"** (`[4000:4470]` val, `[4470:4535]` test).
  - Explicitly documented that this slice crosses the 26-day batch boundary, has 69.23% test prevalence over only 65 test windows, and contains 1 campaign. **No scientific conclusions regarding general detector performance are drawn from this block.**
  - Added the **UNSW Flow Contiguous Block** (8,000 contiguous flows strictly inside Batch 1) as the primary benchmark for flow-level evaluation.

---

### 6. Single Unified Definition of "Campaign" & SRE Operational Metrics
- **Protocol Repair:** Defined "attack campaign" once in `src/evaluation.py` via `find_campaign_intervals` with $g=0$ (strictly contiguous attack-positive time steps, with zero intervening normal steps).
- **Reconciliation:** Reconciled earlier reporting of "5 Friday episodes" vs. the actual 2 Friday campaigns (Hulk and SlowHTTPTest). In raw Friday data, exactly 2 attack campaigns exist.
- **Reporting Rules:**
  - Campaign recall is always reported as the exact ratio ($k/n$) with exact **Clopper-Pearson 95% binomial confidence intervals**.
  - MTTD (Mean Time to Detect) is reported **only for detected campaigns**, labeled `"detected campaigns only"`.
  - Omitted `Alerts_Per_Hour` for flow-level blocks (where the test slice spans ~60 seconds); operational volume is reported as **Alerts per 1,000 flows** (`Alerts_Per_1000_Events`). `Alerts_Per_Hour` is retained exclusively for window blocks.

---

### 7. Config Identity & Persistence Filter Disambiguation (Config C)
- **Anomaly in v2:** In v2 tables, "Config C (B1, k=1)" had an $F_1$ of 0.7467 while B1 had 0.6397, despite $k=1$ theoretically being an identity filter.
- **Root Cause:** A reporting artifact in v2 scripts where dynamic selection picked B2 on Friday and macro averaging across days masked mismatched keys.
- **Our Repair:**
  - Explicitly named all persistence variants by their exact parent: `Config C (B1, k)`, `Config C (B2, k)`, `Config C (A-prime, k)`.
  - Added unit tests (`tests/test_persistence_filter.py`) mathematically asserting that for any binary sequence $y$, $\text{Filter}_{k=1}(y) \equiv y$. Bit-identical equality was verified across all metrics and alert sequences ($F_1 = 0.07052$, ROC-AUC = 0.60002 on CSE multi-day).

---

### 8. Honest Matched-Operating-Point Evaluation
- **Prior Flaw in v2:** V2 selected thresholds by reading test labels (`y_true == 1` in test parquet), violating anti-leakage principles.
- **Our Repair (Stage 1 Step 3):**
  - **Variant (a) VALIDATION-SELECTED:** Thresholds for target recall (0.80, 0.50) and target FPR (0.05, 0.01) are chosen strictly on validation data. Achieved test metrics are reported honestly. A row is labeled `"matched"` if and only if test recall/FPR is within $\pm 0.05$ of target; otherwise labeled `"target not reached"`. Score ties preventing target FPR are explicitly recorded as `"target unreachable on validation (score ties)"`.
  - **Variant (b) EVALUATION-ONLY OPERATING CURVES:** Test-set operating curves (Alerts/1,000 events vs. Recall and vs. FPR) were plotted and archived (`results/v3/figures/matched_curves_*.png`).

---

### 9. Validation-Selected Subsequence Length Sensitivity ($m$)
- **Prior Protocol:** Prior $m$-sensitivity reported test metrics without an explicit validation selection step.
- **Our Repair:** Re-ran $m \in [5, 10, 20, 30, 50, 75, 100]$ on UNSW Flow. Selected $m^* = 5$ strictly based on validation $F_1$ ($\text{Val } F_1 = 0.2965$), reporting achieved test metrics ($F_1 = 0.3770$ [0.3120, 0.4369]) with Moving-Block Bootstrap CIs in `results/v3/metrics/sensitivity_m.csv`.

---

### 10. Audit of Base Paper Claims & Prevalence Sensitivity
- **Wording Correction:** The base paper does NOT report test prevalence for its evaluation slices. The claim that the "base paper evaluated on saturated slices" is updated to:
  > *"Unverified; our regime-shift demonstration block shows All-Attack reaches F1 0.9975, which is one plausible explanation for near-perfect scores."*  
  Status: **UNVERIFIED**.
- **Trivial Baseline Benchmark:** Every results table now includes `Baseline: All-Attack`, `Baseline: All-Normal`, `Baseline: Random Uniform`, and `Baseline: Random Stratified`, along with `Beats_All_Attack_F1` and `PR_AUC_Lift`. On Friday (prevalence 44.34%) and Wednesday (prevalence 51.43%), zero models beat All-Attack $F_1$. Models only beat All-Attack on Thursday (prevalence 26.54%) and UNSW Flow (prevalence 11.69%).

