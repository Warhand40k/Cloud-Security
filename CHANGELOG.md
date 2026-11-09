# CHANGELOG: Methodological Decisions Differing from Base Paper

This document details every mathematical, algorithmic, and evaluation decision in this project that differs from or extends the base paper:  
*Al-Mazrawe & Al-Musawi (2025), "Enhancing Cloud Network Security with Innovative Time Series Analysis", Journal of Internet Services and Applications (JISA).*

---

### 1. Subsequence Alignment & Causal Indexing
- **Base Paper:** Underspecified subsequence alignment. Subsequences of length $m$ span $[t, t+m-1]$. Centered or left-aligned indexing accesses future observations within the sliding window, introducing data leakage.
- **Our Decision:** Implemented strict **causal right-alignment** ($t_{\text{score}} = t_{\text{end}} = i + m - 1$). An anomaly score assigned to time $t$ uses only observations up to and including $t$. Boundary prefix steps ($t < m - 1$) are causally padded with the first available valid window score.

---

### 2. Causal Benign-Reference Scorer (Config A-prime) vs. Symmetric Self-Join (Config A)
- **Base Paper:** Computed symmetric self-join matrix profiles (`stumpy.mstump`) over the combined evaluation stream.
- **Our Discovery & Decision:** Diagnostic testing proved that in symmetric self-joins, **50.0% of nearest-neighbor indices in test data point to future time steps**, and **48.0% of test scores change** when future data is truncated. Furthermore, sustained or repeated attacks match themselves, causing **motif collapse** (ROC-AUC drops from 0.74 to 0.02). We designed and implemented **Config A-prime (`src/causal_ab_scorer.py`)**, which computes 1D AB-joins (`stumpy.stump(A, m, B)`) against a static benign training library $B$, sorting and averaging the $k$ smallest dimensions to mirror mSTAMP without future dependence.

---

### 3. Threshold Calibration & Anti-Leakage Protocol
- **Base Paper:** Did not specify how continuous distance scores were converted to binary attack alerts (implied post-hoc thresholding or evaluation on saturated attack slices).
- **Our Decision:** Decision thresholds are **strictly forbidden from reading test labels**. Thresholds are fitted on benign training/validation scores using target false-alarm rates (FAR) or tuned on validation splits whose metrics are evaluated independently of the held-out test split.

---

### 4. Adaptive Thresholding Layers (Configs B1 & B2)
- **Base Paper:** Relied solely on raw matrix profile distances.
- **Our Decision:** Introduced two adaptive thresholding mechanisms:
  1. **Config B1 (Adaptive Rolling MAD):** $T_t = \text{Median}(S) + c \cdot (1.4826 \cdot \text{MAD}(S))$ computed causally over rolling history window $W$.
  2. **Config B2 (Adaptive EVT POT):** Extreme Value Theory Peaks-Over-Threshold fitting a Generalized Pareto Distribution (GPD) on extreme score excesses with $\ge 30$ tail excesses above quantile $u$. Evaluated empirical calibration on held-out benign data.

---

### 5. Persistence Filtering Layer (Config C)
- **Base Paper:** Dispatched alerts instantaneously on single-window score excursions.
- **Our Decision:** Introduced temporal persistence filtering requiring $k$ consecutive anomalous windows before raising an incident alert. Swept $k \in [1..5]$ with $k^*$ chosen strictly on validation splits. Explicitly named variants by threshold and parameter (e.g. `C(B1, k=2)`, `C(B2, k=1)`).

---

### 6. Kneedle Curvature & Direction Parameterization
- **Base Paper:** Cited Kneedle conceptually without specifying curve concavity, direction, or online settings.
- **Our Decision:** Empirically verified that the dimension-wise maximum matrix profile curve passed to `KneeLocator` is monotonically increasing ($\Delta y > 0$) and concave ($\Delta^2 y < 0$). Configured `curve="concave", direction="increasing", online=True`. Added unit tests verifying known knee points (`tests/test_kneedle.py`).

---

### 7. Evaluation Protocol, Splits & Operational SRE Metrics
- **Base Paper:** Evaluated predominantly on Batch 2 saturation slices (where test prevalence exceeds 99%), reporting accuracy >99% and omitting operational SRE metrics.
- **Our Decision:**
  1. **Multi-Day Rolling-Origin Evaluation:** Evaluated across three full days of CSE-CIC-IDS2018 (Thursday 15, Friday 16, Wednesday 21), ensuring both classes are present in validation and test splits, and restoring the full 191 Friday windows (fixing upstream 175-window truncation).
  2. **Realistic Proportion Blocks:** Evaluated UNSW-NB15 with realistic class proportions, categorizing the old Batch 2 saturation run strictly as a labeled "Regime Shift Demonstration".
  3. **Operational Metrics:** Simultaneously reported ROC-AUC, PR-AUC, Prevalence, PR-AUC Lift, Precision, Recall, $F_1$, FPR, Campaign Recall next to MTTD (detected campaigns only), total campaign counts, alerts/1,000 windows, and alerts/hour.
  4. **Uncertainty Quantification:** Moving-Block Bootstrap (MBB, $B=m$, 500 resamples) preserving temporal autocorrelation.
  5. **Matched-Operating-Point Comparison:** Evaluated alert volume at matched recall (0.80 and 0.50) and matched FPR (0.01 and 0.05).
