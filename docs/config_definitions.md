# Configuration Definitions & Score Provenance Specification

This document provides the definitive specification of every detector configuration and baseline evaluated across UNSW-NB15 and CSE-CIC-IDS2018 in Stage 1. For each model, it documents the anomaly scoring function, the training and threshold calibration protocol, the data and label requirements, and temporal persistence filtering parameters.

---

## 1. Summary Matrix of Model Configurations

| Configuration Name | Model Role | Anomaly Score Source | Threshold Source & Calibration Split | Labels Used for Threshold? | Persistence Filter Applied |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **Config A** | Paper Reproduction | Symmetric Self-Join mSTAMP (`stumpy.mstump`) | Validation Percentile Sweep ($p \in [80, 99.8]$) on `scores_val_a` | Yes ($F_1$ on $y_{val}$) | No ($k=1$) |
| **Config A-prime** | Causal Extension | Causal AB-Join (`stumpy.stump(A, m, B)`) against benign history $B$ | Validation Percentile Sweep on held-out `scores_val_aprime` | Yes ($F_1$ on $y_{val}$) | No ($k=1$) |
| **Config B1** | Adaptive Extension | Config A scores ($S_t^A$) | Adaptive Rolling MAD ($W \in [5, 20]$); multiplier $c$ tuned on validation | Yes ($F_1$ on $y_{val}$) | No ($k=1$) |
| **Config B2** | Adaptive Extension | Config A scores ($S_t^A$) | Extreme Value Theory POT (GPD tail, $q=0.80$); risk $p$ tuned on validation | Yes ($F_1$ on $y_{val}$) | No ($k=1$) |
| **Config C (B1, k)** | Temporal Extension | Config A scores ($S_t^A$) | Inherits Config B1 threshold; persistence $k \in [1..5]$ tuned on validation | Yes ($F_1$ on $y_{val}$) | **Yes ($k=k^*$ consecutive)** |
| **Config C (B2, k)** | Temporal Extension | Config A scores ($S_t^A$) | Inherits Config B2 threshold; persistence $k \in [1..5]$ tuned on validation | Yes ($F_1$ on $y_{val}$) | **Yes ($k=k^*$ consecutive)** |
| **Config C (A-prime, k)** | Temporal Extension | Config A-prime scores ($S_t^{A'}$) | Inherits Config A-prime threshold; persistence $k \in [1..5]$ tuned on validation | Yes ($F_1$ on $y_{val}$) | **Yes ($k=k^*$ consecutive)** |
| **Baseline: ARIMA Residual** | ML Baseline | Mean absolute 1-step forecast residual from ARIMA(1,0,1) | Validation Percentile Sweep ($p \in [80, 99.8]$) on validation residuals | Yes ($F_1$ on $y_{val}$) | No ($k=1$) |
| **Baseline: Isolation Forest** | ML Baseline | Inverted anomaly score from 100 isolation trees | Validation Percentile Sweep ($p \in [80, 99.8]$) on validation scores | Yes ($F_1$ on $y_{val}$) | No ($k=1$) |
| **Baseline: All-Attack** | Trivial Sanity Check | Constant $S_t = 1.0$ | None (unconditional $\hat{y}_t = 1$) | None | None |
| **Baseline: All-Normal** | Trivial Sanity Check | Constant $S_t = 0.0$ | None (unconditional $\hat{y}_t = 0$) | None | None |
| **Baseline: Random Uniform** | Trivial Sanity Check | $S_t \sim \text{Uniform}(0, 1)$ | $\hat{y}_t \sim \text{Bernoulli}(0.5)$ | None | None |
| **Baseline: Random Stratified**| Trivial Sanity Check | $S_t \sim \text{Uniform}(0, 1)$ | $\hat{y}_t \sim \text{Bernoulli}(\pi_{train})$, $\pi_{train} = \text{mean}(y_{train})$ | Training labels only | None |

---

## 2. Detailed Algorithmic Specifications

### 2.1 Config A: Multidimensional Matrix Profile (mSTAMP + Kneedle)
- **Role:** Direct reproduction of the core unsupervised architecture in Al-Mazrawe & Al-Musawi (2025).
- **Anomaly Score Formulation:**
  Evaluates the entire concatenated stream $X_{\text{full}} = [X_{\text{train}}; X_{\text{val}}; X_{\text{test}}]$ using STUMPY multidimensional matrix profile:
  $$(\text{mps}, \text{indices}) = \text{stumpy.mstump}(X_{\text{full}}^T, m)$$
  For each subsequence $i$, dimension-wise distances are sorted ascendingly $\text{mps}_{(1), i} \le \text{mps}_{(2), i} \le \dots \le \text{mps}_{(D), i}$.
  The elbow/knee dimension $k^*$ is identified using `find_knee_dimension` with Kneedle parameters (`curve="concave", direction="increasing", online=True, metric="max"`) evaluated strictly on the reference prefix $(\le n_{\text{train}} + n_{\text{val}} - m + 1)$.
  Subsequence scores are mapped to causal point anomaly scores using right alignment ($t = i + m - 1$):
  $$S_t = \frac{1}{k^*} \sum_{d=1}^{k^*} \text{mps}_{(d), t - m + 1}$$
  Prefix steps ($t < m - 1$) are causally padded with $S_{m-1}$.
- **Threshold Calibration:**
  Extracted validation slice $S_{\text{val}} = S[n_{\text{train}} : n_{\text{train}} + n_{\text{val}}]$.
  Sweeps 80 linearly spaced percentiles $p \in [80.0, 99.8]$ of $S_{\text{val}}$.
  Selects the threshold $T^* = \text{percentile}(S_{\text{val}}, p^*)$ that maximizes validation $F_1(y_{\text{val}}, \mathbb{I}(S_{\text{val}} \ge T))$.
  Test decision rule: $\hat{y}_{\text{test}}[t] = \mathbb{I}(S_{\text{test}}[t] \ge T^*)$.
- **Persistence:** None ($k=1$).

---

### 2.2 Config A-prime: Causal Benign-Reference AB-Join Scorer
- **Role:** Causal extension eliminating the future-dependence and motif collapse identified in Config A's symmetric self-join.
- **Anomaly Score Formulation:**
  Extracts pure benign reference library $B = X_{\text{train}}[y_{\text{train}} == 0]$.
  For any evaluation series $A$ (validation $X_{\text{val}}$ or test $X_{\text{test}}$), computes 1D AB-joins against $B$ without allowing cross-series future comparisons:
  $$\text{stump\_out}_d = \text{stumpy.stump}(T_A = A[:, d], m = m, T_B = B[:, d], \text{ignore\_trivial} = \text{False})$$
  Distances are sorted ascendingly across features at each time step, and the mean of the $k^*$ smallest dimensions is computed to mirror mSTAMP:
  $$S_t^{A'} = \frac{1}{k^*} \sum_{d=1}^{k^*} \text{mps}_{(d), t - m + 1}^{\text{AB}}$$
  Nearest neighbors are strictly constrained to past benign training data $B$. Future observations in $A$ are never accessed.
- **Threshold Calibration & Anti-Self-Matching Verification:**
  Threshold calibration is performed on **held-out validation scores**:
  $$S_{\text{val}}^{A'} = \text{aprime\_scorer.score}(X_{\text{val}})$$
  *Audit Requirement:* $X_{\text{val}}$ is disjoint from $B = X_{\text{train\_benign}}$.
  When scoring $B$ against $B$ (self-scoring), 100.0% of distances are identically $0.0000$ due to self-matches.
  On held-out validation data, benign distances are non-trivial ($1.04 \le S_{\text{val}}^{A'} \le 1.90$).
  Threshold $T^*$ is selected by sweeping percentiles $p \in [80.0, 99.8]$ of $S_{\text{val}}^{A'}$ to maximize validation $F_1(y_{\text{val}}, \mathbb{I}(S_{\text{val}}^{A'} \ge T))$.
- **Persistence:** None ($k=1$).

---

### 2.3 Config B1: Adaptive Rolling Median Absolute Deviation (MAD)
- **Role:** Dynamic adaptive thresholding extension accounting for local variance drift.
- **Anomaly Score Formulation:**
  Operates on the matrix profile anomaly scores $S_t$ from Config A.
- **Threshold Calibration:**
  Causally maintains a rolling history buffer of length $W = \min(20, \max(5, n_{\text{val}} // 2))$ over incoming stream scores:
  $$T_t = \text{Median}_W(S) + c \cdot (1.4826 \cdot \text{MAD}_W(S))$$
  The baseline statistics are initialized on benign score history ($S_{\text{train}}[y_{\text{train}}==0]$ concatenated with $S_{\text{val}}[y_{\text{val}}==0]$).
  The multiplier $c^*$ is selected on the validation split by sweeping candidate multipliers $c \in \{1.5, 2.0, 2.5, 3.0, 3.5\}$ to maximize validation $F_1$.
  Test alert rule: $\hat{y}_{\text{test}}[t] = \mathbb{I}(S_{\text{test}}[t] \ge T_t)$.
- **Persistence:** None ($k=1$).

---

### 2.4 Config B2: Adaptive Extreme Value Theory Peaks-Over-Threshold (EVT-POT)
- **Role:** Semi-parametric extreme value thresholding extension modeling extreme tail risk.
- **Anomaly Score Formulation:**
  Operates on the continuous matrix profile scores $S_t$ from Config A.
- **Threshold Calibration:**
  Fits an EVT Generalized Pareto Distribution (GPD) on extreme excesses above the high quantile $u = \text{quantile}(S_{\text{benign}}, q=0.80)$ over benign score history, requiring $\ge 30$ excesses.
  Analytical threshold for target risk $p$:
  $$T(p) = u + \frac{\hat{\sigma}}{\hat{\gamma}} \left( \left( \frac{N_t}{N_{\text{excess}}} \frac{1}{p} \right)^{\hat{\gamma}} - 1 \right)$$
  Nominal risk level $p^* \in \{0.10, 0.05, 0.02, 0.01, 0.005, 0.001\}$ is selected on the validation split by evaluating the alert sequence $\mathbb{I}(S_{\text{val}} \ge T(p))$ against $y_{\text{val}}$ to maximize validation $F_1$.
- **Persistence:** None ($k=1$).

---

### 2.5 Config C: Temporal Persistence Filtering Layer
- **Role:** SRE operational layer suppressing isolated transient single-window alerts.
- **Naming Rule:** Every persistence variant is **strictly named by its parent detector and parameter**:
  - `Config C (B1, k=k*)`: Persistence filter applied to Config B1 alerts.
  - `Config C (B2, k=k*)`: Persistence filter applied to Config B2 alerts.
  - `Config C (A-prime, k=k*)`: Persistence filter applied to Config A-prime alerts.
  The bare term "Config C" is deprecated and prohibited in all reporting.
- **Algorithmic Definition:**
  Given an underlying binary alert stream $a_t \in \{0, 1\}$ produced by a parent configuration:
  $$\hat{y}_t = \mathbb{I}\left( \sum_{j=0}^{k-1} a_{t-j} = k \right)$$
  Once triggered, ongoing contiguous alarms continue firing until the raw alarm returns to 0.
- **Threshold Calibration & Parameter Selection:**
  The parent's decision threshold is calibrated first on validation data.
  The persistence parameter $k^* \in \{1, 2, 3, 4, 5\}$ is selected by filtering the parent's validation alerts and selecting $k^*$ that maximizes validation $F_1$.
- **Identity Property at $k=1$:**
  When $k=1$, `PersistenceFilter(k=1)` is a pure identity mapping ($\hat{y}_t \equiv a_t$).
  All prediction arrays, classification metrics ($F_1$, Precision, Recall, FPR), operational SRE metrics (MTTD, alerts/1,000 windows, alerts/hr), and confidence intervals are mathematically and bit-for-bit identical to the parent model. Verified by unit tests (`tests/test_persistence_filter.py`).

---

### 2.6 Machine Learning Baselines

#### Baseline: ARIMA Residual
- **Score Formulation:**
  For each feature dimension $d \in \{1 \dots D\}$, fits an autoregressive moving average model $\text{ARIMA}(1, 0, 1)$ on training observations $X_{\text{train}}[:, d]$.
  Forecasts one-step-ahead $\hat{X}_{t, d} = \mathbb{E}[X_{t, d} \mid X_{<t, d}]$.
  Anomaly score is the mean absolute residual across features:
  $$S_t^{\text{AR}} = \frac{1}{D} \sum_{d=1}^D |X_{t, d} - \hat{X}_{t, d}|$$
- **Threshold Calibration:**
  Computes validation residuals $S_{\text{val}}^{\text{AR}}$.
  Sweeps percentiles $p \in [80.0, 99.8]$ of $S_{\text{val}}^{\text{AR}}$ to select $T^*$ maximizing validation $F_1$ against $y_{\text{val}}$.
- **Persistence:** None ($k=1$).

#### Baseline: Isolation Forest
- **Score Formulation:**
  Fits an ensemble of 100 isolation trees (`sklearn.ensemble.IsolationForest(n_estimators=100, random_state=42)`) on $X_{\text{train}}$ in an unsupervised manner (no labels used).
  Point anomaly score is inverted decision function:
  $$S_t^{\text{IF}} = -\text{score\_samples}(X_t)$$
  Higher scores correspond to anomalous points with shorter average tree path lengths.
- **Threshold Calibration:**
  Computes validation scores $S_{\text{val}}^{\text{IF}}$.
  Sweeps percentiles $p \in [80.0, 99.8]$ of $S_{\text{val}}^{\text{IF}}$ to select $T^*$ maximizing validation $F_1$ against $y_{\text{val}}$.
- **Persistence:** None ($k=1$).

---

### 2.7 Trivial Baselines (Sanity & Prevalence Calibration)
- **All-Attack:**
  - Prediction: $\hat{y}_t = 1$ unconditionally.
  - Score: $S_t = 1.0$.
  - Purpose: Provides the exact theoretical upper bound on Recall (1.0) and lower bound on FPR (1.0). Serves as the benchmark $F_1$ ceiling that every non-trivial detector must surpass to prove meaningful discrimination under high attack prevalence.
- **All-Normal:**
  - Prediction: $\hat{y}_t = 0$ unconditionally.
  - Score: $S_t = 0.0$.
  - Purpose: Lower bound on false alarm volume (0 alerts, 0 FPR).
- **Random Uniform:**
  - Prediction: $\hat{y}_t \sim \text{Bernoulli}(0.5)$ sampled independently per time step (seed = 42).
  - Score: $S_t \sim \text{Uniform}(0, 1)$.
- **Random Stratified:**
  - Prediction: $\hat{y}_t \sim \text{Bernoulli}(\pi_{\text{train}})$ where $\pi_{\text{train}} = \frac{1}{N_{\text{train}}} \sum y_{\text{train}}$ is training attack prevalence (seed = 42).
  - Score: $S_t \sim \text{Uniform}(0, 1)$.

