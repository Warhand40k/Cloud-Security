# Stage 2 Candidate Methodologies & Architectural Extensions

This document records architectural and methodological observations arising from Stage 1 audit and verification. As mandated by Stage 1 protocol constraints, no new methods, thresholding schemes, fusion algorithms, reference refresh mechanisms, or cloud testbeds have been implemented. Instead, each entry outlines an empirical pathology observed in the verified Stage 1 results (`results/v3/`), the theoretical deficiency it reveals, and the corresponding Stage 2 design candidate for future work.

---

## 1. Block-Aware Empirical / Conformal Threshold Calibration

### Empirical Evidence from Stage 1 (v3 Results)
In the matched-operating-point evaluation (`results/v3/metrics/matched_operating_points.csv`), thresholds calibrated on validation to hit target operating points ($\text{Recall} = 0.80$, $\text{FPR} = 0.05$) suffered large generalization gaps on the held-out test partitions:
- On CSE-CIC-IDS2018 Thursday-15-02-2018, Isolation Forest calibrated on validation for $\text{Recall} = 0.80$ collapsed to $\text{Recall} = 0.4186$ on test.
- On Wednesday-21-02-2018, Isolation Forest collapsed to $\text{Recall} = 0.0000$ and $\text{F1} = 0.0000$, despite an apparent validation $F_1 = 0.5833$.
- In the multiday summary (`results/v3/metrics/csecicids2018_multiday_summary.csv`), EVT thresholding (Config B2) yielded an $F_1$ standard deviation of $\pm 0.2665$ ($F_1 = 0.4615$ on Thursday vs. $F_1 = 0.0000$ on Friday and Wednesday), demonstrating high sensitivity to the shape of the extreme-value tail fitted on small validation histories.

### Pathology
Static quantile and parametric EVT calibration assume that the anomaly score distribution under benign conditions is strictly stationary between validation and test windows. When daily diurnal drift, network load shifts, or background scanning occur, the score distribution shifts, leading to threshold mismatch (either massive alert storms or complete silence).

### Stage 2 Candidate Design
- **Rolling Conformal Prediction / Conformal Anomaly Detection**: Implement split-conformal quantile calibration with finite-sample coverage guarantees over rolling calibration windows.
- **Block-Aware Empirical Thresholding**: Calibrate thresholds dynamically using exponentially weighted moving quantiles (EWMQ) over recent verified-benign windows rather than a single static pre-attack validation slice.

---

## 2. Complementary Fusion of Causal Matrix Profile (A-prime) with Autoregressive Residuals (ARIMA)

### Empirical Evidence from Stage 1 (v3 Results)
Analysis of the per-day CSE-CIC-IDS2018 metrics (`results/v3/metrics/csecicids2018_multiday_results.csv`) and UNSW Flow results (`results/v3/metrics/unsw_detailed.csv`) reveals that Causal AB (Config A-prime) and ARIMA Residuals exhibit orthogonal, non-overlapping performance profiles:
1. **Stationary / Trend-Dominant Regimes (ARIMA strength, A-prime weakness)**:
   - On Wednesday-21-02-2018 (LOIC-UDP / HOIC floods), ARIMA Residual achieved $F_1 = 0.6415$ (Precision = 1.0000, Recall = 0.4722, FPR = 0.0000, PR-AUC = 1.0000). In contrast, Config A-prime achieved $F_1 = 0.1500$ (Precision = 0.7500, Recall = 0.0833, FPR = 0.0294).
   - On UNSW Flow Contiguous, ARIMA Residual achieved $F_1 = 0.6162$ (Recall = 0.9786, Campaign Recall = 88/88), whereas Config A-prime saturated at $F_1 = 0.2093$ due to high flow-level variance.
2. **Short History / Complex Non-Linear Discord Regimes (A-prime strength, ARIMA weakness)**:
   - On Friday-16-02-2018 (26-minute training history), ARIMA Residual completely failed to converge (Optimization ConvergenceWarning; $F_1 = 0.0000$, Recall = 0.0000). Config A-prime maintained detection ($F_1 = 0.2540$, Campaign Recall = 1/1, PR-AUC = 0.5442).
   - On Thursday-15-02-2018 (Slowloris stealth attack), Config A-prime achieved MTTD = 0.0s (immediate detection), whereas ARIMA suffered a 360.0s detection delay.

### Pathology
Matrix profile distance measures non-parametric geometric discords across subsequence shapes, invariant to linear trend and amplitude offsets. ARIMA measures statistical forecast error under a linear autoregressive structure. Neither alone captures both volumetric network floods (linear surge) and low-rate stealth attacks (subtle temporal subsequence discord).

### Stage 2 Candidate Design
- **Dual-Stream Causal Anomaly Fusion**: Construct an ensemble detector that fuses:
  $$\mathcal{S}_{\text{fused}}(t) = \alpha \cdot \tilde{\mathcal{S}}_{\text{A-prime}}(t) + (1 - \alpha) \cdot \tilde{\mathcal{S}}_{\text{ARIMA}}(t)$$
  where $\tilde{\mathcal{S}}$ represents min-max or rank-normalized scores, and $\alpha$ is dynamically adjusted based on local variance or autocorrelation estimates.
- **Gated Residual-Discord Architecture**: Trigger an alert if either the short-term autoregressive residual exceeds a conservative conformal threshold OR the causal AB-join distance exceeds an empirical discord knee.

---

## 3. Dynamic Reference Library Refresh for Long-Horizon Drift Adaptation

### Empirical Evidence from Stage 1 (v3 Results)
In the UNSW Window Regime Shift Demonstration (`results/v3/metrics/unsw_detailed.csv`):
- A-prime scored Batch 2 windows (recorded 26 days after Batch 1) strictly against a fixed benign reference library extracted from Batch 1.
- Because background traffic features drifted over the 26-day gap, A-prime scored every Batch 2 window as a massive discord: Test Recall = 1.0000, Test FPR = 1.0000, Total Alerts = 1200 / 1200, $F_1 = 0.9975$ (matching All-Attack baseline exactly).
- Rather than detecting attacks, A-prime detected the regime shift in the underlying benign data distribution.

### Pathology
Static reference libraries in $AB$-join matrix profiles suffer catastrophic false-positive saturation when deployed in non-stationary environments. Any permanent or seasonal shift in benign traffic appears indefinitely as a discord against a stale historical dictionary.

### Stage 2 Candidate Design
- **FIFO / Reservoir Reference Dictionary**: Maintain a rolling reservoir of verified-benign subsequences of size $N_{\text{ref}}$, updating the library whenever operator feedback confirms benign operation:
  $$\mathcal{D}_{t} = (\mathcal{D}_{t-1} \setminus \{S_{\text{old}}\}) \cup \{S_{\text{new}}\}$$
- **Multi-Scale Dictionary Clustering**: Instead of keeping all raw subsequences, cluster benign subsequences into medoids using k-medoids or k-shape, updating cluster centers online to track gradual diurnal drift while rejecting sudden discord bursts.
- **Dual-Dictionary Architecture**: Maintain a permanent reference dictionary (representing baseline invariants) alongside an adaptive short-term dictionary (representing recent benign behavior), alerting only when a subsequence is anomalous relative to *both*.

---

## Summary Matrix of Stage 2 Candidates

| Problem Identified in v3 | Evidence File | Stage 2 Proposed Remedy | Feasibility / Scope |
|:---|:---|:---|:---|
| Threshold Generalization Gap | `results/v3/metrics/matched_operating_points.csv` | Conformal anomaly thresholding & rolling empirical quantiles | High (pure post-processing of scores) |
| Orthogonal Detection Failures | `results/v3/metrics/csecicids2018_multiday_results.csv` | Dual-stream fusion of A-prime discord + ARIMA residual | High (combines existing pipeline models) |
| Stale Reference Library Saturation | `results/v3/metrics/unsw_detailed.csv` | Reservoir dictionary refresh with verified-benign updates | Medium (requires streaming buffer management) |

