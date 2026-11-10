# Conformal Calibrator Definitions and Label-Feedback Audit (Stage 4 Step 1)

**Commit / Provenance Baseline:** Branch `stage4-verify`  
**File Under Audit:** `src/adaptive_threshold.py` (`ConformalQuantileThreshold`)  
**Evaluation Harnesses Audited:**  
- `experiments/run_stage2_conformal_evaluations.py` (lines 207–223)  
- `experiments/run_stage3_testbed_evaluation.py` (lines 181–191)  

---

## 1. Executive Code-Audit Findings

In Stages 2 and 3, `ConformalQuantileThreshold` was introduced to provide rolling split-conformal calibration and Adaptive Conformal Inference (ACI). Our line-by-line inspection of the implementation in `src/adaptive_threshold.py` and the evaluation scripts reveals a critical methodological distinction between the theoretical description and the empirical code:

> **Audit Finding (Test-Label Leakage / Oracle Feedback):**  
> In both Stage 2 (`run_stage2_conformal_evaluations.py`, lines 208 and 218) and Stage 3 (`run_stage3_testbed_evaluation.py`, lines 183 and 189), the rolling calibrators were called with:  
> `verified_benign_mask = (y_test == 0)`  
> Passing `(y_test == 0)` at test time provides the calibrator with **true test ground-truth labels**. Consequently, the published Stage 2 and Stage 3 results represent an **"oracle-feedback upper bound"** rather than an autonomous, label-free streaming detector.

---

## 2. Line-by-Line Technical Audit

### (a) Which scores enter the rolling buffer?

The buffer admission logic in `predict_rolling` (`src/adaptive_threshold.py`, lines 351–362) is:
```python
# Buffer update logic:
should_add = False
if verified_benign_mask is not None:
    should_add = bool(verified_benign_mask[t])
else:
    should_add = (is_anomaly == 0)

if should_add:
    buffer.append(score_t)
    if len(buffer) > window_size:
        buffer.pop(0)
```

1. **Under `verified_benign_mask = (y_test == 0)` (Stages 2 & 3 Evaluation Pipeline):**
   - **True Benign Windows (`y_test[t] == 0`):** `should_add = True`. The score $s_t$ enters the buffer regardless of whether the model flagged it as an anomaly (`is_anomaly == 1` or `0`). That is, false alarms on benign windows are admitted into the buffer.
   - **True Attack Windows (`y_test[t] == 1`):** `should_add = False`. The score $s_t$ is strictly prevented from entering the buffer, even if the model failed to detect it (`is_anomaly == 0`, a false negative).
   - **Operational Reality:** This requires an omniscient oracle that knows whether incoming traffic is an attack or benign with zero latency. In actual production SRE deployments, operator review occurs with non-zero triage delay, or is absent for unflagged traffic.

2. **Under `verified_benign_mask is None` (Label-Free Self-Filtering):**
   - `should_add = (is_anomaly == 0)`.
   - Only unflagged test windows enter the rolling buffer.
   - If a subtle or missed attack occurs (`is_anomaly == 0`), its score enters the buffer, risking buffer poisoning.
   - If a benign window is flagged (`is_anomaly == 1`, a false alarm), it is excluded from the buffer.

---

### (b) Exactly how `err_t` is computed in ACI and which windows contribute?

The ACI update rule in `predict_aci` (`src/adaptive_threshold.py`, lines 412–422) is:
```python
is_benign = True
if verified_benign_mask is not None:
    is_benign = bool(verified_benign_mask[t])

if is_benign:
    err_t = float(is_anomaly)
    alpha_t = float(np.clip(alpha_t + gamma * (target_alpha - err_t), 0.001, 0.50))
    buffer.append(score_t)
    if len(buffer) > window_size:
        buffer.pop(0)
```

1. **Error Definition:**
   - $\text{err}_t = \mathbb{I}(s_t \ge \tau_t(\alpha_t)) \in \{0, 1\}$.
   - In standard conformal prediction (Gibbs & Candès 2021), coverage error on benign instances is $\text{err}_t = 1$ when a false alarm occurs.

2. **Contributing Windows:**
   - **Under `verified_benign_mask = (y_test == 0)`:**
     - Only true benign windows (`y_test[t] == 0`) contribute to adaptation.
     - On a true benign window:
       - If false alarm ($\text{err}_t = 1$): $\alpha_{t+1} = \text{clip}(\alpha_t + \gamma \cdot (\alpha - 1), \dots) = \alpha_t - \gamma(1 - \alpha)$. At $\alpha = 0.05, \gamma=0.01$, $\alpha$ drops by $0.0095$, making the threshold more conservative to suppress further false alarms.
       - If normal ($\text{err}_t = 0$): $\alpha_{t+1} = \text{clip}(\alpha_t + \gamma \cdot \alpha, \dots) = \alpha_t + \gamma \cdot \alpha$. At $\alpha = 0.05, \gamma=0.01$, $\alpha$ gently increases by $+0.0005$, relaxing the threshold.
     - On true attack windows (`y_test[t] == 1`): `is_benign` is `False`. The entire block is bypassed! No update occurs, $\alpha_t$ remains frozen across the attack campaign, and no attack scores enter the buffer.
   - **Under `verified_benign_mask is None` (Original Unmodified Fallback):**
     - `is_benign` defaults to `True` for **all windows** (benign and attack alike).
     - As a result, every detected attack window triggers $\text{err}_t = 1.0$, which incorrectly penalizes $\alpha_t$ as if the detector had committed a false alarm, rapidly driving $\alpha_t \to 0.001$ ($\alpha_{\min}$) and causing extreme threshold inflation! Furthermore, `buffer.append(score_t)` admits all windows (including attacks) into the buffer.

---

### (c) Buffer seeding, ordering, and capacity $W$

1. **Seeding:**
   ```python
   buffer = list(self.cal_scores_[-window_size:]) if self.n_cal_ > 0 else []
   ```
   - In `fit(cal_scores, y_cal)`:
     ```python
     clean = cal_scores[y_cal == 0]
     self.cal_scores_ = np.sort(clean)
     ```
   - Because `self.cal_scores_` is sorted in ascending order during `fit()`, `cal_scores_[-window_size:]` takes the **$W$ largest scores from the calibration set** (the extreme upper tail of calibration scores), rather than the chronological terminal slice of calibration time.
2. **Buffer Capacity $W$:**
   - $W = 60$ windows (corresponding to 60 minutes for 60s windows in CSE and Testbed, or 10 minutes for 10s windows in UNSW).
   - Once $|B| > W$, the FIFO queue discards the oldest element: `buffer.pop(0)`.
3. **Warm-Up Guard:**
   - While $|B| < 10$, the calibrator falls back to the static calibration threshold `self.threshold_`.
   - Once $|B| \ge 10$, the threshold is calculated dynamically from the empirical distribution of $B$.

---

## 3. Taxonomy of Calibrator Variants for Stage 4 Verification

To ensure zero ambiguity, Stage 4 defines two explicit variants:

1. **Oracle-Feedback Upper Bound (Legacy Stage 2 & Stage 3):**
   - Receives ground truth labels at test time: `verified_benign_mask = (y_test == 0)`.
   - Represents the theoretical upper bound when a human operator provides instant, perfect verification on every window.
2. **Label-Free Autonomous Variant (Strict Production Protocol):**
   - Receives zero test labels (`y_test` is never accessed by the calibrator).
   - Rolling buffer admission rule: admits unflagged windows only (`is_anomaly == 0`).
   - ACI adaptation rule:
     - Autonomous self-supervised: `err_t` is driven by unflagged/flagged state under anti-poisoning constraints, or
     - Alarm rate feedback: tracks long-term alert frequency $\bar{a}_t$ against nominal budget $\alpha$.
   - Must pass the label-permutation assertion test with bit-identical outputs.
