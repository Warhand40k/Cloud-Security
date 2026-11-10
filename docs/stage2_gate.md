# Stage 2 Gate: Decision Criteria, Empirical Complementarity, and Architecture Protocols

## 1. Formal Pre-Registration of Fusion Gate Criterion

**Registration Timestamp:** Stage 1.5 Step 7 (Pre-computation)  
**Evaluation Targets:** Dual-Stream Fusion of Causal AB-Join Discord (`Config A-prime`) and Autoregressive Residuals (`ARIMA Residual`).

### Explicit Mathematical Criterion
Stage 2 implementation of dual-stream detector fusion is formally justified if and only if:
An **Oracle-OR** combiner (flagging an alert at window $t$ if either detector flags an alert at fixed false alarm rate $\alpha = 0.05$):
1. **Recall Gain:** Increases test recall by at least **$+0.10$ absolute** ($\Delta \text{Recall} \ge +0.10$) over the better single detector ($\max(\text{Recall}_{\text{A-prime}}, \text{Recall}_{\text{ARIMA}})$),
2. **False Positive Control:** Keeps combined test $\text{FPR} \le \alpha$ ($\text{FPR} \le 0.05$) on **at least 50% of evaluation blocks** ($\ge 3$ of 5 blocks).

If this criterion is met, the gate decision is **GO** (fusion provides substantive complementary signal justifying Stage 2 architectural complexity).  
If this criterion is not met, the gate decision is **NO-GO** (fusion is rejected as unjustified complexity; methods do not provide sufficient orthogonal detection benefit under false-positive budget constraints).

---

## 2. Empirical Complementarity Metrics and Gate Decision

The complementarity metrics were computed across all 5 benchmark evaluation blocks (`Thursday-15-02-2018`, `Friday-16-02-2018`, `Wednesday-21-02-2018`, `UNSW Window Small Regime-Shift Block`, and `UNSW Window Regime Shift Demonstration`) using `experiments/run_stage2_gate_complementarity.py` and output to `results/v3_1/metrics/stage2_gate_complementarity.csv` and `.json`:

### Summary Table of Empirical Complementarity:
| Evaluation Block | Design | Spearman $r_s$ | Jaccard Overlap $J$ | Recall A-prime | Recall ARIMA | Oracle-OR Recall | $\Delta \text{Recall}_{\text{Oracle}}$ | Oracle-OR FPR | Meets Pre-Registered Criterion? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Thursday-15-02-2018** | Cross-Day Primary | 0.1623 | 0.0000 | 0.0000 | 0.0698 | 0.0698 | +0.0000 | 0.0000 | **NO** ($\Delta \text{Recall} < 0.10$) |
| **Friday-16-02-2018** | Cross-Day Primary | 0.0267 | 0.0000 | 0.5532 | 0.0000 | 0.5532 | +0.0000 | 0.2917 | **NO** ($\text{FPR} > 0.05, \Delta \text{Recall} < 0.10$) |
| **Wednesday-21-02-2018** | Cross-Day Primary | 0.4648 | 0.2632 | 0.2778 | 1.0000 | 1.0000 | +0.0000 | 0.0588 | **NO** ($\text{FPR} > 0.05, \Delta \text{Recall} < 0.10$) |
| **UNSW Small Regime-Shift** | Window Block | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | +0.0000 | 1.0000 | **NO** ($\text{FPR} > 0.05, \Delta \text{Recall} < 0.10$) |
| **UNSW Regime-Shift Demo** | Window Block | 0.0000 | 0.0000 | 0.0000 | 0.2278 | 0.2278 | +0.0000 | 0.0000 | **NO** ($\Delta \text{Recall} < 0.10$) |

### Gate Decision
- **Blocks Meeting Criterion:** **0 / 5 (0.0%)** (Required: $\ge 50\%$, i.e. $\ge 3/5$)
- **Final Pre-Registered Decision:** **`NO-GO`**

### Analysis of the NO-GO Result:
1. **Zero Orthogonal Detection Gain ($\Delta \text{Recall} = 0.0000$ across all blocks):**
   - On every block where one detector successfully flagged attacks (Friday for A-prime; Wednesday and UNSW Regime Shift Demo for ARIMA), the *other* detector either detected zero attacks or its alert set was a strict subset of the better detector.
   - Consequently, forming an OR combiner did not add a single newly detected attack window over the best individual model.
2. **False Positive Amplification:**
   - Instead of improving recall, the OR combiner accumulated false alarms from both detectors. On Friday, combining A-prime and ARIMA inflated the test false positive rate from $0.2417$ (A-prime alone) and $0.0000$ (ARIMA alone) up to $0.2917$, violating the $\alpha = 0.05$ budget. On Wednesday, the combined FPR climbed to $0.0588$, violating the budget.
3. **Implication for Stage 2:**
   - Naive dual-stream fusion of A-prime and ARIMA is rejected. Stage 2 should not spend complexity on an OR/linear fusion scheme for these two detectors, as the empirical data proves it provides zero complementary coverage while worsening false alarms. Focus should remain on single-detector calibration (conformal thresholding) and reference library stability.

---

## 3. Protocol Draft: CSE-CIC-IDS2018 Cross-Day Drift Tracking

In non-stationary network environments, background traffic rates, protocol proportions, and connection durations evolve across days of the week. Stage 1.5 proved that training on Thursday morning ($N=507$ benign windows) and evaluating on Friday and Wednesday requires explicit drift tracking.

### Architecture Protocol for Cross-Day Drift Tracking:
1. **Daily Benign Baseline Anchoring:**
   - Anchor the initial benign reference library $\mathcal{D}_0$ using the pure morning benign traffic of the earliest available day (Thursday 15-02-2018, 00:00 to 08:27 UTC, $N=507$ windows).
   - Fit feature scalers $\mathcal{S}_0$ strictly on $\mathcal{D}_0$ and persist their parameters (mean $\mu_0$, standard deviation $\sigma_0$).
2. **Streaming Statistical Drift Detection:**
   - For each incoming day $d \in \{\text{Friday}, \text{Wednesday}, \dots\}$, track two orthogonal drift metrics over incoming 60-second windows:
     a. **Feature-Wise Population Stability Index (PSI) & Wasserstein Distance:**
        Calculate the 1-Wasserstein distance $W_1(P_{\text{ref}, j}, P_{\text{curr}, j})$ for each feature $j \in \{1, \dots, D\}$ over a sliding calibration window of $W_{\text{drift}} = 60$ minutes.
     b. **Matrix-Profile Self-Distance Drift:**
        Compute the internal 1-NN discord distance among incoming benign validation windows against themselves ($AA$-join). A persistent upward drift in the median 1-NN distance indicates structural background pattern divergence from $\mathcal{D}_0$.
3. **Drift Warning & Retraining Triggers:**
   - If $\text{PSI} > 0.25$ or median $AA$-join distance increases by $> 50\%$ relative to day 0:
     - Issue a **Regime Drift Alert** to network operators.
     - Freeze the current anomaly detector confidence weights.
     - Trigger the verified-benign reference refresh loop.

---

## 4. Protocol Draft: Verified-Benign Reference Library Refresh Loop

Static reference dictionaries in causal $AB$-join matrix profiles (`Config A-prime`) become obsolete when network topology or background services change. However, naively inserting unverified streaming windows into the reference library causes **attack poisoning** (an ongoing stealth attack would be absorbed into the dictionary, silencing future alerts).

### Reference Refresh Specification:
1. **Definition of "Verified-Benign":**
   A time window $W_t$ is certified as "verified-benign" if and only if:
   a. **Operator Clearance:** No high-severity security incidents or SOC alerts were correlated with the source/destination subnets during window $t$ through $t + T_{\text{quarantine}}$.
   b. **Quarantine Window ($T_{\text{quarantine}} = 4$ hours):** Windows cannot enter the active reference library immediately. They must sit in a staging quarantine buffer for at least 4 hours to allow post-hoc incident triage, threat intelligence correlation, or customer ticket resolution.
   c. **Discord Invariance Check:** The window must not exhibit extreme discords ($> 99.9\text{th}$ percentile) against existing long-term reference invariant medoids.
2. **Buffer Sizing & Replacement Policy:**
   - **Fixed Library Capacity:** Enforce a maximum library size of $N_{\text{max}} = 1{,}000$ windows ($\approx 16.67$ hours of traffic).
   - **Reservoir / FIFO Replacement:** When capacity is reached, retire the oldest verified-benign windows ($FIFO$) while preserving a core subset of $K_{\text{core}} = 100$ invariant anchor windows selected via $k$-medoids clustering over the historical baseline.
3. **Update Cadence:**
   - Batch reference refresh is executed once every 24 hours during off-peak hours (e.g., 02:00 UTC).
   - Up to $N_{\text{update}} = 100$ verified windows from the quarantine buffer are integrated per update step.
   - Matrix profile distance index structures (e.g., precomputed Fourier transforms / STUMPY precomputations) are incrementally refreshed rather than recomputed from scratch.
