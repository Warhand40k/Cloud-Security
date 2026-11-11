# Presentation Blueprint
**Paper:** Reproduction, Causal Extension, and Methodological Audit of Multidimensional Matrix Profile for Network Anomaly Detection in Cloud Environments
**Authors:** Aalok Kumar, Aditya Sahrawat, Amal Mohanan (IIIT Dharwad)
**Target length:** 28 main slides + 5 backup slides, about 25-30 minutes plus Q&A (about 1 minute per slide; slides marked "light" take 30 seconds).

---

## 0. Global Design System

### 0.1 Theme
Clean, technical, "security operations" feel. Dark title/section slides, light content slides (the paper's figures have white backgrounds, so content slides must be light).

| Role | Colour | Hex |
|---|---|---|
| Primary (titles, header bar) | Deep navy | `#0B1F3A` |
| Accent 1 (key numbers, highlights) | Teal | `#0FA3B1` |
| Accent 2 (negative results, warnings) | Crimson | `#D64045` |
| Accent 3 (positive results, success) | Green | `#2E9E5B` |
| Neutral text | Charcoal | `#222B36` |
| Light background | Off-white | `#F7F9FB` |
| Muted/secondary text | Slate grey | `#6B7785` |

**Semantic colour rule (use consistently):** green = works / good result, crimson = failure / negative result, teal = neutral key figure. This matches the paper's own figure colours (red = failure, green = cure).

### 0.2 Typography
- Titles: **Inter Bold** (or Calibri Bold), 32 pt, navy.
- Body: Inter Regular (or Calibri), 20-22 pt minimum. Never below 18 pt.
- Big numbers ("stat callouts"): 60-72 pt bold, accent colour.
- Equations: render with LaTeX/MathType, 26-28 pt. Monospace (JetBrains Mono / Consolas) for code identifiers such as `verified_benign_mask`.

### 0.3 Layout grid (16:9)
- Margins: 0.6 in all sides.
- Title top-left; thin teal line (3 pt) under the title.
- Footer (every content slide): left = short title "mSTAMP Audit", centre = IIIT Dharwad logo (if allowed), right = slide number. 10 pt, slate grey.
- Max 5 bullets per slide, max 12 words per bullet. Details go into speaker notes.
- One idea per slide. Every results slide ends with a one-line **"Takeaway" bar** (navy rounded rectangle, white text, bottom of slide).

### 0.4 Figures and tables policy
- Paper figures are on a white background: place them in a rounded-corner card with a subtle shadow, never stretched. Keep aspect ratio.
- Use the **PNG files from `paper/figures/`** (same as `paper/assets/`). Filenames are given per slide.
- Tables from the paper (Table 1, Table 2) are too dense to paste whole. **Rebuild them as trimmed native tables** showing only the rows named in the slide; full versions go to the backup slides.
- Every figure slide has a small caption (14 pt, grey), "Figure N in paper".
- Highlight the one thing to look at with a crimson/teal arrow or box added in the slide software (not baked into the image).

### 0.5 Animation
Minimal. Only: (a) bullets appear one at a time on slides 11-16 and 24 where the argument builds, (b) a fade for the Takeaway bar. No transitions other than a plain fade.

### 0.6 Figure inventory (what is available and where used)

| Paper figure | File | Used on slide |
|---|---|---|
| Fig. 1 Saturation diagnosis | `score_histograms_saturation_diagnosis.png` | 13 |
| Fig. 2 FPR vs budget across 32 configs | `conformal_fpr_control_alpha05.png` | 19 |
| Fig. 3 Rolling/ACI thresholds, Friday DoS-Hulk | `conformal_rolling_thresholds_friday.png` | 20 |
| Fig. 4 10-hour testbed timeline | `testbed_timeline_scores.png` | 22 |
| Fig. 5 Recall by campaign type + flash crowd FAR | `testbed_campaign_type_recall.png` | 23 |
| Optional extras (present in your repo; check they look right before using) | `kneedle_selection_curve.png`, `paired_persistence_effect.png`, `unsw_multiblock_flow_f1.png`, `timeblock_f1_spread.png`, `sensitivity_m.png`, `matched_curves_cse_friday.png`, `conformal_f1_vs_fpr.png` | 7, 15, 16, backup |

> I could only see the five numbered figures from the PDF. The optional extras are taken from your `PROJECT_STRUCTURE.md` file names, so I haven't seen what they look like. Share them if you want me to fine-tune placement.

---

## SECTION A: Opening

### Slide 1: Title
- **Layout:** Full-bleed dark navy background. Title left-aligned in white, 40 pt, max 3 lines. Teal accent line beneath.
- **On-slide content:**
  - Title: *Reproduction, Causal Extension, and Methodological Audit of Multidimensional Matrix Profile for Network Anomaly Detection in Cloud Environments*
  - Authors: Aalok Kumar, Aditya Sahrawat, Amal Mohanan
  - Department of CSE, IIIT Dharwad, November 2026
- **Visual:** Subtle abstract network/time-series line pattern on the right (decorative, 15% opacity). No paper figure here.
- **Speaker notes:** One sentence of framing: "We took a published cloud-security method that reported 99.6% accuracy, re-implemented it with strict leakage-free rules, and audited what actually holds up."
- **Time:** 0:30

### Slide 2: Agenda (light)
- **Layout:** Light. Left: numbered vertical list; right: a simple 5-step horizontal flow icon strip.
- **On-slide content (5 items):**
  1. Why this problem matters
  2. The method we reproduced
  3. Methodological audit: what went wrong and why
  4. Conformal calibration for false alarms
  5. Live testbed validation and guidelines
- **Speaker notes:** Say that the talk is "audit first, then fix attempts, then real-system check."
- **Time:** 0:30

---

## SECTION B: Motivation and Background

### Slide 3: The Cloud Telemetry Trilemma
- **Layout:** Light. Three equal columns (cards) with an icon on top, heading, one-line description. Teal heading bars.
- **On-slide content:**
  - Card 1 **High sensitivity**: detect attacks fast (low Mean Time to Detect).
  - Card 2 **Strict false-positive control**: avoid alert fatigue.
  - Card 3 **Resilience to non-stationarity**: diurnal cycles, flash crowds, marketing surges.
  - Small line above the cards: "Telemetry sources: AWS VPC Flow Logs, IPFIX, Prometheus metrics."
- **Figure:** None. Use three simple icons (radar, bell with slash, wave).
- **Speaker notes:** Explain that SRE and SOC teams need all three at once, and that most benchmark papers only report accuracy. Cite Sommer & Paxson [6] for the gap between lab and production.
- **Time:** 1:15

### Slide 4: The Base Paper and What Was Left Unspecified
- **Layout:** Light, two-panel. Left panel (green tint) "What was claimed"; right panel (crimson tint) "What was missing".
- **On-slide content:**
  - Left: Al-Mazrawe & Al-Musawi [1]: mSTAMP + Kneedle on UNSW-NB15 → **99.6% accuracy, F1 = 0.998** (large stat callout).
  - Right (4 bullets): anomaly-score semantics undefined; threshold calibration unspecified; causal alignment unaddressed; chronological split integrity not guaranteed.
- **Speaker notes:** "A 0.998 F1 is only meaningful if scores, thresholds, and splits are defined. These four gaps are what our audit probes."
- **Time:** 1:15

### Slide 5: Our Contributions
- **Layout:** Light. Five horizontal rows, each with an icon, a bold keyword, and one line. Rows 3 and 4 carry a small crimson "negative result" tag.
- **On-slide content:**
  1. **Leakage-free reproduction and audit**: causal alignment, strict chronological splits; five pathologies diagnosed.
  2. **Config A-prime**: causal streaming variant; look-ahead in Config A quantified (50% val / 48% test windows).
  3. **Persistence filter**: negative result, hurt F1 in 67.5% of 80 configs.
  4. **Conformal calibration**: adaptive helps FPR variance, costs −17.9 to −23.9 pp recall.
  5. **Testbed validation**: 25 campaigns × 5 seeds; Isolation Forest F1 = 0.841, 100% campaign recall.
- **Speaker notes:** Stress that the paper is honest about negative results, including mistakes in the authors' own pipeline.
- **Time:** 1:15

### Slide 6: Background: Related Work (light)
- **Layout:** Light. Horizontal timeline-style row of four labelled boxes connected by arrows.
- **On-slide content:**
  - Matrix Profile (Yeh et al. 2016) → mSTAMP (Yeh et al. 2017) + STUMPY
  - Kneedle (Satopaa et al. 2011)
  - Tabular/time-series detectors: ARIMA, Isolation Forest
  - Conformal prediction (Vovk; Angelopoulos & Bates) → ACI (Gibbs & Candès 2021)
  - Footnote: "High-dimensional distance concentration erodes contrast [Beyer et al.]."
- **Speaker notes:** Keep to 30-45 seconds. Only point to remember: conformal guarantees assume exchangeability, which autocorrelated telemetry violates.
- **Time:** 0:45

---

## SECTION C: The Method

### Slide 7: mSTAMP + Kneedle Pipeline
- **Layout:** Light. Top: horizontal pipeline diagram (5 boxes). Bottom: two equations side by side.
- **On-slide content:**
  - Pipeline: Telemetry → Windowing (d standardised features) → mSTAMP discord profile → **Kneedle picks k\*** → Threshold → Alert.
  - Equation (2): P_i^(k) = min over j≠i of Σ_{l=1..k} d_(l)(i,j), sum of k smallest per-dimension distances.
  - Equation (3): k\* = argmax_k [ (y_k − y_1)/(y_d − y_1) − (k−1)/(d−1) ], y_k = max_i P_i^(k).
  - Footnote: "Concavity is an empirical observation, not a theorem."
- **Figure (optional):** `kneedle_selection_curve.png`, small inset on the right of the pipeline, labelled "Kneedle selection curve (our run)". Skip if it crowds the slide.
- **Speaker notes:** Explain in plain words: for each time window, find its nearest look-alike elsewhere; if even the closest match is far, it is a discord (anomaly). Kneedle then chooses how many dimensions to use by finding the "elbow" in the discord curve.
- **Time:** 1:30

### Slide 8: Look-Ahead Bias: Config A vs Config A-prime
- **Layout:** Light. Two side-by-side diagrams drawn on a time axis (build natively, no paper figure).
- **On-slide content:**
  - Left **Config A (self-join)**: arrow from window at time t pointing *forward* to a match at t′ > t, in crimson. Label: "Nearest neighbour can lie in the future."
  - Right **Config A-prime (causal AB-join)**: test window points only *back* into a training-only reference library R, in green. Equation (4): S(t) = P^(k\*)_{t−m+1}(AB-join vs R).
  - Stat callout under left: **50% of validation, 48% of test windows** had future nearest neighbours.
  - Caveat line under right: "Causal, but smaller reference → more score degeneracy."
- **Speaker notes:** This is a key conceptual slide. Config A is not deployable in streaming because it peeks ahead; A-prime fixes that but has a price.
- **Time:** 1:30

### Slide 9: Experimental Setup
- **Layout:** Light, 2×2 grid of cards. Top strip: protocol rule.
- **On-slide content:**
  - Top strip: **Train End < Val Start < Test Start. No test labels in training, calibration, or thresholding.**
  - Card **Datasets**: UNSW-NB15 (10 blocks × 8,000 flows = 80,000); CSE-CIC-IDS2018 (Thu/Fri/Wed, 60 s windows); live Flask testbed.
  - Card **Detectors**: Config A, Config A-prime (m ∈ {5,10}), Isolation Forest (100 trees), ARIMA(1,0,1) residual.
  - Card **Calibration**: static quantile, static split-conformal, rolling conformal (W = 60), ACI (γ = 0.01); α ∈ {0.005 … 0.10}.
  - Card **Rule**: minimum N ≥ 100 benign training windows.
- **Speaker notes:** Emphasise that "label-free" rolling/ACI means zero test labels. Oracle versions are reported only as upper bounds.
- **Time:** 1:15

---

## SECTION D: Methodological Audit

### Slide 10: Five Pathologies in Our Own Pipeline (roadmap)
- **Layout:** Light. Five numbered crimson-outlined tiles in a row (2 rows if needed), each with a one-line headline and a number. Used again as a progress tracker on slides 11-16 (small version in the top-right corner, current tile highlighted).
- **On-slide content:**
  1. **Time-axis compression**: 12 h squeezed into 3.1 h
  2. **Training starvation**: IF F1 0.000 → 0.986
  3. **Threshold collapse**: 99.73% zero scores
  4. **Persistence filter**: hurt F1 in 67.5% of configs
  5. **Flow blocks**: all MP variants ≤ 0.1246 F1 (below All-Attack baseline 0.1281)
- **Speaker notes:** Stress "our own pipeline" so the audience sees this as self-audit, not blame on the base paper. The base paper did not evaluate on CSE-CIC-IDS2018.
- **Time:** 1:00

### Slide 11: Pathology 1: Time-Axis Integrity
- **Layout:** Light. Left: simple self-drawn timeline graphic. Right: stat callouts.
- **On-slide content:**
  - Timeline graphic: a 12-hour bar with a hatched 454-minute gap, below it a short 3.1-hour bar labelled "what our first pipeline saw".
  - Callouts: **528 quiescent minutes skipped**; **11.97 h → 3.1 h**.
  - Bullets: inflated attack prevalence; distorted wall-clock MTTD.
  - Fix: project onto continuous gapless 60 s grid + chronological assertions.
- **Figure:** None from the paper (self-drawn timeline).
- **Speaker notes:** Dataset: CSE-CIC-IDS2018 Friday, DoS-Hulk. Sequential indexing of only active windows made the attack seem far more frequent than it was.
- **Time:** 1:00

### Slide 12: Pathology 2: Training Sizing Flips the Rankings
- **Layout:** Light. A native bar chart on the left (build in slides) and takeaway on right.
- **On-slide content:**
  - Bar chart, Isolation Forest F1 on Wednesday: within-day **N = 16 → F1 = 0.0000** (crimson) vs cross-day **N = 507 → F1 = 0.9859** (green).
  - Side note: Friday within-day N = 45 also starved; ARIMA failed to converge.
  - Also: under fixed α = 0.05 conformal, Wednesday IF F1 = 0.8780 (FPR 29.41%, perfect recall).
  - Takeaway bar: "Rankings from small-reference runs reflect starvation, not algorithms. Use N ≥ 100."
- **Speaker notes:** Be careful to say 0.9859 is under validation-F1 tuning, and 0.8780 is under fixed α = 0.05 conformal calibration. They are different protocols.
- **Time:** 1:15

### Slide 13: Pathology 3: Threshold Collapse (Root-Cause Diagnosis)
- **Layout:** Light. Full-width figure card in the centre; two short bullets above it; takeaway bar below.
- **Figure:** **Figure 1: `score_histograms_saturation_diagnosis.png`**. Place at ~85% slide width. Add a teal arrow on panel (a) at the spike at 0.0 and a box on panel (b) around the "UNSW Flow" bars (100% → 0.57%).
- **On-slide content:**
  - Bullet 1: Hypothesis refuted. The "26-day calendar gap" was false; flow block lies 107 s after the reference period in Batch 1.
  - Bullet 2: Real cause: **99.73% of benign validation scores = 0** → validation-F1 picks τ\* = 0 → FPR 100%.
  - Takeaway bar: "ε-MAD floor cures FPR (100% → 0.57%) but recall is only 2.14% (ROC-AUC 0.5079): it hides alerts, it does not restore discrimination."
- **Speaker notes:** Walk through the figure left to right. Panel (a): the blue spike is benign scores stuck at zero. Panel (b): red = collapsed threshold, green = quantile rule with MAD floor. Warn the audience that low FPR here is not a win.
- **Time:** 1:45

### Slide 14: Score Degeneracy on the Live Testbed
- **Layout:** Light. Left: big stat callouts. Right: a compact 4-row table.
- **On-slide content:**
  - Callouts: **1 unique score value (0.0)**, **ROC-AUC = 0.5000**, **PR-AUC = 0.4533** (= class prevalence).
  - Cause: zero-variance channels (4xx count, 5xx count, error rate) → z-normalised distance collapses.
  - Table "Diagnostic variants tried":

    | Variant | ROC-AUC (A / A′) |
    |---|---|
    | Drop 3 constant channels | 0.5013 / 0.4580 |
    | Smooth counts (w = 3) | 0.5000 / 0.5000 |
    | No z-normalisation | 0.5000 / 0.5000 |
    | Larger m = 20 | 0.5000 / 0.4557 |

  - Contrast line: Isolation Forest and ARIMA on the same data: **ROC-AUC > 0.90**.
- **Speaker notes:** "It is not just a bug we could fix; none of the four fixes helped, so beyond the math artefact there is no discriminative subsequence signal in this HTTP telemetry."
- **Time:** 1:15

### Slide 15: Pathology 4: The Persistence Filter (Negative Result)
- **Layout:** Light. Left: small flow diagram of the rule. Right: a three-segment horizontal stacked bar (native).
- **On-slide content:**
  - Rule: alert only after **k ≥ 2 consecutive** threshold crossings (our extension; the base paper alerts on a single crossing).
  - Stacked bar over 80 paired configurations: **Degraded 67.5%** (crimson) · **Neutral 30.0%** (grey) · remaining improved (green; compute as 2.5%).
  - Bullet: validation correctly picked k\* = 1 in 80% of splits.
  - Takeaway bar: "On bursty network attacks, delaying alerts costs recall."
- **Figure (optional):** `paired_persistence_effect.png` replaces the stacked bar if it clearly shows per-config paired F1 changes.
- **Speaker notes:** The paired design (same score stream, same threshold, parent vs variant) is what makes the result trustworthy. Say that the 2.5% "improved" is the remainder (100 − 67.5 − 30.0); the paper states only the first two numbers.
- **Time:** 1:00

### Slide 16: Pathology 5: Matrix Profiles vs a Trivial Baseline on Flows
- **Layout:** Light. Central native bar chart; callouts either side.
- **On-slide content:**
  - Bar chart: **All-Attack baseline F1 = 0.1281** (grey) vs **best matrix-profile mean F1 ≤ 0.1246** (crimson), shown as a horizontal reference line.
  - Callouts: 10 blocks × 8,000 flows = 80,000 flows; ROC-AUC **0.52-0.56** (near chance).
  - One line: "Flow summaries are point-in-time transactions, not smooth motifs."
- **Figure (optional):** `unsw_multiblock_flow_f1.png` in place of the native bar chart.
- **Speaker notes:** A detector that cannot beat "flag everything" has no operational value here.
- **Time:** 1:00

---

## SECTION E: Conformal Calibration

### Slide 17: Conformal Calibration Framework
- **Layout:** Light. Three stacked rows (Split-Conformal, ACI, Assumption), each with its equation at left and a plain-English line at right.
- **On-slide content:**
  - **Split-conformal:** q_α = ⌈(n+1)(1−α)⌉ / n; τ_α = Quantile(S_cal, q_α); p-value p(s_t) = (1 + Σ 𝟙(s_i ≥ s_t)) / (n+1); alert if p ≤ α. (Eq. 5-6)
  - **ACI:** α_{t+1} = clip(α_t + γ(α − err_t), α_min, α_max), γ = 0.01, W = 60. (Eq. 7)
  - **Label-free rule:** only *unflagged* windows enter the rolling buffer (flagged windows quarantined).
  - Warning chip (amber): "Exchangeability does not strictly hold → guarantee is empirical, not exact."
- **Speaker notes:** Intuition: the threshold is a high percentile of "known-normal" scores; ACI nudges that percentile up or down depending on recent false alarms.
- **Time:** 1:30

### Slide 18: Label-Leakage Audit: We Caught Ourselves
- **Layout:** Light. Left: red "before" card; right: green "after" card; arrow between.
- **On-slide content:**
  - Before (Stages 2-3): calibrators fed `verified_benign_mask = (y_test == 0)` → oracle feedback → flash-crowd FAR looked like **100% → 11.43%**.
  - Test: label-permutation test showed the improvement was **entirely an artefact of leakage**.
  - After: all reported results are **label-free**; oracle results are marked and used only as upper bounds.
- **Speaker notes:** This is a good moment to underline research integrity: the headline result was retracted by the authors themselves.
- **Time:** 1:00

### Slide 19: Benchmark at α = 0.05 Across 32 Configurations
- **Layout:** Light. Left (~45%): trimmed native table. Right (~55%): figure card.
- **Figure:** **Figure 2: `conformal_fpr_control_alpha05.png`**. Highlight the red dashed α = 0.05 budget line with a teal arrow.
- **Trimmed table (from Table 1, α = 0.05):**

  | Method | Mean FPR | Target met | Mean recall |
  |---|---|---|---|
  | Static benign quantile | 0.1237 | 14/32 | 0.3943 |
  | Static split-conformal | 0.1199 | 14/32 | 0.3890 |
  | Rolling (label-free) | 0.1203 | 18/32 | 0.3362 |
  | ACI (label-free) | 0.1003 | 17/32 | 0.2606 |
  | *Rolling (oracle)* | *0.0306* | *22/32* | *0.2093* |

  Show the oracle row in italics, grey, labelled "needs test labels".
- **Takeaway bar:** "Label-free adaptive methods do not reach the FPR reductions that oracle feedback suggested, and recall drops."
- **Speaker notes:** Mention the α = 0.01 finding verbally: static split-conformal met budget in 71.9% of runs (mean FPR 1.82%) versus 53.1% for label-free rolling/ACI (mean FPR 5.70%, max 50%). Figure 2 shows static thresholds exceeding the 5% budget on Friday and Wednesday.
- **Time:** 1:45

### Slide 20: Matched-FPR Comparison: Adaptive Costs Recall
- **Layout:** Light. Top: two big stat callouts. Bottom: figure card.
- **On-slide content:**
  - Callout 1: **Rolling LF vs matched static**: 17 losses vs 6 wins; mean ΔRecall **−17.91 pp** (95% CI [−0.323, −0.049]).
  - Callout 2: **ACI LF vs matched static**: 18 losses vs 6 wins; mean ΔRecall **−23.91 pp** (95% CI [−0.402, −0.103]).
  - Small line: 1,000-replicate moving-block bootstrap, block length 10. CSE cross-day only (12 runs): no significant wins, mean penalty beyond −30 pp.
- **Figure:** **Figure 3: `conformal_rolling_thresholds_friday.png`**. Caption: "Friday DoS-Hulk. Under *oracle* feedback FPR fell 12.50% → 1.67%; label-free FPR stays similar to static." Mark the caption clearly as oracle.
- **Takeaway bar:** "Only benefit: lower day-to-day FPR variance for well-separated detectors (IF: 10.79% → 4.03% std at α = 0.05)."
- **Speaker notes:** Explain that matched-FPR means we compare at equal achieved false alarm rate, otherwise lower FPR can come simply from alarming less. Mention that at α = 0.01 adaptive methods had 3× higher FPR variance (10.68% vs 3.87%).
- **Time:** 1:45

---

## SECTION F: Live Testbed Validation

### Slide 21: Testbed Architecture
- **Layout:** Light. A self-drawn architecture diagram across the slide; four labels beneath.
- **Diagram boxes:** Locust load generator (sinusoidal diurnal) → Flask REST service (catalog, search, checkout) with Prometheus client → 60 s window aggregator (11 features); separate isolated **Attacker container** (`internal: true` bridge, 127.0.0.1:8088 only) pointing at the service.
- **On-slide content (below the diagram):**
  - 600 windows = 10 emulated hours; 25 attack campaigns (HTTP flood, endpoint fuzzing, slow-rate stealth); 5 benign flash crowds (4-5× volume, 200 OK, 0 errors).
  - Train 0-199 and val 200-299 are 100% benign; test 300-599.
  - 5 seeds (42-46): shuffled campaign order, random durations, interleaved flash crowds.
  - Time-compressed: ~0.14 s per window.
- **Speaker notes:** Safety point: the attacker is network-confined. Features include request volume, error rate, 2xx/4xx/5xx counts, P95 latency, bytes in/out, TCP RST counts.
- **Time:** 1:15

### Slide 22: Testbed Results: Tabular Beats Matrix Profile
- **Layout:** Light. Top ~55%: Figure 4 (wide). Bottom ~45%: trimmed table.
- **Figure:** **Figure 4: `testbed_timeline_scores.png`**. It is tall, so crop or scale to full width and highlight the bottom panel ("Anomaly Score") where the mSTAMP dotted line is flat at zero.
- **Trimmed table (Table 2, α = 0.05, mean ± std over 5 seeds):**

  | Model | ROC-AUC | Recall (%) | F1 | Campaign recall |
  |---|---|---|---|---|
  | Isolation Forest (static) | 0.942 ± 0.009 | 98.14 ± 0.80 | **0.841 ± 0.009** | 100/100 |
  | ARIMA Residual (static) | 0.906 ± 0.006 | 98.14 ± 0.80 | 0.846 ± 0.006 | 100/100 |
  | Config A (mSTAMP) | 0.500 | 0.0 | 0.000 | 0/100 |
  | Config A-prime | 0.500 | 0.0 | 0.000 | 0/100 |

- **Takeaway bar:** "Tabular detectors catch every campaign; matrix profiles catch none (single designed testbed)."
- **Speaker notes:** Note the Clopper-Pearson 95% CI for 100/100 is [0.964, 1.000]. Also mention static-threshold test FPR is ~26% on the testbed, mostly driven by flash crowds, so F1 of 0.84 is not an "operations-ready" number.
- **Time:** 1:30

### Slide 23: The Flash Crowd Problem
- **Layout:** Light. Left (~60%): Figure 5. Right (~40%): three numbered findings.
- **Figure:** **Figure 5: `testbed_campaign_type_recall.png`**. Highlight the rightmost group "Flash Crowd (BENIGN)" with a crimson box. Note: in the PDF, a few bar labels in the middle group overlap; if it looks cluttered, zoom into the left and right groups.
- **On-slide content (right):**
  1. Static thresholds flag **100% ± 0.0%** of flash-crowd windows.
  2. Label-free rolling does **not** fix it (still 100%): flagged windows are quarantined, so the threshold never adapts. The earlier 11.43% was oracle leakage.
  3. **Training-data augmentation** with benign surge examples: flash-crowd FAR → **10.16% ± 7.78%**, attack recall stays **> 95.98%**.
- **Alert-load strip (bottom):** ~4.5-5.4 alerts/h benign, ~59 alerts/h during attacks (98.14% window recall), 60/h during flash crowds.
- **Speaker notes:** Be precise: ACI label-free reduced flash-crowd FAR to 26.1% ± 37.3% in some seeds, but campaign recall fell to 88/100, so this is not a clean win. Augmentation needs prior knowledge of what a flash crowd looks like (limitation 3).
- **Time:** 1:45

---

## SECTION G: Discussion and Close

### Slide 24: Why Matrix Profiles Fail on Flow Telemetry
- **Layout:** Light. Left: two columns "Mathematical artefact" vs "Genuine signal absence". Right: small comparison statement.
- **On-slide content:**
  - Mathematical: zero-variance channels + z-normalisation → distance collapse; discrete, sparse features → non-concave Kneedle curves.
  - Structural: flow logs are point-in-time transactions with no repeating motifs or phase relationships; distance concentration in high dimensions.
  - Contrast: MPs work on smooth sensor / physiological series; tabular detectors treat each window independently and win here.
- **Speaker notes:** Be balanced: DTW or other distance metrics and heavier hyperparameter search might help a little (limitation 5), but the point-in-time nature remains.
- **Time:** 1:00

### Slide 25: SRE Operational Guidelines
- **Layout:** Light. Three large numbered cards, each with an evidence chip underneath.
- **On-slide content:**
  1. **Prefer tabular ensembles for HTTP/flow telemetry**, evidence: IF F1 0.841 vs MP 0.000 (single testbed).
  2. **Use static split-conformal for tight budgets**, evidence: budget met in 71.9% of runs at α = 0.01. Rolling only for permissive budgets on well-separated detectors.
  3. **Enforce N ≥ 100 training windows**, evidence: IF F1 0.000 → 0.986 with adequate reference.
- **Speaker notes:** These are guidelines with stated evidence limits, not universal rules.
- **Time:** 1:00

### Slide 26: Limitations
- **Layout:** Light. Two-column compact list with small amber warning icons.
- **On-slide content (6 bullets):**
  - Single Flask service; HTTP statistics, not raw flow captures
  - Designer-controlled attacks; may not generalise to novel attacks
  - Conformal guarantees are empirical (exchangeability violated)
  - Flash-crowd fix needs prior knowledge and retraining
  - Fixed traffic generator and feature set despite 5 seeds
  - Config A-prime is causal but not better at detection
- **Speaker notes:** Mention matrix-profile hyperparameter search was limited (m ∈ {5,10,20}).
- **Time:** 0:45

### Slide 27: Conclusions
- **Layout:** Dark navy (matches title slide). Four large white statements with teal numerals.
- **On-slide content:**
  1. Reported results are highly sensitive to unspecified choices: time axis, training size, thresholds, causality.
  2. Matrix profiles do not beat simple tabular baselines on flow/HTTP telemetry.
  3. Adaptive conformal trades recall (−17.9 to −23.9 pp) for FPR stability; static split-conformal is better at tight budgets.
  4. Flash crowds need training-data augmentation; our own persistence filter is a negative result.
- **Speaker notes:** End on the message that auditing and reporting negative results is a contribution in itself.
- **Time:** 1:00

### Slide 28: Thank You / Questions
- **Layout:** Dark navy. Centred "Thank you" in white, 48 pt. Below: authors, IIIT Dharwad, contact emails, and a QR code linking to the project repository (if public).
- **Figure:** None.
- **Time:** Q&A

---

## BACKUP SLIDES (after Q&A slide, not presented unless asked)

### B1: Full Table 1 (α = 0.05 and 0.01, all rows)
- Layout: Full-width table, 14 pt. Reproduce all 12 rows from Table 1, oracle rows in italics.

### B2: Full Table 2 (testbed, all 10 rows)
- Layout: Full-width table with Clopper-Pearson CIs. Include the Isolation Forest ACI LF (FPR 7.89 ± 7.73, recall 74.43 ± 14.30, campaign recall 88/100) and Rolling Oracle rows.

### B3: Sensitivity of subsequence length m
- Figure: `sensitivity_m.png` (from `paper/figures/`) if it shows m ∈ {5,10,20}. Add 2 lines of interpretation.

### B4: Kneedle behaviour on flow data
- Figure: `kneedle_curve_flow.png`. Explain that discrete/sparse features give non-concave curves (sensitive to boundary noise).

### B5: Anticipated Questions (speaker-only, hide from audience view)

| Likely question | Short answer |
|---|---|
| Did you replicate the 99.6% accuracy? | The paper's claim concerns UNSW-NB15; our contribution is showing that under leakage-free, causal evaluation matrix profiles do not outperform simple baselines. Be ready to cite the multi-block result (mean F1 ≤ 0.1246). |
| Is the testbed realistic enough? | No, it is a single designed service; we state this explicitly (limitations 1 and 4). |
| Why is IF's test FPR ~26% on the testbed? | Mainly flash-crowd windows flagged at 100%; augmentation brings flash-crowd FAR to 10.16%. |
| Why did ACI label-free show 26.1% flash-crowd FAR but you call it no fix? | It reduced FAR in some seeds only (high variance, ± 37.3) and cut campaign recall to 88/100. |
| Does conformal fail theoretically? | Not wrong, but exchangeability is violated by autocorrelated drifting scores, so guarantees are empirical. |
| Is Config A-prime the recommended method? | It removes look-ahead bias but does not improve detection; its value is methodological correctness. |
| Why was oracle leakage not caught earlier? | Rolling calibrators were given `y_test == 0` masks in Stages 2-3; label-permutation testing exposed it. |

---

## Suggested Timing Summary

| Section | Slides | Minutes |
|---|---|---|
| A Opening | 1-2 | 1 |
| B Motivation and background | 3-6 | 4.5 |
| C Method | 7-9 | 4.25 |
| D Audit | 10-16 | 8 |
| E Conformal | 17-20 | 6 |
| F Testbed | 21-23 | 4.5 |
| G Discussion and close | 24-28 | 4 |
| **Total** | | **~32 min** (trim slides 6, 14, 16, 24 to hit 25-28 min) |

## Final Checklist
- [ ] All five paper figures exported at 200+ dpi from `paper/figures/`.
- [ ] Oracle results visibly marked (italic, grey, "needs test labels") on slides 18-20.
- [ ] Every stat callout rechecked against the paper (especially: 0.9859, 0.8780, 99.73%, 67.5%, 0.1246 vs 0.1281, −17.91 / −23.91 pp, 10.16% ± 7.78%).
- [ ] Slide 15: the "2.5% improved" figure is derived (100 − 67.5 − 30.0), not stated in the paper; mention it as such or remove it.
- [ ] Footer and slide numbers consistent; font sizes ≥ 18 pt.
