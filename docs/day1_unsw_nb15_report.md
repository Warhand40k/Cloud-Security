# Day-1 Verification Report: UNSW-NB15 Dataset

> **Date:** 2026-11-09  
> **Target Requirement:** Section 4.1 of `README.md`  
> **Script:** `scripts/verify_unsw_nb15.py`

---

## 1. File Inventory and Row Counts

The raw UNSW-NB15 dataset files were downloaded directly and linked into `data/raw/`:

| File Name | File Size | Row Count | Format |
|---|---|---|---|
| `UNSW-NB15_1.csv` | 161.15 MB | 700,001 | Headless CSV (49 columns) |
| `UNSW-NB15_2.csv` | 157.57 MB | 700,001 | Headless CSV (49 columns) |
| `UNSW-NB15_3.csv` | 147.43 MB | 700,001 | Headless CSV (49 columns) |
| `UNSW-NB15_4.csv` | 93.07 MB | 440,044 | Headless CSV (49 columns) |
| **Total** | **559.21 MB** | **2,540,047** | |

Feature schema was parsed from `NUSW-NB15_features.csv` (49 columns).

---

## 2. Timestamps and Chronology

* **Timestamp Columns:** `Stime` (record start time) and `Ltime` (record last time).
* **Null Count:** 0 nulls across all 2,540,047 records.
* **Epoch Range:**
  * `Stime`: `1421927377` to `1424262068` (2015-01-22 11:49:37 UTC to 2015-02-18 12:21:08 UTC)
  * `Ltime`: `1421927414` to `1424262069` (2015-01-22 11:50:14 UTC to 2015-02-18 12:21:09 UTC)
* **Duration Inversions:** 0 records where `Stime > Ltime`.
* **Chronological Sorting:**
  * Raw concatenation of files 1 through 4 is **NOT** monotonically sorted in time.
  * Encountered **345,831 backward time jumps** across raw file boundaries.
  * **Action Required:** The dataset must be strictly sorted by `(Stime, Ltime)` prior to time series windowing or chronological train/validation/test partitioning.
* **Temporal Discontinuity:**
  * Total duration spanned is 27.02 days, but contains a 623.97-hour (~26 day) inactive recording gap between the two distinct simulation batches (January 22, 2015 vs February 15–18, 2015).
  * Grouped into 10-second intervals, there are 8,571 active windows (~23.8 active network traffic hours total).

---

## 3. Paper Features Verification

The base paper (*Al-Mazrawe & Al-Musawi 2025*) selects 9 specific features for UNSW-NB15. All 9 exist in the raw schema:

| Feature | Type in Schema | Nulls | Missing Markers (`-`, `?`, `#DIV/0!`) | Value Summary / Top Categories |
|---|---|---|---|---|
| `sloss` | Integer | 0 | None | min=0, max=5319, mean=5.16 |
| `state` | Nominal | 0 | None | 16 categories (`FIN`: 1.48M, `CON`: 560k, `INT`: 490k) |
| `dur` | Float | 0 | None | min=0.0s, max=8786.6s, mean=0.66s |
| `sbytes` | Integer | 0 | None | min=0, max=14,355,774, mean=4,339.6 |
| `dbytes` | Integer | 0 | None | min=0, max=14,657,531, mean=36,427.6 |
| `sttl` | Integer | 0 | None | min=0, max=255, mean=62.78 |
| `dttl` | Integer | 0 | None | min=0, max=254, mean=30.77 |
| `dloss` | Integer | 0 | None | min=0, max=5507, mean=16.33 |
| `service` | Nominal | 0 | `-`: 1,246,397 | 13 categories (`-`: 1.25M, `dns`: 781k, `http`: 206k, `ftp-data`: 125k) |

* **Note on `service`:** The `-` token represents unclassified/standard traffic (the mode of the column). Preprocessing must encode `-` as a distinct category or replace it with a designated unknown token.

---

## 4. Class Balance and Ground Truth Integrity

* **Binary Labels:**
  * Normal (`0`): 2,218,764 records (**87.35%**)
  * Attack (`1`): 321,283 records (**12.65%**)
* **Integrity:**
  * Zero records labeled `0` had an attack category.
  * Zero records labeled `1` were marked `Normal`.
* **Attack Categories Breakdown:**
  * `Generic`: 215,481 (8.48%)
  * `Exploits`: 44,525 (1.75%)
  * `Fuzzers`: 24,246 (0.95%)
  * `DoS`: 16,353 (0.64%)
  * `Reconnaissance`: 13,987 (0.55%)
  * `Analysis`: 2,677 (0.11%)
  * `Backdoor` / `Backdoors`: 2,329 (0.09%) (normalized)
  * `Shellcode`: 1,511 (0.06%)
  * `Worms`: 174 (0.01%)

---

## 5. Temporal Attack Distribution (Interleaving vs. Episodic Analysis)

* **Key Finding for RQ5 & SRE Alerting:**
  * Total distinct attack runs: **59,392**.
  * Median attack run length: **1 single flow**.
  * **51.84%** of all attack episodes consist of an isolated single flow surrounded by normal traffic.
  * **76.30%** of attack episodes are $\le 5$ flows.
  * Only **0.35%** of attack episodes are $\ge 50$ flows.
* **Implication for Persistence Filtering ($k$ consecutive anomalies):**
  * Persistence filtering requiring $k \ge 2$ or $k \ge 3$ consecutive anomalous observations at the flow level will inherently suppress single-flow transient attacks.
  * However, when aggregating into 10-second windows (as the base paper suggests), 55.76% of windows contain at least one attack flow.
  * This confirms the project plan's justification for using **CSE-CIC-IDS2018** (AWS infrastructure DoS/DDoS flooding) for detection delay and persistence filtering operational evaluations.

