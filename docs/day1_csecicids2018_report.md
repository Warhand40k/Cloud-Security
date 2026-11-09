# Day-1 Verification Report: CSE-CIC-IDS2018 Dataset (Friday-16-02-2018)

> **Date:** 2026-11-09  
> **Source:** AWS Registry of Open Data (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`)  
> **File:** `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` (318.26 MB)  
> **Script:** `scripts/verify_csecicids2018.py`

---

## 1. Dataset Overview & Provenance
* **Cloud Origin:** Generated on dedicated Amazon Web Services (AWS) infrastructure by the Communications Security Establishment (CSE) and Canadian Institute for Cybersecurity (CIC).
* **Attacks Simulated:** DoS Attacks - Hulk (High-volume HTTP flooding) and DoS Attacks - SlowHTTPTest (Low-and-slow exhaustion).
* **Volume:** 1,048,575 flow records across 80 CICFlowMeter features. One duplicate embedded header row detected and pruned.

---

## 2. Timestamps and Chronological Order
* **Timestamp Format:** `dd/MM/yyyy HH:mm:ss`. 0 unparseable or null timestamps.
* **Span:** `2018-02-16 01:00:32` to `2018-02-16 12:58:24` (11.96 continuous hours).
* **Raw Sorting:** Encountered 268,941 backward time jumps in raw file order; strictly sorted chronologically by timestamp prior to windowing and partitioning.

---

## 3. Ground Truth Labels & Class Balance
* **DoS attacks - Hulk:** 461,912 records (44.05%)
* **Benign Traffic:** 446,772 records (42.61%)
* **DoS attacks - SlowHTTPTest:** 139,890 records (13.34%)
* **Total Malicious Records:** 601,802 records (57.39%)

---

## 4. Attack Episode Contiguity (Comparison with UNSW-NB15)

| Metric | UNSW-NB15 (Lab Testbed) | CSE-CIC-IDS2018 (AWS Cloud DoS) |
|---|---|---|
| **Primary Threat Model** | Synthesized multi-vector intrusion | Contiguous DoS/DDoS flooding |
| **Median Attack Run Length** | **1 single flow** | **Contiguous multi-thousand flow bursts** |
| **Max Contiguous Attack Run** | 181 flows | **11,236 flows** |
| **1-Flow Attack Run Share** | 51.84% (interleaved) | Rapid high-throughput bursts |
| **Suitability for Persistence Filter** | Low (suppresses isolated single-flow exploits) | **Optimal (filters noise, detects sustained campaigns)** |

---

## 5. Window-Level Telemetry
* **60-Second Windows:** 191 active windows spanning the 12-hour AWS workday.
  * Benign Windows: 140 (73.30%)
  * Attack Windows: 51 (26.70%)
  * Pure Attack Windows (100% attack flows): 20 windows
* **10-Second Windows:** 500 active windows (40.6% Benign, 59.4% Attack).

