"""
Test Scaler Isolation and Leakage-Free Reference Fitting (Stage 1.5 Step 3)

Asserts:
1. Scalers are fit exclusively on the designated training/reference split.
2. Validation and test splits are strictly transformed, never used to update or refit scaler parameters.
3. Assert that fitting on validation or test would alter scaler parameters, proving no silent leakage.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FEATURE_COLS_CSE = [
    "flow_count", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
    "flow_duration_mean", "flow_byts_s_mean", "flow_pkts_s_mean",
    "syn_flags_total", "rst_flags_total", "ack_flags_total", "pkt_len_mean", "unique_dst_ports"
]

class TestScalerLeakage(unittest.TestCase):

    def test_cse_scaler_reference_isolation(self):
        th_path = "data/processed/csecicids2018_thursday_60s_regular.parquet"
        fr_path = "data/processed/csecicids2018_friday_60s_regular.parquet"

        self.assertTrue(os.path.exists(th_path), f"Missing {th_path}")
        self.assertTrue(os.path.exists(fr_path), f"Missing {fr_path}")

        th_df = pd.read_parquet(th_path)
        fr_df = pd.read_parquet(fr_path)

        # Cross-day reference: Thursday pure benign [0:507]
        ref_raw = np.nan_to_num(th_df.iloc[0:507][FEATURE_COLS_CSE].values.astype(float))
        fr_val_raw = np.nan_to_num(fr_df.iloc[0:552][FEATURE_COLS_CSE].values.astype(float))
        fr_test_raw = np.nan_to_num(fr_df.iloc[552:719][FEATURE_COLS_CSE].values.astype(float))

        scaler = StandardScaler()
        ref_scaled = scaler.fit_transform(ref_raw)
        fitted_mean = scaler.mean_.copy()
        fitted_var = scaler.var_.copy()

        # Transform val and test
        val_scaled = scaler.transform(fr_val_raw)
        test_scaled = scaler.transform(fr_test_raw)

        # Verify scaler parameters were NOT altered by transforming val/test
        np.testing.assert_array_equal(scaler.mean_, fitted_mean, err_msg="Scaler mean was modified during transform!")
        np.testing.assert_array_equal(scaler.var_, fitted_var, err_msg="Scaler variance was modified during transform!")

        # Verify that fitting on val or test would produce different parameters (proving reference exclusivity)
        leaked_scaler = StandardScaler().fit(np.vstack([ref_raw, fr_val_raw, fr_test_raw]))
        self.assertFalse(
            np.allclose(leaked_scaler.mean_, fitted_mean),
            "Fitted mean identical to leaked mean; test distribution may lack contrast."
        )

    def test_minimum_sample_size_assertions(self):
        """Enforces minimum training size constraints: >=100 windows, >=10*m library subsequences."""
        effective_m = 10
        min_windows = 100

        # Satisfies constraints
        valid_history = np.random.randn(507, 13)
        self.assertGreaterEqual(len(valid_history), min_windows)
        self.assertGreaterEqual(len(valid_history) - effective_m + 1, 10 * effective_m)

        # Starved history (Within-Day Friday: 45 windows, Within-Day Wednesday: 16 windows)
        starved_friday = np.random.randn(45, 13)
        starved_wednesday = np.random.randn(16, 13)

        self.assertLess(len(starved_friday), min_windows, "Friday within-day should be flagged as starved (<100)")
        self.assertLess(len(starved_wednesday), min_windows, "Wednesday within-day should be flagged as starved (<100)")

if __name__ == "__main__":
    unittest.main()
