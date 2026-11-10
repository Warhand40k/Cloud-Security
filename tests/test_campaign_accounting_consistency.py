"""
Test Campaign Accounting Consistency (Stage 1.5 Step 2)

Asserts:
1. find_campaign_intervals behaves strictly as specified (g=0, contiguous 1s, clipped to slice).
2. The campaign count in every row of results/v3_1/metrics/timeblock_v3_1_detailed.csv
   strictly matches the count in results/v3_1/metrics/slice_composition.csv for that slice.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.evaluation import find_campaign_intervals

class TestCampaignAccountingConsistency(unittest.TestCase):

    def test_find_campaign_intervals_contract(self):
        """Verify g=0 contiguous attack semantics and clipping to slice."""
        # Empty sequence
        self.assertEqual(find_campaign_intervals(np.array([])), [])

        # All zeros
        self.assertEqual(find_campaign_intervals(np.zeros(50, dtype=int)), [])

        # All ones
        self.assertEqual(find_campaign_intervals(np.ones(50, dtype=int)), [(0, 49)])

        # Alternating ones and zeros under g=0 (each is separate campaign)
        y_alt = np.array([1, 0, 1, 0, 1])
        self.assertEqual(find_campaign_intervals(y_alt, gap_tolerance=0), [(0, 0), (2, 2), (4, 4)])

        # Under g=1, gaps of size 1 are merged
        self.assertEqual(find_campaign_intervals(y_alt, gap_tolerance=1), [(0, 4)])

        # Isolated burst in middle
        y_burst = np.array([0, 0, 1, 1, 1, 0, 0])
        self.assertEqual(find_campaign_intervals(y_burst, gap_tolerance=0), [(2, 4)])

        # Boundary clipping: burst at start and burst at end
        y_bounds = np.array([1, 1, 0, 0, 1])
        self.assertEqual(find_campaign_intervals(y_bounds, gap_tolerance=0), [(0, 1), (4, 4)])

    def test_performance_campaigns_match_composition_table(self):
        """Assert that every performance row matches the composition table campaign count exactly."""
        comp_path = "results/v3_1/metrics/slice_composition.csv"
        perf_path = "results/v3_1/metrics/timeblock_v3_1_detailed.csv"

        self.assertTrue(os.path.exists(comp_path), f"Missing {comp_path}")
        self.assertTrue(os.path.exists(perf_path), f"Missing {perf_path}")

        comp_df = pd.read_csv(comp_path)
        perf_df = pd.read_csv(perf_path)

        comp_test = comp_df[comp_df["Partition"] == "Test"].copy()
        self.assertGreater(len(comp_test), 0, "No test slices found in composition table")

        for _, c_row in comp_test.iterrows():
            block_name = c_row["Block"]
            expected_camps = int(c_row["Campaigns"])

            sub_perf = perf_df[perf_df["Block"] == block_name]
            self.assertGreater(len(sub_perf), 0, f"No performance rows found for block: {block_name}")

            actual_camps = sub_perf["Total_Campaigns"].values
            for idx, act in enumerate(actual_camps):
                model_name = sub_perf.iloc[idx]["Model"]
                self.assertEqual(
                    act, expected_camps,
                    f"Campaign count mismatch for [{block_name} - {model_name}]: "
                    f"Performance table shows {act}, but composition table shows {expected_camps}"
                )

if __name__ == "__main__":
    unittest.main()
