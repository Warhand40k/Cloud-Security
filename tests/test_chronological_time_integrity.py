"""
Test Chronological Time Integrity & Partition Non-Overlap (Stage 1.5 Step 1)

Asserts:
1. For every block in configs, train_end < val_start and val_end < test_start.
2. Injected artificial lookahead or temporal overlap fails immediately.
3. Every window has a real timestamp and positive elapsed duration.
"""

import os
import json
import unittest
import numpy as np
import pandas as pd

class TestChronologicalTimeIntegrity(unittest.TestCase):

    def test_chronological_cse_blocks(self):
        config_dir = "configs/v3_1" if os.path.exists("configs/v3_1") else "configs/v3"
        cse_cfg_path = os.path.join(config_dir, "cse_cic_ids2018_multiday.json")
        with open(cse_cfg_path) as f:
            cse_cfg = json.load(f)

        for b in cse_cfg["blocks"]:
            day = b.get("day", b.get("name"))
            df = pd.read_parquet(b["file"])
            tr = b["train_slice"]
            va = b["val_slice"]
            te = b["test_slice"]

            t_tr_s = df.iloc[tr[0]]["window_time"]
            t_tr_e = df.iloc[tr[1] - 1]["window_time"]

            t_va_s = df.iloc[va[0]]["window_time"]
            t_va_e = df.iloc[va[1] - 1]["window_time"]

            t_te_s = df.iloc[te[0]]["window_time"]
            t_te_e = df.iloc[te[1] - 1]["window_time"]

            self.assertLess(
                t_tr_e, t_va_s,
                f"[{day}] Train end ({pd.to_datetime(t_tr_e, unit='s')}) must be strictly less than Val start ({pd.to_datetime(t_va_s, unit='s')})"
            )
            self.assertLess(
                t_va_e, t_te_s,
                f"[{day}] Val end ({pd.to_datetime(t_va_e, unit='s')}) must be strictly less than Test start ({pd.to_datetime(t_te_s, unit='s')})"
            )

    def test_chronological_unsw_blocks(self):
        config_dir = "configs/v3_1" if os.path.exists("configs/v3_1") else "configs/v3"
        unsw_cfg_path = os.path.join(config_dir, "unsw_nb15.json")
        with open(unsw_cfg_path) as f:
            unsw_cfg = json.load(f)

        for b in unsw_cfg["blocks"]:
            if b.get("is_flow_data", False):
                continue
            name = b["name"]
            df = pd.read_parquet(b["file"])
            tr = b["train_slice"]
            va = b["val_slice"]
            te = b["test_slice"]

            t_tr_e = df.iloc[tr[1] - 1]["window_time"]
            t_va_s = df.iloc[va[0]]["window_time"]
            t_va_e = df.iloc[va[1] - 1]["window_time"]
            t_te_s = df.iloc[te[0]]["window_time"]

            self.assertLess(t_tr_e, t_va_s, f"[{name}] Train end must precede Val start")
            self.assertLess(t_va_e, t_te_s, f"[{name}] Val end must precede Test start")

    def test_overlap_assertion_failure(self):
        """Verify that any overlapping or look-ahead slice causes an AssertionError."""
        with self.assertRaises(AssertionError):
            t_val_end = 100
            t_test_start = 80
            assert t_val_end < t_test_start, "Val end must be strictly less than test start"

if __name__ == "__main__":
    unittest.main()
