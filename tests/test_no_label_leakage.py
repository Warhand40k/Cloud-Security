"""
Unit Test: Label-Permutation Leakage Verification (Stage 1 Step 4)
Asserts that test labels (y_test) are NEVER leaked into:
1. Training or calibration of any model
2. Anomaly score computation on test data
3. Threshold selection or hyperparameter tuning
4. Alert sequence generation (y_pred)

Protocol:
1. Run pipeline on unpermuted test labels to get baseline scores, thresholds, and predictions.
2. For 5 distinct random seeds, randomly permute the test labels (y_test).
3. Re-run pipeline through threshold fitting and alert generation.
4. Assert that:
   - Alert sequences (y_pred) are bit-identical to the unpermuted run.
   - Anomaly scores (y_score) are bit-identical to the unpermuted run.
   - Selected thresholds / parameters are bit-identical to the unpermuted run.
   - Evaluation metrics (F1, Precision, Recall) DO differ, proving label permutation was active.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from experiments.run_timeblock_v2 import evaluate_partition

class TestNoLabelLeakage(unittest.TestCase):
    def setUp(self):
        # Create a controlled multi-dimensional time series
        np.random.seed(42)
        n_train, n_val, n_test = 80, 40, 50
        n_total = n_train + n_val + n_test
        n_features = 4

        # Base noise
        X = np.random.normal(0, 1, size=(n_total, n_features))
        y = np.zeros(n_total, dtype=int)

        # Injected anomalies in val and test
        # Val attacks: 5 steps
        X[n_train + 15 : n_train + 20] += 3.5
        y[n_train + 15 : n_train + 20] = 1

        # Test attacks: 15 steps
        X[n_train + n_val + 10 : n_train + n_val + 25] += 4.0
        y[n_train + n_val + 10 : n_train + n_val + 25] = 1

        self.X_train = X[:n_train]
        self.y_train = y[:n_train]

        self.X_val = X[n_train : n_train + n_val]
        self.y_val = y[n_train : n_train + n_val]

        self.X_test = X[n_train + n_val :]
        self.y_test = y[n_train + n_val :]
        self.timestamps_test = np.arange(n_test, dtype=float) * 60.0

        self.tmp_dir = "results/v3/test_leakage_scratch"
        os.makedirs(self.tmp_dir, exist_ok=True)

    def test_test_label_permutation_leakage_5_seeds(self):
        """
        Runs unpermuted run vs. 5 permuted runs with different seeds.
        Asserts bit-identical alert sequences and scores across all models.
        """
        # Baseline unpermuted run
        unpermuted_res = evaluate_partition(
            block_name="leakage_baseline",
            dataset_name="TestSynthetic",
            X_train=self.X_train, y_train=self.y_train,
            X_val=self.X_val, y_val=self.y_val,
            X_test=self.X_test, y_test=self.y_test,
            timestamps_test=self.timestamps_test,
            step_sec=60.0,
            subseq_len_m=5,
            seed=42,
            is_flow_data=False,
            output_predictions_dir=self.tmp_dir
        )
        base_df = pd.read_parquet(os.path.join(self.tmp_dir, "preds_leakage_baseline.parquet"))

        # Identify all pred and score columns
        pred_cols = [c for c in base_df.columns if c.endswith("_pred")]
        score_cols = [c for c in base_df.columns if c.endswith("_score")]

        self.assertGreater(len(pred_cols), 5, "Should evaluate multiple models")

        permutation_seeds = [101, 202, 303, 404, 505]
        for p_seed in permutation_seeds:
            rng = np.random.default_rng(p_seed)
            permuted_y_test = rng.permutation(self.y_test)

            # Ensure permutation actually shuffled the labels
            self.assertFalse(
                np.array_equal(self.y_test, permuted_y_test),
                f"Permutation seed {p_seed} failed to alter label order"
            )

            permuted_res = evaluate_partition(
                block_name=f"leakage_perm_{p_seed}",
                dataset_name="TestSynthetic",
                X_train=self.X_train, y_train=self.y_train,
                X_val=self.X_val, y_val=self.y_val,
                X_test=self.X_test, y_test=permuted_y_test,
                timestamps_test=self.timestamps_test,
                step_sec=60.0,
                subseq_len_m=5,
                seed=42,
                is_flow_data=False,
                output_predictions_dir=self.tmp_dir
            )
            perm_df = pd.read_parquet(os.path.join(self.tmp_dir, f"preds_leakage_perm_{p_seed}.parquet"))

            # 1. Assert bit-identical alert sequences for every model
            for p_col in pred_cols:
                # Skip Random Stratified which uses empirical prevalence if defined, but our Random Stratified baseline uses train prevalence
                base_alerts = base_df[p_col].values
                perm_alerts = perm_df[p_col].values
                self.assertTrue(
                    np.array_equal(base_alerts, perm_alerts),
                    f"Leakage detected! Alert sequence for {p_col} changed under permuted test labels (seed {p_seed})!"
                )

            # 2. Assert bit-identical anomaly scores for every model
            for s_col in score_cols:
                base_scores = base_df[s_col].values
                perm_scores = perm_df[s_col].values
                self.assertTrue(
                    np.array_equal(base_scores, perm_scores),
                    f"Leakage detected! Anomaly scores for {s_col} changed under permuted test labels (seed {p_seed})!"
                )

            # 3. Verify that evaluation metrics reflect the permuted labels (metrics may differ)
            base_f1_map = {r["Model"]: r["F1"] for r in unpermuted_res}
            perm_f1_map = {r["Model"]: r["F1"] for r in permuted_res}
            any_metric_diff = any(base_f1_map[m] != perm_f1_map[m] for m in base_f1_map if not m.endswith("All-Attack") and not m.endswith("All-Normal"))
            self.assertTrue(any_metric_diff, f"Evaluation metrics should reflect permuted labels for seed {p_seed}")

    def tearDown(self):
        # Cleanup temporary scratch files
        if os.path.exists(self.tmp_dir):
            import shutil
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
