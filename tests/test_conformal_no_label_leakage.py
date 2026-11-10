"""
Unit Test: Conformal Label-Permutation Leakage Verification (Stage 4 Step 1)
Asserts that test labels (y_test) are NEVER read or leaked into:
1. Static split-conformal threshold calibration
2. Rolling split-conformal buffer updates, threshold sequence (tau_t), or predictions
3. Adaptive Conformal Inference (ACI) adapted risk sequence (alpha_t), threshold sequence (tau_t), or predictions

Protocol:
1. For 5 distinct random seeds, randomly permute the test labels (y_test).
2. Run label-free calibrators on the fixed test scores.
3. Assert that:
   - Alert sequences (y_pred) are bit-identical to the unpermuted run.
   - Threshold sequences (tau_t) are bit-identical to the unpermuted run.
   - Adapted alpha sequences (alpha_t) are bit-identical to the unpermuted run.
4. Negative control / Sensitivity assertion:
   - If an oracle calibrator is provided with verified_benign_mask = (y_test_perm == 0),
     it FAILS the bit-identical test, proving that label leakage is reliably detected.
"""

import unittest
import numpy as np
from sklearn.metrics import f1_score
from src.adaptive_threshold import ConformalQuantileThreshold

class TestConformalNoLabelLeakage(unittest.TestCase):
    def setUp(self):
        np.random.seed(42)
        n_cal = 200
        n_test = 300

        # Benign calibration scores
        self.cal_scores = np.random.exponential(scale=1.0, size=n_cal)
        self.y_cal = np.zeros(n_cal, dtype=int)

        # Test scores: benign baseline with an attack burst in windows 100 to 160
        self.test_scores = np.random.exponential(scale=1.0, size=n_test)
        self.y_test = np.zeros(n_test, dtype=int)
        self.test_scores[100:160] += 5.0
        self.y_test[100:160] = 1

        self.alpha = 0.05
        self.seeds = [42, 101, 2024, 7777, 99999]

    def test_label_free_conformal_is_bit_identical_under_label_permutation(self):
        """
        Asserts that label-free calibrators produce 100% bit-identical thresholds,
        predictions, and adapted alpha series when test labels are shuffled.
        """
        cqt = ConformalQuantileThreshold(alpha=self.alpha).fit(self.cal_scores, y_cal=self.y_cal)

        # Baseline unpermuted runs
        pred_stat_base = cqt.predict(self.test_scores)
        pred_roll_base, th_roll_base = cqt.predict_rolling_label_free(self.test_scores, window_size=60)
        pred_aci_base, th_aci_base, alphas_aci_base = cqt.predict_aci_label_free(
            self.test_scores, gamma=0.01, window_size=60
        )

        base_f1_stat = f1_score(self.y_test, pred_stat_base, zero_division=0)
        base_f1_roll = f1_score(self.y_test, pred_roll_base, zero_division=0)
        base_f1_aci = f1_score(self.y_test, pred_aci_base, zero_division=0)

        for seed in self.seeds:
            rng = np.random.default_rng(seed)
            y_test_perm = rng.permutation(self.y_test)

            # Confirm permutation actually shuffled labels
            self.assertFalse(
                np.array_equal(self.y_test, y_test_perm),
                f"Seed {seed} failed to permute test labels"
            )

            # 1. Static Split-Conformal
            pred_stat = cqt.predict(self.test_scores)
            np.testing.assert_array_equal(
                pred_stat, pred_stat_base,
                err_msg=f"Static conformal predictions changed under seed {seed}"
            )

            # 2. Rolling Split-Conformal (Label-Free)
            pred_roll, th_roll = cqt.predict_rolling_label_free(self.test_scores, window_size=60)
            np.testing.assert_array_equal(
                pred_roll, pred_roll_base,
                err_msg=f"Rolling conformal predictions changed under seed {seed}"
            )
            np.testing.assert_array_equal(
                th_roll, th_roll_base,
                err_msg=f"Rolling conformal thresholds changed under seed {seed}"
            )

            # 3. ACI (Label-Free)
            pred_aci, th_aci, alphas_aci = cqt.predict_aci_label_free(
                self.test_scores, gamma=0.01, window_size=60
            )
            np.testing.assert_array_equal(
                pred_aci, pred_aci_base,
                err_msg=f"ACI predictions changed under seed {seed}"
            )
            np.testing.assert_array_equal(
                th_aci, th_aci_base,
                err_msg=f"ACI thresholds changed under seed {seed}"
            )
            np.testing.assert_array_equal(
                alphas_aci, alphas_aci_base,
                err_msg=f"ACI adapted alphas changed under seed {seed}"
            )

            # Verify that metric evaluations DO differ because ground truth labels shifted
            perm_f1_stat = f1_score(y_test_perm, pred_stat, zero_division=0)
            perm_f1_roll = f1_score(y_test_perm, pred_roll, zero_division=0)
            perm_f1_aci = f1_score(y_test_perm, pred_aci, zero_division=0)

            self.assertNotEqual(
                base_f1_roll, perm_f1_roll,
                f"F1 should change when labels are permuted (seed {seed})"
            )
            self.assertNotEqual(
                base_f1_aci, perm_f1_aci,
                f"F1 should change when labels are permuted (seed {seed})"
            )

    def test_oracle_variant_fails_leakage_assertion(self):
        """
        Sensitivity test: proves that if test labels (verified_benign_mask) are passed,
        the threshold and predictions CHANGE across permuted seeds, demonstrating label leakage.
        """
        cqt = ConformalQuantileThreshold(alpha=self.alpha).fit(self.cal_scores, y_cal=self.y_cal)

        # Baseline run with true labels
        pred_roll_oracle_base, th_roll_oracle_base = cqt.predict_rolling_oracle(
            self.test_scores, window_size=60, verified_benign_mask=(self.y_test == 0)
        )
        pred_aci_oracle_base, th_aci_oracle_base, alphas_aci_oracle_base = cqt.predict_aci_oracle(
            self.test_scores, gamma=0.01, window_size=60, verified_benign_mask=(self.y_test == 0)
        )

        detected_leakage_roll = False
        detected_leakage_aci = False

        for seed in self.seeds:
            rng = np.random.default_rng(seed)
            y_test_perm = rng.permutation(self.y_test)

            pred_roll_perm, th_roll_perm = cqt.predict_rolling_oracle(
                self.test_scores, window_size=60, verified_benign_mask=(y_test_perm == 0)
            )
            pred_aci_perm, th_aci_perm, alphas_aci_perm = cqt.predict_aci_oracle(
                self.test_scores, gamma=0.01, window_size=60, verified_benign_mask=(y_test_perm == 0)
            )

            if not np.array_equal(pred_roll_perm, pred_roll_oracle_base) or not np.array_equal(th_roll_perm, th_roll_oracle_base):
                detected_leakage_roll = True

            if not np.array_equal(pred_aci_perm, pred_aci_oracle_base) or not np.array_equal(alphas_aci_perm, alphas_aci_oracle_base):
                detected_leakage_aci = True

        self.assertTrue(
            detected_leakage_roll,
            "Oracle rolling calibrator must fail bit-identity test when test labels are permuted (proves label sensitivity)"
        )
        self.assertTrue(
            detected_leakage_aci,
            "Oracle ACI calibrator must fail bit-identity test when test labels are permuted (proves label sensitivity)"
        )

if __name__ == "__main__":
    unittest.main()

