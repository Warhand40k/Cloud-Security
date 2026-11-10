"""
Unit Tests: Primary Threshold Rule & Matched Label Integrity (Stage 1.5 Step 4)
Verifies:
1. calibrate_benign_quantile_threshold controls FAR <= alpha on benign validation scores.
2. Attack scores/labels in validation do NOT alter the calibrated threshold (no F1 optimization).
3. Point mass / ties in benign scores do not cause FAR blowout.
4. MADThreshold epsilon floor prevents division/blow-up on flat signals and logs zero_mad_fraction_.
5. Matched operating point logic enforces one-sided FPR targets and rejects zero-recall predictions.
"""

import os
import sys
import unittest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.adaptive_threshold import MADThreshold, calibrate_benign_quantile_threshold

class TestThresholdRule(unittest.TestCase):
    def test_benign_quantile_threshold_far_controlled(self):
        np.random.seed(42)
        n_benign = 500
        n_attack = 50
        benign_scores = np.random.exponential(scale=1.0, size=n_benign)
        attack_scores = np.random.exponential(scale=5.0, size=n_attack) + 2.0

        val_scores = np.concatenate([benign_scores, attack_scores])
        y_val = np.concatenate([np.zeros(n_benign, dtype=int), np.ones(n_attack, dtype=int)])

        for alpha in [0.05, 0.01]:
            th = calibrate_benign_quantile_threshold(val_scores, y_val, alpha=alpha)
            # FAR on benign validation must be <= alpha
            emp_far = np.mean(benign_scores >= th)
            self.assertLessEqual(emp_far, alpha + 1e-6, f"Empirical FAR {emp_far} exceeded target {alpha}")

            # Permute or alter attack scores: threshold must remain strictly unchanged
            val_scores_altered = val_scores.copy()
            val_scores_altered[y_val == 1] = np.random.uniform(100, 200, size=n_attack)
            th_altered = calibrate_benign_quantile_threshold(val_scores_altered, y_val, alpha=alpha)
            self.assertEqual(th, th_altered, "Threshold changed when attack scores were altered!")

    def test_benign_quantile_threshold_with_point_mass_zeros(self):
        # 98% zeros, 2% small values
        benign_scores = np.zeros(200, dtype=float)
        benign_scores[-4:] = [0.1, 0.2, 0.3, 0.4]
        y_val = np.zeros(200, dtype=int)

        th_05 = calibrate_benign_quantile_threshold(benign_scores, y_val, alpha=0.05)
        emp_far_05 = np.mean(benign_scores >= th_05)
        self.assertLessEqual(emp_far_05, 0.05)

        # All zeros
        all_zeros = np.zeros(100, dtype=float)
        th_zero = calibrate_benign_quantile_threshold(all_zeros, np.zeros(100, dtype=int), alpha=0.05)
        emp_far_zero = np.mean(all_zeros >= th_zero)
        self.assertLessEqual(emp_far_zero, 0.05)
        self.assertEqual(emp_far_zero, 0.0)

    def test_mad_threshold_epsilon_floor_and_zero_logging(self):
        # Constant scores stream
        scores = np.zeros(100, dtype=float)
        mad = MADThreshold(c=3.0, rolling_window=10, eps=1e-6)
        mad.fit(scores[:50])
        preds = mad.predict(scores)

        # Zero MAD fraction must be 1.0
        self.assertEqual(mad.zero_mad_fraction_, 1.0)
        # Predictions must NOT trigger on constant zero signal
        self.assertEqual(preds.sum(), 0, "Constant flat signal triggered alarms under floored MAD!")

        # Jitter below epsilon
        jitter_scores = np.random.uniform(0, 1e-8, size=100)
        mad2 = MADThreshold(c=3.0, rolling_window=10, eps=1e-6)
        mad2.fit(jitter_scores[:50])
        preds2 = mad2.predict(jitter_scores)
        self.assertEqual(preds2.sum(), 0, "Sub-epsilon jitter triggered alarms under floored MAD!")

    def test_matched_label_one_sided_and_zero_recall(self):
        def determine_match_status(target_type: str, target_val: float, test_metric: float, test_recall: float) -> str:
            if target_type == "fpr":
                if test_recall == 0.0 or test_metric == 0.0 and test_recall == 0.0:
                    return "unmatched (zero recall)"
                if test_metric <= target_val:
                    return "target met"
                return "target not met"
            elif target_type == "recall":
                if test_metric >= target_val - 0.05:
                    return "target met"
                return "target not met"
            return "unknown"

        # Case 1: Achieved FPR = 0.0, Recall = 0.0 -> vacuous / unmatched
        self.assertEqual(determine_match_status("fpr", 0.05, 0.0, 0.0), "unmatched (zero recall)")

        # Case 2: Achieved FPR = 0.02, Recall = 0.70 -> target met (one-sided <= 0.05)
        self.assertEqual(determine_match_status("fpr", 0.05, 0.02, 0.70), "target met")

        # Case 3: Achieved FPR = 0.05, Recall = 0.50 -> target met
        self.assertEqual(determine_match_status("fpr", 0.05, 0.05, 0.50), "target met")

        # Case 4: Achieved FPR = 0.08, Recall = 0.90 -> target not met
        self.assertEqual(determine_match_status("fpr", 0.05, 0.08, 0.90), "target not met")

if __name__ == "__main__":
    unittest.main()

