"""
Unit Tests for ConformalQuantileThreshold (Stage 2 Step 2)
Tests:
1. Finite-sample coverage guarantee on stationary exchangeable benign scores
2. Point-mass tie adjustment on zero-inflated anomaly scores
3. Conformal p-values: bounds in [0, 1] and monotonic decrease with score
4. Causal rolling conformal thresholding: zero look-ahead bias
5. Adaptive Conformal Inference (ACI): dynamic alpha adaptation under drift
6. Ground-truth label filtering in calibration
"""

import unittest
import numpy as np
from src.adaptive_threshold import ConformalQuantileThreshold

class TestConformalQuantileThreshold(unittest.TestCase):
    def setUp(self):
        np.random.seed(42)

    def test_finite_sample_coverage_guarantee(self):
        """
        Under exchangeability (stationary Gaussian noise),
        the empirical false alarm rate on held-out test data must be <= alpha + margin.
        """
        n_cal = 500
        n_test = 2000
        alpha = 0.05

        cal_scores = np.random.exponential(scale=1.0, size=n_cal)
        test_scores = np.random.exponential(scale=1.0, size=n_test)

        cqt = ConformalQuantileThreshold(alpha=alpha)
        cqt.fit(cal_scores)

        preds = cqt.predict(test_scores)
        empirical_far = float(np.mean(preds))

        # Margin: 3 standard deviations of Binomial(n_test, alpha)
        margin = 3.0 * np.sqrt(alpha * (1.0 - alpha) / n_test)
        self.assertLessEqual(
            empirical_far,
            alpha + margin,
            f"Empirical FAR ({empirical_far:.4f}) exceeded target alpha ({alpha}) + 3-sigma margin ({margin:.4f})"
        )

    def test_point_mass_tie_handling(self):
        """
        When calibration scores are heavily compressed at zero (e.g. 95% zeros),
        point-mass tie adjustment must prevent empirical FAR from exceeding alpha.
        """
        n_cal = 400
        n_test = 1000
        alpha = 0.05

        # 95% zeros, 5% positive exponential
        cal_scores = np.zeros(n_cal)
        cal_scores[int(n_cal * 0.95):] = np.random.exponential(scale=2.0, size=n_cal - int(n_cal * 0.95))

        test_scores = np.zeros(n_test)
        test_scores[int(n_test * 0.95):] = np.random.exponential(scale=2.0, size=n_test - int(n_test * 0.95))

        cqt = ConformalQuantileThreshold(alpha=alpha)
        cqt.fit(cal_scores)

        # Threshold must be strictly positive (greater than 0) to avoid flagging all zeros
        self.assertGreater(cqt.threshold_, 0.0, "Threshold must not collapse to 0.0 on zero-inflated scores")

        preds = cqt.predict(test_scores)
        empirical_far = float(np.mean(preds))
        self.assertLessEqual(empirical_far, alpha + 0.02)

    def test_conformal_p_values(self):
        """
        Verify that p-values are bounded in (0, 1] and strictly monotonically non-increasing.
        """
        cal_scores = np.array([0.1, 0.2, 0.5, 0.8, 1.2, 2.0, 3.5, 5.0])
        cqt = ConformalQuantileThreshold(alpha=0.05).fit(cal_scores)

        test_scores = np.array([0.0, 0.15, 0.5, 1.0, 3.0, 6.0])
        p_vals = cqt.compute_p_values(test_scores)

        # All p-values must be in (0, 1]
        self.assertTrue(np.all(p_vals > 0.0))
        self.assertTrue(np.all(p_vals <= 1.0))

        # Monotonically non-increasing with increasing test score
        diffs = np.diff(p_vals)
        self.assertTrue(np.all(diffs <= 1e-9), f"P-values must be non-increasing with score: {p_vals}")

        # An alert from predict() should match p_val <= alpha
        preds = cqt.predict(test_scores, alpha=0.25)
        expected_preds = (p_vals <= 0.25).astype(int)
        np.testing.assert_array_equal(preds, expected_preds)

    def test_rolling_conformal_causality(self):
        """
        Verify that rolling conformal threshold at time t does NOT depend on test_scores[t:].
        """
        n_test = 50
        cal_scores = np.random.normal(10, 1, size=100)
        test_scores_1 = np.random.normal(10, 1, size=n_test)
        test_scores_2 = test_scores_1.copy()
        # Corrupt future values after t=25
        test_scores_2[25:] += 100.0

        cqt = ConformalQuantileThreshold(alpha=0.05).fit(cal_scores)

        # Rolling predictions on both
        _, thresh_1 = cqt.predict_rolling(test_scores_1, window_size=20)
        _, thresh_2 = cqt.predict_rolling(test_scores_2, window_size=20)

        # Thresholds up to t=25 must be bit-identical
        np.testing.assert_array_almost_equal(
            thresh_1[:25],
            thresh_2[:25],
            err_msg="Rolling threshold at time t <= 24 must not depend on future corrupted data at t >= 25"
        )

    def test_aci_adaptation_under_drift(self):
        """
        Verify that Adaptive Conformal Inference (ACI) adapts alpha_t
        when a distribution drift occurs.
        """
        cal_scores = np.random.normal(5, 1, size=200)
        cqt = ConformalQuantileThreshold(alpha=0.05).fit(cal_scores)

        # Drift occurs: mean shifts from 5 to 7
        drifted_scores = np.random.normal(7, 1, size=150)
        preds, thresholds, adapted_alphas = cqt.predict_aci(drifted_scores, gamma=0.05, window_size=30)

        # Initial adapted alpha should start at nominal 0.05
        self.assertAlmostEqual(adapted_alphas[0], 0.05, places=3)
        # Because scores are higher, false alarms occur, which forces alpha_t to decrease (become more conservative)
        self.assertLess(np.min(adapted_alphas), 0.05, "ACI should decrease nominal alpha under positive drift")

    def test_fit_with_labels(self):
        """
        Verify that passing y_cal filters out non-benign calibration points.
        """
        cal_scores = np.array([1.0, 2.0, 1.5, 100.0, 200.0])
        y_cal = np.array([0, 0, 0, 1, 1])

        cqt = ConformalQuantileThreshold(alpha=0.05)
        cqt.fit(cal_scores, y_cal=y_cal)

        # Calibration set should only have length 3 (the benign scores)
        self.assertEqual(cqt.n_cal_, 3)
        self.assertLess(cqt.threshold_, 10.0, "Threshold should be fitted only on benign scores (< 10.0)")

if __name__ == "__main__":
    unittest.main()
