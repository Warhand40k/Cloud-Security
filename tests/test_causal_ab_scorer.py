"""
Unit tests for Causal AB-Join Scorer (Config A-prime).
Verifies:
1. Acceptance Check: No future data used by A-prime scores (truncation & future-mutation invariance).
2. Correctness of multidimensional distance combination (mirroring mSTAMP).
3. Causal right-alignment properties.
"""

import unittest
import numpy as np
from src.causal_ab_scorer import (
    compute_multidimensional_ab_profile,
    compute_causal_point_scores,
    CausalABScorer
)

class TestCausalABScorer(unittest.TestCase):
    def setUp(self):
        np.random.seed(42)
        self.m = 15
        self.D = 4
        # Benign training history B
        self.B = np.random.randn(300, self.D)
        # Evaluation series A
        self.A = np.random.randn(200, self.D)

    def test_no_future_data_used_by_aprime_scores(self):
        """
        CRITICAL ACCEPTANCE CHECK:
        Verify that a window's score at time t in A depends ONLY on data up to time t,
        and is completely invariant to future data truncation or future mutations.
        """
        scorer = CausalABScorer(m=self.m, knee_dim=2)
        scorer.fit(self.B)
        
        # 1. Full scores on A (length 200)
        full_scores = scorer.score(self.A)
        
        # 2. Score on truncated A (length 100, zero future data beyond t=100)
        N_eval = 100
        A_trunc = self.A[:N_eval].copy()
        trunc_scores = scorer.score(A_trunc)
        
        # Subsequence scores up to N_eval must match EXACTLY
        # For causal right-alignment, time steps up to N_eval depend strictly on A[:N_eval]
        np.testing.assert_allclose(
            full_scores[:N_eval],
            trunc_scores[:N_eval],
            rtol=1e-10,
            atol=1e-10,
            err_msg="A-prime score of window t must NOT change when future series is truncated!"
        )
        
        # 3. Mutate future data in A drastically (inject massive spike at t in [150, 180])
        A_mutated = self.A.copy()
        A_mutated[150:180, :] += 100.0
        mutated_scores = scorer.score(A_mutated)
        
        # Scores before t=150 must remain bit-for-bit identical!
        np.testing.assert_allclose(
            full_scores[:150],
            mutated_scores[:150],
            rtol=1e-10,
            atol=1e-10,
            err_msg="A-prime score before an anomaly must NOT change when future data is mutated!"
        )

    def test_multidimensional_combination_correctness(self):
        """
        Verify that multidimensional combination computes the mean of the
        k smallest 1D profile distances at every time step.
        """
        mps, per_dim = compute_multidimensional_ab_profile(self.A, self.B, m=self.m)
        D, L = per_dim.shape
        self.assertEqual(mps.shape, (D, L))
        
        # Check for each k in 1..D that mps[k-1, i] is exactly mean of sorted[:k]
        for i in range(0, L, 20):
            sorted_i = np.sort(per_dim[:, i])
            for k in range(1, D + 1):
                expected_mean = np.mean(sorted_i[:k])
                self.assertAlmostEqual(mps[k - 1, i], expected_mean, places=7)

    def test_causal_right_alignment(self):
        """
        Verify causal alignment mapping:
        Score at time step t >= m - 1 corresponds to profile index i = t - m + 1.
        """
        mps = np.arange(1, 11).reshape(1, 10).astype(float) # shape (1, 10)
        m = 5
        n_samples = 14 # L = 10, so n_samples = 10 + 5 - 1 = 14
        scores = compute_causal_point_scores(mps, knee_dim=1, n_samples=n_samples, m=m)
        
        # Pre-fill
        self.assertEqual(scores[0], mps[0, 0])
        self.assertEqual(scores[m - 2], mps[0, 0])
        # First completed window at t = m - 1
        self.assertEqual(scores[m - 1], mps[0, 0])
        # Subsequent windows
        for i in range(10):
            self.assertEqual(scores[m - 1 + i], mps[0, i])

if __name__ == "__main__":
    unittest.main()

