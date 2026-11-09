"""
Unit tests for Kneedle dimension selection.
Verifies:
1. Orientation correctness (increasing & concave vs wrong orientations)
2. Detection accuracy on toy curves with known knee points
3. Monotonicity and curvature properties
"""

import unittest
import numpy as np
from kneed import KneeLocator
from src.kneedle import find_knee_dimension

class TestKneedleOrientation(unittest.TestCase):
    def test_toy_curve_known_knee(self):
        """
        Verify that KneeLocator with curve='concave', direction='increasing'
        accurately identifies the known knee point on a synthetic concave curve.
        """
        x = np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        # Sharp bend at x = 3: slope drops from 2.0 to 0.4
        y = np.array([1.0, 3.2, 5.0, 5.5, 5.9, 6.2, 6.4, 6.6, 6.7, 6.8])
        
        # Verify curve is strictly increasing
        self.assertTrue(all(np.diff(y) > 0), "Curve must be monotonically increasing")
        
        kl = KneeLocator(x, y, curve="concave", direction="increasing", online=True)
        self.assertEqual(kl.knee, 3, f"Expected knee at 3, got {kl.knee}")

    def test_wrong_orientation_fails_or_yields_boundary(self):
        """
        Verify that passing the wrong orientation (e.g. convex/decreasing)
        either fails to find a knee or returns a degenerate boundary point.
        """
        x = np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        y = np.array([1.0, 3.2, 5.0, 5.5, 5.9, 6.2, 6.4, 6.6, 6.7, 6.8])
        
        kl_wrong = KneeLocator(x, y, curve="convex", direction="decreasing", online=True)
        # On an increasing concave curve, convex/decreasing will find knee=1 or None
        self.assertTrue(kl_wrong.knee is None or kl_wrong.knee == 1,
                        f"Wrong orientation should fail or return boundary, got {kl_wrong.knee}")

    def test_find_knee_dimension_wrapper(self):
        """
        Verify find_knee_dimension wrapper on synthetic matrix profile array.
        """
        # Create dummy mps with shape (5, 100) where per-dim max is increasing & concave
        mps = np.zeros((5, 100))
        # Dim 1 max = 2.0, Dim 2 max = 4.0, Dim 3 max = 5.2, Dim 4 max = 5.6, Dim 5 max = 5.8
        target_maxes = [2.0, 4.0, 5.2, 5.6, 5.8]
        for k, m_val in enumerate(target_maxes):
            mps[k, :] = np.linspace(0.5, m_val, 100)
            
        knee, info = find_knee_dimension(mps, online=True, metric="max")
        self.assertIn(knee, [2, 3], f"Expected knee around 2 or 3, got {knee}")
        self.assertEqual(info["x"], [1, 2, 3, 4, 5])
        self.assertEqual(info["y"], target_maxes)

if __name__ == "__main__":
    unittest.main()

