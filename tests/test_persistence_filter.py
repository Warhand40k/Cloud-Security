"""
Unit tests for Persistence Filter (Config C), verifying the k=1 identity property
and higher-order temporal filtering semantics.
"""

import unittest
import numpy as np
from src.persistence_filter import PersistenceFilter
from src.evaluation import compute_classification_metrics, compute_sre_operational_metrics

class TestPersistenceFilter(unittest.TestCase):
    def test_k1_identity_on_various_sequences(self):
        """Assert that k=1 persistence is an exact identity transformation."""
        rng = np.random.RandomState(42)
        pf = PersistenceFilter(k=1)

        test_cases = [
            # Trivial cases
            np.zeros(100, dtype=int),
            np.ones(100, dtype=int),
            # Intermittent spikes
            np.array([0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0]),
            # Random Bernoulli sequences
            rng.binomial(1, 0.05, size=500),
            rng.binomial(1, 0.20, size=500),
            rng.binomial(1, 0.80, size=500)
        ]

        for i, seq in enumerate(test_cases):
            filtered = pf.filter(seq)
            np.testing.assert_array_equal(
                filtered, seq.astype(int),
                err_msg=f"Test case {i}: k=1 persistence altered the alert sequence!"
            )

    def test_k1_identity_leaves_metrics_identical(self):
        """Assert that classification and SRE operational metrics are identical with k=1."""
        rng = np.random.RandomState(123)
        y_true = rng.binomial(1, 0.15, size=300)
        raw_alerts = rng.binomial(1, 0.20, size=300)

        pf = PersistenceFilter(k=1)
        filtered_alerts = pf.filter(raw_alerts)

        m_raw = compute_classification_metrics(y_true, raw_alerts)
        m_filt = compute_classification_metrics(y_true, filtered_alerts)

        self.assertEqual(m_raw["f1"], m_filt["f1"])
        self.assertEqual(m_raw["precision"], m_filt["precision"])
        self.assertEqual(m_raw["recall"], m_filt["recall"])
        self.assertEqual(m_raw["fpr"], m_filt["fpr"])

        sre_raw = compute_sre_operational_metrics(y_true, raw_alerts)
        sre_filt = compute_sre_operational_metrics(y_true, filtered_alerts)

        self.assertEqual(sre_raw["total_alerts"], sre_filt["total_alerts"])
        self.assertEqual(sre_raw["campaign_recall"], sre_filt["campaign_recall"])
        self.assertEqual(sre_raw["mttd_detected_campaigns_only_sec"], sre_filt["mttd_detected_campaigns_only_sec"])

    def test_k_greater_than_one_suppresses_transient_spikes(self):
        """Assert that k=2 and k=3 properly suppress isolated spikes and require consecutive runs."""
        # Sequence with isolated 1, pair of 1s, and triple of 1s
        seq = np.array([0, 1, 0, 1, 1, 0, 1, 1, 1, 0])
        # Indices:      0  1  2  3  4  5  6  7  8  9

        pf_k2 = PersistenceFilter(k=2)
        filtered_k2 = pf_k2.filter(seq)
        # Expected k=2: index 1 suppressed; index 3,4 fires at 4; index 6,7,8 fires at 7, 8
        expected_k2 = np.array([0, 0, 0, 0, 1, 0, 0, 1, 1, 0])
        np.testing.assert_array_equal(filtered_k2, expected_k2)

        pf_k3 = PersistenceFilter(k=3)
        filtered_k3 = pf_k3.filter(seq)
        # Expected k=3: only index 8 fires
        expected_k3 = np.array([0, 0, 0, 0, 0, 0, 0, 0, 1, 0])
        np.testing.assert_array_equal(filtered_k3, expected_k3)

if __name__ == "__main__":
    unittest.main()

