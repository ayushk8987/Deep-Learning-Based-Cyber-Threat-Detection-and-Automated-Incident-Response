import unittest
import pandas as pd
import numpy as np
import config
from src.preprocessing import map_to_canonical_category, FlowDataPreprocessor

class TestPreprocessing(unittest.TestCase):
    def test_canonical_mapping(self):
        self.assertEqual(map_to_canonical_category("normal"), "Benign")
        self.assertEqual(map_to_canonical_category("BENIGN"), "Benign")
        self.assertEqual(map_to_canonical_category("neptune"), "DoS")
        self.assertEqual(map_to_canonical_category("DDoS"), "DoS")
        self.assertEqual(map_to_canonical_category("ipsweep"), "Probe")
        self.assertEqual(map_to_canonical_category("PortScan"), "Probe")
        self.assertEqual(map_to_canonical_category("guess_passwd"), "R2L")
        self.assertEqual(map_to_canonical_category("buffer_overflow"), "U2R")

    def test_preprocessor_fit_transform(self):
        sample_df = pd.DataFrame({
            "duration": [0, 5, 2],
            "protocol_type": ["tcp", "udp", "icmp"],
            "service": ["http", "dns", "other"],
            "flag": ["SF", "S0", "REJ"],
            "src_bytes": [100, 200, 0],
            "dst_bytes": [500, 0, 0],
            "count": [1, 10, 5],
            "label": ["normal", "neptune", "satan"]
        })

        prep = FlowDataPreprocessor()
        prep.fit(sample_df, target_col="label")
        X, y = prep.transform(sample_df, target_col="label")

        self.assertEqual(X.shape[0], 3)
        self.assertEqual(len(y), 3)
        self.assertFalse(np.isnan(X).any(), "Preprocessed features should contain no NaNs")
        self.assertEqual(y[0], 0)  # Benign
        self.assertEqual(y[1], 1)  # DoS

if __name__ == "__main__":
    unittest.main()
