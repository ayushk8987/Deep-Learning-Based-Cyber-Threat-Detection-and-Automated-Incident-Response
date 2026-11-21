import unittest
import config
from src.severity_engine import calculate_threat_severity
from src.response_engine import generate_response_recommendation
from src.database import init_db

class TestResponseEngine(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_severity_calculation(self):
        sev_benign, _ = calculate_threat_severity("Benign", 0.99)
        self.assertEqual(sev_benign, "Informational")

        sev_probe, _ = calculate_threat_severity("Probe", 0.70)
        self.assertEqual(sev_probe, "Low")

        sev_dos, _ = calculate_threat_severity("DoS", 0.95, {"count": 400})
        self.assertEqual(sev_dos, "Critical")

        sev_u2r, _ = calculate_threat_severity("U2R", 0.80)
        self.assertEqual(sev_u2r, "Critical")

    def test_response_safeguard_mode(self):
        resp = generate_response_recommendation(
            threat_category="DoS",
            severity="High",
            confidence=0.92,
            auto_save=False
        )
        self.assertEqual(resp["response_mode"], "SIMULATION_ONLY")
        self.assertTrue(resp["requires_approval"])
        self.assertEqual(resp["action_status"], "PENDING_APPROVAL")
        self.assertEqual(resp["recommended_action"], "SIMULATED_IP_BLOCK")

if __name__ == "__main__":
    unittest.main()
