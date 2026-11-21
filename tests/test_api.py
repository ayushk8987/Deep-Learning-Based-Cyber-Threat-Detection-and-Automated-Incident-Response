import unittest
import json
from app import app
from src.database import init_db

class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["response_mode"], "SIMULATION_ONLY")

    def test_dashboard_summary(self):
        response = self.client.get("/api/dashboard/summary")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("total_analyzed", data)
        self.assertIn("threat_distribution", data)

    def test_incidents_list(self):
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_export_csv(self):
        response = self.client.get("/api/export/incidents")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")

    def test_simulate_preset(self):
        response = self.client.post(
            "/api/detection/simulate-preset",
            json={"category": "dos", "count": 2}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["category"], "dos")
        self.assertGreaterEqual(data["processed_count"], 1)

    def test_ai_explain_incident(self):
        # Create an incident first via preset simulation
        sim_res = self.client.post("/api/detection/simulate-preset", json={"category": "probe", "count": 1})
        self.assertEqual(sim_res.status_code, 200)
        inc_id = sim_res.get_json()["results"][0]["incident_id"]

        # Call AI explain endpoint
        response = self.client.get(f"/api/incidents/{inc_id}/ai-explain")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIn("analysis", data)
        self.assertIn("provider", data)

if __name__ == "__main__":
    unittest.main()
