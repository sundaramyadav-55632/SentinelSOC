import unittest

from src.risk.risk_engine import RiskEngine


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RiskEngine()

    def test_critical_brute_force_with_success(self):

        incident = {
            "incident_type": "brute_force_with_success",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "failed_attempts": 5,
            "successful_login": True
        }

        result = self.engine.calculate_score(incident)

        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["severity"], "critical")

    def test_high_brute_force_without_success(self):

        incident = {
            "incident_type": "brute_force",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "failed_attempts": 5,
            "successful_login": False
        }

        result = self.engine.calculate_score(incident)

        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["severity"], "high")

    def test_low_risk_event(self):

        incident = {
            "incident_type": "unknown",
            "failed_attempts": 1,
            "successful_login": False
        }

        result = self.engine.calculate_score(incident)

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["severity"], "low")


if __name__ == "__main__":
    unittest.main()