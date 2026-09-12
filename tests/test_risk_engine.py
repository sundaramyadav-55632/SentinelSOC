import unittest

from src.risk.risk_engine import RiskEngine


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RiskEngine()

    def test_brute_force_with_success(self):

        incident = {
            "incident_type": "brute_force_with_success",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "failed_attempts": 5,
            "successful_login": True
        }

        result = self.engine.calculate_score(
            incident
        )

        self.assertEqual(
            result["risk_score"],
            100
        )

        self.assertEqual(
            result["severity"],
            "critical"
        )

    def test_brute_force_without_success(self):

        incident = {
            "incident_type": "brute_force",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "failed_attempts": 5,
            "successful_login": False
        }

        result = self.engine.calculate_score(
            incident
        )

        self.assertEqual(
            result["risk_score"],
            70
        )

        self.assertEqual(
            result["severity"],
            "high"
        )

    def test_password_spray(self):

        incident = {
            "incident_type": "password_spray",
            "source_ip": "192.168.1.60",
            "unique_users": 5,
            "failed_attempts": 5
        }

        result = self.engine.calculate_score(
            incident
        )

        self.assertEqual(
            result["risk_score"],
            80
        )

        self.assertEqual(
            result["severity"],
            "critical"
        )

    def test_port_scan(self):

        incident = {
            "incident_type": "port_scan",
            "source_ip": "192.168.1.70",
            "unique_ports": 8,
            "connection_attempts": 8
        }

        result = self.engine.calculate_score(
            incident
        )

        self.assertEqual(
            result["risk_score"],
            50
        )

        self.assertEqual(
            result["severity"],
            "medium"
        )

    def test_low_risk_event(self):

        incident = {
            "incident_type": "unknown"
        }

        result = self.engine.calculate_score(
            incident
        )

        self.assertEqual(
            result["risk_score"],
            0
        )

        self.assertEqual(
            result["severity"],
            "low"
        )


if __name__ == "__main__":
    unittest.main()