import unittest

from src.response.response_engine import ResponseEngine


class TestResponseEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ResponseEngine()

    def test_brute_force_with_success_response(self):

        incident = {
            "incident_type": "brute_force_with_success",
            "severity": "critical",
            "source_ip": "192.168.1.50",
            "username": "admin"
        }

        response = self.engine.generate_response(
            incident
        )

        actions = response["recommended_actions"]

        self.assertEqual(
            response["severity"],
            "critical"
        )

        self.assertIn(
            "Escalate incident to the security operations team",
            actions
        )

        self.assertIn(
            "Treat the account as potentially compromised",
            actions
        )

        self.assertIn(
            "Force a password reset for the affected account",
            actions
        )

    def test_password_spray_response(self):

        incident = {
            "incident_type": "password_spray",
            "severity": "critical",
            "source_ip": "192.168.1.60",
            "unique_users": 5
        }

        response = self.engine.generate_response(
            incident
        )

        actions = response["recommended_actions"]

        self.assertEqual(
            response["severity"],
            "critical"
        )

        self.assertIn(
            "Identify all targeted user accounts",
            actions
        )

        self.assertIn(
            "Search for successful logins from the source IP",
            actions
        )

        self.assertIn(
            "Verify MFA protection for targeted accounts",
            actions
        )

    def test_port_scan_response(self):

        incident = {
            "incident_type": "port_scan",
            "severity": "medium",
            "source_ip": "192.168.1.70",
            "unique_ports": 8
        }

        response = self.engine.generate_response(
            incident
        )

        actions = response["recommended_actions"]

        self.assertEqual(
            response["severity"],
            "medium"
        )

        self.assertIn(
            "Identify the destination systems that were scanned",
            actions
        )

        self.assertIn(
            "Review firewall logs for additional activity",
            actions
        )

        self.assertIn(
            "Determine whether the source IP is authorized",
            actions
        )

    def test_unknown_incident_response(self):

        incident = {
            "incident_type": "unknown",
            "severity": "low"
        }

        response = self.engine.generate_response(
            incident
        )

        self.assertEqual(
            response["severity"],
            "low"
        )

        self.assertIn(
            "Perform manual security investigation",
            response["recommended_actions"]
        )


if __name__ == "__main__":
    unittest.main()