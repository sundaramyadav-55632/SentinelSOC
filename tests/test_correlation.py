import unittest

from src.correlation.correlation_engine import CorrelationEngine
from src.utils.event_schema import SecurityEvent


class TestCorrelationEngine(unittest.TestCase):

    def create_event(
        self,
        timestamp,
        event_type,
        username="admin",
        source_ip="192.168.1.50"
    ):
        return SecurityEvent(
            timestamp=timestamp,
            source="linux",
            event_type=event_type,
            severity="medium",
            username=username,
            source_ip=source_ip,
            destination_port=22,
            message="Test security event"
        )

    def test_brute_force_followed_by_success(self):

        events = [
            self.create_event(
                "2026-09-12T17:30:01",
                "authentication_failure"
            ),
            self.create_event(
                "2026-09-12T17:30:04",
                "authentication_failure"
            ),
            self.create_event(
                "2026-09-12T17:30:07",
                "authentication_failure"
            ),
            self.create_event(
                "2026-09-12T17:30:10",
                "authentication_failure"
            ),
            self.create_event(
                "2026-09-12T17:30:13",
                "authentication_failure"
            ),
            self.create_event(
                "2026-09-12T17:30:20",
                "authentication_success"
            ),
        ]

        alerts = [
            {
                "alert_type": "brute_force",
                "source_ip": "192.168.1.50",
                "username": "admin",
                "failed_attempts": 5,
                "window_seconds": 60,
                "severity": "high"
            }
        ]

        engine = CorrelationEngine(
            correlation_window_seconds=60
        )

        incidents = engine.correlate(
            events,
            alerts
        )

        self.assertEqual(len(incidents), 1)

        incident = incidents[0]

        self.assertEqual(
            incident["incident_type"],
            "brute_force_with_success"
        )

        self.assertEqual(
            incident["source_ip"],
            "192.168.1.50"
        )

        self.assertEqual(
            incident["username"],
            "admin"
        )

        self.assertEqual(
            incident["failed_attempts"],
            5
        )

        self.assertTrue(
            incident["successful_login"]
        )

        self.assertEqual(
            incident["severity"],
            "critical"
        )


if __name__ == "__main__":
    unittest.main()