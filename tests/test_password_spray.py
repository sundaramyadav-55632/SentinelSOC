import unittest

from src.detectors.password_spray import PasswordSprayDetector
from src.utils.event_schema import SecurityEvent


class TestPasswordSprayDetector(unittest.TestCase):

    def create_event(
        self,
        timestamp,
        username,
        source_ip="192.168.1.60"
    ):
        return SecurityEvent(
            timestamp=timestamp,
            source="linux",
            event_type="authentication_failure",
            severity="medium",
            username=username,
            source_ip=source_ip,
            destination_port=22,
            message="Test authentication failure"
        )

    def test_password_spray_detected(self):

        events = [
            self.create_event("2026-09-12T18:00:01", "admin"),
            self.create_event("2026-09-12T18:00:05", "alice"),
            self.create_event("2026-09-12T18:00:09", "bob"),
            self.create_event("2026-09-12T18:00:13", "john"),
            self.create_event("2026-09-12T18:00:17", "david"),
        ]

        detector = PasswordSprayDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 1)

        alert = alerts[0]

        self.assertEqual(
            alert["alert_type"],
            "password_spray"
        )

        self.assertEqual(
            alert["source_ip"],
            "192.168.1.60"
        )

        self.assertEqual(
            alert["unique_users"],
            5
        )

        self.assertEqual(
            alert["failed_attempts"],
            5
        )

    def test_no_alert_for_same_user(self):

        events = [
            self.create_event("2026-09-12T18:00:01", "admin"),
            self.create_event("2026-09-12T18:00:05", "admin"),
            self.create_event("2026-09-12T18:00:09", "admin"),
            self.create_event("2026-09-12T18:00:13", "admin"),
            self.create_event("2026-09-12T18:00:17", "admin"),
        ]

        detector = PasswordSprayDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 0)

    def test_no_alert_below_threshold(self):

        events = [
            self.create_event("2026-09-12T18:00:01", "admin"),
            self.create_event("2026-09-12T18:00:05", "alice"),
            self.create_event("2026-09-12T18:00:09", "bob"),
        ]

        detector = PasswordSprayDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()