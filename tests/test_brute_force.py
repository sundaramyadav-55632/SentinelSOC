import unittest

from src.detectors.brute_force import BruteForceDetector
from src.utils.event_schema import SecurityEvent


class TestBruteForceDetector(unittest.TestCase):

    def create_event(
        self,
        timestamp,
        event_type="authentication_failure",
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
            message="Test authentication event"
        )

    def test_brute_force_detected(self):

        events = [
            self.create_event("2026-09-12T17:30:01"),
            self.create_event("2026-09-12T17:30:04"),
            self.create_event("2026-09-12T17:30:07"),
            self.create_event("2026-09-12T17:30:10"),
            self.create_event("2026-09-12T17:30:13"),
        ]

        detector = BruteForceDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "brute_force")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.50")
        self.assertEqual(alerts[0]["username"], "admin")
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    def test_no_alert_below_threshold(self):

        events = [
            self.create_event("2026-09-12T17:30:01"),
            self.create_event("2026-09-12T17:30:04"),
            self.create_event("2026-09-12T17:30:07"),
        ]

        detector = BruteForceDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 0)

    def test_no_alert_outside_time_window(self):

        events = [
            self.create_event("2026-09-12T17:30:01"),
            self.create_event("2026-09-12T17:30:20"),
            self.create_event("2026-09-12T17:30:40"),
            self.create_event("2026-09-12T17:31:00"),
            self.create_event("2026-09-12T17:31:30"),
        ]

        detector = BruteForceDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()