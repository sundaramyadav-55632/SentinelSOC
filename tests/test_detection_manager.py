import unittest

from src.detectors.detection_manager import DetectionManager
from src.utils.event_schema import SecurityEvent


class TestDetectionManager(unittest.TestCase):

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

    def test_password_spray_detection(self):

        events = [
            self.create_event(
                "2026-09-12T18:00:01",
                "admin"
            ),
            self.create_event(
                "2026-09-12T18:00:05",
                "alice"
            ),
            self.create_event(
                "2026-09-12T18:00:09",
                "bob"
            ),
            self.create_event(
                "2026-09-12T18:00:13",
                "john"
            ),
            self.create_event(
                "2026-09-12T18:00:17",
                "david"
            )
        ]

        manager = DetectionManager()

        alerts = manager.detect(events)

        spray_alerts = [
            alert
            for alert in alerts
            if alert["alert_type"] == "password_spray"
        ]

        self.assertEqual(len(spray_alerts), 1)

    def test_no_password_spray_for_same_user(self):

        events = [
            self.create_event(
                "2026-09-12T18:00:01",
                "admin"
            ),
            self.create_event(
                "2026-09-12T18:00:05",
                "admin"
            ),
            self.create_event(
                "2026-09-12T18:00:09",
                "admin"
            ),
            self.create_event(
                "2026-09-12T18:00:13",
                "admin"
            ),
            self.create_event(
                "2026-09-12T18:00:17",
                "admin"
            )
        ]

        manager = DetectionManager()

        alerts = manager.detect(events)

        spray_alerts = [
            alert
            for alert in alerts
            if alert["alert_type"] == "password_spray"
        ]

        self.assertEqual(len(spray_alerts), 0)


if __name__ == "__main__":
    unittest.main()