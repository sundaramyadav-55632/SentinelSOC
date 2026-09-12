import unittest

from src.detectors.detection_manager import DetectionManager
from src.utils.event_schema import SecurityEvent


class TestDetectionManager(unittest.TestCase):

    def create_auth_event(
        self,
        timestamp,
        username,
        source_ip="192.168.1.50"
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

    def create_network_event(
        self,
        timestamp,
        destination_port,
        source_ip="192.168.1.70"
    ):
        return SecurityEvent(
            timestamp=timestamp,
            source="firewall",
            event_type="connection_attempt",
            severity="low",
            source_ip=source_ip,
            source_port=49100,
            destination_ip="192.168.1.10",
            destination_port=destination_port,
            protocol="TCP",
            action="ALLOW",
            message="Test network connection"
        )

    def test_password_spray_detection(self):

        events = [
            self.create_auth_event(
                "2026-09-12T18:00:01",
                "admin",
                "192.168.1.60"
            ),
            self.create_auth_event(
                "2026-09-12T18:00:05",
                "alice",
                "192.168.1.60"
            ),
            self.create_auth_event(
                "2026-09-12T18:00:09",
                "bob",
                "192.168.1.60"
            ),
            self.create_auth_event(
                "2026-09-12T18:00:13",
                "john",
                "192.168.1.60"
            ),
            self.create_auth_event(
                "2026-09-12T18:00:17",
                "david",
                "192.168.1.60"
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
            self.create_auth_event(
                "2026-09-12T18:00:01",
                "admin"
            ),
            self.create_auth_event(
                "2026-09-12T18:00:05",
                "admin"
            ),
            self.create_auth_event(
                "2026-09-12T18:00:09",
                "admin"
            ),
            self.create_auth_event(
                "2026-09-12T18:00:13",
                "admin"
            ),
            self.create_auth_event(
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

    def test_port_scan_detection(self):

        events = [
            self.create_network_event(
                "2026-09-12T18:30:01",
                21
            ),
            self.create_network_event(
                "2026-09-12T18:30:02",
                22
            ),
            self.create_network_event(
                "2026-09-12T18:30:03",
                23
            ),
            self.create_network_event(
                "2026-09-12T18:30:04",
                25
            ),
            self.create_network_event(
                "2026-09-12T18:30:05",
                53
            )
        ]

        manager = DetectionManager()

        alerts = manager.detect(events)

        port_scan_alerts = [
            alert
            for alert in alerts
            if alert["alert_type"] == "port_scan"
        ]

        self.assertEqual(len(port_scan_alerts), 1)

        alert = port_scan_alerts[0]

        self.assertEqual(
            alert["source_ip"],
            "192.168.1.70"
        )

        self.assertEqual(
            alert["unique_ports"],
            5
        )

    def test_no_port_scan_for_repeated_port(self):

        events = [
            self.create_network_event(
                "2026-09-12T18:30:01",
                22
            ),
            self.create_network_event(
                "2026-09-12T18:30:02",
                22
            ),
            self.create_network_event(
                "2026-09-12T18:30:03",
                22
            ),
            self.create_network_event(
                "2026-09-12T18:30:04",
                22
            ),
            self.create_network_event(
                "2026-09-12T18:30:05",
                22
            )
        ]

        manager = DetectionManager()

        alerts = manager.detect(events)

        port_scan_alerts = [
            alert
            for alert in alerts
            if alert["alert_type"] == "port_scan"
        ]

        self.assertEqual(len(port_scan_alerts), 0)


if __name__ == "__main__":
    unittest.main()