import unittest

from src.detectors.port_scan import PortScanDetector
from src.utils.event_schema import SecurityEvent


class TestPortScanDetector(unittest.TestCase):

    def create_event(
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

    def test_port_scan_detected(self):

        events = [
            self.create_event("2026-09-12T18:30:01", 21),
            self.create_event("2026-09-12T18:30:02", 22),
            self.create_event("2026-09-12T18:30:03", 23),
            self.create_event("2026-09-12T18:30:04", 25),
            self.create_event("2026-09-12T18:30:05", 53),
        ]

        detector = PortScanDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 1)

        alert = alerts[0]

        self.assertEqual(
            alert["alert_type"],
            "port_scan"
        )

        self.assertEqual(
            alert["source_ip"],
            "192.168.1.70"
        )

        self.assertEqual(
            alert["unique_ports"],
            5
        )

    def test_no_alert_for_repeated_same_port(self):

        events = [
            self.create_event("2026-09-12T18:30:01", 22),
            self.create_event("2026-09-12T18:30:02", 22),
            self.create_event("2026-09-12T18:30:03", 22),
            self.create_event("2026-09-12T18:30:04", 22),
            self.create_event("2026-09-12T18:30:05", 22),
        ]

        detector = PortScanDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 0)

    def test_no_alert_below_threshold(self):

        events = [
            self.create_event("2026-09-12T18:30:01", 21),
            self.create_event("2026-09-12T18:30:02", 22),
            self.create_event("2026-09-12T18:30:03", 23),
            self.create_event("2026-09-12T18:30:04", 25),
        ]

        detector = PortScanDetector(
            threshold=5,
            window_seconds=60
        )

        alerts = detector.detect(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()