from src.detectors.brute_force import BruteForceDetector
from src.detectors.password_spray import PasswordSprayDetector
from src.detectors.port_scan import PortScanDetector


class DetectionManager:

    def __init__(self):

        self.detectors = [
            BruteForceDetector(
                threshold=5,
                window_seconds=60
            ),
            PasswordSprayDetector(
                threshold=5,
                window_seconds=60
            ),
            PortScanDetector(
                threshold=5,
                window_seconds=60
            )
        ]

    def detect(self, events):

        alerts = []

        for detector in self.detectors:

            detector_alerts = detector.detect(events)

            alerts.extend(detector_alerts)

        return alerts


if __name__ == "__main__":

    from src.collector.log_collector import LogCollector
    from src.parser.linux_auth_parser import LinuxAuthParser

    collector = LogCollector(
        "data/samples/auth.log"
    )

    parser = LinuxAuthParser()

    raw_logs = collector.collect()

    events = []

    for log in raw_logs:

        event = parser.parse(log)

        if event:
            events.append(event)

    manager = DetectionManager()

    alerts = manager.detect(events)

    print(f"Detection alerts: {len(alerts)}")

    for alert in alerts:

        print(alert)