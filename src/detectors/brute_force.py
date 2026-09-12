from datetime import datetime


class BruteForceDetector:

    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def detect(self, events):

        failed_events = [
            event
            for event in events
            if event.event_type == "authentication_failure"
        ]

        alerts = []

        # Group failed attempts by source IP and username
        grouped_events = {}

        for event in failed_events:
            key = (event.source_ip, event.username)

            if key not in grouped_events:
                grouped_events[key] = []

            grouped_events[key].append(event)

        # Analyze each group
        for (source_ip, username), group in grouped_events.items():

            group.sort(key=lambda event: event.timestamp)

            for i in range(len(group)):

                window = [
                    event
                    for event in group[i:]
                    if self._within_window(
                        group[i].timestamp,
                        event.timestamp
                    )
                ]

                if len(window) >= self.threshold:

                    alerts.append({
                        "alert_type": "brute_force",
                        "source_ip": source_ip,
                        "username": username,
                        "failed_attempts": len(window),
                        "window_seconds": self.window_seconds,
                        "severity": "high"
                    })

                    break

        return alerts

    def _within_window(self, start_time, end_time):

        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)

        difference = (end - start).total_seconds()

        return difference <= self.window_seconds


if __name__ == "__main__":

    from src.collector.log_collector import LogCollector
    from src.parser.linux_auth_parser import LinuxAuthParser

    collector = LogCollector("data/samples/auth.log")
    parser = LinuxAuthParser()

    raw_logs = collector.collect()

    events = []

    for log in raw_logs:
        event = parser.parse(log)

        if event:
            events.append(event)

    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60
    )

    alerts = detector.detect(events)

    for alert in alerts:
        print("🚨 BRUTE FORCE DETECTED")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Username: {alert['username']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")
        print(f"Time Window: {alert['window_seconds']} seconds")
        print(f"Severity: {alert['severity']}")