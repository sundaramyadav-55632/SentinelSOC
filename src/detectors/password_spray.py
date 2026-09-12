from datetime import datetime


class PasswordSprayDetector:

    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def detect(self, events):

        failed_events = [
            event
            for event in events
            if event.event_type == "authentication_failure"
        ]

        grouped_events = {}

        # Group authentication failures by source IP
        for event in failed_events:

            source_ip = event.source_ip

            if source_ip not in grouped_events:
                grouped_events[source_ip] = []

            grouped_events[source_ip].append(event)

        alerts = []

        for source_ip, group in grouped_events.items():

            group.sort(
                key=lambda event: event.timestamp
            )

            for i in range(len(group)):

                window = [
                    event
                    for event in group[i:]
                    if self._within_window(
                        group[i].timestamp,
                        event.timestamp
                    )
                ]

                unique_users = {
                    event.username
                    for event in window
                }

                if (
                    len(window) >= self.threshold
                    and len(unique_users) >= self.threshold
                ):

                    alerts.append({
                        "alert_type": "password_spray",
                        "source_ip": source_ip,
                        "targeted_users": sorted(unique_users),
                        "failed_attempts": len(window),
                        "unique_users": len(unique_users),
                        "window_seconds": self.window_seconds,
                        "severity": "high"
                    })

                    break

        return alerts

    def _within_window(self, start_time, end_time):

        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)

        difference = (
            end - start
        ).total_seconds()

        return difference <= self.window_seconds


if __name__ == "__main__":

    from src.collector.log_collector import LogCollector
    from src.parser.linux_auth_parser import LinuxAuthParser

    collector = LogCollector(
        "data/samples/password_spray.log"
    )

    parser = LinuxAuthParser()

    raw_logs = collector.collect()

    events = []

    for log in raw_logs:

        event = parser.parse(log)

        if event:
            events.append(event)

    detector = PasswordSprayDetector(
        threshold=5,
        window_seconds=60
    )

    alerts = detector.detect(events)

    for alert in alerts:

        print("🚨 PASSWORD SPRAY DETECTED")
        print(
            f"Source IP: {alert['source_ip']}"
        )
        print(
            f"Targeted Users: "
            f"{', '.join(alert['targeted_users'])}"
        )
        print(
            f"Failed Attempts: "
            f"{alert['failed_attempts']}"
        )
        print(
            f"Unique Users: "
            f"{alert['unique_users']}"
        )
        print(
            f"Time Window: "
            f"{alert['window_seconds']} seconds"
        )
        print(
            f"Severity: "
            f"{alert['severity']}"
        )