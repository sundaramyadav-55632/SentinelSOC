from datetime import datetime


class PortScanDetector:

    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def detect(self, events):

        network_events = [
            event
            for event in events
            if (
                event.event_type == "connection_attempt"
                and event.source_ip
                and event.destination_port
            )
        ]

        grouped_events = {}

        # Group network connections by source IP
        for event in network_events:

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

                unique_ports = {
                    event.destination_port
                    for event in window
                }

                if len(unique_ports) >= self.threshold:

                    alerts.append({
                        "alert_type": "port_scan",
                        "source_ip": source_ip,
                        "targeted_ports": sorted(unique_ports),
                        "unique_ports": len(unique_ports),
                        "connection_attempts": len(window),
                        "window_seconds": self.window_seconds,
                        "severity": "medium"
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

    from src.parser.network_parser import NetworkParser

    parser = NetworkParser()

    events = []

    with open(
        "data/samples/port_scan.log",
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            event = parser.parse(line.strip())

            if event:
                events.append(event)

    detector = PortScanDetector(
        threshold=5,
        window_seconds=60
    )

    alerts = detector.detect(events)

    for alert in alerts:

        print("🚨 PORT SCAN DETECTED")

        print(
            f"Source IP: {alert['source_ip']}"
        )

        print(
            f"Targeted Ports: "
            f"{', '.join(map(str, alert['targeted_ports']))}"
        )

        print(
            f"Unique Ports: "
            f"{alert['unique_ports']}"
        )

        print(
            f"Connection Attempts: "
            f"{alert['connection_attempts']}"
        )

        print(
            f"Time Window: "
            f"{alert['window_seconds']} seconds"
        )

        print(
            f"Severity: "
            f"{alert['severity']}"
        )