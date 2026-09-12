from datetime import datetime


class CorrelationEngine:

    def __init__(self, correlation_window_seconds=60):
        self.correlation_window_seconds = correlation_window_seconds

    def correlate(self, events, alerts):

        incidents = []

        for alert in alerts:

            source_ip = alert["source_ip"]
            username = alert["username"]

            successful_logins = [
                event
                for event in events
                if (
                    event.event_type == "authentication_success"
                    and event.source_ip == source_ip
                    and event.username == username
                )
            ]

            if not successful_logins:
                continue

            for login in successful_logins:

                related_failures = [
                    event
                    for event in events
                    if (
                        event.event_type == "authentication_failure"
                        and event.source_ip == source_ip
                        and event.username == username
                        and self._within_window(
                            event.timestamp,
                            login.timestamp
                        )
                    )
                ]

                if related_failures:

                    incidents.append({
                        "incident_type": "brute_force_with_success",
                        "source_ip": source_ip,
                        "username": username,
                        "failed_attempts": len(related_failures),
                        "successful_login": True,
                        "severity": "critical"
                    })

        return incidents

    def _within_window(self, event_time, success_time):

        event_timestamp = datetime.fromisoformat(event_time)
        success_timestamp = datetime.fromisoformat(success_time)

        difference = (
            success_timestamp - event_timestamp
        ).total_seconds()

        return (
            0 <= difference <= self.correlation_window_seconds
        )