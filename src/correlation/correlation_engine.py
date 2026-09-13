from collections import defaultdict


class CorrelationEngine:

    def __init__(self, correlation_window_seconds=300):

        self.correlation_window_seconds = (
            correlation_window_seconds
        )

    def _get(self, obj, field, default=None):

        if isinstance(obj, dict):
            return obj.get(field, default)

        return getattr(obj, field, default)

    def _detect_incident_type(self, alerts):

        types = set()

        for alert in alerts:

            incident_type = self._get(
                alert,
                "incident_type"
            )

            if not incident_type:
                incident_type = self._get(
                    alert,
                    "alert_type"
                )

            if not incident_type:
                incident_type = self._get(
                    alert,
                    "event_type"
                )

            if incident_type:
                types.add(incident_type)

        # Strongest/most specific classification first
        priority = [
            "brute_force_with_success",
            "password_spray",
            "brute_force",
            "port_scan",
            "connection_burst",
            "suspicious_activity"
        ]

        for incident_type in priority:

            if incident_type in types:
                return incident_type

        # Port scan can also be identified from network telemetry
        # when the detector type was not preserved.
        port_count = 0

        for alert in alerts:

            destination_port = self._get(
                alert,
                "destination_port"
            )

            if destination_port:
                port_count += 1

        if port_count >= 5:
            return "port_scan"

        if types:
            return next(iter(types))

        return "suspicious_activity"

    def correlate(self, alerts, events=None):

        incidents = []

        if not alerts:
            return incidents

        # ---------------------------------------------------------
        # Group alerts by source IP
        # ---------------------------------------------------------

        source_groups = defaultdict(list)

        alerts_without_ip = []

        for alert in alerts:

            source_ip = self._get(
                alert,
                "source_ip"
            )

            if source_ip:

                source_groups[source_ip].append(
                    alert
                )

            else:

                alerts_without_ip.append(
                    alert
                )

        # ---------------------------------------------------------
        # Build incidents
        # ---------------------------------------------------------

        for source_ip, grouped_alerts in source_groups.items():

            usernames = set()
            destination_ports = set()

            failed_attempts = 0
            successful_login = False

            evidence = []

            for alert in grouped_alerts:

                username = self._get(
                    alert,
                    "username"
                )

                if username:
                    usernames.add(username)

                destination_port = self._get(
                    alert,
                    "destination_port"
                )

                if destination_port:
                    destination_ports.add(
                        destination_port
                    )

                failed = self._get(
                    alert,
                    "failed_attempts",
                    0
                )

                if isinstance(failed, int):
                    failed_attempts += failed

                if self._get(
                    alert,
                    "successful_login",
                    False
                ):
                    successful_login = True

                raw_message = self._get(
                    alert,
                    "message"
                )

                if not raw_message:
                    raw_message = self._get(
                        alert,
                        "raw_log"
                    )

                if raw_message:
                    evidence.append(
                        raw_message
                    )

            # -----------------------------------------------------
            # Correct incident classification
            # -----------------------------------------------------

            incident_type = self._detect_incident_type(
                grouped_alerts
            )

            # -----------------------------------------------------
            # Cross-event correlation
            # -----------------------------------------------------

            if events:

                for event in events:

                    event_source_ip = self._get(
                        event,
                        "source_ip"
                    )

                    if event_source_ip != source_ip:
                        continue

                    username = self._get(
                        event,
                        "username"
                    )

                    if username:
                        usernames.add(
                            username
                        )

                    destination_port = self._get(
                        event,
                        "destination_port"
                    )

                    if destination_port:
                        destination_ports.add(
                            destination_port
                        )

            # -----------------------------------------------------
            # Special handling for port scans
            # -----------------------------------------------------

            if (
                len(destination_ports) >= 5
                and incident_type
                == "suspicious_activity"
            ):

                incident_type = "port_scan"

            # -----------------------------------------------------
            # Description
            # -----------------------------------------------------

            if incident_type == "port_scan":

                description = (
                    f"Network port scan detected from "
                    f"{source_ip}. "
                    f"{len(destination_ports)} unique "
                    f"destination ports were probed."
                )

            elif incident_type == "brute_force":

                description = (
                    f"Brute-force authentication activity "
                    f"detected from {source_ip}."
                )

            elif incident_type == "password_spray":

                description = (
                    f"Password-spray activity detected "
                    f"from {source_ip} targeting "
                    f"{len(usernames)} user account(s)."
                )

            else:

                description = (
                    f"Correlated {len(grouped_alerts)} "
                    f"security alert(s) from "
                    f"{source_ip}."
                )

            # -----------------------------------------------------
            # Incident object
            # -----------------------------------------------------

            incident = {

                "incident_type":
                    incident_type,

                "source_ip":
                    source_ip,

                "username":
                    (
                        next(iter(usernames))
                        if usernames
                        else None
                    ),

                "successful_login":
                    successful_login,

                "failed_attempts":
                    failed_attempts,

                "unique_users":
                    len(usernames),

                "unique_ports":
                    len(destination_ports),

                "alert_count":
                    len(grouped_alerts),

                "alerts":
                    grouped_alerts,

                "evidence":
                    evidence,

                "description":
                    description
            }

            incidents.append(
                incident
            )

        # ---------------------------------------------------------
        # Alerts without source IP
        # ---------------------------------------------------------

        for alert in alerts_without_ip:

            incident_type = self._detect_incident_type(
                [alert]
            )

            username = self._get(
                alert,
                "username"
            )

            raw_message = self._get(
                alert,
                "message"
            )

            if not raw_message:
                raw_message = self._get(
                    alert,
                    "raw_log"
                )

            incidents.append({

                "incident_type":
                    incident_type,

                "source_ip":
                    None,

                "username":
                    username,

                "successful_login":
                    self._get(
                        alert,
                        "successful_login",
                        False
                    ),

                "failed_attempts":
                    self._get(
                        alert,
                        "failed_attempts",
                        0
                    ),

                "unique_users":
                    1 if username else 0,

                "unique_ports":
                    0,

                "alert_count":
                    1,

                "alerts":
                    [alert],

                "evidence":
                    [raw_message]
                    if raw_message
                    else [],

                "description":
                    "Security alert without a source IP."
            })

        return incidents