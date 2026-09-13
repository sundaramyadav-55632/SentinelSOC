from collections import defaultdict


class CorrelationEngine:

    def __init__(self, correlation_window_seconds=300):

        self.correlation_window_seconds = (
            correlation_window_seconds
        )

    def _get(self, obj, field, default=None):

        if isinstance(obj, dict):

            return obj.get(
                field,
                default
            )

        return getattr(
            obj,
            field,
            default
        )

    def correlate(self, alerts, events=None):

        incidents = []

        if not alerts:
            return incidents

        # ---------------------------------------------------------
        # Group alerts by source IP
        # ---------------------------------------------------------

        source_groups = defaultdict(list)

        for alert in alerts:

            source_ip = self._get(
                alert,
                "source_ip"
            )

            if source_ip:

                source_groups[
                    source_ip
                ].append(alert)

        # ---------------------------------------------------------
        # Correlate alerts from the same source
        # ---------------------------------------------------------

        for source_ip, grouped_alerts in source_groups.items():

            incident_types = set()

            usernames = set()

            unique_ports = set()

            failed_attempts = 0

            successful_login = False

            for alert in grouped_alerts:

                incident_type = self._get(
                    alert,
                    "incident_type",
                    self._get(
                        alert,
                        "alert_type",
                        ""
                    )
                )

                if incident_type:

                    incident_types.add(
                        incident_type
                    )

                # Username may not exist on network events
                username = self._get(
                    alert,
                    "username"
                )

                if username:

                    usernames.add(
                        username
                    )

                # Failed authentication attempts
                failed_attempts += self._get(
                    alert,
                    "failed_attempts",
                    0
                )

                # Network destination port
                destination_port = self._get(
                    alert,
                    "destination_port"
                )

                if destination_port:

                    unique_ports.add(
                        destination_port
                    )

                # Successful login correlation
                if self._get(
                    alert,
                    "successful_login",
                    False
                ):

                    successful_login = True

            # -----------------------------------------------------
            # Determine strongest incident type
            # -----------------------------------------------------

            if (
                "brute_force_with_success"
                in incident_types
            ):

                incident_type = (
                    "brute_force_with_success"
                )

            elif "brute_force" in incident_types:

                incident_type = "brute_force"

            elif "password_spray" in incident_types:

                incident_type = "password_spray"

            elif "port_scan" in incident_types:

                incident_type = "port_scan"

            elif incident_types:

                incident_type = next(
                    iter(incident_types)
                )

            else:

                incident_type = (
                    "suspicious_activity"
                )

            # -----------------------------------------------------
            # Build incident
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
                    len(unique_ports),

                "alert_count":
                    len(grouped_alerts),

                "alerts":
                    grouped_alerts,

                "description":
                    (
                        f"Correlated "
                        f"{len(grouped_alerts)} "
                        f"security alert(s) "
                        f"from {source_ip}"
                    )
            }

            incidents.append(
                incident
            )

        # ---------------------------------------------------------
        # Handle alerts without source IP
        # ---------------------------------------------------------

        for alert in alerts:

            source_ip = self._get(
                alert,
                "source_ip"
            )

            if source_ip:

                continue

            incident_type = self._get(
                alert,
                "incident_type",
                self._get(
                    alert,
                    "alert_type",
                    "suspicious_activity"
                )
            )

            username = self._get(
                alert,
                "username"
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
                    (
                        1
                        if username
                        else 0
                    ),

                "unique_ports":
                    0,

                "alert_count":
                    1,

                "alerts":
                    [alert],

                "description":
                    (
                        "Security alert "
                        "without a source IP"
                    )
            })

        return incidents