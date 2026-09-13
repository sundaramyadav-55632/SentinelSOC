from datetime import datetime


class CorrelationEngine:

    def __init__(self, correlation_window_seconds=60):
        self.correlation_window_seconds = correlation_window_seconds

    @staticmethod
    def _to_dict(value):

        if isinstance(value, dict):
            return value

        if hasattr(value, "to_dict"):
            return value.to_dict()

        return vars(value)

    @staticmethod
    def _parse_timestamp(value):

        if not value:
            return None

        if isinstance(value, datetime):
            return value

        try:
            return datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )
        except Exception:
            return None

    def _within_window(self, event_a, event_b):

        time_a = self._parse_timestamp(
            event_a.get("timestamp")
        )

        time_b = self._parse_timestamp(
            event_b.get("timestamp")
        )

        if not time_a or not time_b:
            return True

        try:
            difference = abs(
                (time_b - time_a).total_seconds()
            )

            return difference <= self.correlation_window_seconds

        except Exception:
            return True

    @staticmethod
    def _looks_like_alert(item):

        return any(
            key in item
            for key in (
                "alert_type",
                "incident_type",
                "failed_attempts",
                "window_seconds"
            )
        )

    @staticmethod
    def _looks_like_event(item):

        return any(
            key in item
            for key in (
                "event_type",
                "destination_port",
                "protocol",
                "raw_log"
            )
        )

    def correlate(self, first, second):

        if not first and not second:
            return []

        first_items = [
            self._to_dict(item)
            for item in first
        ]

        second_items = [
            self._to_dict(item)
            for item in second
        ]

        # Support both:
        # correlate(alerts, events)
        # correlate(events, alerts)

        first_is_event = any(
            self._looks_like_event(item)
            for item in first_items
        )

        second_is_alert = any(
            self._looks_like_alert(item)
            for item in second_items
        )

        if first_is_event and second_is_alert:

            events = first_items
            alerts = second_items

        else:

            alerts = first_items
            events = second_items

        if not alerts:
            return []

        grouped = {}

        for alert in alerts:

            source_ip = (
                alert.get("source_ip")
                or "unknown"
            )

            grouped.setdefault(
                source_ip,
                []
            ).append(alert)

        incidents = []

        for source_ip, source_alerts in grouped.items():

            incident = self._build_correlated_incident(
                source_ip,
                source_alerts,
                events
            )

            if incident:
                incidents.append(incident)

        return incidents

    def _build_correlated_incident(
        self,
        source_ip,
        alerts,
        events
    ):

        attack_types = set()

        failed_attempts = 0

        unique_users = set()

        unique_ports = set()

        successful_login = False

        reasons = []

        evidence = []

        # ==========================================
        # PROCESS ALERTS
        # ==========================================

        for alert in alerts:

            incident_type = alert.get(
                "incident_type",
                alert.get(
                    "alert_type",
                    ""
                )
            )

            normalized_type = str(
                incident_type
            ).lower().strip()

            if normalized_type:
                attack_types.add(
                    normalized_type
                )

            failed_attempts += int(
                alert.get(
                    "failed_attempts",
                    0
                ) or 0
            )

            username = alert.get("username")

            if username:
                unique_users.add(username)

            if alert.get(
                "successful_login",
                False
            ):
                successful_login = True

            evidence.append(alert)

        # ==========================================
        # PROCESS EVENTS
        # ==========================================

        for event in events:

            event_source_ip = event.get(
                "source_ip"
            )

            if (
                event_source_ip
                and event_source_ip != source_ip
            ):
                continue

            username = event.get("username")

            if username:
                unique_users.add(username)

            destination_port = event.get(
                "destination_port"
            )

            if destination_port:
                unique_ports.add(
                    destination_port
                )

            event_type = str(
                event.get(
                    "event_type",
                    ""
                )
            ).lower().strip()

            if event_type in (
                "authentication_success",
                "authentication success",
                "login_success",
                "login success",
                "successful_login",
                "successful login"
            ):

                successful_login = True

                evidence.append(event)

        # ==========================================
        # NORMALIZE ATTACK TYPES
        # ==========================================

        has_brute_force = any(
            attack_type in (
                "brute_force",
                "brute-force",
                "brute force"
            )
            for attack_type in attack_types
        )

        has_password_spray = any(
            attack_type in (
                "password_spray",
                "password-spray",
                "password spray"
            )
            for attack_type in attack_types
        )

        has_port_scan = any(
            attack_type in (
                "port_scan",
                "port-scan",
                "port scan"
            )
            for attack_type in attack_types
        )

        # ==========================================
        # INCIDENT TYPE
        # ==========================================

        if has_brute_force and has_port_scan:

            incident_type = "attack_chain"

        elif has_brute_force and successful_login:

            incident_type = "brute_force_with_success"

        elif has_password_spray:

            incident_type = "password_spray"

        elif has_port_scan:

            incident_type = "port_scan"

        elif has_brute_force:

            incident_type = "brute_force"

        else:

            incident_type = next(
                iter(attack_types),
                "unknown"
            )

        # ==========================================
        # SEVERITY
        # ==========================================

        if (
            incident_type == "attack_chain"
            or (
                incident_type == "brute_force_with_success"
                and successful_login
            )
        ):

            severity = "critical"

        elif incident_type == "password_spray":

            severity = "high"

        elif incident_type == "brute_force":

            severity = "high"

        elif incident_type == "port_scan":

            severity = "medium"

        else:

            severity = "low"

        # ==========================================
        # REASONS
        # ==========================================

        if has_brute_force:

            reasons.append(
                "Brute-force activity detected"
            )

        if has_password_spray:

            reasons.append(
                "Password-spray activity detected"
            )

        if has_port_scan:

            reasons.append(
                "Port scanning detected"
            )

        if successful_login:

            reasons.append(
                "Successful login correlated with "
                "previous authentication failures"
            )

        if len(attack_types) > 1:

            reasons.append(
                "Multiple attack types correlated "
                "from the same source"
            )

        # ==========================================
        # CONFIDENCE
        # ==========================================

        confidence = 60

        if len(attack_types) > 1:
            confidence += 15

        if has_brute_force and has_port_scan:
            confidence += 15

        if successful_login:
            confidence += 10

        confidence = min(
            confidence,
            100
        )

        # ==========================================
        # DESCRIPTION
        # ==========================================

        if incident_type == "attack_chain":

            description = (
                "Multi-stage attack detected involving "
                "network reconnaissance and "
                "authentication attacks."
            )

        elif incident_type == "brute_force_with_success":

            description = (
                "Brute-force authentication activity "
                "was followed by a successful login."
            )

        elif incident_type == "password_spray":

            description = (
                "Multiple user accounts were targeted "
                "with authentication attempts."
            )

        elif incident_type == "port_scan":

            description = (
                "Multiple destination ports were "
                "probed from the same source."
            )

        elif incident_type == "brute_force":

            description = (
                "Repeated authentication failures "
                "were detected from the same source."
            )

        else:

            description = (
                "Suspicious security activity "
                "was detected."
            )

        # ==========================================
        # USERNAME
        # ==========================================

        username = (
            next(iter(unique_users))
            if unique_users
            else None
        )

        # ==========================================
        # FINAL INCIDENT
        # ==========================================

        return {
            "incident_type": incident_type,
            "source_ip": source_ip,
            "username": username,
            "failed_attempts": failed_attempts,
            "unique_users": len(unique_users),
            "unique_ports": len(unique_ports),
            "successful_login": successful_login,
            "attack_types": sorted(attack_types),
            "risk_score": 0,
            "severity": severity,
            "confidence": confidence,
            "status": "open",
            "reasons": reasons,
            "evidence": evidence,
            "description": description,
            "correlated_alert_count": len(alerts)
        }