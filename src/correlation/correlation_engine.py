class CorrelationEngine:

    def __init__(self):
        pass

    # =========================================================
    # NORMALIZE OBJECT / DICT
    # =========================================================

    @staticmethod
    def _to_dict(value):

        if isinstance(value, dict):

            return value

        if hasattr(
            value,
            "to_dict"
        ):

            return value.to_dict()

        return vars(value)

    # =========================================================
    # MAIN CORRELATION
    # =========================================================

    def correlate(
        self,
        alerts,
        events
    ):

        incidents = []

        if not alerts:

            return incidents

        normalized_alerts = [
            self._to_dict(alert)
            for alert in alerts
        ]

        normalized_events = [
            self._to_dict(event)
            for event in events
        ]

        # -----------------------------------------------------
        # Group alerts by source IP
        # -----------------------------------------------------

        grouped = {}

        for alert in normalized_alerts:

            source_ip = alert.get(
                "source_ip"
            )

            if not source_ip:

                source_ip = "unknown"

            grouped.setdefault(
                source_ip,
                []
            ).append(alert)

        # -----------------------------------------------------
        # Build incidents
        # -----------------------------------------------------

        for source_ip, source_alerts in grouped.items():

            incident = (
                self._build_correlated_incident(
                    source_ip,
                    source_alerts,
                    normalized_events
                )
            )

            if incident:

                incidents.append(
                    incident
                )

        return incidents

    # =========================================================
    # BUILD CORRELATED INCIDENT
    # =========================================================

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

        # =====================================================
        # ALERT ANALYSIS
        # =====================================================

        for alert in alerts:

            incident_type = alert.get(
                "incident_type",
                alert.get(
                    "alert_type",
                    ""
                )
            )

            if incident_type:

                attack_types.add(
                    incident_type
                )

            failed_attempts += int(
                alert.get(
                    "failed_attempts",
                    0
                ) or 0
            )

            username = alert.get(
                "username"
            )

            if username:

                unique_users.add(
                    username
                )

            if alert.get(
                "successful_login",
                False
            ):

                successful_login = True

            # Some detectors provide a count
            # rather than individual ports.

            port_count = alert.get(
                "unique_ports",
                0
            )

            try:

                port_count = int(
                    port_count
                )

            except (
                ValueError,
                TypeError
            ):

                port_count = 0

            if port_count > 0:

                for port_number in range(
                    port_count
                ):

                    unique_ports.add(
                        f"alert-port-{port_number}"
                    )

        # =====================================================
        # EVENT ANALYSIS
        # =====================================================

        for event in events:

            if event.get(
                "source_ip"
            ) != source_ip:

                continue

            event_type = event.get(
                "event_type",
                ""
            )

            username = event.get(
                "username"
            )

            if username:

                unique_users.add(
                    username
                )

            destination_port = event.get(
                "destination_port"
            )

            if destination_port:

                unique_ports.add(
                    destination_port
                )

            if event_type in {
                "login_success",
                "authentication_success",
                "successful_login"
            }:

                successful_login = True

        # =====================================================
        # ATTACK TYPE
        # =====================================================

        if (
            "port_scan" in attack_types
            and "brute_force" in attack_types
        ):

            incident_type = "attack_chain"

        elif "port_scan" in attack_types:

            incident_type = "port_scan"

        elif "password_spray" in attack_types:

            incident_type = "password_spray"

        elif "brute_force" in attack_types:

            incident_type = "brute_force"

        else:

            incident_type = next(
                iter(attack_types),
                "suspicious_activity"
            )

        # =====================================================
        # REASONS
        # =====================================================

        if "port_scan" in attack_types:

            reasons.append(
                "Network reconnaissance detected"
            )

        if "brute_force" in attack_types:

            reasons.append(
                "Repeated authentication failures detected"
            )

        if "password_spray" in attack_types:

            reasons.append(
                "Multiple user accounts targeted"
            )

        if (
            "port_scan" in attack_types
            and "brute_force" in attack_types
        ):

            reasons.append(
                "Network reconnaissance followed by authentication attacks"
            )

        if successful_login:

            reasons.append(
                "Successful login occurred after suspicious activity"
            )

        if source_ip != "unknown":

            reasons.append(
                "Source IP correlated across multiple security events"
            )

        # =====================================================
        # EVIDENCE
        # =====================================================

        for attack_type in sorted(
            attack_types
        ):

            evidence.append(
                f"Detection alert: {attack_type}"
            )

        if failed_attempts:

            evidence.append(
                f"{failed_attempts} failed authentication attempts observed"
            )

        if unique_ports:

            evidence.append(
                f"{len(unique_ports)} unique destination ports observed"
            )

        if unique_users:

            evidence.append(
                f"{len(unique_users)} unique user accounts observed"
            )

        if successful_login:

            evidence.append(
                "Successful authentication event observed"
            )

        # =====================================================
        # CONFIDENCE
        # =====================================================

        confidence = 60

        if len(attack_types) >= 2:

            confidence += 15

        if (
            "port_scan" in attack_types
            and "brute_force" in attack_types
        ):

            confidence += 15

        if successful_login:

            confidence += 10

        confidence = min(
            confidence,
            100
        )

        # =====================================================
        # DESCRIPTION
        # =====================================================

        if incident_type == "attack_chain":

            description = (
                f"Multi-stage attack activity detected "
                f"from {source_ip}. Network reconnaissance "
                f"was correlated with authentication attacks."
            )

        elif incident_type == "brute_force":

            description = (
                f"Brute-force authentication activity "
                f"detected from {source_ip}."
            )

        elif incident_type == "password_spray":

            description = (
                f"Password-spray activity detected "
                f"from {source_ip}."
            )

        elif incident_type == "port_scan":

            description = (
                f"Network port scanning activity "
                f"detected from {source_ip}."
            )

        else:

            description = (
                f"Suspicious security activity "
                f"detected from {source_ip}."
            )

        # =====================================================
        # RETURN INCIDENT
        # =====================================================

        return {

            "incident_type":
                incident_type,

            "source_ip":
                None
                if source_ip == "unknown"
                else source_ip,

            "username":
                next(
                    iter(unique_users)
                )
                if len(unique_users) == 1
                else None,

            "failed_attempts":
                failed_attempts,

            "unique_users":
                len(unique_users),

            "unique_ports":
                len(unique_ports),

            "successful_login":
                successful_login,

            "attack_types":
                sorted(
                    attack_types
                ),

            "risk_score":
                0,

            "severity":
                "low",

            "confidence":
                confidence,

            "status":
                "open",

            "reasons":
                reasons,

            "evidence":
                evidence,

            "description":
                description,

            "correlated_alert_count":
                len(alerts)

        }