from src.intelligence.mitre_mapper import MitreMapper


class IncidentIntelligence:

    def enrich(self, incident):

        incident_type = incident.get(
            "incident_type",
            "suspicious_activity"
        )

        mitre = MitreMapper.map_incident(
            incident_type
        )

        evidence = list(
            incident.get(
                "evidence",
                []
            )
        )

        confidence = 50

        # ---------------------------------------------------------
        # Port scan confidence
        # ---------------------------------------------------------

        unique_ports = incident.get(
            "unique_ports",
            0
        )

        if incident_type == "port_scan":

            if unique_ports >= 10:
                confidence = 98

            elif unique_ports >= 8:
                confidence = 95

            elif unique_ports >= 5:
                confidence = 90

            evidence.append(
                f"{unique_ports} unique destination "
                f"ports were observed"
            )

            source_ip = incident.get(
                "source_ip"
            )

            if source_ip:

                evidence.append(
                    f"Source IP {source_ip} generated "
                    f"multiple connection attempts"
                )

        # ---------------------------------------------------------
        # Brute force confidence
        # ---------------------------------------------------------

        failed_attempts = incident.get(
            "failed_attempts",
            0
        )

        if incident_type in (
            "brute_force",
            "brute_force_with_success"
        ):

            confidence = 85

            if failed_attempts >= 10:
                confidence = 95

            elif failed_attempts >= 5:
                confidence = 90

            evidence.append(
                f"{failed_attempts} failed "
                f"authentication attempts observed"
            )

        # ---------------------------------------------------------
        # Password spray confidence
        # ---------------------------------------------------------

        unique_users = incident.get(
            "unique_users",
            0
        )

        if incident_type == "password_spray":

            confidence = 88

            if unique_users >= 10:
                confidence = 97

            elif unique_users >= 5:
                confidence = 93

            evidence.append(
                f"{unique_users} unique user accounts "
                f"were targeted"
            )

        # ---------------------------------------------------------
        # Source correlation evidence
        # ---------------------------------------------------------

        if incident.get("source_ip"):

            evidence.append(
                "Source IP correlated across "
                "security telemetry"
            )

        # Remove duplicate evidence
        cleaned_evidence = []

        for item in evidence:

            if item and item not in cleaned_evidence:

                cleaned_evidence.append(item)

        incident["mitre"] = mitre

        incident["confidence"] = min(
            confidence,
            100
        )

        incident["evidence"] = (
            cleaned_evidence
        )

        return incident