class RiskEngine:

    def __init__(self):
        pass

    def calculate_score(self, incident):

        score = 0
        reasons = []

        incident_type = incident.get(
            "incident_type",
            incident.get("alert_type", "")
        )

        # --------------------------------------------------
        # Base risk by attack type
        # --------------------------------------------------

        if incident_type == "brute_force":
            score += 40
            reasons.append(
                "Brute-force activity detected"
            )

        elif incident_type == "brute_force_with_success":
            score += 40
            reasons.append(
                "Brute-force activity detected"
            )

        elif incident_type == "password_spray":
            score += 45
            reasons.append(
                "Password-spray activity detected"
            )

        elif incident_type == "port_scan":
            score += 30
            reasons.append(
                "Port-scan activity detected"
            )

        # --------------------------------------------------
        # Successful authentication after attack
        # --------------------------------------------------

        if incident.get("successful_login", False):

            score += 30

            reasons.append(
                "Successful login occurred after failed attempts"
            )

        # --------------------------------------------------
        # Source IP correlation
        # --------------------------------------------------

        if incident.get("source_ip"):

            score += 10

            reasons.append(
                "Source IP correlated across security events"
            )

        # --------------------------------------------------
        # Username correlation
        # --------------------------------------------------

        if incident.get("username"):

            score += 10

            reasons.append(
                "Username correlated across security events"
            )

        # --------------------------------------------------
        # Authentication failure volume
        # --------------------------------------------------

        failed_attempts = incident.get(
            "failed_attempts",
            0
        )

        if failed_attempts >= 5:

            score += 10

            reasons.append(
                "Multiple authentication failures detected"
            )

        # --------------------------------------------------
        # Password spray targeted users
        # --------------------------------------------------

        unique_users = incident.get(
            "unique_users",
            0
        )

        if unique_users >= 5:

            score += 15

            reasons.append(
                "Multiple user accounts targeted"
            )

        # --------------------------------------------------
        # Port scan volume
        # --------------------------------------------------

        unique_ports = incident.get(
            "unique_ports",
            0
        )

        if unique_ports >= 5:

            score += 10

            reasons.append(
                "Multiple destination ports probed"
            )

        if unique_ports >= 10:

            score += 10

            reasons.append(
                "High-volume port reconnaissance detected"
            )

        # --------------------------------------------------
        # Cap score at 100
        # --------------------------------------------------

        score = min(score, 100)

        # --------------------------------------------------
        # Determine severity
        # --------------------------------------------------

        if score >= 80:

            severity = "critical"

        elif score >= 60:

            severity = "high"

        elif score >= 30:

            severity = "medium"

        else:

            severity = "low"

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }


if __name__ == "__main__":

    engine = RiskEngine()

    test_incident = {
        "incident_type": "port_scan",
        "source_ip": "192.168.1.70",
        "unique_ports": 8,
        "connection_attempts": 8
    }

    result = engine.calculate_score(
        test_incident
    )

    print("Risk Assessment")
    print("----------------")
    print(
        f"Risk Score: "
        f"{result['risk_score']}/100"
    )
    print(
        f"Severity: "
        f"{result['severity'].upper()}"
    )

    print("\nReasons:")

    for reason in result["reasons"]:

        print(f"- {reason}")