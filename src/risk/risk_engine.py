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

        # -----------------------------
        # BASE ATTACK SCORE
        # -----------------------------

        if incident_type == "attack_chain":
            score += 50
            reasons.append(
                "Multi-stage attack chain detected"
            )

        elif incident_type == "brute_force":
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

        # -----------------------------
        # SUCCESSFUL LOGIN
        # -----------------------------

        if incident.get("successful_login", False):

            score += 30

            reasons.append(
                "Successful login occurred after failed attempts"
            )

        # -----------------------------
        # SOURCE CORRELATION
        # -----------------------------

        if incident.get("source_ip"):

            score += 10

            reasons.append(
                "Source IP correlated across security events"
            )

        # -----------------------------
        # USER CORRELATION
        # -----------------------------

        if incident.get("username"):

            score += 10

            reasons.append(
                "Username correlated across security events"
            )

        # -----------------------------
        # FAILED ATTEMPTS
        # -----------------------------

        failed_attempts = incident.get(
            "failed_attempts",
            0
        )

        if failed_attempts >= 5:

            score += 10

            reasons.append(
                "Multiple authentication failures detected"
            )

        # -----------------------------
        # MULTIPLE USERS
        # -----------------------------

        unique_users = incident.get(
            "unique_users",
            0
        )

        if unique_users >= 5:

            score += 15

            reasons.append(
                "Multiple user accounts targeted"
            )

        # -----------------------------
        # PORT RECON
        # -----------------------------

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

        # -----------------------------
        # CAP SCORE
        # -----------------------------

        score = min(score, 100)

        # -----------------------------
        # SEVERITY
        # -----------------------------

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