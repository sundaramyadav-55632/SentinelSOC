class RiskEngine:

    def calculate_score(self, incident):

        score = 0
        reasons = []

        # Brute-force detection
        if incident.get("incident_type") in [
            "brute_force",
            "brute_force_with_success"
        ]:
            score += 40
            reasons.append("Brute-force activity detected")

        # Successful login after attack
        if incident.get("successful_login"):
            score += 30
            reasons.append(
                "Successful login occurred after failed attempts"
            )

        # Source IP correlation
        if incident.get("source_ip"):
            score += 10
            reasons.append(
                "Source IP correlated across security events"
            )

        # Username correlation
        if incident.get("username"):
            score += 10
            reasons.append(
                "Username correlated across security events"
            )

        # Multiple failed attempts
        if incident.get("failed_attempts", 0) >= 5:
            score += 10
            reasons.append(
                "Multiple authentication failures detected"
            )

        severity = self._get_severity(score)

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }

    def _get_severity(self, score):

        if score >= 80:
            return "critical"

        if score >= 60:
            return "high"

        if score >= 30:
            return "medium"

        return "low"


if __name__ == "__main__":

    engine = RiskEngine()

    incident = {
        "incident_type": "brute_force_with_success",
        "source_ip": "192.168.1.50",
        "username": "admin",
        "failed_attempts": 5,
        "successful_login": True
    }

    result = engine.calculate_score(incident)

    print("Risk Assessment")
    print("----------------")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Severity: {result['severity'].upper()}")

    print("\nReasons:")

    for reason in result["reasons"]:
        print(f"- {reason}")