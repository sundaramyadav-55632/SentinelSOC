class ResponseEngine:

    def __init__(self):
        pass

    def generate_response(self, incident):

        incident_type = incident.get(
            "incident_type",
            incident.get("alert_type", "")
        )

        severity = incident.get(
            "severity",
            "low"
        ).lower()

        actions = []

        # --------------------------------------------------
        # Brute Force
        # --------------------------------------------------

        if incident_type in [
            "brute_force",
            "brute_force_with_success"
        ]:

            actions.append(
                "Investigate the affected user account"
            )

            actions.append(
                "Review authentication logs for the source IP"
            )

            if incident_type == "brute_force_with_success":

                actions.append(
                    "Treat the account as potentially compromised"
                )

                actions.append(
                    "Terminate suspicious active sessions"
                )

                actions.append(
                    "Force a password reset for the affected account"
                )

            else:

                actions.append(
                    "Consider temporarily blocking the source IP"
                )

        # --------------------------------------------------
        # Password Spray
        # --------------------------------------------------

        elif incident_type == "password_spray":

            actions.append(
                "Identify all targeted user accounts"
            )

            actions.append(
                "Search for successful logins from the source IP"
            )

            actions.append(
                "Review authentication activity across targeted accounts"
            )

            actions.append(
                "Consider temporarily blocking the source IP"
            )

            actions.append(
                "Verify MFA protection for targeted accounts"
            )

        # --------------------------------------------------
        # Port Scan
        # --------------------------------------------------

        elif incident_type == "port_scan":

            actions.append(
                "Identify the destination systems that were scanned"
            )

            actions.append(
                "Review firewall logs for additional activity"
            )

            actions.append(
                "Determine whether the source IP is authorized"
            )

            actions.append(
                "Monitor the source for follow-up exploitation attempts"
            )

        # --------------------------------------------------
        # Critical severity
        # --------------------------------------------------

        if severity == "critical":

            actions.insert(
                0,
                "Escalate incident to the security operations team"
            )

        elif severity == "high":

            actions.insert(
                0,
                "Prioritize incident for analyst investigation"
            )

        # --------------------------------------------------
        # Unknown incident
        # --------------------------------------------------

        if not actions:

            actions.append(
                "Perform manual security investigation"
            )

        return {
            "incident_type": incident_type,
            "severity": severity,
            "recommended_actions": actions
        }


if __name__ == "__main__":

    engine = ResponseEngine()

    test_incident = {
        "incident_type": "brute_force_with_success",
        "severity": "critical",
        "source_ip": "192.168.1.50",
        "username": "admin"
    }

    response = engine.generate_response(
        test_incident
    )

    print("Incident Response")
    print("-----------------")

    print(
        f"Incident Type: "
        f"{response['incident_type']}"
    )

    print(
        f"Severity: "
        f"{response['severity'].upper()}"
    )

    print("\nRecommended Actions:")

    for number, action in enumerate(
        response["recommended_actions"],
        start=1
    ):

        print(
            f"{number}. {action}"
        )