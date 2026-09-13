class IntelligenceEngine:

    def __init__(self):
        self.mitre_map = {
            "brute_force": {
                "id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access"
            },
            "password_spray": {
                "id": "T1110.003",
                "technique": "Password Spraying",
                "tactic": "Credential Access"
            },
            "port_scan": {
                "id": "T1046",
                "technique": "Network Service Scanning",
                "tactic": "Discovery"
            },
            "attack_chain": {
                "id": "T1046",
                "technique": "Network Service Scanning + Credential Access",
                "tactic": "Discovery / Credential Access"
            }
        }

    def enrich(self, incident):

        incident_type = incident.get(
            "incident_type",
            incident.get("alert_type", "")
        )

        mitre = self.mitre_map.get(
            incident_type,
            {
                "id": "N/A",
                "technique": "Unknown",
                "tactic": "Unknown"
            }
        )

        return {
            "mitre_technique_id": mitre["id"],
            "mitre_technique": mitre["technique"],
            "mitre_tactic": mitre["tactic"]
        }