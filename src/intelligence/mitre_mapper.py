class MitreMapper:

    TECHNIQUES = {
        "brute_force": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access"
        },

        "brute_force_with_success": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access"
        },

        "password_spray": {
            "technique_id": "T1110.003",
            "technique_name": "Password Spraying",
            "tactic": "Credential Access"
        },

        "port_scan": {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "tactic": "Discovery"
        },

        "connection_burst": {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "tactic": "Discovery"
        },

        "suspicious_activity": {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "tactic": "Discovery"
        }
    }

    @classmethod
    def map_incident(cls, incident_type):

        return cls.TECHNIQUES.get(
            incident_type,
            {
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "tactic": "Command and Control"
            }
        )