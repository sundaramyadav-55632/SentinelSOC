import json

from src.database.database import Database


class IncidentStore:

    ALLOWED_STATUSES = {
        "open",
        "investigating",
        "contained",
        "resolved",
        "false_positive"
    }

    def __init__(self, database=None):

        self.database = (
            database
            if database is not None
            else Database()
        )

    # =========================================================
    # HELPER
    # =========================================================

    @staticmethod
    def _to_dict(value):

        if hasattr(value, "to_dict"):
            return value.to_dict()

        if isinstance(value, dict):
            return value

        return vars(value)

    # =========================================================
    # EVENT DEDUPLICATION KEY
    # =========================================================

    @staticmethod
    def _event_key(event):

        return (
            event.get("timestamp"),
            event.get("source"),
            event.get("event_type"),
            event.get("severity"),
            event.get("username"),
            event.get("source_ip"),
            event.get("source_port"),
            event.get("destination_ip"),
            event.get("destination_port"),
            event.get("protocol"),
            event.get("action"),
            event.get("message")
        )

    # =========================================================
    # CHECK EXISTING EVENT
    # =========================================================

    def _find_existing_event(self, event):

        key = self._event_key(event)

        cursor = self.database.connection.cursor()

        rows = cursor.execute(
            """
            SELECT *
            FROM events
            ORDER BY id DESC
            """
        ).fetchall()

        for row in rows:

            existing = dict(row)

            if self._event_key(existing) == key:

                return existing

        return None

    # =========================================================
    # SAVE EVENT
    # =========================================================

    def save_event(self, event):

        event = self._to_dict(event)

        # -----------------------------------------------------
        # Prevent duplicate events
        # -----------------------------------------------------

        existing = self._find_existing_event(
            event
        )

        if existing:

            return existing["id"]

        cursor = self.database.connection.cursor()

        cursor.execute(
            """
            INSERT INTO events (
                timestamp,
                source,
                event_type,
                severity,
                username,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,
                action,
                message,
                raw_log
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("timestamp"),
                event.get("source"),
                event.get("event_type"),
                event.get("severity"),
                event.get("username"),
                event.get("source_ip"),
                event.get("source_port"),
                event.get("destination_ip"),
                event.get("destination_port"),
                event.get("protocol"),
                event.get("action"),
                event.get("message"),
                event.get(
                    "raw_log",
                    event.get("message")
                )
            )
        )

        self.database.connection.commit()

        return cursor.lastrowid

    # =========================================================
    # ALERT DEDUPLICATION KEY
    # =========================================================

    @staticmethod
    def _alert_key(alert):

        return (
            alert.get(
                "alert_type",
                alert.get("incident_type")
            ),
            alert.get(
                "incident_type"
            ),
            alert.get("severity"),
            alert.get("source_ip"),
            alert.get("username"),
            alert.get("failed_attempts", 0),
            alert.get("unique_users", 0),
            alert.get("unique_ports", 0),
            alert.get("confidence", 0),
            alert.get(
                "message",
                alert.get("description")
            )
        )

    # =========================================================
    # CHECK EXISTING ALERT
    # =========================================================

    def _find_existing_alert(self, alert):

        key = self._alert_key(alert)

        cursor = self.database.connection.cursor()

        rows = cursor.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY id DESC
            """
        ).fetchall()

        for row in rows:

            existing = dict(row)

            if self._alert_key(existing) == key:

                return existing

        return None

    # =========================================================
    # SAVE ALERT
    # =========================================================

    def save_alert(self, alert):

        alert = self._to_dict(alert)

        # -----------------------------------------------------
        # Prevent duplicate alerts
        # -----------------------------------------------------

        existing = self._find_existing_alert(
            alert
        )

        if existing:

            return existing["id"]

        cursor = self.database.connection.cursor()

        cursor.execute(
            """
            INSERT INTO alerts (
                alert_type,
                incident_type,
                severity,
                source_ip,
                username,
                failed_attempts,
                unique_users,
                unique_ports,
                confidence,
                message,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get(
                    "alert_type",
                    alert.get("incident_type")
                ),

                alert.get(
                    "incident_type",
                    alert.get("alert_type")
                ),

                alert.get(
                    "severity"
                ),

                alert.get(
                    "source_ip"
                ),

                alert.get(
                    "username"
                ),

                alert.get(
                    "failed_attempts",
                    0
                ),

                alert.get(
                    "unique_users",
                    0
                ),

                alert.get(
                    "unique_ports",
                    0
                ),

                alert.get(
                    "confidence",
                    0
                ),

                alert.get(
                    "message",
                    alert.get("description")
                ),

                alert.get(
                    "created_at"
                )
            )
        )

        self.database.connection.commit()

        return cursor.lastrowid

    # =========================================================
    # INCIDENT DEDUPLICATION KEY
    # =========================================================

    @staticmethod
    def _incident_key(incident):

        return (
            incident.get("incident_type"),
            incident.get("source_ip"),
            incident.get("username"),
            incident.get("failed_attempts", 0),
            incident.get("unique_users", 0),
            incident.get("unique_ports", 0),
            incident.get("risk_score", 0),
            incident.get("severity"),
            incident.get("description")
        )

    # =========================================================
    # CHECK EXISTING INCIDENT
    # =========================================================

    def _find_existing_incident(self, incident):

        key = self._incident_key(
            incident
        )

        cursor = self.database.connection.cursor()

        rows = cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY id DESC
            """
        ).fetchall()

        for row in rows:

            existing = dict(row)

            if self._incident_key(
                existing
            ) == key:

                return existing

        return None

    # =========================================================
    # SAVE INCIDENT
    # =========================================================

    def save_incident(self, incident):

        incident = self._to_dict(
            incident
        )

        # -----------------------------------------------------
        # Prevent duplicate incidents
        # -----------------------------------------------------

        existing = self._find_existing_incident(
            incident
        )

        if existing:

            return existing["id"]

        cursor = self.database.connection.cursor()

        reasons = incident.get(
            "reasons",
            []
        )

        evidence = incident.get(
            "evidence",
            []
        )

        mitre = incident.get(
            "mitre",
            {}
        )

        if not isinstance(
            mitre,
            dict
        ):
            mitre = {}

        # -----------------------------------------------------
        # Insert incident
        # -----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO incidents (
                incident_type,
                source_ip,
                username,
                failed_attempts,
                unique_users,
                unique_ports,
                risk_score,
                severity,
                status,
                reasons,
                created_at,
                confidence,
                successful_login,
                description,
                evidence,
                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic,
                mitre_description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.get(
                    "incident_type"
                ),

                incident.get(
                    "source_ip"
                ),

                incident.get(
                    "username"
                ),

                incident.get(
                    "failed_attempts",
                    0
                ),

                incident.get(
                    "unique_users",
                    0
                ),

                incident.get(
                    "unique_ports",
                    0
                ),

                incident.get(
                    "risk_score",
                    0
                ),

                incident.get(
                    "severity",
                    "low"
                ),

                incident.get(
                    "status",
                    "open"
                ),

                json.dumps(
                    reasons
                ),

                incident.get(
                    "created_at"
                ),

                incident.get(
                    "confidence",
                    0
                ),

                int(
                    bool(
                        incident.get(
                            "successful_login",
                            False
                        )
                    )
                ),

                incident.get(
                    "description"
                ),

                json.dumps(
                    evidence
                ),

                mitre.get(
                    "technique_id"
                ),

                mitre.get(
                    "technique_name"
                ),

                mitre.get(
                    "tactic"
                ),

                mitre.get(
                    "description"
                )
            )
        )

        incident_id = cursor.lastrowid

        # =====================================================
        # RESPONSE ACTIONS
        # =====================================================

        response = incident.get(
            "response",
            incident.get(
                "recommended_response",
                {}
            )
        )

        if isinstance(
            response,
            dict
        ):

            actions = response.get(
                "recommended_actions",
                []
            )

            for action in actions:

                cursor.execute(
                    """
                    INSERT INTO response_actions (
                        incident_id,
                        action,
                        status
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        incident_id,
                        action,
                        "recommended"
                    )
                )

        self.database.connection.commit()

        return incident_id

    # =========================================================
    # JSON HELPER
    # =========================================================

    @staticmethod
    def _parse_json(value):

        if not value:

            return []

        try:

            return json.loads(
                value
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            return []

    # =========================================================
    # GET ALL INCIDENTS
    # =========================================================

    def get_incidents(self):

        cursor = self.database.connection.cursor()

        rows = cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY id DESC
            """
        ).fetchall()

        incidents = []

        for row in rows:

            incident = dict(row)

            incident["reasons"] = self._parse_json(
                incident.get(
                    "reasons"
                )
            )

            incident["evidence"] = self._parse_json(
                incident.get(
                    "evidence"
                )
            )

            incidents.append(
                incident
            )

        return incidents

    # =========================================================
    # GET SINGLE INCIDENT
    # =========================================================

    def get_incident(
        self,
        incident_id
    ):

        cursor = self.database.connection.cursor()

        row = cursor.execute(
            """
            SELECT *
            FROM incidents
            WHERE id = ?
            """,
            (
                incident_id,
            )
        ).fetchone()

        if row is None:

            return None

        incident = dict(row)

        incident["reasons"] = self._parse_json(
            incident.get(
                "reasons"
            )
        )

        incident["evidence"] = self._parse_json(
            incident.get(
                "evidence"
            )
        )

        return incident

    # =========================================================
    # UPDATE INCIDENT STATUS
    # =========================================================

    def update_incident_status(
        self,
        incident_id,
        status
    ):

        status = status.lower().strip()

        if status not in self.ALLOWED_STATUSES:

            raise ValueError(
                "Invalid incident status. "
                f"Allowed values: "
                f"{', '.join(sorted(self.ALLOWED_STATUSES))}"
            )

        cursor = self.database.connection.cursor()

        cursor.execute(
            """
            UPDATE incidents
            SET
                status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                status,
                incident_id
            )
        )

        self.database.connection.commit()

        return cursor.rowcount