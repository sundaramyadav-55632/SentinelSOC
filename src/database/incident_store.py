import json
from datetime import datetime

from src.database.database import Database


class IncidentStore:

    def __init__(
        self,
        database=None
    ):

        self.database = (
            database
            if database
            else Database()
        )


    # =========================================================
    # EVENTS
    # =========================================================

    def save_event(
        self,
        event
    ):

        cursor = (
            self.database.connection.cursor()
        )


        def get_value(
            key,
            default=None
        ):

            if isinstance(event, dict):

                return event.get(
                    key,
                    default
                )

            return getattr(
                event,
                key,
                default
            )


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
                message

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                get_value("timestamp"),

                get_value("source"),

                get_value("event_type"),

                get_value("severity"),

                get_value("username"),

                get_value("source_ip"),

                get_value("source_port"),

                get_value("destination_ip"),

                get_value("destination_port"),

                get_value("protocol"),

                get_value("action"),

                get_value("message")
            )
        )


        self.database.connection.commit()

        return cursor.lastrowid


    # =========================================================
    # ALERTS
    # =========================================================

    def save_alert(
        self,
        alert
    ):

        cursor = (
            self.database.connection.cursor()
        )


        def get_value(
            key,
            default=None
        ):

            if isinstance(alert, dict):

                return alert.get(
                    key,
                    default
                )

            return getattr(
                alert,
                key,
                default
            )


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
                message

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                get_value(
                    "alert_type",
                    get_value(
                        "incident_type"
                    )
                ),

                get_value(
                    "incident_type"
                ),

                get_value(
                    "severity",
                    "low"
                ),

                get_value(
                    "source_ip"
                ),

                get_value(
                    "username"
                ),

                get_value(
                    "failed_attempts",
                    0
                ),

                get_value(
                    "unique_users",
                    0
                ),

                get_value(
                    "unique_ports",
                    0
                ),

                get_value(
                    "confidence",
                    0
                ),

                get_value(
                    "message",
                    ""
                )
            )
        )


        self.database.connection.commit()

        return cursor.lastrowid


    # =========================================================
    # INCIDENTS
    # =========================================================

    def save_incident(
        self,
        incident
    ):

        cursor = (
            self.database.connection.cursor()
        )


        def get_value(
            key,
            default=None
        ):

            if isinstance(incident, dict):

                return incident.get(
                    key,
                    default
                )

            return getattr(
                incident,
                key,
                default
            )


        incident_type = get_value(
            "incident_type",
            get_value(
                "alert_type",
                "unknown"
            )
        )


        severity = get_value(
            "severity",
            "low"
        )


        risk_score = get_value(
            "risk_score",
            0
        )


        confidence = get_value(
            "confidence",
            0
        )


        source_ip = get_value(
            "source_ip"
        )


        username = get_value(
            "username"
        )


        failed_attempts = get_value(
            "failed_attempts",
            0
        )


        unique_users = get_value(
            "unique_users",
            0
        )


        unique_ports = get_value(
            "unique_ports",
            0
        )


        successful_login = get_value(
            "successful_login",
            False
        )


        status = get_value(
            "status",
            "open"
        )


        description = get_value(
            "description",
            ""
        )


        reasons = get_value(
            "reasons",
            []
        )


        evidence = get_value(
            "evidence",
            []
        )


        recommended_response = get_value(
            "recommended_response",
            []
        )


        mitre = get_value(
            "mitre",
            {}
        )


        if mitre is None:

            mitre = {}


        if not isinstance(
            mitre,
            dict
        ):

            mitre = {}


        mitre_technique_id = (
            mitre.get(
                "technique_id"
            )
        )


        mitre_technique_name = (
            mitre.get(
                "technique_name"
            )
        )


        mitre_tactic = (
            mitre.get(
                "tactic"
            )
        )


        mitre_description = (
            mitre.get(
                "description"
            )
        )


        # -----------------------------------------------------
        # Convert complex fields into JSON strings
        # -----------------------------------------------------

        reasons_json = json.dumps(
            reasons,
            default=str
        )


        evidence_json = json.dumps(
            evidence,
            default=str
        )


        response_json = json.dumps(
            recommended_response,
            default=str
        )


        now = datetime.now().isoformat(
            timespec="seconds"
        )


        cursor.execute(
            """
            INSERT INTO incidents (

                incident_type,
                severity,
                risk_score,
                confidence,

                source_ip,
                username,

                failed_attempts,
                unique_users,
                unique_ports,

                successful_login,

                status,

                description,

                reasons,
                evidence,

                recommended_response,

                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic,
                mitre_description,

                created_at,
                updated_at

            )

            VALUES (

                ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?,
                ?,
                ?,
                ?, ?,
                ?,
                ?, ?, ?, ?,
                ?, ?

            )
            """,
            (
                incident_type,
                severity,
                risk_score,
                confidence,

                source_ip,
                username,

                failed_attempts,
                unique_users,
                unique_ports,

                int(
                    bool(
                        successful_login
                    )
                ),

                status,

                description,

                reasons_json,
                evidence_json,

                response_json,

                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic,
                mitre_description,

                now,
                now
            )
        )


        incident_id = (
            cursor.lastrowid
        )


        # -----------------------------------------------------
        # Save recommended response actions
        # -----------------------------------------------------

        if isinstance(
            recommended_response,
            dict
        ):

            actions = (
                recommended_response.get(
                    "recommended_actions",
                    []
                )
            )

        elif isinstance(
            recommended_response,
            list
        ):

            actions = (
                recommended_response
            )

        else:

            actions = []


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
                    str(action),
                    "recommended"
                )
            )


        self.database.connection.commit()


        return incident_id


    # =========================================================
    # GET INCIDENTS
    # =========================================================

    def get_incidents(self):

        cursor = (
            self.database.connection.cursor()
        )


        cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY id DESC
            """
        )


        rows = cursor.fetchall()


        return [
            self._incident_from_row(
                row
            )
            for row in rows
        ]


    # =========================================================
    # GET ONE INCIDENT
    # =========================================================

    def get_incident(
        self,
        incident_id
    ):

        cursor = (
            self.database.connection.cursor()
        )


        cursor.execute(
            """
            SELECT *
            FROM incidents
            WHERE id = ?
            """,
            (
                incident_id,
            )
        )


        row = cursor.fetchone()


        if row is None:

            return None


        return self._incident_from_row(
            row
        )


    # =========================================================
    # CONVERT DATABASE ROW
    # =========================================================

    def _incident_from_row(
        self,
        row
    ):

        incident = dict(
            row
        )


        # -----------------------------------------------------
        # Restore JSON fields
        # -----------------------------------------------------

        incident["reasons"] = (
            self._json_load(
                incident.get(
                    "reasons"
                ),
                []
            )
        )


        incident["evidence"] = (
            self._json_load(
                incident.get(
                    "evidence"
                ),
                []
            )
        )


        incident["recommended_response"] = (
            self._json_load(
                incident.get(
                    "recommended_response"
                ),
                []
            )
        )


        # -----------------------------------------------------
        # Reconstruct MITRE object
        # -----------------------------------------------------

        incident["mitre"] = {

            "technique_id":
                incident.get(
                    "mitre_technique_id"
                ),

            "technique_name":
                incident.get(
                    "mitre_technique_name"
                ),

            "tactic":
                incident.get(
                    "mitre_tactic"
                ),

            "description":
                incident.get(
                    "mitre_description"
                )

        }


        # -----------------------------------------------------
        # Clean database-specific MITRE columns from the
        # frontend representation.
        # -----------------------------------------------------

        incident.pop(
            "mitre_technique_id",
            None
        )

        incident.pop(
            "mitre_technique_name",
            None
        )

        incident.pop(
            "mitre_tactic",
            None
        )

        incident.pop(
            "mitre_description",
            None
        )


        return incident


    # =========================================================
    # JSON HELPER
    # =========================================================

    @staticmethod
    def _json_load(
        value,
        default
    ):

        if value is None:

            return default


        if isinstance(
            value,
            (
                list,
                dict
            )
        ):

            return value


        try:

            return json.loads(
                value
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            return default


    # =========================================================
    # UPDATE INCIDENT STATUS
    # =========================================================

    def update_incident_status(
        self,
        incident_id,
        status
    ):

        allowed_statuses = {

            "open",

            "investigating",

            "contained",

            "resolved",

            "false_positive"

        }


        if status not in allowed_statuses:

            raise ValueError(
                "Invalid incident status. "
                "Allowed values: "
                + ", ".join(
                    sorted(
                        allowed_statuses
                    )
                )
            )


        cursor = (
            self.database.connection.cursor()
        )


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