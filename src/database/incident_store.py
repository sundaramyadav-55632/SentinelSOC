import json

from src.database.database import Database


class IncidentStore:

    def __init__(self, database=None):

        self.database = database or Database()

    def save_event(self, event):

        cursor = self.database.connection.cursor()

        data = event.to_dict()

        cursor.execute("""
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
        """, (

            data.get("timestamp"),

            data.get("source"),

            data.get("event_type"),

            data.get("severity"),

            data.get("username"),

            data.get("source_ip"),

            data.get("source_port"),

            data.get("destination_ip"),

            data.get("destination_port"),

            data.get("protocol"),

            data.get("action"),

            data.get("message")
        ))

        self.database.connection.commit()

    def save_alert(self, alert):

        cursor = self.database.connection.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                alert_type,
                source_ip,
                username,
                failed_attempts,
                unique_users,
                unique_ports,
                window_seconds,
                severity
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (

            alert.get("alert_type"),

            alert.get("source_ip"),

            alert.get("username"),

            alert.get("failed_attempts", 0),

            alert.get("unique_users", 0),

            alert.get("unique_ports", 0),

            alert.get("window_seconds", 0),

            alert.get("severity", "low")
        ))

        self.database.connection.commit()

    def save_incident(self, incident):

        cursor = self.database.connection.cursor()

        reasons = json.dumps(
            incident.get("reasons", [])
        )

        cursor.execute("""
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
                reasons
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (

            incident.get(
                "incident_type",
                "unknown"
            ),

            incident.get("source_ip"),

            incident.get("username"),

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

            reasons
        ))

        incident_id = cursor.lastrowid

        actions = incident.get(
            "recommended_actions",
            []
        )

        for order, action in enumerate(
            actions,
            start=1
        ):

            cursor.execute("""
                INSERT INTO response_actions (
                    incident_id,
                    action,
                    action_order
                )

                VALUES (?, ?, ?)
            """, (

                incident_id,

                action,

                order
            ))

        self.database.connection.commit()

        return incident_id

    def get_incidents(self):

        cursor = self.database.connection.cursor()

        cursor.execute("""
            SELECT *
            FROM incidents
            ORDER BY id DESC
        """)

        return [
            dict(row)
            for row in cursor.fetchall()
        ]

    def get_incident(self, incident_id):

        cursor = self.database.connection.cursor()

        cursor.execute("""
            SELECT *
            FROM incidents
            WHERE id = ?
        """, (incident_id,))

        row = cursor.fetchone()

        if row is None:
            return None

        incident = dict(row)

        cursor.execute("""
            SELECT action, action_order
            FROM response_actions
            WHERE incident_id = ?
            ORDER BY action_order
        """, (incident_id,))

        incident["recommended_actions"] = [
            row["action"]
            for row in cursor.fetchall()
        ]

        return incident

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
                "Invalid incident status"
            )

        cursor = self.database.connection.cursor()

        cursor.execute("""
            UPDATE incidents
            SET status = ?
            WHERE id = ?
        """, (

            status,

            incident_id
        ))

        self.database.connection.commit()

        return cursor.rowcount