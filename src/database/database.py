import sqlite3
from pathlib import Path


class Database:

    def __init__(self, database_path="data/sentinelsoc.db"):

        self.database_path = database_path

        Path(database_path).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False
        )

        self.connection.row_factory = sqlite3.Row

        self.create_tables()

    # ==========================================================
    # CREATE DATABASE TABLES
    # ==========================================================

    def create_tables(self):

        cursor = self.connection.cursor()

        # ------------------------------------------------------
        # EVENTS
        # ------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                event_hash TEXT UNIQUE,

                timestamp TEXT,

                source TEXT,

                event_type TEXT,

                severity TEXT,

                source_ip TEXT,

                source_port INTEGER,

                destination_ip TEXT,

                destination_port INTEGER,

                username TEXT,

                protocol TEXT,

                action TEXT,

                raw_log TEXT,

                metadata TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # ------------------------------------------------------
        # ALERTS
        # ------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                alert_hash TEXT UNIQUE,

                alert_type TEXT,

                event_type TEXT,

                message TEXT,

                source_ip TEXT,

                username TEXT,

                severity TEXT,

                confidence INTEGER,

                evidence TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # ------------------------------------------------------
        # INCIDENTS
        # ------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_hash TEXT UNIQUE,

                incident_type TEXT,

                source_ip TEXT,

                username TEXT,

                failed_attempts INTEGER DEFAULT 0,

                unique_users INTEGER DEFAULT 0,

                unique_ports INTEGER DEFAULT 0,

                risk_score INTEGER DEFAULT 0,

                severity TEXT,

                status TEXT DEFAULT 'open',

                reasons TEXT,

                evidence TEXT,

                attack_types TEXT,

                successful_login INTEGER DEFAULT 0,

                confidence INTEGER,

                mitre_technique_id TEXT,

                mitre_technique TEXT,

                mitre_tactic TEXT,

                description TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # ------------------------------------------------------
        # RESPONSE ACTIONS
        # ------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS response_actions (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_id INTEGER,

                action TEXT,

                status TEXT DEFAULT 'recommended',

                details TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id)
            )
            """
        )

        # ------------------------------------------------------
        # INDEXES
        # ------------------------------------------------------

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_source_ip
            ON events(source_ip)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_event_type
            ON events(event_type)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
            ON alerts(source_ip)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_incidents_source_ip
            ON incidents(source_ip)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_incidents_status
            ON incidents(status)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_incidents_severity
            ON incidents(severity)
            """
        )

        self.connection.commit()

    # ==========================================================
    # DATABASE MIGRATION SUPPORT
    # ==========================================================

    def _column_exists(self, table_name, column_name):

        cursor = self.connection.cursor()

        cursor.execute(
            f"PRAGMA table_info({table_name})"
        )

        columns = [
            row["name"]
            for row in cursor.fetchall()
        ]

        return column_name in columns

    def add_column_if_missing(
        self,
        table_name,
        column_name,
        column_definition
    ):

        if not self._column_exists(
            table_name,
            column_name
        ):

            cursor = self.connection.cursor()

            cursor.execute(
                f"""
                ALTER TABLE {table_name}
                ADD COLUMN {column_name}
                {column_definition}
                """
            )

            self.connection.commit()

    # ==========================================================
    # CONNECTION
    # ==========================================================

    def close(self):

        if self.connection:

            self.connection.close()
            self.connection = None