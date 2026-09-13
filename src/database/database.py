import sqlite3
from pathlib import Path


class Database:

    def __init__(self, database_path="data/sentinelsoc.db"):

        self.database_path = database_path

        Path(self.database_path).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False
        )

        self.connection.row_factory = sqlite3.Row

        self.create_tables()

    # =========================================================
    # CREATE TABLES
    # =========================================================

    def create_tables(self):

        cursor = self.connection.cursor()

        # =====================================================
        # EVENTS
        # =====================================================

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                event_type TEXT,
                severity TEXT,
                username TEXT,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                protocol TEXT,
                action TEXT,
                message TEXT,
                raw_log TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # =====================================================
        # ALERTS
        # =====================================================

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                incident_type TEXT,
                severity TEXT,
                source_ip TEXT,
                username TEXT,
                failed_attempts INTEGER DEFAULT 0,
                unique_users INTEGER DEFAULT 0,
                unique_ports INTEGER DEFAULT 0,
                confidence INTEGER DEFAULT 0,
                message TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # =====================================================
        # INCIDENTS
        # =====================================================

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                confidence INTEGER DEFAULT 0,
                successful_login INTEGER DEFAULT 0,
                description TEXT,
                evidence TEXT,
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                mitre_tactic TEXT,
                mitre_description TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # =====================================================
        # RESPONSE ACTIONS
        # =====================================================

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                action TEXT,
                status TEXT DEFAULT 'recommended',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
            )
            """
        )

        self.connection.commit()

        # =====================================================
        # DATABASE MIGRATIONS
        # =====================================================

        self._migrate_table(
            "events",
            {
                "timestamp": "TEXT",
                "source": "TEXT",
                "event_type": "TEXT",
                "severity": "TEXT",
                "username": "TEXT",
                "source_ip": "TEXT",
                "source_port": "INTEGER",
                "destination_ip": "TEXT",
                "destination_port": "INTEGER",
                "protocol": "TEXT",
                "action": "TEXT",
                "message": "TEXT",
                "raw_log": "TEXT",
                "created_at": "TEXT"
            }
        )

        self._migrate_table(
            "alerts",
            {
                "alert_type": "TEXT",
                "incident_type": "TEXT",
                "severity": "TEXT",
                "source_ip": "TEXT",
                "username": "TEXT",
                "failed_attempts": "INTEGER DEFAULT 0",
                "unique_users": "INTEGER DEFAULT 0",
                "unique_ports": "INTEGER DEFAULT 0",
                "confidence": "INTEGER DEFAULT 0",
                "message": "TEXT",
                "created_at": "TEXT"
            }
        )

        self._migrate_table(
            "incidents",
            {
                "incident_type": "TEXT",
                "source_ip": "TEXT",
                "username": "TEXT",
                "failed_attempts": "INTEGER DEFAULT 0",
                "unique_users": "INTEGER DEFAULT 0",
                "unique_ports": "INTEGER DEFAULT 0",
                "risk_score": "INTEGER DEFAULT 0",
                "severity": "TEXT",
                "status": "TEXT DEFAULT 'open'",
                "reasons": "TEXT",
                "created_at": "TEXT",
                "confidence": "INTEGER DEFAULT 0",
                "successful_login": "INTEGER DEFAULT 0",
                "description": "TEXT",
                "evidence": "TEXT",
                "mitre_technique_id": "TEXT",
                "mitre_technique_name": "TEXT",
                "mitre_tactic": "TEXT",
                "mitre_description": "TEXT",
                "updated_at": "TEXT"
            }
        )

        self._migrate_table(
            "response_actions",
            {
                "incident_id": "INTEGER",
                "action": "TEXT",
                "status": "TEXT DEFAULT 'recommended'",
                "created_at": "TEXT"
            }
        )

        self.connection.commit()

    # =========================================================
    # SAFE SQLITE MIGRATION
    # =========================================================

    def _migrate_table(
        self,
        table_name,
        columns
    ):

        cursor = self.connection.cursor()

        cursor.execute(
            f"PRAGMA table_info({table_name})"
        )

        existing_columns = {
            row["name"]
            for row in cursor.fetchall()
        }

        for column_name, definition in columns.items():

            if column_name not in existing_columns:

                try:

                    cursor.execute(
                        f"""
                        ALTER TABLE {table_name}
                        ADD COLUMN {column_name}
                        {definition}
                        """
                    )

                    print(
                        f"[+] Database migration: "
                        f"{table_name}.{column_name}"
                    )

                except sqlite3.OperationalError as error:

                    print(
                        f"[!] Migration warning: "
                        f"{table_name}.{column_name}: "
                        f"{error}"
                    )

    # =========================================================
    # CLOSE
    # =========================================================

    def close(self):

        if self.connection:

            self.connection.close()