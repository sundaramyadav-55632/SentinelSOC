import sqlite3
from pathlib import Path


DATABASE_PATH = Path("data/sentinelsoc.db")


class Database:

    def __init__(self, database_path=DATABASE_PATH):

        self.database_path = database_path

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.connection = sqlite3.connect(
            self.database_path
        )

        self.connection.row_factory = sqlite3.Row

        self.create_tables()

    def create_tables(self):

        cursor = self.connection.cursor()

        cursor.execute("""
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

                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                alert_type TEXT,

                source_ip TEXT,

                username TEXT,

                failed_attempts INTEGER,

                unique_users INTEGER,

                unique_ports INTEGER,

                window_seconds INTEGER,

                severity TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_type TEXT,

                source_ip TEXT,

                username TEXT,

                failed_attempts INTEGER,

                unique_users INTEGER,

                unique_ports INTEGER,

                risk_score INTEGER,

                severity TEXT,

                status TEXT DEFAULT 'open',

                reasons TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS response_actions (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_id INTEGER,

                action TEXT,

                action_order INTEGER,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id)
            )
        """)

        self.connection.commit()

    def close(self):

        self.connection.close()