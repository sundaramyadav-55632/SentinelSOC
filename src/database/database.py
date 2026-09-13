import os
import sqlite3


class Database:

    def __init__(
        self,
        database_path="data/sentinelsoc.db"
    ):

        self.database_path = database_path

        directory = os.path.dirname(
            self.database_path
        )

        if directory:
            os.makedirs(
                directory,
                exist_ok=True
            )

        self.connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False
        )

        self.connection.row_factory = sqlite3.Row

        self.create_tables()

    def create_tables(self):

        cursor = self.connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT,

                source TEXT,

                event_type TEXT,

                severity TEXT,

                source_ip TEXT,

                source_port INTEGER,

                destination_ip TEXT,

                destination_port INTEGER,

                protocol TEXT,

                username TEXT,

                action TEXT,

                raw_log TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP

            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                alert_type TEXT,

                severity TEXT,

                source_ip TEXT,

                username TEXT,

                description TEXT,

                evidence TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP

            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_type TEXT,

                severity TEXT,

                risk_score INTEGER,

                status TEXT DEFAULT 'open',

                source_ip TEXT,

                username TEXT,

                description TEXT,

                evidence TEXT,

                reasons TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP

            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS response_actions (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_id INTEGER,

                action TEXT,

                status TEXT,

                description TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (
                    incident_id
                )
                REFERENCES incidents(id)

            )
            """
        )

        self.connection.commit()

    def close(self):

        if self.connection:

            self.connection.close()