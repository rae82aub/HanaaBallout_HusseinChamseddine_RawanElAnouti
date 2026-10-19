import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "database.db"
USERS_DB_PATH = Path(__file__).resolve().parent.parent / "service1_users" / "database.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def get_users_connection():
    connection = sqlite3.connect(USERS_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            reporter_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            assigned_analyst_id INTEGER,
            status TEXT NOT NULL DEFAULT 'Open',
            creation_date TEXT DEFAULT CURRENT_TIMESTAMP,
            resolution_date TEXT,
            CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
            CHECK (status IN (
                'Open',
                'Under Investigation',
                'Mitigated',
                'Resolved',
                'Closed'
            ))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigation_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            analyst_id INTEGER NOT NULL,
            note_content TEXT NOT NULL,
            creation_timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                ON DELETE CASCADE
        )
    """)

    connection.commit()
    connection.close()
