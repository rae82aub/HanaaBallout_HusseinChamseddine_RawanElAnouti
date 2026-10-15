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
        CREATE TABLE IF NOT EXISTS notifications (
            notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            notification_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Unread',
            creation_date TEXT DEFAULT CURRENT_TIMESTAMP,
            read_date TEXT,
            CHECK (notification_type IN (
                'Incident Assignment',
                'Security Alert',
                'System Notification',
                'Threat Alert',
                'Vulnerability Alert'
            )),
            CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
            CHECK (status IN ('Unread', 'Read'))
        )
    """)

    connection.commit()
    connection.close()
