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
        CREATE TABLE IF NOT EXISTS playbooks (
            playbook_id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_name TEXT NOT NULL,
            description TEXT NOT NULL,
            incident_category TEXT NOT NULL,
            severity TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            creation_date TEXT DEFAULT CURRENT_TIMESTAMP,
            CHECK (severity IN ('Low', 'Medium', 'High', 'Critical'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_actions (
            action_id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id INTEGER NOT NULL,
            action_description TEXT NOT NULL,
            step_number INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            assigned_user_id INTEGER,
            completion_date TEXT,
            UNIQUE (playbook_id, step_number),
            CHECK (step_number > 0),
            CHECK (status IN ('Pending', 'In Progress', 'Completed')),
            FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id)
                ON DELETE CASCADE
        )
    """)

    connection.commit()
    connection.close()
