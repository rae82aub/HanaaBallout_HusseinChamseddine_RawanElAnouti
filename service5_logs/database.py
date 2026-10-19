import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


def get_db_connection():
    """
    create a connection to the SQLite audit logs database.
    enable foreign key constraints and dictionary-like row access.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """
    create the logs table if it does not exist.
    store user activity, severity, related service, and timestamp.
    logs are inserted once and are not updated after creation.
    """
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            severity TEXT NOT NULL
                CHECK (severity IN (
                    'Information', 'Warning', 'Error', 'Critical'
                )),
            related_service TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Audit logs database initialized successfully.")
