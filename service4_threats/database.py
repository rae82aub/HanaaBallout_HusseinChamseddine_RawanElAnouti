import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


def get_db_connection():
    """
    create a connection to the SQLite threats database.
    enable foreign key constraints and dictionary-like row access.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """
    create the threats table if it does not exist.
    store threat type, value, description, severity, and source
    with a unique constraint on type plus value.
    """
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            threat_id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type TEXT NOT NULL
                CHECK (threat_type IN (
                    'IP Address',
                    'Domain',
                    'File Hash',
                    'Malware Signature',
                    'Other'
                )),
            threat_value TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL
                CHECK (severity IN (
                    'Low', 'Medium', 'High', 'Critical'
                )),
            source TEXT NOT NULL,
            date_added TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (threat_type, threat_value)
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Threats database initialized successfully.")
