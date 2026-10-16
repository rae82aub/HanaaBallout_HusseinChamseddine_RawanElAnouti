import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


def get_db_connection():
    """
    create a connection to the SQLite vulnerabilities database.
    enable foreign key constraints and dictionary-like row access.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """
    createe the vulnerabilities table if it does not exist.
    Store vulnerability details, CVE identifiers, CVSS scores,
    affected assets, severity levels, and resolution status.
    Enforce valid CVSS scores, severity levels, and statuses.
    """
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            cvss_score REAL NOT NULL
                CHECK (cvss_score >= 0 AND cvss_score <= 10),
            severity_level TEXT NOT NULL
                CHECK (severity_level IN (
                    'Low', 'Medium', 'High', 'Critical'
                )),
            asset_id INTEGER NOT NULL,
            discovery_source TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open'
                CHECK (status IN (
                    'Open',
                    'Under Investigation',
                    'In Progress',
                    'Resolved',
                    'Closed'
                )),
            creation_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolution_date TEXT
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Vulnerabilities database initialized successfully.")
