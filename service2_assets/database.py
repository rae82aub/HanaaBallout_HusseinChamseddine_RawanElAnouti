
import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            operating_system TEXT,
            owner_id INTEGER NOT NULL,
            department TEXT NOT NULL,
            location TEXT,
            criticality_level TEXT NOT NULL
                CHECK (criticality_level IN (
                    'Low', 'Medium', 'High', 'Critical'
                )),
            status TEXT NOT NULL DEFAULT 'Active'
                CHECK (status IN (
                    'Active', 'Inactive', 'Under Maintenance'
                ))
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Assets database initialized successfully.")
