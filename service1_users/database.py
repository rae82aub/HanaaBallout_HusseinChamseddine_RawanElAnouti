import sqlite3
from pathlib import Path
from getpass import getpass
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).resolve().parent / "database.db"


def get_connection():
    """
    create a connection to the SQLite database.
    Enable foreign key constraints and dictionary-like row access.
    """
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create_tables():
    """
    create the users table if it does not exist.
    Define user information, unique credentials, allowed roles,
    and valid account statuses.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            department TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Regular Employee',
            account_status TEXT NOT NULL DEFAULT 'Active',
            created_date TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login_date TEXT,
            CHECK (role IN (
                'Security Administrator',
                'Security Analyst',
                'Regular Employee',
                'Auditor'
            )),
            CHECK (account_status IN (
                'Active',
                'Inactive',
                'Suspended'
            ))
        )
    """)

    connection.commit()
    connection.close()


def create_initial_admin():
    """
    create the first Security Administrator through terminal input.
    prevent duplicate administrator initialization, validate required
    fields, and securely hash the password before storing it.
    """
    connection = get_connection()

    try:
        existing_admin = connection.execute("""
            SELECT user_id FROM users
            WHERE role = 'Security Administrator'
            LIMIT 1
        """).fetchone()

        if existing_admin:
            print("A Security Administrator already exists.")
            return

        print("Create the initial Security Administrator")

        full_name = input("Full name: ").strip()
        username = input("Username: ").strip()
        email = input("Email: ").strip().lower()
        password = getpass("Password: ")

        if not full_name or not username or not email or not password:
            print("All fields are required.")
            return

        if len(password) < 8:
            print("Password must contain at least 8 characters.")
            return

        password_hash = generate_password_hash(password)

        connection.execute("""
            INSERT INTO users (
                full_name, username, email,
                password_hash, department, role, account_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            full_name,
            username,
            email,
            password_hash,
            "IT",
            "Security Administrator",
            "Active"
        ))

        connection.commit()
        print("Security Administrator created successfully!")

    except sqlite3.IntegrityError:
        print("Username or email already exists.")

    finally:
        connection.close()


if __name__ == "__main__":
    create_tables()
    create_initial_admin()
