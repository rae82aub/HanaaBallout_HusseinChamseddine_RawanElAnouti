import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import g, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent
HANAA_DIR = PROJECT_DIR
RAWAN_DIR = PROJECT_DIR

load_dotenv(PROJECT_DIR / ".env")

PREFIX = "/Hussein-Chamseddine"
LOGS_DB = Path(
    os.environ.get(
        "AUDIT_DB_PATH",
        str(PROJECT_DIR / "service5_logs" / "database.db")
    )
)
THREATS_DB = PROJECT_DIR / "service4_threats" / "database.db"

DEFAULT_USERS_DB = HANAA_DIR / "service1_users" / "database.db"
ASSETS_DB = HANAA_DIR / "service2_assets" / "database.db"
VULNERABILITIES_DB = HANAA_DIR / "Service7_vulnerabilities" / "database.db"
INCIDENTS_DB = RAWAN_DIR / "service3_incidents" / "database.db"


def users_db_path():
    """Return the Service 1 users database path."""
    configured = os.environ.get("USERS_DB_PATH")
    if configured:
        return Path(configured)
    return DEFAULT_USERS_DB


def connect_sqlite(path):
    """Open a SQLite database with row access and foreign keys enabled."""
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def get_users_connection():
    """Connect to the Service 1 users database for identity and role checks."""
    return connect_sqlite(users_db_path())


def get_current_user():
    """Load the authenticated user from Service 1 using the JWT identity."""
    user_id = get_jwt_identity()
    connection = get_users_connection()

    user = connection.execute(
        """
        SELECT user_id, username, role, account_status
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()

    if user is None:
        try:
            user = connection.execute(
                """
                SELECT user_id, username, role, account_status
                FROM users
                WHERE user_id = ?
                """,
                (int(user_id),),
            ).fetchone()
        except (TypeError, ValueError):
            user = None

    connection.close()
    return dict(user) if user else None


def write_audit_log(user_id, action, description, severity, related_service):
    """Insert an immutable audit record into the Service 5 logs database."""
    try:
        LOGS_DB.parent.mkdir(parents=True, exist_ok=True)
        connection = connect_sqlite(LOGS_DB)
        connection.execute(
            """
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
            """
        )
        connection.execute(
            """
            INSERT INTO logs (
                user_id, action, description, severity, related_service
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, action, description, severity, related_service),
        )
        connection.commit()
        connection.close()
    except sqlite3.Error:
        pass


def role_required(allowed_roles, related_service):
    """Restrict an endpoint to active users with one of the specified roles."""

    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = get_current_user()

            if not user or user["account_status"] != "Active":
                write_audit_log(
                    get_jwt_identity(),
                    "Unauthorized access",
                    "Request rejected because the account is inactive or not found",
                    "Warning",
                    related_service,
                )
                return jsonify({
                    "message": "Account not active or not found"
                }), 403

            if user["role"] not in allowed_roles:
                write_audit_log(
                    user["user_id"],
                    "Unauthorized access",
                    (
                        f"{user['role']} attempted {request.method} "
                        f"{request.path}"
                    ),
                    "Warning",
                    related_service,
                )
                return jsonify({
                    "message": "Permission denied"
                }), 403

            g.current_user = user
            return fn(*args, **kwargs)

        return wrapper

    return decorator
