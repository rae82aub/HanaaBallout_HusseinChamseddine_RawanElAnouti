import os
import sys
from pathlib import Path

from flask import Flask, g, request, jsonify
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

from database import get_db_connection, init_db

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_DIR))

from common import PREFIX, get_users_connection, role_required, write_audit_log

load_dotenv(PROJECT_DIR / ".env")

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY is missing from .env")

jwt = JWTManager(app)
init_db()

VALID_SEVERITIES = ["Information", "Warning", "Error", "Critical"]
SERVICE_NAME = "Security Audit Logging"


def user_exists(user_id):
    """Return True when the user ID exists in Service 1."""
    connection = get_users_connection()
    user = connection.execute(
        "SELECT user_id FROM users WHERE user_id = ?",
        (user_id,)
    ).fetchone()
    connection.close()
    return user is not None


@app.route("/", methods=["GET"])
def home():
    """Return a confirmation that the Security Audit Logging Service is running."""
    return jsonify({
        "message": "Security Audit Logging Service is running"
    })


@app.route(f"{PREFIX}/logs", methods=["POST"])
@role_required(["Security Administrator"], SERVICE_NAME)
def create_log():
    """Create a new audit log record.
    Accessible only to Security Administrators.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    required_fields = [
        "user_id",
        "action",
        "description",
        "severity",
        "related_service"
    ]

    for field in required_fields:
        value = data.get(field)
        if value is None or (isinstance(value, str) and not str(value).strip()):
            return jsonify({"message": f"{field} is required"}), 400

    try:
        user_id = int(data["user_id"])
        if user_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"message": "user_id must be a positive integer"}), 400

    if not user_exists(user_id):
        return jsonify({"message": "User not found"}), 404

    if not isinstance(data["action"], str) or not data["action"].strip():
        return jsonify({"message": "Invalid action"}), 400

    if not isinstance(data["description"], str) or not data["description"].strip():
        return jsonify({"message": "Invalid description"}), 400

    if not isinstance(data["related_service"], str) or not data["related_service"].strip():
        return jsonify({"message": "Invalid related_service"}), 400

    if data["severity"] not in VALID_SEVERITIES:
        return jsonify({
            "message": "Invalid severity. Allowed values: Information, Warning, Error, Critical"
        }), 400

    conn = get_db_connection()
    cursor = conn.execute(
        """
        INSERT INTO logs (
            user_id, action, description, severity, related_service
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user_id,
            data["action"].strip(),
            data["description"].strip(),
            data["severity"],
            data["related_service"].strip()
        )
    )
    conn.commit()
    log = conn.execute(
        "SELECT * FROM logs WHERE log_id = ?",
        (cursor.lastrowid,)
    ).fetchone()
    conn.close()

    return jsonify({
        "message": "Log created successfully",
        "log": dict(log)
    }), 201


@app.route(f"{PREFIX}/logs", methods=["GET"])
@role_required(["Security Administrator", "Auditor"], SERVICE_NAME)
def get_all_logs():
    """Retrieve all audit records.
    Accessible to Security Administrators and Auditors.
    """
    conn = get_db_connection()
    logs = conn.execute(
        "SELECT * FROM logs ORDER BY log_id"
    ).fetchall()
    conn.close()

    return jsonify({
        "message": "Logs retrieved successfully",
        "count": len(logs),
        "logs": [dict(log) for log in logs]
    }), 200


@app.route(f"{PREFIX}/logs/search", methods=["GET"])
@role_required(
    ["Security Administrator", "Auditor", "Security Analyst"],
    SERVICE_NAME
)
def search_logs():
    """Search logs by user, date, action, severity, or related service."""
    allowed_filters = {
        "user",
        "user_id",
        "date",
        "action",
        "severity",
        "related_service"
    }
    filters = request.args.to_dict()

    if not filters:
        return jsonify({
            "message": "At least one search parameter is required"
        }), 400

    if not set(filters).issubset(allowed_filters):
        return jsonify({"message": "Invalid search parameter"}), 400

    for field, value in filters.items():
        if not value.strip():
            return jsonify({"message": f"{field} cannot be empty"}), 400

    if "severity" in filters and filters["severity"] not in VALID_SEVERITIES:
        return jsonify({"message": "Invalid severity"}), 400

    query = "SELECT * FROM logs WHERE 1=1"
    parameters = []

    user_id = filters.get("user") or filters.get("user_id")
    if user_id:
        if not user_id.isdigit() or int(user_id) <= 0:
            return jsonify({"message": "Invalid user ID"}), 400
        query += " AND user_id = ?"
        parameters.append(int(user_id))

    if "date" in filters:
        query += " AND timestamp LIKE ?"
        parameters.append(f"{filters['date']}%")

    if "action" in filters:
        query += " AND action LIKE ?"
        parameters.append(f"%{filters['action']}%")

    if "severity" in filters:
        query += " AND severity = ?"
        parameters.append(filters["severity"])

    if "related_service" in filters:
        query += " AND related_service LIKE ?"
        parameters.append(f"%{filters['related_service']}%")

    query += " ORDER BY log_id"

    conn = get_db_connection()
    logs = conn.execute(query, parameters).fetchall()
    conn.close()

    return jsonify({
        "message": "Log search completed successfully",
        "count": len(logs),
        "logs": [dict(log) for log in logs]
    }), 200


@app.route(f"{PREFIX}/logs/user/<int:user_id>", methods=["GET"])
@role_required(["Security Administrator", "Auditor"], SERVICE_NAME)
def get_logs_by_user(user_id):
    """Return all security activities performed by a specific user."""
    if not user_exists(user_id):
        return jsonify({"message": "User not found"}), 404

    conn = get_db_connection()
    logs = conn.execute(
        """
        SELECT * FROM logs
        WHERE user_id = ?
        ORDER BY log_id
        """,
        (user_id,)
    ).fetchall()
    conn.close()

    return jsonify({
        "message": "User logs retrieved successfully",
        "user_id": user_id,
        "count": len(logs),
        "logs": [dict(log) for log in logs]
    }), 200


@app.route(f"{PREFIX}/logs/<int:log_id>", methods=["GET"])
@role_required(
    ["Security Administrator", "Auditor", "Security Analyst"],
    SERVICE_NAME
)
def get_log(log_id):
    """Retrieve a specific audit record by ID."""
    conn = get_db_connection()
    log = conn.execute(
        "SELECT * FROM logs WHERE log_id = ?",
        (log_id,)
    ).fetchone()
    conn.close()

    if not log:
        return jsonify({"message": "Log not found"}), 404

    return jsonify({
        "message": "Log retrieved successfully",
        "log": dict(log)
    }), 200


@app.route(f"{PREFIX}/logs/<int:log_id>", methods=["DELETE"])
@role_required(["Security Administrator"], SERVICE_NAME)
def delete_log(log_id):
    """Delete an audit record. Only Security Administrators may delete logs."""
    conn = get_db_connection()
    log = conn.execute(
        "SELECT * FROM logs WHERE log_id = ?",
        (log_id,)
    ).fetchone()

    if not log:
        conn.close()
        return jsonify({"message": "Log not found"}), 404

    conn.execute("DELETE FROM logs WHERE log_id = ?", (log_id,))
    conn.commit()
    conn.close()

    write_audit_log(
        g.current_user["user_id"],
        "Data modification",
        f"Deleted audit log {log_id}",
        "Warning",
        SERVICE_NAME
    )

    return jsonify({
        "message": "Log deleted successfully",
        "log_id": log_id
    }), 200


if __name__ == "__main__":
    app.run(debug=True, port=5005)
