import os
import re
import sqlite3
import ipaddress
import sys
from pathlib import Path

from flask import Flask, g, request, jsonify
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

from database import get_db_connection, init_db

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_DIR))

from common import PREFIX, role_required, write_audit_log

load_dotenv(PROJECT_DIR / ".env")

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY is missing from .env")

jwt = JWTManager(app)
init_db()

VALID_TYPES = [
    "IP Address",
    "Domain",
    "File Hash",
    "Malware Signature",
    "Other"
]
VALID_SEVERITIES = ["Low", "Medium", "High", "Critical"]
SERVICE_NAME = "Threat Intelligence"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.[A-Za-z0-9-]{1,63})+$"
)
HASH_PATTERN = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


def normalize_threat_value(threat_type, threat_value):
    """Normalize stored threat values by type."""
    value = threat_value.strip()
    if threat_type in ["Domain", "File Hash"]:
        return value.lower()
    return value


def validate_threat_value(threat_type, threat_value):
    """Validate IP, domain, and hash formats for the selected threat type."""
    if threat_type == "IP Address":
        try:
            ipaddress.ip_address(threat_value)
        except (ValueError, TypeError):
            return "Invalid IP address format"
    elif threat_type == "Domain":
        if not DOMAIN_PATTERN.fullmatch(threat_value):
            return "Invalid domain format"
    elif threat_type == "File Hash":
        if not HASH_PATTERN.fullmatch(threat_value):
            return "Invalid hash format. Use MD5, SHA-1, or SHA-256"
    elif threat_type in ["Malware Signature", "Other"]:
        if not isinstance(threat_value, str) or not threat_value.strip():
            return "Invalid threat value"
    return None


@app.route("/", methods=["GET"])
def home():
    """Return a confirmation that the Threat Intelligence Service is running."""
    return jsonify({
        "message": "Threat Intelligence Service is running"
    })


@app.route(f"{PREFIX}/threats", methods=["POST"])
@role_required(["Security Administrator"], SERVICE_NAME)
def add_threat():
    """Add a threat indicator after validating type, value, and severity.
    Accessible only to Security Administrators.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    required_fields = [
        "threat_type",
        "threat_value",
        "description",
        "severity",
        "source"
    ]

    for field in required_fields:
        value = data.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return jsonify({"message": f"{field} is required"}), 400

    threat_type = data["threat_type"].strip() if isinstance(data["threat_type"], str) else data["threat_type"]
    if threat_type not in VALID_TYPES:
        return jsonify({"message": "Invalid threat type"}), 400

    if not isinstance(data["threat_value"], str) or not data["threat_value"].strip():
        return jsonify({"message": "Invalid threat value"}), 400

    if not isinstance(data["description"], str) or not data["description"].strip():
        return jsonify({"message": "Invalid description"}), 400

    if not isinstance(data["source"], str) or not data["source"].strip():
        return jsonify({"message": "Invalid source"}), 400

    if data["severity"] not in VALID_SEVERITIES:
        return jsonify({"message": "Invalid severity"}), 400

    error = validate_threat_value(threat_type, data["threat_value"].strip())
    if error:
        return jsonify({"message": error}), 400

    threat_value = normalize_threat_value(threat_type, data["threat_value"])

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO threats (
                threat_type, threat_value, description, severity, source
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                threat_type,
                threat_value,
                data["description"].strip(),
                data["severity"],
                data["source"].strip()
            )
        )
        conn.commit()
        threat_id = cursor.lastrowid
        threat = conn.execute(
            "SELECT * FROM threats WHERE threat_id = ?",
            (threat_id,)
        ).fetchone()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({
            "message": "A threat with the same type and value already exists"
        }), 409

    conn.close()

    write_audit_log(
        g.current_user["user_id"],
        "Data modification",
        f"Added threat {threat_id} ({threat_type}: {threat_value})",
        "Information",
        SERVICE_NAME
    )

    return jsonify({
        "message": "Threat created successfully",
        "threat": dict(threat)
    }), 201


@app.route(f"{PREFIX}/threats", methods=["GET"])
@role_required(
    ["Security Administrator", "Security Analyst", "Auditor"],
    SERVICE_NAME
)
def get_all_threats():
    """Retrieve all threat intelligence records.
    Accessible to Security Administrators, Security Analysts, and Auditors.
    """
    conn = get_db_connection()
    threats = conn.execute(
        "SELECT * FROM threats ORDER BY threat_id"
    ).fetchall()
    conn.close()

    return jsonify({
        "message": "Threats retrieved successfully",
        "count": len(threats),
        "threats": [dict(threat) for threat in threats]
    }), 200


@app.route(f"{PREFIX}/threats/search", methods=["GET"])
@role_required(
    ["Security Administrator", "Security Analyst"],
    SERVICE_NAME
)
def search_threats():
    """Search threats by type, value, severity, or source.
    Accessible to Security Administrators and Security Analysts.
    """
    allowed_filters = {
        "threat_type",
        "threat_value",
        "severity",
        "source"
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

    if "threat_type" in filters and filters["threat_type"] not in VALID_TYPES:
        return jsonify({"message": "Invalid threat type"}), 400

    if "severity" in filters and filters["severity"] not in VALID_SEVERITIES:
        return jsonify({"message": "Invalid severity"}), 400

    query = "SELECT * FROM threats WHERE 1=1"
    parameters = []

    for field, value in filters.items():
        if field in ["threat_value", "source"]:
            query += f" AND {field} LIKE ?"
            parameters.append(f"%{value}%")
        else:
            query += f" AND {field} = ?"
            parameters.append(value)

    query += " ORDER BY threat_id"

    conn = get_db_connection()
    threats = conn.execute(query, parameters).fetchall()
    conn.close()

    return jsonify({
        "message": "Threat search completed successfully",
        "count": len(threats),
        "threats": [dict(threat) for threat in threats]
    }), 200


@app.route(f"{PREFIX}/threats/<int:threat_id>", methods=["GET"])
@role_required(
    ["Security Administrator", "Security Analyst", "Auditor"],
    SERVICE_NAME
)
def get_threat(threat_id):
    """Retrieve a threat indicator by ID.
    Accessible to Security Administrators, Security Analysts, and Auditors.
    """
    conn = get_db_connection()
    threat = conn.execute(
        "SELECT * FROM threats WHERE threat_id = ?",
        (threat_id,)
    ).fetchone()
    conn.close()

    if not threat:
        return jsonify({"message": "Threat not found"}), 404

    return jsonify({
        "message": "Threat retrieved successfully",
        "threat": dict(threat)
    }), 200


@app.route(f"{PREFIX}/threats/<int:threat_id>", methods=["PUT"])
@role_required(["Security Administrator"], SERVICE_NAME)
def update_threat(threat_id):
    """Update description, severity, or source for an existing threat.
    Accessible only to Security Administrators.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        return jsonify({
            "message": "A non-empty JSON object is required"
        }), 400

    allowed_fields = {"description", "severity", "source"}
    if not set(data).issubset(allowed_fields):
        return jsonify({"message": "Invalid update fields"}), 400

    conn = get_db_connection()
    threat = conn.execute(
        "SELECT * FROM threats WHERE threat_id = ?",
        (threat_id,)
    ).fetchone()

    if not threat:
        conn.close()
        return jsonify({"message": "Threat not found"}), 404

    if "description" in data:
        if not isinstance(data["description"], str) or not data["description"].strip():
            conn.close()
            return jsonify({"message": "Invalid description"}), 400

    if "source" in data:
        if not isinstance(data["source"], str) or not data["source"].strip():
            conn.close()
            return jsonify({"message": "Invalid source"}), 400

    if "severity" in data and data["severity"] not in VALID_SEVERITIES:
        conn.close()
        return jsonify({"message": "Invalid severity"}), 400

    updated_description = data.get("description", threat["description"])
    updated_severity = data.get("severity", threat["severity"])
    updated_source = data.get("source", threat["source"])

    if isinstance(updated_description, str):
        updated_description = updated_description.strip()
    if isinstance(updated_source, str):
        updated_source = updated_source.strip()

    conn.execute(
        """
        UPDATE threats
        SET description = ?, severity = ?, source = ?
        WHERE threat_id = ?
        """,
        (updated_description, updated_severity, updated_source, threat_id)
    )
    conn.commit()

    updated = conn.execute(
        "SELECT * FROM threats WHERE threat_id = ?",
        (threat_id,)
    ).fetchone()
    conn.close()

    write_audit_log(
        g.current_user["user_id"],
        "Data modification",
        f"Updated threat {threat_id}",
        "Information",
        SERVICE_NAME
    )

    return jsonify({
        "message": "Threat updated successfully",
        "threat": dict(updated)
    }), 200


@app.route(f"{PREFIX}/threats/<int:threat_id>", methods=["DELETE"])
@role_required(["Security Administrator"], SERVICE_NAME)
def delete_threat(threat_id):
    """Delete a threat indicator by ID.
    Accessible only to Security Administrators.
    """
    conn = get_db_connection()
    threat = conn.execute(
        "SELECT * FROM threats WHERE threat_id = ?",
        (threat_id,)
    ).fetchone()

    if not threat:
        conn.close()
        return jsonify({"message": "Threat not found"}), 404

    conn.execute(
        "DELETE FROM threats WHERE threat_id = ?",
        (threat_id,)
    )
    conn.commit()
    conn.close()

    write_audit_log(
        g.current_user["user_id"],
        "Data modification",
        f"Deleted threat {threat_id}",
        "Warning",
        SERVICE_NAME
    )

    return jsonify({
        "message": "Threat deleted successfully",
        "threat_id": threat_id
    }), 200


if __name__ == "__main__":
    app.run(debug=True, port=5004)
