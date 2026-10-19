import os
import sqlite3
import re
from pathlib import Path
from functools import wraps
import requests
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from dotenv import load_dotenv

from database import get_db_connection, init_db


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

load_dotenv(PROJECT_DIR / ".env")

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY is missing from .env")

jwt = JWTManager(app)

init_db()

USERS_DB = PROJECT_DIR / "service1_users" / "database.db"
ASSETS_API = "http://127.0.0.1:5001/Hanaa-Ballout/assets"


def get_users_connection():
    """Connect to the Service 1 users database for authentication and role checks.
    """
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    return conn


def role_required(allowed_roles):
    """Restrict an endpoint to active users with one of the specified roles.
    Require a valid JWT and return 403 when access is denied.
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()

            conn = get_users_connection()

            user = conn.execute("""
                SELECT user_id, role, account_status
                FROM users
                WHERE user_id = ?
            """, (user_id,)).fetchone()

            conn.close()

            if not user or user["account_status"] != "Active":
                return jsonify({
                    "message": "Account not active or not found"
                }), 403

            if user["role"] not in allowed_roles:
                return jsonify({
                    "message": "Permission denied"
                }), 403

            return fn(*args, **kwargs)

        return wrapper
    return decorator


@app.route("/", methods=["GET"])
def home():
    """Return a confirmation that the Vulnerability Management Service is running.
    """
    return jsonify({
        "message": "Vulnerability Management Service is running"
    })


@app.route("/Hanaa-Ballout/vulnerabilities", methods=["POST"])
@role_required(["Security Administrator"])
def add_vulnerability():
    """Register a vulnerability after validating its details and confirming
    the affected asset exists through the Asset Management API.
    Accessible only to Security Administrators.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "message": "A JSON object is required"
        }), 400

    required_fields = [
        "title",
        "description",
        "cve_id",
        "cvss_score",
        "severity_level",
        "asset_id",
        "discovery_source"
    ]

    for field in required_fields:
        value = data.get(field)

        if value is None or (
            isinstance(value, str) and not value.strip()
        ):
            return jsonify({
                "message": f"{field} is required"
            }), 400

    for field in [
        "title", "description",
        "cve_id", "discovery_source"
    ]:
        if not isinstance(data[field], str) or not data[field].strip():
            return jsonify({
                "message": f"Invalid {field}"
            }), 400

    if not re.fullmatch(
        r"CVE-\d{4}-\d{4,}",
        data["cve_id"],
        re.IGNORECASE
    ):
        return jsonify({
            "message": "Invalid CVE identifier format"
        }), 400

    score = data["cvss_score"]

    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0 <= score <= 10
    ):
        return jsonify({
            "message": "CVSS score must be between 0 and 10"
        }), 400

    valid_severities = [
        "Low", "Medium", "High", "Critical"
    ]

    if data["severity_level"] not in valid_severities:
        return jsonify({
            "message": "Invalid severity level"
        }), 400

    asset_id = data["asset_id"]

    if type(asset_id) is not int or asset_id <= 0:
        return jsonify({
            "message": "Invalid asset ID"
        }), 400

    try:
        asset_response = requests.get(
            f"{ASSETS_API}/{asset_id}",
            headers={
                "Authorization": request.headers.get(
                    "Authorization", ""
                )
            },
            timeout=5
        )

    except requests.RequestException:
        return jsonify({
            "message": "Asset Management Service unavailable"
        }), 503

    if asset_response.status_code == 404:
        return jsonify({
            "message": "Affected asset not found"
        }), 404

    if asset_response.status_code != 200:
        return jsonify({
            "message": "Unable to verify affected asset"
        }), 502

    conn = get_db_connection()

    cursor = conn.execute("""
        INSERT INTO vulnerabilities (
            title,
            description,
            cve_id,
            cvss_score,
            severity_level,
            asset_id,
            discovery_source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data["title"].strip(),
        data["description"].strip(),
        data["cve_id"].upper(),
        score,
        data["severity_level"],
        asset_id,
        data["discovery_source"].strip()
    ))

    conn.commit()

    vulnerability_id = cursor.lastrowid

    vulnerability = conn.execute("""
        SELECT * FROM vulnerabilities
        WHERE vulnerability_id = ?
    """, (vulnerability_id,)).fetchone()

    conn.close()

    return jsonify({
        "message": "Vulnerability created successfully",
        "vulnerability": dict(vulnerability)
    }), 201


@app.route("/Hanaa-Ballout/vulnerabilities", methods=["GET"])
@role_required([
    "Security Administrator",
    "Security Analyst",
    "Auditor"
])
def get_all_vulnerabilities():
    """Retrieve all recorded vulnerabilities.
    Accessible to Security Administrators, Security Analysts, and Auditors.
    """
    conn = get_db_connection()

    vulnerabilities = conn.execute("""
        SELECT * FROM vulnerabilities
        ORDER BY vulnerability_id
    """).fetchall()

    conn.close()

    return jsonify({
        "count": len(vulnerabilities),
        "vulnerabilities": [
            dict(vulnerability)
            for vulnerability in vulnerabilities
        ]
    }), 200


@app.route("/Hanaa-Ballout/vulnerabilities/<int:vulnerability_id>", methods=["GET"])
@role_required([
    "Security Administrator",
    "Security Analyst",
    "Auditor"
])
def get_vulnerability(vulnerability_id):
    """Retrieve a vulnerability by its ID, or return 404 if not found.
    Accessible to Security Administrators, Security Analysts, and Auditors.
    """
    conn = get_db_connection()

    vulnerability = conn.execute("""
        SELECT * FROM vulnerabilities
        WHERE vulnerability_id = ?
    """, (vulnerability_id,)).fetchone()

    conn.close()

    if not vulnerability:
        return jsonify({
            "message": "Vulnerability not found"
        }), 404

    return jsonify({
        "vulnerability": dict(vulnerability)
    }), 200


@app.route("/Hanaa-Ballout/vulnerabilities/<int:vulnerability_id>", methods=["PUT"])
@role_required([
    "Security Administrator",
    "Security Analyst"
])
def update_vulnerability(vulnerability_id):
    """update permitted vulnerability fields and enforce status changes.
    Record the resolution timestamp when a vulnerability becomes Resolved.
    Accessible to Security Administrators and Security Analysts.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        return jsonify({
            "message": "A non-empty JSON object is required"
        }), 400

    allowed_fields = {
        "description",
        "severity_level",
        "cvss_score",
        "status"
    }

    if not set(data).issubset(allowed_fields):
        return jsonify({
            "message": "Invalid update fields"
        }), 400

    conn = get_db_connection()

    vulnerability = conn.execute("""
        SELECT * FROM vulnerabilities
        WHERE vulnerability_id = ?
    """, (vulnerability_id,)).fetchone()

    if not vulnerability:
        conn.close()
        return jsonify({
            "message": "Vulnerability not found"
        }), 404

    if "description" in data:
        if not isinstance(data["description"], str) or not data["description"].strip():
            conn.close()
            return jsonify({
                "message": "Invalid description"
            }), 400

    if "severity_level" in data:
        if data["severity_level"] not in [
            "Low", "Medium", "High", "Critical"
        ]:
            conn.close()
            return jsonify({
                "message": "Invalid severity level"
            }), 400

    if "cvss_score" in data:
        score = data["cvss_score"]

        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not 0 <= score <= 10
        ):
            conn.close()
            return jsonify({
                "message": "CVSS score must be between 0 and 10"
            }), 400

    statuses = [
        "Open",
        "Under Investigation",
        "In Progress",
        "Resolved",
        "Closed"
    ]

    resolution_date = vulnerability["resolution_date"]

    if "status" in data:
        new_status = data["status"]
        current_status = vulnerability["status"]

        if new_status not in statuses:
            conn.close()
            return jsonify({
                "message": "Invalid vulnerability status"
            }), 400

        current_index = statuses.index(current_status)

        if (
            current_index >= len(statuses) - 1
            or new_status != statuses[current_index + 1]
        ):
            conn.close()
            return jsonify({
                "message": "Invalid status transition"
            }), 400

        if new_status == "Resolved":
            resolution_date = None

    updated_description = data.get(
        "description", vulnerability["description"]
    )

    updated_severity = data.get(
        "severity_level", vulnerability["severity_level"]
    )

    updated_score = data.get(
        "cvss_score", vulnerability["cvss_score"]
    )

    updated_status = data.get(
        "status", vulnerability["status"]
    )

    if updated_status == "Resolved" and resolution_date is None:
        conn.execute("""
            UPDATE vulnerabilities
            SET description = ?,
                severity_level = ?,
                cvss_score = ?,
                status = ?,
                resolution_date = CURRENT_TIMESTAMP
            WHERE vulnerability_id = ?
        """, (
            updated_description,
            updated_severity,
            updated_score,
            updated_status,
            vulnerability_id
        ))
    else:
        conn.execute("""
            UPDATE vulnerabilities
            SET description = ?,
                severity_level = ?,
                cvss_score = ?,
                status = ?
            WHERE vulnerability_id = ?
        """, (
            updated_description,
            updated_severity,
            updated_score,
            updated_status,
            vulnerability_id
        ))

    conn.commit()

    updated = conn.execute("""
        SELECT * FROM vulnerabilities
        WHERE vulnerability_id = ?
    """, (vulnerability_id,)).fetchone()

    conn.close()

    return jsonify({
        "message": "Vulnerability updated successfully",
        "vulnerability": dict(updated)
    }), 200

@app.route("/Hanaa-Ballout/vulnerabilities/search", methods=["GET"])
@role_required([
    "Security Administrator",
    "Security Analyst",
    "Auditor"
])
def search_vulnerabilities():
    """srearchh vulnerabilities using validated CVE, severity, asset ID, or status filters.
    Accessible to Security Administrators, Security Analysts, and Auditors.
    """
    allowed_filters = {
        "cve_id",
        "severity_level",
        "asset_id",
        "status"
    }

    filters = request.args.to_dict()

    if not filters:
        return jsonify({
            "message": "At least one search parameter is required"
        }), 400

    if not set(filters).issubset(allowed_filters):
        return jsonify({
            "message": "Invalid search parameter"
        }), 400

    valid_severities = [
        "Low", "Medium", "High", "Critical"
    ]

    valid_statuses = [
        "Open",
        "Under Investigation",
        "In Progress",
        "Resolved",
        "Closed"
    ]

    if "severity_level" in filters:
        if filters["severity_level"] not in valid_severities:
            return jsonify({
                "message": "Invalid severity level"
            }), 400

    if "status" in filters:
        if filters["status"] not in valid_statuses:
            return jsonify({
                "message": "Invalid vulnerability status"
            }), 400

    if "asset_id" in filters:
        if not filters["asset_id"].isdigit() or int(filters["asset_id"]) <= 0:
            return jsonify({
                "message": "Invalid asset ID"
            }), 400

    if "cve_id" in filters:
        if not re.fullmatch(
            r"CVE-\d{4}-\d{4,}",
            filters["cve_id"],
            re.IGNORECASE
        ):
            return jsonify({
                "message": "Invalid CVE identifier"
            }), 400

    query = "SELECT * FROM vulnerabilities WHERE 1=1"
    parameters = []

    for field, value in filters.items():
        query += f" AND {field} = ?"

        if field == "asset_id":
            parameters.append(int(value))
        elif field == "cve_id":
            parameters.append(value.upper())
        else:
            parameters.append(value)

    query += " ORDER BY vulnerability_id"

    conn = get_db_connection()

    vulnerabilities = conn.execute(
        query, parameters
    ).fetchall()

    conn.close()

    return jsonify({
        "count": len(vulnerabilities),
        "vulnerabilities": [
            dict(vulnerability)
            for vulnerability in vulnerabilities
        ]
    }), 200


@app.route("/Hanaa-Ballout/vulnerabilities/<int:vulnerability_id>", methods=["DELETE"])
@role_required(["Security Administrator"])
def delete_vulnerability(vulnerability_id):
    """ddelete a vulnerability by ID, returning 404 when it does not exist.
    Accessible only to Security Administrators.
    """
    conn = get_db_connection()

    vulnerability = conn.execute("""
        SELECT * FROM vulnerabilities
        WHERE vulnerability_id = ?
    """, (vulnerability_id,)).fetchone()

    if not vulnerability:
        conn.close()
        return jsonify({
            "message": "Vulnerability not found"
        }), 404

    conn.execute("""
        DELETE FROM vulnerabilities
        WHERE vulnerability_id = ?
    """, (vulnerability_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Vulnerability deleted successfully",
        "vulnerability_id": vulnerability_id
    }), 200

if __name__ == "__main__":
    app.run(debug=True, port=5002)

