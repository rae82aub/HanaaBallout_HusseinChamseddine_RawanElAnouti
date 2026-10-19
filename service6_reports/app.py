import os
import sys
from collections import Counter
from pathlib import Path

import requests
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_DIR))

from common import (
    ASSETS_DB,
    INCIDENTS_DB,
    PREFIX,
    THREATS_DB,
    VULNERABILITIES_DB,
    connect_sqlite,
    role_required,
    users_db_path,
)

load_dotenv(PROJECT_DIR / ".env")

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY is missing from .env")

jwt = JWTManager(app)

SERVICE_NAME = "Security Reports"
REPORT_ROLES = ["Security Administrator", "Auditor"]
OPEN_INCIDENT_STATUSES = ["Open", "Under Investigation", "Mitigated"]

USERS_API = os.environ.get(
    "USERS_API",
    "http://127.0.0.1:5000/Hanaa-Ballout/users"
)
ASSETS_API = os.environ.get(
    "ASSETS_API",
    "http://127.0.0.1:5001/Hanaa-Ballout/assets"
)
INCIDENTS_API = os.environ.get(
    "INCIDENTS_API",
    "http://127.0.0.1:5003/Rawan-El-Anouti/incidents"
)
VULNERABILITIES_API = os.environ.get(
    "VULNERABILITIES_API",
    "http://127.0.0.1:5002/Hanaa-Ballout/vulnerabilities"
)


def auth_headers():
    return {"Authorization": request.headers.get("Authorization", "")}


def fetch_api_list(url, list_key=None):
    """Collect a list of records from a teammate service API."""
    try:
        response = requests.get(url, headers=auth_headers(), timeout=5)
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    payload = response.json()
    if isinstance(payload, list):
        return payload
    if list_key and isinstance(payload, dict) and list_key in payload:
        return payload[list_key]
    return None


def read_table(db_path, query):
    """Read rows from a teammate SQLite database when the API is unavailable."""
    if not Path(db_path).exists():
        return []
    connection = connect_sqlite(db_path)
    rows = [dict(row) for row in connection.execute(query).fetchall()]
    connection.close()
    return rows


def collect_users():
    records = fetch_api_list(USERS_API)
    if records is not None:
        return records
    return read_table(users_db_path(), "SELECT * FROM users")


def collect_assets():
    records = fetch_api_list(ASSETS_API, "assets")
    if records is not None:
        return records
    return read_table(ASSETS_DB, "SELECT * FROM assets")


def collect_incidents():
    records = fetch_api_list(INCIDENTS_API, "incidents")
    if records is not None:
        return records
    return read_table(INCIDENTS_DB, "SELECT * FROM incidents")


def collect_vulnerabilities():
    records = fetch_api_list(VULNERABILITIES_API, "vulnerabilities")
    if records is not None:
        return records
    return read_table(VULNERABILITIES_DB, "SELECT * FROM vulnerabilities")


def collect_threats():
    return read_table(THREATS_DB, "SELECT * FROM threats ORDER BY threat_id")


def collect_logs():
    logs_db = PROJECT_DIR / "service5_logs" / "database.db"
    return read_table(logs_db, "SELECT * FROM logs ORDER BY log_id")


def group_counts(records, field):
    counts = {}
    for record in records:
        key = record.get(field, "Unknown")
        counts[str(key)] = counts.get(str(key), 0) + 1
    return counts


@app.route("/", methods=["GET"])
def home():
    """Return a confirmation that the Security Reports Service is running."""
    return jsonify({
        "message": "Security Reports Service is running"
    })


@app.route(f"{PREFIX}/reports/summary", methods=["GET"])
@role_required(REPORT_ROLES, SERVICE_NAME)
def security_summary():
    """Return an overview of users, assets, open incidents, and critical threats."""
    users = collect_users()
    assets = collect_assets()
    incidents = collect_incidents()
    threats = collect_threats()

    open_incidents = [
        incident for incident in incidents
        if incident.get("status") in OPEN_INCIDENT_STATUSES
    ]
    critical_threats = [
        threat for threat in threats
        if threat.get("severity") == "Critical"
    ]

    return jsonify({
        "message": "Security summary generated successfully",
        "report": {
            "users": len(users),
            "assets": len(assets),
            "open_incidents": len(open_incidents),
            "critical_threats": len(critical_threats)
        }
    }), 200


@app.route(f"{PREFIX}/reports/incidents", methods=["GET"])
@role_required(REPORT_ROLES, SERVICE_NAME)
def incident_report():
    """Return incident totals grouped by severity and status."""
    incidents = collect_incidents()

    return jsonify({
        "message": "Incident report generated successfully",
        "report": {
            "total_incidents": len(incidents),
            "incidents_by_severity": group_counts(incidents, "severity"),
            "incidents_by_status": group_counts(incidents, "status")
        }
    }), 200


@app.route(f"{PREFIX}/reports/assets", methods=["GET"])
@role_required(REPORT_ROLES, SERVICE_NAME)
def asset_report():
    """Return asset totals, critical assets, and grouping by type."""
    assets = collect_assets()
    critical_assets = [
        asset for asset in assets
        if asset.get("criticality_level") == "Critical"
    ]

    return jsonify({
        "message": "Asset report generated successfully",
        "report": {
            "total_assets": len(assets),
            "critical_assets": len(critical_assets),
            "assets_by_type": group_counts(assets, "asset_type"),
            "assets_by_criticality": group_counts(assets, "criticality_level")
        }
    }), 200


@app.route(f"{PREFIX}/reports/threats", methods=["GET"])
@role_required(REPORT_ROLES, SERVICE_NAME)
def threat_report():
    """Return threat totals grouped by severity and type, plus recent threats."""
    threats = collect_threats()
    recent_threats = sorted(
        threats,
        key=lambda item: item.get("date_added") or "",
        reverse=True
    )[:5]

    return jsonify({
        "message": "Threat report generated successfully",
        "report": {
            "total_threats": len(threats),
            "threats_by_severity": group_counts(threats, "severity"),
            "threats_by_type": group_counts(threats, "threat_type"),
            "recent_threats": recent_threats
        }
    }), 200


@app.route(f"{PREFIX}/reports/vulnerabilities", methods=["GET"])
@role_required(REPORT_ROLES, SERVICE_NAME)
def vulnerability_report():
    """Return vulnerability totals grouped by severity and status."""
    vulnerabilities = collect_vulnerabilities()
    critical_vulnerabilities = [
        item for item in vulnerabilities
        if item.get("severity_level") == "Critical"
    ]

    return jsonify({
        "message": "Vulnerability report generated successfully",
        "report": {
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities_by_severity": group_counts(
                vulnerabilities, "severity_level"
            ),
            "vulnerabilities_by_status": group_counts(vulnerabilities, "status"),
            "critical_vulnerabilities": len(critical_vulnerabilities)
        }
    }), 200


@app.route(f"{PREFIX}/reports/activity", methods=["GET"])
@role_required(REPORT_ROLES, SERVICE_NAME)
def activity_report():
    """Return security activity statistics generated from audit logs."""
    logs = collect_logs()
    actions = [str(log.get("action", "")) for log in logs]
    action_counts = Counter(actions)
    most_performed = [
        {"action": action, "count": count}
        for action, count in action_counts.most_common(5)
    ]

    login_attempts = [
        log for log in logs
        if "login" in str(log.get("action", "")).lower()
    ]
    failed_logins = [
        log for log in logs
        if "fail" in str(log.get("action", "")).lower()
        and "login" in str(log.get("action", "")).lower()
    ]

    return jsonify({
        "message": "Activity report generated successfully",
        "report": {
            "total_user_activities": len(logs),
            "login_attempts": len(login_attempts),
            "failed_login_attempts": len(failed_logins),
            "most_performed_actions": most_performed
        }
    }), 200


if __name__ == "__main__":
    app.run(debug=True, port=5006)
