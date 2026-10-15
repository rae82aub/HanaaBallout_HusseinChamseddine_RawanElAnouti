from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from database import create_tables, get_connection, get_users_connection
import os
import requests

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app)

create_tables()

PREFIX = "/Rawan-El-Anouti"
NOTIFICATION_SERVICE_URL = os.environ.get(
    "NOTIFICATION_SERVICE_URL",
    "http://127.0.0.1:5008"
)

VALID_SEVERITIES = ["Low", "Medium", "High", "Critical"]
VALID_CATEGORIES = [
    "Malware infection",
    "Unauthorized access",
    "Phishing attack",
    "Data leakage",
    "Account compromise",
    "Denial of service attack"
]
STATUS_FLOW = {
    "Open": "Under Investigation",
    "Under Investigation": "Mitigated",
    "Mitigated": "Resolved",
    "Resolved": "Closed"
}


def error(message, code):
    return jsonify({
        "status": "error",
        "message": message,
        "implemented_by": "Rawan El Anouti"
    }), code


def ok(payload, code=200):
    if isinstance(payload, dict):
        payload = {
            "status": "success",
            "implemented_by": "Rawan El Anouti",
            **payload
        }
    return jsonify(payload), code


def get_active_user():
    current_user_id = int(get_jwt_identity())
    connection = get_users_connection()
    user = connection.execute(
        """
        SELECT user_id, full_name, username, role, account_status
        FROM users
        WHERE user_id = ?
        """,
        (current_user_id,)
    ).fetchone()
    connection.close()

    if not user or user["account_status"] != "Active":
        return None, error("Account not active or not found", 403)

    return dict(user), None


def get_user_by_id(user_id):
    connection = get_users_connection()
    user = connection.execute(
        """
        SELECT user_id, full_name, username, role, account_status
        FROM users
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()
    connection.close()
    return dict(user) if user else None


def incident_to_dict(incident, notes=None):
    result = {
        "incident_id": incident["incident_id"],
        "title": incident["title"],
        "description": incident["description"],
        "category": incident["category"],
        "severity": incident["severity"],
        "reporter_id": incident["reporter_id"],
        "affected_asset_id": incident["asset_id"],
        "assigned_analyst_id": incident["assigned_analyst_id"],
        "status": incident["status"],
        "creation_date": incident["creation_date"],
        "resolution_date": incident["resolution_date"]
    }
    if notes is not None:
        result["investigation_notes"] = notes
    return result


def get_notes_for_incident(connection, incident_id):
    notes = connection.execute(
        """
        SELECT note_id, incident_id, analyst_id, note_content, creation_timestamp
        FROM investigation_notes
        WHERE incident_id = ?
        ORDER BY creation_timestamp ASC
        """,
        (incident_id,)
    ).fetchall()
    return [dict(note) for note in notes]


def notify_analyst_assignment(analyst_id, incident_id, title):
    authorization = request.headers.get("Authorization")
    if not authorization:
        return

    try:
        requests.post(
            f"{NOTIFICATION_SERVICE_URL}{PREFIX}/notifications",
            json={
                "user_id": analyst_id,
                "title": "Incident Assignment",
                "message": f"Incident {incident_id} ({title}) was assigned to you.",
                "notification_type": "Incident Assignment",
                "severity": "High"
            },
            headers={"Authorization": authorization},
            timeout=3
        )
    except requests.RequestException:
        pass


@app.route("/", methods=["GET"])
def home():
    return ok({
        "message": "Incident Management Service is running",
        "student": "Rawan El Anouti"
    })


@app.route(f"{PREFIX}/incidents", methods=["POST"])
@jwt_required()
def create_incident():
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Regular Employee"]:
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    required_fields = ["title", "description", "category", "severity", "affected_asset"]
    for field in required_fields:
        if data.get(field) is None or (isinstance(data.get(field), str) and not data[field].strip()):
            return error(f"{field} is required", 400)

    title = str(data["title"]).strip()
    description = str(data["description"]).strip()
    category = str(data["category"]).strip()
    severity = str(data["severity"]).strip()

    try:
        asset_id = int(data["affected_asset"])
        if asset_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return error("affected_asset must be a positive integer asset ID", 400)

    if category not in VALID_CATEGORIES:
        return error(
            "Invalid category. Allowed values: " + ", ".join(VALID_CATEGORIES),
            400
        )

    if severity not in VALID_SEVERITIES:
        return error("Invalid severity. Allowed values: Low, Medium, High, Critical", 400)

    reporter_id = current_user["user_id"]
    if current_user["role"] == "Security Administrator" and data.get("reporter") is not None:
        try:
            reporter_id = int(data["reporter"])
        except (TypeError, ValueError):
            return error("reporter must be a valid user ID", 400)
        reporter = get_user_by_id(reporter_id)
        if not reporter:
            return error("Reporter user not found", 404)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO incidents (
            title, description, category, severity, reporter_id, asset_id, status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'Open')
        """,
        (title, description, category, severity, reporter_id, asset_id)
    )
    connection.commit()
    incident_id = cursor.lastrowid
    incident = cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()
    connection.close()

    return ok({
        "message": "Incident created successfully",
        "incident": incident_to_dict(incident, notes=[])
    }, 201)


@app.route(f"{PREFIX}/incidents", methods=["GET"])
@jwt_required()
def get_all_incidents():
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Auditor"]:
        return error("User does not have permission to perform this operation", 403)

    connection = get_connection()
    incidents = connection.execute(
        """
        SELECT * FROM incidents
        ORDER BY creation_date DESC
        """
    ).fetchall()
    connection.close()

    return ok({
        "incidents": [incident_to_dict(incident) for incident in incidents]
    })


@app.route(f"{PREFIX}/incidents/<int:incident_id>", methods=["GET"])
@jwt_required()
def get_incident(incident_id):
    current_user, err = get_active_user()
    if err:
        return err

    connection = get_connection()
    incident = connection.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()

    if not incident:
        connection.close()
        return error("Incident not found", 404)

    if current_user["role"] == "Regular Employee":
        if incident["reporter_id"] != current_user["user_id"]:
            connection.close()
            return error("User does not have permission to perform this operation", 403)

    notes = get_notes_for_incident(connection, incident_id)
    connection.close()

    return ok({"incident": incident_to_dict(incident, notes)})


@app.route(f"{PREFIX}/incidents/<int:incident_id>/assign", methods=["PUT"])
@jwt_required()
def assign_incident(incident_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] != "Security Administrator":
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    analyst_id = data.get("analyst_id", data.get("assigned_analyst_id"))
    try:
        analyst_id = int(analyst_id)
    except (TypeError, ValueError):
        return error("analyst_id is required and must be a valid user ID", 400)

    analyst = get_user_by_id(analyst_id)
    if not analyst:
        return error("Assigned user not found", 404)
    if analyst["role"] != "Security Analyst":
        return error("The assigned user must have the Security Analyst role", 400)
    if analyst["account_status"] != "Active":
        return error("The assigned analyst account is not active", 400)

    connection = get_connection()
    cursor = connection.cursor()
    incident = cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()

    if not incident:
        connection.close()
        return error("Incident not found", 404)

    cursor.execute(
        """
        UPDATE incidents
        SET assigned_analyst_id = ?
        WHERE incident_id = ?
        """,
        (analyst_id, incident_id)
    )
    connection.commit()
    updated = cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()
    notes = get_notes_for_incident(connection, incident_id)
    connection.close()

    notify_analyst_assignment(analyst_id, incident_id, updated["title"])

    return ok({
        "message": "Incident assigned successfully",
        "incident": incident_to_dict(updated, notes)
    })


@app.route(f"{PREFIX}/incidents/<int:incident_id>/status", methods=["PUT"])
@jwt_required()
def update_incident_status(incident_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Security Analyst"]:
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("status"), str):
        return error("status is required", 400)

    new_status = data["status"].strip()
    connection = get_connection()
    cursor = connection.cursor()
    incident = cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()

    if not incident:
        connection.close()
        return error("Incident not found", 404)

    current_status = incident["status"]
    if current_status == "Closed":
        connection.close()
        return error("Closed incidents cannot change status", 400)

    expected = STATUS_FLOW.get(current_status)
    if new_status != expected:
        connection.close()
        return error(
            f"Invalid status transition. {current_status} can only move to {expected}",
            400
        )

    resolution_date = incident["resolution_date"]
    if new_status in ["Resolved", "Closed"]:
        resolution_date = cursor.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]

    cursor.execute(
        """
        UPDATE incidents
        SET status = ?, resolution_date = ?
        WHERE incident_id = ?
        """,
        (new_status, resolution_date, incident_id)
    )
    connection.commit()
    updated = cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()
    notes = get_notes_for_incident(connection, incident_id)
    connection.close()

    return ok({
        "message": "Incident status updated successfully",
        "incident": incident_to_dict(updated, notes)
    })


@app.route(f"{PREFIX}/incidents/<int:incident_id>/notes", methods=["POST"])
@jwt_required()
def add_investigation_note(incident_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Security Analyst"]:
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    note_content = data.get("note_content", data.get("content"))
    if not isinstance(note_content, str) or not note_content.strip():
        return error("note_content is required", 400)

    connection = get_connection()
    cursor = connection.cursor()
    incident = cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()

    if not incident:
        connection.close()
        return error("Incident not found", 404)

    cursor.execute(
        """
        INSERT INTO investigation_notes (incident_id, analyst_id, note_content)
        VALUES (?, ?, ?)
        """,
        (incident_id, current_user["user_id"], note_content.strip())
    )
    connection.commit()
    notes = get_notes_for_incident(connection, incident_id)
    updated = cursor.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()
    connection.close()

    return ok({
        "message": "Investigation note added successfully",
        "incident": incident_to_dict(updated, notes)
    }, 201)


if __name__ == "__main__":
    app.run(debug=True, port=5003)
