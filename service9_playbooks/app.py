from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from database import create_tables, get_connection, get_users_connection
import os
import sqlite3

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app)

create_tables()

PREFIX = "/Rawan-El-Anouti"
VALID_SEVERITIES = ["Low", "Medium", "High", "Critical"]
VALID_CATEGORIES = [
    "Malware infection",
    "Unauthorized access",
    "Phishing attack",
    "Data leakage",
    "Account compromise",
    "Denial of service attack"
]
ACTION_STATUS_FLOW = {
    "Pending": "In Progress",
    "In Progress": "Completed"
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
        SELECT user_id, role, account_status
        FROM users
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()
    connection.close()
    return dict(user) if user else None


def get_actions(connection, playbook_id):
    actions = connection.execute(
        """
        SELECT * FROM response_actions
        WHERE playbook_id = ?
        ORDER BY step_number ASC
        """,
        (playbook_id,)
    ).fetchall()
    return [dict(action) for action in actions]


def playbook_to_dict(playbook, actions=None):
    result = dict(playbook)
    if actions is not None:
        result["response_actions"] = actions
    return result


@app.route("/", methods=["GET"])
def home():
    return ok({
        "message": "Security Playbook and Response Automation Service is running",
        "student": "Rawan El Anouti"
    })


@app.route(f"{PREFIX}/playbooks", methods=["POST"])
@jwt_required()
def create_playbook():
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] != "Security Administrator":
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    required_fields = ["playbook_name", "description", "incident_category", "severity"]
    for field in required_fields:
        if not isinstance(data.get(field), str) or not data[field].strip():
            return error(f"{field} is required", 400)

    name = data["playbook_name"].strip()
    description = data["description"].strip()
    category = data["incident_category"].strip()
    severity = data["severity"].strip()

    if category not in VALID_CATEGORIES:
        return error(
            "Invalid incident_category. Allowed values: " + ", ".join(VALID_CATEGORIES),
            400
        )
    if severity not in VALID_SEVERITIES:
        return error("Invalid severity. Allowed values: Low, Medium, High, Critical", 400)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO playbooks (
            playbook_name, description, incident_category, severity, created_by
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (name, description, category, severity, current_user["user_id"])
    )
    connection.commit()
    playbook = cursor.execute(
        "SELECT * FROM playbooks WHERE playbook_id = ?",
        (cursor.lastrowid,)
    ).fetchone()
    connection.close()

    return ok({
        "message": "Playbook created successfully",
        "playbook": playbook_to_dict(playbook, actions=[])
    }, 201)


@app.route(f"{PREFIX}/playbooks", methods=["GET"])
@jwt_required()
def get_all_playbooks():
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Security Analyst", "Auditor"]:
        return error("User does not have permission to perform this operation", 403)

    connection = get_connection()
    playbooks = connection.execute(
        "SELECT * FROM playbooks ORDER BY creation_date DESC"
    ).fetchall()
    connection.close()

    return ok({
        "playbooks": [playbook_to_dict(playbook) for playbook in playbooks]
    })


@app.route(f"{PREFIX}/playbooks/<int:playbook_id>", methods=["GET"])
@jwt_required()
def get_playbook(playbook_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Security Analyst", "Auditor"]:
        return error("User does not have permission to perform this operation", 403)

    connection = get_connection()
    playbook = connection.execute(
        "SELECT * FROM playbooks WHERE playbook_id = ?",
        (playbook_id,)
    ).fetchone()

    if not playbook:
        connection.close()
        return error("Playbook not found", 404)

    actions = get_actions(connection, playbook_id)
    connection.close()

    return ok({"playbook": playbook_to_dict(playbook, actions)})


@app.route(f"{PREFIX}/playbooks/<int:playbook_id>/actions", methods=["POST"])
@jwt_required()
def add_response_action(playbook_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Security Analyst"]:
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    description = data.get("action_description", data.get("description"))
    if not isinstance(description, str) or not description.strip():
        return error("action_description is required", 400)

    try:
        step_number = int(data["step_number"])
        if step_number <= 0:
            raise ValueError
    except (TypeError, ValueError, KeyError):
        return error("step_number is required and must be a positive integer", 400)

    assigned_user_id = data.get("assigned_user_id")
    if assigned_user_id is not None:
        try:
            assigned_user_id = int(assigned_user_id)
        except (TypeError, ValueError):
            return error("assigned_user_id must be a valid user ID", 400)
        assigned_user = get_user_by_id(assigned_user_id)
        if not assigned_user:
            return error("Assigned user not found", 404)

    connection = get_connection()
    cursor = connection.cursor()
    playbook = cursor.execute(
        "SELECT * FROM playbooks WHERE playbook_id = ?",
        (playbook_id,)
    ).fetchone()

    if not playbook:
        connection.close()
        return error("Playbook not found", 404)

    try:
        cursor.execute(
            """
            INSERT INTO response_actions (
                playbook_id, action_description, step_number, assigned_user_id
            )
            VALUES (?, ?, ?, ?)
            """,
            (playbook_id, description.strip(), step_number, assigned_user_id)
        )
        connection.commit()
    except sqlite3.IntegrityError:
        connection.close()
        return error("step_number must be unique inside the same playbook", 409)

    playbook = cursor.execute(
        "SELECT * FROM playbooks WHERE playbook_id = ?",
        (playbook_id,)
    ).fetchone()
    actions = get_actions(connection, playbook_id)
    connection.close()

    return ok({
        "message": "Response action added successfully",
        "playbook": playbook_to_dict(playbook, actions)
    }, 201)


@app.route(f"{PREFIX}/actions/<int:action_id>/status", methods=["PUT"])
@jwt_required()
def update_action_status(action_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] not in ["Security Administrator", "Security Analyst"]:
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    connection = get_connection()
    cursor = connection.cursor()
    action = cursor.execute(
        "SELECT * FROM response_actions WHERE action_id = ?",
        (action_id,)
    ).fetchone()

    if not action:
        connection.close()
        return error("Response action not found", 404)

    new_status = data.get("status", action["status"])
    if not isinstance(new_status, str) or not new_status.strip():
        connection.close()
        return error("status is required", 400)
    new_status = new_status.strip()

    assigned_user_id = action["assigned_user_id"]
    if "assigned_user_id" in data and data["assigned_user_id"] is not None:
        try:
            assigned_user_id = int(data["assigned_user_id"])
        except (TypeError, ValueError):
            connection.close()
            return error("assigned_user_id must be a valid user ID", 400)
        assigned_user = get_user_by_id(assigned_user_id)
        if not assigned_user:
            connection.close()
            return error("Assigned user not found", 404)

    if new_status != action["status"]:
        expected = ACTION_STATUS_FLOW.get(action["status"])
        if new_status != expected:
            connection.close()
            if action["status"] == "Completed":
                return error("Completed actions cannot change status", 400)
            return error(
                f"Invalid action status transition. {action['status']} can only move to {expected}",
                400
            )

        if new_status == "In Progress":
            previous = cursor.execute(
                """
                SELECT * FROM response_actions
                WHERE playbook_id = ? AND step_number < ?
                ORDER BY step_number DESC
                LIMIT 1
                """,
                (action["playbook_id"], action["step_number"])
            ).fetchone()
            if previous and previous["status"] != "Completed":
                connection.close()
                return error(
                    "Actions must be executed in order. Complete the previous step first.",
                    400
                )

    completion_date = action["completion_date"]
    if new_status == "Completed":
        completion_date = cursor.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]

    cursor.execute(
        """
        UPDATE response_actions
        SET status = ?, assigned_user_id = ?, completion_date = ?
        WHERE action_id = ?
        """,
        (new_status, assigned_user_id, completion_date, action_id)
    )
    connection.commit()
    updated = cursor.execute(
        "SELECT * FROM response_actions WHERE action_id = ?",
        (action_id,)
    ).fetchone()
    connection.close()

    return ok({
        "message": "Response action updated successfully",
        "action": dict(updated)
    })


@app.route(f"{PREFIX}/playbooks/<int:playbook_id>", methods=["DELETE"])
@jwt_required()
def delete_playbook(playbook_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] != "Security Administrator":
        return error("User does not have permission to perform this operation", 403)

    connection = get_connection()
    cursor = connection.cursor()
    playbook = cursor.execute(
        "SELECT * FROM playbooks WHERE playbook_id = ?",
        (playbook_id,)
    ).fetchone()

    if not playbook:
        connection.close()
        return error("Playbook not found", 404)

    cursor.execute(
        "DELETE FROM playbooks WHERE playbook_id = ?",
        (playbook_id,)
    )
    connection.commit()
    connection.close()

    return ok({
        "message": "Playbook deleted successfully",
        "playbook_id": playbook_id
    })


if __name__ == "__main__":
    app.run(debug=True, port=5009)
