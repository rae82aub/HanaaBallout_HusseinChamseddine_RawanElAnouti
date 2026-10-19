from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from database import create_tables, get_connection, get_users_connection
import os
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from common import write_audit_log


app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app)

create_tables()

PREFIX = "/Rawan-El-Anouti"
VALID_TYPES = [
    "Incident Assignment",
    "Security Alert",
    "System Notification",
    "Threat Alert",
    "Vulnerability Alert"
]
VALID_SEVERITIES = ["Low", "Medium", "High", "Critical"]
VALID_STATUSES = ["Unread", "Read"]


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


def user_exists(user_id):
    connection = get_users_connection()
    user = connection.execute(
        "SELECT user_id FROM users WHERE user_id = ?",
        (user_id,)
    ).fetchone()
    connection.close()
    return user is not None


def notification_to_dict(row):
    return dict(row)


def can_view_user_notifications(current_user, target_user_id):
    if current_user["role"] in ["Security Administrator", "Auditor"]:
        return True
    return current_user["user_id"] == target_user_id


@app.route("/", methods=["GET"])
def home():
    return ok({
        "message": "Notification and Alert Management Service is running",
        "student": "Rawan El Anouti"
    })


@app.route(f"{PREFIX}/notifications", methods=["POST"])
@jwt_required()
def create_notification():
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] != "Security Administrator":
        return error("User does not have permission to perform this operation", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    required_fields = ["user_id", "title", "message", "notification_type", "severity"]
    for field in required_fields:
        if data.get(field) is None or (isinstance(data.get(field), str) and not str(data[field]).strip()):
            return error(f"{field} is required", 400)

    try:
        user_id = int(data["user_id"])
    except (TypeError, ValueError):
        return error("user_id must be a valid user ID", 400)

    if not user_exists(user_id):
        return error("User not found", 404)

    title = str(data["title"]).strip()
    message = str(data["message"]).strip()
    notification_type = str(data["notification_type"]).strip()
    severity = str(data["severity"]).strip()

    if notification_type not in VALID_TYPES:
        return error(
            "Invalid notification_type. Allowed values: " + ", ".join(VALID_TYPES),
            400
        )
    if severity not in VALID_SEVERITIES:
        return error("Invalid severity. Allowed values: Low, Medium, High, Critical", 400)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO notifications (
            user_id, title, message, notification_type, severity, status
        )
        VALUES (?, ?, ?, ?, ?, 'Unread')
        """,
        (user_id, title, message, notification_type, severity)
    )
    connection.commit()
    notification = cursor.execute(
        "SELECT * FROM notifications WHERE notification_id = ?",
        (cursor.lastrowid,)
    ).fetchone()
    connection.close()

    write_audit_log(
        user_id=current_user["user_id"],
        action="Notification creation",
        description=f"Created notification {notification['notification_id']} for user {user_id}",
        severity="Information",
        related_service="Notification and Alert Management"
    )

    return ok({
        "message": "Notification created successfully",
        "notification": notification_to_dict(notification)
    }, 201)


@app.route(f"{PREFIX}/notifications/user/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user_notifications(user_id):
    current_user, err = get_active_user()
    if err:
        return err

    if not can_view_user_notifications(current_user, user_id):
        return error("User does not have permission to perform this operation", 403)

    if current_user["role"] in ["Security Administrator", "Auditor"]:
        if not user_exists(user_id):
            return error("User not found", 404)

    connection = get_connection()
    notifications = connection.execute(
        """
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY creation_date DESC
        """,
        (user_id,)
    ).fetchall()
    connection.close()

    return ok({
        "user_id": user_id,
        "count": len(notifications),
        "notifications": [notification_to_dict(item) for item in notifications]
    })


@app.route(f"{PREFIX}/notifications/search", methods=["GET"])
@jwt_required()
def search_notifications():
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] == "Regular Employee":
        return error("User does not have permission to perform this operation", 403)

    user_id = request.args.get("user") or request.args.get("user_id")
    notification_type = request.args.get("notification_type") or request.args.get("type")
    severity = request.args.get("severity")
    status = request.args.get("status")

    query = "SELECT * FROM notifications WHERE 1=1"
    params = []

    if current_user["role"] == "Security Analyst":
        query += " AND user_id = ?"
        params.append(current_user["user_id"])
    elif user_id:
        try:
            query += " AND user_id = ?"
            params.append(int(user_id))
        except ValueError:
            return error("user must be a valid user ID", 400)

    if notification_type:
        if notification_type not in VALID_TYPES:
            return error("Invalid notification_type", 400)
        query += " AND notification_type = ?"
        params.append(notification_type)

    if severity:
        if severity not in VALID_SEVERITIES:
            return error("Invalid severity", 400)
        query += " AND severity = ?"
        params.append(severity)

    if status:
        if status not in VALID_STATUSES:
            return error("Invalid status. Allowed values: Unread, Read", 400)
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY creation_date DESC"

    connection = get_connection()
    notifications = connection.execute(query, params).fetchall()
    connection.close()

    return ok({
        "filters": {
            "user_id": int(user_id) if user_id and current_user["role"] != "Security Analyst" else (
                current_user["user_id"] if current_user["role"] == "Security Analyst" else None
            ),
            "notification_type": notification_type,
            "severity": severity,
            "status": status
        },
        "count": len(notifications),
        "notifications": [notification_to_dict(item) for item in notifications]
    })


@app.route(f"{PREFIX}/notifications/<int:notification_id>", methods=["GET"])
@jwt_required()
def get_notification(notification_id):
    current_user, err = get_active_user()
    if err:
        return err

    connection = get_connection()
    notification = connection.execute(
        "SELECT * FROM notifications WHERE notification_id = ?",
        (notification_id,)
    ).fetchone()
    connection.close()

    if not notification:
        return error("Notification not found", 404)

    if not can_view_user_notifications(current_user, notification["user_id"]):
        return error("User does not have permission to perform this operation", 403)

    return ok({"notification": notification_to_dict(notification)})


@app.route(f"{PREFIX}/notifications/<int:notification_id>/read", methods=["PUT"])
@jwt_required()
def mark_notification_read(notification_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] == "Auditor":
        return error("User does not have permission to perform this operation", 403)

    connection = get_connection()
    cursor = connection.cursor()
    notification = cursor.execute(
        "SELECT * FROM notifications WHERE notification_id = ?",
        (notification_id,)
    ).fetchone()

    if not notification:
        connection.close()
        return error("Notification not found", 404)

    if current_user["role"] != "Security Administrator":
        if notification["user_id"] != current_user["user_id"]:
            connection.close()
            return error("User does not have permission to perform this operation", 403)

    if notification["status"] == "Read":
        connection.close()
        return ok({
            "message": "Notification is already marked as read",
            "notification": notification_to_dict(notification)
        })

    cursor.execute(
        """
        UPDATE notifications
        SET status = 'Read', read_date = CURRENT_TIMESTAMP
        WHERE notification_id = ?
        """,
        (notification_id,)
    )
    connection.commit()
    updated = cursor.execute(
        "SELECT * FROM notifications WHERE notification_id = ?",
        (notification_id,)
    ).fetchone()
    connection.close()

    write_audit_log(
    user_id=current_user["user_id"],
    action="Notification marked as read",
    description=f"Marked notification {notification_id} as read",
    severity="Information",
    related_service="Notification and Alert Management"
)


    return ok({
        "message": "Notification marked as read",
        "notification": notification_to_dict(updated)
    })



@app.route(f"{PREFIX}/notifications/<int:notification_id>", methods=["DELETE"])
@jwt_required()
def delete_notification(notification_id):
    current_user, err = get_active_user()
    if err:
        return err

    if current_user["role"] != "Security Administrator":
        return error("User does not have permission to perform this operation", 403)

    connection = get_connection()
    cursor = connection.cursor()
    notification = cursor.execute(
        "SELECT * FROM notifications WHERE notification_id = ?",
        (notification_id,)
    ).fetchone()

    if not notification:
        connection.close()
        return error("Notification not found", 404)

    cursor.execute(
        "DELETE FROM notifications WHERE notification_id = ?",
        (notification_id,)
    )
    connection.commit()
    connection.close()
    write_audit_log(
    user_id=current_user["user_id"],
    action="Notification deletion",
    description=f"Deleted notification {notification_id}",
    severity="Warning",
    related_service="Notification and Alert Management"
)


    return ok({
        "message": "Notification deleted successfully",
        "notification_id": notification_id
    })


if __name__ == "__main__":
    app.run(debug=True, port=5008)
