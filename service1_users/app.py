from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request
)
from database import create_tables, get_connection
import re
import sqlite3
import os
from dotenv import load_dotenv
from pathlib import Path

app = Flask(__name__)

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app)

create_tables()


@app.route("/", methods=["GET"])
def home():
    """Return a status message confirming that the service is running."""
    return jsonify({
        "message": "Users and Identity Management Service is running"
    })


@app.route("/Hanaa-Ballout/users/register", methods=["POST"])
def register_user():
    """Register a user after validating their details and password.
    Public registration is restricted to Regular Employees; active
    Security Administrators can assign any supported role."""
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    required_fields = [
        "full_name", "username", "email",
        "password", "department", "role"
    ]

    for field in required_fields:
        if not isinstance(data.get(field), str) or not data[field].strip():
            return jsonify({"message": f"{field} is required"}), 400

    valid_roles = [
        "Security Administrator",
        "Security Analyst",
        "Regular Employee",
        "Auditor"
    ]

    role = data["role"]

    if role not in valid_roles:
        return jsonify({"message": "Invalid role"}), 400

    verify_jwt_in_request(optional=True)
    current_user_id = get_jwt_identity()

    if current_user_id is None:
        if role != "Regular Employee":
            return jsonify({
                "message": "Only a Security Administrator can assign this role"
            }), 403
    else:
        connection = get_connection()
        current_user = connection.execute(
            "SELECT role, account_status FROM users WHERE user_id = ?",
            (current_user_id,)
        ).fetchone()
        connection.close()

        if not current_user or current_user["account_status"] != "Active":
            return jsonify({"message": "Account not active or not found"}), 403

        if current_user["role"] == "Security Administrator":
            pass
        elif current_user["role"] == "Regular Employee":
            if role != "Regular Employee":
                return jsonify({
                    "message": "Permission denied"
                }), 403
        else:
            return jsonify({"message": "Permission denied"}), 403

    email = data["email"].strip().lower()
    username = data["username"].strip()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"message": "Invalid email format"}), 400

    if len(data["password"]) < 8:
        return jsonify({
            "message": "Password must contain at least 8 characters"
        }), 400

    password_hash = generate_password_hash(data["password"])

    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO users
            (full_name, username, email, password_hash, department, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data["full_name"].strip(),
            username,
            email,
            password_hash,
            data["department"].strip(),
            role
        ))

        connection.commit()

        return jsonify({
            "message": "User registered successfully",
            "user_id": cursor.lastrowid
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "message": "Username or email already exists"
        }), 409

    finally:
        connection.close()

@app.route("/Hanaa-Ballout/users/login", methods=["POST"])
def login_user():
    """authenticate a user by username or email and password.
    Only active accounts can log in; successful login updates the
    last-login timestamp and returns a JWT access token."""
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "A JSON object is required"}), 400

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not isinstance(password, str) or not password:
        return jsonify({
            "message": "Username/email and password are required"
        }), 400

    if not (
        isinstance(username, str) and username.strip()
        or isinstance(email, str) and email.strip()
    ):
        return jsonify({
            "message": "Username/email and password are required"
        }), 400

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM users
        WHERE username = ? OR email = ?
    """, (username, email))

    user = cursor.fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        connection.close()
        return jsonify({"message": "Invalid credentials"}), 401

    if user["account_status"] != "Active":
        connection.close()
        return jsonify({"message": "Account is not active"}), 403

    cursor.execute("""
        UPDATE users
        SET last_login_date = CURRENT_TIMESTAMP
        WHERE user_id = ?
    """, (user["user_id"],))

    connection.commit()

    access_token = create_access_token(
        identity=str(user["user_id"])
    )

    connection.close()

    return jsonify({
        "message": "Login successful",
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "access_token": access_token
    }), 200


@app.route("/Hanaa-Ballout/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    """update a user's name, email, or department.
    Active Security Administrators can update any user, while active
    Regular Employees can update only their own information."""
    current_user_id = int(get_jwt_identity())

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE user_id = ?",
        (current_user_id,)
    )
    current_user = cursor.fetchone()

    if not current_user or current_user["account_status"] != "Active":
        connection.close()
        return jsonify({"message": "Account not active or not found"}), 403

    if current_user["role"] != "Security Administrator":
        if current_user["role"] != "Regular Employee" or current_user_id != user_id:
            connection.close()
            return jsonify({"message": "Permission denied"}), 403

    cursor.execute(
        "SELECT * FROM users WHERE user_id = ?",
        (user_id,)
    )
    user = cursor.fetchone()

    if not user:
        connection.close()
        return jsonify({"message": "User not found"}), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        connection.close()
        return jsonify({"message": "A JSON object is required"}), 400

    full_name = data.get("full_name", user["full_name"])
    email = data.get("email", user["email"])
    department = data.get("department", user["department"])

    if not all(
        isinstance(value, str) and value.strip()
        for value in [full_name, email, department]
    ):
        connection.close()
        return jsonify({"message": "Fields cannot be empty"}), 400

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
        connection.close()
        return jsonify({"message": "Invalid email format"}), 400

    try:
        cursor.execute("""
            UPDATE users
            SET full_name = ?, email = ?, department = ?
            WHERE user_id = ?
        """, (
            full_name.strip(),
            email.strip().lower(),
            department.strip(),
            user_id
        ))

        connection.commit()

        return jsonify({
            "message": "User updated successfully",
            "user_id": user_id
        }), 200

    except sqlite3.IntegrityError:
        return jsonify({"message": "Email already exists"}), 409

    finally:
        connection.close()

@app.route("/Hanaa-Ballout/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    """delete a user account by ID.
    Requires an active Security Administrator account."""
    current_user_id = int(get_jwt_identity())

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT role, account_status FROM users WHERE user_id = ?",
        (current_user_id,)
    )
    current_user = cursor.fetchone()

    if not current_user or current_user["account_status"] != "Active":
        connection.close()
        return jsonify({"message": "Account not active or not found"}), 403

    if current_user["role"] != "Security Administrator":
        connection.close()
        return jsonify({"message": "Permission denied"}), 403

    cursor.execute(
        "SELECT user_id FROM users WHERE user_id = ?",
        (user_id,)
    )
    user = cursor.fetchone()

    if not user:
        connection.close()
        return jsonify({"message": "User not found"}), 404

    cursor.execute(
        "DELETE FROM users WHERE user_id = ?",
        (user_id,)
    )

    connection.commit()
    connection.close()

    return jsonify({
        "message": "User deleted successfully",
        "user_id": user_id
    }), 200

@app.route("/Hanaa-Ballout/users", methods=["GET"])
@jwt_required()
def get_all_users():
    """retrieve all users without exposing password hashes.
    Access is limited to active Security Administrators and Auditors."""
    current_user_id = int(get_jwt_identity())

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT role, account_status FROM users WHERE user_id = ?",
        (current_user_id,)
    )
    current_user = cursor.fetchone()

    if not current_user or current_user["account_status"] != "Active":
        connection.close()
        return jsonify({"message": "Account not active or not found"}), 403

    if current_user["role"] not in ["Security Administrator", "Auditor"]:
        connection.close()
        return jsonify({"message": "Permission denied"}), 403

    cursor.execute("""
        SELECT user_id, full_name, username, email,
               department, role, account_status,
               created_date, last_login_date
        FROM users
    """)

    users = [dict(user) for user in cursor.fetchall()]
    connection.close()

    return jsonify(users), 200

@app.route("/Hanaa-Ballout/users/<string:username>", methods=["GET"])
@jwt_required()
def get_user_by_username(username):
    """Retrieve a user by username without exposing the password hash.
    Active Administrators and Auditors can view any user; active
    Regular Employees can view only their own account."""
    current_user_id = int(get_jwt_identity())

    connection = get_connection()
    cursor = connection.cursor()

    
    cursor.execute(
        "SELECT user_id, role, account_status FROM users WHERE user_id = ?",
        (current_user_id,)
    )
    current_user = cursor.fetchone()

    if not current_user or current_user["account_status"] != "Active":
        connection.close()
        return jsonify({"message": "Account not active or not found"}), 403

    if current_user["role"] == "Security Analyst":
        connection.close()
        return jsonify({"message": "Permission denied"}), 403

    cursor.execute("""
        SELECT user_id, full_name, username, email,
               department, role, account_status,
               created_date, last_login_date
        FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    if not user:
        connection.close()
        return jsonify({"message": "User not found"}), 404

    if current_user["role"] == "Regular Employee":
        if current_user_id != user["user_id"]:
            connection.close()
            return jsonify({"message": "Permission denied"}), 403

    result = dict(user)
    connection.close()

    return jsonify(result), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)

