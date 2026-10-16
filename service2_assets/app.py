from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from database import get_db_connection, init_db
import sqlite3
import os
import ipaddress
from pathlib import Path
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app)

init_db()

USERS_DB = Path(__file__).resolve().parent.parent / "service1_users" / "database.db"


def get_users_connection():
    """Connect to the Service 1 users database for identity and role checks."""
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/", methods=["GET"])
def home():
    """return a status message confirming the Asset Management Service is running."""
    return jsonify({
        "message": "Asset Management Service is running"
    })


@app.route("/Hanaa-Ballout/assets", methods=["POST"])
@jwt_required()
def add_asset():
    """create an asset for an active Security Administrator.
    Validate asset details, IP address, and the existence of its owner."""


    current_user_id = get_jwt_identity()

    users_conn = get_users_connection()

    current_user = users_conn.execute("""
        SELECT user_id, role, account_status
        FROM users
        WHERE user_id = ?
    """, (current_user_id,)).fetchone()

    if not current_user or current_user["account_status"] != "Active":
        users_conn.close()
        return jsonify({
            "message": "Account not active or not found"
        }), 403

    if current_user["role"] != "Security Administrator":
        users_conn.close()
        return jsonify({
            "message": "Permission denied"
        }), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        users_conn.close()
        return jsonify({
            "message": "A JSON object is required"
        }), 400

    required_fields = [
        "asset_name",
        "asset_type",
        "ip_address",
        "department",
        "owner_id",
        "criticality_level"
    ]

    for field in required_fields:
        value = data.get(field)

        if value is None or (
            isinstance(value, str) and not value.strip()
        ):
            users_conn.close()
            return jsonify({
                "message": f"{field} is required"
            }), 400

    valid_types = [
        "Server",
        "Workstation",
        "Database",
        "Application",
        "Network Device",
        "Cloud Resource"
    ]

    if not isinstance(data["asset_type"], str) or data["asset_type"] not in valid_types:
        users_conn.close()
        return jsonify({
            "message": "Invalid asset type"
        }), 400

    try:
        ipaddress.ip_address(data["ip_address"])
    except (ValueError, TypeError):
        users_conn.close()
        return jsonify({
            "message": "Invalid IP address format"
        }), 400

    valid_levels = ["Low", "Medium", "High", "Critical"]

    if not isinstance(data["criticality_level"], str) or data["criticality_level"] not in valid_levels:
        users_conn.close()
        return jsonify({
            "message": "Invalid criticality level"
        }), 400

    status = data.get("status", "Active")

    valid_statuses = [
        "Active",
        "Inactive",
        "Under Maintenance"
    ]

    if not isinstance(status, str) or status not in valid_statuses:
        users_conn.close()
        return jsonify({
            "message": "Invalid asset status"
        }), 400

    for field in ["asset_name", "department"]:
        if not isinstance(data[field], str) or not data[field].strip():
            users_conn.close()
            return jsonify({
                "message": f"Invalid {field}"
            }), 400

    for field in ["operating_system", "location"]:
        if data.get(field) is not None and not isinstance(data[field], str):
            users_conn.close()
            return jsonify({
                "message": f"Invalid {field}"
            }), 400


    owner_id = data["owner_id"]

    if type(owner_id) is not int or owner_id <= 0:
        users_conn.close()
        return jsonify({
            "message": "owner_id must be a positive integer"
        }), 400

    owner = users_conn.execute("""
        SELECT user_id
        FROM users
        WHERE user_id = ?
    """, (owner_id,)).fetchone()

    users_conn.close()

    if not owner:
        return jsonify({
            "message": "Asset owner does not exist"
        }), 404

    conn = get_db_connection()

    cursor = conn.execute("""
        INSERT INTO assets (
            asset_name,
            asset_type,
            ip_address,
            operating_system,
            owner_id,
            department,
            location,
            criticality_level,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["asset_name"].strip(),
        data["asset_type"],
        data["ip_address"],
        data.get("operating_system"),
        owner_id,
        data["department"].strip(),
        data.get("location"),
        data["criticality_level"],
        status
    ))

    conn.commit()
    asset_id = cursor.lastrowid
    conn.close()

    return jsonify({
        "message": "Asset created successfully",
        "asset_id": asset_id
    }), 201


@app.route("/Hanaa-Ballout/assets/<int:asset_id>", methods=["PUT"])
@jwt_required()
def update_asset(asset_id):
    """Update the allowed asset fields as an active Security Administrator.
    Validate changes and verify any newly assigned owner exists."""


    current_user_id = get_jwt_identity()

    users_conn = get_users_connection()

    current_user = users_conn.execute("""
        SELECT user_id, role, account_status
        FROM users
        WHERE user_id = ?
    """, (current_user_id,)).fetchone()

    if not current_user or current_user["account_status"] != "Active":
        users_conn.close()
        return jsonify({
            "message": "Account not active or not found"
        }), 403

    if current_user["role"] != "Security Administrator":
        users_conn.close()
        return jsonify({
            "message": "Permission denied"
        }), 403

    conn = get_db_connection()

    asset = conn.execute(
        "SELECT * FROM assets WHERE asset_id = ?",
        (asset_id,)
    ).fetchone()

    if not asset:
        conn.close()
        users_conn.close()
        return jsonify({
            "message": "Asset not found"
        }), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        conn.close()
        users_conn.close()
        return jsonify({
            "message": "A non-empty JSON object is required"
        }), 400

    allowed_fields = [
        "asset_name",
        "owner_id",
        "department",
        "criticality_level",
        "status"
    ]

    if any(field not in allowed_fields for field in data):
        conn.close()
        users_conn.close()
        return jsonify({
            "message": "Request contains an invalid update field"
        }), 400

    for field in ["asset_name", "department"]:
        if field in data:
            if not isinstance(data[field], str) or not data[field].strip():
                conn.close()
                users_conn.close()
                return jsonify({
                    "message": f"Invalid {field}"
                }), 400

    if "criticality_level" in data:
        if data["criticality_level"] not in [
            "Low", "Medium", "High", "Critical"
        ]:
            conn.close()
            users_conn.close()
            return jsonify({
                "message": "Invalid criticality level"
            }), 400

    if "status" in data:
        if data["status"] not in [
            "Active", "Inactive", "Under Maintenance"
        ]:
            conn.close()
            users_conn.close()
            return jsonify({
                "message": "Invalid asset status"
            }), 400

    if "owner_id" in data:
        owner_id = data["owner_id"]

        if type(owner_id) is not int or owner_id <= 0:
            conn.close()
            users_conn.close()
            return jsonify({
                "message": "owner_id must be a positive integer"
            }), 400

        owner = users_conn.execute("""
            SELECT user_id FROM users WHERE user_id = ?
        """, (owner_id,)).fetchone()

        if not owner:
            conn.close()
            users_conn.close()
            return jsonify({
                "message": "Asset owner does not exist"
            }), 404

    users_conn.close()

    update_fields = []
    values = []

    for field, value in data.items():
        update_fields.append(f"{field} = ?")
        values.append(value.strip() if field in [
            "asset_name", "department"
        ] else value)

    values.append(asset_id)

    conn.execute(
        f"UPDATE assets SET {', '.join(update_fields)} WHERE asset_id = ?",
        values
    )

    conn.commit()

    updated_asset = conn.execute(
        "SELECT * FROM assets WHERE asset_id = ?",
        (asset_id,)
    ).fetchone()

    result = dict(updated_asset)
    conn.close()

    return jsonify({
        "message": "Asset updated successfully",
        "asset": result
    }), 200


@app.route("/Hanaa-Ballout/assets/<int:asset_id>", methods=["DELETE"])
@jwt_required()
def delete_asset(asset_id):
    """ddelete an existing asset; restricted to active Security Administrators."""

    current_user_id = get_jwt_identity()

    users_conn = get_users_connection()

    current_user = users_conn.execute("""
        SELECT user_id, role, account_status
        FROM users
        WHERE user_id = ?
    """, (current_user_id,)).fetchone()

    users_conn.close()

    if not current_user or current_user["account_status"] != "Active":
        return jsonify({
            "message": "Account not active or not found"
        }), 403

    if current_user["role"] != "Security Administrator":
        return jsonify({
            "message": "Permission denied"
        }), 403

    conn = get_db_connection()

    asset = conn.execute("""
        SELECT * FROM assets WHERE asset_id = ?
    """, (asset_id,)).fetchone()

    if not asset:
        conn.close()
        return jsonify({
            "message": "Asset not found"
        }), 404

    conn.execute("""
        DELETE FROM assets WHERE asset_id = ?
    """, (asset_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Asset deleted successfully",
        "asset_id": asset_id
    }), 200


@app.route("/Hanaa-Ballout/assets", methods=["GET"])
@jwt_required()
def get_all_assets():
    """List all assets for active Security Administrators and Auditors."""

    current_user_id = get_jwt_identity()

    users_conn = get_users_connection()

    current_user = users_conn.execute("""
        SELECT user_id, role, account_status
        FROM users
        WHERE user_id = ?
    """, (current_user_id,)).fetchone()

    users_conn.close()

    if not current_user or current_user["account_status"] != "Active":
        return jsonify({
            "message": "Account not active or not found"
        }), 403

    if current_user["role"] not in [
        "Security Administrator",
        "Auditor"
    ]:
        return jsonify({
            "message": "Permission denied"
        }), 403

    conn = get_db_connection()

    assets = conn.execute("""
        SELECT * FROM assets
        ORDER BY asset_id
    """).fetchall()

    conn.close()

    return jsonify({
        "message": "Assets retrieved successfully",
        "count": len(assets),
        "assets": [dict(asset) for asset in assets]
    }), 200


@app.route("/Hanaa-Ballout/assets/<int:asset_id>", methods=["GET"])
@jwt_required()
def get_asset_by_id(asset_id):
    """Retrieve an asset by ID for active Administrators, Analysts, or Auditors."""

    current_user_id = get_jwt_identity()

    users_conn = get_users_connection()

    current_user = users_conn.execute("""
        SELECT user_id, role, account_status
        FROM users
        WHERE user_id = ?
    """, (current_user_id,)).fetchone()

    users_conn.close()

    if not current_user or current_user["account_status"] != "Active":
        return jsonify({
            "message": "Account not active or not found"
        }), 403

    if current_user["role"] not in [
        "Security Administrator",
        "Security Analyst",
        "Auditor"
    ]:
        return jsonify({
            "message": "Permission denied"
        }), 403

    conn = get_db_connection()

    asset = conn.execute("""
        SELECT * FROM assets
        WHERE asset_id = ?
    """, (asset_id,)).fetchone()

    conn.close()

    if not asset:
        return jsonify({
            "message": "Asset not found"
        }), 404

    return jsonify({
        "message": "Asset retrieved successfully",
        "asset": dict(asset)
    }), 200


@app.route("/Hanaa-Ballout/assets/search", methods=["GET"])
@jwt_required()
def search_assets():
    """Search assets by supported query parameters for authorized users.
    you can use partial matches for names/departments and exact matches for other filters."""

    current_user_id = get_jwt_identity()

    users_conn = get_users_connection()

    current_user = users_conn.execute("""
        SELECT user_id, role, account_status
        FROM users
        WHERE user_id = ?
    """, (current_user_id,)).fetchone()

    users_conn.close()

    if not current_user or current_user["account_status"] != "Active":
        return jsonify({
            "message": "Account not active or not found"
        }), 403

    if current_user["role"] not in [
        "Security Administrator",
        "Security Analyst",
        "Auditor"
    ]:
        return jsonify({
            "message": "Permission denied"
        }), 403

    allowed_filters = [
        "asset_name",
        "asset_type",
        "ip_address",
        "department",
        "criticality_level"
    ]

    filters = request.args.to_dict()

    if not filters:
        return jsonify({
            "message": "At least one search parameter is required"
        }), 400

    for field, value in filters.items():
        if field not in allowed_filters:
            return jsonify({
                "message": f"Invalid search parameter: {field}"
            }), 400

        if not value.strip():
            return jsonify({
                "message": f"{field} cannot be empty"
            }), 400

    if "criticality_level" in filters:
        if filters["criticality_level"] not in [
            "Low", "Medium", "High", "Critical"
        ]:
            return jsonify({
                "message": "Invalid criticality level"
            }), 400

    query = "SELECT * FROM assets WHERE 1=1"
    values = []

    for field, value in filters.items():
        if field in ["asset_name", "department"]:
            query += f" AND {field} LIKE ?"
            values.append(f"%{value}%")
        else:
            query += f" AND {field} = ?"
            values.append(value)

    query += " ORDER BY asset_id"

    conn = get_db_connection()

    assets = conn.execute(query, values).fetchall()

    conn.close()

    return jsonify({
        "message": "Asset search completed successfully",
        "count": len(assets),
        "assets": [dict(asset) for asset in assets]
    }), 200

if __name__ == "__main__":
    app.run(debug=True, port=5001)
