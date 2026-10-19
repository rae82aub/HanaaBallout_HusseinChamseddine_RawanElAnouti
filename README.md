# Security Incident Detection and Response Management System

## Services 1, 2, and 7 — Hanaa Ballout

See the service folders for implementation details.

---


# Security Incident Detection and Response Management System

## Sprint I: Backend Development

**Services Implemented:** 3, 8, and 9  
**Implemented by:** Rawan El Anouti  
**Framework:** Flask  
**Database:** SQLite  
**Authentication:** JSON Web Tokens (JWT)  
**API Testing:** Postman

## 1. Project Overview

This repository contains my backend contributions to the Security Incident Detection and Response Management System, developed as part of Sprint I.

The system provides RESTful APIs for managing cybersecurity incidents, notifications, security playbooks, and response actions.

My contribution consists of three independent Flask services:

- Service 3: Incident Management
- Service 8: Notification and Alert Management
- Service 9: Security Playbook and Response Automation

These services use SQLite databases, JWT authentication, role-based access control, input validation, and HTTP status codes.

Audit logging integration with Service 5 was also implemented and tested.

## 2. Technologies Used

- Python 3
- Flask
- Flask-JWT-Extended
- SQLite
- Requests
- Python-dotenv
- Postman
- Git and GitHub

## 3. Project Structure

```text
servicesrawan/
├── service3_incidents/
│   ├── app.py
│   └── database.py
├── service8_notifications/
│   ├── app.py
│   └── database.py
├── service9_playbooks/
│   ├── app.py
│   └── database.py
├── common.py
├── postman/
├── requirements.txt
├── .gitignore
└── README.md
```

SQLite database files and environment files are excluded from Git.

Service 1 and Service 5 are maintained by other team members and are required for certain integration features.

## 4. Installation and Setup

### Step 1: Clone the Repository

```bash
git clone -b rawan-services-3-8-9 https://github.com/rae82aub/HanaaBallout_HusseinChamseddine_RawanElAnouti.git
```

Navigate into the cloned project folder.

### Step 2: Create a Virtual Environment

```bash
python3 -m venv .venv
```

Activate it on macOS or Linux:

```bash
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
python -m pip install -r requirements.txt
python -m pip install python-dotenv
```

### Step 4: Configure JWT Authentication

All protected services must use the same JWT secret key as Service 1.

Set the shared secret through an environment variable:

```bash
export JWT_SECRET_KEY='YOUR_SHARED_JWT_SECRET'
```

Replace the placeholder with the secret agreed upon by the team.

Never commit JWT secrets or access tokens to GitHub.

### Step 5: Configure the Users Database

Services 3, 8, and 9 require access to Service 1's Users database for authentication and authorization checks.

The default expected location is:

```text
service1_users/database.db
```

Ensure the Service 1 database is available at the configured path and contains the required test users.

### Step 6: Run the Services

Start each service in a separate terminal.

Service 3:

```bash
python service3_incidents/app.py
```

Service 8:

```bash
python service8_notifications/app.py
```

Service 9:

```bash
python service9_playbooks/app.py
```

Make sure each terminal has the shared JWT secret configured.

## 5. Service 3: Incident Management

**Port:** 5003  
**Base URL:**

```text
http://127.0.0.1:5003/Rawan-El-Anouti
```

### Responsibilities

Service 3 manages cybersecurity incidents throughout their lifecycle.

Main features include:

- Creating cybersecurity incidents
- Retrieving incident records
- Assigning incidents to Security Analysts
- Updating incident statuses
- Adding investigation notes
- Enforcing role-based permissions
- Validating incident information
- Sending incident assignment notifications
- Recording important operations in Service 5

### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/incidents` | Create an incident |
| GET | `/incidents` | Retrieve all incidents |
| GET | `/incidents/{id}` | Retrieve a specific incident |
| PUT | `/incidents/{id}/assign` | Assign an incident to an analyst |
| PUT | `/incidents/{id}/status` | Update incident status |
| POST | `/incidents/{id}/notes` | Add an investigation note |

### Incident Lifecycle

```text
Open
  |
  v
Under Investigation
  |
  v
Mitigated
  |
  v
Resolved
  |
  v
Closed
```

Invalid status transitions are rejected.

### Example Request

**POST** `/Rawan-El-Anouti/incidents`

```json
{
  "title": "Phishing Email Detected",
  "description": "An employee received a suspicious email.",
  "category": "Phishing attack",
  "severity": "Medium",
  "affected_asset": 1
}
```

A successful request returns HTTP `201 Created` with the newly created incident.

## 6. Service 8: Notification and Alert Management

**Port:** 5008  
**Base URL:**

```text
http://127.0.0.1:5008/Rawan-El-Anouti
```

### Responsibilities

Service 8 manages cybersecurity notifications delivered to system users.

Main features include:

- Creating notifications
- Retrieving user notifications
- Retrieving individual notifications
- Marking notifications as read
- Searching notifications using filters
- Deleting notifications
- Enforcing role-based permissions
- Recording important operations in Service 5

### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/notifications` | Create a notification |
| GET | `/notifications/user/{user_id}` | Retrieve notifications for a user |
| GET | `/notifications/{id}` | Retrieve a specific notification |
| PUT | `/notifications/{id}/read` | Mark a notification as read |
| GET | `/notifications/search` | Search notifications using filters |
| DELETE | `/notifications/{id}` | Delete a notification |

### Example Request

**POST** `/Rawan-El-Anouti/notifications`

```json
{
  "user_id": 2,
  "title": "Security Alert",
  "message": "A suspicious login attempt was detected.",
  "notification_type": "Security Alert",
  "severity": "High"
}
```

A successful request returns HTTP `201 Created`.

New notifications initially have the status `Unread`.

## 7. Service 9: Security Playbook and Response Automation

**Port:** 5009  
**Base URL:**

```text
http://127.0.0.1:5009/Rawan-El-Anouti
```

### Responsibilities

Service 9 provides structured security response procedures through playbooks and response actions.

Main features include:

- Creating security playbooks
- Retrieving playbooks
- Adding response actions
- Assigning response actions to users
- Updating action statuses
- Enforcing sequential action execution
- Deleting playbooks
- Recording important operations in Service 5

### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/playbooks` | Create a playbook |
| GET | `/playbooks` | Retrieve all playbooks |
| GET | `/playbooks/{id}` | Retrieve a specific playbook |
| POST | `/playbooks/{id}/actions` | Add a response action |
| PUT | `/actions/{id}/status` | Update a response action |
| DELETE | `/playbooks/{id}` | Delete a playbook |

### Response Action Lifecycle

```text
Pending
  |
  v
In Progress
  |
  v
Completed
```

Response actions follow the required sequence. A previous action must be completed before the next action can begin.

### Example Request

**POST** `/Rawan-El-Anouti/playbooks`

```json
{
  "playbook_name": "Phishing Incident Response",
  "description": "Standard response procedure for phishing incidents.",
  "incident_category": "Phishing attack",
  "severity": "High"
}
```

A successful request returns HTTP `201 Created`.

## 8. Authentication and Authorization

Authentication is handled through Service 1, developed by Hanaa Ballout.

Service 1 generates JWT access tokens after successful login.

The supported user roles are:

- Security Administrator
- Security Analyst
- Regular Employee
- Auditor

Protected endpoints require a valid JWT access token.

### Login Endpoint

```text
POST http://127.0.0.1:5000/Hanaa-Ballout/users/login
```

Example request:

```json
{
  "username": "YOUR_TEST_USERNAME",
  "password": "YOUR_TEST_PASSWORD"
}
```

The response includes an `access_token`.

In Postman, select:

```text
Authorization > Bearer Token
```

Paste the access token into the token field.

Access permissions depend on the user's role and the requested operation.

## 9. Database Design

Each service uses SQLite for persistent storage.

### Service 3

Tables:

- `incidents`
- `investigation_notes`

Investigation notes are linked to incidents through `incident_id`.

### Service 8

Table:

- `notifications`

Notifications contain information such as the recipient user ID, title, message, type, severity, status, and timestamps.

### Service 9

Tables:

- `playbooks`
- `response_actions`

Response actions are linked to playbooks through `playbook_id`.

### Cross-Service References

Some records reference users and assets maintained by other services.

The relevant IDs are validated or retrieved through the available shared database and service integration mechanisms.

## 10. Audit Logging Integration

Audit logging was integrated with Hussein Chamseddine's Service 5.

The shared `write_audit_log()` function records security-related operations in the Service 5 SQLite database.

### Service 3 Audit Events

- Incident creation
- Incident assignment
- Incident status update
- Investigation note creation

### Service 8 Audit Events

- Notification creation
- Notification marked as read
- Notification deletion

### Service 9 Audit Events

- Playbook creation
- Response action creation
- Response action status update
- Playbook deletion

A total of 11 operation types were tested successfully.

### Audit Log Information

Each recorded event contains:

- User ID
- Action
- Description
- Severity
- Related service
- Timestamp

### Integration Requirements

The Service 5 database must be accessible at the path configured by `common.py`.

For the local integration tests, the expected default path was:

```text
service5_logs/database.db
```

Service 5 is developed by Hussein Chamseddine and should be included during final team integration.

The logging mechanism writes to the configured SQLite database. It does not require a separate Postman request for each audit event.

## 11. Error Handling and Validation

The services validate request data and enforce authorization rules.

Common HTTP response codes include:

| Status Code | Meaning |
|---|---|
| 200 OK | Operation completed successfully |
| 201 Created | New record created successfully |
| 400 Bad Request | Invalid or missing input |
| 401 Unauthorized | Missing or invalid JWT token |
| 403 Forbidden | Insufficient permissions |
| 404 Not Found | Requested record does not exist |
| 409 Conflict | Conflicting or duplicate data |

Additional validation includes:

- Incident severity and category validation
- Sequential incident status transitions
- Verification of assigned analyst roles
- Notification type and severity validation
- Restricted notification deletion
- Playbook category and severity validation
- Unique response action step numbers
- Sequential response action status transitions

## 12. Postman Testing

The APIs were tested using Postman.

Testing included:

- Successful API requests
- Invalid input handling
- Missing or nonexistent records
- Unauthorized role access
- JWT-based authentication
- Incident lifecycle updates
- Notification status updates
- Playbook and response action management
- Audit logging integration with Service 5

Postman collection files are maintained in the `postman/` directory.

To use a collection:

1. Open Postman.
2. Select Import.
3. Select the relevant collection JSON file.
4. Configure the local service URLs.
5. Obtain a valid JWT token from Service 1.
6. Execute the requests.

The services must be running before sending requests.

## 13. GitHub and Version Control

Development branch:

```text
rawan-services-3-8-9
```

Repository:

https://github.com/rae82aub/HanaaBallout_HusseinChamseddine_RawanElAnouti

Git and GitHub were used for source control, separate team contributions, and integration work.

The audit logging integration was developed and tested on a temporary branch before the changes were transferred to `rawan-services-3-8-9`.

## 14. Team Responsibilities

| Team Member | Services |
|---|---|
| Hanaa Ballout | 1, 2, and 7 |
| Hussein Chamseddine | 4, 5, and 6 |
| Rawan El Anouti | 3, 8, and 9 |

Each member developed and tested their assigned backend services.

The final integration combines the nine services into one cybersecurity management system.

## 15. Notes

- This branch contains Rawan El Anouti's contributions to Sprint I.
- The project is backend-only for Sprint I.
- Flask development servers are intended for local testing.
- All services must share the correct JWT configuration.
- Local SQLite databases and JWT secrets must not be committed.
- External service dependencies must be configured during team integration.
- Audit logging integration has been tested locally for Services 3, 8, and 9.


---

# Hussein Chamseddine — Services 4, 5, and 6

This folder is part of the EECE 435L Sprint 1 backend for the Security Incident Detection and Response Management System.

**Implemented by:** Hussein Chamseddine

| Service | Folder | Port | Route prefix |
| --- | --- | --- | --- |
| 4. Threat Intelligence | `service4_threats` | 5004 | `/Hussein-Chamseddine/threats` |
| 5. Security Audit Logging | `service5_logs` | 5005 | `/Hussein-Chamseddine/logs` |
| 6. Security Reports | `service6_reports` | 5006 | `/Hussein-Chamseddine/reports` |

Login and user roles come from Service 1 (`Hanaa-Ballout`). Use the same `JWT_SECRET_KEY` as Service 1.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Put the same `JWT_SECRET_KEY` value used in Hanaa's Service 1 into `.env`.

Start each service in its own terminal from this folder:

```bash
python service4_threats/app.py
python service5_logs/app.py
python service6_reports/app.py
```

Service 1 should already be running on port 5000 so JWT identities and roles can be checked.

## Service 4 — Threat Intelligence

Stores searchable threat indicators: IP Address, Domain, File Hash, Malware Signature, and Other.

- Validates IP, domain, and hash formats
- Severity: Low, Medium, High, Critical
- Rejects duplicate type + value pairs
- Add / update / delete: Security Administrator
- List / get: Administrator, Analyst, Auditor
- Search: Administrator, Analyst
- Regular employees have no access
- Analysts cannot delete threats

## Service 5 — Security Audit Logging

Stores immutable activity records. There is no update endpoint.

Automatic logs are written for unauthorized access attempts and data modifications in Services 4, 5, and 6. Login, user creation, user deletion, and role-change events can be recorded with `POST /Hussein-Chamseddine/logs`.

- Create / delete: Security Administrator
- List all / logs by user: Administrator, Auditor
- Get one / search: Administrator, Auditor, Analyst
- Regular employees have no access
- Severity: Information, Warning, Error, Critical

## Service 6 — Security Reports

Read-only reports for Security Administrators and Auditors only.

Reports try teammate REST APIs first (users, assets, incidents, vulnerabilities) and fall back to those SQLite databases if a service is not running. Threat and activity numbers come from this project's own databases.

- `GET /reports/summary`
- `GET /reports/incidents`
- `GET /reports/assets`
- `GET /reports/threats`
- `GET /reports/vulnerabilities`
- `GET /reports/activity`

## Postman

Import `postman/Hussein Chamseddine-postman-collection-services-4-5-6.postman_collection.json`.

1. Log in through Service 1 and copy the access token into the collection `access_token` variable.
2. Run the Service 4, 5, and 6 requests.
3. Capture screenshots of successful calls, failed authorization, missing IDs, searches, and the matching SQLite rows.
