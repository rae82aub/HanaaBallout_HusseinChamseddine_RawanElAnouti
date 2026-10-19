## EECE 435L | Sprint 1

This project is a backend system developed using Python, Flask, SQLite, and JWT authentication.

The system helps organizations manage users, IT assets, security incidents, threats, audit logs, reports, vulnerabilities, notifications, and automated response playbooks.

The backend is divided into nine services. Each service has its own Flask application and API endpoints.

## Team Members

| Team Member | Services |
|---|---|
| Hanaa Ballout | Services 1, 2, and 7 |
| Hussein Chamseddine | Services 4, 5, and 6 |
| Rawan El Anouti | Services 3, 8, and 9 |

## 1. Project Services

| Service | Name | Folder | Port |
|---|---|---|---|
| 1 | Users and Identity Management | `service1_users` | 5000 |
| 2 | Asset Management | `service2_assets` | 5001 |
| 3 | Incident Management | `service3_incidents` | 5003 |
| 4 | Threat Intelligence | `service4_threats` | 5004 |
| 5 | Security Audit Logging | `service5_logs` | 5005 |
| 6 | Security Reports | `service6_reports` | 5006 |
| 7 | Vulnerability Management | `Service7_vulnerabilities` | 5002 |
| 8 | Notification and Alert Management | `service8_notifications` | 5008 |
| 9 | Security Playbooks and Response Automation | `service9_playbooks` | 5009 |

### Service 1: Users and Identity Management

**Implemented by Hanaa Ballout**

This service manages user accounts and authentication.

Main features:
- Register new users
- Log in using a username or email and password
- Generate JWT access tokens
- Update user information
- Delete users
- Retrieve user information
- Manage access based on user roles

Service 1 provides authentication for the other services.

### Service 2: Asset Management

**Implemented by Hanaa Ballout**

This service manages the organization's IT assets.

Main features:
- Register new assets
- Update asset information
- Delete assets
- Retrieve assets
- Search for assets
- Assign assets to users
- Manage asset criticality and status

Assets can include servers, workstations, databases, applications, network devices, and cloud resources.

### Service 3: Incident Management

**Implemented by Rawan El Anouti**

This service manages reported security incidents.

Main features:
- Create an incident
- Retrieve all incidents
- Retrieve an incident by ID
- Assign an incident to an analyst
- Update an incident's status
- Add investigation notes

Incidents contain information such as title, description, category, severity, affected asset, reporter, and status.

Incident categories include malware infections, unauthorized access, phishing attacks, data leakage, account compromise, and denial of service attacks.

Incident management actions are also recorded in the security audit logs.

### Service 4: Threat Intelligence

**Implemented by Hussein Chamseddine**

This service stores and manages security threat indicators.

Main features:
- Add threat indicators
- Retrieve threats
- Update threat information
- Delete threats
- Search for threats
- Validate threat information

Threat indicators include IP addresses, domains, file hashes, malware signatures, and other indicators.

### Service 5: Security Audit Logging

**Implemented by Hussein Chamseddine**

This service records important activities in the system.

Main features:
- Create audit logs
- Retrieve all logs
- Retrieve a specific log
- Search audit logs
- Retrieve logs by user
- Delete logs with the required permissions

Audit records can include the user, action, description, severity, related service, and timestamp.

Other services can record important operations through the shared audit logging functionality in `common.py`.

### Service 6: Security Reports

**Implemented by Hussein Chamseddine**

This service generates security reports using information from other services.

Main reports:
- Overall security summary
- Incident report
- Asset report
- Threat report
- Vulnerability report
- Activity report

The reports help security administrators and auditors review system activity and security information.

### Service 7: Vulnerability Management

**Implemented by Hanaa Ballout**

This service manages vulnerabilities affecting the organization's assets.

Main features:
- Register vulnerabilities
- Retrieve vulnerabilities
- Update vulnerability information
- Delete vulnerabilities
- Search and manage vulnerability records

This service helps track security weaknesses and the assets affected by them.

### Service 8: Notification and Alert Management

**Implemented by Rawan El Anouti**

This service manages security notifications sent to users.

Main features:
- Create notifications
- Retrieve notifications
- Retrieve a specific notification
- Update notification information
- Mark notifications as read
- Delete notifications

Notifications can be related to incident assignments, security alerts, system notifications, threats, and vulnerabilities.

Notification records include their type, severity, status, recipient, and related information.

Important notification actions can also be recorded in Service 5.

### Service 9: Security Playbooks and Response Automation

**Implemented by Rawan El Anouti**

This service manages security playbooks and response actions.

Main features:
- Create security playbooks
- Retrieve playbooks
- Delete playbooks
- Create response actions
- Retrieve response actions
- Update response action status

Each playbook can contain multiple response steps.

Response actions can have statuses such as Pending, In Progress, and Completed.

Playbook and response action changes can also be recorded in Service 5.

## 2. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | REST API development |
| SQLite | Database storage |
| Flask-JWT-Extended | JWT authentication |
| Werkzeug | Password hashing and verification |
| python-dotenv | Environment configuration |
| Requests | Communication between services |
| Postman | API testing |
| Git and GitHub | Version control and teamwork |

## 3. Project Structure

```text
Security Incident Detection and Response Management System/
│
├── service1_users/
│   ├── app.py
│   └── database.py
│
├── service2_assets/
│   ├── app.py
│   └── database.py
│
├── service3_incidents/
│   ├── app.py
│   └── database.py
│
├── service4_threats/
│   ├── app.py
│   └── database.py
│
├── service5_logs/
│   ├── app.py
│   └── database.py
│
├── service6_reports/
│   └── app.py
│
├── Service7_vulnerabilities/
│   ├── app.py
│   └── database.py
│
├── service8_notifications/
│   ├── app.py
│   └── database.py
│
├── service9_playbooks/
│   ├── app.py
│   └── database.py
│
├── postman/
├── common.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

Each service stores its data in a local SQLite database named `database.db`, except Service 6, which reads information from other services.

The `.env` file and SQLite database files are excluded from Git tracking.

## 4. Installation and Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/rae82aub/HanaaBallout_HusseinChamseddine_RawanElAnouti.git
```

Move into the project folder:

```bash
cd HanaaBallout_HusseinChamseddine_RawanElAnouti
```

### Step 2: Create a Virtual Environment

```bash
python3 -m venv .venv
```

Activate the virtual environment.

On macOS or Linux:

```bash
source .venv/bin/activate
```

On Windows:

```bash
.venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Set the `JWT_SECRET_KEY` inside `.env`.

All services must use the same JWT secret to validate tokens generated by Service 1.

Keep `.env` private. Do not upload passwords, access tokens, or secret keys to GitHub.

### Step 5: Initialize the Databases

Start by initializing the Service 1 database:

```bash
python service1_users/database.py
```

Follow the terminal instructions to create the initial Security Administrator.

Then initialize Services 2, 4, 5, and 7:

```bash
python service2_assets/database.py
python service4_threats/database.py
python service5_logs/database.py
python Service7_vulnerabilities/database.py
```

Initialize Services 3, 8, and 9:

```bash
python -c "from service3_incidents.database import create_tables; create_tables()"
python -c "from service8_notifications.database import create_tables; create_tables()"
python -c "from service9_playbooks.database import create_tables; create_tables()"
```

The project uses SQLite tables created with `CREATE TABLE IF NOT EXISTS`.

## 5. Running the Services

Open a separate terminal for each service.

Activate the virtual environment in each terminal before running the Flask application.

### Service 1

```bash
python service1_users/app.py
```

Runs on `http://127.0.0.1:5000`

### Service 2

```bash
python service2_assets/app.py
```

Runs on `http://127.0.0.1:5001`

### Service 3

```bash
python service3_incidents/app.py
```

Runs on `http://127.0.0.1:5003`

### Service 4

```bash
python service4_threats/app.py
```

Runs on `http://127.0.0.1:5004`

### Service 5

```bash
python service5_logs/app.py
```

Runs on `http://127.0.0.1:5005`

### Service 6

```bash
python service6_reports/app.py
```

Runs on `http://127.0.0.1:5006`

### Service 7

```bash
python Service7_vulnerabilities/app.py
```

Runs on `http://127.0.0.1:5002`

### Service 8

```bash
python service8_notifications/app.py
```

Use the port configured in its `app.py`.

### Service 9

```bash
python service9_playbooks/app.py
```

Use the port configured in its `app.py`.

Start Service 1 first so the other services can validate user accounts and roles.

## 6. Authentication and Authorization

The backend uses JWT authentication.

Users log in through Service 1 and receive an access token.

### Login Endpoint

**POST**

```text
http://127.0.0.1:5000/Hanaa-Ballout/users/login
```

Example request:

```json
{
  "username": "admin_test",
  "password": "YOUR_PASSWORD"
}
```

A successful login returns an access token and information about the authenticated user.

For protected endpoints, open the Authorization tab in Postman, select Bearer Token, and paste the access token.

### User Roles

The system uses role-based authorization.

Roles include:
- Security Administrator
- Security Analyst
- Security Auditor
- Regular Employee

Each service checks whether the authenticated user's role is allowed to perform the requested operation.

Requests without a valid token or the required permissions are rejected.

## 7. Main API Endpoints

The following examples show the main routes used by the services.

| Service | Method | Endpoint |
|---|---|---|
| 1 | POST | `/Hanaa-Ballout/users/register` |
| 1 | POST | `/Hanaa-Ballout/users/login` |
| 1 | GET | `/Hanaa-Ballout/users` |
| 2 | POST | `/Hanaa-Ballout/assets` |
| 2 | GET | `/Hanaa-Ballout/assets` |
| 3 | POST | `/Rawan-El-Anouti/incidents` |
| 3 | GET | `/Rawan-El-Anouti/incidents` |
| 3 | PUT | `/Rawan-El-Anouti/incidents/<incident_id>/assign` |
| 3 | PUT | `/Rawan-El-Anouti/incidents/<incident_id>/status` |
| 3 | POST | `/Rawan-El-Anouti/incidents/<incident_id>/notes` |
| 4 | GET | `/Hussein-Chamseddine/threats` |
| 5 | GET | `/Hussein-Chamseddine/logs` |
| 5 | GET | `/Hussein-Chamseddine/logs/search` |
| 6 | GET | `/Hussein-Chamseddine/reports/summary` |
| 6 | GET | `/Hussein-Chamseddine/reports/incidents` |
| 6 | GET | `/Hussein-Chamseddine/reports/assets` |
| 6 | GET | `/Hussein-Chamseddine/reports/threats` |
| 6 | GET | `/Hussein-Chamseddine/reports/vulnerabilities` |
| 6 | GET | `/Hussein-Chamseddine/reports/activity` |

The routes for Services 7, 8, and 9, along with additional operations for all services, are available in their respective `app.py` files and Postman collections.

## 8. Postman Testing

Postman is used to test the REST APIs.

The `postman` folder contains API collections developed by the team members.

### How to Test

1. Start the required Flask services.
2. Open Postman.
3. Import the relevant collection from the `postman` folder.
4. Log in through Service 1.
5. Copy the returned JWT access token.
6. Set the Bearer Token for protected requests.
7. Send requests and review the responses.
8. Check the corresponding SQLite database when necessary.

### Test Cases

The APIs can be tested using:
- Successful requests
- Missing required fields
- Invalid field values
- Invalid or missing JWT tokens
- Insufficient user permissions
- Nonexistent record IDs
- Invalid status changes
- Duplicate records
- Search and retrieval operations

Postman responses can include status codes such as:

| Status Code | Meaning |
|---|---|
| 200 | Request successful |
| 201 | Resource created |
| 400 | Invalid request |
| 401 | Authentication required or invalid |
| 403 | Permission denied |
| 404 | Resource not found |
| 409 | Conflict with an existing record |

The exact status code depends on the endpoint and the validation rules.

## 9. Integration Between Services

The nine services work together through shared user authentication, database references, and REST API requests.

Examples of integration include:

**User Authentication:** Service 1 generates JWT tokens that other services use to authenticate requests.

**Incident Management:** Service 3 links reported incidents to users and affected assets.

**Audit Logging:** Services can record important actions in Service 5 using the shared functions in `common.py`.

**Security Reports:** Service 6 collects information from other services to generate reports.

**Response Playbooks:** Service 9 manages structured response actions related to security operations.

These integrations allow the backend services to support a single security management system.

## 10. GitHub Collaboration

The project was developed using Git and GitHub.

Each team member worked on their assigned services in a separate feature branch.

| Branch | Purpose |
|---|---|
| `hanaa-services-1-2-7` | Hanaa's services |
| `hussein-services-4-5-6` | Hussein's services |
| `rawan-services-3-8-9` | Rawan's services |
| `sprint1-integration` | Combined implementation |
| `main` | Shared project branch |

The feature branches were merged into `sprint1-integration` to combine the nine services and resolve merge conflicts.

The integration was then prepared for merging into `main` through a GitHub pull request.

## 11. Current Project Status

The following integration checks have been completed:

- All nine service folders were combined.
- All Python files passed a syntax check.
- All eight SQLite databases were initialized.
- Shared database paths were updated for the integrated project.
- Service 1 started successfully.
- JWT authentication between Services 1 and 5 was tested successfully.
- Service 2 successfully created a test asset.
- Service 3 started successfully.
- The integrated code was pushed to GitHub.

Complete end-to-end testing of every service in the merged project has not yet been performed.

## 12. Team Contributions

**Hanaa Ballout:** Developed user and identity management, asset management, and vulnerability management.

**Hussein Chamseddine:** Developed threat intelligence, security audit logging, and security reports.

**Rawan El Anouti:** Developed incident management, notification and alert management, and security playbooks and response automation.

All three team members contributed to the backend implementation and GitHub collaboration.
