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
