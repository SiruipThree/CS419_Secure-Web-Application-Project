# CS419 Secure Web Application Project

Secure document sharing system scaffold for the CS 419 course project.

## Recommended Stack

- Backend: Python + Flask
- Frontend: HTML, CSS, JavaScript
- Storage: JSON files
- Security libraries: bcrypt, cryptography, PyJWT

## Current Status

This repository now includes:

- project structure and Flask app scaffold
- input validation helpers for usernames, emails, passwords, titles, and uploads
- path traversal defenses and safe file naming for document storage
- encrypted document upload and download using `cryptography.Fernet`
- optional HTTPS redirect/TLS runtime configuration for non-development use
- security and access log wiring plus audit trail persistence for document events
- smoke tests and document-focused security tests

## Project Layout

```text
.
├── app.py
├── config.py
├── data/
├── docs/
├── logs/
├── presentation/
├── requirements.txt
├── secure_app/
├── static/
├── templates/
└── tests/
```

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app.py --debug run
```

## Implemented For Parts C And D

1. Form and upload validation using whitelist rules, size limits, and file signature checks
2. XSS-aware rendering using Jinja auto-escaping and explicit text sanitization helpers
3. Path traversal prevention for stored document payloads
4. Encrypted document storage at rest with generated Fernet key management
5. HTTPS enforcement support and HSTS on secure requests
6. Audit logging for document upload and download activity

## Remaining Priorities

1. Finish route-level and object-level authorization for admin, user, guest, owner, editor, and viewer flows
2. Complete server-side session lifecycle handling
3. Expand authentication routes to fully use the updated auth service
4. Extend penetration test coverage and final course deliverables
