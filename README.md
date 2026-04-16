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
- role-based access control for `admin`, `user`, and `guest` system roles
- document-level authorization for `owner`, `editor`, and `viewer` permissions
- server-side session creation, validation, and logout using the file-based store
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

## Admin Credentials

For testing/demo purposes only:

- **Username:** `test@test.com`
- **Password:** `#Adminpassword1`
