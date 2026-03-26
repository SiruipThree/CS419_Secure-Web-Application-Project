# CS419 Secure Web Application Project

Secure document sharing system scaffold for the CS 419 course project.

## Recommended Stack

- Backend: Python + Flask
- Frontend: HTML, CSS, JavaScript
- Storage: JSON files
- Security libraries: bcrypt, cryptography, PyJWT

## Current Status

This repository now contains the project structure and a minimal Flask scaffold.
Core security features, document encryption, sharing logic, and penetration tests
still need to be implemented.

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

## Next Implementation Priorities

1. Registration and login with bcrypt and account lockout
2. Server-side session management and secure cookies
3. Encrypted document upload, download, and versioning
4. Admin, user, guest, owner, editor, viewer authorization rules
5. Security event logging and penetration test coverage
