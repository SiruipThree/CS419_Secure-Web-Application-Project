"""Server-side session management skeleton.

Implement secure token creation, timeout validation, and session invalidation
using the file-based session store.
"""

from secure_app.storage import load_json


def load_sessions(config):
    return load_json(config["SESSIONS_FILE"], {})
