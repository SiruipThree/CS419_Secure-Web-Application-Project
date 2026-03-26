"""Document storage service skeleton.

Implement encrypted upload, download authorization, metadata persistence,
versioning, and audit hooks in this module.
"""

from secure_app.storage import load_json


def load_documents(config):
    return load_json(config["DOCUMENTS_FILE"], [])
