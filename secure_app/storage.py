import json #for read and write json file
import tempfile # temporary file for atomic write
from pathlib import Path
from typing import Any

#TODO: data storage and logging, read and write json file 

#TODO: define dafult json list 
DEFAULT_JSON_FILES = {
    "USERS_FILE": {},
    "RATE_LIMITS_FILE": {},
    "SESSIONS_FILE": {},
    "DOCUMENTS_FILE": [],
    "SHARES_FILE": [],
    "AUDIT_FILE": [],
}
#if the file does not exist, create it with default value, if exist, do nothing

#ensure the json file is exist
def _ensure_json_file(path: Path, default_value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps(default_value, indent=2), encoding="utf-8")

#initial the storage
def bootstrap_storage(config: dict[str, Any]) -> None:
    config["DATA_DIR"].mkdir(parents=True, exist_ok=True)
    config["DOCUMENT_STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    config["UPLOAD_STAGING_DIR"].mkdir(parents=True, exist_ok=True)
    config["LOG_DIR"].mkdir(parents=True, exist_ok=True)

    for key, default_value in DEFAULT_JSON_FILES.items():
        _ensure_json_file(config[key], default_value)

    for log_file in ("SECURITY_LOG_FILE", "ACCESS_LOG_FILE"):
        Path(config[log_file]).touch(exist_ok=True)

#load json 
def load_json(path: Path, default_value: Any) -> Any:
    if not path.exists():
        return default_value
    return json.loads(path.read_text(encoding="utf-8"))

#TODO: save 
    #make sure path parent exist first. 
def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as temp_file:
        temp_file.write(serialized)
        temp_path = Path(temp_file.name)
    temp_path.replace(path)
