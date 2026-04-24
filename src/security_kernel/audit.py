import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict

def log_audit_event(audit_file: Path, operation: str, virtual_path: str, result: str, details: Dict[str, Any] = None) -> None:
    """
    Appends a kernel evaluation event to the security audit log.
    """
    payload: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "path": virtual_path,
        "result": result,
        "details": details or {},
    }
    
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    with audit_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")