from typing import List
from pathlib import Path

def is_operation_allowed(operation: str, allowed_ops: List[str]) -> bool:
    """
    Checks if the requested file operation is in the whitelist.
    """
    return operation.lower() in [op.lower() for op in allowed_ops]

def is_path_denied(virtual_path: str, denied_patterns: List[str]) -> bool:
    """
    Checks if a virtual path matches any glob patterns in the deny list.
    Returns True if the path is blocked, False if it is safe.
    """
    return any(Path(virtual_path).match(pattern) for pattern in denied_patterns)