from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)
VIRTUAL_ROOT = "/workspace"

def resolve_virtual_to_real(virtual_path: str, workspace_root: Path) -> Path:
    """
    Converts a virtual path (e.g., '/workspace/reports/q1.pdf') 
    into an absolute, real OS path (e.g., '/Users/name/Downloads/reports/q1.pdf').
    """

    if virtual_path != VIRTUAL_ROOT and not virtual_path.startswith(f"{VIRTUAL_ROOT}/"):
        logger.error(f"Invalid virtual path '{virtual_path}': must start with '{VIRTUAL_ROOT}'.")
        raise ValueError(f"Invalid virtual path '{virtual_path}': must start with '{VIRTUAL_ROOT}'.")
    
    relative_part = virtual_path[len(VIRTUAL_ROOT):].lstrip("/")
    real_path = workspace_root / relative_part
    return real_path.resolve()


def resolve_real_to_virtual(real_path: Path, workspace_root: Path) -> str:
    """
    Converts a real OS path back into a virtual path string for the LLM.
    """
    
    abs_real = real_path.resolve()
    abs_root = workspace_root.resolve()
    if not abs_real.is_relative_to(abs_root):
        logger.error(f"Path '{real_path}' is outside workspace root '{workspace_root}'.")
        raise ValueError(f"Path '{real_path}' is outside workspace root '{workspace_root}'.")

    relative_part = abs_real.relative_to(abs_root)

    virtual_rel = relative_part.as_posix()
    if virtual_rel == ".":
        return VIRTUAL_ROOT
    return f"{VIRTUAL_ROOT}/{virtual_rel}"

def has_traversal(virtual_path: str) -> bool:
    """
    Checks if a virtual path contains directory traversal attempts (e.g., '..').
    Returns True if traversal is detected, False otherwise.
    """
    return ".." in Path(virtual_path).parts

def in_allowed_root(real_path: Path, workspace_root: Path) -> bool:
    """
    Verifies that a real OS path is strictly within the allowed workspace root.
    Returns True if safe, False if it escapes the root.
    """
    abs_real = real_path.resolve(strict=False)
    abs_root = workspace_root.resolve(strict=False)
    return abs_real.is_relative_to(abs_root)

#? INPUT: virtual path or real path
#? PROCESSING: check path safety / translate
#? OUTPUT: boolean / virtual path or real path