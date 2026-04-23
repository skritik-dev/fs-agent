import yaml
from pathlib import Path
from typing import List
from pydantic import BaseModel, ValidationError

class PermissionConfig(BaseModel):
    """Schema for permissions.yaml."""
    allowed_roots: List[str]
    denied_patterns: List[str]
    allowed_operations: List[str]

def load_config(config_path: str | Path) -> PermissionConfig:
    """Loads and validates the permissions configuration.

    Raises:
        FileNotFoundError: If the config file does not exist at the given path.
        ValidationError: If the YAML content does not satisfy the PermissionConfig schema.
    """
    config_path = Path(config_path)

    if not config_path.is_file():
        raise FileNotFoundError(
            f"Security config not found at '{config_path}'. "
            "The agent cannot start without an explicit permissions file."
        )

    with config_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    return PermissionConfig.model_validate(raw)

#? INPUT: permissions.yaml
#? PROCESSING: yaml_parser -> validate -> PermissionConfig object
#? OUTPUT: PermissionConfig object