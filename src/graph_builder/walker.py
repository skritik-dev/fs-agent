import os
from datetime import datetime
from pathlib import Path
from typing import List, Literal
from dataclasses import dataclass, field
import hashlib

from security_kernel.kernel import is_path_denied
from security_kernel.path_utils import resolve_real_to_virtual, is_agent_memory
from security_kernel.config_loader import PermissionConfig

@dataclass
class FileNode:
    """Represents a file or folder in the workspace graph."""
    id: str
    virtual_path: str
    node_type: Literal["file", "folder"]
    extension: str
    size_bytes: int
    last_modified: datetime
    entity_tags: List[str] = field(default_factory=list)
    content_preview: str = ""


def walk_workspace(workspace_root: Path, config: PermissionConfig) -> List[FileNode]:
    """
    Traverses the workspace and returns a list of allowed FileNodes.

    Directories matching any denied pattern or flagged as agent memory are
    pruned in-place so os.walk never descends into them — this avoids
    scanning entire subtrees that would be discarded anyway.
    """
    nodes: List[FileNode] = []

    for root, dirs, files in os.walk(workspace_root):
        root_path = Path(root)

        allowed_dirs = []
        for dirname in dirs:
            dir_real = root_path / dirname
            try:
                dir_virtual = resolve_real_to_virtual(dir_real, workspace_root)
            except ValueError:
                continue   

            if is_path_denied(dir_virtual, config.denied_patterns):
                continue
            if is_agent_memory(dir_virtual):
                continue

            allowed_dirs.append(dirname)

            # Build folder node
            try:
                stat = dir_real.stat()
            except PermissionError:
                continue

            nodes.append(FileNode(
                id=hashlib.sha256(dir_virtual.encode('utf-8')).hexdigest(),
                virtual_path=dir_virtual,
                node_type="folder",
                extension="",
                size_bytes=0,
                last_modified=datetime.fromtimestamp(stat.st_mtime),
            ))

        dirs[:] = allowed_dirs

        for filename in files:
            file_real = root_path / filename
            try:
                file_virtual = resolve_real_to_virtual(file_real, workspace_root)
            except ValueError:
                continue

            if is_path_denied(file_virtual, config.denied_patterns):
                continue
            if is_agent_memory(file_virtual):
                continue

            try:
                stat = file_real.stat()
            except PermissionError:
                continue
            
            nodes.append(FileNode(
                id=hashlib.sha256(file_virtual.encode('utf-8')).hexdigest(),
                virtual_path=file_virtual,
                node_type="file",
                extension=file_real.suffix,
                size_bytes=stat.st_size,
                last_modified=datetime.fromtimestamp(stat.st_mtime),
                # TODO: Add entity_tags and content_preview
            ))

    return nodes

#? INPUT: workspace root
#? PROCESSING: Walk the workspace directory tree, apply security rules, build nodes
#? OUTPUT: List of FileNodes