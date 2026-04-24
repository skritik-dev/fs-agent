import pytest
from pathlib import Path

from security_kernel.path_utils import (
    resolve_virtual_to_real,
    resolve_real_to_virtual,
    has_traversal,
    in_allowed_root,
    is_agent_memory,
)
from security_kernel.kernel import is_operation_allowed, is_path_denied


class TestResolveVirtualToReal:
    def test_basic_file(self, tmp_path):
        result = resolve_virtual_to_real("/workspace/reports/q1.pdf", tmp_path)
        assert result == (tmp_path / "reports" / "q1.pdf").resolve()

    def test_workspace_root_itself(self, tmp_path):
        result = resolve_virtual_to_real("/workspace", tmp_path)
        assert result == tmp_path.resolve()

    def test_nested_path(self, tmp_path):
        result = resolve_virtual_to_real("/workspace/a/b/c/file.txt", tmp_path)
        assert result == (tmp_path / "a" / "b" / "c" / "file.txt").resolve()

    def test_invalid_prefix_raises(self, tmp_path):
        with pytest.raises(ValueError, match="must start with"):
            resolve_virtual_to_real("/not_workspace/file.txt", tmp_path)

    def test_bare_string_raises(self, tmp_path):
        with pytest.raises(ValueError):
            resolve_virtual_to_real("reports/q1.pdf", tmp_path)

    def test_no_double_traversal_in_output(self, tmp_path):
        # resolve() collapses any remaining '..' — result must be under tmp_path
        result = resolve_virtual_to_real("/workspace/sub/file.txt", tmp_path)
        assert result.is_relative_to(tmp_path.resolve())


class TestResolveRealToVirtual:
    def test_basic_file(self, tmp_path):
        real = tmp_path / "reports" / "q1.pdf"
        assert resolve_real_to_virtual(real, tmp_path) == "/workspace/reports/q1.pdf"

    def test_workspace_root_itself(self, tmp_path):
        assert resolve_real_to_virtual(tmp_path, tmp_path) == "/workspace"

    def test_nested_path(self, tmp_path):
        real = tmp_path / "a" / "b" / "c.txt"
        assert resolve_real_to_virtual(real, tmp_path) == "/workspace/a/b/c.txt"

    def test_outside_root_raises(self, tmp_path):
        outside = tmp_path.parent / "other_file.txt"
        with pytest.raises(ValueError, match="outside workspace root"):
            resolve_real_to_virtual(outside, tmp_path)

    def test_forward_slashes_on_windows(self, tmp_path):
        # Must always return POSIX-style virtual path, even on Windows
        real = tmp_path / "deep" / "nested" / "file.log"
        result = resolve_real_to_virtual(real, tmp_path)
        assert "\\" not in result
        assert result.startswith("/workspace/")

    def test_roundtrip(self, tmp_path):
        virtual = "/workspace/data/file.csv"
        real = resolve_virtual_to_real(virtual, tmp_path)
        assert resolve_real_to_virtual(real, tmp_path) == virtual


class TestHasTraversal:
    def test_clean_path_is_safe(self):
        assert has_traversal("/workspace/reports/q1.pdf") is False

    def test_dotdot_component_detected(self):
        assert has_traversal("/workspace/../etc/passwd") is True

    def test_dotdot_at_end(self):
        assert has_traversal("/workspace/reports/..") is True

    def test_double_dot_in_filename_is_safe(self):
        # 'data..csv' is NOT a traversal — the dots are part of the filename
        assert has_traversal("/workspace/data..csv") is False

    def test_single_dot_component_is_safe(self):
        assert has_traversal("/workspace/./reports/q1.pdf") is False

    def test_workspace_root_safe(self):
        assert has_traversal("/workspace") is False


class TestInAllowedRoot:
    def test_file_inside_root(self, tmp_path):
        target = tmp_path / "subdir" / "file.txt"
        assert in_allowed_root(target, tmp_path) is True

    def test_root_itself(self, tmp_path):
        assert in_allowed_root(tmp_path, tmp_path) is True

    def test_file_outside_root(self, tmp_path):
        outside = tmp_path.parent / "sibling_file.txt"
        assert in_allowed_root(outside, tmp_path) is False

    def test_parent_directory_is_outside(self, tmp_path):
        assert in_allowed_root(tmp_path.parent, tmp_path) is False

    def test_nonexistent_nested_file_still_validates(self, tmp_path):
        # strict=False — file doesn't need to exist
        target = tmp_path / "ghost" / "phantom.txt"
        assert in_allowed_root(target, tmp_path) is True


class TestIsOperationAllowed:
    ALLOWED = ["read", "move", "copy"]

    def test_allowed_operation(self):
        assert is_operation_allowed("read", self.ALLOWED) is True

    def test_denied_operation(self):
        assert is_operation_allowed("delete", self.ALLOWED) is False

    def test_case_insensitive_upper(self):
        assert is_operation_allowed("MOVE", self.ALLOWED) is True

    def test_case_insensitive_mixed(self):
        assert is_operation_allowed("Copy", self.ALLOWED) is True

    def test_empty_allowed_list(self):
        assert is_operation_allowed("read", []) is False

    def test_partial_match_is_denied(self):
        # 'rea' is not 'read'
        assert is_operation_allowed("rea", self.ALLOWED) is False


class TestIsPathDenied:
    PATTERNS = ["*.exe", ".git/*", "secrets.env", "*.env"]

    def test_exe_blocked(self):
        assert is_path_denied("/workspace/malware.exe", self.PATTERNS) is True

    def test_env_file_blocked(self):
        assert is_path_denied("/workspace/secrets.env", self.PATTERNS) is True

    def test_dotenv_pattern_blocked(self):
        assert is_path_denied("/workspace/.production.env", self.PATTERNS) is True

    def test_safe_file_allowed(self):
        assert is_path_denied("/workspace/reports/q1.pdf", self.PATTERNS) is False

    def test_empty_deny_list_allows_all(self):
        assert is_path_denied("/workspace/malware.exe", []) is False

    def test_git_config_blocked(self):
        assert is_path_denied("/workspace/.git/config", self.PATTERNS) is True

    def test_git_root_dir_not_matched_by_subpath_pattern(self):
        # '.git/*' should not match '/workspace/.git' itself (no child component)
        assert is_path_denied("/workspace/.git", ["*/.git/*"]) is False


class TestIsAgentMemory:
    def test_vault_root_blocked(self):
        assert is_agent_memory("/workspace/.vault") is True

    def test_vault_child_blocked(self):
        assert is_agent_memory("/workspace/.vault/keys/master.key") is True

    def test_snapshots_blocked(self):
        assert is_agent_memory("/workspace/.snapshots/snap_001.json") is True

    def test_checkpoints_blocked(self):
        assert is_agent_memory("/workspace/.checkpoints/ckpt_42") is True

    def test_vault_copy_is_safe(self):
        # '.vault_copy' is NOT a protected directory
        assert is_agent_memory("/workspace/.vault_copy/file.txt") is False

    def test_normal_file_is_safe(self):
        assert is_agent_memory("/workspace/reports/q1.pdf") is False

    def test_workspace_root_is_safe(self):
        assert is_agent_memory("/workspace") is False

    def test_non_workspace_path_is_safe(self):
        # Falls through the ValueError branch — non-workspace path is not memory
        assert is_agent_memory("/somewhere/.vault/key") is False
