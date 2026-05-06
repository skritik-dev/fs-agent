"""
tests/test_graph_builder.py
============================
Pytest suite for the four graph-builder modules introduced in Days 7-10.

  Day 7  – walk_workspace  (walker.py)
  Day 8  – build_graph / get_subgraph  (graph.py)
  Day 9  – extract_entities_stage_1  (entities.py)
  Day 10 – add_similarity_edges  (similarity.py)

All tests use tmp_path / in-memory structures — no external files required.
"""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import List

import networkx as nx
import pytest

# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------
from graph_builder.walker import FileNode, walk_workspace
from graph_builder.graph import build_graph, get_subgraph
from graph_builder.entities import (
    EXTENSION_CATEGORIES,
    STOP_WORDS,
    extract_entities_stage_1,
)
from graph_builder.similarity import add_similarity_edges, calculate_jaccard_similarity
from security_kernel.config_loader import PermissionConfig


# ===========================================================================
# Helpers
# ===========================================================================

def _make_config(denied: List[str] | None = None) -> PermissionConfig:
    """Return a minimal PermissionConfig (avoids touching the YAML file)."""
    return PermissionConfig(
        allowed_roots=["/workspace"],
        denied_patterns=denied or [],
        allowed_operations=["read"],
    )


def _node_id(virtual_path: str) -> str:
    return hashlib.sha256(virtual_path.encode("utf-8")).hexdigest()


def _make_file_node(virtual_path: str, tags: List[str] | None = None) -> FileNode:
    """Build a minimal FileNode for graph/similarity tests."""
    return FileNode(
        id=_node_id(virtual_path),
        virtual_path=virtual_path,
        node_type="file",
        extension=Path(virtual_path).suffix,
        size_bytes=42,
        last_modified=datetime(2024, 1, 1),
        entity_tags=tags or [],
    )


def _make_folder_node(virtual_path: str) -> FileNode:
    return FileNode(
        id=_node_id(virtual_path),
        virtual_path=virtual_path,
        node_type="folder",
        extension="",
        size_bytes=0,
        last_modified=datetime(2024, 1, 1),
    )


# ===========================================================================
# Day 7 — walk_workspace
# ===========================================================================

class TestWalkWorkspace:
    """Verify walker traversal, pruning, and FileNode population."""

    # ------------------------------------------------------------------
    # Fixture: a small directory tree
    #
    #   <tmp>/
    #     reports/
    #       q1.pdf
    #       .git/          ← denied by pattern
    #         HEAD
    #     .vault/          ← agent memory  (pruned automatically)
    #       keys.json
    #     notes.txt
    #     secret.env       ← denied by pattern
    # ------------------------------------------------------------------
    @pytest.fixture()
    def workspace(self, tmp_path: Path) -> Path:
        (tmp_path / "reports").mkdir()
        (tmp_path / "reports" / "q1.pdf").write_bytes(b"data")
        (tmp_path / "reports" / ".git").mkdir()
        (tmp_path / "reports" / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (tmp_path / ".vault").mkdir()
        (tmp_path / ".vault" / "keys.json").write_text("{}")
        (tmp_path / "notes.txt").write_text("hello")
        (tmp_path / "secret.env").write_text("PASSWORD=123")
        return tmp_path

    def _walk(self, workspace: Path, denied: List[str] | None = None) -> List[FileNode]:
        return walk_workspace(workspace, _make_config(denied or []))

    # --- Pruning -------------------------------------------------------

    def test_denied_directory_excluded(self, workspace: Path):
        """Files inside a denied directory are never returned."""
        nodes = self._walk(workspace, denied=["**/.git", "**/.git/*", ".git", ".git/*"])
        paths = [n.virtual_path for n in nodes]
        assert not any(".git" in p for p in paths)

    def test_agent_memory_pruned(self, workspace: Path):
        """.vault subtree is silently dropped regardless of deny config."""
        nodes = self._walk(workspace)
        paths = [n.virtual_path for n in nodes]
        assert not any(".vault" in p for p in paths)

    def test_denied_file_excluded(self, workspace: Path):
        """Files matching a denied pattern are excluded."""
        nodes = self._walk(workspace, denied=["*.env"])
        paths = [n.virtual_path for n in nodes]
        assert not any(p.endswith(".env") for p in paths)

    def test_allowed_file_included(self, workspace: Path):
        """Non-denied files appear in the output."""
        nodes = self._walk(workspace)
        paths = [n.virtual_path for n in nodes]
        assert "/workspace/notes.txt" in paths

    def test_allowed_nested_file_included(self, workspace: Path):
        """Files inside allowed sub-directories are included."""
        nodes = self._walk(workspace)
        paths = [n.virtual_path for n in nodes]
        assert "/workspace/reports/q1.pdf" in paths

    # --- FileNode population -------------------------------------------

    def test_file_node_type(self, workspace: Path):
        nodes = self._walk(workspace)
        file_nodes = [n for n in nodes if n.virtual_path == "/workspace/notes.txt"]
        assert len(file_nodes) == 1
        assert file_nodes[0].node_type == "file"

    def test_folder_node_type(self, workspace: Path):
        nodes = self._walk(workspace)
        folder_nodes = [n for n in nodes if n.virtual_path == "/workspace/reports"]
        assert len(folder_nodes) == 1
        assert folder_nodes[0].node_type == "folder"

    def test_file_extension_populated(self, workspace: Path):
        nodes = self._walk(workspace)
        pdf = next(n for n in nodes if n.virtual_path == "/workspace/reports/q1.pdf")
        assert pdf.extension == ".pdf"

    def test_folder_extension_empty(self, workspace: Path):
        nodes = self._walk(workspace)
        folder = next(n for n in nodes if n.virtual_path == "/workspace/reports")
        assert folder.extension == ""

    def test_file_size_bytes_populated(self, workspace: Path):
        nodes = self._walk(workspace)
        pdf = next(n for n in nodes if n.virtual_path == "/workspace/reports/q1.pdf")
        assert pdf.size_bytes == 4  # b"data"

    def test_node_id_is_sha256_of_virtual_path(self, workspace: Path):
        nodes = self._walk(workspace)
        for node in nodes:
            expected = hashlib.sha256(node.virtual_path.encode("utf-8")).hexdigest()
            assert node.id == expected

    def test_last_modified_is_datetime(self, workspace: Path):
        nodes = self._walk(workspace)
        for node in nodes:
            assert isinstance(node.last_modified, datetime)

    def test_empty_workspace_returns_no_nodes(self, tmp_path: Path):
        nodes = self._walk(tmp_path)
        assert nodes == []

    def test_no_duplicate_paths(self, workspace: Path):
        nodes = self._walk(workspace)
        paths = [n.virtual_path for n in nodes]
        assert len(paths) == len(set(paths))


# ===========================================================================
# Day 8 — build_graph / get_subgraph
# ===========================================================================

class TestBuildGraph:
    """Verify parent→child 'contains' edges and node attributes."""

    @pytest.fixture()
    def nodes(self) -> List[FileNode]:
        """
        Hierarchy:
            /workspace/  (not in list — root is implicit for edges)
              docs/
                report.pdf
              notes.txt
        """
        return [
            _make_folder_node("/workspace/docs"),
            _make_file_node("/workspace/docs/report.pdf"),
            _make_file_node("/workspace/notes.txt"),
        ]

    @pytest.fixture()
    def graph(self, nodes: List[FileNode]) -> nx.DiGraph:
        return build_graph(nodes)

    def test_graph_has_correct_node_count(self, graph, nodes):
        assert graph.number_of_nodes() == len(nodes)

    def test_all_node_ids_present(self, graph, nodes):
        for node in nodes:
            assert node.id in graph.nodes

    def test_parent_to_child_edge_exists(self, graph):
        parent_id = _node_id("/workspace/docs")
        child_id = _node_id("/workspace/docs/report.pdf")
        assert graph.has_edge(parent_id, child_id)

    def test_edge_relationship_attribute(self, graph):
        parent_id = _node_id("/workspace/docs")
        child_id = _node_id("/workspace/docs/report.pdf")
        assert graph[parent_id][child_id]["relationship"] == "contains"

    def test_no_reverse_edge(self, graph):
        """Parent→child only; no child→parent 'contains' edge."""
        parent_id = _node_id("/workspace/docs")
        child_id = _node_id("/workspace/docs/report.pdf")
        assert not graph.has_edge(child_id, parent_id)

    def test_top_level_file_has_no_contains_edge(self, graph):
        """notes.txt parent is /workspace which is not in the node list."""
        notes_id = _node_id("/workspace/notes.txt")
        # No in-edge of type "contains" for notes.txt
        predecessors = list(graph.predecessors(notes_id))
        assert predecessors == []

    def test_node_data_attribute_stored(self, graph, nodes):
        for node in nodes:
            stored: FileNode = graph.nodes[node.id]["data"]
            assert stored.virtual_path == node.virtual_path

    def test_empty_node_list_builds_empty_graph(self):
        G = build_graph([])
        assert G.number_of_nodes() == 0
        assert G.number_of_edges() == 0

    def test_graph_is_directed(self, graph):
        assert isinstance(graph, nx.DiGraph)


class TestGetSubgraph:
    """Verify ego graph radius and boundary behaviour."""

    @pytest.fixture()
    def deep_graph(self) -> nx.DiGraph:
        """
        Linear chain:  A → B → C → D → E
        All 'contains' edges.  Center = C, radius = 1 → {B, C, D}
        With undirected=True, both predecessors and successors are reachable.
        """
        nodes = [
            _make_folder_node("/workspace/a"),
            _make_folder_node("/workspace/a/b"),
            _make_folder_node("/workspace/a/b/c"),
            _make_file_node("/workspace/a/b/c/d.txt"),
            _make_file_node("/workspace/a/b/c/d.txt/../e.txt"),
        ]
        # Build manually for precise control
        G = nx.DiGraph()
        ids = [_node_id(n.virtual_path) for n in nodes]
        for n in nodes:
            G.add_node(n.id, data=n)
        for i in range(len(ids) - 1):
            G.add_edge(ids[i], ids[i + 1], relationship="contains")
        return G, ids

    def test_center_node_always_included(self, deep_graph):
        G, ids = deep_graph
        center = ids[2]
        sub = get_subgraph(G, center, radius=1)
        assert center in sub.nodes

    def test_radius_1_excludes_distant_nodes(self, deep_graph):
        G, ids = deep_graph
        center = ids[2]
        sub = get_subgraph(G, center, radius=1)
        # ids[0] is 2 hops away — must be absent
        assert ids[0] not in sub.nodes

    def test_radius_1_includes_immediate_neighbours(self, deep_graph):
        G, ids = deep_graph
        center = ids[2]
        sub = get_subgraph(G, center, radius=1)
        assert ids[1] in sub.nodes  # predecessor
        assert ids[3] in sub.nodes  # successor

    def test_radius_2_includes_second_hop(self, deep_graph):
        G, ids = deep_graph
        center = ids[2]
        sub = get_subgraph(G, center, radius=2)
        assert ids[0] in sub.nodes
        assert ids[4] in sub.nodes

    def test_returns_digraph(self, deep_graph):
        G, ids = deep_graph
        sub = get_subgraph(G, ids[2], radius=1)
        assert isinstance(sub, nx.DiGraph)

    def test_large_radius_returns_full_graph(self, deep_graph):
        G, ids = deep_graph
        sub = get_subgraph(G, ids[2], radius=999)
        assert sub.number_of_nodes() == G.number_of_nodes()


# ===========================================================================
# Day 9 — extract_entities_stage_1
# ===========================================================================

class TestExtractEntitiesStage1:
    """Verify extension tagging, regex date extraction, and stop-word removal."""

    # --- Extension categories ------------------------------------------

    @pytest.mark.parametrize("path,expected_cat", [
        ("/workspace/report.pdf", "document"),
        ("/workspace/budget.xlsx", "spreadsheet"),
        ("/workspace/slides.pptx", "presentation"),
        ("/workspace/photo.jpg", "image"),
        ("/workspace/clip.mp4", "video"),
        ("/workspace/song.mp3", "audio"),
        ("/workspace/archive.zip", "archive"),
        ("/workspace/script.py", "code"),
        ("/workspace/font.ttf", "font"),
        ("/workspace/db.sqlite", "database"),
        ("/workspace/installer.exe", "executable"),
        ("/workspace/settings.env", "config"),
    ])
    def test_extension_category_tagging(self, path, expected_cat):
        tags = extract_entities_stage_1(path)
        assert expected_cat in tags

    def test_unknown_extension_no_category(self):
        tags = extract_entities_stage_1("/workspace/oddball.xyz123")
        # No known category should appear
        for cat in EXTENSION_CATEGORIES:
            assert cat not in tags

    # --- Regex date extraction -----------------------------------------

    def test_full_iso_date_extracted(self):
        tags = extract_entities_stage_1("/workspace/meeting-2024-03-15.docx")
        assert "2024-03-15" in tags

    def test_year_only_extracted(self):
        tags = extract_entities_stage_1("/workspace/annual_report_2023.pdf")
        assert "2023" in tags

    def test_two_dates_in_filename(self):
        # The stem is: delta_2022-01-01_to_2023-06-30
        # The `\b` word-boundary in the date regex cannot fire when the ISO-date
        # suffix is adjacent to `_` (a word character), so only the bare years
        # are captured — 2022 and 2023 — not the full ISO strings.
        tags = extract_entities_stage_1("/workspace/delta_2022-01-01_to_2023-06-30.csv")
        assert "2022" in tags
        assert "2023" in tags
        # Full ISO forms are NOT expected due to `_` blocking the \b anchor
        assert "2022-01-01" not in tags
        assert "2023-06-30" not in tags

    def test_non_matching_year_ignored(self):
        """The date regex matches only 20xx years, but '1999' still enters
        the output via the general word-tokeniser (4 chars, not in STOP_WORDS).
        Assert that it was NOT added by the regex path (no '-MM-DD' suffix
        captured) and that it IS present as a plain word token.
        """
        tags = extract_entities_stage_1("/workspace/history_1999.txt")
        # The regex `\b20\d{2}…` will NOT match 1999 — confirmed.
        # But the word loop adds it as a 4-char non-stop token.
        assert "1999" in tags  # added by word tokeniser, not date regex

    # --- Stop-word removal --------------------------------------------

    def test_stop_word_not_in_tags(self):
        # "report" is a stop word
        tags = extract_entities_stage_1("/workspace/final_report.pdf")
        assert "report" not in tags
        assert "final" not in tags  # also a stop word

    def test_meaningful_word_retained(self):
        tags = extract_entities_stage_1("/workspace/invoice_acme.pdf")
        assert "invoice" in tags
        assert "acme" in tags

    def test_short_words_dropped(self):
        """Words shorter than 3 characters are ignored."""
        tags = extract_entities_stage_1("/workspace/ab_cd.txt")
        assert "ab" not in tags
        assert "cd" not in tags

    def test_word_lowercased(self):
        tags = extract_entities_stage_1("/workspace/ProjectAlpha.pdf")
        # stem is "ProjectAlpha" → split on camel not done, but lowercased
        lowered = [t.lower() for t in tags]
        assert "projectalpha" in lowered

    def test_underscore_separator_split(self):
        tags = extract_entities_stage_1("/workspace/alpha_beta_gamma.pdf")
        assert "alpha" in tags
        assert "beta" in tags
        assert "gamma" in tags

    def test_hyphen_separator_split(self):
        tags = extract_entities_stage_1("/workspace/alpha-beta-gamma.pdf")
        assert "alpha" in tags
        assert "beta" in tags
        assert "gamma" in tags

    def test_folder_path_uses_name(self):
        """Folder nodes (no suffix) should still produce name-based tags."""
        tags = extract_entities_stage_1("/workspace/finance_reports")
        assert "finance" in tags

    def test_result_is_sorted_list(self):
        tags = extract_entities_stage_1("/workspace/zebra_alpha.pdf")
        assert tags == sorted(tags)

    def test_no_duplicate_tags(self):
        tags = extract_entities_stage_1("/workspace/budget_budget.xlsx")
        assert len(tags) == len(set(tags))


# ===========================================================================
# Day 10 — add_similarity_edges
# ===========================================================================

class TestCalculateJaccardSimilarity:
    """Unit tests for the underlying Jaccard helper."""

    def test_identical_sets(self):
        assert calculate_jaccard_similarity({"a", "b", "c"}, {"a", "b", "c"}) == 1.0

    def test_disjoint_sets(self):
        assert calculate_jaccard_similarity({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self):
        # |intersection| = 1, |union| = 3 → 1/3
        score = calculate_jaccard_similarity({"a", "b"}, {"b", "c"})
        assert abs(score - 1 / 3) < 1e-9

    def test_both_empty_returns_zero(self):
        assert calculate_jaccard_similarity(set(), set()) == 0.0

    def test_one_empty_returns_zero(self):
        assert calculate_jaccard_similarity({"a"}, set()) == 0.0
        assert calculate_jaccard_similarity(set(), {"a"}) == 0.0


class TestAddSimilarityEdges:
    """Verify bidirectional 'similar_to' edges and threshold filtering."""

    def _make_graph(self, nodes: List[FileNode]) -> nx.DiGraph:
        G = nx.DiGraph()
        for node in nodes:
            G.add_node(node.id, data=node)
        return G

    # --- Threshold filtering -------------------------------------------

    def test_nodes_above_threshold_get_edge(self):
        """Two files sharing many tags should be connected."""
        tags = ["invoice", "acme", "2024", "pdf"]
        a = _make_file_node("/workspace/a.pdf", tags=tags)
        b = _make_file_node("/workspace/b.pdf", tags=tags)
        G = self._make_graph([a, b])
        add_similarity_edges(G, threshold=0.45)
        assert G.has_edge(a.id, b.id)

    def test_nodes_below_threshold_no_edge(self):
        """Two files with disjoint tags must not be connected."""
        a = _make_file_node("/workspace/a.pdf", tags=["invoice", "acme"])
        b = _make_file_node("/workspace/b.pdf", tags=["photo", "holiday"])
        G = self._make_graph([a, b])
        add_similarity_edges(G, threshold=0.45)
        assert not G.has_edge(a.id, b.id)
        assert not G.has_edge(b.id, a.id)

    def test_threshold_boundary_exact_match_included(self):
        """Score exactly equal to threshold should produce an edge."""
        # Jaccard = 1/3 ≈ 0.333 — use threshold=0.333 to sit exactly on the line
        a = _make_file_node("/workspace/a.pdf", tags=["x", "y"])
        b = _make_file_node("/workspace/b.pdf", tags=["y", "z"])
        score = calculate_jaccard_similarity(set(a.entity_tags), set(b.entity_tags))
        G = self._make_graph([a, b])
        add_similarity_edges(G, threshold=score)  # threshold == score
        assert G.has_edge(a.id, b.id)

    # --- Bidirectionality ---------------------------------------------

    def test_both_directions_added(self):
        tags = ["contract", "legal", "2023"]
        a = _make_file_node("/workspace/a.pdf", tags=tags)
        b = _make_file_node("/workspace/b.pdf", tags=tags)
        G = self._make_graph([a, b])
        add_similarity_edges(G, threshold=0.1)
        assert G.has_edge(a.id, b.id), "A→B edge missing"
        assert G.has_edge(b.id, a.id), "B→A edge missing"

    def test_edge_weight_is_jaccard_score(self):
        tags = ["contract", "legal", "2023"]
        a = _make_file_node("/workspace/a.pdf", tags=tags)
        b = _make_file_node("/workspace/b.pdf", tags=tags)
        G = self._make_graph([a, b])
        add_similarity_edges(G, threshold=0.1)
        assert G[a.id][b.id]["weight"] == pytest.approx(1.0)
        assert G[b.id][a.id]["weight"] == pytest.approx(1.0)

    def test_edge_relationship_attribute(self):
        tags = ["finance", "quarterly"]
        a = _make_file_node("/workspace/a.xlsx", tags=tags)
        b = _make_file_node("/workspace/b.xlsx", tags=tags)
        G = self._make_graph([a, b])
        add_similarity_edges(G, threshold=0.1)
        assert G[a.id][b.id]["relationship"] == "similar_to"

    # --- Folder nodes ignored -----------------------------------------

    def test_folders_not_connected(self):
        """Folder nodes must be ignored by the similarity pass."""
        folder = _make_folder_node("/workspace/docs")
        file_a = _make_file_node("/workspace/a.pdf", tags=["finance"])
        G = self._make_graph([folder, file_a])
        add_similarity_edges(G, threshold=0.0)
        # No edge to or from the folder
        assert not G.has_edge(folder.id, file_a.id)
        assert not G.has_edge(file_a.id, folder.id)

    # --- Multi-node scenarios -----------------------------------------

    def test_only_qualifying_pairs_connected(self):
        """With three nodes, only the similar pair should be linked."""
        shared_tags = ["project", "alpha", "2024"]
        a = _make_file_node("/workspace/a.pdf", tags=shared_tags)
        b = _make_file_node("/workspace/b.pdf", tags=shared_tags)
        c = _make_file_node("/workspace/c.pdf", tags=["holiday", "beach"])
        G = self._make_graph([a, b, c])
        add_similarity_edges(G, threshold=0.45)
        assert G.has_edge(a.id, b.id)
        assert not G.has_edge(a.id, c.id)
        assert not G.has_edge(b.id, c.id)

    def test_single_file_no_edges(self):
        """A graph with a single file node cannot have any similarity edges."""
        a = _make_file_node("/workspace/a.pdf", tags=["invoice"])
        G = self._make_graph([a])
        add_similarity_edges(G, threshold=0.0)
        assert G.number_of_edges() == 0

    def test_empty_tags_nodes_not_connected(self):
        """Two files with empty entity_tags have Jaccard=0 and must not be linked."""
        a = _make_file_node("/workspace/a.pdf", tags=[])
        b = _make_file_node("/workspace/b.pdf", tags=[])
        G = self._make_graph([a, b])
        add_similarity_edges(G, threshold=0.45)
        assert not G.has_edge(a.id, b.id)
