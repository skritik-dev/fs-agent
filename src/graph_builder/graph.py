import hashlib
from pathlib import Path
from typing import Any, Dict, List

import networkx as nx

from graph_builder.walker import FileNode

def build_graph(nodes: List[FileNode]) -> nx.DiGraph:
    """
    Builds a directed graph representing the file system hierarchy.

    Each node's graph ID is the SHA-256 hash of its virtual_path (already
    computed in walker.py as FileNode.id).  A 'contains' edge is drawn from
    every parent folder to each of its direct children.
    """
    G = nx.DiGraph()

    # virtual_path -> SHA-256 id lookup (avoids re-hashing during edge phase)
    path_to_id: Dict[str, str] = {node.virtual_path: node.id for node in nodes}

    # Add all nodes first so edges can always resolve both endpoints
    for node in nodes:
        G.add_node(
            node.id,
            data=node,
        )

    # Establish 'contains' edges (parent_folder -> child)
    for node in nodes:
        if node.virtual_path == "/workspace":
            continue

        parent_virtual = Path(node.virtual_path).parent.as_posix()
        parent_id = path_to_id.get(parent_virtual)

        if parent_id is not None:
            G.add_edge(parent_id, node.id, relationship="contains")

    return G


def get_subgraph(G: nx.DiGraph, center_node_id: str, radius: int = 2) -> nx.DiGraph:
    """
    Extracts a localized subgraph around a specific node.

    Uses undirected traversal so the ego graph walks both up to ancestor
    folders and down into sibling files — giving the LLM full local context
    without loading the entire workspace graph.
    """
    return nx.ego_graph(G, center_node_id, radius=radius, undirected=True)


def graph_to_dict(G: nx.DiGraph) -> Dict[str, Any]:
    """
    Serializes a NetworkX graph into a plain dictionary.

    Output is 100% JSON-serializable so it can be stored in LangGraph's
    AgentState and persisted by the SqliteSaver checkpointer.
    FileNode objects in node data are converted to dicts before serialization.
    """
    # Temporarily replace FileNode objects with plain dicts for serialization
    serializable = nx.DiGraph()
    for node_id, attrs in G.nodes(data=True):
        node: FileNode = attrs.get("data")
        serializable.add_node(
            node_id,
            data={
                "id": node.id,
                "virtual_path": node.virtual_path,
                "node_type": node.node_type,
                "extension": node.extension,
                "size_bytes": node.size_bytes,
                "last_modified": node.last_modified.isoformat(),
                "entity_tags": node.entity_tags,
                "content_preview": node.content_preview,
            } if node else attrs,
        )
    for u, v, edge_attrs in G.edges(data=True):
        serializable.add_edge(u, v, **edge_attrs)

    return nx.node_link_data(serializable)


#? INPUT: List[FileNode] / nx.DiGraph + center node id / nx.DiGraph
#? PROCESSING: build hierarchy graph / extract ego subgraph / serialize to dict
#? OUTPUT: nx.DiGraph / nx.DiGraph subgraph / JSON-serializable dict
