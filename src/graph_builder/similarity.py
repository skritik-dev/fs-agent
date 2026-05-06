import itertools
import networkx as nx
from typing import Set

def calculate_jaccard_similarity(tags_a: Set[str], tags_b: Set[str]) -> float:
    """
    Calculates the Jaccard similarity index between two sets of tags.
    Formula: Intersection size divided by Union size.
    """

    # If both sets of tags are empty, return 0.0 to avoid division by zero
    if not tags_a and not tags_b:
        return 0.0

    # Finding the jaccard index to find the similarity between two sets
    return len(tags_a & tags_b) / len(tags_a | tags_b)

# TODO: Tune the threshold
def add_similarity_edges(G: nx.DiGraph, threshold: float = 0.25) -> None:
    """
    Mutates the graph in-place, adding 'similar_to' edges between file nodes
    that have a Jaccard similarity >= threshold.
    """ 
    # Extract all file nodes (folders are structural, files are semantic)
    file_nodes = [(node_id, set(attrs["data"].entity_tags)) for node_id, attrs in G.nodes(data=True) if attrs.get("data") and attrs["data"].node_type == "file"]
    
    for (id_a, tags_a), (id_b, tags_b) in itertools.combinations(file_nodes, 2):
        score = calculate_jaccard_similarity(tags_a, tags_b)
        
        # Add bidirectional edges so undirected ego_graph traversal can cross from either side
        if score >= threshold:
            G.add_edge(id_a, id_b, relationship="similar_to", weight=score)
            G.add_edge(id_b, id_a, relationship="similar_to", weight=score)