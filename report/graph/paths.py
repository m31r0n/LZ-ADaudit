"""Shortest-path search + choke point analysis on AttackGraph.

No external graph libs. BFS up to MAX_DEPTH for tractability on 500-node
graphs (real AD audits rarely exceed that).
"""
from __future__ import annotations

from collections import deque

from .model import AttackGraph, Edge, Node, Path, Tier

MAX_DEPTH = 6     # avoid combinatorial explosion on noisy graphs
MAX_PATHS = 500   # cap the path list


def shortest_paths_to_tier0(graph: AttackGraph) -> list[Path]:
    """Return shortest paths from every low-tier source to every Tier-0 node.

    For each (source, target) pair we keep ONE shortest path. This produces
    a richer set of attack paths than "one per source" for visualization.
    """
    target_ids = {n.id for n in graph.tier0_targets()}
    if not target_ids:
        return []
    out: list[Path] = []
    for src in graph.low_tier_sources():
        # BFS from this source; collect every target it can reach
        for tgt_id in target_ids:
            path = _bfs_path(graph, src.id, {tgt_id})
            if path is not None:
                out.append(path)
            if len(out) >= MAX_PATHS:
                break
        if len(out) >= MAX_PATHS:
            break
    out.sort(key=lambda p: (p.length, p.total_cost))
    return out


def _bfs_path(graph: AttackGraph, src_id: str,
              target_ids: set[str]) -> Path | None:
    if src_id in target_ids:
        return None
    visited: set[str] = {src_id}
    # Each item: (current_id, list_of_node_ids_so_far, list_of_edges_so_far)
    queue: deque = deque([(src_id, [src_id], [])])
    while queue:
        node_id, npath, epath = queue.popleft()
        if len(epath) >= MAX_DEPTH:
            continue
        for nbr_id, edge in graph.neighbors(node_id):
            if nbr_id in visited:
                continue
            new_npath = npath + [nbr_id]
            new_epath = epath + [edge]
            if nbr_id in target_ids:
                return _materialize(graph, new_npath, new_epath)
            visited.add(nbr_id)
            queue.append((nbr_id, new_npath, new_epath))
    return None


def _materialize(graph: AttackGraph, node_ids: list[str],
                 edges: list[Edge]) -> Path:
    return Path(
        nodes=[graph.nodes[nid] for nid in node_ids if nid in graph.nodes],
        edges=edges,
    )


def choke_points(graph: AttackGraph, paths: list[Path],
                 top_n: int = 10) -> list[tuple[str, int]]:
    """Count node occurrences in shortest paths (excluding endpoints).

    A node with high count is a *choke point*: removing it (rotating its
    password, disabling, removing privilege) breaks many attack paths at once.
    """
    counter: dict[str, int] = {}
    for p in paths:
        for n in p.nodes[1:-1]:        # skip source + target endpoint
            counter[n.id] = counter.get(n.id, 0) + 1
    ranked = sorted(counter.items(), key=lambda x: -x[1])
    return ranked[:top_n]


def populate_analytics(graph: AttackGraph) -> None:
    """Compute paths + choke points + stats and store on the graph."""
    paths = shortest_paths_to_tier0(graph)
    graph.paths = paths
    graph.choke = choke_points(graph, paths)
    graph.stats = {
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "tier0_targets": len(graph.tier0_targets()),
        "total_paths": len(paths),
        "paths_le_3": sum(1 for p in paths if p.length <= 3),
        "paths_le_5": sum(1 for p in paths if p.length <= 5),
    }
