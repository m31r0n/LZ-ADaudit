"""Attack-path graph engine (v1.6.0).

Generic, data-driven: builds a directed graph of AD principals + Tier-0
objects from any AuditData, runs shortest-path heuristics from low-tier
sources to high-tier targets, identifies choke points. Renders to SVG with
zero external dependencies and a strict CSP.

Key entry points:
  - build_attack_graph(data) -> AttackGraph
  - AttackGraph.top_paths(n)  -> list[Path]
  - AttackGraph.choke_points(n) -> list[(node, score)]
  - render_svg(graph)         -> str (inline SVG)
"""
from .model import Node, Edge, AttackGraph, NodeKind, EdgeKind, Tier
from .builder import build_attack_graph
from .svg import render_svg

__all__ = [
    "Node", "Edge", "AttackGraph", "NodeKind", "EdgeKind", "Tier",
    "build_attack_graph", "render_svg",
]
