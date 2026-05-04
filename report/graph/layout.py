"""Radial-by-tier layout for AttackGraph nodes — pure stdlib.

Each tier is a concentric ring. Nodes inside a ring distribute evenly by
angle, ordered alphabetically for determinism (so the same data always
produces the same picture). No physics simulation, no external lib.
"""
from __future__ import annotations

import math

from .model import AttackGraph, Tier

# Canvas geometry (SVG viewBox uses these — feel free to scale in renderer)
CENTER_X = 500
CENTER_Y = 380
RADII = {
    Tier.T0: 80,
    Tier.T1: 200,
    Tier.T2: 320,
    Tier.T3: 440,
}
NODE_R = 18
LABEL_OFFSET = 26


def compute_positions(graph: AttackGraph) -> dict[str, tuple[float, float]]:
    """Return {node_id: (x, y)} for every node in the graph."""
    by_tier: dict[Tier, list[str]] = {t: [] for t in Tier}
    for node in graph.nodes.values():
        by_tier[node.tier].append(node.id)
    # Alphabetic stability
    for t in by_tier:
        by_tier[t].sort(key=lambda nid: graph.nodes[nid].label.lower())
    out: dict[str, tuple[float, float]] = {}
    for tier, nids in by_tier.items():
        if not nids:
            continue
        radius = RADII[tier]
        n = len(nids)
        for i, nid in enumerate(nids):
            # Spread nodes evenly. Skip a small gap at the top to avoid label
            # collisions with the (typical) DA group.
            angle = -math.pi / 2 + 2 * math.pi * i / max(n, 1)
            x = CENTER_X + radius * math.cos(angle)
            y = CENTER_Y + radius * math.sin(angle)
            out[nid] = (x, y)
    return out
