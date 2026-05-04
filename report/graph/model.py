"""Data model for the attack-path graph.

Nodes and edges are *typed* enums so consumers (SVG renderer, JSON exporter,
XLSX summary, future BloodHound-compat output) can branch on them safely.
The graph itself is plain dicts/lists — no NetworkX, no external deps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    DC = "dc"
    DOMAIN = "domain"
    TEMPLATE = "template"
    OU = "ou"
    PSEUDO = "pseudo"  # synthetic source like "Authenticated Users"


class EdgeKind(str, Enum):
    MEMBER_OF = "MemberOf"
    DCSYNC = "DCSync"
    GENERIC_ALL = "GenericAll"
    WRITE_DACL = "WriteDACL"
    WRITE_OWNER = "WriteOwner"
    OWNS = "Owns"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    HAS_SPN_ROASTABLE = "HasSPN-Roastable"
    ASREP_ROASTABLE = "ASREP-Roastable"
    SHADOW_CREDENTIAL = "ShadowCredential"
    RBCD = "RBCD-Delegation"
    UNCONSTRAINED_DELEGATION = "UnconstrainedDelegation"
    ESC4_ENROLL = "ESC4-Enroll"
    ESC10_SPOOF = "ESC10-Spoof"
    GP_LINK = "GPLink"
    LOGON_SESSION = "HasSession"  # last-logon evidence


# Severity weight for path scoring. Lower edge cost = "easier" attack.
EDGE_COST: dict[EdgeKind, int] = {
    EdgeKind.MEMBER_OF: 1,
    EdgeKind.DCSYNC: 1,
    EdgeKind.GENERIC_ALL: 1,
    EdgeKind.WRITE_DACL: 1,
    EdgeKind.WRITE_OWNER: 1,
    EdgeKind.OWNS: 1,
    EdgeKind.FORCE_CHANGE_PASSWORD: 1,
    EdgeKind.HAS_SPN_ROASTABLE: 2,   # offline crack effort
    EdgeKind.ASREP_ROASTABLE: 2,
    EdgeKind.SHADOW_CREDENTIAL: 1,
    EdgeKind.RBCD: 2,
    EdgeKind.UNCONSTRAINED_DELEGATION: 2,
    EdgeKind.ESC4_ENROLL: 1,
    EdgeKind.ESC10_SPOOF: 2,
    EdgeKind.GP_LINK: 1,
    EdgeKind.LOGON_SESSION: 3,       # opportunistic only
}


class Tier(int, Enum):
    """Microsoft tier model + extras for graph visualisation.

    0 = Forest/Domain control (DA, EA, SA, DCs, Domain root, krbtgt, AdminSDHolder)
    1 = Server admins (Account/Backup/Server Operators, AdminCount=1 outside T0)
    2 = Workstation admins, helpdesk, GPO link rights to non-DC OUs
    3 = Regular user space (Authenticated Users, Domain Users)
    """
    T0 = 0
    T1 = 1
    T2 = 2
    T3 = 3


@dataclass
class Node:
    id: str                       # canonical, e.g. "user:diradmin" or "group:Domain Admins"
    label: str                    # display name
    kind: NodeKind
    tier: Tier = Tier.T3
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def is_tier0(self) -> bool:
        return self.tier == Tier.T0

    @property
    def short(self) -> str:
        # 18 char ellipsis for SVG labels
        return self.label if len(self.label) <= 18 else self.label[:16] + "…"


@dataclass
class Edge:
    src_id: str
    dst_id: str
    kind: EdgeKind
    evidence: str = ""            # raw line/source for traceability

    @property
    def cost(self) -> int:
        return EDGE_COST.get(self.kind, 1)


@dataclass
class Path:
    nodes: list[Node]
    edges: list[Edge]

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def total_cost(self) -> int:
        return sum(e.cost for e in self.edges)

    def signature(self) -> str:
        """Short string representation: 'src → kind → ... → tgt'."""
        if not self.nodes:
            return ""
        parts = [self.nodes[0].label]
        for n, e in zip(self.nodes[1:], self.edges):
            parts.append(f"={e.kind.value}=>")
            parts.append(n.label)
        return " ".join(parts)


@dataclass
class AttackGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    # Pre-computed analyses
    paths: list[Path] = field(default_factory=list)
    choke: list[tuple[str, int]] = field(default_factory=list)  # node_id, score
    # Stats for the report header
    stats: dict[str, int] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
        else:
            # Merge attrs but keep highest tier (T0 wins over T3)
            existing = self.nodes[node.id]
            if node.tier.value < existing.tier.value:
                existing.tier = node.tier
            existing.attrs.update(node.attrs)

    def add_edge(self, edge: Edge) -> None:
        # Skip dup edges (same src+dst+kind)
        for existing in self.edges:
            if (existing.src_id == edge.src_id and
                existing.dst_id == edge.dst_id and
                existing.kind == edge.kind):
                return
        # Only add if both endpoints exist as nodes
        if edge.src_id in self.nodes and edge.dst_id in self.nodes:
            self.edges.append(edge)

    def neighbors(self, node_id: str) -> list[tuple[str, Edge]]:
        """Out-neighbors of a node."""
        return [(e.dst_id, e) for e in self.edges if e.src_id == node_id]

    def tier0_targets(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.is_tier0]

    def low_tier_sources(self) -> list[Node]:
        """Pseudo + Tier-3 + Tier-2 nodes used as path sources."""
        return [n for n in self.nodes.values()
                if n.tier in (Tier.T2, Tier.T3) or n.kind == NodeKind.PSEUDO]
