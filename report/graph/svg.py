"""SVG renderer for AttackGraph — zero JS, zero external deps.

Produces a self-contained <svg> with concentric rings (one per tier),
nodes coloured by NodeKind, edges coloured by EdgeKind, and CSS hover
tooltips for interactivity. Critical paths (length ≤ 3 to Tier 0) are
drawn in red on top.
"""
from __future__ import annotations

from .layout import (
    CENTER_X, CENTER_Y, LABEL_OFFSET, NODE_R, RADII, compute_positions,
)
from .model import AttackGraph, EdgeKind, NodeKind, Tier

# Colour palette — consistent with the rest of the report
NODE_FILL = {
    NodeKind.USER:     "#e74c3c",
    NodeKind.GROUP:    "#9b59b6",
    NodeKind.COMPUTER: "#3498db",
    NodeKind.DC:       "#c0392b",
    NodeKind.DOMAIN:   "#8b0000",
    NodeKind.TEMPLATE: "#f39c12",
    NodeKind.OU:       "#1abc9c",
    NodeKind.PSEUDO:   "#7f849c",
}
TIER_RING = {
    Tier.T0: "#5a0f0f",
    Tier.T1: "#3a2a0a",
    Tier.T2: "#1a3a3a",
    Tier.T3: "#1a2035",
}
EDGE_COLOR = {
    EdgeKind.MEMBER_OF:               "#7f849c",
    EdgeKind.DCSYNC:                  "#e74c3c",
    EdgeKind.GENERIC_ALL:             "#c0392b",
    EdgeKind.WRITE_DACL:              "#c0392b",
    EdgeKind.WRITE_OWNER:             "#c0392b",
    EdgeKind.OWNS:                    "#c0392b",
    EdgeKind.FORCE_CHANGE_PASSWORD:   "#e67e22",
    EdgeKind.HAS_SPN_ROASTABLE:       "#f39c12",
    EdgeKind.ASREP_ROASTABLE:         "#f39c12",
    EdgeKind.SHADOW_CREDENTIAL:       "#9b59b6",
    EdgeKind.RBCD:                    "#e67e22",
    EdgeKind.UNCONSTRAINED_DELEGATION:"#e74c3c",
    EdgeKind.ESC4_ENROLL:             "#f39c12",
    EdgeKind.ESC10_SPOOF:             "#f39c12",
    EdgeKind.GP_LINK:                 "#3498db",
    EdgeKind.LOGON_SESSION:           "#7f849c",
}
WIDTH = 1000
HEIGHT = 760


def _h(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                  .replace(">", "&gt;").replace('"', "&quot;"))


def render_svg(graph: AttackGraph) -> str:
    if not graph.nodes:
        return ('<div class="dim small">'
                'No hay datos suficientes para construir el grafo de ataque.</div>')

    pos = compute_positions(graph)
    parts: list[str] = []

    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" width="100%" '
        f'style="background:#0f1117;border-radius:8px;'
        f'font-family:Segoe UI,system-ui,sans-serif" '
        f'class="attack-graph">'
    )

    # Concentric tier rings (decorative)
    for tier, radius in RADII.items():
        parts.append(
            f'<circle cx="{CENTER_X}" cy="{CENTER_Y}" r="{radius}" '
            f'fill="none" stroke="{TIER_RING[tier]}" stroke-width="1" '
            f'stroke-dasharray="4,4" opacity="0.6"/>'
        )
        # Tier label
        ly = CENTER_Y + radius - 8
        parts.append(
            f'<text x="{CENTER_X-radius+6}" y="{ly}" fill="{TIER_RING[tier]}" '
            f'font-size="10" opacity="0.8" font-family="monospace">'
            f'TIER {tier.value}</text>'
        )

    # ------------------------------------------------------------------
    # Edges  (drawn first so nodes paint on top)
    # ------------------------------------------------------------------
    # Identify edges that participate in critical paths (length ≤ 3)
    critical_edge_ids: set[tuple[str, str, EdgeKind]] = set()
    for p in graph.paths[:50]:
        if p.length <= 3:
            for e in p.edges:
                critical_edge_ids.add((e.src_id, e.dst_id, e.kind))

    for e in graph.edges:
        if e.src_id not in pos or e.dst_id not in pos:
            continue
        x1, y1 = pos[e.src_id]
        x2, y2 = pos[e.dst_id]
        is_crit = (e.src_id, e.dst_id, e.kind) in critical_edge_ids
        color = "#ff5e5e" if is_crit else EDGE_COLOR.get(e.kind, "#7f849c")
        opacity = "0.85" if is_crit else "0.35"
        width = "2" if is_crit else "1"
        title = f"{graph.nodes[e.src_id].label} —{e.kind.value}→ {graph.nodes[e.dst_id].label}"
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{color}" stroke-width="{width}" opacity="{opacity}">'
            f'<title>{_h(title)}</title></line>'
        )

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------
    for nid, node in graph.nodes.items():
        if nid not in pos:
            continue
        x, y = pos[nid]
        fill = NODE_FILL.get(node.kind, "#7f849c")
        stroke = "#fff" if node.is_tier0 else "#222840"
        stroke_w = "2.5" if node.is_tier0 else "1.5"
        radius = NODE_R + (4 if node.is_tier0 else 0)

        # Build hover title with key attrs
        attr_lines = [
            f"{node.kind.value.upper()}: {node.label}",
            f"Tier: {node.tier.name}",
        ]
        for key in ("AdminCount", "Roastable", "AsRepRoastable",
                    "DoesNotRequirePreAuth", "PasswordNeverExpires",
                    "UnconstrainedDelegation"):
            v = node.attrs.get(key)
            if v:
                attr_lines.append(f"{key}: {v}")
        if node.attrs.get("LastLogonDate"):
            attr_lines.append(f"LastLogon: {node.attrs['LastLogonDate']}")
        title = "\n".join(attr_lines)

        parts.append(
            f'<g class="ag-node" data-tier="{node.tier.value}" '
            f'data-kind="{node.kind.value}">'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_w}">'
            f'<title>{_h(title)}</title></circle>'
        )

        # Inline icon by kind (emoji, falls back gracefully)
        icon_map = {
            NodeKind.USER:     "👤",
            NodeKind.GROUP:    "👥",
            NodeKind.COMPUTER: "💻",
            NodeKind.DC:       "🏛",
            NodeKind.DOMAIN:   "🌐",
            NodeKind.TEMPLATE: "📜",
            NodeKind.PSEUDO:   "*",
            NodeKind.OU:       "📁",
        }
        parts.append(
            f'<text x="{x:.1f}" y="{y+5:.1f}" font-size="14" '
            f'text-anchor="middle" fill="#fff">{icon_map.get(node.kind,"?")}</text>'
        )

        # Node label
        ly = y + radius + 12
        parts.append(
            f'<text x="{x:.1f}" y="{ly:.1f}" fill="#cdd6f4" '
            f'font-size="10" text-anchor="middle" font-family="monospace">'
            f'{_h(node.short)}</text>'
            f'</g>'
        )

    # Legend (bottom-left)
    legend_x = 14
    legend_y = HEIGHT - 145
    parts.append(
        f'<g transform="translate({legend_x},{legend_y})">'
        f'<rect width="180" height="135" fill="#1a2035" '
        f'stroke="#2d3561" rx="6"/>'
        f'<text x="10" y="18" fill="#cdd6f4" font-size="11" '
        f'font-weight="bold">Leyenda</text>'
    )
    legend_items = [
        (NODE_FILL[NodeKind.DOMAIN],   "Dominio / Tier 0"),
        (NODE_FILL[NodeKind.GROUP],    "Grupo"),
        (NODE_FILL[NodeKind.USER],     "Usuario"),
        (NODE_FILL[NodeKind.DC],       "Domain Controller"),
        (NODE_FILL[NodeKind.TEMPLATE], "Plantilla ADCS"),
        (NODE_FILL[NodeKind.PSEUDO],   "Auth. Users (origen)"),
        ("#ff5e5e",                    "Path crítico ≤ 3 saltos"),
    ]
    for i, (color, label) in enumerate(legend_items):
        y = 32 + i * 14
        parts.append(
            f'<circle cx="14" cy="{y}" r="5" fill="{color}"/>'
            f'<text x="26" y="{y+4}" fill="#cdd6f4" '
            f'font-size="10" font-family="monospace">{_h(label)}</text>'
        )
    parts.append("</g>")

    # KPIs box (top-right)
    s = graph.stats
    kpi_lines = [
        f"Nodos: {s.get('total_nodes',0)}",
        f"Aristas: {s.get('total_edges',0)}",
        f"Objetivos Tier 0: {s.get('tier0_targets',0)}",
        f"Paths a Tier 0: {s.get('total_paths',0)}",
        f"Paths ≤ 3 saltos: {s.get('paths_le_3',0)}",
    ]
    kx = WIDTH - 200
    ky = 14
    parts.append(
        f'<g transform="translate({kx},{ky})">'
        f'<rect width="186" height="110" fill="#1a2035" '
        f'stroke="#2d3561" rx="6"/>'
        f'<text x="10" y="18" fill="#cdd6f4" font-size="11" '
        f'font-weight="bold">Estadísticas</text>'
    )
    for i, ln in enumerate(kpi_lines):
        parts.append(
            f'<text x="10" y="{36+i*14}" fill="#cdd6f4" '
            f'font-size="10" font-family="monospace">{_h(ln)}</text>'
        )
    parts.append("</g>")

    parts.append("</svg>")
    return "".join(parts)
