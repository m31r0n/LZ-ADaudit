"""Attack-path graph section (v1.6.0).

Renders the AD attack surface as a self-contained SVG plus a critical-paths
table and a choke-points table. Generic — works for any AuditData.
"""
from __future__ import annotations

from ...data import AuditData
from ...graph import build_attack_graph, render_svg
from ...graph.paths import populate_analytics
from ...i18n import t
from ...utils import h


def section_attack_paths(data: AuditData) -> str:
    graph = build_attack_graph(data)
    populate_analytics(graph)
    if not graph.nodes:
        return ""

    lang = data.incident.language or "es"
    s = graph.stats

    svg = render_svg(graph)

    # ---- Top 10 critical paths table ----
    paths_rows: list[str] = []
    for p in graph.paths[:10]:
        if not p.nodes:
            continue
        # Build a colorful chain like "src --kind--> mid --kind--> tgt"
        parts: list[str] = [
            f'<span class="ag-node-pill ag-{p.nodes[0].kind.value}">'
            f'{h(p.nodes[0].label)}</span>'
        ]
        for n, e in zip(p.nodes[1:], p.edges):
            parts.append(
                f'<span class="ag-edge-arrow" '
                f'title="{h(e.evidence)}">&rarr;{h(e.kind.value)}&rarr;</span>'
            )
            parts.append(
                f'<span class="ag-node-pill ag-{n.kind.value}">'
                f'{h(n.label)}</span>'
            )
        chain_html = "".join(parts)
        sev_color = ("#c0392b" if p.length <= 1 else
                     ("#e74c3c" if p.length <= 3 else "#f39c12"))
        paths_rows.append(
            f'<tr>'
            f'<td class="center bold" style="color:{sev_color}">{p.length}</td>'
            f'<td>{chain_html}</td>'
            f'</tr>'
        )

    paths_table = ""
    if paths_rows:
        paths_table = (
            '<h3 class="sh">Paths más cortos hacia Tier 0</h3>'
            '<p class="dim small" style="margin-bottom:8px">'
            'Cada fila representa una cadena de privilegios desde un origen '
            'no-Tier 0 hasta un objeto Tier 0. Cuanto menor el conteo de '
            'saltos, más facil para un atacante con credenciales de bajo '
            'nivel.</p>'
            '<div class="table-scroll">'
            '<table class="data-table small">'
            '<thead><tr>'
            '<th class="center" style="width:60px">Saltos</th>'
            '<th>Cadena de privilegios</th>'
            '</tr></thead>'
            f'<tbody>{"".join(paths_rows)}</tbody></table></div>'
        )

    # ---- Choke points table ----
    choke_rows: list[str] = []
    for nid, score in graph.choke[:10]:
        n = graph.nodes.get(nid)
        if not n:
            continue
        rationale = (
            "Eliminar privilegio / rotar contrasena / mover a Protected Users "
            "interrumpe los paths que pasan por aqui."
        )
        choke_rows.append(
            f'<tr>'
            f'<td class="center bold" style="color:#e74c3c">{score}</td>'
            f'<td><span class="ag-node-pill ag-{n.kind.value}">'
            f'{h(n.label)}</span></td>'
            f'<td class="small">{h(n.kind.value)} / {n.tier.name}</td>'
            f'<td class="small dim">{h(rationale)}</td>'
            f'</tr>'
        )
    choke_table = ""
    if choke_rows:
        choke_table = (
            '<h3 class="sh">Choke points (puntos de quiebre)</h3>'
            '<p class="dim small" style="margin-bottom:8px">'
            'Nodos que aparecen en muchos paths a la vez. Remediar uno solo '
            'corta todos los paths donde participa &mdash; es la forma de '
            'mayor ROI para reducir blast radius.</p>'
            '<div class="table-scroll">'
            '<table class="data-table small">'
            '<thead><tr>'
            '<th class="center" style="width:60px">Score</th>'
            '<th>Nodo</th>'
            '<th>Tipo / Tier</th>'
            '<th>Mitigacion</th>'
            '</tr></thead>'
            f'<tbody>{"".join(choke_rows)}</tbody></table></div>'
        )

    # ---- KPI cards header ----
    kpis_html = (
        '<div class="info-grid" style="margin-bottom:12px">'
        f'<div class="ic" style="border-left:3px solid #c0392b">'
        f'<div class="ic-l">Paths a Tier 0</div>'
        f'<div class="ic-v" style="color:#e74c3c">{s.get("total_paths",0)}</div></div>'
        f'<div class="ic" style="border-left:3px solid #e74c3c">'
        f'<div class="ic-l">Paths &le; 3 saltos</div>'
        f'<div class="ic-v" style="color:#e74c3c">{s.get("paths_le_3",0)}</div></div>'
        f'<div class="ic" style="border-left:3px solid #f39c12">'
        f'<div class="ic-l">Choke points</div>'
        f'<div class="ic-v" style="color:#f39c12">{len(graph.choke)}</div></div>'
        f'<div class="ic" style="border-left:3px solid #3498db">'
        f'<div class="ic-l">Objetos Tier 0</div>'
        f'<div class="ic-v" style="color:#3498db">{s.get("tier0_targets",0)}</div></div>'
        f'<div class="ic" style="border-left:3px solid #7f849c">'
        f'<div class="ic-l">Nodos / Aristas</div>'
        f'<div class="ic-v" style="color:#cdd6f4">'
        f'{s.get("total_nodes",0)} / {s.get("total_edges",0)}</div></div>'
        '</div>'
    )

    return f"""
<section class="section" id="attack-paths">
  <h2 class="st">Mapa de paths de ataque a Tier 0</h2>
  <p class="dim small" style="margin-bottom:10px">
    Heuristica de paths cortos derivada de membresias, derechos DCSync,
    SPN, AS-REP, Shadow Credentials, RBCD, delegacion y plantillas ESC4.
    Lineas rojas indican paths &le; 3 saltos &mdash; equivalentes a
    <em>game over</em> con credenciales de un usuario regular.
  </p>
  {kpis_html}
  <div class="ag-svg-wrap">{svg}</div>
  {paths_table}
  {choke_table}
</section>"""
