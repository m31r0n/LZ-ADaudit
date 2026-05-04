"""IR-specific sections (v1.5.0): banner, timeline, correlations, post-
ransomware checklist. Rendered only when --incident-date is provided."""
from __future__ import annotations

import re

from ...data import AuditData
from ...i18n import t
from ...utils import h, SEV_BADGE, txt
from ..charts import svg_ir_timeline
from ...ir.parsers import parse_dt_loose, finding_timestamps


def section_ir_banner(data: AuditData) -> str:
    """Red banner with incident KPIs. Empty when IR Mode off."""
    inc = data.incident
    if not inc.active:
        return ""
    in_window = sum(1 for f in data.findings if f.get("_in_incident_window"))
    persistence_ids = {"IR-CORR-002", "IR-CORR-003", "IR-CORR-004",
                       "IR-CORR-005", "IR-CORR-008", "IR-CORR-009"}
    persistence = sum(1 for c in data.correlations
                      if c.get("id") in persistence_ids)
    return f"""
<section class="ir-banner" id="ir-banner">
  <div class="ir-banner-top">
    <span class="ir-flame">&#128680;</span>
    <div class="ir-titles">
      <div class="ir-title">INFORME POST-INCIDENTE</div>
      <div class="ir-sub">
        Fecha de siniestro: <strong>{inc.incident_date.strftime('%Y-%m-%d')}</strong>
        &nbsp;&middot;&nbsp; Ventana:
        {inc.window_start.strftime('%Y-%m-%d')} &rarr;
        {inc.window_end.strftime('%Y-%m-%d')}
        &nbsp;&middot;&nbsp; Auditor: {h(inc.auditor) if inc.auditor else '&mdash;'}
      </div>
    </div>
  </div>
  <div class="ir-kpis">
    <div class="ir-kpi"><div class="ir-kpi-n">{in_window}</div>
      <div class="ir-kpi-l">Hallazgos en ventana</div></div>
    <div class="ir-kpi"><div class="ir-kpi-n">{persistence}</div>
      <div class="ir-kpi-l">Indicadores de persistencia</div></div>
    <div class="ir-kpi"><div class="ir-kpi-n">{len(data.correlations)}</div>
      <div class="ir-kpi-l">Correlaciones IR</div></div>
    <div class="ir-kpi"><div class="ir-kpi-n">{len(data.missing_inputs)}</div>
      <div class="ir-kpi-l">Gaps de evidencia</div></div>
  </div>
</section>
"""


def section_ir_timeline(data: AuditData) -> str:
    inc = data.incident
    if not inc.active:
        return ""

    events: list[tuple] = []  # (ts, label, color, source)

    # Account creations from new_users.txt
    for ln in txt(data, "new_users"):
        m = re.match(r"Account (\S+) was created (.+)", ln)
        if not m:
            continue
        d = parse_dt_loose(m.group(2))
        if d:
            events.append((d, f"Cuenta creada: {m.group(1)}",
                           "#e74c3c", "new_users.txt"))

    # Security events
    for e in data.security_events_csv:
        ts = e.get("timestamp_utc", "")
        d = parse_dt_loose(ts)
        if not d:
            continue
        events.append((d,
                       f"{e.get('action', '')} by {e.get('actor', '')}",
                       "#f39c12",
                       f"event {e.get('event_id', '')}"))

    # Findings whose evidence has dates inside window
    for f in data.findings:
        for ts in finding_timestamps(f):
            if inc.in_window(ts):
                sev = f.get("severity", "")
                color = {"critical": "#c0392b", "high": "#e74c3c",
                         "medium": "#f39c12", "low": "#3498db"}.get(sev, "#7f849c")
                events.append((ts, f.get("title", ""),
                               color, f.get("check_id", "")))
                break

    events = [e for e in events if inc.in_window(e[0])]
    events.sort(key=lambda x: x[0])

    if not events:
        return f"""
<section class="section" id="ir-timeline">
  <h2 class="st">Timeline en ventana de incidente</h2>
  <p class="dim small">No se identificaron eventos cronologicos dentro de la
  ventana ({inc.window_start.strftime('%Y-%m-%d')} &rarr;
  {inc.window_end.strftime('%Y-%m-%d')}). En post-ransomware esto suele indicar
  borrado del Security log o auditoria desactivada.</p>
</section>"""

    svg = svg_ir_timeline(inc.window_start, inc.window_end,
                          inc.incident_date, events)
    return f"""
<section class="section" id="ir-timeline">
  <h2 class="st">Timeline en ventana de incidente</h2>
  <p class="dim small">Eventos cronologicos dentro de la ventana
  ({inc.window_start.strftime('%Y-%m-%d')} &rarr;
  {inc.window_end.strftime('%Y-%m-%d')}). La linea discontinua marca el
  momento del siniestro.</p>
  <div class="ir-timeline-wrap">{svg}</div>
</section>"""


def section_correlations(data: AuditData) -> str:
    if not data.correlations:
        return ""
    sev_ord = {"critical": 0, "high": 1, "medium": 2,
               "low": 3, "informational": 4}
    rows: list[str] = []
    for c in sorted(data.correlations,
                    key=lambda x: sev_ord.get(x.get("severity", ""), 5)):
        sev = c.get("severity", "")
        mitre = " &middot; ".join(c.get("mitre", []))
        refs = " &middot; ".join(c.get("refs", []))
        ev = c.get("evidence", "") or ""
        ev_html = (f'<pre class="cmd-block" style="margin-top:6px">'
                   f'{h(ev)}</pre>') if ev else ""
        refs_html = (f' &middot; <span class="ref-tag">{h(refs)}</span>'
                     if refs else "")
        rows.append(
            '<tr>'
            f'<td>{SEV_BADGE.get(sev, h(sev))}</td>'
            f'<td class="mono small">{h(c.get("id", ""))}</td>'
            f'<td><strong>{h(c.get("title", ""))}</strong>'
            f'<div class="dim small" style="margin-top:4px">'
            f'{h(c.get("narrative", ""))}</div>'
            f'{ev_html}'
            f'<div class="rem-refs">'
            f'<span class="ref-tag">MITRE: {h(mitre)}</span>{refs_html}</div>'
            '</td>'
            '</tr>'
        )
    return f"""
<section class="section" id="correlations">
  <h2 class="st">Correlaciones IR</h2>
  <p class="dim small" style="margin-bottom:10px">
    Hallazgos cruzados &mdash; los siguientes patrones aparecen en runs
    post-compromiso y deben verificarse manualmente antes de cerrar el caso.
  </p>
  <table class="data-table">
    <thead><tr>
      <th style="width:90px">Severidad</th>
      <th style="width:120px">Regla</th>
      <th>Detalle</th>
    </tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>"""


def section_post_ransomware(data: AuditData) -> str:
    if not data.ir_indicators:
        return ""
    sections: dict[str, list[dict]] = {}
    for it in data.ir_indicators:
        sections.setdefault(it["section"], []).append(it)

    sev_color = {"critical": "#c0392b", "high": "#e74c3c",
                 "warn": "#f39c12", "info": "#2ecc71"}
    out: list[str] = []
    for sec_name, items in sections.items():
        rows: list[str] = []
        for it in items:
            color = sev_color.get(it.get("severity", "info"), "#7f849c")
            rows.append(
                '<tr>'
                f'<td><span class="state-dot" style="background:{color}"></span> '
                f'<strong style="color:{color}">{h(it["state"])}</strong></td>'
                f'<td><div class="ind-name">{h(it["name"])}</div>'
                f'<div class="dim small">{h(it["detail"])}</div></td>'
                f'<td><pre class="cmd-block">{h(it["verify"])}</pre></td>'
                '</tr>'
            )
        out.append(
            f'<h3 class="sh">{h(sec_name)}</h3>'
            '<table class="data-table">'
            '<thead><tr>'
            '<th style="width:130px">Estado</th>'
            '<th>Indicador</th>'
            '<th>Verificacion</th>'
            '</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )
    return f"""
<section class="section" id="ir-checklist">
  <h2 class="st">Indicadores post-ransomware</h2>
  <p class="dim small" style="margin-bottom:10px">
    Lista de comprobacion de persistencia, hardening del host, integridad
    forense y preparacion para recuperacion. Cada estado puede re-verificarse
    manualmente con el comando indicado.
  </p>
  {''.join(out)}
</section>"""
