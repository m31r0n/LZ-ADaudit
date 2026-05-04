"""GPO Post-Ransomware analysis section (v1.5.0).

Renders a table of all GPOs with creation/modification dates, IR indicators
(scheduled tasks, scripts, MSI deployment, cpassword, hardening tampering),
and links. Modifications inside the incident window are flagged red.
"""
from __future__ import annotations

from ...data import AuditData
from ...gpo_analysis import parse_gpo_report
from ...i18n import t
from ...utils import h


def section_gpo_ir(data: AuditData) -> str:
    gpos = parse_gpo_report(data.folder)
    if not gpos:
        return ""

    lang = data.incident.language or "es"
    inc = data.incident

    # Sort: modified descending, in-window first
    def _sort_key(g):
        in_win = inc.active and (
            (g.modified and inc.in_window(g.modified)) or
            (g.created and inc.in_window(g.created))
        )
        ts = g.modified.timestamp() if g.modified else 0
        return (0 if in_win else 1, -ts)

    rows: list[str] = []
    flagged_count = 0

    for g in sorted(gpos, key=_sort_key):
        in_win_mod = inc.active and g.modified and inc.in_window(g.modified)
        in_win_cre = inc.active and g.created and inc.in_window(g.created)
        any_in_window = in_win_mod or in_win_cre
        if any_in_window:
            flagged_count += 1

        def _fmt_dt_cell(dt, in_win):
            if not dt:
                return '<span class="dim">&mdash;</span>'
            text = dt.strftime("%Y-%m-%d %H:%M UTC")
            if in_win:
                return (f'<span style="color:#e74c3c;font-weight:600">{h(text)}</span>'
                        f' <span class="badge ir-window">EN VENTANA</span>')
            return f'<span class="mono small">{h(text)}</span>'

        ind_html = ""
        if g.indicators:
            severity_class = "risk-crit" if any(
                kw in i for kw in ("cpassword", "Scheduled", "Defender",
                                   "Firewall", "UAC", "AlwaysInstall")
                for i in g.indicators
            ) else "risk-warn"
            badges = "".join(
                f'<span class="badge {severity_class}" '
                f'style="margin-right:4px;display:inline-block;margin-bottom:2px">'
                f'{h(ind)}</span>'
                for ind in g.indicators
            )
            ind_html = badges
        else:
            ind_html = '<span class="dim small">&mdash;</span>'

        links_html = ""
        if g.linked_to:
            visible = g.linked_to[:3]
            more = (f' <span class="dim small">+{len(g.linked_to)-3} mas</span>'
                    if len(g.linked_to) > 3 else "")
            links_html = "<br>".join(
                f'<span class="mono small">{h(l)}</span>' for l in visible
            ) + more
            if g.targets_dc:
                links_html = ('<span class="badge sev-crit">DOMAIN CONTROLLERS</span><br>'
                              + links_html)
        else:
            links_html = '<span class="dim small">&mdash;</span>'

        row_class = "fr-window" if any_in_window else ""
        rows.append(
            f'<tr class="{row_class}">'
            f'<td><strong>{h(g.name)}</strong>'
            f'<div class="dim small mono">{h(g.guid)}</div></td>'
            f'<td>{_fmt_dt_cell(g.created, in_win_cre)}</td>'
            f'<td>{_fmt_dt_cell(g.modified, in_win_mod)}</td>'
            f'<td>{links_html}</td>'
            f'<td>{ind_html}</td>'
            f'</tr>'
        )

    legend = ""
    if inc.active:
        if flagged_count > 0:
            legend = (
                f'<p class="dim small" style="margin-bottom:8px">'
                f'<strong style="color:#e74c3c">{flagged_count} GPO(s) creados o '
                f'modificados dentro de la ventana de incidente</strong> &mdash; '
                f'verificar cada cambio contra change management.</p>'
            )
        else:
            legend = (
                f'<p class="dim small" style="margin-bottom:8px">'
                f'Ningun GPO fue modificado dentro de la ventana de incidente '
                f'({inc.window_start.strftime("%Y-%m-%d")} &rarr; '
                f'{inc.window_end.strftime("%Y-%m-%d")}). '
                f'Esto reduce la probabilidad de propagacion via GPO &mdash; '
                f'pero no la descarta (atacantes pueden modificar GPO y luego '
                f'restaurar).</p>'
            )

    indicators_summary = _build_summary(gpos)

    return f"""
<section class="section" id="gpo-ir">
  <h2 class="st">{t("section.gpo_ir", lang)}</h2>
  {legend}
  {indicators_summary}
  <div class="table-scroll">
    <table class="data-table small">
      <thead><tr>
        <th>GPO</th>
        <th>{t("gpo.created", lang)}</th>
        <th>{t("gpo.modified", lang)}</th>
        <th>{t("gpo.linked_to", lang)}</th>
        <th>{t("gpo.indicators", lang)}</th>
      </tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</section>"""


def _build_summary(gpos: list) -> str:
    """Build a compact KPI summary for the GPO IR section."""
    total = len(gpos)
    n_sched = sum(1 for g in gpos if g.has_scheduled_tasks)
    n_scripts = sum(1 for g in gpos if g.has_scripts)
    n_msi = sum(1 for g in gpos if g.has_software_install)
    n_cpwd = sum(1 for g in gpos if g.has_cpassword)
    n_dc = sum(1 for g in gpos if g.targets_dc)

    cards = [
        ("Total GPOs", str(total), "#3498db"),
        ("Scheduled Tasks", str(n_sched), "#e74c3c" if n_sched else "#7f849c"),
        ("Scripts", str(n_scripts), "#f39c12" if n_scripts else "#7f849c"),
        ("MSI Deploy", str(n_msi), "#f39c12" if n_msi else "#7f849c"),
        ("cpassword", str(n_cpwd), "#c0392b" if n_cpwd else "#2ecc71"),
        ("Targets DCs", str(n_dc), "#7f849c"),
    ]
    cards_html = "".join(
        f'<div class="ic" style="border-left:3px solid {color}">'
        f'<div class="ic-l">{label}</div>'
        f'<div class="ic-v" style="color:{color}">{value}</div></div>'
        for label, value, color in cards
    )
    return f'<div class="info-grid" style="margin-bottom:10px">{cards_html}</div>'
