"""HTML section builders. Each function returns a string of HTML for one
logical section of the report; build_html assembles them in order."""
from __future__ import annotations

import re

from ...data import AuditData
from ...utils import (
    h as _h, fmt_dt as _fmt_dt, fmt_dur as _fmt_dur, txt as _txt,
    dfl_label as _dfl_label, msdate as _msdate,
    SEV_BADGE as _SEV_BADGE, SEVERITY_COLORS as _SEVERITY_COLORS,
    CAT_COLORS as _CAT_COLORS, GPO_STATUS, IR_BADGE as _IR_BADGE,
    SYNTHETIC_BADGE as _SYNTHETIC_BADGE, TIMELINE as _TIMELINE,
)
from ...i18n import t
from ...remediation import (
    get_rem as _get_rem,
    timeline_badge as _timeline_badge,
    remediation_context as _remediation_context,
)
from ..charts import svg_donut as _svg_donut, svg_hbar as _svg_hbar


def _section_gpo(data: AuditData) -> str:
    gpos_ev = data.evidence.get("gpo", [])
    ou_lines = _txt(data, "ous_inheritedGPOs")

    gpo_table = ""
    if gpos_ev:
        status_cls = {0: "risk-ok", 1: "risk-warn", 2: "risk-warn", 3: "risk-crit"}
        rows = "".join(
            f'<tr><td class="small">{_h(g.get("DisplayName",""))}</td>'
            f'<td><span class="{status_cls.get(g.get("GpoStatus",0),"")}">'
            f'{_h(GPO_STATUS.get(g.get("GpoStatus",-1),"?"))}</span></td>'
            f'<td class="mono small">{_msdate(g.get("ModificationTime"))}</td>'
            f'<td class="mono small dim">{_h(g.get("Id",""))}</td></tr>'
            for g in gpos_ev
        )
        gpo_table = (
            f'<table class="data-table"><thead>'
            f'<tr><th>Name</th><th>Status</th><th>Modified</th><th>GUID</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    ou_html = ""
    if ou_lines:
        ou_rows = []
        for ln in ou_lines:
            if " Inherits these GPOs: " in ln:
                ou_name, gpo_list = ln.split(" Inherits these GPOs: ", 1)
                gpo_badges = " ".join(
                    f'<span class="tag">{_h(g.strip())}</span>'
                    for g in gpo_list.split(",") if g.strip()
                )
                ou_rows.append(f'<tr><td class="mono small">{_h(ou_name)}</td><td>{gpo_badges}</td></tr>')
            else:
                ou_rows.append(f'<tr><td colspan="2" class="small">{_h(ln)}</td></tr>')
        ou_html = (
            '<h3 class="sh">OU GPO Inheritance</h3>'
            '<table class="data-table"><thead><tr><th>OU</th><th>Inherited GPOs</th></tr></thead>'
            f'<tbody>{"".join(ou_rows)}</tbody></table>'
        )

    gpo_report_note = ""
    if data.gpo_report_exists:
        gpo_report_note = (
            '<p class="dim small" style="margin-top:8px">'
            '&#x1F4C4; <strong>GPOReport.html</strong> is available in the audit folder '
            '— open it in a browser for the full Group Policy Object detail report.</p>'
        )

    if not gpo_table and not ou_html and not gpo_report_note:
        return ""
    return f"""
<section class="section" id="gpo">
  <h2 class="st">{t("section.gpo", data.incident.language)}</h2>
  {gpo_table}
  {ou_html}
  {gpo_report_note}
</section>"""


def _section_adcs(data: AuditData) -> str:
    adcs = data.evidence.get("adcs", {})
    if not adcs:
        return ""

    svcs = adcs.get("enrollment_services", [])
    templates = adcs.get("templates", [])

    svc_html = ""
    if svcs:
        rows = "".join(
            f'<tr><td class="small">{_h(s.get("displayName",""))}</td>'
            f'<td class="mono small">{_h(s.get("dNSHostName",""))}</td>'
            f'<td class="small dim">{_h(s.get("certificateTemplates",""))}</td></tr>'
            for s in svcs
        )
        svc_html = (
            '<table class="data-table"><thead>'
            '<tr><th>CA Name</th><th>Host</th><th>Templates</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    tpl_html = ""
    if templates:
        rows = "".join(
            f'<tr><td class="mono small">{_h(t.get("Name",""))}</td>'
            f'<td class="small">{_h(t.get("displayName",""))}</td>'
            f'<td class="mono small dim">{_h(t.get("EKUs",""))}</td></tr>'
            for t in templates
        )
        tpl_html = (
            f'<h3 class="sh">Certificate Templates ({len(templates)})</h3>'
            '<div class="table-scroll"><table class="data-table small">'
            '<thead><tr><th>Name</th><th>Display Name</th><th>EKUs</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    return f"""
<section class="section" id="adcs">
  <h2 class="st">{t("section.adcs", data.incident.language)}</h2>
  {svc_html}
  {tpl_html}
</section>"""


def _section_modules(data: AuditData) -> str:
    modules_detail = data.execution.get("modules_detail", {})
    if not modules_detail:
        return ""
    _st_color = {"executed": "#2ecc71", "skipped": "#f39c12",
                 "failed": "#e74c3c", "partial": "#e67e22"}
    _st_icon  = {"executed": "✓", "skipped": "–", "failed": "✗", "partial": "~"}
    rows = []
    for mod, info in modules_detail.items():
        st = info.get("status", "unknown")
        color = _st_color.get(st, "#888")
        findings = info.get("findings_added", 0)
        err = info.get("error", "") or ""
        rows.append(
            f'<tr><td style="color:{color};font-weight:bold">'
            f'{_st_icon.get(st,"?")} {_h(st.upper())}</td>'
            f'<td class="small">{_h(info.get("display_name",mod))}</td>'
            f'<td class="mono small">{_h(mod)}</td>'
            f'<td class="center">{findings}</td>'
            f'<td class="center">{_fmt_dur(info.get("duration_seconds"))}</td>'
            f'<td class="small dim">'
            f'{"" if not err else f"""<span class="warn-note">{_h(err)}</span>"""}'
            f'</td></tr>'
        )
    return f"""
<section class="section" id="modules">
  <h2 class="st">{t("section.modules", data.incident.language)}</h2>
  <table class="data-table">
    <thead><tr><th>Status</th><th>Module</th><th>ID</th>
      <th class="center">Findings</th><th class="center">Duration</th><th>Notes</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</section>"""
