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
from ..charts_proxy import _svg_donut, _svg_hbar


def _section_domain(data: AuditData) -> str:
    dom = data.evidence.get("domain", {})
    ex = data.execution
    if not dom and not ex:
        return ""

    def card(label: str, value: str, cls: str = "") -> str:
        return (f'<div class="ic {cls}"><div class="ic-l">{_h(label)}</div>'
                f'<div class="ic-v">{_h(value)}</div></div>')

    recycle = dom.get("recycle_bin_enabled")
    rb_cls = "risk-ok" if recycle else "risk-warn"
    rb_val = "Enabled" if recycle else "Disabled (risk)"

    fsmo_rows = ""
    for role in ["pdc_emulator", "rid_master", "infrastructure_master",
                 "schema_master", "domain_naming_master"]:
        val = dom.get(role, "—")
        label = role.replace("_", " ").title()
        fsmo_rows += f"<tr><td class='td-label'>{_h(label)}</td><td class='mono small'>{_h(val)}</td></tr>"

    cards = (
        card(t("label.domain", data.incident.language), dom.get("domain_name") or ex.get("domain_name", "—")) +
        card(t("label.forest", data.incident.language), dom.get("forest_name") or ex.get("forest_name", "—")) +
        card("Nivel Funcional de Dominio" if data.incident.language == "es" else "Domain Functional Level", _dfl_label(dom.get("domain_mode", ""))) +
        card(t("label.forest_dfl", data.incident.language), _dfl_label(dom.get("forest_mode", ""))) +
        card(t("label.recycle_bin", data.incident.language), rb_val, rb_cls)
    )
    return f"""
<section class="section" id="domain">
  <h2 class="st">{t("section.domain", data.incident.language)}</h2>
  <div class="info-grid">{cards}</div>
  <h3 class="sh">{t("label.fsmo", data.incident.language)}</h3>
  <table class="data-table" style="max-width:600px">
    <tbody>{fsmo_rows}</tbody>
  </table>
</section>"""


def _section_top_priorities(data: AuditData) -> str:
    top = data.summary.get("top_priorities", [])
    if not top:
        return ""
    seen: set[str] = set()
    rows = []
    for i, p in enumerate(top, 1):
        cid = p.get("check_id", "")
        if cid in seen:
            continue
        seen.add(cid)
        sev = p.get("severity", "")
        rows.append(
            f'<tr><td class="center bold">{i}</td>'
            f'<td>{_SEV_BADGE.get(sev, _h(sev))}</td>'
            f'<td class="mono small">{_h(cid)}</td>'
            f'<td>{_h(p.get("title",""))}</td>'
            f'<td class="center">{_h(p.get("priority_score",""))}</td></tr>'
        )
    return f"""
<section class="section" id="priorities">
  <h2 class="st">{t("section.priorities", data.incident.language)}</h2>
  <table class="data-table">
    <thead><tr><th>#</th><th>Severity</th><th>Check ID</th><th>Title</th><th>Score</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</section>"""


def _section_preflight(data: AuditData) -> str:
    pf = data.preflight
    if not pf:
        return ""
    overall = pf.get("overall_pass", True)
    badge = '<span class="badge sev-ok">PASS</span>' if overall else '<span class="badge sev-high">FAIL</span>'
    rows = []
    for c in pf.get("checks", []):
        st = c.get("status", "")
        icon_color = {"pass": ("#2ecc71", "✓"), "warn": ("#f39c12", "⚠"), "fail": ("#e74c3c", "✗")}.get(st, ("#888", "?"))
        rows.append(
            f'<tr><td style="color:{icon_color[0]};font-weight:bold">{icon_color[1]} {_h(st.upper())}</td>'
            f'<td class="mono small">{_h(c.get("check",""))}</td>'
            f'<td>{_h(c.get("detail",""))}</td></tr>'
        )
    return f"""
<section class="section" id="preflight">
  <h2 class="st">{t("section.preflight", data.incident.language)} {badge}</h2>
  <table class="data-table">
    <thead><tr><th>Result</th><th>Check</th><th>Detail</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</section>"""
