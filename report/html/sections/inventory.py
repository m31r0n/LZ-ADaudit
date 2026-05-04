"""HTML section builders. Each function returns a string of HTML for one
logical section of the report; build_html assembles them in order."""
from __future__ import annotations

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


def _section_inventory(data: AuditData) -> str:
    if not data.inventory:
        return ""
    tabs: list[str] = []
    panels: list[str] = []
    for i, (name, rows) in enumerate(data.inventory.items()):
        if not rows:
            continue
        cols = list(rows[0].keys())
        thead = "".join(f"<th>{_h(c)}</th>" for c in cols)
        tbody = "".join(
            "<tr>" + "".join(f"<td>{_h(r.get(c,''))}</td>" for c in cols) + "</tr>"
            for r in rows[:500]
        )
        more = f'<p class="dim small">First 500 of {len(rows)} rows.</p>' if len(rows) > 500 else ""
        active = "active" if i == 0 else ""
        label = name.replace("_", " ").title()
        tabs.append(f'<button class="tab-btn {active}" data-tab="inv-{name}">{label} ({len(rows)})</button>')
        panels.append(
            f'<div class="tab-panel {active}" id="inv-{name}">{more}'
            f'<div class="table-scroll"><table class="data-table small">'
            f'<thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table></div></div>'
        )
    if not tabs:
        return ""
    return f"""
<section class="section" id="inventory">
  <h2 class="st">{t("section.inventory", data.incident.language)}</h2>
  <div class="tab-bar">{"".join(tabs)}</div>
  {"".join(panels)}
</section>"""
