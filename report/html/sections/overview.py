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


def _section_charts(data: AuditData) -> str:
    sev_order = ["critical", "high", "medium", "low", "informational"]
    raw_sev = data.summary.get("findings_by_severity", {})
    sev = {k: raw_sev[k] for k in sev_order if k in raw_sev}
    cat = dict(sorted(data.summary.get("findings_by_category", {}).items(), key=lambda x: -x[1]))
    if not sev and not cat:
        return ""
    return f"""
<section class="section" id="charts">
  <h2 class="st">{t("section.overview", data.incident.language)}</h2>
  <div class="charts-row">
    <div class="chart-card">{_svg_donut(sev, _SEVERITY_COLORS, "Findings by Severity")}
      <button class="copy-chart-btn" onclick="copyChartAsPng(this)">&#x1F4CB; Copy as PNG</button></div>
    <div class="chart-card">{_svg_hbar(cat, _CAT_COLORS, "Findings by Category")}
      <button class="copy-chart-btn" onclick="copyChartAsPng(this)">&#x1F4CB; Copy as PNG</button></div>
  </div>
</section>"""
