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


def _section_findings(data: AuditData) -> str:
    if not data.findings:
        return ""
    sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    sorted_f = sorted(
        data.findings,
        key=lambda f: (sev_ord.get(f.get("severity", ""), 4), -f.get("priority_score", 0)),
    )
    rem_ctx = _remediation_context(data)
    rows = []
    for f in sorted_f:
        sev = f.get("severity", "")
        affected = f.get("affected_objects") or []
        aff_html = ""
        if affected:
            items = "".join(f"<li>{_h(a)}</li>" for a in affected[:20])
            more = f"<li class='dim'>…{len(affected)-20} more</li>" if len(affected) > 20 else ""
            aff_html = f'<ul class="affected-list">{items}{more}</ul>'
        check_id = f.get("check_id", "")
        tags = " ".join(f'<span class="tag">{_h(t)}</span>' for t in (f.get("tags") or []))
        ev = _h(f.get("evidence", "") or "").strip()
        rec = _h(f.get("recommendation", "") or "").strip()
        score = f.get("priority_score", "")
        tl_badge = _timeline_badge(check_id, data.incident.language)

        # Enhanced remediation block from DB
        rem = _get_rem(check_id, rem_ctx)
        rem_html = ""
        if rem:
            ctx = _h(rem.get("context", ""))
            steps_html = "".join(
                f'<li class="rem-step">{_h(s)}</li>' for s in rem.get("steps", [])
            )
            refs = " &nbsp;·&nbsp; ".join(
                f'<span class="ref-tag">{_h(r)}</span>' for r in rem.get("references", [])
            )
            rem_html = (
                f'<button class="rem-toggle">&#9654; {t("label.show_remediation", data.incident.language)}</button>'
                f'<div class="rem-block" style="display:none">'
                f'<div class="rem-ctx">{ctx}</div>'
                f'<ol class="rem-steps">{steps_html}</ol>'
                f'{"<div class=rem-refs>" + refs + "</div>" if refs else ""}'
                f'</div>'
            )

        rows.append(f"""
<tr class="fr" data-sev="{_h(sev)}" data-cat="{_h(f.get('category',''))}">
  <td>
    {_SEV_BADGE.get(sev, f'<span class="badge">{_h(sev)}</span>')}
    <div style="margin-top:6px">{tl_badge}</div>
  </td>
  <td>
    <div class="ft">{_h(f.get('title',''))}</div>
    <div class="fm">
      <span class="mono small">{_h(check_id)}</span>&nbsp;·&nbsp;
      <span class="small">{_h(f.get('category',''))}</span>
      {f'&nbsp;·&nbsp;<span class="small">score {score}</span>' if score else ''}
    </div>
    {f'<div class="ev-block">{ev}</div>' if ev else ''}
    {f'<div class="rec-block">&#x1F4A1; {rec}</div>' if rec else ''}
    {aff_html}
    {rem_html}
    <div class="tags">{tags}</div>
  </td>
  <td class="center small">{_h(f.get('confidence',''))}</td>
  <td class="center small">{_h(f.get('impact',''))}</td>
  <td class="center">{_h(f.get('status',''))}</td>
  <td class="small mono">{_fmt_dt(f.get('created_at_utc'))}</td>
</tr>""")

    return f"""
<section class="section" id="findings">
  <h2 class="st">{t("section.findings", data.incident.language)}
    <span class="filter-bar">
      Filter:
      <button class="fbtn active" data-f="all">{t("label.all", data.incident.language)}</button>
      <button class="fbtn" data-f="high" style="color:#e74c3c">{t("label.high", data.incident.language)}</button>
      <button class="fbtn" data-f="medium" style="color:#f39c12">{t("label.medium", data.incident.language)}</button>
      <button class="fbtn" data-f="low" style="color:#3498db">{t("label.low", data.incident.language)}</button>
      <button class="fbtn" data-f="informational" style="color:#95a5a6">{t("label.info", data.incident.language)}</button>
    </span>
    <input class="search-box" id="finding-search" placeholder="{t('label.search', data.incident.language)}" type="text">
  </h2>
  <div class="table-scroll">
  <table class="data-table sortable" id="tbl-findings">
    <thead><tr>
      <th style="width:80px" data-col="0">{t("label.severity", data.incident.language)}</th><th>{t("label.title", data.incident.language)}</th>
      <th class="center" style="width:70px" data-col="2">{t("label.confidence", data.incident.language)}</th>
      <th class="center" style="width:60px" data-col="3">{t("label.impact", data.incident.language)}</th>
      <th class="center" style="width:70px" data-col="4">{t("label.status", data.incident.language)}</th>
      <th style="width:130px" data-col="5">{t("label.detected", data.incident.language)}</th>
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
  </div>
</section>"""
