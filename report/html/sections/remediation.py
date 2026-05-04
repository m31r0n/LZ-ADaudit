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


def _section_remediation_plan(data: AuditData) -> str:
    """Prioritized remediation plan grouped by timeline."""
    if not data.findings:
        return ""

    rem_ctx = _remediation_context(data)
    # Group failed findings by timeline, deduplicated by check_id
    buckets: dict[str, list[dict]] = {k: [] for k in _TIMELINE}
    seen: set[str] = set()
    sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

    for f in sorted(data.findings,
                    key=lambda x: (sev_ord.get(x.get("severity", ""), 4),
                                   -x.get("priority_score", 0))):
        if f.get("status") == "passed":
            continue
        cid = f.get("check_id", "")
        if cid in seen:
            continue
        seen.add(cid)
        rem = _get_rem(cid, rem_ctx)
        tl = rem.get("timeline", "none") if rem else "none"
        if tl not in buckets:
            tl = "none"
        buckets[tl].append(f)

    html_parts: list[str] = []
    priority = 0
    for tl_key, (tl_label_en, tl_color, tl_icon) in _TIMELINE.items():
        tl_label = t(f"timeline.{tl_key}", data.incident.language)
        bucket = buckets.get(tl_key, [])
        if not bucket:
            continue

        rows = []
        for f in bucket:
            priority += 1
            cid = f.get("check_id", "")
            sev = f.get("severity", "")
            rem = _get_rem(cid, rem_ctx)
            steps = rem.get("steps", [])
            refs  = rem.get("references", [])

            # First non-indented step as the action summary; indented lines as sub-detail
            main_steps = [s for s in steps if not s.startswith("  ")]
            cmd_steps  = [s for s in steps if s.startswith("  ")]

            steps_html = ""
            if main_steps:
                items = "".join(f"<li>{_h(s)}</li>" for s in main_steps[:4])
                steps_html = f'<ul class="rem-steps-compact">{items}</ul>'
            if cmd_steps:
                cmds = "\n".join(s.strip() for s in cmd_steps[:4])
                steps_html += f'<pre class="cmd-block">{_h(cmds)}</pre>'

            refs_html = ""
            if refs:
                refs_html = '<div class="rem-refs">' + " &nbsp;·&nbsp; ".join(
                    f'<span class="ref-tag">{_h(r)}</span>' for r in refs
                ) + '</div>'

            rows.append(
                f'<tr>'
                f'<td class="center bold" style="color:{tl_color};font-size:16px">{priority}</td>'
                f'<td>{_SEV_BADGE.get(sev, _h(sev))}</td>'
                f'<td class="mono small">{_h(cid)}</td>'
                f'<td><strong>{_h(f.get("title",""))}</strong>'
                f'{steps_html}{refs_html}</td>'
                f'</tr>'
            )

        header_color = tl_color
        html_parts.append(
            f'<h3 class="sh" style="color:{header_color};font-size:14px;margin-top:20px">'
            f'{tl_icon} {tl_label}</h3>'
            f'<table class="data-table">'
            f'<thead><tr><th style="width:36px">#</th><th style="width:80px">{t("label.severity", data.incident.language)}</th>'
            f'<th style="width:160px">{t("label.check_id", data.incident.language)}</th><th>{t("label.action", data.incident.language)}</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )

    if not html_parts:
        return ""

    return f"""
<section class="section" id="remediation">
  <h2 class="st">{t("section.remediation", data.incident.language)}</h2>
  <p class="dim small" style="margin-bottom:4px">
    Unique findings grouped by remediation urgency. Each finding appears once,
    sorted by severity within each tier.
  </p>
  {"".join(html_parts)}
</section>"""
