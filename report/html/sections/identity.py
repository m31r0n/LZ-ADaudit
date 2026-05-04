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


def _section_account_issues(data: AuditData) -> str:
    tabs: list[str] = []
    panels: list[str] = []

    def _add_raw_tab(key: str, title: str) -> None:
        lines = _txt(data, key)
        if not lines:
            return
        active = "active" if not tabs else ""
        idx = len(tabs)
        tabs.append(f'<button class="tab-btn {active}" data-tab="acct-{idx}">{title} ({len(lines)})</button>')
        rows = "".join(f'<tr><td class="small">{_h(ln)}</td></tr>' for ln in lines)
        panels.append(
            f'<div class="tab-panel {active}" id="acct-{idx}">'
            f'<table class="data-table"><tbody>{rows}</tbody></table></div>'
        )

    _add_raw_tab("accounts_inactive",       "Inactive (180+ days)")
    _add_raw_tab("accounts_passdontexpire", "Password Never Expires")
    _add_raw_tab("accounts_disabled",       "Disabled Accounts")
    _add_raw_tab("new_users",               "Recently Created Users")
    _add_raw_tab("new_groups",              "Recently Created Groups")

    if not tabs:
        return ""
    return f"""
<section class="section" id="acctissues">
  <h2 class="st">{t("section.accounts", data.incident.language)}</h2>
  <div class="tab-bar">{"".join(tabs)}</div>
  {"".join(panels)}
</section>"""
