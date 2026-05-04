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


def _section_positive_controls(data: AuditData) -> str:
    """Show passed findings and a static positive-controls checklist."""
    passed = [f for f in data.findings if f.get("status") == "passed"]

    # Static positive indicators derived from evidence
    ev_ldap   = data.evidence.get("ldap", {})
    ev_dom    = data.evidence.get("domain", {})
    ev_pp     = data.evidence.get("password_policy", {}).get("default_policy", {})
    ev_laps   = data.evidence.get("laps", {})

    positives: list[tuple[str, str]] = []

    # Password policy positives
    if ev_pp.get("ComplexityEnabled"):
        positives.append(("Password Complexity", "Enabled — requires uppercase, lowercase, digits and symbols."))
    if ev_pp.get("ReversibleEncryptionEnabled") is False:
        positives.append(("Reversible Encryption", "Disabled — passwords cannot be extracted as plaintext from NTDS.dit."))
    hist = ev_pp.get("PasswordHistoryCount", 0)
    if isinstance(hist, int) and hist >= 10:
        positives.append(("Password History", f"{hist} passwords remembered — prevents recent password reuse."))
    thresh = ev_pp.get("LockoutThreshold", 0)
    if isinstance(thresh, int) and 0 < thresh <= 10:
        positives.append(("Account Lockout Threshold", f"{thresh} attempts — brute-force protection active."))

    # LDAP positives
    if ev_ldap.get("RestrictAnonymousSam") == 1:
        positives.append(("SAM Anonymous Enumeration", "Restricted — prevents anonymous SAM account listing."))

    # Domain positives
    if ev_dom.get("recycle_bin_enabled"):
        positives.append(("AD Recycle Bin", "Enabled — deleted objects recoverable without DC restore."))

    # LAPS positives (negative check — if LAPS is actually configured somewhere)
    if ev_laps.get("windows_laps_schema") or ev_laps.get("legacy_laps_schema"):
        positives.append(("LAPS Schema", "LAPS schema detected in AD — local password management active."))

    # From IR events — no recent user creations is positive
    ev_sec = data.evidence.get("security_events", {})
    if ev_sec.get("totals", {}).get("user_creations", -1) == 0:
        positives.append(("Recent Account Creation", "No new user accounts detected in the last 30 days (Event ID 4720)."))

    # Passed findings from ndjson
    for f in passed:
        positives.append((f.get("title", f.get("check_id", "")),
                          f.get("evidence", "") or "Check passed — no issues found."))

    if not positives:
        return ""

    rows = "".join(
        f'<tr>'
        f'<td class="pos-icon">&#x2713;</td>'
        f'<td class="small bold" style="color:#2ecc71">{_h(title)}</td>'
        f'<td class="small">{_h(detail)}</td>'
        f'</tr>'
        for title, detail in positives
    )
    return f"""
<section class="section" id="positives">
  <h2 class="st" style="color:#2ecc71">&#x2705; Positive Controls</h2>
  <p class="dim small" style="margin-bottom:10px">Controls and configurations that are correctly implemented.</p>
  <table class="data-table">
    <thead><tr><th style="width:30px"></th><th>Control</th><th>Detail</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""
