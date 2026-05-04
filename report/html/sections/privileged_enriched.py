"""Enriched privileged-account table (v1.5.0): cross-references the SAM-only
lists from domain_admins.txt / enterprise_admins.txt / schema_admins.txt /
accounts_userPrivileged.txt against inventory/users.csv to surface, for each
admin: WhenCreated, PasswordLastSet, LastLogonDate, AdminCount, SPN, flags.

In incident-response context, accounts whose PasswordLastSet or LastLogonDate
fall inside the incident window are flagged red - this is the most direct
signal of an account being used during the breach.
"""
from __future__ import annotations

import re

from ...data import AuditData
from ...i18n import t
from ...ir.parsers import parse_dt_loose
from ...utils import h, txt


def _parse_admin_lists(data: AuditData) -> dict[str, list[str]]:
    """Return dict {sam_lower: [groups...]} for every privileged account
    detected by the .ps1, regardless of source list."""
    sam_groups: dict[str, list[str]] = {}

    def _add(group: str, sam: str) -> None:
        sam = sam.strip().lower()
        if not sam:
            return
        sam_groups.setdefault(sam, [])
        if group not in sam_groups[sam]:
            sam_groups[sam].append(group)

    for key, group in [("domain_admins", "Domain Admins"),
                       ("enterprise_admins", "Enterprise Admins"),
                       ("schema_admins", "Schema Admins")]:
        for ln in txt(data, key):
            parts = ln.split(" ", 2)
            if len(parts) >= 2:
                _add(group, parts[1])

    # accounts_userPrivileged: format "sam (display) ..."
    for ln in txt(data, "accounts_userPrivileged"):
        m = re.match(r"^(\S+)\s+\(", ln)
        if m:
            _add("Privileged", m.group(1))
        else:
            _add("Privileged", ln.split()[0] if ln.split() else "")

    # accounts_protectedusers
    for ln in txt(data, "accounts_protectedusers"):
        m = re.match(r"^(\S+)\s+\(", ln)
        if m:
            _add("Protected Users", m.group(1))

    return sam_groups


def section_privileged_enriched(data: AuditData) -> str:
    """Render the enriched admin table. Returns empty string if no admins."""
    sam_groups = _parse_admin_lists(data)
    if not sam_groups:
        return ""

    lang = data.incident.language or "es"
    inc = data.incident

    # Index users.csv by SAM for fast lookup
    users_by_sam: dict[str, dict[str, str]] = {}
    for row in data.inventory.get("users", []):
        s = (row.get("SamAccountName") or "").strip().lower()
        if s:
            users_by_sam[s] = row

    rows: list[str] = []
    flagged_count = 0

    # Sort: in-window first, then by group priority (DA > EA > SA > Priv)
    group_order = ["Domain Admins", "Enterprise Admins", "Schema Admins",
                   "Privileged", "Protected Users"]
    def _row_sort_key(item):
        sam, groups = item
        u = users_by_sam.get(sam, {})
        pls = parse_dt_loose(u.get("PasswordLastSet", ""))
        llogon = parse_dt_loose(u.get("LastLogonDate", ""))
        in_win = (inc.in_window(pls) or inc.in_window(llogon)) if inc.active else False
        # in_win first (0), else 1; then highest-priority group
        primary_group = min(
            (group_order.index(g) for g in groups if g in group_order),
            default=99,
        )
        return (0 if in_win else 1, primary_group, sam)

    for sam, groups in sorted(sam_groups.items(), key=_row_sort_key):
        u = users_by_sam.get(sam, {})
        display = u.get("DisplayName") or ""
        when_created = u.get("WhenCreated") or ""
        pwd_last = u.get("PasswordLastSet") or ""
        last_logon = u.get("LastLogonDate") or ""
        spn_raw = u.get("SPNs") or ""
        enabled = u.get("Enabled") or ""
        pwd_never = u.get("PasswordNeverExpires") or ""
        no_preauth = u.get("DoesNotRequirePreAuth") or ""

        # Determine in-window flags
        pls_dt = parse_dt_loose(pwd_last)
        llogon_dt = parse_dt_loose(last_logon)
        wc_dt = parse_dt_loose(when_created)
        in_win_pls = inc.active and inc.in_window(pls_dt)
        in_win_llogon = inc.active and inc.in_window(llogon_dt)
        in_win_wc = inc.active and inc.in_window(wc_dt)
        any_in_window = in_win_pls or in_win_llogon or in_win_wc
        if any_in_window:
            flagged_count += 1

        def _date_cell(raw: str, in_window: bool) -> str:
            if not raw:
                return '<span class="dim">&mdash;</span>'
            cls = ' style="color:#e74c3c;font-weight:600"' if in_window else ""
            badge = (' <span class="badge ir-window">EN VENTANA</span>'
                     if in_window else "")
            return f'<span{cls}>{h(raw)}</span>{badge}'

        # Flags column
        flag_parts = []
        if (enabled or "").lower() in ("false", "0"):
            flag_parts.append('<span class="dim">DISABLED</span>')
        if (pwd_never or "").lower() in ("true", "1"):
            flag_parts.append('<span class="risk-warn">PWD-NEVER</span>')
        if (no_preauth or "").lower() in ("true", "1"):
            flag_parts.append('<span class="risk-crit">NO-PREAUTH</span>')
        if spn_raw:
            flag_parts.append('<span class="risk-warn">SPN</span>')
        flags_html = " ".join(flag_parts) or '<span class="dim">&mdash;</span>'

        groups_html = " ".join(
            f'<span class="tag">{h(g)}</span>' for g in groups
        )

        row_class = "fr-window" if any_in_window else ""

        rows.append(
            f'<tr class="{row_class}">'
            f'<td>{groups_html}</td>'
            f'<td class="mono small">{h(sam)}</td>'
            f'<td class="small">{h(display)}</td>'
            f'<td class="small mono">{_date_cell(when_created, in_win_wc)}</td>'
            f'<td class="small mono">{_date_cell(pwd_last, in_win_pls)}</td>'
            f'<td class="small mono">{_date_cell(last_logon, in_win_llogon)}</td>'
            f'<td class="small">{flags_html}</td>'
            f'</tr>'
        )

    legend = ""
    if inc.active:
        legend = (
            f'<p class="dim small" style="margin-bottom:8px">'
            f'{t("priv.legend", lang)} '
            f'<strong style="color:#e74c3c">'
            f'{flagged_count} cuenta(s) tienen actividad en ventana.</strong></p>'
        )

    return f"""
<section class="section" id="privaccounts">
  <h2 class="st">{t("section.privileged", lang)}</h2>
  {legend}
  <div class="table-scroll">
    <table class="data-table">
      <thead><tr>
        <th>{t("priv.col.group", lang)}</th>
        <th>{t("priv.col.sam", lang)}</th>
        <th>{t("priv.col.display", lang)}</th>
        <th>{t("priv.col.created", lang)}</th>
        <th>{t("priv.col.pwd_last", lang)}</th>
        <th>{t("priv.col.last_logon", lang)}</th>
        <th>{t("priv.col.flags", lang)}</th>
      </tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</section>"""
