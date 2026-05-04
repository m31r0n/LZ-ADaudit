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


def _section_password_policy(data: AuditData) -> str:
    pp = data.evidence.get("password_policy", {})
    if not pp:
        return ""
    dp = pp.get("default_policy", {})
    fgp = pp.get("fine_grained_policies", [])

    def _days(field_obj: Any) -> str:
        if isinstance(field_obj, dict):
            d = int(field_obj.get("TotalDays", 0))
            return f"{d} days" if d else "Never"
        return str(field_obj)

    def _mins(field_obj: Any) -> str:
        if isinstance(field_obj, dict):
            m = int(field_obj.get("TotalMinutes", 0))
            return f"{m} min" if m else "Indefinite"
        return str(field_obj)

    def _bool_risk(val: Any, good_if_true: bool = True) -> str:
        is_true = bool(val)
        ok = is_true if good_if_true else not is_true
        cls = "risk-ok" if ok else "risk-warn"
        return f'<span class="{cls}">{"Yes" if is_true else "No"}</span>'

    max_age = dp.get("MaxPasswordAge", {})
    max_age_days = int(max_age.get("TotalDays", 0)) if isinstance(max_age, dict) else 0
    age_cls = "risk-ok" if 0 < max_age_days <= 90 else "risk-warn"

    min_len = dp.get("MinPasswordLength", 0)
    len_cls = "risk-ok" if min_len >= 14 else ("risk-warn" if min_len >= 12 else "risk-crit")

    threshold = dp.get("LockoutThreshold", 0)
    thresh_cls = "risk-ok" if 0 < threshold <= 10 else "risk-warn"

    rows = [
        ("Min Password Length",   f'<span class="{len_cls}">{min_len} chars</span>'),
        ("Max Password Age",      f'<span class="{age_cls}">{_days(max_age)}</span>'),
        ("Min Password Age",      _days(dp.get("MinPasswordAge", {}))),
        ("Password History",      f'{dp.get("PasswordHistoryCount","—")} remembered'),
        ("Complexity Required",   _bool_risk(dp.get("ComplexityEnabled"), True)),
        ("Reversible Encryption", _bool_risk(dp.get("ReversibleEncryptionEnabled"), False)),
        ("Lockout Threshold",     f'<span class="{thresh_cls}">{threshold} attempts</span>'),
        ("Lockout Duration",      _mins(dp.get("LockoutDuration", {}))),
        ("Observation Window",    _mins(dp.get("LockoutObservationWindow", {}))),
    ]

    tbody = "".join(
        f"<tr><td class='td-label'>{_h(k)}</td><td>{v}</td></tr>"
        for k, v in rows
    )

    fgp_html = ""
    if fgp:
        fgp_rows = "".join(
            f'<tr><td class="mono small">{_h(p.get("Name",""))}</td>'
            f'<td>{_h(p.get("Precedence",""))}</td>'
            f'<td class="small">{_h(str(p.get("AppliesTo","")))}</td></tr>'
            for p in fgp
        )
        fgp_html = f"""
  <h3 class="sh">Fine-Grained Policies ({len(fgp)})</h3>
  <table class="data-table"><thead><tr><th>Name</th><th>Precedence</th><th>Applies To</th></tr></thead>
  <tbody>{fgp_rows}</tbody></table>"""
    else:
        fgp_html = '<p class="dim small" style="margin-top:8px">No fine-grained password policies configured.</p>'

    return f"""
<section class="section" id="pwpolicy">
  <h2 class="st">{t("section.password_policy", data.incident.language)}</h2>
  <table class="data-table" style="max-width:520px">
    <tbody>{tbody}</tbody>
  </table>
  {fgp_html}
</section>"""


def _section_ldap_security(data: AuditData) -> str:
    ldap = data.evidence.get("ldap", {})

    integrity = ldap.get("LDAPServerIntegrity", -1)
    anon = ldap.get("RestrictAnonymous", -1)
    anon_sam = ldap.get("RestrictAnonymousSam", -1)

    _INT_LABEL = {0: ("NONE — No signing required", "risk-crit"),
                  1: ("Negotiate — Not enforced", "risk-warn"),
                  2: ("Require Signing", "risk-ok")}
    _ANON_LABEL = {0: ("None — Anonymous enum allowed", "risk-crit"),
                   1: ("No SAM anonymous listing", "risk-warn"),
                   2: ("Restricted", "risk-ok")}
    _SAM_LABEL  = {0: ("Allowed", "risk-crit"), 1: ("Restricted", "risk-ok")}

    def row(label: str, val: int, lookup: dict) -> str:
        txt, cls = lookup.get(val, (f"Unknown ({val})", ""))
        return f"<tr><td class='td-label'>{_h(label)}</td><td><span class='{cls}'>{_h(txt)}</span></td></tr>"

    ldap_table = ""
    if ldap:
        ldap_table = f"""
  <table class="data-table" style="max-width:560px">
    <tbody>
      {row("LDAP Server Integrity", integrity, _INT_LABEL)}
      {row("Restrict Anonymous", anon, _ANON_LABEL)}
      {row("Restrict Anonymous SAM", anon_sam, _SAM_LABEL)}
    </tbody>
  </table>"""

    def txt_block(key: str, title: str) -> str:
        lines = _txt(data, key)
        if not lines:
            return ""
        content = "\n".join(_h(l) for l in lines)
        return f'<h3 class="sh">{title}</h3><pre class="text-block">{content}</pre>'

    ldap_txt = txt_block("LDAPSecurity", "LDAP Security Assessment")
    ntlm_txt = txt_block("ntlm_restrictions", "NTLM Restrictions (GPO)")
    kerb_lines = _txt(data, "dcs_weak_kerberos_ciphersuite")
    kerb_html = ""
    if kerb_lines:
        kerb_rows = "".join(
            f'<tr><td class="mono small">{_h(p[0])}</td>'
            f'<td class="center"><span class="risk-warn">{_h(p[1])} (includes RC4)</span></td></tr>'
            for ln in kerb_lines if len(p := ln.split()) == 2
        )
        kerb_html = (
            '<h3 class="sh">DCs with Weak Kerberos Encryption (msDS-SupportedEncryptionTypes)</h3>'
            f'<table class="data-table" style="max-width:500px"><thead>'
            f'<tr><th>DC</th><th>Enc Types Value</th></tr></thead>'
            f'<tbody>{kerb_rows}</tbody></table>'
        )

    return f"""
<section class="section" id="ldap">
  <h2 class="st">{t("section.ldap", data.incident.language)}</h2>
  {ldap_table}
  {ldap_txt}
  {ntlm_txt}
  {kerb_html}
</section>"""


def _section_laps(data: AuditData) -> str:
    laps = data.evidence.get("laps", {})
    missing = _txt(data, "winlaps_missing-computers")
    missing_dsrm = _txt(data, "winlaps_dcs_missing-dsrm")
    read_rights = _txt(data, "winlaps_read-extendedrights")

    legacy = laps.get("legacy_laps_schema", None)
    win_laps = laps.get("windows_laps_schema", None)

    def schema_badge(val: Any) -> str:
        if val is True:
            return '<span class="risk-ok">Configured</span>'
        if val is False:
            return '<span class="risk-crit">Not Configured</span>'
        return "—"

    schema_html = ""
    if laps:
        schema_html = f"""
  <table class="data-table" style="max-width:400px">
    <tbody>
      <tr><td class='td-label'>Legacy LAPS Schema</td><td>{schema_badge(legacy)}</td></tr>
      <tr><td class='td-label'>Windows LAPS Schema</td><td>{schema_badge(win_laps)}</td></tr>
      <tr><td class='td-label'>Domain Functional Level</td><td class="mono small">{_dfl_label(laps.get('domain_functional_level',''))}</td></tr>
    </tbody>
  </table>"""

    missing_html = ""
    if missing:
        items = "".join(f"<li class='mono small'>{_h(c)}</li>" for c in missing)
        missing_html = (f'<h3 class="sh">Computers Without LAPS ({len(missing)})</h3>'
                        f'<ul class="plain-list">{items}</ul>')

    dsrm_html = ""
    if missing_dsrm:
        items = "".join(f"<li class='mono small risk-crit'>{_h(c)}</li>" for c in missing_dsrm)
        dsrm_html = (f'<h3 class="sh">DCs Missing DSRM Password ({len(missing_dsrm)})</h3>'
                     f'<ul class="plain-list">{items}</ul>')

    rights_html = ""
    if read_rights:
        content = "\n".join(_h(l) for l in read_rights)
        rights_html = f'<h3 class="sh">LAPS Read Extended Rights</h3><pre class="text-block">{content}</pre>'

    return f"""
<section class="section" id="laps">
  <h2 class="st">{t("section.laps", data.incident.language)}</h2>
  {schema_html}
  {missing_html}
  {dsrm_html}
  {rights_html}
</section>"""


def _section_security_events(data: AuditData) -> str:
    ev_json = data.evidence.get("security_events", {})
    ev_csv = data.security_events_csv

    totals = ev_json.get("totals", {})
    events = ev_json.get("events", [])
    lookback = ev_json.get("lookback_days", "?")

    totals_html = ""
    if totals:
        cards = "".join(
            f'<div class="ic"><div class="ic-l">{_h(k.replace("_"," ").title())}</div>'
            f'<div class="ic-v">{_h(v)}</div></div>'
            for k, v in totals.items()
        )
        totals_html = f'<p class="dim small" style="margin-bottom:8px">Lookback: {lookback} days</p><div class="info-grid">{cards}</div>'

    events_html = ""
    if ev_csv:
        # Use CSV (may have more rows than JSON summary)
        source = ev_csv
        rows = "".join(
            f'<tr><td class="mono small">{_h(e.get("timestamp_utc",""))}</td>'
            f'<td class="center">{_h(e.get("event_id",""))}</td>'
            f'<td class="small">{_h(e.get("action",""))}</td>'
            f'<td class="mono small">{_h(e.get("actor",""))}</td>'
            f'<td class="mono small">{_h(e.get("target",""))}</td>'
            f'<td class="small">{_h(e.get("group_name",""))}</td></tr>'
            for e in source[:200]
        )
        more = f'<p class="dim small">Showing {min(len(source),200)} of {len(source)} events.</p>' if len(source) > 200 else ""
        events_html = (
            f'<h3 class="sh">Security Events (IDs: {", ".join(str(i) for i in ev_json.get("event_ids",[]))})</h3>'
            f'{more}<div class="table-scroll"><table class="data-table small">'
            f'<thead><tr><th>Timestamp</th><th>Event ID</th><th>Action</th>'
            f'<th>Actor</th><th>Target</th><th>Group</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )
    elif events:
        rows = "".join(
            f'<tr><td class="mono small">{_h(e.get("timestamp_utc",""))}</td>'
            f'<td class="center">{_h(e.get("event_id",""))}</td>'
            f'<td class="small">{_h(e.get("action",""))}</td>'
            f'<td class="mono small">{_h(e.get("actor",""))}</td>'
            f'<td class="mono small">{_h(e.get("target",""))}</td>'
            f'<td class="small">{_h(e.get("group_name",""))}</td></tr>'
            for e in events
        )
        events_html = (
            '<h3 class="sh">Security Events</h3>'
            '<div class="table-scroll"><table class="data-table small">'
            '<thead><tr><th>Timestamp</th><th>Event ID</th><th>Action</th>'
            '<th>Actor</th><th>Target</th><th>Group</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    if not totals_html and not events_html:
        return ""
    return f"""
<section class="section" id="secevents">
  <h2 class="st">{t("section.events", data.incident.language)}</h2>
  {totals_html}
  {events_html}
</section>"""
