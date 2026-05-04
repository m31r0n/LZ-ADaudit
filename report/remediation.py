"""Remediation API: get_rem(check_id, ctx) substitutes {{tokens}} from an
audit-derived context dict. Keeps the data (remediation_db.py) decoupled
from the rendering."""
from __future__ import annotations

import re

from .remediation_db import _REMEDIATION_DB

_TOKEN_RX = re.compile(r"\{\{\s*([\w\.\-]+)\s*\}\}")


def resolve_tokens(text, ctx: dict[str, str]):
    """Replace {{token}} placeholders in *text* using the *ctx* dict.

    Tokens absent from the context are left intact so the report makes the
    gap visible (rather than silently rendering an empty string).
    """
    if not text or "{{" not in str(text):
        return text

    def _sub(m: re.Match[str]) -> str:
        return ctx.get(m.group(1).strip(), m.group(0))

    return _TOKEN_RX.sub(_sub, str(text))


def _ctx_domain_dn(dom: dict, ex: dict) -> str:
    fqdn = dom.get("domain_name") or ex.get("domain_name") or ""
    if fqdn and "." in fqdn:
        return ",".join(f"DC={p}" for p in fqdn.split("."))
    return "<DC=your-domain,DC=tld>"


def remediation_context(data) -> dict[str, str]:
    """Build the token substitution context from evidence + IR config."""
    dom = data.evidence.get("domain", {}) or {}
    ex = data.execution or {}
    inc = data.incident
    return {
        "domain_dn":     _ctx_domain_dn(dom, ex),
        "domain_fqdn":   dom.get("domain_name") or ex.get("domain_name") or "<your-domain.tld>",
        "forest_root":   dom.get("forest_name") or ex.get("forest_name") or "<forest.root.tld>",
        "netbios":       dom.get("netbios_name") or "<NETBIOS>",
        "computer_pdc":  dom.get("pdc_emulator") or "<PDC>",
        "hostname":      ex.get("hostname") or "<DC>",
        "auditor":       inc.auditor or "<auditor>",
        "incident_date": (inc.incident_date.strftime("%Y-%m-%d")
                          if inc.incident_date else "<incident-date>"),
        "window_start":  (inc.window_start.strftime("%Y-%m-%d")
                          if inc.window_start else "<window-start>"),
        "window_end":    (inc.window_end.strftime("%Y-%m-%d")
                          if inc.window_end else "<window-end>"),
    }


def get_rem(check_id: str, ctx: dict[str, str] | None = None) -> dict:
    """Return the remediation entry for *check_id*, with optional token
    substitution. Empty dict when the check_id is unknown."""
    rem = _REMEDIATION_DB.get(check_id, {})
    if not rem or not ctx:
        return rem
    return {
        "timeline": rem.get("timeline", "none"),
        "context":  resolve_tokens(rem.get("context", ""), ctx),
        "steps":    [resolve_tokens(s, ctx) for s in rem.get("steps", [])],
        "references": [resolve_tokens(r, ctx)
                       for r in rem.get("references", [])],
    }


def timeline_badge(check_id: str, lang: str = "es") -> str:
    """Return an HTML badge for the timeline of a check_id (or empty string)."""
    from .utils import TIMELINE
    rem = _REMEDIATION_DB.get(check_id, {})
    tl = rem.get("timeline", "")
    if not tl or tl not in TIMELINE:
        return ""
    from .i18n import t
    _label, color, icon = TIMELINE[tl]
    label = t(f"timeline.{tl}", lang)
    return (f'<span class="tl-badge" style="border-color:{color};color:{color}">'
            f'{icon} {label}</span>')


def coverage_check() -> tuple[set[str], int]:
    """Return (check_ids in DB, total entries) for sanity / coverage scripts."""
    return set(_REMEDIATION_DB.keys()), len(_REMEDIATION_DB)
