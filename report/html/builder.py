"""HTML report builder. Assembles all sections into a single self-contained
HTML document with inline CSS/JS and a strict CSP."""
from __future__ import annotations

from datetime import datetime, timezone

from ..data import AuditData
from ..i18n import t
from ..utils import h
from .assets import load_css, load_js

from .sections.header import _section_header
from .sections.overview import _section_charts
from .sections.domain import (
    _section_domain, _section_top_priorities, _section_preflight,
)
from .sections.auth import (
    _section_password_policy, _section_ldap_security, _section_laps,
    _section_security_events,
)
from .sections.identity import _section_account_issues
from .sections.privileged_enriched import section_privileged_enriched
from .sections.infra import (
    _section_gpo, _section_adcs, _section_modules,
)
from .sections.findings import _section_findings
from .sections.positives import _section_positive_controls
from .sections.remediation import _section_remediation_plan
from .sections.inventory import _section_inventory
from .sections.ir import (
    section_ir_banner, section_ir_timeline,
    section_correlations, section_post_ransomware,
)
from .sections.extra_evidence import section_orphan_txt
from .sections.gpo_ir import section_gpo_ir
from .sections.attack_paths import section_attack_paths
from .sections.scorecard import section_scorecard
from .sections.diagnostics import (
    section_evidence_coverage, section_diagnostics,
)


_NAV_ITEMS_BASE = [
    ("#scorecard",      "nav.scorecard"),
    ("#charts",         "nav.overview"),
    ("#domain",         "nav.domain"),
    ("#priorities",     "nav.priorities"),
    ("#remediation",    "nav.remediation"),
    ("#positives",      "nav.positives"),
    ("#pwpolicy",       "nav.passwords"),
    ("#ldap",           "nav.ldap"),
    ("#laps",           "nav.laps"),
    ("#secevents",      "nav.events"),
    ("#attack-paths",   "nav.attack_paths"),
    ("#privaccounts",   "nav.privileged"),
    ("#acctissues",     "nav.accounts"),
    ("#gpo",            "nav.gpo"),
    ("#gpo-ir",         "nav.gpo_ir"),
    ("#adcs",           "nav.adcs"),
    ("#extra-evidence", "nav.evidence_extra"),
    ("#preflight",      "nav.preflight"),
    ("#modules",        "nav.modules"),
    ("#findings",       "nav.findings"),
    ("#inventory",      "nav.inventory"),
    ("#coverage",       "nav.coverage"),
    ("#diagnostics",    "nav.diagnostics"),
]

_NAV_ITEMS_IR = [
    ("#ir-banner",    "nav.ir_banner"),
    ("#ir-timeline",  "nav.ir_timeline"),
    ("#correlations", "nav.correlations"),
    ("#ir-checklist", "nav.ir_checklist"),
]

_CSP = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none';"
)

NL = chr(10)


def build_html(data: AuditData) -> str:
    hostname = data.execution.get("hostname", "ADaudit")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lang = data.incident.language or "es"

    nav_items = (_NAV_ITEMS_IR if data.incident.active else []) + _NAV_ITEMS_BASE
    nav = "".join(
        '<a href="' + href + '">' + t(key, lang) + '</a>'
        for href, key in nav_items
    )

    sections = [
        section_ir_banner(data),
        _section_header(data),
        section_scorecard(data),
        _section_charts(data),
        section_evidence_coverage(data),
        section_ir_timeline(data),
        section_correlations(data),
        section_post_ransomware(data),
        _section_domain(data),
        _section_top_priorities(data),
        _section_remediation_plan(data),
        _section_positive_controls(data),
        _section_password_policy(data),
        _section_ldap_security(data),
        _section_laps(data),
        _section_security_events(data),
        section_attack_paths(data),
        section_privileged_enriched(data),
        _section_account_issues(data),
        _section_gpo(data),
        section_gpo_ir(data),
        _section_adcs(data),
        section_orphan_txt(data),
        _section_preflight(data),
        _section_modules(data),
        _section_findings(data),
        _section_inventory(data),
        section_diagnostics(data),
    ]

    css = load_css()
    js = load_js()
    body_sections = "".join(s for s in sections if s)
    fqdn = h(data.execution.get("fqdn", ""))
    title_host = h(hostname)

    parts = [
        "<!DOCTYPE html>",
        '<html lang="' + h(lang) + '">',
        "<head>",
        '  <meta charset="UTF-8">',
        '  <meta name="viewport" content="width=device-width,initial-scale=1">',
        '  <meta http-equiv="Content-Security-Policy" content="' + _CSP + '">',
        '  <meta name="referrer" content="no-referrer">',
        "  <title>ADaudit &mdash; " + title_host + "</title>",
        "  <style>" + css + "</style>",
        "</head>",
        "<body>",
        '<nav class="nav-toc">',
        '  <strong style="color:#fff;margin-right:6px">LZ-ADaudit</strong>',
        "  " + nav,
        ('  <span style="margin-left:auto;color:var(--dim);font-size:11px">'
         + t("label.generated", lang) + " " + generated + "</span>"),
        "</nav>",
        '<div class="wrapper">',
        body_sections,
        "<footer>LZ-ADaudit &nbsp;&middot;&nbsp; " + t("label.generated", lang) + ": " + generated +
        " &nbsp;&middot;&nbsp; " + fqdn + "</footer>",
        "</div>",
        "<script>" + js + "</script>",
        "</body>",
        "</html>",
    ]
    return NL.join(parts)
