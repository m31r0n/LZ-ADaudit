"""Report header section: brand, host metadata, severity scorecard."""
from __future__ import annotations

from ...data import AuditData
from ...i18n import t
from ...utils import h as _h, fmt_dt as _fmt_dt, fmt_dur as _fmt_dur


def _section_header(data: AuditData) -> str:
    ex = data.execution
    sm = data.summary
    hostname = ex.get("hostname") or ex.get("fqdn") or "Unknown"
    sev = sm.get("findings_by_severity", {}) or {}
    crit = sev.get("critical", 0)
    hi = sev.get("high", 0)
    med = sev.get("medium", 0)
    low = sev.get("low", 0)
    inf = sev.get("informational", 0)
    tot = sm.get("total_findings", len(data.findings))
    # Border tint for HIGH card: critical-driven if any critical, else high
    rc = ("#c0392b" if crit > 0
          else ("#e74c3c" if hi >= 5
                else ("#f39c12" if hi > 0 else "#3498db")))
    return f"""
<header class="report-header">
  <div class="header-brand">
    <span class="brand-icon">&#x1F512;</span>
    <div>
      <div class="brand-title">LZ-ADaudit {_h(ex.get('tool_version',''))}</div>
      <div class="brand-sub">{t("label.subtitle", data.incident.language)}</div>
    </div>
  </div>
  <div class="header-meta">
    <div class="meta-item"><span class="ml">{t("label.host", data.incident.language)}</span><span class="mv">{_h(hostname)}</span></div>
    <div class="meta-item"><span class="ml">{t("label.domain", data.incident.language)}</span><span class="mv">{_h(ex.get('domain_name','—'))}</span></div>
    <div class="meta-item"><span class="ml">{t("label.profile", data.incident.language)}</span><span class="mv">{_h(ex.get('profile_selected','—'))}</span></div>
    <div class="meta-item"><span class="ml">{t("label.started", data.incident.language)}</span><span class="mv">{_fmt_dt(ex.get('started_at_utc'))}</span></div>
    <div class="meta-item"><span class="ml">{t("label.duration", data.incident.language)}</span><span class="mv">{_fmt_dur(ex.get('duration_seconds'))}</span></div>
  </div>
  <div class="scorecard">
    <div class="sc-box" style="border-color:#c0392b"><div class="sc-n" style="color:#c0392b">{crit}</div><div class="sc-l">CRITICAL</div></div>
    <div class="sc-box" style="border-color:{rc}"><div class="sc-n" style="color:{rc}">{hi}</div><div class="sc-l">HIGH</div></div>
    <div class="sc-box" style="border-color:#f39c12"><div class="sc-n" style="color:#f39c12">{med}</div><div class="sc-l">MEDIUM</div></div>
    <div class="sc-box" style="border-color:#3498db"><div class="sc-n" style="color:#3498db">{low}</div><div class="sc-l">LOW</div></div>
    <div class="sc-box" style="border-color:#95a5a6"><div class="sc-n" style="color:#95a5a6">{inf}</div><div class="sc-l">INFO</div></div>
    <div class="sc-box" style="border-color:#cdd6f4"><div class="sc-n" style="color:#cdd6f4">{tot}</div><div class="sc-l">TOTAL</div></div>
  </div>
</header>"""
