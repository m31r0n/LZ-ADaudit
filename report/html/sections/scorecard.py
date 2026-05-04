"""Posture scorecard section (v1.6.0).

Renders the front-of-report dashboard:
  - 5 KPI cards (Domain Maturity Score, Stale %, Privileged Density,
    Audit Coverage, Forest Risk)
  - SVG gauge for the overall maturity score
  - SVG radar chart for the 7 categories
  - Table with score per category + remediation pointers
  - Trend line if posture_history.json exists
"""
from __future__ import annotations

import math

from ...data import AuditData
from ...i18n import t
from ...scoring import (
    compute_posture_score, persist_history, load_history, CategoryScore,
)
from ...utils import h
from ..charts import svg_gauge, svg_radar


def _risk_color(score: float) -> str:
    if score >= 80:
        return "#2ecc71"   # green — Low
    if score >= 60:
        return "#f1c40f"
    if score >= 40:
        return "#f39c12"
    return "#c0392b"       # red — Critical


def _kpi_card(label: str, value: str, color: str, sublabel: str = "") -> str:
    sub = f'<div class="kpi-sub">{h(sublabel)}</div>' if sublabel else ""
    return (
        '<div class="kpi-card" style="border-top:4px solid ' + color + '">'
        f'<div class="kpi-label">{h(label)}</div>'
        f'<div class="kpi-value" style="color:{color}">{h(value)}</div>'
        f'{sub}</div>'
    )


def _trend_line_svg(history: list[dict], width: int = 240, height: int = 60) -> str:
    """Mini sparkline of overall_score across past runs."""
    if len(history) < 2:
        return ""
    points = [(h.get("overall_score") or 0) for h in history]
    n = len(points)
    margin = 4
    inner_w = width - 2 * margin
    inner_h = height - 2 * margin
    coords = []
    for i, sc in enumerate(points):
        x = margin + (inner_w * i / max(n - 1, 1))
        y = margin + (inner_h * (100 - sc) / 100)
        coords.append((x, y))
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    delta = points[-1] - points[0]
    delta_color = "#2ecc71" if delta >= 0 else "#e74c3c"
    delta_sign = "+" if delta >= 0 else ""
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'style="background:transparent">'
        f'<polyline points="{poly}" fill="none" stroke="{_risk_color(points[-1])}" '
        f'stroke-width="2"/>'
        + "".join(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" '
            f'fill="{_risk_color(points[i])}"/>'
            for i, (x, y) in enumerate(coords))
        + f'<text x="{width-4}" y="14" text-anchor="end" fill="{delta_color}" '
        f'font-size="11" font-weight="bold" font-family="monospace">'
        f'{delta_sign}{delta:.1f}</text>'
        '</svg>'
    )


def section_scorecard(data: AuditData) -> str:
    posture = compute_posture_score(data)
    persist_history(data.folder, posture)
    history = load_history(data.folder)

    # ---- KPI cards (5 grandes) ----
    kp = posture.kpis
    overall = posture.overall_score
    cards = (
        _kpi_card("Domain Maturity Score",
                  f"{kp['domain_maturity_score']:.1f}",
                  _risk_color(kp["domain_maturity_score"]),
                  f"Risk band: {posture.risk_band}") +
        _kpi_card("Stale Object %",
                  f"{kp['stale_object_pct']:.1f} %",
                  ("#2ecc71" if kp["stale_object_pct"] < 5
                   else "#f39c12" if kp["stale_object_pct"] < 15 else "#c0392b"),
                  f"{kp['inactive_count']} inactivas, {kp['disabled_count']} disabled") +
        _kpi_card("Privileged Density",
                  f"{kp['priv_account_density']:.2f} %",
                  ("#2ecc71" if kp["priv_account_density"] < 1
                   else "#f39c12" if kp["priv_account_density"] < 3 else "#c0392b"),
                  f"{kp['admin_count']} admins / {kp['users_total']} usuarios") +
        _kpi_card("Audit Coverage",
                  f"{kp['audit_coverage_pct']} %",
                  "#2ecc71" if kp["audit_coverage_pct"] == 100 else "#c0392b",
                  ("Security log activo" if kp["audit_coverage_pct"] == 100
                   else "AD-IR-001: log silencioso")) +
        _kpi_card("Forest Risk Score",
                  f"{kp['forest_risk_score']}",
                  _risk_color(kp["forest_risk_score"]),
                  "Riesgo de takeover de bosque")
    )

    # ---- Gauge + radar side-by-side ----
    gauge_svg = svg_gauge(overall, label="Domain Maturity Score")
    radar_data = {cat: cs.score for cat, cs in posture.category_scores.items()}
    radar_svg = svg_radar(radar_data)

    # ---- History trend ----
    trend = ""
    if len(history) >= 2:
        trend_svg = _trend_line_svg(history)
        trend = (
            '<div class="trend-card">'
            f'<div class="kpi-label">Tendencia (ultimos {len(history)} runs)</div>'
            f'{trend_svg}</div>'
        )

    # ---- Category breakdown table ----
    rows: list[str] = []
    for cs in sorted(posture.category_scores.values(),
                     key=lambda x: x.score):
        sev = cs.severity_breakdown
        sev_html = " ".join(
            f'<span class="sev-pill sev-{s}">{n} {s[:3]}</span>'
            for s, n in sorted(sev.items(),
                               key=lambda kv: -SEV_ORDER.get(kv[0], 99))
        ) or '<span class="dim small">&mdash;</span>'
        top_html = ", ".join(cs.top_check_ids[:3]) or "&mdash;"
        bar_w = int(cs.score)
        color = _risk_color(cs.score)
        rows.append(
            '<tr>'
            f'<td><strong>{h(cs.name)}</strong></td>'
            f'<td class="center">{cs.weight}%</td>'
            f'<td><div class="score-bar"><div class="score-bar-fill" '
            f'style="width:{bar_w}%;background:{color}"></div>'
            f'<span class="score-bar-text">{cs.score:.1f}</span></div></td>'
            f'<td class="center">{cs.findings_count}</td>'
            f'<td>{sev_html}</td>'
            f'<td class="mono small">{top_html}</td>'
            '</tr>'
        )

    return f"""
<section class="section" id="scorecard">
  <h2 class="st">Posture Score &mdash; estado general del dominio</h2>
  <p class="dim small" style="margin-bottom:12px">
    Score 0&ndash;100 (mas alto = mejor) calculado a partir de los hallazgos
    activos. Metodologia publica (v{posture.methodology_version}): cada
    finding penaliza segun severidad, ponderado por categoria. Trazable y
    re-medible en cada run.
  </p>
  <div class="kpi-row">{cards}{trend}</div>
  <div class="charts-row" style="margin-top:14px">
    <div class="chart-card">{gauge_svg}</div>
    <div class="chart-card">{radar_svg}</div>
  </div>
  <h3 class="sh">Score por categoria</h3>
  <table class="data-table">
    <thead><tr>
      <th>Categoria</th>
      <th class="center" style="width:60px">Peso</th>
      <th style="width:240px">Score</th>
      <th class="center" style="width:80px">Findings</th>
      <th>Severidades</th>
      <th>Top check IDs</th>
    </tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>"""


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
