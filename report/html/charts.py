"""SVG chart builders. Inline-friendly: no external assets, fixed sizes."""
from __future__ import annotations

import math
from datetime import datetime

from ..utils import h, CAT_COLORS


def svg_donut(counts: dict[str, int], colors: dict[str, str], title: str,
              size: int = 220) -> str:
    """Donut chart with center total + legend on the right."""
    total = sum(counts.values()) or 1
    cx = cy = size / 2
    ro, ri = size * 0.38, size * 0.22
    segs: list[str] = []
    legend: list[str] = []
    angle = -math.pi / 2
    for i, (key, val) in enumerate(counts.items()):
        if not val:
            continue
        sweep = 2 * math.pi * val / total
        x1 = cx + ro * math.cos(angle)
        y1 = cy + ro * math.sin(angle)
        x2 = cx + ro * math.cos(angle + sweep)
        y2 = cy + ro * math.sin(angle + sweep)
        xi1 = cx + ri * math.cos(angle + sweep)
        yi1 = cy + ri * math.sin(angle + sweep)
        xi2 = cx + ri * math.cos(angle)
        yi2 = cy + ri * math.sin(angle)
        lg = 1 if sweep > math.pi else 0
        c = colors.get(key, CAT_COLORS[i % len(CAT_COLORS)])
        segs.append(
            f'<path d="M{x1:.1f} {y1:.1f} A{ro:.1f} {ro:.1f} 0 {lg} 1 '
            f'{x2:.1f} {y2:.1f} L{xi1:.1f} {yi1:.1f} '
            f'A{ri:.1f} {ri:.1f} 0 {lg} 0 {xi2:.1f} {yi2:.1f}Z" '
            f'fill="{c}" stroke="#1a2035" stroke-width="1.5">'
            f'<title>{key}: {val}</title></path>'
        )
        if sweep > 0.28:
            mid = angle + sweep / 2
            lx = cx + ro * 1.18 * math.cos(mid)
            ly = cy + ro * 1.18 * math.sin(mid)
            segs.append(
                f'<text x="{lx:.1f}" y="{ly:.1f}" fill="{c}" font-size="10" '
                f'text-anchor="middle" dominant-baseline="middle" '
                f'font-family="monospace">{val/total*100:.0f}%</text>'
            )
        angle += sweep
        ly_l = 14 + i * 16
        legend.append(
            f'<rect x="0" y="{ly_l-9}" width="10" height="10" '
            f'fill="{c}" rx="2"/>'
            f'<text x="14" y="{ly_l}" fill="#cdd6f4" font-size="10" '
            f'font-family="monospace">{key} ({val})</text>'
        )
    segs += [
        f'<text x="{cx:.1f}" y="{cy-7:.1f}" fill="#fff" font-size="22" '
        f'text-anchor="middle" font-family="monospace" font-weight="bold">'
        f'{sum(counts.values())}</text>',
        f'<text x="{cx:.1f}" y="{cy+11:.1f}" fill="#888" font-size="10" '
        f'text-anchor="middle" font-family="monospace">total</text>',
    ]
    tw, th = size + 140, size + 30
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="{th}" '
        f'viewBox="0 0 {tw} {th}" style="background:transparent">'
        f'<text x="{tw/2:.1f}" y="18" fill="#cdd6f4" font-size="13" '
        f'text-anchor="middle" font-family="monospace" font-weight="bold">'
        f'{title}</text>'
        f'<g transform="translate(0,24)">{"".join(segs)}</g>'
        f'<g transform="translate({size+10},'
        f'{24+(size-len(counts)*16)//2})">{"".join(legend)}</g>'
        f'</svg>'
    )


def svg_hbar(counts: dict[str, int], colors: list[str], title: str,
             width: int = 460) -> str:
    """Horizontal bar chart."""
    if not counts:
        return ""
    max_v = max(counts.values()) or 1
    bh, gap, lw = 22, 6, 120
    ba = width - lw - 50
    ch = len(counts) * (bh + gap) + 40
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{ch}" viewBox="0 0 {width} {ch}" '
        f'style="background:transparent">',
        f'<text x="{width/2:.1f}" y="16" fill="#cdd6f4" font-size="13" '
        f'text-anchor="middle" font-family="monospace" font-weight="bold">'
        f'{title}</text>',
    ]
    for i, (key, val) in enumerate(counts.items()):
        c = colors[i % len(colors)]
        y = 28 + i * (bh + gap)
        bw = int(ba * val / max_v)
        lines += [
            f'<text x="{lw-4}" y="{y+bh-5}" fill="#cdd6f4" font-size="11" '
            f'text-anchor="end" font-family="monospace">{h(key)}</text>',
            f'<rect x="{lw}" y="{y}" width="{bw}" height="{bh}" '
            f'fill="{c}" rx="3"><title>{key}: {val}</title></rect>',
            f'<text x="{lw+bw+4}" y="{y+bh-5}" fill="{c}" font-size="11" '
            f'font-family="monospace">{val}</text>',
        ]
    lines.append("</svg>")
    return "".join(lines)


# ---------------------------------------------------------------------------
# v1.5.0 — IR timeline
# ---------------------------------------------------------------------------

def svg_ir_timeline(window_start: datetime, window_end: datetime,
                    incident_date: datetime,
                    events: list[tuple[datetime, str, str, str]],
                    width: int = 940, height: int = 220) -> str:
    """Horizontal SVG timeline with events as colour-coded dots/labels.

    Each event is a tuple ``(timestamp, label, color, source)``. The incident
    date is rendered as a vertical dashed red line.
    """
    margin_x = 60
    inner_w = width - 2 * margin_x
    ws_ts = window_start.timestamp()
    we_ts = window_end.timestamp()
    span = max(we_ts - ws_ts, 1)
    inc_x = margin_x + inner_w * (incident_date.timestamp() - ws_ts) / span

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" width="100%" '
        f'style="background:transparent;font-family:monospace">',
        f'<line x1="{margin_x}" y1="{height/2}" '
        f'x2="{width-margin_x}" y2="{height/2}" '
        f'stroke="#7f849c" stroke-width="2"/>',
        f'<line x1="{inc_x:.1f}" y1="20" x2="{inc_x:.1f}" '
        f'y2="{height-20}" stroke="#e74c3c" stroke-width="2" '
        f'stroke-dasharray="4,2"/>',
        f'<text x="{inc_x:.1f}" y="14" fill="#e74c3c" font-size="11" '
        f'text-anchor="middle">&#9889; Siniestro '
        f'{incident_date.strftime("%Y-%m-%d")}</text>',
        f'<text x="{margin_x}" y="{height-4}" fill="#7f849c" font-size="10">'
        f'{window_start.strftime("%Y-%m-%d")}</text>',
        f'<text x="{width-margin_x}" y="{height-4}" fill="#7f849c" '
        f'font-size="10" text-anchor="end">'
        f'{window_end.strftime("%Y-%m-%d")}</text>',
    ]

    last_x = -999
    last_above = False
    for ts, label, color, src in events:
        x = margin_x + inner_w * (ts.timestamp() - ws_ts) / span
        above = not last_above if abs(x - last_x) < 80 else False
        last_above = above
        last_x = x
        y_dot = height / 2
        y_line_end = height / 2 - 25 if above else height / 2 + 25
        y_text = y_line_end - 3 if above else y_line_end + 12
        label_short = label[:32] + ("…" if len(label) > 32 else "")
        parts.extend([
            f'<line x1="{x:.1f}" y1="{y_dot}" x2="{x:.1f}" '
            f'y2="{y_line_end}" stroke="{color}" stroke-width="1"/>',
            f'<circle cx="{x:.1f}" cy="{y_dot}" r="5" fill="{color}" '
            f'stroke="#1a2035"><title>{h(label)} ({h(src)})</title>'
            f'</circle>',
            f'<text x="{x:.1f}" y="{y_text}" fill="{color}" font-size="9" '
            f'text-anchor="middle">{h(label_short)}</text>',
        ])

    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# v1.6.0 — posture gauge + radar
# ---------------------------------------------------------------------------

def svg_gauge(score: float, label: str = "Domain Maturity Score",
              size: int = 240) -> str:
    """Semicircular gauge (0-100) with a needle. Red→Amber→Green band."""
    import math
    cx = size / 2
    cy = size * 0.62
    r_outer = size * 0.42
    r_inner = size * 0.32
    # Three coloured bands
    bands = [
        (0,  40, "#c0392b"),
        (40, 60, "#f39c12"),
        (60, 80, "#f1c40f"),
        (80, 100, "#2ecc71"),
    ]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'width="100%" style="background:transparent">'
    ]
    for lo, hi, color in bands:
        a0 = math.pi * (1 + lo / 100.0)
        a1 = math.pi * (1 + hi / 100.0)
        x0o = cx + r_outer * math.cos(a0); y0o = cy + r_outer * math.sin(a0)
        x1o = cx + r_outer * math.cos(a1); y1o = cy + r_outer * math.sin(a1)
        x1i = cx + r_inner * math.cos(a1); y1i = cy + r_inner * math.sin(a1)
        x0i = cx + r_inner * math.cos(a0); y0i = cy + r_inner * math.sin(a0)
        large = 1 if (a1 - a0) > math.pi else 0
        parts.append(
            f'<path d="M{x0o:.1f} {y0o:.1f} A{r_outer:.1f} {r_outer:.1f} 0 {large} 1 '
            f'{x1o:.1f} {y1o:.1f} L{x1i:.1f} {y1i:.1f} '
            f'A{r_inner:.1f} {r_inner:.1f} 0 {large} 0 {x0i:.1f} {y0i:.1f} Z" '
            f'fill="{color}" opacity="0.85"/>'
        )
    # Needle
    score = max(0, min(100, score))
    a = math.pi * (1 + score / 100.0)
    nx = cx + r_outer * 0.92 * math.cos(a)
    ny = cy + r_outer * 0.92 * math.sin(a)
    parts.append(
        f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{nx:.1f}" y2="{ny:.1f}" '
        f'stroke="#cdd6f4" stroke-width="3"/>'
        f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="6" fill="#cdd6f4"/>'
    )
    # Score number
    parts.append(
        f'<text x="{cx:.1f}" y="{cy + 36:.1f}" fill="#fff" '
        f'font-size="32" font-weight="800" text-anchor="middle" '
        f'font-family="monospace">{score:.0f}</text>'
        f'<text x="{cx:.1f}" y="{cy + 56:.1f}" fill="#7f849c" '
        f'font-size="11" text-anchor="middle">/ 100</text>'
        f'<text x="{cx:.1f}" y="{size - 8:.1f}" fill="#cdd6f4" font-size="11" '
        f'text-anchor="middle" font-family="monospace">{h(label)}</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def svg_radar(scores: dict[str, float], size: int = 360) -> str:
    """Radar/spider chart for category scores 0-100."""
    import math
    cx = cy = size / 2
    r_max = size * 0.36
    rings = 4   # 25/50/75/100 grid lines
    n = len(scores)
    if n < 3:
        return ""
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'width="100%" style="background:transparent">'
    ]
    # Grid rings
    for i in range(1, rings + 1):
        rr = r_max * i / rings
        dash = ' stroke-dasharray="3,3"' if i < rings else ''
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{rr:.1f}" fill="none" '
            f'stroke="#2d3561" stroke-width="0.8"{dash}/>'
        )
    # Axes
    pts: list[tuple[float, float, str]] = []
    for i, (cat, score) in enumerate(scores.items()):
        angle = -math.pi / 2 + 2 * math.pi * i / n
        x_axis = cx + r_max * math.cos(angle)
        y_axis = cy + r_max * math.sin(angle)
        parts.append(
            f'<line x1="{cx}" y1="{cy}" x2="{x_axis:.1f}" y2="{y_axis:.1f}" '
            f'stroke="#2d3561" stroke-width="0.8"/>'
        )
        # Axis label
        lx = cx + (r_max + 22) * math.cos(angle)
        ly = cy + (r_max + 22) * math.sin(angle)
        anchor = "middle"
        if math.cos(angle) > 0.3:
            anchor = "start"
        elif math.cos(angle) < -0.3:
            anchor = "end"
        parts.append(
            f'<text x="{lx:.1f}" y="{ly:.1f}" fill="#cdd6f4" '
            f'font-size="10" text-anchor="{anchor}" font-family="monospace">'
            f'{h(cat)} ({int(score)})</text>'
        )
        # Data point
        rr = r_max * max(0, min(100, score)) / 100
        px = cx + rr * math.cos(angle)
        py = cy + rr * math.sin(angle)
        pts.append((px, py, h(cat)))
    # Polygon connecting data points
    poly_d = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)
    parts.append(
        f'<polygon points="{poly_d}" fill="rgba(231,76,60,0.25)" '
        f'stroke="#e74c3c" stroke-width="2"/>'
    )
    for x, y, label in pts:
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="#e74c3c">'
            f'<title>{label}</title></circle>'
        )
    parts.append("</svg>")
    return "".join(parts)
