"""Coverage gaps + diagnostics (log excerpts) — surfaced when inputs are
missing/empty or the audit logs contain ERROR/WARN entries."""
from __future__ import annotations

from ...data import AuditData
from ...i18n import t
from ...utils import h


def section_evidence_coverage(data: AuditData) -> str:
    if (not data.missing_inputs
            and not data.summary_derived
            and not data.execution_derived):
        return ""
    rows: list[str] = []
    if data.summary_derived:
        rows.append(
            '<tr><td class="bold" style="color:#f39c12">&#9888; DERIVED</td>'
            '<td class="mono small">summary.json</td>'
            '<td>Reconstruido a partir de findings.ndjson &mdash; el resumen '
            'mostrado es derivado, no el oficial.</td></tr>'
        )
    if data.execution_derived:
        rows.append(
            '<tr><td class="bold" style="color:#f39c12">&#9888; DERIVED</td>'
            '<td class="mono small">execution.json</td>'
            '<td>Reconstruido a partir de timestamps en findings + nombre de '
            'carpeta.</td></tr>'
        )
    for name, reason in sorted(data.missing_inputs.items()):
        bad = "empty" in reason or "invalid" in reason
        color = "#e74c3c" if bad else "#7f849c"
        label = ("EMPTY" if "empty" in reason
                 else ("INVALID" if "invalid" in reason
                       else "MISSING"))
        rows.append(
            f'<tr><td class="bold" style="color:{color}">{label}</td>'
            f'<td class="mono small">{h(name)}</td>'
            f'<td>{h(reason)}</td></tr>'
        )
    return f"""
<section class="section" id="coverage">
  <h2 class="st">Cobertura de evidencia</h2>
  <p class="dim small" style="margin-bottom:10px">
    Inputs esperados que estan ausentes, vacios o invalidos. El resto del
    informe se ha construido sin esta evidencia y puede tener gaps.
  </p>
  <table class="data-table">
    <thead><tr>
      <th style="width:120px">Estado</th>
      <th style="width:240px">Archivo</th>
      <th>Detalle</th>
    </tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>"""


def section_diagnostics(data: AuditData) -> str:
    if not data.log_excerpts:
        return ""
    panels: list[str] = []
    for log_name, lines in data.log_excerpts.items():
        body = "\n".join(h(ln) for ln in lines)
        panels.append(
            '<details class="diag-block">'
            f'<summary><strong>{h(log_name)}</strong> '
            f'<span class="dim small">&mdash; {len(lines)} entradas</span></summary>'
            f'<pre class="text-block">{body}</pre></details>'
        )
    return f"""
<section class="section" id="diagnostics">
  <h2 class="st">Diagnostico de la auditoria</h2>
  <p class="dim small" style="margin-bottom:10px">
    Errores y advertencias capturadas durante la ejecucion de
    <code>AdAudit.ps1</code>. Util cuando un modulo cae silenciosamente.
  </p>
  {''.join(panels)}
</section>"""
