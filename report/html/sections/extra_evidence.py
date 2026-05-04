"""Surface .txt artifacts produced by AdAudit.ps1 that the original report
generator left orphaned (v1.5.0)."""
from __future__ import annotations

import re

from ...data import AuditData
from ...i18n import t
from ...utils import h, txt


def section_orphan_txt(data: AuditData) -> str:
    blocks: list[str] = []

    # 1) Old machines / EOL OS — one combined table
    eol_groups = [
        ("Legacy (XP / 2000 / 2003 / 2008 / Vista / 7 / 8)",
            "machines_old_Legacy_2000_2008_XP_Vista_7_8"),
        ("Windows Server 2016", "machines_old_Windows_Server_2016"),
        ("Windows Server 2019", "machines_old_Windows_Server_2019"),
        ("Windows Server 2022", "machines_old_Windows_Server_2022"),
        ("Other obsolete machines", "machines_old"),
    ]
    eol_rows: list[str] = []
    for label, key in eol_groups:
        lines = txt(data, key)
        if not lines:
            continue
        host_li = "".join(f"<li class='mono small'>{h(ln)}</li>"
                          for ln in lines[:200])
        eol_rows.append(
            f'<tr><td class="bold" style="color:#e74c3c">{h(label)}</td>'
            f'<td class="center">{len(lines)}</td>'
            f'<td><details><summary class="dim">Ver hosts</summary>'
            f'<ul class="plain-list">{host_li}</ul></details></td></tr>'
        )
    if eol_rows:
        blocks.append(
            '<h3 class="sh">Sistemas operativos obsoletos / EOL</h3>'
            '<table class="data-table">'
            '<thead><tr><th>Categoria</th><th class="center">Conteo</th>'
            '<th>Hosts</th></tr></thead>'
            f'<tbody>{"".join(eol_rows)}</tbody></table>'
        )

    # 2) Vulnerable ADCS templates — parse ESC tag
    vt = txt(data, "vulnerable_templates")
    if vt:
        rx = re.compile(r"^(ESC\d+)[: ]+(.+?)\s+\(([^)]+)\)\s*$")
        rows: list[str] = []
        for ln in vt:
            m = rx.match(ln)
            if m:
                rows.append(
                    f'<tr><td class="bold" style="color:#c0392b">'
                    f'{h(m.group(1))}</td>'
                    f'<td><strong>{h(m.group(2).strip())}</strong></td>'
                    f'<td class="mono small">{h(m.group(3))}</td></tr>'
                )
            else:
                rows.append(
                    '<tr><td class="dim">&mdash;</td>'
                    f'<td colspan="2" class="mono small">{h(ln)}</td></tr>'
                )
        blocks.append(
            '<h3 class="sh">Plantillas ADCS vulnerables (ESC1-15)</h3>'
            '<table class="data-table">'
            '<thead><tr><th style="width:80px">Tipo</th>'
            '<th>Plantilla</th><th>Atributos</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )

    # 3) SPNs (Kerberoasteables)
    spns = txt(data, "SPNs")
    if spns:
        rows = "".join(f'<li class="mono small">{h(ln)}</li>' for ln in spns[:200])
        blocks.append(
            '<h3 class="sh">Cuentas con SPN (Kerberoasteables)</h3>'
            f'<ul class="plain-list">{rows}</ul>'
        )

    # 4) AS-REP roastable
    asr = txt(data, "ASREP")
    if asr:
        rows = "".join(f'<li class="mono small">{h(ln)}</li>' for ln in asr[:200])
        blocks.append(
            '<h3 class="sh">Cuentas AS-REP Roastable (sin pre-auth)</h3>'
            f'<ul class="plain-list">{rows}</ul>'
        )

    # 5) Constrained / RBCD / Shadow Credentials
    for stem, label in [
        ("ConstrainedDelegation", "Constrained Delegation"),
        ("RBCD", "Resource-Based Constrained Delegation (RBCD)"),
        ("ShadowCredentials", "Shadow Credentials (msDS-KeyCredentialLink)"),
    ]:
        ln = txt(data, stem)
        if ln:
            content = "\n".join(h(x) for x in ln)
            blocks.append(
                f'<h3 class="sh">{label} ({len(ln)})</h3>'
                f'<pre class="text-block">{content}</pre>'
            )

    # 6) Stale passwords — parsed table
    spw = txt(data, "accounts_with_old_passwords")
    if spw:
        rx_user = re.compile(
            r"User\s+(\S+)\s+\(([^)]*)\)\s+has not changed their password since\s+(.+?)$"
        )
        parsed: list[tuple[str, str, str]] = []
        for ln in spw:
            m = rx_user.search(ln)
            if m:
                parsed.append((m.group(1), m.group(2), m.group(3)))
            else:
                parsed.append(("?", "", ln))
        rows = "".join(
            f'<tr><td class="mono small">{h(sam)}</td>'
            f'<td>{h(disp)}</td>'
            f'<td class="small">{h(last)}</td></tr>'
            for sam, disp, last in parsed[:500]
        )
        more = (f'<p class="dim small">Mostrando 500 de {len(parsed)} cuentas.</p>'
                if len(parsed) > 500 else "")
        blocks.append(
            f'<h3 class="sh">Cuentas con contrasenas antiguas '
            f'({len(parsed)})</h3>{more}'
            '<div class="table-scroll"><table class="data-table small">'
            '<thead><tr><th style="width:160px">SAM</th>'
            '<th>Display Name</th><th>Ultima rotacion</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    # 7) accounts_locked
    locked = txt(data, "accounts_locked")
    if locked:
        rows = "".join(f'<li class="mono small">{h(ln)}</li>' for ln in locked)
        blocks.append(
            f'<h3 class="sh">Cuentas bloqueadas ({len(locked)})</h3>'
            f'<ul class="plain-list">{rows}</ul>'
        )

    # 8) ou_permissions
    ou_p = txt(data, "ou_permissions")
    if ou_p:
        content = "\n".join(h(ln) for ln in ou_p)
        blocks.append(
            '<h3 class="sh">OU Permissions (no estandar)</h3>'
            f'<pre class="text-block">{content}</pre>'
        )

    # 9) default_domain_controller_policy_audit
    ddcp = txt(data, "default_domain_controller_policy_audit")
    if ddcp:
        content = "\n".join(h(ln) for ln in ddcp)
        blocks.append(
            '<h3 class="sh">Default Domain Controller Policy &mdash; Audit</h3>'
            f'<pre class="text-block">{content}</pre>'
        )

    if not blocks:
        return ""
    return f"""
<section class="section" id="extra-evidence">
  <h2 class="st">Evidencia adicional</h2>
  <p class="dim small" style="margin-bottom:10px">
    Salidas adicionales generadas por <code>AdAudit.ps1</code> que el
    generador surfaca en este informe (v1.5.0).
  </p>
  {''.join(blocks)}
</section>"""
