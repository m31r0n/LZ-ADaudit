"""Built-in IR correlation rules. Each match enriches the report with a
narrative + MITRE refs + evidence pulled from the loaded AuditData."""
from __future__ import annotations

import re

from .parsers import parse_dt_loose


def _txt(data, key: str) -> list[str]:
    return data.txt_files.get(key, []) if data else []


def _build_priv_set(data) -> set[str]:
    """Collect lower-cased SAM names of all known privileged accounts."""
    priv: set[str] = set()
    for ln in _txt(data, "accounts_userPrivileged"):
        m = re.match(r"^(\S+)", ln)
        if m:
            priv.add(m.group(1).lower())
    for grp_key in ("domain_admins", "enterprise_admins", "schema_admins"):
        for ln in _txt(data, grp_key):
            parts = ln.split(" ", 2)
            if len(parts) >= 2:
                priv.add(parts[1].lower())
    return priv


def run_correlations(data) -> list[dict]:
    """Run every built-in correlation rule. Returns a list of match dicts."""
    out: list[dict] = []
    inc = data.incident
    priv_sams = _build_priv_set(data)

    # GPO ransomware analysis (IR-GPO-001..004) — runs in addition to the
    # standard correlation rules below.
    try:
        from ..gpo_analysis import gpo_correlations
        out.extend(gpo_correlations(data))
    except Exception:  # pylint: disable=broad-except
        # Never let optional analysis break the report
        pass

    # IR-CORR-001: account created in incident window
    if inc.active:
        for ln in _txt(data, "new_users"):
            m = re.match(r"Account (\S+) was created (.+)", ln)
            if not m:
                continue
            sam = m.group(1)
            dt = parse_dt_loose(m.group(2))
            if dt and inc.in_window(dt):
                priv = sam.lower() in priv_sams
                out.append({
                    "id": "IR-CORR-001",
                    "severity": "critical" if priv else "high",
                    "title": (f"Cuenta {sam} creada en ventana de incidente"
                              + (" (privilegiada)" if priv else "")),
                    "narrative": (
                        f"Cuenta {sam} creada el "
                        f"{dt.strftime('%Y-%m-%d %H:%M')}, dentro de la "
                        "ventana del incidente. "
                        + ("La cuenta tiene privilegios elevados — vector "
                           "clasico de persistencia post-compromiso." if priv
                           else "Verificar legitimidad contra change "
                           "management.")
                    ),
                    "mitre": ["T1136.002", "T1078.002" if priv else "T1136"],
                    "evidence": ln,
                    "refs": ["MITRE T1136 — Create Account"],
                })

    # IR-CORR-002: DCSync rights on non-administrative principal
    legit = ("Domain Admins", "Enterprise Admins", "Domain Controllers",
             "SYSTEM", "Enterprise Read-only Domain Controllers")
    for ln in _txt(data, "DCSyncRights"):
        m = re.search(r"IDENTITY:\s*([^|]+)", ln)
        if not m:
            continue
        ident = m.group(1).strip()
        if any(g in ident for g in legit):
            continue
        out.append({
            "id": "IR-CORR-002",
            "severity": "critical",
            "title": "DCSync rights on non-administrative principal",
            "narrative": (
                f"{ident} holds DS-Replication-Get-Changes-All. This grants "
                "the ability to dump every credential in the domain without "
                "touching a DC. Treat as compromised until proven otherwise."
            ),
            "mitre": ["T1003.006", "T1098"],
            "evidence": ln,
            "refs": ["MITRE T1003.006 — DCSync"],
        })

    # IR-CORR-003: unconstrained delegation on non-DC host
    for ln in _txt(data, "UnconstrainedDelegation"):
        if re.search(r"\bDC\b|Domain Controllers", ln, re.IGNORECASE):
            continue
        out.append({
            "id": "IR-CORR-003",
            "severity": "high",
            "title": "Unconstrained Kerberos delegation on non-DC host",
            "narrative": (
                "Compromise of a host with unconstrained delegation lets an "
                "attacker capture TGTs from any user that authenticates to "
                "it — including Domain Admins."
            ),
            "mitre": ["T1558.001", "T1550.003"],
            "evidence": ln,
            "refs": ["Harmj0y — Unconstrained Delegation"],
        })

    # IR-CORR-004: Shadow Credentials
    for ln in _txt(data, "ShadowCredentials"):
        out.append({
            "id": "IR-CORR-004",
            "severity": "critical",
            "title": "Shadow Credentials (msDS-KeyCredentialLink) populated",
            "narrative": (
                "PKINIT-based persistence vector. Attacker can authenticate "
                "as the target account using a self-issued certificate, "
                "bypassing password rotation."
            ),
            "mitre": ["T1098.005"],
            "evidence": ln,
            "refs": ["Whisker — Shadow Credentials research"],
        })

    # IR-CORR-005: RBCD anomaly
    for ln in _txt(data, "RBCD"):
        out.append({
            "id": "IR-CORR-005",
            "severity": "high",
            "title": "Resource-Based Constrained Delegation anomaly",
            "narrative": (
                "msDS-AllowedToActOnBehalfOfOtherIdentity populated on an "
                "account that does not legitimately need RBCD. KrbRelayUp / "
                "S4U2Self abuse vector."
            ),
            "mitre": ["T1558.003"],
            "evidence": ln,
        })

    # IR-CORR-006: kerberoastable privileged account
    for ln in _txt(data, "SPNs"):
        m = re.search(r"^(\S+)", ln)
        if not m:
            continue
        sam = m.group(1).lower()
        if sam in priv_sams:
            out.append({
                "id": "IR-CORR-006",
                "severity": "high",
                "title": f"Kerberoastable privileged account: {sam}",
                "narrative": (
                    "A privileged account exposing an SPN is roastable "
                    "offline. Combined with weak password, this is a direct "
                    "path to Domain Admin."
                ),
                "mitre": ["T1558.003"],
                "evidence": ln,
            })

    # IR-CORR-007: AS-REP roastable
    for ln in _txt(data, "ASREP"):
        out.append({
            "id": "IR-CORR-007",
            "severity": "high",
            "title": "AS-REP roastable account",
            "narrative": (
                "Account configured with DOES_NOT_REQUIRE_PREAUTH — its hash "
                "can be requested without authenticating."
            ),
            "mitre": ["T1558.004"],
            "evidence": ln,
        })

    # IR-CORR-008: ESC4 ADCS templates (User-class)
    for ln in _txt(data, "vulnerable_templates"):
        if "ESC4" in ln and ("User" in ln or "Smartcard" in ln):
            out.append({
                "id": "IR-CORR-008",
                "severity": "critical",
                "title": "ESC4 ADCS template enrollable for any user",
                "narrative": (
                    "Misconfigured certificate template allows low-privilege "
                    "users to enroll a certificate that authenticates as "
                    "another principal. Direct path to Domain Admin via ADCS."
                ),
                "mitre": ["T1649", "T1098.005"],
                "evidence": ln.strip(),
            })

    # IR-CORR-009: Security log silent during incident window
    if inc.active and any(s.get("check_id") == "AD-IR-001"
                          for s in data.synthetic_findings):
        out.append({
            "id": "IR-CORR-009",
            "severity": "critical",
            "title": "Security log silent during incident window",
            "narrative": (
                "Audit returned zero account-management events in 30-day "
                f"lookback that includes the incident date "
                f"({inc.incident_date.strftime('%Y-%m-%d')}). Treat as "
                "evidence tampering until investigation excludes audit-policy "
                "issues."
            ),
            "mitre": ["T1070.001", "T1562.002"],
            "evidence": "security_events.csv empty + lookback covers incident",
        })

    # IR-CORR-010: WDigest enabled OR LSA Protection absent
    hh = _txt(data, "HostHardening")
    has_wdigest = any("UseLogonCredential" in ln and "1" in ln for ln in hh)
    no_ppl = any("RunAsPPL" in ln and ("absent" in ln.lower()
                                       or "missing" in ln.lower())
                 for ln in hh)
    if has_wdigest or no_ppl:
        out.append({
            "id": "IR-CORR-010",
            "severity": "high",
            "title": "LSASS unprotected + WDigest exposure",
            "narrative": (
                "DC permite extraccion directa de credenciales en memoria via "
                "Mimikatz. Combinado con cualquier ejecucion arbitraria en el "
                "DC, equivale a compromiso de dominio inmediato."
            ),
            "mitre": ["T1003.001"],
            "evidence": " | ".join(
                ln for ln in hh if "WDigest" in ln or "RunAsPPL" in ln
            ),
        })

    return out

    return out
