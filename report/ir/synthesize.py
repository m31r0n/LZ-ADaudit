"""Synthetic IR findings — emitted when the .ps1 leaves a high-signal
condition as not_evaluated but, in incident-response context, the silence
itself is the finding."""
from __future__ import annotations

from datetime import datetime, timezone

from .parsers import parse_dt_loose


def _txt(data, key: str) -> list[str]:
    return data.txt_files.get(key, []) if data else []


def synthesize_ir_findings(data) -> list[dict]:
    """Emit synthetic findings (AD-IR-001/002/003) where applicable."""
    out: list[dict] = []

    sec_csv_path = data.folder / "security_events.csv"
    sec_ev = data.evidence.get("security_events", {}) or {}

    csv_empty = (
        sec_csv_path.exists() and len(data.security_events_csv) == 0
    )
    not_eval = (sec_ev.get("status") == "not_evaluated")
    reason = (sec_ev.get("reason") or "").lower()
    no_events = csv_empty or (not_eval and any(
        s in reason for s in ("no se encontraron", "no events",
                              "0 events", "ningun evento", "ningún evento")
    ))

    # ------------------------------------------------------------------
    # AD-IR-001: Security log empty / cleared
    # ------------------------------------------------------------------
    if no_events:
        sev = "critical" if data.incident.active else "high"
        lookback = sec_ev.get("lookback_days", "?")
        evidence = (
            f"Security log lookback ({lookback} days) returned ZERO events "
            f"for IDs {sec_ev.get('event_ids', [4720, 4728, 4732, 4756])}. "
            "Possible causes: log cleared (Event 1102), audit policy "
            "disabled, or log rotation due to undersized log."
        )
        if data.incident.active:
            evidence += (
                f"  Incident date: "
                f"{data.incident.incident_date.strftime('%Y-%m-%d')}; "
                "window covers ZERO admin events — suspicious."
            )
        out.append({
            "finding_id": "FIND-SYNTHETIC-IR001",
            "finding_fingerprint": "ir001-security-log-gap",
            "check_id": "AD-IR-001",
            "check_name": "SecurityLogGap",
            "category": "incident_response",
            "title": "Security event log empty or unevaluable — possible log clearing",
            "description": "SecurityLogGap",
            "severity": sev,
            "confidence": "high",
            "impact": "high",
            "exploitability": "n/a",
            "remediation_effort": "low",
            "status": "failed",
            "scope": "domain",
            "affected_count": 1,
            "affected_objects": [(data.execution.get("hostname") or "DC")],
            "evidence": evidence,
            "data_source": "Synthesized",
            "recommendation": (
                "Investigate Security log retention and clearing events "
                "(4719/1102). Cross-check with EDR/Sysmon. Re-run audit "
                "with extended lookback."
            ),
            "tags": ["synthetic", "incident-response", "log-clearing"],
            "priority_score": 95 if data.incident.active else 75,
            "created_at_utc": datetime.now(timezone.utc).isoformat()
                                                       .replace("+00:00", "Z"),
            "_synthetic": True,
        })

    # ------------------------------------------------------------------
    # AD-IR-002: krbtgt password not rotated after incident
    # ------------------------------------------------------------------
    krbtgt_pls = (data.evidence.get("domain", {}) or {}).get("krbtgt_pwd_last_set")
    if data.incident.active and krbtgt_pls:
        krb_dt = parse_dt_loose(krbtgt_pls)
        if krb_dt and krb_dt < data.incident.incident_date:
            age = (datetime.now(timezone.utc) - krb_dt).days
            out.append({
                "finding_id": "FIND-SYNTHETIC-IR002",
                "finding_fingerprint": "ir002-krbtgt-not-rotated",
                "check_id": "AD-IR-002",
                "check_name": "KrbtgtNotRotatedAfterIncident",
                "category": "incident_response",
                "title": "krbtgt password not rotated after incident — Golden Ticket risk",
                "severity": "critical",
                "confidence": "high",
                "impact": "high",
                "exploitability": "high",
                "status": "failed",
                "scope": "domain",
                "affected_count": 1,
                "affected_objects": ["krbtgt"],
                "evidence": (
                    f"krbtgt pwdLastSet = {krbtgt_pls} "
                    f"(age {age} days, before incident on "
                    f"{data.incident.incident_date.strftime('%Y-%m-%d')})."
                ),
                "recommendation": (
                    "Reset krbtgt password TWICE with 12-24h between resets."
                ),
                "tags": ["synthetic", "incident-response", "kerberos"],
                "priority_score": 100,
                "created_at_utc": datetime.now(timezone.utc).isoformat()
                                                           .replace("+00:00", "Z"),
                "_synthetic": True,
            })

    # ------------------------------------------------------------------
    # AD-IR-003: mass stale passwords at incident time
    # ------------------------------------------------------------------
    stale_count = len(_txt(data, "accounts_with_old_passwords"))
    if data.incident.active and stale_count >= 50:
        out.append({
            "finding_id": "FIND-SYNTHETIC-IR003",
            "finding_fingerprint": "ir003-stale-pw-mass",
            "check_id": "AD-IR-003",
            "check_name": "MassStalePasswordsAtIncident",
            "category": "incident_response",
            "title": "Mass stale passwords at incident time — credential reuse risk",
            "severity": "high",
            "confidence": "high",
            "impact": "high",
            "status": "failed",
            "scope": "domain",
            "affected_count": stale_count,
            "evidence": (
                f"{stale_count} accounts had passwords older than the policy "
                "threshold at the time of the incident."
            ),
            "recommendation": (
                "Force password reset on all listed accounts; "
                "prioritise privileged."
            ),
            "tags": ["synthetic", "incident-response", "credentials"],
            "priority_score": 80,
            "created_at_utc": datetime.now(timezone.utc).isoformat()
                                                       .replace("+00:00", "Z"),
            "_synthetic": True,
        })

    return out
