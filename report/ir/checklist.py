"""Post-ransomware verification checklist. Each item declares an
auto-detected state plus a re-run command for manual verification."""
from __future__ import annotations

from .parsers import parse_dt_loose
from ..remediation import remediation_context, resolve_tokens


def _txt(data, key: str) -> list[str]:
    return data.txt_files.get(key, []) if data else []


def _add(items: list[dict], section: str, name: str, state: str,
         detail: str, verify: str, severity: str = "info") -> None:
    items.append({
        "section": section, "name": name, "state": state,
        "detail": detail, "verify": verify, "severity": severity,
    })


def build_ir_indicators(data) -> list[dict]:
    """Build the post-ransomware verification checklist.

    Returns an empty list when IR mode is not active — preventing
    'POST-INCIDENT' / 'PRE-INCIDENT' labels from appearing on baseline
    runs where no incident date was supplied.
    """
    if not getattr(data, "incident", None) or not data.incident.active:
        return []
    items: list[dict] = []
    dom = data.evidence.get("domain", {}) or {}
    hh = _txt(data, "HostHardening")
    dcsync = _txt(data, "DCSyncRights")
    shadow = _txt(data, "ShadowCredentials")
    rbcd = _txt(data, "RBCD")
    sec_ev = data.evidence.get("security_events", {}) or {}

    # ----- Identity persistence -----
    krb = dom.get("krbtgt_pwd_last_set")
    if krb:
        krb_dt = parse_dt_loose(krb)
        risk = "critical" if (data.incident.incident_date and krb_dt
                              and krb_dt < data.incident.incident_date) else "warn"
        _add(items, "Identity persistence", "krbtgt password rotation",
             "PRE-INCIDENT" if risk == "critical" else "POST-INCIDENT",
             f"krbtgt pwdLastSet = {krb}",
             "Get-ADUser krbtgt -Properties pwdLastSet | Select pwdLastSet",
             risk)
    else:
        _add(items, "Identity persistence", "krbtgt password rotation",
             "UNKNOWN",
             "krbtgt last-set not reported in evidence",
             "Get-ADUser krbtgt -Properties pwdLastSet",
             "warn")

    _add(items, "Identity persistence", "AdminSDHolder ACL integrity",
         "FINDING" if dcsync else "OK",
         (f"{len(dcsync)} DCSync ACE entries reported"
          if dcsync else "No anomalous DCSync rights detected"),
         "Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,{{domain_dn}}' | "
         "Select -Expand Access",
         "critical" if dcsync else "info")

    _add(items, "Identity persistence",
         "Shadow Credentials (msDS-KeyCredentialLink)",
         "FINDING" if shadow else "OK",
         (f"{len(shadow)} accounts with key credentials"
          if shadow else "No shadow credentials detected"),
         ("Get-ADUser -Filter * -Properties msDS-KeyCredentialLink "
          "| Where-Object {$_.\"msDS-KeyCredentialLink\"}"),
         "critical" if shadow else "info")

    _add(items, "Identity persistence",
         "Resource-Based Constrained Delegation",
         "FINDING" if rbcd else "OK",
         (f"{len(rbcd)} RBCD entries"
          if rbcd else "No anomalous RBCD detected"),
         ("Get-ADComputer -Filter * -Properties "
          "msDS-AllowedToActOnBehalfOfOtherIdentity "
          "| Where-Object {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'}"),
         "high" if rbcd else "info")

    # ----- Host hardening -----
    has_wdigest = any("UseLogonCredential" in ln and "1" in ln for ln in hh)
    _add(items, "Host hardening", "WDigest plaintext caching",
         "EXPOSED" if has_wdigest else "OK",
         ("UseLogonCredential = 1 (plaintext credentials cached in LSASS)"
          if has_wdigest else "WDigest plaintext caching disabled"),
         ("Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
          "SecurityProviders\\WDigest' UseLogonCredential"),
         "high" if has_wdigest else "info")

    no_ppl = any("RunAsPPL" in ln and ("absent" in ln.lower()
                                       or "missing" in ln.lower())
                 for ln in hh)
    _add(items, "Host hardening", "LSA Protection (RunAsPPL)",
         "MISSING" if no_ppl else "OK",
         ("LSASS not running as PPL — credential dumping possible"
          if no_ppl else "LSASS protected as PPL"),
         ("Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
          "RunAsPPL"),
         "high" if no_ppl else "info")

    # ----- Forensic state -----
    log_silent = (sec_ev.get("status") == "not_evaluated"
                  and any(s in (sec_ev.get("reason") or "").lower()
                          for s in ("no se encontraron", "no events",
                                    "0 events", "ningun evento",
                                    "ningún evento")))
    _add(items, "Forensic state", "Security log activity",
         "SILENT" if log_silent else "ACTIVE",
         ("Lookback returned zero account/group events — possible log clearing"
          if log_silent else "Security log produced events in lookback"),
         ("Get-WinEvent -LogName Security -MaxEvents 5000 "
          "| Group-Object Id | Sort-Object Count -Descending"),
         ("critical" if (log_silent and data.incident.active)
          else ("high" if log_silent else "info")))

    _add(items, "Forensic state", "Log clearing events (1102 / 104 / 4719)",
         "VERIFY",
         "Run forensic check: any clear/policy-change events in window?",
         ("Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} "
          "-MaxEvents 50"),
         "warn")

    _add(items, "Forensic state", "Audit policy coverage", "VERIFY",
         "Confirm Account Management and Security Group Mgmt are Success+Failure",
         "AuditPol /get /category:* | findstr /i 'Account Group'",
         "warn")

    # ----- Recovery readiness -----
    missing_dsrm = _txt(data, "winlaps_dcs_missing-dsrm")
    _add(items, "Recovery readiness", "DSRM password set on all DCs",
         "FINDING" if missing_dsrm else "OK",
         (f"{len(missing_dsrm)} DCs missing DSRM"
          if missing_dsrm else "All DCs have DSRM password set"),
         "Get-ADComputer -Filter {primaryGroupID -eq 516} -Properties DSRMRecovery",
         "high" if missing_dsrm else "info")

    # (token-resolved at the bottom of this function)
    _add(items, "Recovery readiness", "AD Recycle Bin",
         "ENABLED" if dom.get("recycle_bin_enabled") else "DISABLED",
         ("Object recovery without DC restore"
          if dom.get("recycle_bin_enabled")
          else "Cannot recover deleted objects"),
         "Get-ADOptionalFeature 'Recycle Bin Feature'",
         "info" if dom.get("recycle_bin_enabled") else "high")

    # Resolve {{tokens}} in the verify commands so that the rendered checklist
    # contains executable PowerShell rather than placeholders.
    ctx = remediation_context(data)
    for it in items:
        it["verify"] = resolve_tokens(it.get("verify", ""), ctx)
        it["detail"] = resolve_tokens(it.get("detail", ""), ctx)
    return items
