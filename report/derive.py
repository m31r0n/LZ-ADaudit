"""Derivation: rebuild missing summary.json / execution.json + track gaps."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .data import AuditData, read_text
from .ir.parsers import parse_dt_loose


def derive_summary_from_findings(findings: list[dict]) -> dict[str, Any]:
    """Reconstruct a summary dict from findings.ndjson when summary.json is missing."""
    if not findings:
        return {}
    by_sev: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in findings:
        if f.get("status") == "passed":
            continue
        sev = (f.get("severity") or "informational").lower()
        cat = f.get("category") or "uncategorized"
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_cat[cat] = by_cat.get(cat, 0) + 1
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                 "informational": 4}
    by_sev_sorted = dict(sorted(by_sev.items(),
                                key=lambda kv: sev_order.get(kv[0], 9)))
    by_cat_sorted = dict(sorted(by_cat.items(), key=lambda kv: -kv[1]))
    actionable = [f for f in findings if f.get("status") != "passed"]
    top_priorities = [
        {"check_id": f.get("check_id", ""),
         "title": f.get("title", ""),
         "severity": f.get("severity", ""),
         "priority_score": f.get("priority_score", 0),
         "category": f.get("category", "")}
        for f in sorted(actionable,
                        key=lambda x: -x.get("priority_score", 0))[:10]
    ]
    return {
        "total_findings": len(actionable),
        "findings_by_severity": by_sev_sorted,
        "findings_by_category": by_cat_sorted,
        "top_priorities": top_priorities,
        "_derived": True,
    }


def derive_execution_from_files(folder: Path,
                                findings: list[dict],
                                evidence: dict,
                                preflight: dict) -> dict[str, Any]:
    """Reconstruct minimal execution metadata when execution.json is missing."""
    ex: dict[str, Any] = {"_derived": True}
    fallback_host = (folder.name.split("_", 2)[-1]
                     if "_" in folder.name else folder.name)
    ex["hostname"] = (preflight.get("hostname")
                      or (evidence.get("domain", {}) or {}).get("hostname")
                      or fallback_host)
    dom_ev = evidence.get("domain", {}) or {}
    ex["domain_name"] = dom_ev.get("domain_name") or ""
    ex["forest_name"] = dom_ev.get("forest_name") or ""
    ex["fqdn"] = dom_ev.get("fqdn") or ""

    ts_list = [parse_dt_loose(f.get("created_at_utc", "")) for f in findings]
    ts_list = [t for t in ts_list if t]
    if ts_list:
        ex["started_at_utc"] = min(ts_list).isoformat().replace("+00:00", "Z")
        ex["ended_at_utc"] = max(ts_list).isoformat().replace("+00:00", "Z")
        ex["duration_seconds"] = int(
            (max(ts_list) - min(ts_list)).total_seconds()
        )

    name_lower = folder.name.lower()
    if "_ir" in name_lower or "incident" in name_lower:
        ex["profile_selected"] = "incident-response (derived)"
    else:
        ex["profile_selected"] = "(derived)"

    cats: dict[str, int] = {}
    for f in findings:
        c = f.get("category", "uncategorized")
        cats[c] = cats.get(c, 0) + 1
    ex["modules_detail"] = {
        c: {"status": "ok",
            "display_name": c.title(),
            "findings_added": n,
            "duration_seconds": ""}
        for c, n in cats.items()
    }
    ex["tool_name"] = "LZ-ADaudit"
    ex["tool_version"] = "(unknown)"
    return ex


def track_missing_inputs(data: AuditData) -> None:
    """Populate ``data.missing_inputs`` with any expected files that are
    absent, empty, or invalid JSON."""
    folder = data.folder
    checks = [
        ("summary.json",        folder / "summary.json"),
        ("execution.json",      folder / "execution.json"),
        ("preflight.json",      folder / "preflight.json"),
        ("findings.ndjson",     folder / "findings.ndjson"),
        ("findings.csv",        folder / "findings.csv"),
        ("evidence/password_policy.json",
            folder / "evidence" / "password_policy.json"),
        ("evidence/domain.json",
            folder / "evidence" / "domain.json"),
        ("evidence/ldap.json",
            folder / "evidence" / "ldap.json"),
        ("evidence/security_events.json",
            folder / "evidence" / "security_events.json"),
        ("security_events.csv", folder / "security_events.csv"),
        ("logs/console.log",    folder / "logs" / "console.log"),
        ("logs/errors.log",     folder / "logs" / "errors.log"),
    ]
    for name, p in checks:
        if not p.exists():
            data.missing_inputs[name] = "not present"
        elif p.stat().st_size == 0:
            data.missing_inputs[name] = "file empty (0 bytes)"
        elif p.suffix == ".json":
            try:
                content = read_text(p).strip()
                if content:
                    json.loads(content)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                data.missing_inputs[name] = f"json invalid: {type(e).__name__}"
