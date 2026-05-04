"""Posture scoring (v1.6.0).

Computes a 0-100 maturity score per category and an overall weighted score
inspired by PingCastle methodology. The algorithm is deliberately simple
and deterministic so the consultant can re-run it quarterly and show a
trend line to the client.

Scoring methodology (publicly documented — clients can audit it):

    For each category C with assigned weight W_C:
        category_score(C) = max(0, 100 - sum(w_finding × severity_factor))
        where severity_factor = 1.0 (critical), 0.6 (high),
                                0.3 (medium), 0.1 (low)
        and  w_finding = 25 (the per-finding penalty cap)

    overall_score = sum(category_score(C) × W_C) / sum(W_C)

Lower score = worse posture (opposite of PingCastle, which uses
"penalty points"). 0 = no findings, 100 = clean. We use 0-100 ascending
because every other metric in our HTML report follows that convention.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Category model
# ---------------------------------------------------------------------------

# Canonical posture categories with weights (sum = 100)
CATEGORY_WEIGHTS: dict[str, int] = {
    "Stale Objects":        10,
    "Privileged Accounts":  20,
    "Trusts":               10,
    "Anomalies":            10,
    "Kerberos":             15,
    "ADCS":                 20,
    "Hygiene":              15,
}

# Mapping from finding.category (as emitted by AdAudit.ps1) to posture bucket.
# Falls through to "Hygiene" for unknown categories.
_BUCKET_MAP = {
    "domain":             "Kerberos",     # most domain findings are auth-related
    "identity":           "Privileged Accounts",
    "policy":             "Hygiene",
    "ldap":               "Kerberos",
    "gpo":                "Hygiene",
    "acl":                "Privileged Accounts",
    "laps":               "Hygiene",
    "spn":                "Kerberos",
    "hardening":          "Hygiene",
    "adcs":               "ADCS",
    "incident_response":  "Anomalies",
    "trusts":             "Trusts",
    "stale":              "Stale Objects",
}

# Override per check_id when category is too generic
_CHECK_ID_BUCKET = {
    "AD-IDENTITY-003": "Stale Objects",   # inactive accounts
    "AD-IDENTITY-005": "Stale Objects",   # disabled accounts
    "AD-DOMAIN-005":   "Stale Objects",   # EOL OSes
    "AD-DOMAIN-005c":  "Stale Objects",
    "AD-IDENTITY-001": "Privileged Accounts",
    "AD-IDENTITY-002": "Privileged Accounts",
    "AD-IDENTITY-004": "Privileged Accounts",
    "AD-IDENTITY-006": "Kerberos",        # krbtgt rotation
    "AD-IDENTITY-007": "Privileged Accounts",
    "AD-PWPOL-001":    "Hygiene",
    "AD-PWPOL-002":    "Hygiene",
    "AD-PWPOL-003":    "Hygiene",
    "AD-PWPOL-005":    "Hygiene",
    "AD-DOMAIN-002":   "Hygiene",         # MachineAccountQuota
    "AD-DOMAIN-006":   "Kerberos",        # weak Kerberos enctypes
    "AD-LDAP-001":     "Kerberos",
    "AD-LDAP-002":     "Kerberos",
    "AD-LAPS-001":     "Hygiene",
    "AD-GPO-002":      "Privileged Accounts",
    "AD-ACL-001":      "Privileged Accounts",
    "AD-ACL-002":      "Privileged Accounts",
    "AD-SPN-001":      "Kerberos",
    "AD-ADCS-002":     "ADCS",
    "AD-HOSTHARDENING-001": "Hygiene",
    "AD-IR-001":       "Anomalies",
    "AD-IR-002":       "Anomalies",
    "AD-IR-003":       "Anomalies",
    "AD-IR-SEC-002":   "Anomalies",
    "AD-IR-SEC-003":   "Anomalies",
    "AD-KERBEROS-001": "Kerberos",
    "AD-IDENTITY-008": "Hygiene",
}

SEVERITY_FACTOR = {
    "critical":      1.0,
    "high":          0.6,
    "medium":        0.3,
    "low":           0.1,
    "informational": 0.0,
}

PENALTY_PER_FINDING = 25  # cap; multiplied by severity factor


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CategoryScore:
    name: str
    weight: int
    score: float          # 0-100
    findings_count: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    top_check_ids: list[str] = field(default_factory=list)

    def asdict(self) -> dict[str, Any]:
        return {
            "name": self.name, "weight": self.weight,
            "score": round(self.score, 1),
            "findings_count": self.findings_count,
            "severity_breakdown": dict(self.severity_breakdown),
            "top_check_ids": list(self.top_check_ids),
        }


@dataclass
class PostureReport:
    overall_score: float
    risk_band: str        # "Low" / "Medium" / "High" / "Critical"
    category_scores: dict[str, CategoryScore]
    kpis: dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""
    methodology_version: str = "v1.6.0"

    def asdict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 1),
            "risk_band": self.risk_band,
            "category_scores": {k: v.asdict() for k, v in self.category_scores.items()},
            "kpis": self.kpis,
            "generated_at": self.generated_at,
            "methodology_version": self.methodology_version,
        }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _bucket_for(check_id: str, category: str) -> str:
    if check_id in _CHECK_ID_BUCKET:
        return _CHECK_ID_BUCKET[check_id]
    return _BUCKET_MAP.get((category or "").lower(), "Hygiene")


def _interpret(score: float) -> str:
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def compute_posture_score(data) -> PostureReport:
    """Build a PostureReport from a fully-loaded AuditData."""
    # Initialize empty category buckets
    cat_findings: dict[str, list[dict]] = {c: [] for c in CATEGORY_WEIGHTS}
    for f in data.findings:
        if f.get("status") == "passed":
            continue
        bucket = _bucket_for(f.get("check_id", ""), f.get("category", ""))
        if bucket not in cat_findings:
            bucket = "Hygiene"
        cat_findings[bucket].append(f)

    category_scores: dict[str, CategoryScore] = {}
    for cat, findings in cat_findings.items():
        # Compute penalty
        penalty = 0.0
        sev_breakdown: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "informational").lower()
            sev_breakdown[sev] = sev_breakdown.get(sev, 0) + 1
            penalty += PENALTY_PER_FINDING * SEVERITY_FACTOR.get(sev, 0)
        score = max(0.0, 100.0 - penalty)
        # Top 3 findings by priority_score
        top_ids = [f.get("check_id", "")
                   for f in sorted(findings,
                                   key=lambda x: -x.get("priority_score", 0))][:3]
        category_scores[cat] = CategoryScore(
            name=cat,
            weight=CATEGORY_WEIGHTS[cat],
            score=score,
            findings_count=len(findings),
            severity_breakdown=sev_breakdown,
            top_check_ids=top_ids,
        )

    # Weighted overall
    total_w = sum(CATEGORY_WEIGHTS.values()) or 1
    overall = sum(cs.score * cs.weight for cs in category_scores.values()) / total_w

    # KPIs (portada)
    kpis = _compute_kpis(data, category_scores)

    return PostureReport(
        overall_score=overall,
        risk_band=_interpret(overall),
        category_scores=category_scores,
        kpis=kpis,
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def _compute_kpis(data, category_scores) -> dict[str, Any]:
    """Top-of-page KPIs in PingCastle style."""
    users_total = len(data.inventory.get("users", []))
    admin_count = sum(
        1 for u in data.inventory.get("users", [])
        if u.get("AdminCount", "0") == "1"
    )
    inactive = len(data.txt_files.get("accounts_inactive", []))
    disabled = len(data.txt_files.get("accounts_disabled", []))
    stale_pct = round(100 * (inactive + disabled) / max(users_total, 1), 1)
    priv_density = round(100 * admin_count / max(users_total, 1), 2)

    # Audit Policy coverage proxy: synthetic AD-IR-001 fired or not
    ad_ir_001 = any(f.get("check_id") == "AD-IR-001" for f in data.findings)
    audit_coverage_pct = 0 if ad_ir_001 else 100

    # Forest Risk: # T0 findings (critical+high in privileged + ADCS + kerberos)
    forest_risk_findings = sum(
        1 for f in data.findings
        if (f.get("severity") in ("critical", "high")
            and f.get("category") in ("identity", "acl", "adcs", "domain", "ldap"))
    )
    # Map count → 0-100 (lower is better; clamp 0 = no findings, 20+ = max)
    forest_risk_score = max(0, 100 - forest_risk_findings * 5)

    return {
        "domain_maturity_score": round(
            sum(c.score * c.weight for c in category_scores.values())
            / sum(CATEGORY_WEIGHTS.values()), 1),
        "stale_object_pct":      stale_pct,
        "priv_account_density":  priv_density,
        "audit_coverage_pct":    audit_coverage_pct,
        "forest_risk_score":     forest_risk_score,
        "users_total":           users_total,
        "admin_count":           admin_count,
        "inactive_count":        inactive,
        "disabled_count":        disabled,
    }


# ---------------------------------------------------------------------------
# History persistence (for trend lines across runs)
# ---------------------------------------------------------------------------

def persist_history(folder: Path, posture: PostureReport) -> None:
    """Append the current posture to ``posture_history.json`` in *folder*."""
    from .data import read_text  # BOM-tolerant
    hp = folder / "posture_history.json"
    history: list[dict] = []
    if hp.exists():
        try:
            history = json.loads(read_text(hp))
            if not isinstance(history, list):
                history = []
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            history = []
    history.append(posture.asdict())
    # Keep last 24 entries (2 years of monthly runs)
    history = history[-24:]
    try:
        hp.write_text(json.dumps(history, indent=2, ensure_ascii=False),
                      encoding="utf-8")
    except OSError:
        pass


def load_history(folder: Path) -> list[dict]:
    from .data import read_text  # BOM-tolerant
    hp = folder / "posture_history.json"
    if not hp.exists():
        return []
    try:
        history = json.loads(read_text(hp))
        return history if isinstance(history, list) else []
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []
