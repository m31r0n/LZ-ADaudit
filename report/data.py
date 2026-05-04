"""Data layer: AuditData, IncidentConfig, file loaders, auto-detect."""
from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .utils import make_progress, RICH_AVAILABLE, warn

# ---------------------------------------------------------------------------
# File contracts (extended in v1.5.0 with orphan stems)
# ---------------------------------------------------------------------------

TXT_STEMS = [
    "accounts_disabled", "accounts_inactive", "accounts_passdontexpire",
    "accounts_protectedusers", "accounts_userPrivileged",
    "accounts_locked", "accounts_with_old_passwords",
    "domain_admins", "enterprise_admins", "schema_admins",
    "new_users", "new_groups",
    "ntlm_restrictions", "ous_inheritedGPOs",
    "dcs_weak_kerberos_ciphersuite",
    "winlaps_dcs_missing-dsrm", "winlaps_missing-computers",
    "winlaps_read-extendedrights", "LDAPSecurity",
    "UnconstrainedDelegation", "DCSyncRights", "HostHardening",
    # v1.5.0 — orphan stems previously not surfaced in the report
    "machines_old", "machines_old_Legacy_2000_2008_XP_Vista_7_8",
    "machines_old_Windows_Server_2016", "machines_old_Windows_Server_2019",
    "machines_old_Windows_Server_2022",
    "vulnerable_templates", "default_domain_controller_policy_audit",
    "ou_permissions", "SPNs", "ASREP",
    "ConstrainedDelegation", "RBCD", "ShadowCredentials",
    "kerbdelegation_summary",
]

EVIDENCE_STEMS = [
    "acl", "adcs", "domain", "gpo", "laps",
    "ldap", "password_policy", "security_events", "trusts",
]

INVENTORY_STEMS = [
    "adcs_templates", "computers", "dcs", "gpos",
    "groups", "service_accounts", "trusts", "users",
]

_TOTAL_STEPS = (4 + len(TXT_STEMS) + len(EVIDENCE_STEMS) +
                len(INVENTORY_STEMS) + 2)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class IncidentConfig:
    """Optional incident-response context for the report (v1.5.0).

    When ``incident_date`` is set, the generator switches to "IR Mode":
      - findings whose timestamp/evidence falls within the window are
        boosted in priority and tagged with a "EN VENTANA" badge,
      - a red banner is rendered at the top,
      - timeline + correlation engine + post-ransomware checklist sections
        are produced.
    """
    incident_date: datetime | None = None
    window_before_days: int = 30
    window_after_days: int = 7
    auditor: str = ""
    baseline_folder: Path | None = None
    language: str = "es"

    @property
    def window_start(self) -> datetime | None:
        if not self.incident_date:
            return None
        return self.incident_date - timedelta(days=self.window_before_days)

    @property
    def window_end(self) -> datetime | None:
        if not self.incident_date:
            return None
        return self.incident_date + timedelta(days=self.window_after_days)

    def in_window(self, dt: datetime | None) -> bool:
        if not dt or not self.incident_date:
            return False
        ws, we = self.window_start, self.window_end
        if ws is None or we is None:
            return False
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if ws.tzinfo is None:
            ws = ws.replace(tzinfo=timezone.utc)
        if we.tzinfo is None:
            we = we.replace(tzinfo=timezone.utc)
        return ws <= dt <= we

    @property
    def active(self) -> bool:
        return self.incident_date is not None


# ---------------------------------------------------------------------------
# AuditData
# ---------------------------------------------------------------------------

@dataclass
class AuditData:
    """All inputs the report builders consume — loaded from one folder."""
    folder: Path
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    execution: dict[str, Any] = field(default_factory=dict)
    preflight: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    inventory: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    txt_files: dict[str, list[str]] = field(default_factory=dict)
    security_events_csv: list[dict[str, str]] = field(default_factory=list)
    findings_csv: list[dict[str, str]] = field(default_factory=list)
    gpo_report_exists: bool = False
    # v1.5.0 — IR / robustness
    incident: IncidentConfig = field(default_factory=IncidentConfig)
    missing_inputs: dict[str, str] = field(default_factory=dict)
    summary_derived: bool = False
    execution_derived: bool = False
    correlations: list[dict[str, Any]] = field(default_factory=list)
    ir_indicators: list[dict[str, Any]] = field(default_factory=list)
    synthetic_findings: list[dict[str, Any]] = field(default_factory=list)
    log_excerpts: dict[str, list[str]] = field(default_factory=dict)
    baseline: "AuditData | None" = None


# ---------------------------------------------------------------------------
# File readers (BOM-tolerant)
# ---------------------------------------------------------------------------

def read_text(path: Path) -> str:
    raw = path.read_bytes()
    for bom, enc in (
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\xff\xfe", "utf-16"),       # UTF-16-LE
        (b"\xfe\xff", "utf-16"),       # UTF-16-BE (PS Core -Encoding bigendianunicode)
    ):
        if raw.startswith(bom):
            return raw.decode(enc)
    return raw.decode("utf-8", errors="replace")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(read_text(path))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    bad = 0
    for line in read_text(path).splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    if bad:
        warn(f"{path.name}: skipped {bad} malformed NDJSON line(s)")
    return records


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    try:
        reader = csv.DictReader(read_text(path).splitlines())
        return [dict(row) for row in reader]
    except (csv.Error, UnicodeDecodeError, OSError) as e:
        warn(f"{path.name}: failed to parse CSV ({type(e).__name__}: {e})")
        return []


def load_txt(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln for ln in read_text(path).splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_audit_data(folder: Path,
                    incident: IncidentConfig | None = None) -> AuditData:
    """Load every AdAudit output file from *folder*.

    v1.5.0 — accepts optional IR config and runs the IR pipeline at the end:
    derive missing summary/exec, synthesize IR findings, score boost, run
    correlations, build post-ransomware checklist.
    """
    # IR pipeline imports are lazy so this module can be imported without IR
    from . import derive
    from .ir import window as ir_window
    from .ir import synthesize as ir_synth
    from .ir import correlations as ir_corr
    from .ir import checklist as ir_chk

    data = AuditData(folder=folder, incident=incident or IncidentConfig())
    prg = make_progress(_TOTAL_STEPS)

    with prg as p:
        if RICH_AVAILABLE:
            task = p.add_task("Loading…", total=_TOTAL_STEPS)

        def step(label: str) -> None:
            if RICH_AVAILABLE:
                p.update(task, description=label)
            if RICH_AVAILABLE:
                p.advance(task, 1)
            else:
                p.advance(0, 1)

        # --- Core JSON ---
        step("findings.ndjson")
        data.findings = load_ndjson(folder / "findings.ndjson")

        step("summary.json")
        data.summary = load_json(folder / "summary.json")

        step("execution.json")
        data.execution = load_json(folder / "execution.json")

        step("preflight.json")
        data.preflight = load_json(folder / "preflight.json")
        # Fallback to preflight_result inside execution.json. The actual
        # fallback runs *after* execution derivation below to guarantee
        # data.execution is populated, even when execution.json is missing.

        # --- Evidence JSON ---
        ev_dir = folder / "evidence"
        for stem in EVIDENCE_STEMS:
            step(f"evidence/{stem}.json")
            j = load_json(ev_dir / f"{stem}.json")
            if j:
                data.evidence[stem] = j

        # --- Inventory CSV ---
        inv_dir = folder / "inventory"
        for stem in INVENTORY_STEMS:
            step(f"inventory/{stem}.csv")
            rows = load_csv(inv_dir / f"{stem}.csv")
            if rows:
                data.inventory[stem] = rows

        # --- Root TXT files (manifest-aware) ---
        manifest = data.execution.get("output_manifest", []) or []
        manifest_txt_stems = sorted({
            Path(name).stem for name in manifest
            if isinstance(name, str) and name.lower().endswith(".txt")
        })
        all_txt_stems = sorted(set(TXT_STEMS) | set(manifest_txt_stems))
        for stem in all_txt_stems:
            step(f"{stem}.txt")
            lines = load_txt(folder / f"{stem}.txt")
            if lines:
                data.txt_files[stem] = lines

        step("security_events.csv")
        data.security_events_csv = load_csv(folder / "security_events.csv")

        step("findings.csv")
        data.findings_csv = load_csv(folder / "findings.csv")

        data.gpo_report_exists = (folder / "GPOReport.html").exists()

        # --- Logs (v1.5.0) — extract ERROR/WARN excerpts ---
        for log_name in ("console.log", "debug.log", "errors.log"):
            lp = folder / "logs" / log_name
            if lp.exists():
                lines = read_text(lp).splitlines()
                excerpts = [
                    ln for ln in lines
                    if re.search(r"\b(ERROR|WARN|FAIL|FATAL|EXCEPTION)\b",
                                 ln, re.IGNORECASE)
                ]
                if excerpts:
                    data.log_excerpts[log_name] = excerpts[-50:]

    # ----- v1.5.0 post-load processing pipeline -----
    derive.track_missing_inputs(data)

    if not data.summary:
        data.summary = derive.derive_summary_from_findings(data.findings)
        data.summary_derived = True
    if not data.execution:
        data.execution = derive.derive_execution_from_files(
            folder, data.findings, data.evidence, data.preflight
        )
        data.execution_derived = True
    # QA-#11: now that execution is populated (loaded or derived), apply the
    # preflight_result fallback if preflight.json wasn't found on disk.
    if not data.preflight:
        data.preflight = data.execution.get("preflight_result", {}) or {}

    data.synthetic_findings = ir_synth.synthesize_ir_findings(data)
    if data.synthetic_findings:
        data.findings.extend(data.synthetic_findings)
        if data.summary_derived:
            data.summary = derive.derive_summary_from_findings(data.findings)

    ir_window.apply_incident_window(data)
    data.correlations = ir_corr.run_correlations(data)
    data.ir_indicators = ir_chk.build_ir_indicators(data)

    if data.incident.baseline_folder and data.incident.baseline_folder.exists():
        try:
            data.baseline = load_audit_data(
                data.incident.baseline_folder, incident=None
            )
        except (OSError, ValueError) as e:
            warn(f"could not load baseline {data.incident.baseline_folder}: {e}")

    return data


def auto_detect_folder() -> Path | None:
    """Scan cwd for the most recent AdAudit output folder."""
    cwd = Path.cwd()
    if (cwd / "findings.ndjson").exists():
        return cwd
    candidates = sorted(
        [d for d in cwd.iterdir()
         if d.is_dir() and (d / "findings.ndjson").exists()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return None
    if len(candidates) > 1:
        print("  Multiple audit folders found — using the most recent:")
        for c in candidates[:5]:
            print(f"    {c.name}")
        print()
    return candidates[0]
