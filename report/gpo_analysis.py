"""GPO IR analysis (v1.5.0).

Parses GPOReport.xml + inventory/gpos.csv to surface ransomware-style
indicators on Group Policy Objects:

  * GPOs created/modified within the incident window (red flag)
  * GPOs containing scheduled tasks (T1053.005)
  * GPOs containing registry preferences with cpassword (T1552.006)
  * GPOs deploying software via MSI (T1072 / T1547)
  * GPOs with startup/logon/shutdown scripts (T1037)
  * GPOs that disable Defender / firewall / RDP-restricting policy
  * GPOs targeting Domain Controllers OU
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .ir.parsers import parse_dt_loose

NS = "{http://www.microsoft.com/GroupPolicy/Settings}"


@dataclass
class GPOInfo:
    name: str = ""
    guid: str = ""
    created: datetime | None = None
    modified: datetime | None = None
    linked_to: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)  # IR-relevant flags
    has_scripts: bool = False
    has_scheduled_tasks: bool = False
    has_software_install: bool = False
    has_cpassword: bool = False
    has_registry_settings: bool = False
    targets_dc: bool = False
    raw_xml_excerpt: str = ""


def _read_gpo_xml(path: Path) -> ET.Element | None:
    """Read the GPOReport.xml file (handles UTF-16 BOM and UTF-8)."""
    if not path.exists():
        return None
    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xff\xfe"):
            text = raw.decode("utf-16")
        elif raw.startswith(b"\xfe\xff"):
            text = raw.decode("utf-16-be")
        elif raw.startswith(b"\xef\xbb\xbf"):
            text = raw.decode("utf-8-sig")
        else:
            text = raw.decode("utf-8", errors="replace")
        if text.startswith("﻿"):
            text = text[1:]
        return ET.fromstring(text)
    except (ET.ParseError, OSError, UnicodeDecodeError):
        return None


def parse_gpo_report(folder: Path) -> list[GPOInfo]:
    """Parse GPOReport.xml into a list of GPOInfo with IR indicators."""
    root = _read_gpo_xml(folder / "GPOReport.xml")
    if root is None:
        return []

    out: list[GPOInfo] = []
    for g in root.findall(f".//{NS}GPO"):
        info = GPOInfo()
        info.name = (g.findtext(f"{NS}Name") or "").strip()
        ident = g.find(f"{NS}Identifier")
        if ident is not None:
            info.guid = (ident.findtext(f"{NS}Identifier") or "").strip("{}")
        created_text = g.findtext(f"{NS}CreatedTime") or ""
        modified_text = g.findtext(f"{NS}ModifiedTime") or ""
        info.created = parse_dt_loose(created_text)
        info.modified = parse_dt_loose(modified_text)

        for lt in g.findall(f"{NS}LinksTo"):
            sompath = lt.findtext(f"{NS}SOMPath") or ""
            if sompath:
                info.linked_to.append(sompath)
                if "Domain Controllers" in sompath:
                    info.targets_dc = True

        # Inspect Computer + User extension data
        gpo_xml = ET.tostring(g, encoding="unicode")[:5000]
        info.raw_xml_excerpt = gpo_xml

        if "ScheduledTasks" in gpo_xml or "<ScheduledTask" in gpo_xml:
            info.has_scheduled_tasks = True
            info.indicators.append("Scheduled tasks (T1053.005)")
        if re.search(r"Scripts(Settings)?\b", gpo_xml):
            info.has_scripts = True
            info.indicators.append("Startup / logon scripts (T1037)")
        if "SoftwareInstallation" in gpo_xml or "MsiApplication" in gpo_xml:
            info.has_software_install = True
            info.indicators.append("Software deployment via MSI (T1072)")
        if "cpassword" in gpo_xml.lower():
            info.has_cpassword = True
            info.indicators.append("Group Policy Preference cpassword (T1552.006)")
        if "RegistrySettings" in gpo_xml:
            info.has_registry_settings = True

        # Look for high-impact registry pushes:
        # disable Defender / firewall / SmartScreen / UAC / RDP toggle
        suspicious_regs = [
            ("Defender disable", r"DisableAntiSpyware"),
            ("Defender disable", r"DisableRealtimeMonitoring"),
            ("Firewall disable", r"EnableFirewall.*<.+?>0<"),
            ("RDP enable", r"fDenyTSConnections.*<.+?>0<"),
            ("UAC disable", r"EnableLUA.*<.+?>0<"),
            ("AlwaysInstallElevated", r"AlwaysInstallElevated"),
            ("LocalAccountTokenFilterPolicy", r"LocalAccountTokenFilterPolicy"),
            ("RestrictAnonymous=0", r"RestrictAnonymous.*<.+?>0<"),
        ]
        for label, pat in suspicious_regs:
            if re.search(pat, gpo_xml, re.IGNORECASE):
                info.indicators.append(label)

        out.append(info)
    return out


# ---------------------------------------------------------------------------
# Correlation helper: invoked from the IR engine to add GPO-specific findings
# ---------------------------------------------------------------------------

def gpo_correlations(data) -> list[dict[str, Any]]:
    """Generate IR-style correlation matches for GPO indicators."""
    out: list[dict[str, Any]] = []
    inc = data.incident
    gpos = parse_gpo_report(data.folder)
    if not gpos:
        return out

    for g in gpos:
        in_win = inc.active and (
            (g.modified and inc.in_window(g.modified)) or
            (g.created and inc.in_window(g.created))
        )

        # GPO-IR-001: GPO modified during incident window — major red flag
        if in_win:
            out.append({
                "id": "GPO-IR-001",
                "severity": "critical",
                "title": f"GPO modificado durante ventana de incidente: {g.name}",
                "narrative": (
                    f"El GPO '{g.name}' fue modificado el "
                    f"{g.modified.strftime('%Y-%m-%d %H:%M') if g.modified else '?'}, "
                    "dentro de la ventana del incidente. Verificar el cambio "
                    "contra change management y revisar las settings introducidas - "
                    "este es el vector primario de propagacion de ransomware via GPO."
                ),
                "mitre": ["T1484.001", "T1078.002"],
                "evidence": (
                    f"created={g.created}, modified={g.modified}, "
                    f"linked_to={', '.join(g.linked_to[:3])}"
                ),
                "refs": ["MITRE T1484.001 - Group Policy Modification"],
            })

        # GPO-IR-002: any GPO that pushes scheduled tasks
        if g.has_scheduled_tasks:
            sev = "critical" if g.targets_dc else "high"
            out.append({
                "id": "GPO-IR-002",
                "severity": sev,
                "title": f"GPO con Scheduled Tasks: {g.name}",
                "narrative": (
                    "Tareas programadas distribuidas por GPO son uno de los "
                    "vectores tipicos de ransomware (encryptor/wiper). Revisar "
                    "el comando ejecutado, el usuario bajo el que corre, y la "
                    "frecuencia. "
                    + ("APUNTA A DOMAIN CONTROLLERS - prioridad maxima."
                       if g.targets_dc else
                       "Verificar contra change management.")
                ),
                "mitre": ["T1053.005"],
                "evidence": f"linked_to={', '.join(g.linked_to[:3])}",
            })

        # GPO-IR-003: cpassword in Group Policy Preferences
        if g.has_cpassword:
            out.append({
                "id": "GPO-IR-003",
                "severity": "critical",
                "title": f"GPO con cpassword en Preferences: {g.name}",
                "narrative": (
                    "cpassword es un campo cifrado con clave AES publica conocida. "
                    "Cualquier usuario del dominio puede descifrarlo (gpp-decrypt). "
                    "MS14-025 elimino la creacion pero los GPOs antiguos persisten."
                ),
                "mitre": ["T1552.006"],
                "evidence": "cpassword=<presente> (ver GPOReport.xml)",
            })

        # GPO-IR-004: Defender / firewall / UAC tampering
        for ind in g.indicators:
            if any(t in ind for t in ("Defender disable", "Firewall disable",
                                      "UAC disable", "AlwaysInstallElevated",
                                      "LocalAccountTokenFilterPolicy")):
                out.append({
                    "id": "GPO-IR-004",
                    "severity": "high",
                    "title": f"GPO debilita controles del host: {g.name}",
                    "narrative": (
                        f"Indicador '{ind}' en GPO '{g.name}'. "
                        "Patron caracteristico de ransomware preparando el "
                        "terreno: deshabilitar AV, firewall y UAC antes de la "
                        "ejecucion del payload."
                    ),
                    "mitre": ["T1562.001", "T1562.004"],
                    "evidence": f"GPO={g.name}, indicator={ind}",
                })

    return out
