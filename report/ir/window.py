"""Apply incident-window scoring boost + tagging."""
from __future__ import annotations

from .parsers import extract_dates

IN_WINDOW_BOOST = 20


def _evidence_timestamps(f: dict) -> list:
    """Timestamps derived from finding evidence/affected_objects only.

    Excludes ``created_at_utc`` (the audit run time) on purpose: including it
    would mark every finding "in window" whenever the audit runs inside the
    window, destroying the signal.
    """
    out = []
    out.extend(extract_dates(f.get("evidence", "") or ""))
    for ao in f.get("affected_objects") or []:
        out.extend(extract_dates(str(ao)))
    return out


def apply_incident_window(data) -> None:
    """Tag findings whose evidence falls within the incident window and
    boost their priority_score so they float to the top.

    Synthetic IR findings are always tagged in-window (they ARE the incident
    by construction). Regular findings only get the badge when their
    evidence (not the run timestamp) lands inside the window.

    No-op when the audit was not invoked with --incident-date.
    """
    if not data.incident.active:
        return
    for f in data.findings:
        if f.get("_synthetic"):
            in_win = True
        else:
            ts_list = _evidence_timestamps(f)
            in_win = any(data.incident.in_window(t) for t in ts_list)
        if in_win:
            f["_in_incident_window"] = True
            try:
                f["priority_score"] = (
                    int(f.get("priority_score", 0)) + IN_WINDOW_BOOST
                )
            except (TypeError, ValueError):
                f["priority_score"] = IN_WINDOW_BOOST
            tags = list(f.get("tags") or [])
            if "incident-window" not in tags:
                tags.append("incident-window")
            f["tags"] = tags
        else:
            f["_in_incident_window"] = False
