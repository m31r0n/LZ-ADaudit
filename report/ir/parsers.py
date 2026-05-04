"""Datetime parsing helpers shared by the IR pipeline."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Common AdAudit / Windows date patterns:
#   "Account jherrera was created 04/01/2026 16:39:44"
#   "User foo has not logged on since 12/03/2025 09:11:22"
#   "25/04/2026 6:03:01 p. m." (Spanish locale, dd/mm/yyyy)
#   "Account bar password last set 2026-04-26T18:00:00Z"
DATE_RE_LIST = [
    re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})(?:[\s,T]+(\d{1,2}):(\d{2}):(\d{2}))?\b"),
    re.compile(r"\b(\d{4})-(\d{2})-(\d{2})(?:[T\s](\d{2}):(\d{2}):(\d{2}))?\b"),
]


def parse_dt_loose(s: Any) -> datetime | None:
    """Parse a wide variety of date formats. Returns UTC datetime or None.

    Accepts ISO 8601 (with optional Z), d/m/yyyy or m/d/yyyy (auto-detected),
    and yyyy-m-d. Naive results are interpreted as UTC. Recognises Spanish
    locale ``p. m.`` / ``a. m.`` markers commonly seen in es-CO AD exports.
    """
    if not s:
        return None
    s = str(s).strip()
    s_low = s.lower()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        pass

    for rx in DATE_RE_LIST:
        m = rx.search(s)
        if not m:
            continue
        g = m.groups()
        try:
            if rx is DATE_RE_LIST[0]:
                a, b, year = int(g[0]), int(g[1]), int(g[2])
                # Auto-detect d/m/y vs m/d/y. If unambiguous (one > 12) we
                # know. Otherwise prefer d/m/y when the raw string carries
                # Spanish AM/PM markers; default to US m/d/y for compatibility.
                if a > 12 and b <= 12:
                    day, month = a, b
                elif b > 12 and a <= 12:
                    month, day = a, b
                else:
                    if "p. m." in s_low or "a. m." in s_low:
                        day, month = a, b
                    else:
                        month, day = a, b
            else:
                year, month, day = int(g[0]), int(g[1]), int(g[2])

            hour = int(g[3]) if g[3] else 0
            minute = int(g[4]) if g[4] else 0
            second = int(g[5]) if g[5] else 0
            # PM/AM adjustment for Spanish locale.
            if "p. m." in s_low and hour < 12:
                hour += 12
            elif "a. m." in s_low and hour == 12:
                hour = 0

            return datetime(year, month, day, hour, minute, second,
                            tzinfo=timezone.utc)
        except (ValueError, IndexError):
            continue
    return None


def extract_dates(text: Any) -> list[datetime]:
    """Extract every recognisable timestamp from a free-text blob."""
    out: list[datetime] = []
    if not text:
        return out
    seen: set[str] = set()
    for rx in DATE_RE_LIST:
        for m in rx.finditer(str(text)):
            key = m.group(0)
            if key in seen:
                continue
            seen.add(key)
            d = parse_dt_loose(key)
            if d:
                out.append(d)
    return out


def finding_timestamps(f: dict) -> list[datetime]:
    """All timestamps associated with a finding: created_at + dates in evidence."""
    out: list[datetime] = []
    ca = f.get("created_at_utc")
    if ca:
        d = parse_dt_loose(ca)
        if d:
            out.append(d)
    out.extend(extract_dates(f.get("evidence", "") or ""))
    for ao in f.get("affected_objects") or []:
        out.extend(extract_dates(str(ao)))
    return out
