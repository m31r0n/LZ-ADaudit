"""Command-line entry point for the report generator."""
from __future__ import annotations

import argparse
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .data import auto_detect_folder, load_audit_data, IncidentConfig

try:
    import openpyxl  # noqa: F401
    _XLSX_OK = True
except ImportError:
    _XLSX_OK = False


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="report_generator",
        description="Generate HTML and/or XLSX security report from an "
                    "AdAudit output folder.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python report_generator.py                              # auto-detect folder
  python report_generator.py C:\\Audit\\<DC>_<timestamp>  # explicit folder
  python report_generator.py . -f html                   # HTML only

Incident-response examples (v1.5.0):
  python report_generator.py . --incident-date 2026-04-25
  python report_generator.py . --incident-date 2026-04-25 \\
      --window-before 30 --window-after 7
  python report_generator.py . --incident-date 2026-04-25 \\
      --auditor "J. Doe" --baseline ../prev_run
""",
    )
    p.add_argument("folder", nargs="?", default=None,
                   help="AdAudit output folder (auto-detected if omitted)")
    p.add_argument("-f", "--format", choices=["html", "xlsx", "both"],
                   default="both",
                   help="Output format (default: both)")
    p.add_argument("-o", "--output", default=None,
                   help="Base name for output files (no extension)")
    p.add_argument("--open", action="store_true",
                   help="Open HTML report in default browser after generation")

    # v1.5.0 — IR mode
    p.add_argument("--incident-date", default=None, metavar="YYYY-MM-DD",
                   help="Activate IR Mode: incident date (UTC). Findings "
                        "inside the window are scored higher and rendered "
                        "with a banner + timeline.")
    p.add_argument("--window-before", type=int, default=30, metavar="DAYS",
                   help="Days BEFORE incident date to include (default: 30)")
    p.add_argument("--window-after", type=int, default=7, metavar="DAYS",
                   help="Days AFTER incident date to include (default: 7)")
    p.add_argument("--auditor", default="",
                   help="Auditor name (shown in IR banner and chain-of-custody)")
    p.add_argument("--baseline", default=None, metavar="FOLDER",
                   help="Optional previous audit folder to diff against")
    p.add_argument("--lang", choices=["es", "en"], default="es",
                   help="UI language (default: es)")
    return p.parse_args(argv)


def _build_incident_config(args: argparse.Namespace) -> IncidentConfig:
    cfg = IncidentConfig(
        window_before_days=args.window_before,
        window_after_days=args.window_after,
        auditor=args.auditor,
        language=args.lang,
    )
    if args.incident_date:
        try:
            cfg.incident_date = datetime.strptime(
                args.incident_date, "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"[ERROR] --incident-date must be YYYY-MM-DD, got "
                  f"'{args.incident_date}'", file=sys.stderr)
            sys.exit(2)
    if args.baseline:
        bp = Path(args.baseline).expanduser().resolve()
        if not bp.exists():
            print(f"[WARN] --baseline folder not found: {bp}",
                  file=sys.stderr)
        else:
            cfg.baseline_folder = bp
    return cfg


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    # ---- Resolve folder ----
    if args.folder:
        folder = Path(args.folder).expanduser().resolve()
    else:
        folder = auto_detect_folder()
        if not folder:
            print("[ERROR] No AdAudit output folder found. "
                  "Pass a folder path as argument.", file=sys.stderr)
            sys.exit(1)
        print(f"  Auto-detected: {folder}")

    if not folder.is_dir():
        print(f"[ERROR] Not a directory: {folder}", file=sys.stderr)
        sys.exit(1)
    if not (folder / "findings.ndjson").exists():
        print(f"[ERROR] findings.ndjson not found in {folder}",
              file=sys.stderr)
        sys.exit(1)

    base_name = args.output or "report"
    html_path = folder / f"{base_name}.html"
    xlsx_path = folder / f"{base_name}.xlsx"

    if args.format in ("xlsx", "both") and not _XLSX_OK:
        print(
            "[ERROR] openpyxl is required for XLSX output but is not installed.\n"
            "        Install with: pip install openpyxl\n"
            "        Or run with -f html to generate only the HTML report.",
            file=sys.stderr,
        )
        if args.format == "xlsx":
            sys.exit(2)

    print(f"\n  Folder : {folder}")
    if args.format in ("html", "both"):
        print(f"  HTML   : {html_path.name}")
    if args.format in ("xlsx", "both"):
        marker = "  [SKIPPED — openpyxl missing]" if not _XLSX_OK else ""
        print(f"  XLSX   : {xlsx_path.name}{marker}")
    print()

    # ---- Load (with IR pipeline if --incident-date) ----
    incident_cfg = _build_incident_config(args)
    if incident_cfg.active:
        print(f"  IR Mode: ON — incident "
              f"{incident_cfg.incident_date.strftime('%Y-%m-%d')} "
              f"(window {incident_cfg.window_start.strftime('%Y-%m-%d')} -> "
              f"{incident_cfg.window_end.strftime('%Y-%m-%d')})")

    data = load_audit_data(folder, incident=incident_cfg)
    total = len(data.findings)
    sev = data.summary.get("findings_by_severity", {}) or {}
    crit = sev.get("critical", 0)
    hi = sev.get("high", 0)
    in_w = sum(1 for f in data.findings if f.get("_in_incident_window"))
    print(f"\n  {total} findings loaded  ({crit} critical, {hi} high"
          + (f", {in_w} in incident window" if incident_cfg.active else "")
          + ")")
    if data.synthetic_findings:
        ids = ", ".join(s["check_id"] for s in data.synthetic_findings)
        print(f"  ! {len(data.synthetic_findings)} synthetic IR finding(s) "
              f"injected: {ids}")
    if data.correlations:
        print(f"  -> {len(data.correlations)} correlation rule match(es)")
    if data.missing_inputs:
        print(f"  ! {len(data.missing_inputs)} missing/empty inputs - "
              f"see 'Cobertura de evidencia' section")
    print()

    # ---- HTML ----
    if args.format in ("html", "both"):
        from .html.builder import build_html
        print("  Building HTML...", end=" ", flush=True)
        html_path.write_text(build_html(data), encoding="utf-8")
        size_kb = html_path.stat().st_size // 1024
        print(f"done  ({size_kb} KB)")

    # ---- XLSX ----
    if args.format in ("xlsx", "both") and _XLSX_OK:
        from .xlsx.builder import build_xlsx
        print("  Building XLSX...", end=" ", flush=True)
        build_xlsx(data, xlsx_path)
        if xlsx_path.exists():
            size_kb = xlsx_path.stat().st_size // 1024
            print(f"done  ({size_kb} KB)")

    print(f"\n  Reports saved to: {folder}\n")

    if args.open and args.format in ("html", "both"):
        webbrowser.open(html_path.as_uri())

    if args.format in ("xlsx", "both") and not _XLSX_OK:
        sys.exit(2)


if __name__ == "__main__":
    main()
