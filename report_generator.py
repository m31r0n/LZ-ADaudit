#!/usr/bin/env python3
"""LZ-ADaudit Report Generator — v1.5.0 entry-point shim.

The implementation lives in the ``report`` package. This file exists so
existing scripts and scheduled tasks calling

    python report_generator.py [args]

keep working without changes. New code should use ``python -m report`` or
``from report.cli import main``.
"""
from __future__ import annotations

from report.cli import main

if __name__ == "__main__":
    main()
