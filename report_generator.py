#!/usr/bin/env python3
"""LZ-ADaudit Report Generator — entry-point shim.

The implementation lives in the ``report`` package. This file exists so
existing scripts and scheduled tasks calling

    python report_generator.py [args]

keep working without changes. New code should use ``python -m report`` or
``from report.cli import main``.

Version is sourced from ``report.__version__`` (single source of truth).
"""
from __future__ import annotations

from report import __version__
from report.cli import main

__all__ = ["main", "__version__"]

if __name__ == "__main__":
    main()
