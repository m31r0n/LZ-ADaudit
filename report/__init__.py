"""LZ-ADaudit report package.

Single source of truth for the report-generator version. Everything else
(CLI, shim, scorecard methodology) should import this constant rather than
hard-coding a literal.
"""
__version__ = "1.6.0"
