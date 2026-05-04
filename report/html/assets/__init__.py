"""Asset loaders for inline CSS/JS embedding into the report HTML."""
from __future__ import annotations

from pathlib import Path

_ASSETS_DIR = Path(__file__).resolve().parent


def load_css() -> str:
    return (_ASSETS_DIR / "styles.css").read_text(encoding="utf-8")


def load_js() -> str:
    return (_ASSETS_DIR / "script.js").read_text(encoding="utf-8")
