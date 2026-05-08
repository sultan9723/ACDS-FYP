"""Minimal config loader for ACDS."""

import json
from pathlib import Path


def load_config(path=None):
    """Load configuration from a JSON file (placeholder).

    If path is None, returns an empty dict. Implement YAML or environment
    loading as needed.

    Args:
        path: path-like to a JSON config file

    Returns:
        dict: parsed configuration
    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
