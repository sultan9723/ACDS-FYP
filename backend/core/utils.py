"""Utility helpers for ACDS."""


def noop(*args, **kwargs):
    """No-op placeholder utility."""
    return None


def ensure_list(x):
    """Ensure the input is a list. If None, returns empty list."""
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]
