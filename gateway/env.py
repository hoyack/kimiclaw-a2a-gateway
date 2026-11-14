"""Parse numeric process env vars; raise a one-line RuntimeError on bad input."""
import math
import os


def _env_num(name: str, default: str, kind=int, *, lo=None, hi=None, gt=None):
    """Parse a numeric env var; reject non-numeric values, nan, inf, and out-of-range numbers."""
    raw = os.environ.get(name, default)
    try:
        value = kind(raw)
    except (TypeError, ValueError):
        want = "an integer" if kind is int else "a number"
        raise RuntimeError(f"{name} must be {want}") from None
    if isinstance(value, float) and not math.isfinite(value):
        raise RuntimeError(f"{name} must be a number") from None
    if gt is not None and not value > gt:
        raise RuntimeError(f"{name} must be > {gt}") from None
    if lo is not None and value < lo:
        raise RuntimeError(f"{name} must be >= {lo}") from None
    if hi is not None and value > hi:
        raise RuntimeError(f"{name} must be <= {hi}") from None
    return value
