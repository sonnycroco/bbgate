"""Timestamp helpers shared by the checks, the mutators and the log."""
from __future__ import annotations

from datetime import datetime


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def parse_ts(value: str) -> datetime | None:
    """Parse an ISO timestamp, returning None when it cannot be trusted.

    Timezone is dropped after parsing. These stamps come from a person's own
    machine and the only question ever asked of them is which of two came
    first, so a naive comparison is the honest one. Callers must treat None as
    ambiguous and fail, never as a pass.
    """
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=None)
