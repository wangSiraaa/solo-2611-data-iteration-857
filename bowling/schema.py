"""Access to the compiled bowling lane event directory."""

from __future__ import annotations

import json
from pathlib import Path

BOWLING_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "bowling_lane_v1.json"


def load_schema() -> dict:
    """Return the ``bowling.lane.event`` directory document."""
    return json.loads(BOWLING_SCHEMA_PATH.read_text(encoding="utf-8"))
