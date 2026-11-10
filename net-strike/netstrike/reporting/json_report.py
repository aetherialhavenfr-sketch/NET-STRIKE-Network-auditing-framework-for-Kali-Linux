"""Machine-readable JSON report."""

from __future__ import annotations

import json
from pathlib import Path

from ..runner import write_private


def write_json(data: dict, path: Path) -> Path:
    """Write the session dict (see ScanSession.to_dict) as pretty JSON, owner-readable only."""
    write_private(path, json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")
    return path
