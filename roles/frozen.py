"""Persist a stable (frozen) set of role edges.

The controller learns observed edges over time in BOOTSTRAP/observe mode.
To avoid enforcing transient/ephemeral ports, we promote selected observed
edges into a frozen allowlist that ENFORCE/APPLY can depend on.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

Edge = tuple[str, str, int, str]  # src, dst, port, proto

BUNDLE_DIR = Path(__file__).resolve().parent.parent / "policyBundle"
FROZEN_PATH = BUNDLE_DIR / "roles.frozen.json"


def load_frozen() -> set[Edge]:
    """Load frozen edges as a set of tuples.

    File format:
      { "edges": [[src, dst, port, proto], ...], "frozen_at": <epoch>, ... }
    """

    if not FROZEN_PATH.exists():
        return set()

    try:
        data = json.loads(FROZEN_PATH.read_text())
    except Exception:
        return set()

    edges_raw = (data or {}).get("edges", []) or []
    out: set[Edge] = set()
    for item in edges_raw:
        try:
            src, dst, port, proto = item
        except Exception:
            continue
        out.add((str(src), str(dst), int(port), str(proto).upper()))
    return out


def save_frozen(edges: set[Edge]) -> None:
    """Write frozen edges to disk."""

    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    frozen = {
        "edges": sorted([[s, d, int(p), str(proto).upper()] for s, d, p, proto in edges]),
        "frozen_at": int(time.time()),
        "source": "promote",
    }
    FROZEN_PATH.write_text(json.dumps(frozen, indent=2, sort_keys=True))
