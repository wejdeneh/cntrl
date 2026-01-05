# roles/frozen.py
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict
import time

BUNDLE_DIR = Path(__file__).resolve().parent.parent / "policyBundle"
OBSERVED_PATH = BUNDLE_DIR / "roles.observed.json"
FROZEN_PATH = BUNDLE_DIR / "roles.frozen.json"

def load_observed() -> Dict:
    if not OBSERVED_PATH.exists():
        return {"edges": [], "last_updated": 0}
    return json.loads(OBSERVED_PATH.read_text())

def save_frozen(observed: Dict) -> None:
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    frozen = {
        "edges": observed.get("edges", []),
        "frozen_at": int(time.time()),
        "source": "observed",
    }
    FROZEN_PATH.write_text(json.dumps(frozen, indent=2, sort_keys=True))
