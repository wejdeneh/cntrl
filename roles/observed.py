# roles/observed.py
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Tuple, List
import time

Edge = Tuple[str, str, int, str]  # src, dst, port, proto

BUNDLE_DIR = Path(__file__).resolve().parent.parent / "policyBundle"
OBSERVED_PATH = BUNDLE_DIR / "roles.observed.json"

def _load() -> Dict:
    if not OBSERVED_PATH.exists():
        return {"edges": [], "last_updated": 0}
    try:
        return json.loads(OBSERVED_PATH.read_text())
    except Exception:
        return {"edges": [], "last_updated": 0}

def _save(data: Dict) -> None:
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    OBSERVED_PATH.write_text(json.dumps(data, indent=2, sort_keys=True))

def record_edge(src: str, dst: str, port: int, proto: str) -> None:
    proto = proto.upper()
    data = _load()
    edges: List = data.get("edges", [])

    edge = [src, dst, int(port), proto]
    if edge not in edges:
        edges.append(edge)
        data["edges"] = edges
        data["last_updated"] = int(time.time())
        _save(data)


def load_observed() -> set[Edge]:
    """Return observed edges as a set of tuples for promotion/diffing."""
    data = _load()
    edges_raw = data.get("edges", []) or []
    out: set[Edge] = set()
    for item in edges_raw:
        try:
            src, dst, port, proto = item
        except Exception:
            continue
        out.add((str(src), str(dst), int(port), str(proto).upper()))
    return out
