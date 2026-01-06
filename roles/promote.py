# roles/promote.py
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path when running as a script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from roles.observed import load_observed  # noqa: E402
from roles.frozen import load_frozen, save_frozen  # noqa: E402


def promote_all():
    observed = load_observed()
    frozen = load_frozen()

    new_edges = observed - frozen
    if not new_edges:
        print("[promote] nothing new")
        return

    print("[promote] promoting:")
    for e in new_edges:
        print("  +", e)

    save_frozen(frozen | new_edges)
