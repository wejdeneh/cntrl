# roles/promote.py
from roles.observed import load_observed
from roles.frozen import load_frozen, save_frozen


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
