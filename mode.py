# mode.py
import os

def compute_mode(pods=None, namespace_obj=None) -> str:
    """
    Decide controller mode.
    Priority:
      1) Environment variable CONTROLLER_MODE (BOOTSTRAP/APPLY)
      2) Namespace annotation trirematics.io/controller-mode
      3) Default to BOOTSTRAP
    """
    env_mode = os.environ.get("CONTROLLER_MODE") or os.environ.get("MODE")
    if env_mode in {"BOOTSTRAP", "APPLY"}:
        return env_mode

    ann = ((namespace_obj or {}).get("metadata", {}) or {}).get("annotations", {}) or {}
    ns_mode = ann.get("trirematics.io/controller-mode")
    if ns_mode in {"BOOTSTRAP", "APPLY"}:
        return ns_mode

    return "BOOTSTRAP"
