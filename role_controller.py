#controller/oles.py
from __future__ import annotations
import json
from pathlib import Path
from typing import List, Tuple

from policies.roles import generate_roles_from_edges

PodEdge = Tuple[str, str, int, str]
RoleEdge = Tuple[str, str, int, str]


BUNDLE_DIR = Path(__file__).resolve().parent / "policyBundle"
OBSERVED_PATH = BUNDLE_DIR / "roles.observed.json"
FROZEN_PATH = BUNDLE_DIR / "roles.frozen.json"


def _read_edges(path: Path) -> List[PodEdge]:
    if not path.exists():
        return []
    text = path.read_text().strip()
    if not text:
        # Empty file (e.g., being written) -> treat as no edges yet
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Partially written or corrupted; ignore for this cycle
        return []
    raw = data.get("edges", [])
    edges: List[PodEdge] = []
    for item in raw:
        # item can be list/tuple: [src, dst, port, proto]
        try:
            src, dst, port, proto = item
        except Exception:
            # Skip malformed entries
            continue
        edges.append((str(src), str(dst), int(port), str(proto).upper()))
    return edges


def _to_role(pod_id: str) -> tuple[str, str]:
    """
    Map full pod identity (namespace/pod) to (namespace, role).
    Simple heuristics based on pod name prefixes; adjust as needed.
    """
    try:
        ns, pod = pod_id.split("/", 1)
    except ValueError:
        return pod_id, "unknown"
    name = pod.lower()
    # UE/RAN simulators
    if "nr-rfsim" in name or "rfsim" in name:
        return ns, "nr-rfsim"
    # RIC (FlexRIC)
    if "flexric" in name or name.startswith("ric") or ".ric" in name:
        return ns, "ric"
    # xApps
    if "xapp" in name or "x-app" in name:
        return ns, "xapp"
    if name.startswith("gnb.") or "oai-gnb" in name:
        return ns, "gnb"
    if name.startswith("upf.") or "upf" in name:
        return ns, "upf"
    if name.startswith("smf.") or "smf" in name:
        return ns, "smf"
    if name.startswith("amf.") or "amf" in name:
        return ns, "amf"
    if "mysql" in name or name.startswith("db."):
        return ns, "db"
    if "monitor" in name:
        return ns, "monitoring"
    return ns, "unknown"


KNOWN_PORTS = {
    ("gnb", "upf"): {("UDP", 2152)},
    ("upf", "smf"): {("TCP", 60001), ("UDP", 8805)},
    ("gnb", "amf"): {("SCTP", 38412), ("SCTP", 57871), ("TCP", 60001)},
    # AMF typically talks to DB on 3306 (MySQL) but observed control plane also uses TCP/60001
    ("amf", "db"): {("TCP", 3306), ("TCP", 60001)},
    # RIC (FlexRIC) control channel observed on TCP/60001
    ("gnb", "ric"): {("TCP", 60001)},
    ("ric", "gnb"): {("TCP", 60001)},
    # UE simulator to gNB (observed stable UE->gNB port)
    # Some setups also use TCP/60001 for control.
    ("nr-rfsim", "gnb"): {("TCP", 4043), ("TCP", 60001)},
    # Monitoring to DB (MySQL) for metrics collection
    ("monitoring", "db"): {("TCP", 3306)},
    # Monitoring to RIC (observed TCP/60001)
    ("monitoring", "ric"): {("TCP", 60001)},
    # add more known pairs if needed
}


def _filter_and_aggregate(ns: str, pod_edges: List[PodEdge]) -> List[RoleEdge]:
    """
    - Keep only edges within target namespace
    - Map pods to roles
    - Allowlist known service ports per role-pair
    - Deduplicate
    """
    role_edges: set[RoleEdge] = set()
    for src_pod, dst_pod, port, proto in pod_edges:
        src_ns, src_role = _to_role(src_pod)
        dst_ns, dst_role = _to_role(dst_pod)
        if src_ns != ns or dst_ns != ns:
            continue
        # allow only known service ports for the role pair
        allowed = KNOWN_PORTS.get((src_role, dst_role))
        if not allowed:
            continue
        if (proto, port) not in allowed:
            continue
        role_edges.add((src_role, dst_role, int(port), proto))
    return list(role_edges)


def desired_role_policies(ns: str, mode: str) -> list[dict]:
    """
    BOOTSTRAP -> use observed edges (dynamic)
    ENFORCE   -> use frozen edges (stable)
    """
    if mode == "ENFORCE":
        pod_edges = _read_edges(FROZEN_PATH)
        role_edges = _filter_and_aggregate(ns, pod_edges)
        return generate_roles_from_edges(ns, role_edges, mode="ENFORCE")

    # BOOTSTRAP default
    pod_edges = _read_edges(OBSERVED_PATH)
    role_edges = _filter_and_aggregate(ns, pod_edges)
    return generate_roles_from_edges(ns, role_edges, mode="BOOTSTRAP")
