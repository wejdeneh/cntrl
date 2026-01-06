#controller/oles.py
from __future__ import annotations
import os
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from policies.roles import generate_roles_from_edges
from roles.labels import role_from_labels

PodEdge = Tuple[str, str, int, str]
RoleEdge = Tuple[str, str, int, str]


def _pod_labels(p: dict) -> dict:
    return ((p or {}).get("metadata", {}) or {}).get("labels", {}) or {}


def _pod_namespace(p: dict) -> str:
    return ((p or {}).get("metadata", {}) or {}).get("namespace", "")


def _pod_name(p: dict) -> str:
    return ((p or {}).get("metadata", {}) or {}).get("name", "")


def _pod_ip(p: dict) -> Optional[str]:
    return ((p or {}).get("status", {}) or {}).get("podIP")


def _container_ports(p: dict) -> Set[Tuple[str, int]]:
    ports: Set[Tuple[str, int]] = set()
    spec = (p or {}).get("spec", {}) or {}
    for c in spec.get("containers", []) or []:
        for cp in (c or {}).get("ports", []) or []:
            try:
                port = int(cp.get("containerPort"))
            except Exception:
                continue
            proto = str(cp.get("protocol", "TCP")).upper()
            ports.add((proto, port))
    return ports


def _service_ports(svc: dict) -> Set[Tuple[str, int]]:
    ports: Set[Tuple[str, int]] = set()
    spec = (svc or {}).get("spec", {}) or {}
    for p in spec.get("ports", []) or []:
        try:
            portnum = int(p.get("port"))
        except Exception:
            continue
        proto = str(p.get("protocol", "TCP")).upper()
        ports.add((proto, portnum))
    return ports


def _service_selector(svc: dict) -> dict:
    return ((svc or {}).get("spec", {}) or {}).get("selector", {}) or {}


def _labels_match_selector(labels: dict, selector: dict) -> bool:
    if not selector:
        return False
    for k, v in selector.items():
        if labels.get(k) != v:
            return False
    return True


def _endpoints_pod_ips(endpoints: dict) -> Set[str]:
    ips: Set[str] = set()
    for subset in (endpoints or {}).get("subsets", []) or []:
        for addr in subset.get("addresses", []) or []:
            ip = addr.get("ip")
            if ip:
                ips.add(str(ip))
    return ips


def derive_role_edges_from_cluster_state(
    ns: str,
    pods: List[dict],
    services: Optional[List[dict]] = None,
    endpoints: Optional[List[dict]] = None,
) -> List[RoleEdge]:
    """Derive stable role->role edges from cluster *intent* rather than transient flows.

    Sources:
      - destination role from pod role labels (roles.athena.t9s.io/*)
      - stable ports from:
          (a) Services selecting dst pods (service.spec.ports)
          (b) dst containerPorts (fallback)

    IMPORTANT: This intentionally does *not* infer which src roles should be allowed.
    It only produces edges observed in flows (later) OR edges where we can map src role.
    In this controller, we use this as an additional allowlist for ports/protocols
    when translating observed/frozen edges pod->pod into role->role.
    """

    # Build pod indexes
    pods_in_ns = [p for p in pods if _pod_namespace(p) == ns]
    ip_to_pod: Dict[str, dict] = {}
    name_to_pod: Dict[str, dict] = {}
    for p in pods_in_ns:
        ip = _pod_ip(p)
        if ip:
            ip_to_pod[ip] = p
        name_to_pod[_pod_name(p)] = p

    # Map role -> (proto,port) stable ports
    role_ports: Dict[str, Set[Tuple[str, int]]] = {}
    for p in pods_in_ns:
        role = role_from_labels(_pod_labels(p))
        if not role:
            continue
        role_ports.setdefault(role, set()).update(_container_ports(p))

    # Add Service ports for roles (more stable than containerPorts)
    if services:
        for svc in services:
            if ((svc or {}).get("metadata", {}) or {}).get("namespace") != ns:
                continue
            sel = _service_selector(svc)
            if not sel:
                continue
            svc_ports = _service_ports(svc)
            if not svc_ports:
                continue
            for p in pods_in_ns:
                if _labels_match_selector(_pod_labels(p), sel):
                    role = role_from_labels(_pod_labels(p))
                    if role:
                        role_ports.setdefault(role, set()).update(svc_ports)

    # If Endpoints are provided, we can be stricter: only apply Service ports to pods
    # actually in the endpoints set.
    if services and endpoints:
        ep_by_ns_name: Dict[Tuple[str, str], dict] = {}
        for ep in endpoints:
            meta = (ep or {}).get("metadata", {}) or {}
            ep_by_ns_name[(meta.get("namespace"), meta.get("name"))] = ep
        for svc in services:
            meta = (svc or {}).get("metadata", {}) or {}
            if meta.get("namespace") != ns:
                continue
            ep = ep_by_ns_name.get((ns, meta.get("name")))
            if not ep:
                continue
            ips = _endpoints_pod_ips(ep)
            if not ips:
                continue
            svc_ports = _service_ports(svc)
            if not svc_ports:
                continue
            for ip in ips:
                p = ip_to_pod.get(ip)
                if not p:
                    continue
                role = role_from_labels(_pod_labels(p))
                if role:
                    role_ports.setdefault(role, set()).update(svc_ports)

    # Convert per-role stable ports into a set of "allowed port tuples" for filtering.
    # We return edges later by intersecting observed role pairs with these ports.
    # Here we just return a placeholder-style list: ("*", dst_role, port, proto)
    # so upstream can check "is (proto,port) stable for dst_role".
    edges: Set[RoleEdge] = set()
    for dst_role, ports in role_ports.items():
        for proto, port in ports:
            edges.add(("*", dst_role, port, proto))
    return sorted(edges)


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
    # Athena operator / controllers
    if "operator" in name or "athena-base-operator" in name:
        return ns, "operator"
    # MySQL database (various charts)
    if "mysql-db" in name or "mysql" in name:
        return ns, "db"
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
    if name.startswith("db."):
        return ns, "db"
    if "monitor" in name:
        return ns, "monitoring"
    return ns, "unknown"


KNOWN_PORTS = {
    ("gnb", "upf"): {("UDP", 2152)},
    ("upf", "smf"): {("TCP", 60001), ("UDP", 8805)},
    ("gnb", "amf"): {("SCTP", 38412), ("SCTP", 57871), ("TCP", 60001)},
    # AMF needs to be able to initiate toward gNB as well in some stacks (service ports only)
    ("amf", "gnb"): {("SCTP", 38412), ("TCP", 60001)},
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
    # Some deployments also query metrics/control over 60001; keep off by default unless confirmed.
    # ("monitoring", "db"): {("TCP", 3306), ("TCP", 60001)},
    # Monitoring to RIC (observed TCP/60001)
    ("monitoring", "ric"): {("TCP", 60001)},

    # SBI (HTTP) between AMF and SMF: observed TCP/80
    ("amf", "smf"): {("TCP", 80)},
    ("smf", "amf"): {("TCP", 80)},

    # PFCP can be initiated either way depending on implementation; keep symmetric on the service port.
    ("smf", "upf"): {("UDP", 8805), ("TCP", 60001)},
    # add more known pairs if needed
}


def _stable_ports_for_dst_role(
    dst_role: str,
    derived_edges: Optional[Iterable[RoleEdge]],
) -> Set[Tuple[str, int]]:
    if not derived_edges:
        return set()
    out: Set[Tuple[str, int]] = set()
    for src, dst, port, proto in derived_edges:
        if src != "*":
            continue
        if dst != dst_role:
            continue
        out.add((proto, int(port)))
    return out


def _filter_and_aggregate(
    ns: str,
    pod_edges: List[PodEdge],
    derived_stable_ports: Optional[Iterable[RoleEdge]] = None,
) -> List[RoleEdge]:
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

        # 1) Prefer strict allowlist for role-pair (hand-curated, safest)
        allowed = KNOWN_PORTS.get((src_role, dst_role)) or set()

        # 2) Also allow if the dst_role appears to expose this as a stable port
        #    via Service/Endpoints/containerPorts (automatic port coverage).
        stable_dst_ports = _stable_ports_for_dst_role(dst_role, derived_stable_ports)

        if (proto, port) not in allowed and (proto, port) not in stable_dst_ports:
            continue

        role_edges.add((src_role, dst_role, int(port), proto))
    return list(role_edges)


def desired_role_policies(ns: str, mode: str) -> list[dict]:
    """
    BOOTSTRAP -> use observed edges (dynamic)
    ENFORCE   -> use frozen edges (stable)
    """
    # Optional: automatically consider stable destination ports derived from K8s Services/Endpoints
    # and containerPorts, to reduce outages from missing "known ports".
    derived_stable_ports = None
    if os.environ.get("CONTROLLER_DERIVE_PORTS", "1") == "1":
        try:
            from kubernetes import client, config

            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()

            corev1 = client.CoreV1Api()
            pods = [p.to_dict() for p in corev1.list_namespaced_pod(ns).items]
            svcs = [s.to_dict() for s in corev1.list_namespaced_service(ns).items]
            eps = [e.to_dict() for e in corev1.list_namespaced_endpoints(ns).items]
            derived_stable_ports = derive_role_edges_from_cluster_state(ns, pods, svcs, eps)
        except Exception:
            # If we can't talk to the cluster here, just fall back to KNOWN_PORTS.
            derived_stable_ports = None

    if mode == "ENFORCE":
        pod_edges = _read_edges(FROZEN_PATH)
        role_edges = _filter_and_aggregate(ns, pod_edges, derived_stable_ports=derived_stable_ports)
        return generate_roles_from_edges(ns, role_edges, mode="ENFORCE")

    # BOOTSTRAP default
    pod_edges = _read_edges(OBSERVED_PATH)
    role_edges = _filter_and_aggregate(ns, pod_edges, derived_stable_ports=derived_stable_ports)
    return generate_roles_from_edges(ns, role_edges, mode="BOOTSTRAP")
