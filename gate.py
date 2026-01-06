# gate.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class GateResult:
    ok: bool
    errors: List[str]
    warnings: List[str]


def _has_ports(policy: dict, ports: List[Tuple[str, int]]) -> bool:
    """Return True if ANY (proto,port) exists in ingress/egress->toPorts."""
    spec = policy.get("spec", {}) or {}

    def _scan_rules(rules: list[dict]) -> set[Tuple[str, int]]:
        found: set[Tuple[str, int]] = set()
        for r in rules or []:
            for tp in r.get("toPorts", []) or []:
                for p in tp.get("ports", []) or []:
                    proto = str(p.get("protocol", "")).upper()
                    try:
                        port = int(p.get("port"))
                    except Exception:
                        continue
                    found.add((proto, port))
        return found

    found = set()
    found |= _scan_rules(spec.get("ingress", []) or [])
    found |= _scan_rules(spec.get("egress", []) or [])
    return any(pp in found for pp in ports)


def _selector_matches_pod(selector: dict, labels: dict) -> bool:
    """Very small subset of K8s label selector evaluation (matchLabels + In expressions)."""
    selector = selector or {}
    match_labels = selector.get("matchLabels", {}) or {}
    for k, v in match_labels.items():
        if labels.get(k) != v:
            return False

    for expr in selector.get("matchExpressions", []) or []:
        key = expr.get("key")
        op = expr.get("operator")
        vals = expr.get("values", []) or []
        if op == "In":
            if labels.get(key) not in vals:
                return False
        elif op == "NotIn":
            if labels.get(key) in vals:
                return False
        elif op == "Exists":
            if key not in labels:
                return False
        elif op == "DoesNotExist":
            if key in labels:
                return False
        else:
            # Unknown operator -> be safe: treat as non-match
            return False

    return True


def validate_apply_gate(namespace: str, pods: List[dict], desired_policies: List[dict]) -> GateResult:
    """Block APPLY if we detect high-risk setbacks (selectors match nothing, missing critical ports).

    This gate is intentionally conservative. It *does not* prove correctness, but it catches
    common outage causes:
    - infra policy selectors don't match any pod (typo/label drift)
    - critical ports aren't present anywhere in desired set
    - role labels are missing entirely (role policies would select nothing)
    """

    errors: List[str] = []
    warnings: List[str] = []

    # Prepare pod label maps
    pod_labels: List[Dict[str, str]] = []
    for p in pods:
        meta = (p or {}).get("metadata", {}) or {}
        pod_labels.append((meta.get("labels", {}) or {}))

    # 1) Verify we actually have at least one roles label in the namespace
    any_roles_label = False
    for lbls in pod_labels:
        for k in lbls.keys():
            if k.startswith("roles.athena.t9s.io/"):
                any_roles_label = True
                break
        if any_roles_label:
            break
    if not any_roles_label:
        warnings.append(
            "No pod labels matching roles.athena.t9s.io/* were found. Role-based policies may select nothing."
        )

    # 2) Infra selectors sanity: if an infra policy endpointSelector matches zero pods, hard error.
    for pol in desired_policies:
        meta = pol.get("metadata", {}) or {}
        labels = meta.get("labels", {}) or {}
        if labels.get("trirematics.io/type") != "infra":
            continue

        sel = (pol.get("spec", {}) or {}).get("endpointSelector", {}) or {}
        if sel == {}:
            continue  # selects all pods; that's valid

        matches = 0
        for lbls in pod_labels:
            if _selector_matches_pod(sel, lbls):
                matches += 1
        if matches == 0:
            errors.append(
                f"Infra policy {meta.get('name','<unnamed>')} endpointSelector matches 0 pods (label drift? selector too strict)."
            )

    # 3) Critical port presence checks.
    # NOTE: We only check presence anywhere, not directionality.
    required_anywhere: List[Tuple[str, int, str]] = [
        ("UDP", 5553, "operator UDP/5553 appears in pod spec and was seen dropping"),
        ("TCP", 50051, "OLM/operators-plane gRPC 50051 must be allowed"),
        ("UDP", 53, "DNS egress requires UDP/53"),
        ("TCP", 53, "DNS egress requires TCP/53"),
        ("TCP", 6443, "kube-apiserver is commonly needed"),
    ]

    for proto, port, why in required_anywhere:
        if not any(_has_ports(p, [(proto, port)]) for p in desired_policies):
            errors.append(f"No desired policy includes {proto}/{port} ({why}).")

    ok = len(errors) == 0
    return GateResult(ok=ok, errors=errors, warnings=warnings)
