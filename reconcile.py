# reconcile.py
from __future__ import annotations
from typing import Dict, List, Tuple
import re
import hashlib


class ReconcilePlan(dict):
    """A small, json-serializable planning object."""

    # kept as dict subclass for easy printing/JSON dumping

PolicyId = Tuple[str, str, str]  # (namespace, kind, name)


def pid(pol: dict) -> PolicyId:
    meta = pol.get("metadata", {})
    return (meta.get("namespace", ""), pol.get("kind", ""), meta.get("name", ""))


def normalize(pol: dict) -> dict:
    pol = dict(pol)
    pol.pop("status", None)
    meta = dict(pol.get("metadata", {}))
    for k in ["creationTimestamp", "resourceVersion", "uid", "generation", "managedFields"]:
        meta.pop(k, None)
    pol["metadata"] = meta
    return pol


def _sanitize_name(name: str) -> str:
    n = (name or "").lower()
    n = re.sub(r"[^a-z0-9-.]", "-", n)
    n = re.sub(r"[-.]{2,}", "-", n)
    n = re.sub(r"^[^a-z0-9]+", "", n)
    n = re.sub(r"[^a-z0-9]+$", "", n)
    return n or "cnp"


def _sanitize_label_value(val: str) -> str:
    v = str(val or "")
    v = re.sub(r"[^A-Za-z0-9-_.]", "-", v)
    v = re.sub(r"[-_.]{2,}", "-", v)
    v = re.sub(r"^[^A-Za-z0-9]+", "", v)
    v = re.sub(r"[^A-Za-z0-9]+$", "", v)
    if not v:
        return "value"
    if len(v) > 63:
        h = hashlib.sha1(val.encode()).hexdigest()[:6]
        v = v[:(63 - 7)] + "-" + h
        v = re.sub(r"[^A-Za-z0-9]+$", "", v)
        if not v:
            v = h
    return v


def sanitize_policy(pol: dict) -> dict:
    p = normalize(pol)
    meta = dict(p.get("metadata", {}) or {})
    if "name" in meta:
        meta["name"] = _sanitize_name(meta["name"])
    labels = dict(meta.get("labels", {}) or {})
    for k in list(labels.keys()):
        labels[k] = _sanitize_label_value(labels[k])
    meta["labels"] = labels
    p["metadata"] = meta
    return p


def _owned_by_controller(pol: dict) -> bool:
    labels = (pol.get("metadata", {}) or {}).get("labels", {}) or {}
    return (
        labels.get("trirematics.io/managed") == "true"
        and labels.get("trirematics.io/managed-by") == "controller"
    )


def plan_reconcile(client, namespace: str, desired: List[dict]) -> ReconcilePlan:
    """Compute what reconcile() *would* do, without creating/updating/deleting anything."""
    desired_sanitized = [sanitize_policy(p) for p in desired]
    desired_map: Dict[PolicyId, dict] = {pid(p): p for p in desired_sanitized}

    actual = client.list_cnp(namespace)
    actual_map: Dict[PolicyId, dict] = {pid(p): normalize(p) for p in actual}

    to_create: List[str] = []
    to_update: List[str] = []
    to_delete: List[str] = []

    for _id, d in desired_map.items():
        name = d.get("metadata", {}).get("name", "")
        if _id not in actual_map:
            to_create.append(name)
        else:
            if actual_map[_id] != d:
                to_update.append(name)

    for _id, a in actual_map.items():
        if _owned_by_controller(a) and _id not in desired_map:
            to_delete.append(a.get("metadata", {}).get("name", ""))

    to_create.sort()
    to_update.sort()
    to_delete.sort()

    return ReconcilePlan(
        namespace=namespace,
        counts={
            "create": len(to_create),
            "update": len(to_update),
            "delete": len(to_delete),
        },
        create=to_create,
        update=to_update,
        delete=to_delete,
    )


def print_plan(plan: ReconcilePlan) -> None:
    ns = plan.get("namespace")
    counts = plan.get("counts", {})
    print(f"[plan] namespace={ns} create={counts.get('create',0)} update={counts.get('update',0)} delete={counts.get('delete',0)}")
    for k in ("create", "update", "delete"):
        items = plan.get(k, []) or []
        if not items:
            continue
        print(f"[plan] {k}:")
        for name in items:
            print(f"  - {name}")


def reconcile(client, namespace: str, desired: List[dict]) -> None:
    # Sanitize desired so names/labels match creation-time values
    desired_sanitized = [sanitize_policy(p) for p in desired]
    desired_map: Dict[PolicyId, dict] = {pid(p): p for p in desired_sanitized}

    actual = client.list_cnp(namespace)
    actual_map: Dict[PolicyId, dict] = {pid(p): normalize(p) for p in actual}

    # create/update desired
    for _id, d in desired_map.items():
        if _id not in actual_map:
            client.create_cnp(namespace, d)
        else:
            if actual_map[_id] != d:
                client.patch_cnp(namespace, d["metadata"]["name"], d)

    # delete ONLY controller-owned policies not desired
    for _id, a in actual_map.items():
        if _owned_by_controller(a) and _id not in desired_map:
            client.delete_cnp(namespace, a["metadata"]["name"])
