#!/usr/bin/env python3
"""Plan-only runner: prints what the controller would reconcile without applying changes.

Usage:
  NAMESPACE=trirematics CONTROLLER_MODE=BOOTSTRAP python3 tools/plan.py

Notes:
- Uses your local kubeconfig (same behavior as app.py).
- Does not create/update/delete any objects.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from kubernetes import client, config

# Ensure project root is on sys.path when running as a script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import desired_policies  # noqa: E402
from reconcile import plan_reconcile, print_plan  # noqa: E402


def main() -> None:
    namespace = os.environ.get("NAMESPACE", "trirematics")

    try:
        config.load_incluster_config()
        print("[plan] using in-cluster config")
    except Exception:
        config.load_kube_config()
        print("[plan] using kubeconfig (local)")

    cilium = client.CustomObjectsApi()

    # Minimal adapter to match reconcile.py expectations (list_cnp only)
    class _Client:
        def list_cnp(self, ns: str):
            res = cilium.list_namespaced_custom_object(
                group="cilium.io",
                version="v2",
                namespace=ns,
                plural="ciliumnetworkpolicies",
            )
            return res.get("items", [])

    mode = os.environ.get("CONTROLLER_MODE") or os.environ.get("MODE") or "BOOTSTRAP"
    desired = desired_policies(namespace, mode)  # includes infra/safety based on env flags

    plan = plan_reconcile(_Client(), namespace, desired)
    print_plan(plan)


if __name__ == "__main__":
    main()
