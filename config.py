# config.py
from __future__ import annotations
import os
from typing import Literal

Mode = Literal["BOOTSTRAP", "ENFORCE", "TEARDOWN"]

from role_controller import desired_role_policies  # controller/roles.py
from policies.infra import generate_infra
from policies.safety import generate_safety


def desired_policies(ns: str, mode: Mode) -> list[dict]:
    """
    Controller-managed policies ONLY (roles/safety).
    Infra is excluded by design and applied separately via 00-infra.yaml.
    """
    if mode == "TEARDOWN":
        return []

    desired: list[dict] = []

    # Optional: have the controller manage baseline infra policies so pod startup
    # (DNS, kube-apiserver access, webhooks, etc.) doesn't depend on separate YAML apply.
    if os.environ.get("CONTROLLER_MANAGE_INFRA", "0") == "1":
        desired.extend(generate_infra(ns))

    # Optional: temporary safety net policies (world egress, host/remote-node) for
    # debugging/maintenance. Keep disabled by default.
    if os.environ.get("CONTROLLER_ENABLE_SAFETY", "0") == "1":
        desired.extend(generate_safety(ns))

    desired.extend(desired_role_policies(ns, mode))
    return desired
