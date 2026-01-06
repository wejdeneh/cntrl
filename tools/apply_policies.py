#!/usr/bin/env python3
"""tools/apply_policies.py

Apply the controller-generated CiliumNetworkPolicies to a namespace.

This makes application "automatic" (no /tmp file needed) while still allowing
you to save an artifact if you want.

By default this runs server-side dry-run (no mutation). Set APPLY=1 to really apply.

Examples:
  # Validate only (recommended first):
  NAMESPACE=trirematics CONTROLLER_MODE=ENFORCE CONTROLLER_MANAGE_INFRA=1 CONTROLLER_ENABLE_SAFETY=1 \
    python3 tools/apply_policies.py

  # Real apply:
  APPLY=1 NAMESPACE=trirematics CONTROLLER_MODE=ENFORCE CONTROLLER_MANAGE_INFRA=1 CONTROLLER_ENABLE_SAFETY=1 \
    python3 tools/apply_policies.py

  # Save the rendered YAML artifact too:
  OUT=/tmp/cnps.yaml APPLY=1 ... python3 tools/apply_policies.py

Safety:
- Only applies the desired set; does not delete anything.
  (Deletion is handled by controller reconcile in APPLY mode.)
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import yaml

# Allow executing from out/controller/tools without installing as a package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import desired_policies  # noqa: E402
from gate import validate_apply_gate  # noqa: E402

from kubernetes import client, config  # noqa: E402


def _load_kube() -> None:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


def _run(cmd: list[str], timeout_s: int = 120) -> tuple[int, str]:
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_s,
    )
    return p.returncode, p.stdout


def main() -> int:
    namespace = os.environ.get("NAMESPACE", "trirematics")
    controller_mode = os.environ.get("CONTROLLER_MODE", "ENFORCE")
    do_apply = os.environ.get("APPLY", "0") == "1"
    out_path = os.environ.get("OUT")  # optional

    _load_kube()
    corev1 = client.CoreV1Api()
    pods = [p.to_dict() for p in corev1.list_namespaced_pod(namespace).items]

    desired = desired_policies(namespace, controller_mode)

    gate = validate_apply_gate(namespace, pods, desired)
    for w in gate.warnings:
        print(f"[apply] gate warning: {w}")
    if not gate.ok:
        print("[apply] gate FAILED; refusing to apply")
        for e in gate.errors:
            print(f"[apply] gate error: {e}")
        return 2

    # Render YAML to a temp file (kubectl apply -f - doesn't preserve doc boundaries nicely)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        for pol in desired:
            yaml.safe_dump(pol, f, sort_keys=False)
            f.write("---\n")
        tmp_path = f.name

    if out_path:
        with open(out_path, "w") as out:
            with open(tmp_path, "r") as src:
                out.write(src.read())
        print(f"[apply] wrote rendered YAML to {out_path}")

    cmd = ["kubectl", "apply", "-n", namespace]
    if not do_apply:
        cmd.append("--dry-run=server")
    cmd += ["-f", tmp_path]

    rc, out = _run(cmd)
    print(out.rstrip())

    if rc != 0:
        print("[apply] kubectl apply FAILED")
        return 3

    if do_apply:
        print("[apply] applied policies successfully")
    else:
        print("[apply] server-side dry-run apply OK (no mutation)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
