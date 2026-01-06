#!/usr/bin/env python3
"""tools/test_policies.py

End-to-end *safe* testing of generated CiliumNetworkPolicies.

What it does:
  1) Generates desired policies using the same config as the controller.
  2) Runs the APPLY safety gate against live pods in the namespace.
  3) Optionally performs server-side dry-run apply of the policies
     (validates schema/admission without mutating the cluster).

This is meant to be an automated confidence check before switching the
controller to APPLY.

Env vars understood (same as controller):
  - NAMESPACE
  - CONTROLLER_MODE=ENFORCE|BOOTSTRAP
  - CONTROLLER_MANAGE_INFRA=1
  - CONTROLLER_ENABLE_SAFETY=1
  - CONTROLLER_DERIVE_PORTS=1

Testing flags:
  - DRY_RUN_APPLY=1 (default) -> kubectl apply --dry-run=server
  - DRY_RUN_APPLY=0 -> skip kubectl apply validation

Note: This never applies policies for real.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import yaml

# Allow executing from out/controller/tools without installing as a package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from kubernetes import client, config

from config import desired_policies
from gate import validate_apply_gate


def _load_kube() -> None:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


def _kubectl_apply_server_dry_run(yaml_path: str, namespace: str) -> tuple[int, str]:
    # Server-side dry run validates admission and CRD schema without persisting.
    p = subprocess.run(
        [
            "kubectl",
            "apply",
            "-n",
            namespace,
            "--dry-run=server",
            "-f",
            yaml_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return p.returncode, p.stdout


def _run(cmd: list[str], timeout_s: int = 60) -> tuple[int, str]:
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_s,
    )
    return p.returncode, p.stdout


def _smoke_pod_name(namespace: str) -> str:
    # stable name so we can delete/recreate safely
    return f"policy-smoke-{namespace}".lower().replace("_", "-")


def run_smoke_checks(namespace: str) -> int:
    """Run simple dataplane checks from inside the namespace.

    This creates an ephemeral Pod, runs a few commands, then deletes it.
    It does not modify policies.
    """
    name = _smoke_pod_name(namespace)

    print(f"[smoke] creating/refreshing pod {name} in ns={namespace}")
    # Ensure no leftovers
    _run(["kubectl", "-n", namespace, "delete", "pod", name, "--ignore-not-found=true"], timeout_s=30)

    # Use a small image that has nslookup + nc; busybox lacks nc in some builds.
    # nicolaka/netshoot is convenient but bigger; keep timeouts small.
    rc, out = _run(
        [
            "kubectl",
            "-n",
            namespace,
            "run",
            name,
            "--image=nicolaka/netshoot:latest",
            "--restart=Never",
            "--command",
            "--",
            "sleep",
            "300",
        ],
        timeout_s=60,
    )
    print(out.rstrip())
    if rc != 0:
        print("[smoke] FAILED to create smoke pod")
        return 10

    # Wait for Ready
    rc, out = _run(
        [
            "kubectl",
            "-n",
            namespace,
            "wait",
            "--for=condition=Ready",
            f"pod/{name}",
            "--timeout=60s",
        ],
        timeout_s=80,
    )
    print(out.rstrip())
    if rc != 0:
        print("[smoke] pod did not become Ready")
        _run(["kubectl", "-n", namespace, "describe", "pod", name], timeout_s=30)
        _run(["kubectl", "-n", namespace, "delete", "pod", name, "--wait=false"], timeout_s=30)
        return 11

    failures: list[str] = []

    def _exec(args: list[str], label: str, timeout_s: int = 30) -> None:
        nonlocal failures
        cmd = ["kubectl", "-n", namespace, "exec", name, "--"] + args
        rc, out = _run(cmd, timeout_s=timeout_s)
        print(f"[smoke] {label} rc={rc}")
        if out.strip():
            print(out.rstrip())
        if rc != 0:
            failures.append(label)

    # DNS (cluster.local). Use kubernetes.default which should always exist.
    _exec(["nslookup", "kubernetes.default.svc.cluster.local"], "dns:kubernetes.default", timeout_s=20)

    # TCP to kube-apiserver via internal service DNS.
    _exec(["sh", "-lc", "nc -zvw2 kubernetes.default.svc 443"], "tcp:kubeapi:443", timeout_s=20)

    # Basic in-namespace Service check: operators-plane service may not exist, so probe coredns service.
    _exec(["sh", "-lc", "nc -zvw2 kube-dns.kube-system.svc.cluster.local 53"], "tcp:dns:53", timeout_s=20)

    # Cleanup
    _run(["kubectl", "-n", namespace, "delete", "pod", name, "--wait=false"], timeout_s=30)

    if failures:
        print("[smoke] FAILURES: " + ", ".join(failures))
        return 20

    print("[smoke] all checks OK")
    return 0


def main() -> int:
    namespace = os.environ.get("NAMESPACE", "trirematics")
    controller_mode = os.environ.get("CONTROLLER_MODE", "ENFORCE")
    manage_infra = os.environ.get("CONTROLLER_MANAGE_INFRA", "0")
    enable_safety = os.environ.get("CONTROLLER_ENABLE_SAFETY", "0")
    derive_ports = os.environ.get("CONTROLLER_DERIVE_PORTS", "1")

    print(
        "[test] config: "
        f"NAMESPACE={namespace} CONTROLLER_MODE={controller_mode} "
        f"CONTROLLER_MANAGE_INFRA={manage_infra} CONTROLLER_ENABLE_SAFETY={enable_safety} "
        f"CONTROLLER_DERIVE_PORTS={derive_ports}"
    )

    _load_kube()
    corev1 = client.CoreV1Api()

    pods = [p.to_dict() for p in corev1.list_namespaced_pod(namespace).items]

    desired = desired_policies(namespace, controller_mode)

    gate = validate_apply_gate(namespace, pods, desired)
    for w in gate.warnings:
        print(f"[test] gate warning: {w}")
    if not gate.ok:
        print("[test] gate FAILED")
        for e in gate.errors:
            print(f"[test] gate error: {e}")

        # Common footgun: running tests without infra enabled.
        if manage_infra != "1":
            print(
                "[test] hint: you likely want CONTROLLER_MANAGE_INFRA=1 for realistic validation "
                "(DNS/kubeapi/operator/OLM ports are infra)."
            )
        return 2

    print(f"[test] gate OK. desired policies: {len(desired)}")

    dry_run_apply = os.environ.get("DRY_RUN_APPLY", "1") == "1"
    if not dry_run_apply:
        print("[test] DRY_RUN_APPLY=0 -> skipping kubectl dry-run apply")
        # still allow smoke tests
        if os.environ.get("SMOKE", "0") == "1":
            return run_smoke_checks(namespace)
        return 0

    # Dump multi-doc YAML
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        for pol in desired:
            yaml.safe_dump(pol, f, sort_keys=False)
            f.write("---\n")
        path = f.name

    rc, out = _kubectl_apply_server_dry_run(path, namespace)
    print(out.rstrip())
    if rc != 0:
        print("[test] kubectl server-side dry-run apply FAILED")
        return 3

    print("[test] kubectl server-side dry-run apply OK")

    if os.environ.get("SMOKE", "0") == "1":
        return run_smoke_checks(namespace)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
