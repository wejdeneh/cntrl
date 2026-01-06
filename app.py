# app.py
from __future__ import annotations

import os
import time
import threading
from kubernetes import client, config

from mode import compute_mode
from config import desired_policies
from reconcile import reconcile
from k8s import ensure_finalizer, remove_finalizer
from gate import validate_apply_gate

#  OBSERVATION
from observe.runtime import run_observer_loop

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
NAMESPACE = os.environ.get("NAMESPACE", "trirematics")
LOOP_SECONDS = int(os.environ.get("LOOP_SECONDS", "5"))


# ─────────────────────────────────────────────
# Cilium API wrapper
# ─────────────────────────────────────────────
class CiliumClient:
    def __init__(self):
        self.api = client.CustomObjectsApi()

    @staticmethod
    def _sanitize_name(name: str) -> str:
        # RFC1123: lower-case alphanumerics, '-' or '.', start/end alphanumeric
        import re
        n = name.lower()
        # replace invalid chars with '-'
        n = re.sub(r"[^a-z0-9-.]", "-", n)
        # collapse multiple separators
        n = re.sub(r"[-.]{2,}", "-", n)
        # trim leading/trailing non-alphanumeric
        n = re.sub(r"^[^a-z0-9]+", "", n)
        n = re.sub(r"[^a-z0-9]+$", "", n)
        # fallback if empty
        return n or "cnp"

    @staticmethod
    def _sanitize_label_value(val: str) -> str:
        # Labels: alphanumerics, '-', '_', '.', start/end alphanumeric
        import re, hashlib
        v = str(val)
        v = re.sub(r"[^A-Za-z0-9-_.]", "-", v)
        v = re.sub(r"[-_.]{2,}", "-", v)
        v = re.sub(r"^[^A-Za-z0-9]+", "", v)
        v = re.sub(r"[^A-Za-z0-9]+$", "", v)
        if not v:
            return "value"
        # Enforce max length 63: if longer, truncate and add 6-char hash suffix
        if len(v) > 63:
            h = hashlib.sha1(v.encode()).hexdigest()[:6]
            # leave room for '-' and hash
            v = v[:(63 - 7)] + "-" + h
            # ensure ends with alphanumeric
            v = re.sub(r"[^A-Za-z0-9]+$", "", v)
            if not v:
                v = h  # fallback
        return v

    def _sanitize_body(self, body: dict) -> dict:
        b = dict(body)
        meta = dict(b.get("metadata", {}) or {})
        name = meta.get("name")
        if name:
            meta["name"] = self._sanitize_name(name)
        labels = dict(meta.get("labels", {}) or {})
        # sanitize all label values
        for k in list(labels.keys()):
            labels[k] = self._sanitize_label_value(labels[k])
        meta["labels"] = labels
        b["metadata"] = meta
        return b

    def list_cnp(self, namespace: str) -> list[dict]:
        res = self.api.list_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
        )
        return res.get("items", [])

    def create_cnp(self, namespace: str, body: dict) -> None:
        body = self._sanitize_body(body)
        self.api.create_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
            body=body,
        )

    def patch_cnp(self, namespace: str, name: str, body: dict) -> None:
        body = self._sanitize_body(body)
        name = self._sanitize_name(name)
        self.api.patch_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
            name=name,
            body=body,
        )

    def delete_cnp(self, namespace: str, name: str) -> None:
        name = self._sanitize_name(name)
        self.api.delete_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
            name=name,
        )


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def list_pods(corev1, namespace: str) -> list[dict]:
    return [p.to_dict() for p in corev1.list_namespaced_pod(namespace).items]


def read_namespace(corev1, namespace: str) -> dict:
    return corev1.read_namespace(namespace).to_dict()


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main() -> None:
    try:
        config.load_incluster_config()
        print("[controller] using in-cluster config")
    except Exception:
        config.load_kube_config()
        print("[controller] using kubeconfig (local)")

    corev1 = client.CoreV1Api()
    cilium = CiliumClient()

    # 🔹 START OBSERVER THREAD
    stop_event = threading.Event()
    observer_thread = threading.Thread(
        target=run_observer_loop,
        args=(stop_event,),
        daemon=True,
    )
    observer_thread.start()

    last_mode = None

    try:
        while True:
            ns_obj = corev1.read_namespace(NAMESPACE).to_dict()

            if not ns_obj.get("metadata", {}).get("deletionTimestamp"):
                ensure_finalizer(corev1, NAMESPACE)

            pods = [p.to_dict() for p in corev1.list_namespaced_pod(NAMESPACE).items]
            mode = compute_mode(pods, ns_obj)

            # Only reconcile when in APPLY mode; skip during BOOTSTRAP to collect edges safely
            desired = desired_policies(NAMESPACE, mode)
            if mode == "APPLY":
                gate = validate_apply_gate(NAMESPACE, pods, desired)
                if not gate.ok:
                    print("[controller] APPLY gate FAILED; refusing to reconcile to avoid outage")
                    for w in gate.warnings:
                        print(f"[controller] gate warning: {w}")
                    for e in gate.errors:
                        print(f"[controller] gate error:   {e}")
                else:
                    for w in gate.warnings:
                        print(f"[controller] gate warning: {w}")
                    reconcile(cilium, NAMESPACE, desired)
            else:
                if os.environ.get("HUBBLE_DEBUG", "0") == "1":
                    print("[controller] skip reconcile (mode!=APPLY)")

            if ns_obj.get("metadata", {}).get("deletionTimestamp"):
                remove_finalizer(corev1, NAMESPACE)

            if mode != last_mode:
                print(f"[controller] mode={mode}")
                last_mode = mode

            time.sleep(LOOP_SECONDS)

    except KeyboardInterrupt:
        print("[controller] shutting down")
        stop_event.set()
        observer_thread.join(timeout=5)


if __name__ == "__main__":
    main()
