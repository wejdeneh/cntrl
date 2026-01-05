# k8s.py (conceptual)
FINALIZER = "trirematics.io/network-cleanup"

def ensure_finalizer(corev1, ns_name: str) -> None:
    ns = corev1.read_namespace(ns_name).to_dict()
    fins = ns.get("spec", {}).get("finalizers") or ns.get("metadata", {}).get("finalizers") or []
    if FINALIZER not in fins:
        fins.append(FINALIZER)
        patch = {"metadata": {"finalizers": fins}}
        corev1.patch_namespace(ns_name, patch)

def remove_finalizer(corev1, ns_name: str) -> None:
    ns = corev1.read_namespace(ns_name).to_dict()
    fins = ns.get("metadata", {}).get("finalizers") or []
    if FINALIZER in fins:
        fins = [f for f in fins if f != FINALIZER]
        corev1.patch_namespace(ns_name, {"metadata": {"finalizers": fins}})
