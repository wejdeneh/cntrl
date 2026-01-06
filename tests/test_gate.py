from __future__ import annotations

from gate import validate_apply_gate


def _pod(labels: dict) -> dict:
    return {"metadata": {"labels": labels}}


def test_gate_fails_when_infra_selector_matches_nothing() -> None:
    pods = [_pod({"app": "something"})]
    desired = [
        {
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "infra-test", "namespace": "trirematics", "labels": {"trirematics.io/type": "infra"}},
            "spec": {"endpointSelector": {"matchLabels": {"control-plane": "controller-manager"}}},
        },
        # Ensure required ports appear somewhere so only selector causes failure
        {
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "ports", "namespace": "trirematics"},
            "spec": {
                "egress": [
                    {"toPorts": [{"ports": [{"port": "53", "protocol": "UDP"}, {"port": "53", "protocol": "TCP"}, {"port": "6443", "protocol": "TCP"}]}]},
                    {"toPorts": [{"ports": [{"port": "5553", "protocol": "UDP"}]}]},
                ],
                "ingress": [
                    {"toPorts": [{"ports": [{"port": "50051", "protocol": "TCP"}]}]},
                ],
            },
        },
    ]

    res = validate_apply_gate("trirematics", pods, desired)
    assert res.ok is False
    assert any("matches 0 pods" in e for e in res.errors)


def test_gate_passes_for_minimum_happy_path() -> None:
    pods = [
        _pod({
            "control-plane": "controller-manager",
            "operation-plane.t9s.io/level": "base-operator",
            "roles.athena.t9s.io/amf": "active",
        })
    ]
    desired = [
        {
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "infra-ok", "namespace": "trirematics", "labels": {"trirematics.io/type": "infra"}},
            "spec": {"endpointSelector": {"matchLabels": {"control-plane": "controller-manager"}}},
        },
        {
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "ports", "namespace": "trirematics"},
            "spec": {
                "egress": [
                    {"toPorts": [{"ports": [{"port": "53", "protocol": "UDP"}, {"port": "53", "protocol": "TCP"}, {"port": "6443", "protocol": "TCP"}]}]},
                    {"toPorts": [{"ports": [{"port": "5553", "protocol": "UDP"}]}]},
                ],
                "ingress": [
                    {"toPorts": [{"ports": [{"port": "50051", "protocol": "TCP"}]}]},
                ],
            },
        },
    ]

    res = validate_apply_gate("trirematics", pods, desired)
    assert res.ok is True
