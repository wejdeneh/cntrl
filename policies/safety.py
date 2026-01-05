# controller/policies/safety.py
from typing import Dict, Any


def allow_world_egress(ns: str) -> Dict[str, Any]:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-temp-allow-world-egress",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "safety",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": {},
            "egress": [{"toEntities": ["world"]}],
        },
    }


def allow_host_remote_ingress_egress(ns: str) -> Dict[str, Any]:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-temp-allow-host-remote",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "safety",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": {},
            "egress": [
                {"toEntities": ["host"]},
                {"toEntities": ["remote-node"]},
            ],
            "ingress": [
                {"fromEntities": ["host"]},
                {"fromEntities": ["remote-node"]},
            ],
        },
    }


def generate_safety(ns: str):
    return [
        allow_world_egress(ns),
        allow_host_remote_ingress_egress(ns),
    ]
