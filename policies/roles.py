# policies/roles.py
from __future__ import annotations
from typing import Dict, List, Tuple

Edge = Tuple[str, str, int, str]  # (src_role, dst_role, port, protocol)


def allow(
    ns: str,
    src_role: str,
    dst_role: str,
    port: int,
    protocol: str = "TCP",
    mode: str = "ENFORCE",
) -> Dict:
    """
    Allow src_role -> dst_role on port/protocol by matching role labels.
    This is AUTOMATIC: any pod that gets the role label will match immediately.
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": f"role-{src_role}-to-{dst_role}-{port}-{protocol.lower()}",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "role",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
                "trirematics.io/mode": mode,
                "trirematics.io/src": src_role,
                "trirematics.io/dst": dst_role,
            },
        },
        "spec": {
            # Destination pods are those with dst_role active
            "endpointSelector": {
                "matchLabels": {f"roles.athena.t9s.io/{dst_role}": "active"}
            },
            "ingress": [
                {
                    "fromEndpoints": [
                        {
                            "matchLabels": {
                                f"roles.athena.t9s.io/{src_role}": "active"
                            }
                        }
                    ],
                    "toPorts": [
                        {"ports": [{"port": str(port), "protocol": protocol}]}
                    ],
                }
            ],
        },
    }


def generate_roles_from_edges(ns: str, edges: List[Edge], mode: str) -> List[Dict]:
    """
    Convert an edge list into a list of CiliumNetworkPolicies.
    """
    policies: List[Dict] = []
    for src, dst, port, proto in edges:
        policies.append(allow(ns, src, dst, int(port), proto, mode=mode))
    return policies
