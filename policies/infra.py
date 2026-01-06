# controller/policies/infra.py
from __future__ import annotations
from typing import Dict, Any, List


# Select ONLY athena base-operator controller-manager pods (matches your real labels)
OPERATOR_SELECTOR: Dict[str, Any] = {
    "matchLabels": {
        "control-plane": "controller-manager",
        "operation-plane.t9s.io/level": "base-operator",
    }
}

# Select "controller-manager" pods in THIS namespace (covers odin-controller-manager too)
CONTROLLER_MANAGER_SELECTOR: Dict[str, Any] = {
    "matchExpressions": [
        {
            "key": "control-plane",
            "operator": "In",
            "values": ["controller-manager"],
        }
    ]
}

# Select operators-plane pods (the ones OLM talks to).
# In this cluster, these pods are created/managed by OLM and labeled by catalogSource.
OPERATORS_PLANE_SELECTOR: Dict[str, Any] = {
    "matchExpressions": [
        {"key": "olm.managed", "operator": "In", "values": ["true"]},
        {
            "key": "olm.catalogSource",
            "operator": "In",
            "values": ["athena-operators-plane", "odin-operators-plane"],
        },
    ]
}


def dns_policy(ns: str) -> Dict[str, Any]:
    """
    Allow DNS from all pods.
    Using toEndpoints with kube-system label is the safest "works everywhere" pattern.
    (Avoid toEntities: ["cluster"] here: it is too broad and may not match DNS reliably.)
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-dns-egress",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "dns",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": {},
            "egress": [
                {
                    "toEndpoints": [
                        {
                            "matchLabels": {
                                "k8s:io.kubernetes.pod.namespace": "kube-system",
                                # Works for CoreDNS in most clusters; if your cluster uses kube-dns,
                                # this still works because CoreDNS pods still live in kube-system.
                            }
                        }
                    ],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "53", "protocol": "UDP"},
                                {"port": "53", "protocol": "TCP"},
                            ]
                        }
                    ],
                }
            ],
        },
    }


def kubeapi_policy(ns: str) -> Dict[str, Any]:
    """Allow pods to reach kube-apiserver."""
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-kubeapi-egress",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "kubeapi",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": {},
            "egress": [
                {
                    "toEntities": ["kube-apiserver"],
                    "toPorts": [{"ports": [{"port": "6443", "protocol": "TCP"}]}],
                }
            ],
        },
    }


def operator_webhook_ingress(ns: str) -> Dict[str, Any]:
    """
    kube-apiserver must reach validating webhook service backing pods.
    Allow 443 and 8443 (operators often use 8443 for webhook/metrics).
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-operator-webhook",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "webhook",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": OPERATOR_SELECTOR,
            "ingress": [
                {
                    "fromEntities": ["kube-apiserver"],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "443", "protocol": "TCP"},
                                {"port": "8443", "protocol": "TCP"},
                            ]
                        }
                    ],
                },
                # Fallback for some setups where source is seen as host/remote-node
                {
                    "fromEntities": ["host", "remote-node"],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "443", "protocol": "TCP"},
                                {"port": "8443", "protocol": "TCP"},
                            ]
                        }
                    ],
                },
            ],
        },
    }


def controller_metrics_ingress(ns: str) -> Dict[str, Any]:
    """
    Prometheus scrapes controller-manager pods on 8443.
    Matching by namespace is more reliable than matching by a specific Prometheus label.
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-controller-metrics",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "metrics",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            # any controller-manager pod in THIS namespace (athena-base-operator, odin-controller-manager, ...)
            "endpointSelector": {
                "matchExpressions": [
                    {"key": "control-plane", "operator": "In", "values": ["controller-manager"]}
                ]
            },
            "ingress": [
                {
                    # allow anything from the tobs namespace (where your Prometheus runs)
                    "fromEndpoints": [
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "tobs"}}
                    ],
                    "toPorts": [
                        {"ports": [{"port": "8443", "protocol": "TCP"}]}
                    ],
                }
            ],
        },
    }

def operator_ntp_egress(ns: str) -> Dict[str, Any]:
    """Allow operator to reach NTP (UDP/123) on the internet to avoid webhook timeouts due to time sync checks."""
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-operator-ntp",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "ntp",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": OPERATOR_SELECTOR,
            "egress": [
                {
                    "toEntities": ["world"],
                    "toPorts": [{"ports": [{"port": "123", "protocol": "UDP"}]}],
                }
            ],
        },
    }


def operator_db_policy(ns: str) -> Dict[str, Any]:
    """Allow operator -> mdb:3306."""
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-operator-db-3306",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "operator-db",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": OPERATOR_SELECTOR,
            "egress": [
                {
                    "toEndpoints": [{"matchLabels": {"roles.athena.t9s.io/mdb": "active"}}],
                    "toPorts": [{"ports": [{"port": "3306", "protocol": "TCP"}]}],
                }
            ],
        },
    }


def operator_grpc_5553_ingress_policy(ns: str) -> Dict[str, Any]:
    """
    Allow workloads that need to talk to operator on 5553.
    Expand to include upf/spgwu + python-xapp-mon (based on your observed drops).
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-operator-grpc-5553",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "operator-grpc",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": OPERATOR_SELECTOR,
            "ingress": [
                {
                    "fromEndpoints": [
                        {"matchLabels": {"roles.athena.t9s.io/gnb": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/amf": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/smf": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/spgwu": "active"}},  # UPF/spgwu
                        {"matchLabels": {"app": "python-xapp-mon"}},              # python xApp monitor
                    ],
                    "toPorts": [{"ports": [{"port": "5553", "protocol": "TCP"}]}],
                }
            ],
        },
    }


def operator_dns_5553_udp_ingress_policy(ns: str) -> Dict[str, Any]:
    """Allow workloads to reach operator on UDP/5553.

    We verified from the live pod spec that `athena-base-operator` declares
    `port=5553 proto=UDP name=dns`, and frozen edges show multiple flows
    between operator and other roles on UDP/5553.

    This keeps the allow narrow (only to operator pods, only UDP/5553)
    while we continue tightening other traffic.
    """

    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-operator-udp-5553",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "operator-udp-5553",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": OPERATOR_SELECTOR,
            "ingress": [
                {
                    "fromEndpoints": [
                        {"matchLabels": {"roles.athena.t9s.io/gnb": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/amf": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/smf": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/upf": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/nr-rfsim": "active"}},
                        {"matchLabels": {"roles.athena.t9s.io/monitoring": "active"}},
                        # Fallback: allow any pod in the same namespace to reach operator UDP/5553.
                        # This handles unlabeled pods during rollout without widening to external namespaces.
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "trirematics"}},
                    ],
                    "toPorts": [{"ports": [{"port": "5553", "protocol": "UDP"}]}],
                }
            ],
        },
    }


def olm_grpc_ingress(ns: str) -> Dict[str, Any]:
    """
    Allow OLM internal gRPC (packageserver/catalog-operator) -> operators-plane on 50051.
    This fixes the drops you saw on 50051.
    """
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-olm-grpc-50051",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "olm",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": OPERATORS_PLANE_SELECTOR,
            "ingress": [
                {
                    "fromEndpoints": [
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "olm", "app": "packageserver"}},
                        {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "olm", "app": "catalog-operator"}},
                    ],
                    "toPorts": [{"ports": [{"port": "50051", "protocol": "TCP"}]}],
                }
            ],
        },
    }
def operator_olm_grpc_50051_ingress(ns: str) -> Dict[str, Any]:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "infra-allow-operator-from-olm-50051",
            "namespace": ns,
            "labels": {
                "trirematics.io/type": "infra",
                "trirematics.io/infra": "olm-grpc",
                "trirematics.io/managed": "true",
                "trirematics.io/managed-by": "controller",
            },
        },
        "spec": {
            "endpointSelector": OPERATOR_SELECTOR,
            "ingress": [
                {
                    "fromEndpoints": [
                        {
                            "matchLabels": {
                                "k8s:io.kubernetes.pod.namespace": "olm"
                            }
                        }
                    ],
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "50051", "protocol": "TCP"}
                            ]
                        }
                    ],
                }
            ],
        },
    }


def generate_infra(ns: str) -> List[Dict[str, Any]]:
    return [
        dns_policy(ns),
        kubeapi_policy(ns),
        operator_db_policy(ns),
        operator_webhook_ingress(ns),
        controller_metrics_ingress(ns),
        olm_grpc_ingress(ns),
        operator_grpc_5553_ingress_policy(ns),
        operator_dns_5553_udp_ingress_policy(ns),
        operator_ntp_egress(ns),
        operator_olm_grpc_50051_ingress(ns),
    ]
