from __future__ import annotations

from role_controller import derive_role_edges_from_cluster_state


def _pod(ns: str, name: str, labels: dict, pod_ip: str = "10.0.0.1", container_ports=None):
    container_ports = container_ports or []
    return {
        "metadata": {"namespace": ns, "name": name, "labels": labels},
        "status": {"podIP": pod_ip},
        "spec": {
            "containers": [
                {
                    "name": "c",
                    "ports": [
                        {"containerPort": p, "protocol": proto}
                        for (proto, p) in container_ports
                    ],
                }
            ]
        },
    }


def _svc(ns: str, name: str, selector: dict, ports):
    return {
        "metadata": {"namespace": ns, "name": name},
        "spec": {
            "selector": selector,
            "ports": [{"port": p, "protocol": proto} for (proto, p) in ports],
        },
    }


def _eps(ns: str, name: str, ips):
    return {
        "metadata": {"namespace": ns, "name": name},
        "subsets": [{"addresses": [{"ip": ip} for ip in ips]}],
    }


def test_derive_ports_prefers_service_ports_for_role() -> None:
    ns = "trirematics"
    pods = [
        _pod(
            ns,
            "amf-0",
            {"roles.athena.t9s.io/amf": "active", "app": "amf"},
            pod_ip="10.0.0.10",
            container_ports=[("TCP", 9999)],
        )
    ]
    svcs = [
        _svc(ns, "amf-svc", selector={"app": "amf"}, ports=[("TCP", 80)]),
    ]
    eps = [_eps(ns, "amf-svc", ips=["10.0.0.10"])]

    derived = derive_role_edges_from_cluster_state(ns, pods, svcs, eps)
    # We represent derived stable ports as ('*', dst_role, port, proto)
    assert ("*", "amf", 80, "TCP") in derived


def test_derive_ports_falls_back_to_container_ports_when_no_service() -> None:
    ns = "trirematics"
    pods = [
        _pod(
            ns,
            "operators-plane-0",
            {"roles.athena.t9s.io/operator": "active"},
            pod_ip="10.0.0.20",
            container_ports=[("TCP", 50051)],
        )
    ]

    derived = derive_role_edges_from_cluster_state(ns, pods, services=None, endpoints=None)
    assert ("*", "operator", 50051, "TCP") in derived
