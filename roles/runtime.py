# roles/runtime.py
from roles.frozen import load_frozen
from policies.roles import allow


def desired_role_policies(ns: str, mode: str) -> list[dict]:
    policies = []
    for src, dst, port, proto in load_frozen():
        policies.append(
            allow(
                ns=ns,
                src_role=src,
                dst_role=dst,
                port=port,
                protocol=proto,
                mode=mode,
            )
        )
    return policies
