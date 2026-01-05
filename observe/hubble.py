# observe/hubble.py
import grpc
import time
from google.protobuf.json_format import MessageToDict
import os

from observer import observer_pb2, observer_pb2_grpc
from flow import flow_pb2

from roles.observed import record_edge


TARGET_NAMESPACE = os.environ.get("NAMESPACE")


HUBBLE_ADDR = "127.0.0.1:4245"


def _pod_identity(endpoint: dict):
    """
    Return stable identity: namespace/pod
    """
    ns = endpoint.get("namespace")
    pod = endpoint.get("pod_name")
    if not ns or not pod:
        return None
    return f"{ns}/{pod}"


def process_flow(flow: dict) -> None:
    """
    Extract src/dst pod identities and L4 edge.
    Zero cluster mutation. Fully automatic.
    """

    src = flow.get("source", {})
    dst = flow.get("destination", {})

    src_id = _pod_identity(src)
    dst_id = _pod_identity(dst)

    if not src_id or not dst_id:
        return

    # If NAMESPACE is set, only record edges where *both* endpoints are in that namespace.
    # This avoids learning cluster-wide edges and accidentally generating policies for
    # non-target namespaces.
    if TARGET_NAMESPACE:
        try:
            src_ns = src_id.split("/", 1)[0]
            dst_ns = dst_id.split("/", 1)[0]
        except Exception:
            return
        if src_ns != TARGET_NAMESPACE or dst_ns != TARGET_NAMESPACE:
            return

    l4 = flow.get("l4") or {}

    # Hubble dicts vary by version. Prefer generic protocol/port; otherwise inspect TCP/UDP/SCTP.
    proto = l4.get("protocol")
    port = l4.get("port")

    if not (proto and port):
        # Newer schemas often use nested objects per L4 protocol
        for candidate in ("TCP", "UDP", "SCTP"):
            sub = l4.get(candidate)
            if not sub:
                continue
            # Try destination_port first; fallback to source_port
            port = sub.get("destination_port") or sub.get("source_port")
            proto = candidate
            if port:
                break

    if not (proto and port):
        return

    # Optional debug for first few edges
    if os.environ.get("HUBBLE_DEBUG", "0") == "1":
        try:
            print(f"[observer] edge {src_id} -> {dst_id} {proto}/{int(port)}")
        except Exception:
            pass

    record_edge(
        src_id,
        dst_id,
        int(port),
        proto.upper(),
    )


def stream_hubble_flows():
    """
    Version-agnostic Hubble observer stream.
    """
    debug = os.environ.get("HUBBLE_DEBUG", "0") == "1"
    if debug:
        print(f"[observer] connecting to hubble at {HUBBLE_ADDR}")

    backoff = 1.0
    while True:
        try:
            channel = grpc.insecure_channel(HUBBLE_ADDR)
            stub = observer_pb2_grpc.ObserverStub(channel)

            req = observer_pb2.GetFlowsRequest(
                follow=True,
                number=0,
            )

            first = True
            last_log = time.time()
            for resp in stub.GetFlows(req):
                if not resp.flow:
                    continue
                # Convert protobuf message to a Python dict in a version-agnostic way
                try:
                    flow_dict = MessageToDict(resp.flow, preserving_proto_field_name=True)
                except Exception:
                    # Fallback: access fields directly if conversion fails
                    # Note: structure depends on hubble observer version
                    flow_dict = {
                        "source": getattr(resp.flow, "source", None),
                        "destination": getattr(resp.flow, "destination", None),
                        "l4": getattr(resp.flow, "l4", None),
                    }
                if debug and first:
                    print("[observer] first flow received")
                    first = False
                yield flow_dict
                # Periodic heartbeat if no flows for a while
                if debug and time.time() - last_log > 10:
                    print("[observer] hubble stream active")
                    last_log = time.time()
            # If stream ends naturally, reset backoff and reconnect
            backoff = 1.0
        except grpc.RpcError as e:
            if debug:
                print(f"[observer] hubble rpc error: {e}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            if debug:
                print(f"[observer] reconnecting in {backoff:.1f}s")
            continue
