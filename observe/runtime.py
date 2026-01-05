# observe/runtime.py
from __future__ import annotations
import threading
import time

from observe.hubble import stream_hubble_flows, process_flow


def run_observer_loop(stop_event: threading.Event) -> None:
    """
    Background loop that listens to Hubble and records role edges.
    """
    print("[observer] starting Hubble observer loop")

    while not stop_event.is_set():
        try:
            for flow in stream_hubble_flows():
                if stop_event.is_set():
                    break
                process_flow(flow)
        except Exception as e:
            print(f"[observer] error: {e}")
            time.sleep(2)

    print("[observer] observer loop stopped")
