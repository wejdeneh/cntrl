#!/usr/bin/env python3
"""tools/render.py

Render the controller's desired CiliumNetworkPolicies as multi-document YAML.

Why this exists:
- CNPs are generated dynamically by the controller from observed/frozen edges + cluster state.
- Sometimes you want an artifact to review / diff / apply manually.

Usage examples:
  NAMESPACE=trirematics CONTROLLER_MODE=ENFORCE CONTROLLER_MANAGE_INFRA=1 CONTROLLER_ENABLE_SAFETY=1 \
    python3 tools/render.py > /tmp/cnps.yaml

  # Or just print to stdout:
  python3 tools/render.py | head

Notes:
- This does NOT apply anything.
- For safe validation, pair it with: kubectl apply --dry-run=server -f -
"""

from __future__ import annotations

import os
import sys

import yaml

# Allow executing from out/controller/tools without installing as a package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import desired_policies  # noqa: E402


def main() -> int:
    namespace = os.environ.get("NAMESPACE", "trirematics")
    controller_mode = os.environ.get("CONTROLLER_MODE", "ENFORCE")

    desired = desired_policies(namespace, controller_mode)

    # Multi-doc YAML to stdout
  try:
    for pol in desired:
      yaml.safe_dump(pol, sys.stdout, sort_keys=False)
      sys.stdout.write("---\n")
  except BrokenPipeError:
    # Common when piping to `head`; exit cleanly
    return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
