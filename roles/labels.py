# roles/labels.py
def role_from_labels(labels: dict) -> str | None:
    for k, v in labels.items():
        if k.startswith("roles.athena.t9s.io/") and v == "active":
            return k.split("/")[-1]
    return None
