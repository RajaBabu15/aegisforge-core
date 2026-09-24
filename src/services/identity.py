from dataclasses import dataclass

ROLE_SCOPES: dict[str, list[str]] = {
    "org_admin": [
        "agents:approve",
        "tickets:write",
        "billing:read",
        "retrieval:read",
        "keys:write",
    ],
    "workspace_developer": [
        "tickets:write",
        "billing:read",
        "retrieval:read",
        "keys:write",
    ],
    "viewer": ["billing:read", "retrieval:read"],
}


@dataclass
class Principal:
    user_id: str
    tenant_id: str
    scopes: list[str]
    jti: str
    family_id: str
    kind: str


def scopes_for_role(role: str) -> list[str]:
    return list(ROLE_SCOPES[role])
