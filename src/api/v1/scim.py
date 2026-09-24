import json

from fastapi import APIRouter, Request
from sqlalchemy import text

from src.core.errors import AegisError
from src.core.security import sha256_hex

router = APIRouter(prefix="/scim/v2")

_CORE = "urn:ietf:params:scim:schemas:core:2.0:User"


@router.post("/Users")
async def create_user(request: Request) -> dict:
    body = await _body(request)
    return await _upsert(request, body, user_id=None)


@router.get("/Users/{user_id}")
async def get_user(request: Request, user_id: str) -> dict:
    row = await _load(request, user_id)
    if row is None:
        raise AegisError(404, "NOT_FOUND", "user not found")
    return _resource(row)


@router.put("/Users/{user_id}")
async def replace_user(request: Request, user_id: str) -> dict:
    body = await _body(request)
    return await _upsert(request, body, user_id=user_id)


@router.get("/Users")
async def find_users(request: Request) -> dict:
    filt = request.query_params.get("filter", "")
    prefix = 'userName eq "'
    if not (filt.startswith(prefix) and filt.endswith('"')):
        raise AegisError(400, "INVALID_FILTER", "only userName eq filters are supported")
    email = filt[len(prefix) : -1]
    session = request.state.session
    found = await session.execute(
        text("SELECT id, email, is_active, groups, system_role FROM users WHERE lower(email) = lower(:email)"),
        {"email": email},
    )
    rows = found.mappings().all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(rows),
        "Resources": [_resource(row) for row in rows],
    }


async def _upsert(request: Request, body: dict, user_id: str | None) -> dict:
    schemas = body.get("schemas") or []
    if _CORE not in schemas:
        raise AegisError(400, "INVALID_SCHEMA", "core user schema is required")
    email = body.get("userName")
    if not email:
        raise AegisError(400, "INVALID_REQUEST", "userName is required")
    active = bool(body.get("active", True))
    groups = body.get("groups") or []
    session = request.state.session
    principal = request.state.principal
    if user_id is None:
        inserted = await session.execute(
            text(
                """
                INSERT INTO users (tenant_id, email, system_role, is_active, groups)
                VALUES (CAST(:tenant AS uuid), :email, 'viewer', :active, CAST(:groups AS jsonb))
                RETURNING id, email, is_active, groups, system_role
                """
            ),
            {
                "tenant": principal.tenant_id,
                "email": email,
                "active": active,
                "groups": json.dumps(groups),
            },
        )
        row = inserted.mappings().one()
        user_id = str(row["id"])
    else:
        updated = await session.execute(
            text(
                """
                UPDATE users
                   SET email = :email,
                       is_active = :active,
                       groups = CAST(:groups AS jsonb)
                 WHERE id = CAST(:user_id AS uuid)
                RETURNING id, email, is_active, groups, system_role
                """
            ),
            {
                "email": email,
                "active": active,
                "groups": json.dumps(groups),
                "user_id": user_id,
            },
        )
        row = updated.mappings().first()
        if row is None:
            raise AegisError(404, "NOT_FOUND", "user not found")
    if not active:
        revoked = await session.execute(
            text("SELECT auth_revoke_user(CAST(:user_id AS uuid), 'SCIM_DEACTIVATED', CAST(:ip AS inet))"),
            {"user_id": user_id, "ip": _ip(request)},
        )
        payload = revoked.scalar()
        if isinstance(payload, str):
            payload = json.loads(payload)
        family_ids = [str(item) for item in (payload.get("family_ids") or [])]
        uid = user_id

        async def _mirror() -> None:
            await request.app.state.revocation.revoke_families(uid, family_ids, "SCIM_DEACTIVATED")

        request.state.after_commit.append(_mirror)
    return _resource(row)


async def _load(request: Request, user_id: str):
    session = request.state.session
    found = await session.execute(
        text("SELECT id, email, is_active, groups, system_role FROM users WHERE id = CAST(:user_id AS uuid)"),
        {"user_id": user_id},
    )
    return found.mappings().first()


async def _body(request: Request) -> dict:
    raw = await request.json()
    if not isinstance(raw, dict):
        raise AegisError(400, "INVALID_REQUEST", "JSON object required")
    return raw


def _resource(row) -> dict:
    groups = row["groups"]
    if isinstance(groups, str):
        groups = json.loads(groups)
    return {
        "schemas": [_CORE],
        "id": str(row["id"]),
        "userName": row["email"],
        "active": row["is_active"],
        "groups": groups or [],
    }


def _ip(request: Request) -> str | None:
    if request.client is None or request.client.host in {"testclient", "localhost"}:
        return "127.0.0.1"
    return request.client.host


def scim_hash(token: str) -> str:
    return sha256_hex(token)
