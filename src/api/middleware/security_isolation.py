import uuid

from sqlalchemy import text
from starlette.responses import JSONResponse

from src.core.errors import AegisError
from src.core.security import decode_access_token, sha256_hex
from src.services.identity import Principal
from src.services.telemetry import tracer

_PUBLIC_PREFIXES = ("/oauth/", "/docs", "/redoc")
_PUBLIC_EXACT = {"/", "/health", "/metrics", "/openapi.json", "/ui/api/login"}


def install_security(app) -> None:
    @app.middleware("http")
    async def isolate(request, call_next):
        request.state.after_commit = []
        path = request.url.path
        if path in {"/health", "/metrics"}:
            return await call_next(request)
        factory = request.app.state.session_factory
        session = factory()
        request.state.session = session
        await session.begin()
        try:
            if not _is_public(path):
                with tracer().start_as_current_span("iam.token_verify"):
                    await _authenticate(request, session)
        except AegisError as exc:
            await session.rollback()
            await session.close()
            return _error(request, exc)
        try:
            response = await call_next(request)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
        for hook in request.state.after_commit:
            await hook()
        return response

    @app.exception_handler(AegisError)
    async def on_aegis(request, exc: AegisError):
        return _error(request, exc)


def _error(request, exc: AegisError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status,
        content={
            "code": exc.code,
            "message": exc.message,
            "trace_id": getattr(request.state, "trace_id", ""),
        },
    )


def _is_public(path: str) -> bool:
    if path in _PUBLIC_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES)


async def _authenticate(request, session) -> None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise AegisError(401, "UNAUTHORIZED", "bearer token required")
    token = header.split(" ", 1)[1].strip()
    settings = request.app.state.settings
    if request.url.path.startswith("/scim/"):
        found = await session.execute(
            text("SELECT auth_resolve_scim(:token_hash)"),
            {"token_hash": sha256_hex(token)},
        )
        tenant_id = found.scalar()
        if tenant_id is None:
            raise AegisError(401, "UNAUTHORIZED", "SCIM token rejected")
        await _set_tenant(session, str(tenant_id))
        request.state.principal = Principal("scim", str(tenant_id), [], "scim", "scim", "scim")
        return
    try:
        claims = decode_access_token(settings.aegis_jwt_secret, token)
    except AegisError:
        claims = None
    if claims is not None:
        if await request.app.state.revocation.is_revoked(claims["jti"], claims["family_id"]):
            raise AegisError(401, "UNAUTHORIZED", "token revoked")
        await _set_tenant(session, claims["tenant_id"])
        await _require_live_user(session, claims["sub"], claims["family_id"])
        request.state.principal = Principal(
            claims["sub"],
            claims["tenant_id"],
            list(claims["scope"]),
            claims["jti"],
            claims["family_id"],
            "jwt",
        )
        return
    found = await session.execute(
        text("SELECT * FROM auth_resolve_api_key(:token_hash)"),
        {"token_hash": sha256_hex(token)},
    )
    row = found.mappings().first()
    if row is None:
        raise AegisError(401, "UNAUTHORIZED", "credential rejected")
    await _set_tenant(session, str(row["tenant_id"]))
    request.state.principal = Principal(
        str(row["user_id"]),
        str(row["tenant_id"]),
        list(row["allowed_scopes"]),
        str(row["id"]),
        "api-key",
        "api_key",
    )


async def _require_live_user(session, user_id: str, family_id: str) -> None:
    found = await session.execute(
        text(
            """
            SELECT u.is_active AS is_active, f.revoked_at AS revoked_at
            FROM users u
            JOIN refresh_token_families f ON f.user_id = u.id AND f.id = CAST(:family AS uuid)
            WHERE u.id = CAST(:user_id AS uuid)
            """
        ),
        {"user_id": user_id, "family": family_id},
    )
    row = found.mappings().first()
    if row is None or not row["is_active"] or row["revoked_at"] is not None:
        raise AegisError(401, "UNAUTHORIZED", "token revoked")


async def _set_tenant(session, tenant_id: str) -> None:
    try:
        uuid.UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise AegisError(401, "UNAUTHORIZED", "identity rejected") from exc
    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant, true)"),
        {"tenant": tenant_id},
    )
