import json
import logging
from datetime import UTC, datetime, timedelta
from html import escape
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import text

from authlib.oauth2.rfc7636.challenge import compare_s256_code_challenge

from src.core.errors import AegisError
from src.core.security import (
    issue_access_token,
    new_token,
    pkce_s256,
    sha256_hex,
    verify_password,
)
from src.models.schemas import CreateKeyRequest, CreateKeyResponse, TokenResponse
from src.services.identity import scopes_for_role

router = APIRouter()
log = logging.getLogger("aegisforge.iam")

_LOGIN_HTML = """<!doctype html>
<html><body>
<form method="post">
<label>Email <input name="email" type="email" required></label>
<label>Password <input name="password" type="password" required></label>
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
<input type="hidden" name="code_challenge_method" value="{method}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="response_type" value="code">
<button type="submit">Sign in</button>
</form>
</body></html>
"""


def _client_ip(request: Request) -> str | None:
    if request.client is None:
        return None
    host = request.client.host
    if host in {"testclient", "localhost"}:
        return "127.0.0.1"
    return host


@router.get("/oauth/authorize")
async def authorize_form(request: Request) -> HTMLResponse:
    params = request.query_params
    _require_pkce(params.get("code_challenge_method"))
    if params.get("response_type") != "code":
        raise AegisError(400, "INVALID_REQUEST", "response_type must be code")
    html = _LOGIN_HTML.format(
        client_id=escape(params.get("client_id", ""), quote=True),
        redirect_uri=escape(params.get("redirect_uri", ""), quote=True),
        code_challenge=escape(params.get("code_challenge", ""), quote=True),
        method=escape(params.get("code_challenge_method", ""), quote=True),
        state=escape(params.get("state", ""), quote=True),
    )
    return HTMLResponse(html)


@router.post("/oauth/authorize")
async def authorize_submit(request: Request):
    form = await request.form()
    _require_pkce(str(form.get("code_challenge_method") or ""))
    if form.get("response_type") != "code":
        raise AegisError(400, "INVALID_REQUEST", "response_type must be code")
    client_id = str(form.get("client_id") or "")
    redirect_uri = str(form.get("redirect_uri") or "")
    challenge = str(form.get("code_challenge") or "")
    email = str(form.get("email") or "")
    password = str(form.get("password") or "")
    state = str(form.get("state") or "")
    session = request.state.session
    allowed = await session.execute(
        text("SELECT auth_client_redirect_ok(:client_id, :redirect)"),
        {"client_id": client_id, "redirect": redirect_uri},
    )
    if not allowed.scalar():
        raise AegisError(400, "INVALID_REQUEST", "redirect_uri is not registered")
    row = await _unique_user(session, email, password)
    code = new_token()
    scopes = scopes_for_role(row["system_role"])
    await session.execute(
        text(
            """
            SELECT auth_save_code(
                :code_hash, :client_id, :tenant_id, :user_id, :redirect,
                :challenge, 'S256', :scopes, :expires
            )
            """
        ),
        {
            "code_hash": sha256_hex(code),
            "client_id": client_id,
            "tenant_id": row["tenant_id"],
            "user_id": row["id"],
            "redirect": redirect_uri,
            "challenge": challenge,
            "scopes": scopes,
            "expires": datetime.now(UTC) + timedelta(minutes=5),
        },
    )
    query = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)


async def login_with_password(request: Request, email: str, password: str) -> JSONResponse:
    settings = request.app.state.settings
    session = request.state.session
    row = await _unique_user(session, email, password)
    verifier = new_token()
    code = new_token()
    scopes = scopes_for_role(row["system_role"])
    await session.execute(
        text(
            """
            SELECT auth_save_code(
                :code_hash, :client_id, :tenant_id, :user_id, :redirect,
                :challenge, 'S256', :scopes, :expires
            )
            """
        ),
        {
            "code_hash": sha256_hex(code),
            "client_id": settings.oauth_client_id,
            "tenant_id": row["tenant_id"],
            "user_id": row["id"],
            "redirect": settings.oauth_redirect_uri,
            "challenge": pkce_s256(verifier),
            "scopes": scopes,
            "expires": datetime.now(UTC) + timedelta(minutes=5),
        },
    )
    issued = await _authorization_code(
        request,
        {
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": settings.oauth_redirect_uri,
            "client_id": settings.oauth_client_id,
        },
    )
    payload = json.loads(issued.body)
    payload["email"] = email
    payload["role"] = row["system_role"]
    return JSONResponse(payload)


@router.post("/oauth/token", response_model=None)
async def token(request: Request):
    form = await request.form()
    grant = form.get("grant_type")
    if grant == "password":
        raise AegisError(400, "UNSUPPORTED_GRANT", "password grant is not available")
    if grant == "authorization_code":
        return await _authorization_code(request, form)
    if grant == "refresh_token":
        return await _refresh(request, form)
    raise AegisError(400, "UNSUPPORTED_GRANT", "unsupported grant_type")


async def _authorization_code(request: Request, form) -> JSONResponse:
    code = str(form.get("code") or "")
    verifier = str(form.get("code_verifier") or "")
    redirect_uri = str(form.get("redirect_uri") or "")
    client_id = str(form.get("client_id") or "")
    session = request.state.session
    consumed = await session.execute(
        text("SELECT auth_consume_code(:code_hash, :client_id, :redirect, :challenge)"),
        {
            "code_hash": sha256_hex(code),
            "client_id": client_id,
            "redirect": redirect_uri,
            "challenge": pkce_s256(verifier),
        },
    )
    payload = _json(consumed.scalar())
    if payload.get("status") != "ok":
        raise AegisError(400, "INVALID_GRANT", "authorization code rejected")
    if payload["client_id"] != client_id or payload["redirect_uri"] != redirect_uri:
        raise AegisError(400, "INVALID_GRANT", "authorization code rejected")
    if payload["code_challenge_method"] != "S256":
        raise AegisError(400, "INVALID_GRANT", "PKCE method must be S256")
    if not compare_s256_code_challenge(verifier, payload["code_challenge"]):
        raise AegisError(400, "INVALID_GRANT", "PKCE verifier rejected")
    scopes = _string_list(payload["scopes"])
    refresh = new_token()
    expires = datetime.now(UTC) + timedelta(seconds=request.app.state.settings.refresh_ttl_seconds)
    family = await session.execute(
        text(
            """
            SELECT auth_issue_family(
                :tenant_id, :user_id, :token_hash, :expires, :scopes
            )
            """
        ),
        {
            "tenant_id": payload["tenant_id"],
            "user_id": payload["user_id"],
            "token_hash": sha256_hex(refresh),
            "expires": expires,
            "scopes": scopes,
        },
    )
    family_id = str(family.scalar())
    return await _token_response(request, str(payload["user_id"]), str(payload["tenant_id"]), scopes, family_id, refresh)


async def _refresh(request: Request, form) -> JSONResponse:
    presented = str(form.get("refresh_token") or "")
    if not presented:
        raise AegisError(400, "INVALID_GRANT", "refresh token missing")
    replacement = new_token()
    expires = datetime.now(UTC) + timedelta(seconds=request.app.state.settings.refresh_ttl_seconds)
    session = request.state.session
    result = await session.execute(
        text(
            """
            SELECT auth_present_refresh(
                :presented, :new_hash, :expires, CAST(:ip AS inet)
            )
            """
        ),
        {
            "presented": sha256_hex(presented),
            "new_hash": sha256_hex(replacement),
            "expires": expires,
            "ip": _client_ip(request),
        },
    )
    payload = _json(result.scalar())
    status = payload.get("status")
    if status == "replay":
        family_id = str(payload["family_id"])
        user_id = str(payload["user_id"])
        log.critical(
            "REFRESH_TOKEN_REUSE_DETECTED family_id=%s redis_key=af:family:revoked:%s audit=DENY",
            family_id,
            family_id,
        )
        request.state.after_commit.append(
            lambda: request.app.state.revocation.revoke_families(user_id, [family_id], "REFRESH_TOKEN_REUSE_DETECTED")
        )
        raise AegisError(401, "REFRESH_TOKEN_REUSE_DETECTED", "refresh token reuse revoked the family")
    if status != "ok":
        raise AegisError(401, "INVALID_GRANT", "refresh token rejected")
    scopes = _string_list(payload["scopes"])
    return await _token_response(
        request,
        str(payload["user_id"]),
        str(payload["tenant_id"]),
        scopes,
        str(payload["family_id"]),
        replacement,
    )


async def _token_response(
    request: Request,
    user_id: str,
    tenant_id: str,
    scopes: list[str],
    family_id: str,
    refresh: str,
) -> JSONResponse:
    settings = request.app.state.settings
    access, jti = issue_access_token(
        settings.aegis_jwt_secret,
        user_id=user_id,
        tenant_id=tenant_id,
        scopes=scopes,
        family_id=family_id,
        ttl_seconds=settings.access_ttl_seconds,
    )
    request.state.after_commit.append(lambda: request.app.state.revocation.remember_access(user_id, jti))
    body = TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_ttl_seconds,
    )
    return JSONResponse(body.model_dump())


@router.post("/api/v1/keys", response_model=CreateKeyResponse)
async def create_key(request: Request, payload: CreateKeyRequest) -> CreateKeyResponse:
    principal = request.state.principal
    if "keys:write" not in principal.scopes:
        raise AegisError(403, "FORBIDDEN", "keys:write is required")
    if any(scope not in principal.scopes for scope in payload.scopes):
        raise AegisError(403, "FORBIDDEN", "key scopes exceed the caller")
    secret = f"af_{new_token()}"
    prefix = secret[3:11]
    session = request.state.session
    created = await session.execute(
        text(
            """
            INSERT INTO application_keys (tenant_id, user_id, key_hash, key_prefix, allowed_scopes)
            VALUES (CAST(:tenant AS uuid), CAST(:user_id AS uuid), :key_hash, :prefix, :scopes)
            RETURNING id
            """
        ),
        {
            "tenant": principal.tenant_id,
            "user_id": principal.user_id,
            "key_hash": sha256_hex(secret),
            "prefix": prefix,
            "scopes": payload.scopes,
        },
    )
    return CreateKeyResponse(
        id=str(created.scalar()),
        key_prefix=prefix,
        secret=secret,
        allowed_scopes=payload.scopes,
    )


@router.get("/api/v1/me")
async def me(request: Request) -> dict:
    principal = request.state.principal
    return {
        "user_id": principal.user_id,
        "tenant_id": principal.tenant_id,
        "scopes": principal.scopes,
    }


async def _unique_user(session, email: str, password: str):
    found = await session.execute(
        text("SELECT * FROM auth_find_user_by_email(:email)"),
        {"email": email},
    )
    rows = found.mappings().all()
    if len(rows) != 1:
        raise AegisError(401, "UNAUTHORIZED", "login rejected")
    row = rows[0]
    if not row["is_active"] or not row["password_hash"]:
        raise AegisError(401, "UNAUTHORIZED", "login rejected")
    if not verify_password(row["password_hash"], password):
        raise AegisError(401, "UNAUTHORIZED", "login rejected")
    return row


def _require_pkce(method: str | None) -> None:
    if method != "S256":
        raise AegisError(400, "INVALID_REQUEST", "code_challenge_method must be S256")


def _json(value) -> dict:
    if value is None:
        return {}
    if isinstance(value, str):
        return json.loads(value)
    return dict(value)


def _string_list(value) -> list[str]:
    if isinstance(value, str):
        value = json.loads(value)
    return [str(item) for item in value]
