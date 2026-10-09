import base64
import hashlib
import logging
from urllib.parse import parse_qs, urlparse

import asyncpg
import pytest

from src.core.security import pkce_s256
from src.services.migrate import asyncpg_dsn

REDIRECT = "http://127.0.0.1:8765/callback"
VERIFIER = "a" * 64


async def _login(client, email: str, password: str) -> dict:
    challenge = pkce_s256(VERIFIER)
    response = await client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "aegis-demo",
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
            "email": email,
            "password": password,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": "aegis-demo",
            "code_verifier": VERIFIER,
        },
    )
    assert token.status_code == 200, token.text
    return token.json()


@pytest.mark.integration
async def test_refresh_reuse_revokes_family(client, settings, caplog) -> None:
    caplog.set_level(logging.CRITICAL, logger="aegisforge.iam")
    first = await _login(client, "dev@demo.aegisforge.local", "developer-password")
    rotated = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
    )
    assert rotated.status_code == 200, rotated.text
    new_tokens = rotated.json()
    replay = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
    )
    assert replay.status_code == 401
    assert replay.json()["code"] == "REFRESH_TOKEN_REUSE_DETECTED"
    assert "REFRESH_TOKEN_REUSE_DETECTED" in caplog.text
    assert "af:family:revoked:" in caplog.text
    me = await client.get("/api/v1/me", headers={"Authorization": f"Bearer {new_tokens['access_token']}"})
    assert me.status_code == 401

    connection = await asyncpg.connect(asyncpg_dsn(settings.migrator_database_url))
    try:
        reason = await connection.fetchval(
            """
            SELECT rejection_reason_code FROM system_audit_ledger
            WHERE rejection_reason_code = 'REFRESH_TOKEN_REUSE_DETECTED'
            ORDER BY id DESC LIMIT 1
            """
        )
    finally:
        await connection.close()
    assert reason == "REFRESH_TOKEN_REUSE_DETECTED"


@pytest.mark.integration
async def test_password_grant_is_rejected(client) -> None:
    response = await client.post("/oauth/token", data={"grant_type": "password", "username": "a", "password": "b"})
    assert response.status_code == 400


@pytest.mark.integration
async def test_pkce_plain_is_rejected(client) -> None:
    response = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "aegis-demo",
            "redirect_uri": REDIRECT,
            "code_challenge": "abc",
            "code_challenge_method": "plain",
        },
    )
    assert response.status_code == 400


@pytest.mark.integration
async def test_wrong_pkce_verifier_does_not_burn_the_code(client) -> None:
    verifier = "b" * 64
    challenge = pkce_s256(verifier)
    started = await client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "aegis-demo",
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": 'ok"onclick',
            "email": "dev@demo.aegisforge.local",
            "password": "developer-password",
        },
        follow_redirects=False,
    )
    assert started.status_code == 302, started.text
    code = parse_qs(urlparse(started.headers["location"]).query)["code"][0]
    rejected = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": "aegis-demo",
            "code_verifier": "c" * 64,
        },
    )
    assert rejected.status_code == 400
    accepted = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": "aegis-demo",
            "code_verifier": verifier,
        },
    )
    assert accepted.status_code == 200, accepted.text


@pytest.mark.integration
async def test_authorize_page_escapes_state(client) -> None:
    page = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "aegis-demo",
            "redirect_uri": REDIRECT,
            "code_challenge": "abc",
            "code_challenge_method": "S256",
            "state": '"><script>',
        },
    )
    assert page.status_code == 200
    assert "<script>" not in page.text
    assert "&lt;script&gt;" in page.text or "&#34;&gt;&lt;script&gt;" in page.text or "&quot;&gt;&lt;script&gt;" in page.text


def test_pkce_helper_matches_s256() -> None:
    digest = hashlib.sha256(b"verifier").digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert pkce_s256("verifier") == expected
