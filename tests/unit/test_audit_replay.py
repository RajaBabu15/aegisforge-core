import pytest


@pytest.mark.integration
async def test_audit_returns_200_after_replay(client) -> None:
    developer = await client.post(
        "/ui/api/login",
        json={"email": "dev@demo.aegisforge.local", "password": "developer-password"},
    )
    assert developer.status_code == 200, developer.text
    admin = await client.post(
        "/ui/api/login",
        json={"email": "admin@demo.aegisforge.local", "password": "admin-password"},
    )
    assert admin.status_code == 200, admin.text
    used = developer.json()["refresh_token"]
    rotated = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": used},
    )
    assert rotated.status_code == 200, rotated.text
    replay = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": used},
    )
    assert replay.status_code == 401
    assert replay.json()["code"] == "REFRESH_TOKEN_REUSE_DETECTED"
    audit = await client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {admin.json()['access_token']}"},
    )
    assert audit.status_code == 200, audit.text
    body = audit.json()
    assert "events" in body
    assert isinstance(body["events"], list)
