import pytest

from tests.unit.test_token_rotation import _login


@pytest.mark.integration
async def test_console_page_and_buttons(client) -> None:
    page = await client.get("/")
    assert page.status_code == 200
    assert "Run replay check" in page.text
    assert "awaiting_human_approval" in page.text

    developer = await client.post(
        "/ui/api/login",
        json={"email": "dev@demo.aegisforge.local", "password": "developer-password"},
    )
    assert developer.status_code == 200, developer.text
    dev = developer.json()
    admin = (
        await client.post(
            "/ui/api/login",
            json={"email": "admin@demo.aegisforge.local", "password": "admin-password"},
        )
    ).json()

    rotated = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": dev["refresh_token"]},
    )
    assert rotated.status_code == 200, rotated.text
    replay = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": dev["refresh_token"]},
    )
    assert replay.status_code == 401
    assert replay.json()["code"] == "REFRESH_TOKEN_REUSE_DETECTED"

    fresh = await _login(client, "dev@demo.aegisforge.local", "developer-password")
    started = await client.post(
        "/api/v1/agents/jobs",
        headers={"Authorization": f"Bearer {fresh['access_token']}"},
        json={"task": "file a high-priority tracking ticket"},
    )
    assert started.status_code == 200, started.text
    assert started.json()["status"] == "awaiting_human_approval"
    decided = await client.post(
        f"/ui/api/jobs/{started.json()['id']}/decision",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"decision": "APPROVED"},
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["phase"] == "RESPOND"

    loaded = await client.post(
        "/api/v1/retrieval/documents",
        headers={"Authorization": f"Bearer {fresh['access_token']}"},
        json={"title": "Runbook", "content": "Fault AF9001 clears only when the operator runs RESET-9001.", "page": 1, "line_start": 1, "line_end": 1},
    )
    assert loaded.status_code == 200, loaded.text
    found = await client.post(
        "/api/v1/retrieval/query",
        headers={"Authorization": f"Bearer {fresh['access_token']}"},
        json={"query": "AF9001"},
    )
    assert found.status_code == 200, found.text
    assert "RESET-9001" in found.text

    refused = await client.post(
        "/api/v1/retrieval/query",
        headers={"Authorization": f"Bearer {fresh['access_token']}"},
        json={"query": "NOMATCH99999"},
    )
    assert refused.status_code == 422
    assert refused.json()["code"] == "INSUFFICIENT_EVIDENCE"
