import json
import time

import pytest

from src.core.security import approval_signature
from tests.unit.test_token_rotation import _login


@pytest.mark.integration
async def test_signed_approval_resumes_and_repeat_does_not_file_again(client, app) -> None:
    developer = await _login(client, "dev@demo.aegisforge.local", "developer-password")
    admin = await _login(client, "admin@demo.aegisforge.local", "admin-password")
    created = await client.post(
        "/api/v1/agents/jobs",
        headers={"Authorization": f"Bearer {developer['access_token']}"},
        json={"task": "Analyze workspace log files, find the core connection error, and file a high-priority tracking ticket."},
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["phase"] == "SUSPEND"
    assert body["status"] == "awaiting_human_approval"
    job_id = body["id"]
    raw = json.dumps({"decision": "APPROVED"}).encode()
    stale = str(int(time.time()) - 1000)
    forged = await client.post(
        f"/api/v1/agents/jobs/{job_id}/approve",
        headers={
            "Authorization": f"Bearer {admin['access_token']}",
            "X-Aegis-Timestamp": stale,
            "X-Aegis-Signature": approval_signature(app.state.settings.aegis_approval_secret, stale, job_id, raw),
        },
        content=raw,
    )
    assert forged.status_code == 401
    still = await client.get(
        f"/api/v1/agents/jobs/{job_id}",
        headers={"Authorization": f"Bearer {developer['access_token']}"},
    )
    assert still.json()["phase"] == "SUSPEND"
    stamp = str(int(time.time()))
    approved = await client.post(
        f"/api/v1/agents/jobs/{job_id}/approve",
        headers={
            "Authorization": f"Bearer {admin['access_token']}",
            "X-Aegis-Timestamp": stamp,
            "X-Aegis-Signature": approval_signature(app.state.settings.aegis_approval_secret, stamp, job_id, raw),
        },
        content=raw,
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["phase"] == "RESPOND"
    assert app.state.tools.spy == ["file_ticket"]
    # A distinct timestamp (not just a fresh time.time() call, which can land in the
    # same wall-clock second) so this exercises workflow-level idempotency on a genuinely
    # new admin action, not the approval-replay protection tested separately above.
    stamp = str(int(stamp) + 1)
    repeat = await client.post(
        f"/api/v1/agents/jobs/{job_id}/approve",
        headers={
            "Authorization": f"Bearer {admin['access_token']}",
            "X-Aegis-Timestamp": stamp,
            "X-Aegis-Signature": approval_signature(app.state.settings.aegis_approval_secret, stamp, job_id, raw),
        },
        content=raw,
    )
    assert repeat.status_code == 200
    assert app.state.tools.spy == ["file_ticket"]


@pytest.mark.integration
async def test_replayed_signature_is_rejected(client, app) -> None:
    developer = await _login(client, "dev@demo.aegisforge.local", "developer-password")
    admin = await _login(client, "admin@demo.aegisforge.local", "admin-password")
    created = await client.post(
        "/api/v1/agents/jobs",
        headers={"Authorization": f"Bearer {developer['access_token']}"},
        json={"task": "file a high-priority tracking ticket"},
    )
    job_id = created.json()["id"]
    raw = json.dumps({"decision": "APPROVED"}).encode()
    stamp = str(int(time.time()))
    headers = {
        "Authorization": f"Bearer {admin['access_token']}",
        "X-Aegis-Timestamp": stamp,
        "X-Aegis-Signature": approval_signature(app.state.settings.aegis_approval_secret, stamp, job_id, raw),
    }
    first = await client.post(f"/api/v1/agents/jobs/{job_id}/approve", headers=headers, content=raw)
    assert first.status_code == 200, first.text
    replayed = await client.post(f"/api/v1/agents/jobs/{job_id}/approve", headers=headers, content=raw)
    assert replayed.status_code == 401
    assert replayed.json()["code"] == "APPROVAL_REPLAYED"


@pytest.mark.integration
async def test_signature_for_one_job_is_rejected_against_another(client, app) -> None:
    developer = await _login(client, "dev@demo.aegisforge.local", "developer-password")
    admin = await _login(client, "admin@demo.aegisforge.local", "admin-password")

    async def _start() -> str:
        created = await client.post(
            "/api/v1/agents/jobs",
            headers={"Authorization": f"Bearer {developer['access_token']}"},
            json={"task": "file a high-priority tracking ticket"},
        )
        return created.json()["id"]

    job_a = await _start()
    job_b = await _start()
    raw = json.dumps({"decision": "APPROVED"}).encode()
    stamp = str(int(time.time()))
    signature_for_a = approval_signature(app.state.settings.aegis_approval_secret, stamp, job_a, raw)
    cross_job = await client.post(
        f"/api/v1/agents/jobs/{job_b}/approve",
        headers={
            "Authorization": f"Bearer {admin['access_token']}",
            "X-Aegis-Timestamp": stamp,
            "X-Aegis-Signature": signature_for_a,
        },
        content=raw,
    )
    assert cross_job.status_code == 401
    assert cross_job.json()["code"] == "BAD_APPROVAL_SIGNATURE"
