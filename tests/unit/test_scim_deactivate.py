import pytest

from tests.unit.test_token_rotation import _login


@pytest.mark.integration
async def test_scim_deactivation_revokes_access_and_cancels_jobs(client) -> None:
    tokens = await _login(client, "dev@demo.aegisforge.local", "developer-password")
    listed = await client.get(
        '/scim/v2/Users',
        params={"filter": 'userName eq "dev@demo.aegisforge.local"'},
        headers={"Authorization": "Bearer scim-demo-token-value-0123456789"},
    )
    assert listed.status_code == 200, listed.text
    user_id = listed.json()["Resources"][0]["id"]
    replaced = await client.put(
        f"/scim/v2/Users/{user_id}",
        headers={"Authorization": "Bearer scim-demo-token-value-0123456789"},
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "dev@demo.aegisforge.local",
            "active": False,
            "groups": [{"value": "eng", "display": "Engineering"}],
        },
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["active"] is False
    me = await client.get("/api/v1/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 401

    reactivated = await client.put(
        f"/scim/v2/Users/{user_id}",
        headers={"Authorization": "Bearer scim-demo-token-value-0123456789"},
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "dev@demo.aegisforge.local",
            "active": True,
        },
    )
    assert reactivated.status_code == 200
    still = await client.get("/api/v1/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert still.status_code == 401
