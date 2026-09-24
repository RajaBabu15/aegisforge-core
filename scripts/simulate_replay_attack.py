#!/usr/bin/env python3
"""Log in, rotate a refresh token, then present the consumed token."""

import os
import sys
from urllib.parse import parse_qs, urlparse

import httpx

from src.core.security import pkce_s256

BASE = os.environ.get("AEGIS_BASE_URL", "http://localhost:8000")
EMAIL = os.environ.get("AEGIS_BOOTSTRAP_EMAIL", "dev@demo.aegisforge.local")
PASSWORD = os.environ.get("AEGIS_BOOTSTRAP_PASSWORD", "developer-password")
REDIRECT = os.environ.get("AEGIS_OAUTH_REDIRECT_URI", "http://127.0.0.1:8765/callback")
CLIENT = os.environ.get("AEGIS_OAUTH_CLIENT_ID", "aegis-demo")
VERIFIER = "replay-verifier-" + ("a" * 48)


def main() -> int:
    challenge = pkce_s256(VERIFIER)
    with httpx.Client(base_url=BASE, follow_redirects=False, timeout=30) as client:
        login = client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": CLIENT,
                "redirect_uri": REDIRECT,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "replay",
                "email": EMAIL,
                "password": PASSWORD,
            },
        )
        if login.status_code != 302:
            print(f"login failed: {login.status_code} {login.text}", file=sys.stderr)
            return 1
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        issued = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": CLIENT,
                "code_verifier": VERIFIER,
            },
        ).json()
        rotated = client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": issued["refresh_token"]},
        )
        print(f"rotation {rotated.status_code}")
        replay = client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": issued["refresh_token"]},
        )
        print(f"replay {replay.status_code} {replay.text}")
        access = rotated.json()["access_token"]
        follow = client.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"})
        print(f"revoked access {follow.status_code}")
        return 0 if replay.status_code == 401 and follow.status_code == 401 else 1


if __name__ == "__main__":
    raise SystemExit(main())
