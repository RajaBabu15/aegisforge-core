import hashlib
import hmac
import time
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from src.core.errors import AegisError

_HASHER = PasswordHasher()
_JWT_ALGO = "HS256"
APPROVAL_WINDOW_SECONDS = 300


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def new_token() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex


def pkce_s256(verifier: str) -> str:
    return create_s256_code_challenge(verifier)


def issue_access_token(
    secret: str,
    *,
    user_id: str,
    tenant_id: str,
    scopes: list[str],
    family_id: str,
    ttl_seconds: int,
) -> tuple[str, str]:
    now = datetime.now(UTC)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "scope": scopes,
        "jti": jti,
        "family_id": family_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    token = jwt.encode(payload, secret, algorithm=_JWT_ALGO)
    return token, jti


def decode_access_token(secret: str, token: str) -> dict:
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=[_JWT_ALGO],
            leeway=30,
            options={"require": ["exp", "iat", "sub", "tenant_id", "scope", "jti", "family_id"]},
        )
    except jwt.PyJWTError as exc:
        raise AegisError(401, "UNAUTHORIZED", "access token rejected") from exc


def approval_signature(secret: str, timestamp: str, job_id: str, raw_body: bytes) -> str:
    message = timestamp.encode("utf-8") + b"." + job_id.encode("utf-8") + b"." + raw_body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_approval(secret: str, timestamp: str, job_id: str, raw_body: bytes, signature: str) -> None:
    try:
        ts = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise AegisError(401, "BAD_APPROVAL_SIGNATURE", "timestamp missing") from exc
    if abs(time.time() - ts) > APPROVAL_WINDOW_SECONDS:
        raise AegisError(401, "STALE_APPROVAL", "approval timestamp outside the 300 second window")
    expected = approval_signature(secret, timestamp, job_id, raw_body)
    if not hmac.compare_digest(expected, signature or ""):
        raise AegisError(401, "BAD_APPROVAL_SIGNATURE", "approval signature mismatch")
