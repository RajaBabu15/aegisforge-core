from pathlib import Path

import asyncpg

from src.core.config import Settings
from src.core.security import hash_password, sha256_hex

_SCHEMA = Path(__file__).resolve().parents[1] / "models" / "schema.sql"
_REPAIR = Path(__file__).resolve().parents[1] / "models" / "repair.sql"


def asyncpg_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://")


async def apply_schema(migrator_url: str) -> None:
    connection = await asyncpg.connect(asyncpg_dsn(migrator_url))
    try:
        exists = await connection.fetchval("SELECT to_regclass('public.organizations')")
        if not exists:
            await connection.execute(_SCHEMA.read_text())
        if await connection.fetchval("SELECT to_regclass('public.organizations')"):
            await connection.execute(_REPAIR.read_text())
    finally:
        await connection.close()


async def bootstrap(migrator_url: str, settings: Settings) -> None:
    if not settings.bootstrap_email or not settings.bootstrap_password:
        return
    if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
        return
    connection = await asyncpg.connect(asyncpg_dsn(migrator_url))
    try:
        tenant_id = await connection.fetchval(
            """
            INSERT INTO organizations (name, domain_lock)
            VALUES ('Demo', $1)
            ON CONFLICT (domain_lock) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            """,
            settings.bootstrap_domain,
        )
        await _user(
            connection,
            tenant_id,
            settings.bootstrap_admin_email,
            settings.bootstrap_admin_password,
            "org_admin",
        )
        await _user(
            connection,
            tenant_id,
            settings.bootstrap_email,
            settings.bootstrap_password,
            "workspace_developer",
        )
        await connection.execute(
            """
            INSERT INTO oauth_clients (client_id, tenant_id, redirect_uris, is_public)
            VALUES ($1, $2, $3, true)
            ON CONFLICT (client_id) DO UPDATE SET redirect_uris = EXCLUDED.redirect_uris
            """,
            settings.oauth_client_id,
            tenant_id,
            [settings.oauth_redirect_uri],
        )
        if settings.scim_token:
            await connection.execute(
                """
                INSERT INTO scim_tokens (token_hash, tenant_id)
                VALUES ($1, $2)
                ON CONFLICT (token_hash) DO NOTHING
                """,
                sha256_hex(settings.scim_token),
                tenant_id,
            )
    finally:
        await connection.close()


async def _user(connection: asyncpg.Connection, tenant_id, email: str, password: str, role: str) -> None:
    await connection.execute(
        """
        INSERT INTO users (tenant_id, email, password_hash, system_role)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (tenant_id, email) DO UPDATE SET password_hash = EXCLUDED.password_hash
        """,
        tenant_id,
        email,
        hash_password(password),
        role,
    )
