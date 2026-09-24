import uuid

import asyncpg
import pytest

from src.services.migrate import asyncpg_dsn


@pytest.mark.integration
async def test_rls_hides_other_tenants_and_blocks_writes(settings) -> None:
    app_dsn = asyncpg_dsn(settings.database_url)
    owner = await asyncpg.connect(app_dsn)
    tenant_a = str(uuid.uuid4())
    try:
        async with owner.transaction():
            await owner.execute("SELECT set_config('app.current_tenant_id', $1, true)", tenant_a)
            await owner.execute(
                "INSERT INTO organizations (id, name, domain_lock) VALUES ($1, 'A', $2)",
                tenant_a,
                f"{tenant_a}.example",
            )
            await owner.execute(
                "INSERT INTO users (tenant_id, email, system_role) VALUES ($1, 'a@example.com', 'viewer')",
                tenant_a,
            )
    finally:
        await owner.close()

    reader = await asyncpg.connect(app_dsn)
    tenant_b = str(uuid.uuid4())
    try:
        async with reader.transaction():
            await reader.execute("SELECT set_config('app.current_tenant_id', $1, true)", tenant_b)
            visible = await reader.fetch("SELECT email FROM users")
            assert visible == []
            with pytest.raises(asyncpg.PostgresError) as raised:
                await reader.execute(
                    "INSERT INTO users (tenant_id, email, system_role) VALUES ($1, 'cross@example.com', 'viewer')",
                    tenant_a,
                )
            assert "row-level security" in str(raised.value).lower()
    finally:
        await reader.close()

    blank = await asyncpg.connect(app_dsn)
    try:
        async with blank.transaction():
            visible = await blank.fetch("SELECT email FROM users")
            assert visible == []
    finally:
        await blank.close()
