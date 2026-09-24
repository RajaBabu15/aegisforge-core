import re
import uuid

import asyncpg
import pytest

from src.services.migrate import asyncpg_dsn
from src.services.tools_sandbox import ToolRegistry


def _swap_credentials(url: str, user: str, password: str) -> str:
    return re.sub(r"://[^@]+@", f"://{user}:{password}@", url)


@pytest.mark.integration
async def test_aegis_tool_sql_cannot_touch_any_other_table(settings) -> None:
    tool_url = _swap_credentials(settings.migrator_database_url, "aegis_tool_sql", "tool")
    connection = await asyncpg.connect(asyncpg_dsn(tool_url))
    try:
        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
            await connection.fetch("SELECT * FROM users")
        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
            await connection.execute("UPDATE system_audit_ledger SET rejection_reason_code = 'tampered'")
        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
            await connection.execute("DELETE FROM refresh_tokens")
    finally:
        await connection.close()


@pytest.mark.integration
async def test_execute_sql_write_persists_a_tenant_scoped_row_via_the_sandboxed_role(settings) -> None:
    migrator = await asyncpg.connect(asyncpg_dsn(settings.migrator_database_url))
    try:
        tenant_id = await migrator.fetchval(
            "INSERT INTO organizations (name, domain_lock) VALUES ('Tool Isolation Test', $1) RETURNING id",
            f"{uuid.uuid4()}.example",
        )
    finally:
        await migrator.close()
    tenant_id = str(tenant_id)

    tool_url = _swap_credentials(settings.migrator_database_url, "aegis_tool_sql", "tool")
    tools = ToolRegistry(tool_sql_database_url=tool_url)
    result = await tools.invoke(
        "execute_sql_write", {"statement": "reconcile invoice batch"}, ["tickets:write"], tenant_id
    )
    assert result["wrote"] is True

    verify = await asyncpg.connect(asyncpg_dsn(settings.migrator_database_url))
    try:
        row = await verify.fetchrow(
            "SELECT tenant_id, tool_name, statement FROM agent_tool_writes WHERE id = $1::uuid", result["id"]
        )
    finally:
        await verify.close()
    assert row is not None
    assert str(row["tenant_id"]) == tenant_id
    assert row["tool_name"] == "execute_sql_write"
    assert row["statement"] == "reconcile invoice batch"
