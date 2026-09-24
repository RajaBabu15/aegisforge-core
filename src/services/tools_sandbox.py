import inspect
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.services.migrate import asyncpg_dsn
from src.services.telemetry import TOOL_DURATION


@dataclass
class Tool:
    name: str
    required_scopes: set[str]
    requires_approval: bool
    fn: Callable[[dict, str], Any]


@dataclass
class ToolRegistry:
    spy: list[str] = field(default_factory=list)
    cursor_opened: int = 0
    tools: dict[str, Tool] = field(default_factory=dict)
    tool_sql_database_url: str | None = None

    def __post_init__(self) -> None:
        if self.tools:
            return
        self.tools = {
            "file_ticket": Tool("file_ticket", {"tickets:write"}, True, self._file_ticket),
            "execute_sql_write": Tool("execute_sql_write", {"tickets:write"}, True, self._execute_sql_write),
            "read_billing": Tool("read_billing", {"billing:read"}, False, self._read_billing),
        }

    def choose(self, task: str) -> str:
        command = (task or "").splitlines()[0].lower()
        if "ticket" in command:
            return "file_ticket"
        if "sql" in command:
            return "execute_sql_write"
        return "read_billing"

    def allows(self, name: str, scopes: list[str]) -> bool:
        return self.tools[name].required_scopes <= set(scopes)

    async def invoke(self, name: str, args: dict, scopes: list[str], tenant_id: str) -> dict:
        tool = self.tools[name]
        started = time.perf_counter()
        if not self.allows(name, scopes):
            TOOL_DURATION.labels(tool=name, outcome="denied").observe(time.perf_counter() - started)
            raise PermissionError(name)
        self.spy.append(name)
        try:
            result = tool.fn(args, tenant_id)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            TOOL_DURATION.labels(tool=name, outcome="error").observe(time.perf_counter() - started)
            raise
        TOOL_DURATION.labels(tool=name, outcome="ok").observe(time.perf_counter() - started)
        return result

    def _file_ticket(self, args: dict, tenant_id: str) -> dict:
        del tenant_id
        return {"ticket_id": "T-100", "summary": args.get("summary", "high-priority connection error")}

    async def _execute_sql_write(self, args: dict, tenant_id: str) -> dict:
        statement = args.get("statement") or args.get("summary", "")
        if not self.tool_sql_database_url:
            return {"wrote": False, "statement": statement, "reason": "no sandboxed connection configured"}
        import asyncpg

        connection = await asyncpg.connect(asyncpg_dsn(self.tool_sql_database_url))
        self.cursor_opened += 1
        try:
            async with connection.transaction():
                await connection.execute("SELECT set_config('app.current_tenant_id', $1, true)", tenant_id)
                row_id = await connection.fetchval(
                    """
                    INSERT INTO agent_tool_writes (tenant_id, tool_name, statement)
                    VALUES ($1::uuid, 'execute_sql_write', $2)
                    RETURNING id
                    """,
                    tenant_id,
                    statement,
                )
        finally:
            await connection.close()
        return {"wrote": True, "id": str(row_id), "statement": statement}

    def _read_billing(self, args: dict, tenant_id: str) -> dict:
        del args, tenant_id
        return {"balance": "0.00"}
