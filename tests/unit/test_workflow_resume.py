import pytest

from src.services.checkpointer import open_checkpointer
from src.services.identity import Principal
from src.services.llm import StubLLM
from src.services.tools_sandbox import ToolRegistry
from src.services.workflow_engine import MemoryJobStore, WorkflowEngine
from tests.unit.test_tool_scope import _settings


async def test_new_engine_resumes_the_same_checkpoint_without_replaying_plan_cost() -> None:
    jobs = MemoryJobStore()
    first_tools = ToolRegistry()
    settings = _settings()
    first = WorkflowEngine(
        tools=first_tools,
        retrieval=None,
        llm=StubLLM(),
        jobs=jobs,
        settings=settings,
    )
    principal = Principal("user", "tenant", ["tickets:write"], "jti", "family", "jwt")
    suspended = await first.start(
        None,
        job_id="job-crash",
        task="file a high-priority tracking ticket",
        principal=principal,
        trace_id="trace",
    )
    assert suspended["current_phase"] == "SUSPEND"
    cost_at_suspend = suspended["accumulated_token_cost"]
    second_tools = ToolRegistry()
    second = WorkflowEngine(
        tools=second_tools,
        retrieval=None,
        llm=StubLLM(),
        jobs=jobs,
        settings=settings,
        checkpointer=first.checkpointer,
    )
    finished = await second.resume(None, "job-crash", "APPROVED")
    assert finished["current_phase"] == "RESPOND"
    assert second_tools.spy == ["file_ticket"]
    assert finished["accumulated_token_cost"] == cost_at_suspend
    assert second.llm.calls == 0


@pytest.mark.integration
async def test_postgres_checkpointer_survives_a_new_connection(settings) -> None:
    jobs = MemoryJobStore()
    saver, closer = await open_checkpointer(settings)
    first = WorkflowEngine(
        tools=ToolRegistry(),
        retrieval=None,
        llm=StubLLM(),
        jobs=jobs,
        settings=settings,
        checkpointer=saver,
    )
    principal = Principal("user", "tenant", ["tickets:write"], "jti", "family", "jwt")
    suspended = await first.start(
        None,
        job_id="job-pg-crash",
        task="file a high-priority tracking ticket",
        principal=principal,
        trace_id="trace",
    )
    assert suspended["current_phase"] == "SUSPEND"
    await closer.__aexit__(None, None, None)

    saver, closer = await open_checkpointer(settings)
    second_tools = ToolRegistry()
    second = WorkflowEngine(
        tools=second_tools,
        retrieval=None,
        llm=StubLLM(),
        jobs=jobs,
        settings=settings,
        checkpointer=saver,
    )
    try:
        finished = await second.resume(None, "job-pg-crash", "APPROVED")
    finally:
        await closer.__aexit__(None, None, None)
    assert finished["current_phase"] == "RESPOND"
    assert second_tools.spy == ["file_ticket"]
    assert finished["accumulated_token_cost"] == suspended["accumulated_token_cost"]


class _UserResult:
    def __init__(self, row: dict | None) -> None:
        self._row = row

    def mappings(self):
        return self

    def first(self):
        return self._row


class _UserSession:
    def __init__(self, row: dict | None) -> None:
        self.row = row

    async def execute(self, statement, params=None):
        del params
        sql = str(statement)
        if "FROM users" in sql:
            return _UserResult(self.row)
        return _UserResult(None)


async def test_resume_denies_when_owner_is_deactivated() -> None:
    jobs = MemoryJobStore()
    tools = ToolRegistry()
    engine = WorkflowEngine(tools=tools, retrieval=None, llm=StubLLM(), jobs=jobs, settings=_settings())
    principal = Principal("user", "tenant", ["tickets:write"], "jti", "family", "jwt")
    await engine.start(None, job_id="job-dead", task="file a tracking ticket", principal=principal, trace_id="t")
    denied = await engine.resume(_UserSession({"is_active": False, "system_role": "workspace_developer"}), "job-dead", "APPROVED")
    assert denied["current_phase"] == "CRITICAL_SECURITY_DENIAL"
    assert denied["execution_payload_state"]["output"]["code"] == "USER_DEACTIVATED"
    assert tools.spy == []


async def test_resume_denies_when_owner_lost_the_tool_scope() -> None:
    jobs = MemoryJobStore()
    tools = ToolRegistry()
    engine = WorkflowEngine(tools=tools, retrieval=None, llm=StubLLM(), jobs=jobs, settings=_settings())
    principal = Principal("user", "tenant", ["tickets:write"], "jti", "family", "jwt")
    await engine.start(None, job_id="job-viewer", task="file a tracking ticket", principal=principal, trace_id="t")
    denied = await engine.resume(_UserSession({"is_active": True, "system_role": "viewer"}), "job-viewer", "APPROVED")
    assert denied["current_phase"] == "CRITICAL_SECURITY_DENIAL"
    assert denied["execution_payload_state"]["output"]["code"] == "SCOPE_CHANGED"
    assert tools.spy == []
