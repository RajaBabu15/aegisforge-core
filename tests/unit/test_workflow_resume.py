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
