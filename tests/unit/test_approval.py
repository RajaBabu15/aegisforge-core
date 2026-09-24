import time

import pytest

from src.core.errors import AegisError
from src.core.security import approval_signature, verify_approval
from src.services.identity import Principal
from src.services.llm import StubLLM
from src.services.tools_sandbox import ToolRegistry
from src.services.workflow_engine import MemoryJobStore, WorkflowEngine
from tests.unit.test_tool_scope import _settings


def test_stale_and_bad_signatures_are_rejected() -> None:
    secret = "y" * 32
    body = b'{"decision":"APPROVED"}'
    job_id = "job-approve"
    with pytest.raises(AegisError) as stale:
        verify_approval(
            secret, str(int(time.time()) - 1000), job_id, body, approval_signature(secret, "0", job_id, body)
        )
    assert stale.value.status == 401
    with pytest.raises(AegisError) as forged:
        verify_approval(secret, str(int(time.time())), job_id, body, "0" * 64)
    assert forged.value.status == 401


async def test_resume_runs_the_tool_once_and_a_second_approval_does_not() -> None:
    tools = ToolRegistry()
    jobs = MemoryJobStore()
    settings = _settings()
    engine = WorkflowEngine(tools=tools, retrieval=None, llm=StubLLM(), jobs=jobs, settings=settings)
    principal = Principal("user", "tenant", ["tickets:write"], "jti", "family", "jwt")
    started = await engine.start(
        None,
        job_id="job-approve",
        task="Analyze workspace log files and file a high-priority tracking ticket.",
        principal=principal,
        trace_id="trace",
    )
    assert started["current_phase"] == "SUSPEND"
    assert tools.spy == []
    resumed = await engine.resume(None, "job-approve", "APPROVED")
    assert resumed["current_phase"] == "RESPOND"
    assert tools.spy == ["file_ticket"]
    again = await engine.resume(None, "job-approve", "APPROVED")
    assert again["current_phase"] == "RESPOND"
    assert tools.spy == ["file_ticket"]


async def test_version_mismatch_leaves_the_job_unchanged() -> None:
    tools = ToolRegistry()
    jobs = MemoryJobStore()
    engine = WorkflowEngine(tools=tools, retrieval=None, llm=StubLLM(), jobs=jobs, settings=_settings())
    principal = Principal("user", "tenant", ["tickets:write"], "jti", "family", "jwt")
    await engine.start(
        None,
        job_id="job-version",
        task="file a tracking ticket",
        principal=principal,
        trace_id="trace",
    )
    jobs.rows["job-version"]["workflow_definition_version"] = "0.9.0"
    row = await engine.resume(None, "job-version", "APPROVED")
    assert row["workflow_definition_version"] == "0.9.0"
    assert row["current_phase"] == "SUSPEND"
    assert tools.spy == []
