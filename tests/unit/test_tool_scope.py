from src.core.config import Settings
from src.services.identity import Principal
from src.services.llm import StubLLM
from src.services.tools_sandbox import ToolRegistry
from src.services.workflow_engine import MemoryJobStore, WorkflowEngine


def _settings() -> Settings:
    return Settings(_env_file=None, aegis_jwt_secret="x" * 32, aegis_approval_secret="y" * 32)


async def test_missing_scope_never_opens_the_sql_tool() -> None:
    tools = ToolRegistry()
    engine = WorkflowEngine(
        tools=tools,
        retrieval=None,
        llm=StubLLM(),
        jobs=MemoryJobStore(),
        settings=_settings(),
    )
    principal = Principal("user", "tenant", ["billing:read"], "jti", "family", "jwt")
    row = await engine.start(
        None,
        job_id="job-scope",
        task="execute sql write against the workspace",
        principal=principal,
        trace_id="trace",
    )
    assert row["current_phase"] == "CRITICAL_SECURITY_DENIAL"
    assert tools.spy == []
    assert tools.cursor_opened == 0
