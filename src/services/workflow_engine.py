import logging
from typing import Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from sqlalchemy import text

from src.services.llm import infer
from src.services.telemetry import TOKEN_CONSUMPTION, parent_context, tracer
from src.services.tools_sandbox import ToolRegistry

log = logging.getLogger("aegisforge.workflow")

TERMINAL = {"RESPOND", "CRITICAL_SECURITY_DENIAL", "CANCELLED"}
PLAN_COST = 0.001


class WFState(TypedDict, total=False):
    task: str
    scopes: list[str]
    tenant_id: str
    user_id: str
    trace_id: str
    steps: list[str]
    cost: float
    phase: str
    tool_name: str
    tool_result: dict
    citations: list[dict]
    skip_llm: bool
    output: Any
    version: str


class WorkflowEngine:
    def __init__(self, *, tools: ToolRegistry, retrieval, llm, jobs, settings, checkpointer=None) -> None:
        self.tools = tools
        self.retrieval = retrieval
        self.llm = llm
        self.jobs = jobs
        self.settings = settings
        self.checkpointer = checkpointer or MemorySaver()
        self.graph = self._compile()

    def _compile(self):
        graph = StateGraph(WFState)
        graph.add_node("plan", self._plan)
        graph.add_node("choose_tool", self._choose_tool)
        graph.add_node("execute", self._execute)
        graph.add_node("verify", self._verify)
        graph.add_node("respond", self._respond)
        graph.add_edge(START, "plan")
        graph.add_conditional_edges(
            "plan",
            lambda state: "end" if state.get("skip_llm") else "choose_tool",
            {"end": END, "choose_tool": "choose_tool"},
        )
        graph.add_conditional_edges(
            "choose_tool",
            self._after_choose_tool,
            {"execute": "execute", "end": END},
        )
        graph.add_conditional_edges(
            "execute",
            self._after_execute,
            {"verify": "verify", "end": END},
        )
        graph.add_edge("verify", "respond")
        graph.add_edge("respond", END)
        return graph.compile(checkpointer=self.checkpointer)

    async def start(self, session, *, job_id: str, task: str, principal, trace_id: str) -> dict:
        state: WFState = {
            "task": task,
            "scopes": list(principal.scopes),
            "tenant_id": principal.tenant_id,
            "user_id": principal.user_id,
            "trace_id": trace_id,
            "steps": [],
            "cost": 0.0,
            "phase": "START",
            "version": self.settings.workflow_version,
            "citations": [],
            "skip_llm": False,
        }
        config = {"configurable": {"thread_id": job_id}}
        with self._workflow_span(trace_id):
            await self.graph.ainvoke(state, config)
        return await self._persist(session, job_id, config)

    async def resume(self, session, job_id: str, decision: str) -> dict:
        current = await self.jobs.get_for_update(session, job_id)
        if current is None:
            return {}
        if current["workflow_definition_version"] != self.settings.workflow_version:
            return current
        if current["current_phase"] in TERMINAL:
            return current
        config = {"configurable": {"thread_id": job_id}}
        with self._workflow_span(current.get("trace_id") or ""):
            await self.graph.ainvoke(Command(resume=decision), config)
        row = await self._persist(session, job_id, config)
        if decision == "REJECTED":
            await self._audit(session, row, "DENY", "HUMAN_REJECTED")
        return row

    async def _plan(self, state: WFState) -> dict:
        if "plan" in state.get("steps", []):
            return {}
        steps = list(state.get("steps", [])) + ["plan"]
        cost = float(state.get("cost", 0)) + PLAN_COST
        if cost > float(self.settings.agent_max_cost):
            return {
                "phase": "RESPOND",
                "steps": steps,
                "cost": cost,
                "citations": [],
                "skip_llm": True,
                "output": {"code": "BUDGET_EXCEEDED"},
            }
        citations: list[dict] = []
        if self.retrieval is not None:
            found = await self.retrieval.query(state["tenant_id"], state["task"])
            citations = [item.__dict__ if hasattr(item, "__dict__") else item for item in found]
        mutation = self._mutation(state["task"])
        if not citations and not mutation:
            return {
                "phase": "RESPOND",
                "steps": steps,
                "cost": cost,
                "citations": [],
                "skip_llm": True,
                "output": {"code": "INSUFFICIENT_EVIDENCE"},
            }
        return {"phase": "PLAN", "steps": steps, "cost": cost, "citations": citations, "skip_llm": False}

    async def _choose_tool(self, state: WFState) -> dict:
        if "choose_tool" in state.get("steps", []):
            return {}
        name = self.tools.choose(state["task"])
        steps = list(state.get("steps", [])) + ["choose_tool"]
        if not self.tools.allows(name, state.get("scopes", [])):
            return {"phase": "CRITICAL_SECURITY_DENIAL", "tool_name": name, "steps": steps}
        return {"phase": "EXECUTE", "tool_name": name, "steps": steps}

    async def _execute(self, state: WFState) -> dict:
        name = state["tool_name"]
        tool = self.tools.tools[name]
        if tool.requires_approval:
            decision = interrupt({"tool": name, "task": state["task"]})
            if decision != "APPROVED":
                return {"phase": "CANCELLED", "tool_name": name}
        return {"phase": "VERIFY", "tool_name": name}

    async def _verify(self, state: WFState) -> dict:
        if "verify" in state.get("steps", []):
            return {}
        result = await self.tools.invoke(
            state["tool_name"], {"summary": state["task"]}, state.get("scopes", []), state.get("tenant_id", "")
        )
        return {
            "phase": "VERIFY",
            "tool_result": result,
            "steps": list(state.get("steps", [])) + ["verify"],
        }

    async def _respond(self, state: WFState) -> dict:
        if "respond" in state.get("steps", []):
            return {}
        if state.get("citations"):
            answer, tokens = await infer(self.llm, state["task"], state["citations"], self.settings.llm_model)
            TOKEN_CONSUMPTION.labels(tenant_id=state["tenant_id"], model=self.settings.llm_model).inc(tokens)
            output = {"answer": answer, "citations": state["citations"], "tool_result": state.get("tool_result")}
            extra = tokens / 1_000_000
        else:
            output = {"tool_result": state.get("tool_result"), "citations": []}
            extra = 0.0
        return {
            "phase": "RESPOND",
            "output": output,
            "steps": list(state.get("steps", [])) + ["respond"],
            "cost": float(state.get("cost", 0)) + extra,
        }

    @staticmethod
    def _after_choose_tool(state: WFState) -> str:
        if state.get("phase") == "CRITICAL_SECURITY_DENIAL":
            return "end"
        return "execute"

    @staticmethod
    def _after_execute(state: WFState) -> str:
        if state.get("phase") in {"CRITICAL_SECURITY_DENIAL", "CANCELLED"}:
            return "end"
        return "verify"

    @staticmethod
    def _mutation(task: str) -> bool:
        lowered = task.lower()
        return "ticket" in lowered or "sql" in lowered

    async def _persist(self, session, job_id: str, config: dict) -> dict:
        snapshot = await self.graph.aget_state(config)
        values = dict(snapshot.values)
        suspended = bool(getattr(snapshot, "interrupts", None))
        phase = "SUSPEND" if suspended else values.get("phase", "START")
        if phase == "CRITICAL_SECURITY_DENIAL":
            await self._audit(session, {"user_id": values.get("user_id"), "tenant_id": values.get("tenant_id"), "id": job_id, "scopes": values.get("scopes", [])}, "DENY", "SCOPE")
        row = {
            "id": job_id,
            "tenant_id": values.get("tenant_id"),
            "user_id": values.get("user_id"),
            "trace_id": values.get("trace_id", ""),
            "workflow_definition_version": values.get("version", self.settings.workflow_version),
            "current_phase": phase,
            "execution_payload_state": {
                "task": values.get("task"),
                "output": values.get("output"),
                "tool_name": values.get("tool_name"),
                "tool_result": values.get("tool_result"),
                "steps": values.get("steps", []),
            },
            "is_suspended_for_approval": suspended,
            "accumulated_token_cost": float(values.get("cost", 0)),
        }
        await self.jobs.save(session, row)
        status = "awaiting_human_approval" if suspended else phase
        log.info("job=%s phase=%s status=%s trace_id=%s", job_id, phase, status, row["trace_id"])
        return row

    @staticmethod
    def _workflow_span(trace_id: str):
        context = parent_context(trace_id)
        if context is None:
            return tracer().start_as_current_span("workflow.execute")
        return tracer().start_as_current_span("workflow.execute", context=context)

    async def _audit(self, session, row: dict, decision: str, reason: str) -> None:
        if session is None or not hasattr(session, "execute"):
            return
        await session.execute(
            text(
                """
                INSERT INTO system_audit_ledger (
                    tenant_id, user_id, auth_scope_used, action_type, resource_identifier,
                    execution_decision, rejection_reason_code
                ) VALUES (
                    CAST(:tenant AS uuid), CAST(:user_id AS uuid), :scopes, 'workflow',
                    :resource, :decision, :reason
                )
                """
            ),
            {
                "tenant": row.get("tenant_id"),
                "user_id": row.get("user_id"),
                "scopes": list(row.get("scopes") or []),
                "resource": str(row.get("id")),
                "decision": decision,
                "reason": reason,
            },
        )


class JobStore:
    async def save(self, session, row: dict) -> None:
        await session.execute(
            text(
                """
                INSERT INTO agent_workflow_state (
                    id, tenant_id, user_id, trace_id, workflow_definition_version,
                    current_phase, execution_payload_state, is_suspended_for_approval,
                    accumulated_token_cost
                ) VALUES (
                    CAST(:id AS uuid), CAST(:tenant_id AS uuid), CAST(:user_id AS uuid),
                    :trace_id, :version, :phase, CAST(:payload AS jsonb), :suspended, :cost
                )
                ON CONFLICT (id) DO UPDATE SET
                    current_phase = EXCLUDED.current_phase,
                    execution_payload_state = EXCLUDED.execution_payload_state,
                    is_suspended_for_approval = EXCLUDED.is_suspended_for_approval,
                    accumulated_token_cost = EXCLUDED.accumulated_token_cost,
                    updated_at = CURRENT_TIMESTAMP
                """
            ),
            {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "user_id": row["user_id"],
                "trace_id": row["trace_id"],
                "version": row["workflow_definition_version"],
                "phase": row["current_phase"],
                "payload": _json(row["execution_payload_state"]),
                "suspended": row["is_suspended_for_approval"],
                "cost": row["accumulated_token_cost"],
            },
        )

    async def get(self, session, job_id: str) -> dict | None:
        return await self._select(session, job_id, for_update=False)

    async def get_for_update(self, session, job_id: str) -> dict | None:
        return await self._select(session, job_id, for_update=True)

    async def _select(self, session, job_id: str, *, for_update: bool) -> dict | None:
        found = await session.execute(
            text(
                """
                SELECT id, tenant_id, user_id, trace_id, workflow_definition_version,
                       current_phase, execution_payload_state, is_suspended_for_approval,
                       accumulated_token_cost
                FROM agent_workflow_state
                WHERE id = CAST(:id AS uuid)
                """
                + (" FOR UPDATE" if for_update else "")
            ),
            {"id": job_id},
        )
        row = found.mappings().first()
        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "tenant_id": str(row["tenant_id"]),
            "user_id": str(row["user_id"]),
            "trace_id": row["trace_id"],
            "workflow_definition_version": row["workflow_definition_version"],
            "current_phase": row["current_phase"],
            "execution_payload_state": row["execution_payload_state"],
            "is_suspended_for_approval": row["is_suspended_for_approval"],
            "accumulated_token_cost": float(row["accumulated_token_cost"]),
        }


class MemoryJobStore:
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    async def save(self, session, row: dict) -> None:
        del session
        self.rows[row["id"]] = row

    async def get(self, session, job_id: str) -> dict | None:
        del session
        return self.rows.get(job_id)

    async def get_for_update(self, session, job_id: str) -> dict | None:
        return await self.get(session, job_id)


def _json(value) -> str:
    import json

    return json.dumps(value)
