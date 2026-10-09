import json
import logging
from typing import Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from sqlalchemy import text

from src.services.identity import scopes_for_role
from src.services.llm import answer_is_grounded, infer
from src.services.telemetry import HALLUCINATION, TOKEN_CONSUMPTION, record_outcome
from src.services.tools_sandbox import ToolRegistry

log = logging.getLogger("aegisforge.workflow")

TERMINAL = {"RESPOND", "CRITICAL_SECURITY_DENIAL", "CANCELLED"}
NODE_COST = {"plan": 0.001, "choose": 0.0005, "verify": 0.0005, "respond": 0.0005}


class WFState(TypedDict, total=False):
    task: str
    scopes: list[str]
    tenant_id: str
    user_id: str
    trace_id: str
    steps: list[str]
    cost: float
    cost_breakdown: dict
    phase: str
    tool_name: str
    tool_args: dict
    tool_result: dict
    citations: list[dict]
    skip_llm: bool
    output: Any
    version: str
    verification: dict


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
            "cost_breakdown": {},
            "phase": "START",
            "version": self.settings.workflow_version,
            "citations": [],
            "skip_llm": False,
        }
        config = {"configurable": {"thread_id": job_id}}
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
        blocked = await self._resume_blocked(session, current)
        if blocked:
            return await self._deny_resume(session, current, blocked)
        config = {"configurable": {"thread_id": job_id}}
        await self.graph.ainvoke(Command(resume=decision), config)
        return await self._persist(session, job_id, config)

    async def _resume_blocked(self, session, current: dict) -> str | None:
        if session is None or not hasattr(session, "execute"):
            return None
        user_id = current.get("user_id")
        if not user_id:
            return None
        found = await session.execute(
            text("SELECT is_active, system_role FROM users WHERE id = CAST(:id AS uuid)"),
            {"id": str(user_id)},
        )
        row = found.mappings().first()
        if row is None or not row["is_active"]:
            return "USER_DEACTIVATED"
        try:
            live_scopes = scopes_for_role(row["system_role"])
        except KeyError:
            return "SCOPE_CHANGED"
        payload = current.get("execution_payload_state") or {}
        if isinstance(payload, str):
            payload = json.loads(payload)
        tool_name = payload.get("tool_name")
        if tool_name and not self.tools.allows(tool_name, live_scopes):
            return "SCOPE_CHANGED"
        return None

    async def _deny_resume(self, session, current: dict, code: str) -> dict:
        payload = current.get("execution_payload_state") or {}
        if isinstance(payload, str):
            payload = json.loads(payload)
        payload = dict(payload)
        payload["output"] = {"code": code}
        row = {
            **current,
            "current_phase": "CRITICAL_SECURITY_DENIAL",
            "is_suspended_for_approval": False,
            "execution_payload_state": payload,
        }
        await self.jobs.save(session, row)
        await self._audit_phase(session, row)
        return row

    async def _plan(self, state: WFState) -> dict:
        if "plan" in state.get("steps", []):
            return {}
        steps = list(state.get("steps", [])) + ["plan"]
        cost, breakdown, over = _apply_cost(state, "plan", NODE_COST["plan"], float(self.settings.agent_max_cost))
        if over:
            return {
                "phase": "RESPOND",
                "steps": steps,
                "cost": cost,
                "cost_breakdown": breakdown,
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
                "cost_breakdown": breakdown,
                "citations": [],
                "skip_llm": True,
                "output": {"code": "INSUFFICIENT_EVIDENCE"},
            }
        return {
            "phase": "PLAN",
            "steps": steps,
            "cost": cost,
            "cost_breakdown": breakdown,
            "citations": citations,
            "skip_llm": False,
        }

    async def _choose_tool(self, state: WFState) -> dict:
        if "choose_tool" in state.get("steps", []):
            return {}
        name = self.tools.choose(state["task"])
        args = self.tools.args_for(name, state["task"])
        steps = list(state.get("steps", [])) + ["choose_tool"]
        cost, breakdown, over = _apply_cost(state, "choose", NODE_COST["choose"], float(self.settings.agent_max_cost))
        if over:
            return {
                "phase": "RESPOND",
                "steps": steps,
                "cost": cost,
                "cost_breakdown": breakdown,
                "skip_llm": True,
                "output": {"code": "BUDGET_EXCEEDED"},
            }
        if not self.tools.allows(name, state.get("scopes", [])):
            return {
                "phase": "CRITICAL_SECURITY_DENIAL",
                "tool_name": name,
                "tool_args": args,
                "steps": steps,
                "cost": cost,
                "cost_breakdown": breakdown,
            }
        return {
            "phase": "EXECUTE",
            "tool_name": name,
            "tool_args": args,
            "steps": steps,
            "cost": cost,
            "cost_breakdown": breakdown,
        }

    async def _execute(self, state: WFState) -> dict:
        name = state["tool_name"]
        tool = self.tools.tools[name]
        cost, breakdown, over = _apply_cost(state, "execute", tool.cost, float(self.settings.agent_max_cost))
        if over:
            return {
                "phase": "RESPOND",
                "cost": cost,
                "cost_breakdown": breakdown,
                "skip_llm": True,
                "output": {"code": "BUDGET_EXCEEDED"},
            }
        if tool.requires_approval:
            decision = interrupt({"tool": name, "task": state["task"]})
            if decision != "APPROVED":
                return {"phase": "CANCELLED", "tool_name": name, "cost": cost, "cost_breakdown": breakdown}
        return {"phase": "VERIFY", "tool_name": name, "cost": cost, "cost_breakdown": breakdown}

    async def _verify(self, state: WFState) -> dict:
        if "verify" in state.get("steps", []):
            return {}
        name = state["tool_name"]
        args = state.get("tool_args") or self.tools.args_for(name, state["task"])
        result = await self.tools.invoke(name, args, state.get("scopes", []), state.get("tenant_id", ""))
        verification = decide_verification(
            tool_name=name,
            tool_result=result,
            citations=state.get("citations") or [],
            scopes=state.get("scopes") or [],
            tools=self.tools,
        )
        cost, breakdown, _over = _apply_cost(state, "verify", NODE_COST["verify"], float(self.settings.agent_max_cost))
        return {
            "phase": "VERIFY",
            "tool_result": result,
            "tool_args": args,
            "verification": verification,
            "steps": list(state.get("steps", [])) + ["verify"],
            "cost": cost,
            "cost_breakdown": breakdown,
        }

    async def _respond(self, state: WFState) -> dict:
        if "respond" in state.get("steps", []):
            return {}
        verification = state.get("verification") or {}
        cost, breakdown, _over = _apply_cost(
            state, "respond", NODE_COST["respond"], float(self.settings.agent_max_cost)
        )
        if verification.get("decision") == "DENY":
            return {
                "phase": "RESPOND",
                "output": {"code": "VERIFICATION_DENIED", "verification": verification},
                "steps": list(state.get("steps", [])) + ["respond"],
                "cost": cost,
                "cost_breakdown": breakdown,
            }
        llm_tokens = 0
        extra = 0.0
        if state.get("citations"):
            answer, tokens = await infer(self.llm, state["task"], state["citations"], self.settings.llm_model)
            llm_tokens = int(tokens)
            TOKEN_CONSUMPTION.labels(tenant_id=state["tenant_id"], model=self.settings.llm_model).inc(llm_tokens)
            output = {"answer": answer, "citations": state["citations"], "tool_result": state.get("tool_result")}
            if not answer_is_grounded(answer, state["citations"]):
                output["ungrounded"] = True
                HALLUCINATION.labels(tenant_id=state["tenant_id"], model=self.settings.llm_model).inc()
            extra = llm_tokens / 1_000_000
        else:
            output = {"tool_result": state.get("tool_result"), "citations": []}
        charged = {**state, "cost": cost, "cost_breakdown": breakdown}
        cost, breakdown, _over = _apply_cost(charged, "llm_tokens", extra, float(self.settings.agent_max_cost))
        breakdown["llm_tokens_count"] = llm_tokens
        return {
            "phase": "RESPOND",
            "output": output,
            "steps": list(state.get("steps", [])) + ["respond"],
            "cost": cost,
            "cost_breakdown": breakdown,
        }

    @staticmethod
    def _after_choose_tool(state: WFState) -> str:
        if state.get("phase") in {"CRITICAL_SECURITY_DENIAL", "RESPOND"}:
            return "end"
        return "execute"

    @staticmethod
    def _after_execute(state: WFState) -> str:
        if state.get("phase") in {"CRITICAL_SECURITY_DENIAL", "CANCELLED", "RESPOND"}:
            return "end"
        return "verify"

    @staticmethod
    def _mutation(task: str) -> bool:
        command = (task or "").splitlines()[0].lower()
        return "ticket" in command or "sql" in command

    async def _persist(self, session, job_id: str, config: dict) -> dict:
        snapshot = await self.graph.aget_state(config)
        values = dict(snapshot.values)
        suspended = bool(getattr(snapshot, "interrupts", None))
        phase = "SUSPEND" if suspended else values.get("phase", "START")
        row = {
            "id": job_id,
            "tenant_id": values.get("tenant_id"),
            "user_id": values.get("user_id"),
            "scopes": list(values.get("scopes") or []),
            "trace_id": values.get("trace_id", ""),
            "workflow_definition_version": values.get("version", self.settings.workflow_version),
            "current_phase": phase,
            "execution_payload_state": {
                "task": values.get("task"),
                "output": values.get("output"),
                "tool_name": values.get("tool_name"),
                "tool_args": values.get("tool_args"),
                "tool_result": values.get("tool_result"),
                "verification": values.get("verification"),
                "steps": values.get("steps", []),
                "cost_breakdown": values.get("cost_breakdown") or {},
            },
            "is_suspended_for_approval": suspended,
            "accumulated_token_cost": float(values.get("cost", 0)),
        }
        await self.jobs.save(session, row)
        status = "awaiting_human_approval" if suspended else phase
        log.info(
            "job=%s phase=%s status=%s tool=%s cost=%s trace_id=%s",
            job_id,
            phase,
            status,
            values.get("tool_name"),
            row["accumulated_token_cost"],
            row["trace_id"],
        )
        await self._audit_phase(session, row)
        record_outcome(row)
        return row

    async def _audit_phase(self, session, row: dict) -> None:
        phase = row.get("current_phase") or ""
        if row.get("is_suspended_for_approval"):
            return
        payload = row.get("execution_payload_state") or {}
        output = payload.get("output") if isinstance(payload, dict) else None
        code = str((output or {}).get("code") or "") if isinstance(output, dict) else ""
        if phase == "CRITICAL_SECURITY_DENIAL":
            await self._audit(session, row, "DENY", code or "SCOPE")
        elif phase == "CANCELLED":
            await self._audit(session, row, "DENY", "HUMAN_REJECTED")
        elif phase != "RESPOND":
            return
        elif code in {"INSUFFICIENT_EVIDENCE", "VERIFICATION_DENIED", "BUDGET_EXCEEDED"}:
            await self._audit(session, row, "DENY", code)
        else:
            await self._audit(session, row, "ALLOW", "VERIFIED")

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
                "payload": json.dumps(row["execution_payload_state"]),
                "suspended": row["is_suspended_for_approval"],
                "cost": row["accumulated_token_cost"],
            },
        )

    async def get(self, session, job_id: str) -> dict | None:
        return await self._select(session, job_id, for_update=False)

    async def get_for_update(self, session, job_id: str) -> dict | None:
        return await self._select(session, job_id, for_update=True)

    async def list_recent(self, session, *, limit: int = 50) -> list[dict]:
        cap = max(1, min(int(limit), 100))
        found = await session.execute(
            text(
                """
                SELECT id, tenant_id, user_id, trace_id, workflow_definition_version,
                       current_phase, execution_payload_state, is_suspended_for_approval,
                       accumulated_token_cost
                FROM agent_workflow_state
                ORDER BY updated_at DESC
                LIMIT :limit
                """
            ),
            {"limit": cap},
        )
        return [_row(item) for item in found.mappings().all()]

    async def _select(self, session, job_id: str, *, for_update: bool) -> dict | None:
        query = (
            """
            SELECT id, tenant_id, user_id, trace_id, workflow_definition_version,
                   current_phase, execution_payload_state, is_suspended_for_approval,
                   accumulated_token_cost
            FROM agent_workflow_state
            WHERE id = CAST(:id AS uuid)
            FOR UPDATE
            """
            if for_update
            else """
            SELECT id, tenant_id, user_id, trace_id, workflow_definition_version,
                   current_phase, execution_payload_state, is_suspended_for_approval,
                   accumulated_token_cost
            FROM agent_workflow_state
            WHERE id = CAST(:id AS uuid)
            """
        )
        found = await session.execute(text(query), {"id": job_id})
        row = found.mappings().first()
        if row is None:
            return None
        return _row(row)


def _apply_cost(state: WFState, key: str, amount: float, max_cost: float) -> tuple[float, dict, bool]:
    breakdown = dict(state.get("cost_breakdown") or {})
    breakdown[key] = round(float(breakdown.get(key, 0)) + amount, 9)
    cost = round(float(state.get("cost", 0)) + amount, 9)
    return cost, breakdown, cost > max_cost


def decide_verification(
    *,
    tool_name: str,
    tool_result: dict | None,
    citations: list,
    scopes: list[str],
    tools: ToolRegistry,
) -> dict:
    signals = {
        "tool": tool_name,
        "citation_count": len(citations or []),
        "has_tool_result": bool(tool_result),
    }
    if not tools.allows(tool_name, scopes):
        return {"decision": "DENY", "reason": "SCOPE", "signals": signals}
    if not tool_result:
        return {"decision": "DENY", "reason": "TOOL_EMPTY", "signals": signals}
    if tool_name == "file_ticket" and not tool_result.get("ticket_id"):
        return {"decision": "DENY", "reason": "TICKET_SHAPE", "signals": signals}
    if tool_name == "execute_sql_write":
        if tool_result.get("wrote") is False:
            return {"decision": "DENY", "reason": "NO_SANDBOX", "signals": signals}
        if not tool_result.get("id"):
            return {"decision": "DENY", "reason": "SQL_SHAPE", "signals": signals}
    if tool_name == "read_billing" and tool_result.get("balance") is None:
        return {"decision": "DENY", "reason": "BILLING_SHAPE", "signals": signals}
    return {"decision": "ALLOW", "reason": "VERIFIED", "signals": signals}


def _row(row) -> dict:
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

