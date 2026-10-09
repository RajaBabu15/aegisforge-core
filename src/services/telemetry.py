from prometheus_client import Counter, Histogram

TOKEN_CONSUMPTION = Counter(
    "aegisforge_token_consumption_total",
    "LLM tokens recorded for a tenant and model.",
    ["tenant_id", "model"],
)
HALLUCINATION = Counter(
    "aegisforge_llm_ungrounded_total",
    "Generator answers that were not fully contained in retrieved chunks.",
    ["tenant_id", "model"],
)
AGENT_OUTCOME = Counter(
    "aegisforge_agent_outcome_total",
    "Agent job terminal or gate outcomes.",
    ["tenant_id", "outcome"],
)
TOOL_DURATION = Histogram(
    "aegisforge_tool_execution_duration_seconds",
    "Sandboxed tool execution time.",
    ["tool", "outcome"],
)
RATE_LIMITED = Counter(
    "aegisforge_rate_limited_total",
    "Rejected requests that exceeded a sliding window.",
    ["bucket"],
)


def record_outcome(row: dict) -> None:
    tenant = str(row.get("tenant_id") or "unknown")
    if row.get("is_suspended_for_approval"):
        AGENT_OUTCOME.labels(tenant_id=tenant, outcome="awaiting_approval").inc()
        return
    phase = row.get("current_phase") or ""
    payload = row.get("execution_payload_state") or {}
    if isinstance(payload, str):
        import json

        payload = json.loads(payload)
    output = payload.get("output") if isinstance(payload, dict) else None
    code = str((output or {}).get("code") or "") if isinstance(output, dict) else ""
    if phase == "CRITICAL_SECURITY_DENIAL":
        outcome = "scope_denied"
    elif phase == "CANCELLED":
        outcome = "human_rejected"
    elif code == "INSUFFICIENT_EVIDENCE":
        outcome = "insufficient_evidence"
    elif code == "VERIFICATION_DENIED":
        outcome = "verification_denied"
    elif code == "BUDGET_EXCEEDED":
        outcome = "budget_exceeded"
    elif phase == "RESPOND":
        outcome = "completed"
    else:
        return
    AGENT_OUTCOME.labels(tenant_id=tenant, outcome=outcome).inc()
