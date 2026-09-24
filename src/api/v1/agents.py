import json
import uuid

from fastapi import APIRouter, Request

from src.core.errors import AegisError
from src.core.security import APPROVAL_WINDOW_SECONDS, sha256_hex, verify_approval
from src.models.schemas import JobCreate, JobView

router = APIRouter(prefix="/api/v1")


@router.get("/audit")
async def recent_audit(request: Request) -> dict:
    found = await request.state.session.execute(
        text(
            """
            SELECT action_type, execution_decision, rejection_reason_code, resource_identifier
            FROM system_audit_ledger
            ORDER BY timestamp DESC
            LIMIT 8
            """
        )
    )
    return {"events": [dict(row) for row in found.mappings().all()]}


@router.post("/agents/jobs", response_model=JobView)
async def start_job(request: Request, payload: JobCreate) -> JobView:
    principal = request.state.principal
    job_id = str(uuid.uuid4())
    row = await request.app.state.engine.start(
        request.state.session,
        job_id=job_id,
        task=payload.task,
        principal=principal,
        trace_id=getattr(request.state, "trace_id", ""),
    )
    return _view(row)


@router.get("/agents/jobs/{job_id}", response_model=JobView)
async def get_job(request: Request, job_id: str) -> JobView:
    row = await request.app.state.jobs.get(request.state.session, job_id)
    if row is None:
        raise AegisError(404, "NOT_FOUND", "job not found")
    return _view(row)


@router.post("/agents/jobs/{job_id}/approve", response_model=JobView)
async def approve_job(request: Request, job_id: str) -> JobView:
    raw = await request.body()
    settings = request.app.state.settings
    timestamp = request.headers.get("x-aegis-timestamp", "")
    signature = request.headers.get("x-aegis-signature", "")
    verify_approval(settings.aegis_approval_secret, timestamp, job_id, raw, signature)
    nonce_key = "af:approval:used:" + sha256_hex(f"{job_id}:{timestamp}:{signature}")
    first_use = await request.app.state.redis.set(nonce_key, "1", nx=True, ex=APPROVAL_WINDOW_SECONDS + 5)
    if not first_use:
        raise AegisError(401, "APPROVAL_REPLAYED", "approval signature already used")
    principal = request.state.principal
    if "agents:approve" not in principal.scopes:
        raise AegisError(403, "FORBIDDEN", "agents:approve is required")
    try:
        decision = json.loads(raw.decode() or "{}").get("decision")
    except json.JSONDecodeError as exc:
        raise AegisError(400, "INVALID_REQUEST", "approval body must be JSON") from exc
    if decision not in {"APPROVED", "REJECTED"}:
        raise AegisError(400, "INVALID_REQUEST", "decision must be APPROVED or REJECTED")
    existing = await request.app.state.jobs.get(request.state.session, job_id)
    if existing is None:
        raise AegisError(404, "NOT_FOUND", "job not found")
    if existing["workflow_definition_version"] != settings.workflow_version:
        raise AegisError(409, "VERSION_MISMATCH", "workflow definition version changed; approval cannot be applied")
    row = await request.app.state.engine.resume(request.state.session, job_id, decision)
    return _view(row)


def _view(row: dict) -> JobView:
    payload = row.get("execution_payload_state") or {}
    if isinstance(payload, str):
        payload = json.loads(payload)
    phase = row["current_phase"]
    suspended = bool(row["is_suspended_for_approval"])
    return JobView(
        id=str(row["id"]),
        phase=phase,
        status="awaiting_human_approval" if suspended or phase == "SUSPEND" else phase,
        is_suspended_for_approval=suspended,
        trace_id=row.get("trace_id") or "",
        tool_name=payload.get("tool_name"),
        workflow_definition_version=row["workflow_definition_version"],
        output=payload.get("output"),
        accumulated_token_cost=float(row.get("accumulated_token_cost") or 0),
    )
