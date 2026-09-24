from fastapi import APIRouter, Request

from src.core.errors import AegisError
from src.models.schemas import Citation, IngestDocument, RetrievalQuery, RetrievalResponse
from src.services.hybrid_retrieval import RetrievalSideError

router = APIRouter(prefix="/api/v1/retrieval")


@router.post("/documents")
async def ingest_document(request: Request, payload: IngestDocument) -> dict:
    principal = request.state.principal
    if "retrieval:read" not in principal.scopes:
        raise AegisError(403, "FORBIDDEN", "retrieval:read is required")
    if payload.line_end < payload.line_start:
        raise AegisError(400, "INVALID_REQUEST", "line_end precedes line_start")
    doc_id = await request.app.state.retrieval.ingest_durable(
        request.state.session,
        tenant_id=principal.tenant_id,
        title=payload.title,
        content=payload.content,
        page=payload.page,
        line_start=payload.line_start,
        line_end=payload.line_end,
    )
    return {"doc_id": doc_id}


@router.post("/query", response_model=RetrievalResponse)
async def query(request: Request, payload: RetrievalQuery) -> RetrievalResponse:
    principal = request.state.principal
    if "retrieval:read" not in principal.scopes:
        raise AegisError(403, "FORBIDDEN", "retrieval:read is required")
    try:
        citations = await request.app.state.retrieval.query(
            principal.tenant_id,
            payload.query,
            session=request.state.session,
        )
    except RetrievalSideError as exc:
        raise AegisError(503, "RETRIEVAL_SIDE_FAILED", f"{exc.side} search failed") from exc
    if not citations:
        raise AegisError(422, "INSUFFICIENT_EVIDENCE", "reranker score is below the confidence floor")
    return RetrievalResponse(
        citations=[
            Citation(
                doc_id=item.doc_id,
                page=item.page,
                line_range=item.line_range,
                sha256=item.sha256,
                content=item.content,
                score=item.score,
            )
            for item in citations
        ]
    )
