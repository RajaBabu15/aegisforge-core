from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str
    message: str
    trace_id: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class CreateKeyRequest(BaseModel):
    scopes: list[str] = Field(min_length=1)


class CreateKeyResponse(BaseModel):
    id: str
    key_prefix: str
    secret: str
    allowed_scopes: list[str]


class JobCreate(BaseModel):
    task: str = Field(min_length=1)


class JobView(BaseModel):
    id: str
    phase: str
    status: str
    tool_name: str | None = None
    is_suspended_for_approval: bool
    trace_id: str
    workflow_definition_version: str
    output: dict | str | None = None
    accumulated_token_cost: float


class IngestDocument(BaseModel):
    title: str = Field(min_length=1)
    content: str = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    line_start: int = Field(default=1, ge=1)
    line_end: int = Field(default=1, ge=1)


class ApprovalBody(BaseModel):
    decision: str


class RetrievalQuery(BaseModel):
    query: str = Field(min_length=1)


class Citation(BaseModel):
    doc_id: str
    page: int
    line_range: str
    sha256: str
    content: str
    score: float


class RetrievalResponse(BaseModel):
    citations: list[Citation]
