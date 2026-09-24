from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="docker/local.env", extra="ignore", populate_by_name=True)

    aegis_jwt_secret: str
    aegis_approval_secret: str
    database_url: str = "postgresql+asyncpg://aegis_app:app@localhost:5432/aegis"
    migrator_database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/aegis"
    checkpoint_database_url: str | None = Field(
        None, validation_alias=AliasChoices("AEGIS_CHECKPOINT_DATABASE_URL", "CHECKPOINT_DATABASE_URL")
    )
    agent_max_cost: float = Field(1.0, validation_alias=AliasChoices("AEGIS_AGENT_MAX_COST", "AGENT_MAX_COST"))
    redis_url: str = "redis://localhost:6379/0"
    tool_sql_database_url: str = Field(
        "postgresql+asyncpg://aegis_tool_sql:tool@localhost:5432/aegis",
        validation_alias=AliasChoices("AEGIS_TOOL_SQL_DATABASE_URL", "TOOL_SQL_DATABASE_URL"),
    )
    qdrant_url: str = ":memory:"
    tantivy_dir: str = Field("./data/tantivy", validation_alias=AliasChoices("AEGIS_TANTIVY_DIR", "TANTIVY_DIR"))
    auto_migrate: bool = Field(False, validation_alias=AliasChoices("AEGIS_AUTO_MIGRATE", "AUTO_MIGRATE"))
    access_ttl_seconds: int = 900
    refresh_ttl_seconds: int = 60 * 60 * 24 * 30
    rrf_k: int = 60
    rerank_candidates: int = 20
    rerank_min_score: float = 0.2
    embedder: str = "hash"
    reranker: str = "lexical"
    reranker_model: str = "BAAI/bge-reranker-base"
    llm: str = "stub"
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str = "stub-echo"
    bootstrap_email: str | None = Field(None, validation_alias=AliasChoices("AEGIS_BOOTSTRAP_EMAIL", "BOOTSTRAP_EMAIL"))
    bootstrap_password: str | None = Field(None, validation_alias=AliasChoices("AEGIS_BOOTSTRAP_PASSWORD", "BOOTSTRAP_PASSWORD"))
    bootstrap_admin_email: str | None = Field(
        None, validation_alias=AliasChoices("AEGIS_BOOTSTRAP_ADMIN_EMAIL", "BOOTSTRAP_ADMIN_EMAIL")
    )
    bootstrap_admin_password: str | None = Field(
        None, validation_alias=AliasChoices("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_ADMIN_PASSWORD")
    )
    scim_token: str | None = Field(None, validation_alias=AliasChoices("AEGIS_SCIM_TOKEN", "SCIM_TOKEN"))
    oauth_client_id: str = Field("aegis-demo", validation_alias=AliasChoices("AEGIS_OAUTH_CLIENT_ID", "OAUTH_CLIENT_ID"))
    oauth_redirect_uri: str = Field(
        "http://127.0.0.1:8765/callback",
        validation_alias=AliasChoices("AEGIS_OAUTH_REDIRECT_URI", "OAUTH_REDIRECT_URI"),
    )
    workflow_version: str = "2.0.0"
    langfuse_host: str | None = None
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None
    otlp_endpoint: str | None = Field(None, validation_alias=AliasChoices("AEGIS_OTLP_ENDPOINT", "OTLP_ENDPOINT"))
    bootstrap_domain: str = Field(
        "demo.aegisforge.local", validation_alias=AliasChoices("AEGIS_BOOTSTRAP_DOMAIN", "BOOTSTRAP_DOMAIN")
    )

    @field_validator("aegis_jwt_secret", "aegis_approval_secret")
    @classmethod
    def secret_min_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) < 32:
            raise ValueError("secret must be at least 32 bytes")
        return value
