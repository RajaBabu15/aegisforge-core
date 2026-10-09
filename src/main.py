from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from redis.asyncio import Redis
from sqlalchemy import text
from starlette.responses import JSONResponse

from src.api.middleware.security_isolation import install_security
from src.api.v1 import agents, auth, retrieval, scim
from src.core.config import Settings
from src.db import make_session_factory
from src.services.checkpointer import open_checkpointer
from src.services.hybrid_retrieval import HybridRetriever
from src.services.llm import build_llm
from src.services.migrate import apply_schema, bootstrap
from src.services.revocation import RevocationStore
from src.services.tools_sandbox import ToolRegistry
from src.services.workflow_engine import JobStore, WorkflowEngine


def create_app(settings: Settings | None = None, **overrides) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.auto_migrate:
            await apply_schema(settings.migrator_database_url)
            await bootstrap(settings.migrator_database_url, settings)
        app.state.session_factory = overrides.get("session_factory") or make_session_factory(settings.database_url)
        redis = overrides.get("redis")
        owns_redis = redis is None
        if redis is None:
            redis = Redis.from_url(settings.redis_url, decode_responses=True)
        app.state.redis = redis
        app.state.revocation = RevocationStore(
            redis,
            settings.access_ttl_seconds,
            settings.refresh_ttl_seconds,
        )
        app.state.retrieval = overrides.get("retrieval") or HybridRetriever(settings)
        await app.state.retrieval.hydrate(settings.migrator_database_url)
        app.state.llm = overrides.get("llm") or build_llm(settings)
        app.state.jobs = overrides.get("jobs") or JobStore()
        app.state.tools = overrides.get("tools") or ToolRegistry(tool_sql_database_url=settings.tool_sql_database_url)
        app.state.checkpointer_cm = None
        if "checkpointer" in overrides:
            checkpointer = overrides["checkpointer"]
        else:
            checkpointer, app.state.checkpointer_cm = await open_checkpointer(settings)
        app.state.engine = WorkflowEngine(
            tools=app.state.tools,
            retrieval=app.state.retrieval,
            llm=app.state.llm,
            jobs=app.state.jobs,
            settings=settings,
            checkpointer=checkpointer,
        )
        yield
        if app.state.checkpointer_cm is not None:
            await app.state.checkpointer_cm.__aexit__(None, None, None)
        if owns_redis:
            await redis.aclose()

    app = FastAPI(title="AegisForge", version="2.0.0", lifespan=lifespan)
    app.state.settings = settings
    install_security(app)
    app.include_router(auth.router)
    app.include_router(scim.router)
    app.include_router(agents.router)
    app.include_router(retrieval.router)

    @app.get("/health")
    async def health(request: Request) -> dict:
        return {"status": "ok", "trace_id": getattr(request.state, "trace_id", "")}

    @app.get("/ready")
    async def ready(request: Request) -> JSONResponse:
        checks = {"postgres": "down", "redis": "down", "qdrant": "down"}
        try:
            async with request.app.state.session_factory() as session:
                await session.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
        except Exception:
            pass
        try:
            await request.app.state.redis.ping()
            checks["redis"] = "ok"
        except Exception:
            pass
        try:
            checks["qdrant"] = request.app.state.retrieval.ping()
        except Exception:
            pass
        ok = all(value == "ok" for value in checks.values())
        return JSONResponse(
            {
                "status": "ok" if ok else "down",
                "checks": checks,
                "trace_id": getattr(request.state, "trace_id", ""),
            },
            status_code=200 if ok else 503,
        )

    return app
