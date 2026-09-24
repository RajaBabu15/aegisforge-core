import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from redis.asyncio import Redis
from starlette.responses import Response

from src.api.middleware.otel_telemetry import install_telemetry
from src.api.middleware.security_isolation import install_security
from src.api.v1 import agents, auth, console, retrieval, scim, sessions
from src.core.config import Settings
from src.db import make_session_factory
from src.services.checkpointer import open_checkpointer
from src.services.hybrid_retrieval import HybridRetriever
from src.services.llm import build_llm
from src.services.migrate import apply_schema, bootstrap
from src.services.revocation import RevocationStore
from src.services.sessions import LiveSessions
from src.services.telemetry import configure_tracing
from src.services.tools_sandbox import ToolRegistry
from src.services.workflow_engine import JobStore, WorkflowEngine


def create_app(settings: Settings | None = None, **overrides) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_tracing(
            settings.otlp_endpoint,
            _langfuse(settings),
        )
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
        app.state.sessions = overrides.get("sessions") or LiveSessions()
        app.state.revocation.on_revoke = app.state.sessions.close_user
        disconnect_task = asyncio.create_task(_watch_disconnects(redis, app.state.sessions))
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
        disconnect_task.cancel()
        try:
            await disconnect_task
        except asyncio.CancelledError:
            pass
        if app.state.checkpointer_cm is not None:
            await app.state.checkpointer_cm.__aexit__(None, None, None)
        if owns_redis:
            await redis.aclose()

    app = FastAPI(title="AegisForge", version="2.0.0", lifespan=lifespan)
    app.state.settings = settings
    install_security(app)
    install_telemetry(app)
    app.include_router(console.router)
    app.include_router(auth.router)
    app.include_router(scim.router)
    app.include_router(agents.router)
    app.include_router(retrieval.router)
    app.include_router(sessions.router)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


_log = logging.getLogger("aegisforge.sessions")


async def _watch_disconnects(redis, sessions: LiveSessions) -> None:
    backoff = 1.0
    while True:
        pubsub = None
        try:
            pubsub = redis.pubsub()
            await pubsub.psubscribe("af:user:disconnect:*")
            backoff = 1.0
            async for message in pubsub.listen():
                if message.get("type") != "pmessage":
                    continue
                try:
                    payload = json.loads(message["data"])
                    await sessions.close_user(payload["user_id"], payload.get("reason", "revoked"))
                except Exception:
                    _log.exception("failed to process disconnect message: %r", message)
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("disconnect subscriber lost its connection, retrying in %.1fs", backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
        finally:
            if pubsub is not None:
                try:
                    await pubsub.aclose()
                except Exception:
                    pass


def _langfuse(settings: Settings) -> tuple[str, str, str] | None:
    if settings.langfuse_host and settings.langfuse_public_key and settings.langfuse_secret_key:
        return settings.langfuse_host, settings.langfuse_public_key, settings.langfuse_secret_key
    return None
