import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from langgraph.checkpoint.memory import MemorySaver

os.environ.setdefault("AEGIS_JWT_SECRET", "x" * 32)
os.environ.setdefault("AEGIS_APPROVAL_SECRET", "y" * 32)
os.environ.setdefault("AEGIS_BOOTSTRAP_EMAIL", "dev@demo.aegisforge.local")
os.environ.setdefault("AEGIS_BOOTSTRAP_PASSWORD", "developer-password")
os.environ.setdefault("AEGIS_BOOTSTRAP_ADMIN_EMAIL", "admin@demo.aegisforge.local")
os.environ.setdefault("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "admin-password")
os.environ.setdefault("AEGIS_BOOTSTRAP_B_EMAIL", "dev@other.aegisforge.local")
os.environ.setdefault("AEGIS_BOOTSTRAP_B_PASSWORD", "other-developer-password")
os.environ.setdefault("AEGIS_BOOTSTRAP_B_ADMIN_EMAIL", "admin@other.aegisforge.local")
os.environ.setdefault("AEGIS_BOOTSTRAP_B_ADMIN_PASSWORD", "other-admin-password")
os.environ.setdefault("AEGIS_SCIM_TOKEN", "scim-demo-token-value-0123456789")
os.environ["AEGIS_AUTO_MIGRATE"] = "1"

from src.core.config import Settings
from src.main import create_app
from src.services.migrate import apply_schema, bootstrap


def _async(url: str) -> str:
    if url.startswith("postgresql+asyncpg://"):
        return url
    return "postgresql+asyncpg://" + url[len("postgresql://") :]


def _app_url(migrator: str) -> str:
    if "postgresql://postgres:@" in migrator:
        return migrator.replace("postgresql://postgres:@", "postgresql://aegis_app:app@")
    return migrator.replace("postgresql://postgres@", "postgresql://aegis_app:app@")


@pytest.fixture(scope="session")
def pg_uris():
    import asyncio

    migrator_env = os.environ.get("MIGRATOR_DATABASE_URL")
    app_env = os.environ.get("DATABASE_URL")
    if migrator_env and app_env and migrator_env.startswith("postgresql"):
        asyncio.run(apply_schema(migrator_env))
        yield {"migrator": migrator_env, "app": app_env}
        return

    import pgserver

    data = Path(tempfile.mkdtemp(prefix="aegis-pg-"))
    server = pgserver.get_server(data, cleanup_mode="delete")
    admin = server.get_uri()

    async def prepare() -> tuple[str, str]:
        import asyncpg

        connection = await asyncpg.connect(admin)
        try:
            await connection.execute("CREATE DATABASE aegis")
        except asyncpg.DuplicateDatabaseError:
            pass
        finally:
            await connection.close()
        migrator = admin.replace("/postgres?", "/aegis?")
        await apply_schema(migrator)
        return migrator, _app_url(migrator)

    migrator, app_url = asyncio.run(prepare())
    yield {"migrator": _async(migrator), "app": _async(app_url)}


@pytest.fixture(scope="session")
def settings(pg_uris) -> Settings:
    os.environ["DATABASE_URL"] = pg_uris["app"]
    os.environ["MIGRATOR_DATABASE_URL"] = pg_uris["migrator"]
    return Settings(
        _env_file=None,
        aegis_jwt_secret="x" * 32,
        aegis_approval_secret="y" * 32,
        database_url=pg_uris["app"],
        migrator_database_url=pg_uris["migrator"],
        auto_migrate=True,
        qdrant_url=":memory:",
        tantivy_dir=tempfile.mkdtemp(prefix="aegis-tantivy-"),
        bootstrap_email="dev@demo.aegisforge.local",
        bootstrap_password="developer-password",
        bootstrap_admin_email="admin@demo.aegisforge.local",
        bootstrap_admin_password="admin-password",
        bootstrap_b_email="dev@other.aegisforge.local",
        bootstrap_b_password="other-developer-password",
        bootstrap_b_admin_email="admin@other.aegisforge.local",
        bootstrap_b_admin_password="other-admin-password",
        scim_token="scim-demo-token-value-0123456789",
    )


@pytest_asyncio.fixture
async def app(settings):
    try:
        import fakeredis.aioredis as fakeredis_async

        redis = fakeredis_async.FakeRedis(decode_responses=True)
    except Exception:
        from fakeredis import FakeAsyncRedis

        redis = FakeAsyncRedis(decode_responses=True)
    await bootstrap(settings.migrator_database_url, settings)
    application = create_app(
        settings,
        redis=redis,
        checkpointer=MemorySaver(),
    )
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        yield http
