from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import Settings


def make_session_factory(database_url: str) -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(database_url, pool_pre_ping=True)
    return async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def tenant_transaction(
    factory: async_sessionmaker[AsyncSession],
    tenant_id: str | None,
) -> AsyncIterator[AsyncSession]:
    async with factory() as session:
        async with session.begin():
            if tenant_id is not None:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id', :tenant, true)"),
                    {"tenant": tenant_id},
                )
            yield session


def psycopg_dsn(settings: Settings) -> str:
    return settings.database_url.replace("postgresql+asyncpg://", "postgresql://")


def migrator_psycopg_dsn(settings: Settings) -> str:
    return settings.migrator_database_url.replace("postgresql+asyncpg://", "postgresql://")
