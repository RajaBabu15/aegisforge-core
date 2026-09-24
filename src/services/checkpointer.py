import asyncpg
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from src.core.config import Settings
from src.services.migrate import asyncpg_dsn

_CHECKPOINT_TABLES = (
    "checkpoint_migrations",
    "checkpoints",
    "checkpoint_blobs",
    "checkpoint_writes",
)


def psycopg_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def open_checkpointer(settings: Settings) -> tuple[AsyncPostgresSaver, object]:
    setup_cm = AsyncPostgresSaver.from_conn_string(psycopg_dsn(settings.migrator_database_url))
    setup_saver = await setup_cm.__aenter__()
    try:
        await setup_saver.setup()
    finally:
        await setup_cm.__aexit__(None, None, None)
    await _grant_checkpoint_tables(settings.migrator_database_url)
    runtime_url = settings.checkpoint_database_url or settings.migrator_database_url
    runtime_cm = AsyncPostgresSaver.from_conn_string(psycopg_dsn(runtime_url))
    runtime = await runtime_cm.__aenter__()
    return runtime, runtime_cm


async def _grant_checkpoint_tables(migrator_url: str) -> None:
    connection = await asyncpg.connect(asyncpg_dsn(migrator_url))
    try:
        await connection.execute(
            """
            DO $$
            BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_checkpoint') THEN
                CREATE ROLE aegis_checkpoint LOGIN PASSWORD 'checkpoint' NOSUPERUSER NOBYPASSRLS;
              END IF;
            END $$;
            """
        )
        for table in _CHECKPOINT_TABLES:
            await connection.execute(f"REVOKE ALL ON TABLE {table} FROM aegis_app")
            await connection.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {table} TO aegis_checkpoint"
            )
    finally:
        await connection.close()
