import asyncio
import contextlib
import json
import uuid

import pytest
from opentelemetry import trace
from sqlalchemy import text

from src.core.config import Settings
from src.db import make_session_factory
from src.main import _watch_disconnects
from src.services.hybrid_retrieval import HybridRetriever
from src.services.revocation import RevocationStore
from src.services.sessions import LiveSessions
from src.services.telemetry import parent_context


def test_resumed_span_keeps_the_original_trace_id() -> None:
    trace_id = "ab" * 16
    context = parent_context(trace_id)
    span = trace.get_current_span(context)
    assert format(span.get_span_context().trace_id, "032x") == trace_id


async def test_revocation_closes_the_live_socket() -> None:
    import fakeredis.aioredis

    class Socket:
        def __init__(self) -> None:
            self.code = None

        async def close(self, code: int = 1000, reason: str | None = None) -> None:
            self.code = code
            self.reason = reason

    hub = LiveSessions()
    socket = Socket()
    await hub.add("user-1", socket)
    store = RevocationStore(fakeredis.aioredis.FakeRedis(decode_responses=True), 30, 60)
    store.on_revoke = hub.close_user
    await store.remember_access("user-1", "jti-1")
    await store.revoke_families("user-1", ["family-1"], "SCIM_DEACTIVATED")
    assert socket.code == 4401
    assert await store.is_revoked("jti-1", "family-1")


async def test_malformed_tenant_id_is_rejected_before_it_reaches_postgres() -> None:
    from src.api.middleware.security_isolation import _set_tenant
    from src.core.errors import AegisError

    with pytest.raises(AegisError) as exc:
        await _set_tenant(session=None, tenant_id="not-a-uuid")
    assert exc.value.status == 401


class _FlakyPubSub:
    def __init__(self, parent: "_FlakyRedis") -> None:
        self.parent = parent

    async def psubscribe(self, pattern: str) -> None:
        del pattern

    async def listen(self):
        if self.parent.fail_times > 0:
            self.parent.fail_times -= 1
            raise ConnectionError("boom")
        for message in self.parent.messages:
            yield message
        while True:
            await asyncio.sleep(3600)

    async def aclose(self) -> None:
        pass


class _FlakyRedis:
    def __init__(self, fail_times: int, messages: list[dict]) -> None:
        self.fail_times = fail_times
        self.messages = messages
        self.pubsub_calls = 0

    def pubsub(self) -> _FlakyPubSub:
        self.pubsub_calls += 1
        return _FlakyPubSub(self)


async def test_disconnect_subscriber_retries_after_a_transient_failure() -> None:
    class Socket:
        def __init__(self) -> None:
            self.code = None

        async def close(self, code: int = 1000, reason: str | None = None) -> None:
            self.code = code
            self.reason = reason

    hub = LiveSessions()
    socket = Socket()
    await hub.add("user-1", socket)
    redis = _FlakyRedis(
        fail_times=1,
        messages=[{"type": "pmessage", "data": json.dumps({"user_id": "user-1", "reason": "test"})}],
    )
    task = asyncio.create_task(_watch_disconnects(redis, hub))
    try:
        await asyncio.sleep(1.2)
        assert redis.pubsub_calls == 2
        assert socket.code == 4401
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.mark.integration
async def test_query_loads_citation_text_from_postgres(settings, tmp_path) -> None:
    local = Settings(
        _env_file=None,
        aegis_jwt_secret="x" * 32,
        aegis_approval_secret="y" * 32,
        database_url=settings.database_url,
        migrator_database_url=settings.migrator_database_url,
        qdrant_url=":memory:",
        tantivy_dir=str(tmp_path),
    )
    retriever = HybridRetriever(local)
    tenant = str(uuid.uuid4())
    content = "Fault AF4242 clears only when the operator runs RESET-4242."
    factory = make_session_factory(settings.database_url)
    async with factory() as session:
        await session.begin()
        await session.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"), {"tenant": tenant})
        await session.execute(
            text("INSERT INTO organizations (id, name, domain_lock) VALUES (CAST(:id AS uuid), 'T', :domain)"),
            {"id": tenant, "domain": f"{tenant}.example"},
        )
        await retriever.ingest_durable(
            session,
            tenant_id=tenant,
            title="Runbook",
            content=content,
            page=2,
            line_start=4,
            line_end=9,
        )
        await session.commit()
    retriever.meta.clear()
    async with factory() as session:
        await session.begin()
        await session.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"), {"tenant": tenant})
        found = await retriever.query(tenant, "AF4242", session)
        await session.rollback()
    assert found
    assert found[0].content == content
    assert found[0].page == 2
    assert found[0].line_range == "4-9"
    assert len(found[0].sha256) == 64
