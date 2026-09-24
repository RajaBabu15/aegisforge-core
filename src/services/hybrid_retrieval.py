import hashlib
import math
import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import tantivy
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, FieldCondition, Filter, MatchValue, PointStruct, VectorParams

from src.services.telemetry import tracer

_TOKEN = re.compile(r"[a-z0-9]+")
_DIM = 384


class RetrievalSideError(Exception):
    def __init__(self, side: str, cause: Exception) -> None:
        super().__init__(f"{side} search failed")
        self.side = side
        self.cause = cause


@dataclass
class Citation:
    doc_id: str
    page: int
    line_range: str
    sha256: str
    content: str
    score: float
    chunk_id: str


def rrf(rankings: list[list[str]], k: int = 60) -> list[tuple[str, float]]:
    scores: dict[str, float] = defaultdict(float)
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] += 1.0 / (k + rank)
    return sorted(scores.items(), key=lambda item: item[1], reverse=True)


def hash_embed(text: str) -> list[float]:
    vector = [0.0] * _DIM
    for token in _TOKEN.findall(text.lower()):
        digest = hashlib.sha256(token.encode()).digest()
        index = int.from_bytes(digest[:2], "big") % _DIM
        sign = 1.0 if digest[2] % 2 == 0 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector)) or 1.0
    return [value / norm for value in vector]


def lexical_score(query: str, content: str) -> float:
    query_tokens = set(_TOKEN.findall(query.lower()))
    if not query_tokens:
        return 0.0
    content_tokens = set(_TOKEN.findall(content.lower()))
    return len(query_tokens & content_tokens) / len(query_tokens)


class HybridRetriever:
    def __init__(self, settings) -> None:
        self.settings = settings
        self.k = settings.rrf_k
        self.candidate_limit = settings.rerank_candidates
        self.min_score = settings.rerank_min_score
        if settings.qdrant_url == ":memory:":
            self.qdrant = QdrantClient(":memory:")
        else:
            self.qdrant = QdrantClient(url=settings.qdrant_url)
        self._ensure_collection()
        self.tantivy_dir = Path(settings.tantivy_dir)
        self.tantivy_dir.mkdir(parents=True, exist_ok=True)
        self._indexes: dict[str, tantivy.Index] = {}
        self._locks: dict[str, threading.Lock] = {}
        self.meta: dict[str, dict] = {}
        self.embedder = settings.embedder
        self.reranker = settings.reranker

    def _ensure_collection(self) -> None:
        if self.qdrant.collection_exists("chunks"):
            return
        self.qdrant.create_collection(
            "chunks",
            vectors_config=VectorParams(size=_DIM, distance=Distance.COSINE),
        )

    def _embed(self, text: str) -> list[float]:
        if self.embedder == "fastembed":
            from fastembed import TextEmbedding

            model = TextEmbedding("BAAI/bge-small-en-v1.5")
            return list(next(model.embed([text])))
        return hash_embed(text)

    def _score(self, query: str, content: str) -> float:
        if self.reranker == "cross-encoder":
            from sentence_transformers import CrossEncoder

            model = CrossEncoder(self.settings.reranker_model)
            return float(model.predict([(query, content)])[0])
        return lexical_score(query, content)

    def _index(self, tenant_id: str) -> tantivy.Index:
        if tenant_id in self._indexes:
            return self._indexes[tenant_id]
        path = self.tantivy_dir / tenant_id
        path.mkdir(parents=True, exist_ok=True)
        if any(path.iterdir()):
            index = tantivy.Index.open(str(path))
        else:
            builder = tantivy.SchemaBuilder()
            builder.add_text_field("chunk_id", stored=True, tokenizer_name="raw")
            builder.add_text_field("body", stored=True)
            index = tantivy.Index(builder.build(), path=str(path))
        self._indexes[tenant_id] = index
        self._locks[tenant_id] = threading.Lock()
        return index

    def ingest(
        self,
        *,
        tenant_id: str,
        doc_id: str,
        page: int,
        line_start: int,
        line_end: int,
        content: str,
    ) -> str:
        import uuid

        chunk_id = str(uuid.uuid4())
        digest = hashlib.sha256(content.encode()).hexdigest()
        self._index_chunk(
            tenant_id=tenant_id,
            doc_id=doc_id,
            chunk_id=chunk_id,
            page=page,
            line_start=line_start,
            line_end=line_end,
            content=content,
            digest=digest,
            write_sparse=True,
        )
        return chunk_id

    def _index_chunk(
        self,
        *,
        tenant_id: str,
        doc_id: str,
        chunk_id: str,
        page: int,
        line_start: int,
        line_end: int,
        content: str,
        digest: str,
        write_sparse: bool,
    ) -> None:
        self.meta[chunk_id] = {
            "doc_id": doc_id,
            "page": page,
            "line_range": f"{line_start}-{line_end}",
            "sha256": digest,
            "content": content,
            "tenant_id": tenant_id,
            "chunk_id": chunk_id,
        }
        self.qdrant.upsert(
            collection_name="chunks",
            points=[
                PointStruct(
                    id=chunk_id,
                    vector=self._embed(content),
                    payload={"tenant_id": tenant_id, "chunk_id": chunk_id},
                )
            ],
        )
        if not write_sparse:
            return
        index = self._index(tenant_id)
        with self._locks[tenant_id]:
            writer = index.writer()
            writer.add_document(tantivy.Document(chunk_id=chunk_id, body=content))
            writer.commit()
            index.reload()

    async def _meta_from_db(self, session, chunk_id: str) -> dict | None:
        import uuid

        from sqlalchemy import text

        try:
            uuid.UUID(chunk_id)
        except ValueError:
            return None
        found = await session.execute(
            text(
                """
                SELECT d.id::text AS doc_id, c.page, c.line_start, c.line_end,
                       c.sha256, c.content, c.tenant_id::text AS tenant_id, c.qdrant_point_id::text AS chunk_id
                FROM document_chunks c
                JOIN documents d ON d.id = c.document_id
                WHERE c.qdrant_point_id = CAST(:id AS uuid)
                """
            ),
            {"id": chunk_id},
        )
        row = found.mappings().first()
        if row is None:
            return None
        return {
            "doc_id": row["doc_id"],
            "page": row["page"],
            "line_range": f"{row['line_start']}-{row['line_end']}",
            "sha256": str(row["sha256"]).strip(),
            "content": row["content"],
            "tenant_id": row["tenant_id"],
            "chunk_id": row["chunk_id"],
        }

    async def ingest_durable(
        self,
        session,
        *,
        tenant_id: str,
        title: str,
        content: str,
        page: int,
        line_start: int,
        line_end: int,
    ) -> str:
        import uuid

        from sqlalchemy import text

        doc_id = str(uuid.uuid4())
        chunk_id = str(uuid.uuid4())
        digest = hashlib.sha256(content.encode()).hexdigest()
        await session.execute(
            text(
                """
                INSERT INTO documents (id, tenant_id, title, sha256)
                VALUES (CAST(:id AS uuid), CAST(:tenant AS uuid), :title, :sha)
                """
            ),
            {"id": doc_id, "tenant": tenant_id, "title": title, "sha": digest},
        )
        await session.execute(
            text(
                """
                INSERT INTO document_chunks (
                    id, tenant_id, document_id, page, line_start, line_end, sha256, content, qdrant_point_id
                ) VALUES (
                    CAST(:id AS uuid), CAST(:tenant AS uuid), CAST(:doc AS uuid),
                    :page, :line_start, :line_end, :sha, :content, CAST(:point AS uuid)
                )
                """
            ),
            {
                "id": chunk_id,
                "tenant": tenant_id,
                "doc": doc_id,
                "page": page,
                "line_start": line_start,
                "line_end": line_end,
                "sha": digest,
                "content": content,
                "point": chunk_id,
            },
        )
        self._index_chunk(
            tenant_id=tenant_id,
            doc_id=doc_id,
            chunk_id=chunk_id,
            page=page,
            line_start=line_start,
            line_end=line_end,
            content=content,
            digest=digest,
            write_sparse=True,
        )
        return doc_id

    async def hydrate(self, migrator_url: str) -> None:
        import asyncpg

        from src.services.migrate import asyncpg_dsn

        try:
            connection = await asyncpg.connect(asyncpg_dsn(migrator_url))
        except Exception:
            return
        try:
            rows = await connection.fetch(
                """
                SELECT c.tenant_id, c.page, c.line_start, c.line_end, c.sha256, c.content,
                       c.qdrant_point_id, d.id AS doc_id
                FROM document_chunks c
                JOIN documents d ON d.id = c.document_id
                """
            )
        except Exception:
            return
        finally:
            await connection.close()
        write_sparse: dict[str, bool] = {}
        for row in rows:
            tenant_id = str(row["tenant_id"])
            if tenant_id not in write_sparse:
                path = self.tantivy_dir / tenant_id
                write_sparse[tenant_id] = not (path.exists() and any(path.iterdir()))
            self._index_chunk(
                tenant_id=tenant_id,
                doc_id=str(row["doc_id"]),
                chunk_id=str(row["qdrant_point_id"]),
                page=row["page"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                content=row["content"],
                digest=str(row["sha256"]).strip(),
                write_sparse=write_sparse[tenant_id],
            )

    async def query(self, tenant_id: str, query: str, session=None) -> list[Citation]:
        import asyncio

        with tracer().start_as_current_span("retrieval.rrf"):
            dense, sparse = await asyncio.gather(
                asyncio.to_thread(self._dense, tenant_id, query),
                asyncio.to_thread(self._sparse, tenant_id, query),
            )
        fused = rrf([dense, sparse], self.k)[: self.candidate_limit]
        with tracer().start_as_current_span("retrieval.rerank"):
            ranked: list[Citation] = []
            for chunk_id, _fusion in fused:
                meta = self.meta.get(chunk_id)
                if meta is None and session is not None:
                    meta = await self._meta_from_db(session, chunk_id)
                    if meta is not None:
                        self.meta[chunk_id] = meta
                if meta is None or meta["tenant_id"] != tenant_id:
                    continue
                score = self._score(query, meta["content"])
                if score < self.min_score:
                    continue
                ranked.append(Citation(score=score, **{key: meta[key] for key in ("doc_id", "page", "line_range", "sha256", "content", "chunk_id")}))
        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked

    def _dense(self, tenant_id: str, query: str) -> list[str]:
        try:
            points = self.qdrant.query_points(
                collection_name="chunks",
                query=self._embed(query),
                query_filter=Filter(
                    must=[FieldCondition(key="tenant_id", match=MatchValue(value=tenant_id))]
                ),
                limit=self.candidate_limit,
            )
        except Exception as exc:
            raise RetrievalSideError("qdrant", exc) from exc
        return [str(point.id) for point in points.points]

    def _sparse(self, tenant_id: str, query: str) -> list[str]:
        try:
            index = self._index(tenant_id)
            index.reload()
            parsed = index.parse_query(query, ["body"])
            hits = index.searcher().search(parsed, self.candidate_limit)
            found = []
            searcher = index.searcher()
            for _score, address in hits.hits:
                document = searcher.doc(address)
                found.append(document.get_first("chunk_id"))
            return found
        except Exception as exc:
            raise RetrievalSideError("tantivy", exc) from exc
