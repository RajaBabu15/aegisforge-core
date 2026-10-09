import json
from pathlib import Path

import pytest

from src.core.config import Settings
from src.services.hybrid_retrieval import HybridRetriever
from src.services.llm import StubLLM

_ROOT = Path(__file__).resolve().parent
_DATA = json.loads((_ROOT / "dataset.json").read_text())
_THRESHOLDS = json.loads((_ROOT / "thresholds.json").read_text())


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        aegis_jwt_secret="x" * 32,
        aegis_approval_secret="y" * 32,
        qdrant_url=":memory:",
        tantivy_dir=str(tmp_path),
        rerank_min_score=0.2,
    )


@pytest.fixture
def retriever(tmp_path: Path) -> HybridRetriever:
    retriever = HybridRetriever(_settings(tmp_path))
    for doc in _DATA["corpus"]:
        retriever.ingest(
            tenant_id="tenant-a",
            doc_id=doc["doc_id"],
            page=doc["page"],
            line_start=doc["line_start"],
            line_end=doc["line_end"],
            content=doc["content"],
        )
    for doc in _DATA["corpus_b"]:
        retriever.ingest(
            tenant_id="tenant-b",
            doc_id=doc["doc_id"],
            page=doc["page"],
            line_start=doc["line_start"],
            line_end=doc["line_end"],
            content=doc["content"],
        )
    return retriever


async def test_hard_negatives_and_synonyms(retriever: HybridRetriever) -> None:
    llm = StubLLM()
    hits = 0
    faithful = 0
    near_ok = 0
    near_total = 0
    scored = [row for row in _DATA["queries"] if row["kind"] != "isolation"]
    for row in scored:
        citations = await retriever.query("tenant-a", row["query"])
        ids = [item.doc_id for item in citations[:5]]
        if any(doc_id in ids for doc_id in row["relevant_doc_ids"]):
            hits += 1
        blob = " ".join(item.content for item in citations)
        answer, _tokens = await llm.complete(row["query"], [item.__dict__ for item in citations], "stub-echo")
        facts = row.get("expected_facts") or []
        if facts and all(fact in answer for fact in facts):
            faithful += 1
        if row["kind"] == "near_miss":
            near_total += 1
            forbidden = row.get("forbidden_facts") or []
            top = citations[0].content if citations else ""
            if all(fact not in top for fact in forbidden) and all(fact in top for fact in facts):
                near_ok += 1
    total = len(scored)
    scores = {
        "hit_rate": hits / total,
        "faithfulness": faithful / total,
        "near_miss_ok": near_ok / near_total if near_total else 1.0,
    }
    for metric, value in scores.items():
        assert value >= _THRESHOLDS[metric], f"{metric} {value} < {_THRESHOLDS[metric]} {scores}"


async def test_tenant_b_marker_never_appears_for_tenant_a(retriever: HybridRetriever) -> None:
    citations = await retriever.query("tenant-a", "TENANT-B-ONLY")
    blob = " ".join(item.content for item in citations)
    assert "TENANT-B-ONLY" not in blob
    assert all(item.doc_id.startswith("b-") is False for item in citations)
