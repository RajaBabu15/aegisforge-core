import json
from pathlib import Path

import pytest

from src.core.config import Settings
from src.services.hybrid_retrieval import HybridRetriever
from src.services.identity import Principal
from src.services.llm import StubLLM
from src.services.telemetry import EVAL_SCORE
from src.services.tools_sandbox import ToolRegistry
from src.services.workflow_engine import MemoryJobStore, WorkflowEngine

_ROOT = Path(__file__).resolve().parent
_DATA = json.loads((_ROOT / "dataset_golden_eval.json").read_text())
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


def _retriever(tmp_path: Path) -> HybridRetriever:
    retriever = HybridRetriever(_settings(tmp_path))
    for doc in _DATA["corpus"]:
        retriever.ingest(
            tenant_id="tenant-eval",
            doc_id=doc["doc_id"],
            page=doc["page"],
            line_start=doc["line_start"],
            line_end=doc["line_end"],
            content=doc["content"],
        )
    return retriever


@pytest.fixture
def retriever(tmp_path):
    return _retriever(tmp_path)


async def test_golden_set_meets_thresholds(retriever: HybridRetriever) -> None:
    llm = StubLLM()
    hits = 0
    faithful = 0
    completed = 0
    for row in _DATA["queries"]:
        citations = await retriever.query("tenant-eval", row["query"])
        ids = [item.doc_id for item in citations[:5]]
        if any(doc_id in ids for doc_id in row["relevant_doc_ids"]):
            hits += 1
        answer, _tokens = await llm.complete(row["query"], [item.__dict__ for item in citations], "stub-echo")
        if all(fact in answer for fact in row["expected_facts"]):
            faithful += 1
            completed += 1
    total = len(_DATA["queries"])
    scores = {
        "hit_rate": hits / total,
        "faithfulness": faithful / total,
        "task_completion": completed / total,
    }
    for metric, value in scores.items():
        EVAL_SCORE.labels(metric=metric).set(value)
        assert value >= _THRESHOLDS[metric], f"{metric} {value} < {_THRESHOLDS[metric]}"
    print(scores)


async def test_low_score_skips_the_generator(tmp_path) -> None:
    retriever = _retriever(tmp_path)
    retriever.min_score = 0.99
    llm = StubLLM()
    engine = WorkflowEngine(
        tools=ToolRegistry(),
        retrieval=retriever,
        llm=llm,
        jobs=MemoryJobStore(),
        settings=_settings(tmp_path),
    )
    principal = Principal("user", "tenant-eval", ["retrieval:read"], "jti", "family", "jwt")
    row = await engine.start(
        None,
        job_id="job-refuse",
        task="NOMATCH99999",
        principal=principal,
        trace_id="trace",
    )
    assert row["execution_payload_state"]["output"]["code"] == "INSUFFICIENT_EVIDENCE"
    assert llm.calls == 0
