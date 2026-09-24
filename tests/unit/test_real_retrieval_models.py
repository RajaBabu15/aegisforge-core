import pytest

from src.core.config import Settings
from src.services.hybrid_retrieval import HybridRetriever, hash_embed


def _settings(tmp_path, **overrides) -> Settings:
    return Settings(
        _env_file=None,
        aegis_jwt_secret="x" * 32,
        aegis_approval_secret="y" * 32,
        qdrant_url=":memory:",
        tantivy_dir=str(tmp_path),
        **overrides,
    )


@pytest.mark.slow
def test_fastembed_embedder_produces_real_dense_vectors(tmp_path) -> None:
    """The default `hash` embedder is a bag-of-words hash, not a semantic embedding.

    This exercises the real dense-embedding code path (src/services/hybrid_retrieval.py's
    `_embed` when AEGIS_EMBEDDER=fastembed) which no other test in the suite touches.
    """
    pytest.importorskip("fastembed")
    retriever = HybridRetriever(_settings(tmp_path, embedder="fastembed"))
    text = "Fault AF4242 clears only when the operator runs RESET-4242."
    vector = retriever._embed(text)
    assert len(vector) == 384
    assert vector != hash_embed(text)


@pytest.mark.slow
def test_cross_encoder_reranker_scores_a_relevant_pair_higher(tmp_path) -> None:
    """The default `lexical` reranker is Jaccard token overlap, not a cross-encoder.

    This exercises the real `sentence_transformers.CrossEncoder` code path
    (AEGIS_RERANKER=cross-encoder) which no other test in the suite touches.
    """
    pytest.importorskip("sentence_transformers")
    retriever = HybridRetriever(_settings(tmp_path, reranker="cross-encoder"))
    query = "how do I clear fault AF4242"
    relevant = "Fault AF4242 clears only when the operator runs RESET-4242."
    irrelevant = "The quarterly invoice was mailed to the billing address on file."
    assert retriever._score(query, relevant) > retriever._score(query, irrelevant)
