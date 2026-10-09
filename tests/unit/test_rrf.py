from src.services.hybrid_retrieval import rrf


def test_rrf_matches_the_rank_formula() -> None:
    scores = dict(rrf([["a", "b"], ["b", "a"]], k=60))
    assert scores["a"] == (1 / 61) + (1 / 62)
    assert scores["b"] == (1 / 62) + (1 / 61)
    assert scores["a"] == scores["b"]
