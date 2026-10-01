from src.services.hybrid_retrieval import lexical_score, rrf


def test_rrf_matches_the_rank_formula() -> None:
    scores = dict(rrf([["a", "b"], ["b", "a"]], k=60))
    assert scores["a"] == (1 / 61) + (1 / 62)
    assert scores["b"] == (1 / 62) + (1 / 61)
    assert scores["a"] == scores["b"]


def test_aligned_reset_outranks_confused_neighbor() -> None:
    gold = "Fault AF0021 clears only when the operator runs RESET-0021."
    distractor = (
        "AF0021 is often confused with AF0121. AF0121 clears only when the operator "
        "runs RESET-0121. Do not run RESET-0021 on AF0121."
    )
    assert lexical_score("AF0021", gold) > lexical_score("AF0021", distractor)
    bait = "AF0021 is often confused"
    assert lexical_score(bait, gold) > lexical_score(bait, distractor)
