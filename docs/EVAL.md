# Retrieval eval

## What used to pass for free

50 documents of the form `Fault AFxxxx clears only when the operator runs RESET-xxxx`, 50 queries that were exactly `AFxxxx`, hit-rate measured on top-5, stub LLM echoing every retrieved chunk. Hash embedder + Jaccard almost cannot miss.

## What the gate is now

- 10 twins kept as a regression floor.
- 20 gold docs (`AF0021`–`AF0040`) each paired with a neighbor that mentions the same fault but whose **first** RESET is the sibling (`RESET-01xx`).
- 20 synonym queries (`how to clear alarm …`, `factory reset procedure for …`).
- Hit-rate and stub faithfulness use **top-1**. Neighbor RESET ids are `forbidden_facts`.
- Separate test: tenant-B poison `RESET-EVIL` for `AF0001` must never appear in tenant-eval results.

## Change that moved ranking

`lexical_score` prefers a chunk whose **first** `RESET-yyyy` matches the queried `AFxxxx` (`1.0 + 0.5 * Jaccard`). Lookalike chunks that mention the fault but lead with a different RESET score `0.2 + 0.3 * Jaccard`. Unit test: `test_aligned_reset_outranks_confused_neighbor`.

Measured on this set, top-1 hit-rate / stub faithfulness:

- Jaccard only: **0.80** (bait queries `AF00xx is often confused` rank the neighbor `doc-3x`)
- After first-RESET alignment: **0.98**

Thresholds live in `tests/evaluation/thresholds.json`. They belong to hash+lexical. Changing embedder or reranker requires a new threshold commit.

Against `AEGIS_LLM=stub`, faithfulness is retrieval quality, not generation quality.
