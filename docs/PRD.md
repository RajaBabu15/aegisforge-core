# AegisForge product contract

AegisForge is a **multi-tenant agent control plane**. Identity is checked at the JWT and again as a Postgres GUC. Tools run only when checkpoint scopes allow them. High-risk tools stay suspended until a signed approval. Hybrid search cites chunks or returns `INSUFFICIENT_EVIDENCE` before any generator call.

The LangGraph is a five-node state machine around a **deterministic** tool router (`ToolRegistry.choose`): first line of the task, `"ticket"` → `file_ticket`, `"sql"` → `execute_sql_write`, else `read_billing`. There is no planner and no model-chosen tool schema. That is intentional so authorization can be tested without an LLM.

## In scope

- OAuth Authorization Code + PKCE S256 only. Password grant is rejected.
- Refresh presentation as a SQL function that returns `replay` and revokes the family. Reuse of the rotated access token is dead.
- SCIM-lite: create, get, put, list-by-userName, deactivate. Reactivation does not resurrect the old access token.
- Postgres RLS with `set_config('app.current_tenant_id', …)` and `FORCE ROW LEVEL SECURITY` on tenant tables, including `documents` and `agent_tool_writes`.
- Tool sandbox role `aegis_tool_sql`: `SELECT, INSERT` on `agent_tool_writes` only, 5s statement timeout.
- HITL: HMAC over `timestamp + job_id + body`, 300s window, Redis nonce, job-bound signature, workflow version mismatch leaves the job suspended.
- Hybrid retrieval (hash embedder + lexical reranker by default) with a confidence floor.
- Two bootstrap tenants (Demo and Acme) so RAG isolation is clickable in the console.

## Out of scope

- OIDC `id_token`, discovery, userinfo, SAML, FIDO.
- SCIM PATCH / enterprise extensions.
- Multi-agent reasoning, retries, reflection.
- A second product (ColumnarLab).
- Claims about 100M DAU. Tantivy-per-tenant on disk is the first thing that hurts as tenant count grows.

## Login index

`auth_find_user_by_email` is `SECURITY DEFINER` and scans all tenants. Email is the only global index. Uniqueness is `(tenant_id, email)`. `_unique_user` requires exactly one row; if two tenants share an email, login hard-fails.

## Compose credentials

Schema creates `aegis_migrator` / `aegis_app` / `aegis_tool_sql` / `aegis_checkpoint` with passwords `migrator` / `app` / `tool` / `checkpoint`. Those are local-compose values, not a production secret scheme.

## Evaluation

The golden set used to be 50 twin lines (`Fault AFxxxx` / query `AFxxxx`). That gate could not fail. The current set keeps 10 twins, adds 20 gold/distractor pairs (same fault mentioned, first RESET belongs to the neighbor), and 20 synonym queries. Hit-rate and stub faithfulness are **top-1**. Neighbor `RESET-01xx` is a forbidden fact.

The change that moved ranking: `lexical_score` boosts a chunk when the queried fault id matches the **first** `RESET-xxxx` in the chunk. See `docs/EVAL.md`.

Against `AEGIS_LLM=stub`, faithfulness is retrieval echo, not generation quality.
