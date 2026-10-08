# AegisForge build contract

## Isolation
Every authenticated request binds one tenant. JWT (or SCIM token) is checked at the edge; Postgres sets `app.current_tenant_id` and RLS refuses cross-tenant rows. `aegis_app`, `aegis_tool_sql`, and `aegis_checkpoint` cannot bypass RLS. Reusing a refresh token revokes the family. SCIM deactivation closes live sessions.

## Agents
`POST /api/v1/agents/jobs` runs a versioned LangGraph: plan → choose_tool → execute → verify → respond. Cost is capped by `agent_max_cost`. Tools run only with checkpoint scopes. `file_ticket` and `execute_sql_write` suspend until a HMAC approval (`x-aegis-timestamp`, `x-aegis-signature`) is consumed once within 300s. Missing scopes yield `CRITICAL_SECURITY_DENIAL` and open no SQL cursor. `execute_sql_write` INSERTs only into `agent_tool_writes` as `aegis_tool_sql` with a 5s statement timeout.

## Retrieval
Ingest and query are tenant-scoped. Sparse (Tantivy) and dense (Qdrant) ranks fuse with RRF (`rrf_k=60`); a reranker keeps hits above `rerank_min_score`. Zero hits or a floor miss is `INSUFFICIENT_EVIDENCE` and the generator does not run. Default embedder/reranker are hash/lexical; `fastembed` plus a cross-encoder are optional.

## Auth, audit, ops
OAuth2 + PKCE, Argon2 passwords, 15-minute access JWTs. `system_audit_ledger` records ALLOW, DENY, and REVOKED. Traces go to OTLP/Tempo, metrics to Prometheus, optional Langfuse when host and both keys are set. `GET /health` returns that request's `trace_id` so on-call can open Tempo and own a customer incident through RCA. CI: Bandit, Hadolint, Pylint. Secrets are ≥32 bytes. Demo credentials in `docker/local.env.example` are not secrets.
