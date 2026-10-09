# Threat model

Schema SQL does not ship role passwords. `apply_schema` sets `aegis_migrator`, `aegis_app`, `aegis_tool_sql`, and `aegis_checkpoint` from the DSNs in env. Compose `local.env` values are local demo only.

## Refresh replay

A presented refresh token is consumed in SQL. Reuse returns `replay` and revokes the family. Redis then mirrors family and access `jti` keys. Stolen refresh after first use is a full family logout.

## Cross-tenant RAG

Qdrant filters `tenant_id`. Tantivy lives under `tantivy_dir/<tenant_id>/`. Query drops chunks whose stored tenant does not match. `hydrate()` reads as migrator at boot; request path is RLS plus filters. Failed hydrate marks `/ready` down.

## Tool scope

First line of the task chooses the tool. Missing checkpoint scopes yield `CRITICAL_SECURITY_DENIAL` and open no SQL cursor. `aegis_tool_sql` may `SELECT, INSERT` on `agent_tool_writes` only, 5s timeout.

## Approval forgery

HMAC over `timestamp + job_id + body`, 300s window, Redis nonce, job-bound signature. Replay is `APPROVAL_REPLAYED`. Version mismatch leaves the job suspended. Resume re-checks the owner is active and the live role still allows the tool.

## Rate limits

Sliding 60s window in Redis (sorted set). `/oauth/token` is capped per TCP peer IP (default 30). Clients behind one NAT share that bucket. Job approval is capped per user id (default 20). No `X-Forwarded-For`.

## Login before tenant GUC

`auth_find_user_by_email` is `SECURITY DEFINER` and the only global index. Uniqueness is `(tenant_id, email)`. Two tenants sharing an email hard-fail login.
