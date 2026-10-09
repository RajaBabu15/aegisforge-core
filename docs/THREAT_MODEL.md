# Threat model (demo)

Compose role passwords (`migrator` / `app` / `tool` / `checkpoint`) are local only.

## Refresh replay

A presented refresh token is consumed in SQL. Reuse returns `replay` and revokes the family. The new access token is also dead after Redis mirror. Stolen refresh after first use is a full logout of that family, not a second session.

## Cross-tenant RAG

Qdrant filters `tenant_id`. Tantivy indexes live under `tantivy_dir/<tenant_id>/`. Query drops any chunk whose stored tenant does not match. Same document title in two tenants is two rows. Tenant A search must not return Tenant B text.

`hydrate()` reads chunks as the migrator at boot, then partitions indexes by tenant. That boot read is the superuser path; request path is RLS + filter.

## Tool scope

`choose_tool` uses the first line of the task only. Later lines cannot promote `execute_sql_write`. Missing checkpoint scopes yield `CRITICAL_SECURITY_DENIAL` and open no SQL cursor. `aegis_tool_sql` may `SELECT, INSERT` on `agent_tool_writes` only, 5s statement timeout.

## Approval forgery

HMAC over `timestamp + job_id + body`, 300s window, Redis nonce, job-bound signature. Replay of the same signature is `APPROVAL_REPLAYED`. Job A’s signature cannot resume job B. Workflow version mismatch leaves the job suspended.

## Login before tenant GUC

`auth_find_user_by_email` is `SECURITY DEFINER` and the only global index. Uniqueness is `(tenant_id, email)`. `_unique_user` requires exactly one row; two tenants sharing an email hard-fail login. Demo emails are distinct across Demo and Other.

Role change does not rotate tokens. Sign in again. The UI says so.
