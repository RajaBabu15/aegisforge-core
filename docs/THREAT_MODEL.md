# Threat model (demo)

## Refresh replay

A presented refresh token that is already used, or whose family is revoked, is `replay`. The SQL function revokes the family, writes `REFRESH_TOKEN_REUSE_DETECTED` to `system_audit_ledger`, and the API mirrors the family into Redis so the rotated access token dies too.

## Cross-tenant RAG

Qdrant queries filter on `tenant_id`. Tantivy indexes are per-tenant directories. `documents` / `document_chunks` have FORCE RLS. Application metadata also drops chunks whose `tenant_id` does not match the caller. A same-title ingest in Acme must not appear in a Demo search.

## Tool scope

`ToolRegistry.choose` reads only the first line of the task. Prompt body cannot select `execute_sql_write`. Invoke still requires checkpoint scopes. `aegis_tool_sql` can `SELECT, INSERT` on `agent_tool_writes` only; `SELECT users` is `InsufficientPrivilege`. Statement timeout is 5s.

## Approval forgery

HMAC over `timestamp + job_id + body`, 300s window, Redis nonce so the same signature cannot be replayed, job-bound so job A’s approval cannot resume job B. Workflow version mismatch returns 409 and leaves the job suspended.

## Login index

Email is the only global lookup (`auth_find_user_by_email`, SECURITY DEFINER) because the tenant GUC is unknown at login. `(tenant_id, email)` is unique. Two tenants with the same email: login 401s (`_unique_user` requires exactly one row).

## Compose roles

Hardcoded role passwords in schema (`migrator` / `app` / `tool` / `checkpoint`) are for local compose. They are not how this would ship.
