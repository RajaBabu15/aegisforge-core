# 10-minute console demo

Do not open `/docs` unless asked. Grafana stays closed if it is empty.

The graph is the control plane. Tool choice is the first line of the task: `ticket` → `file_ticket`, `sql` → `execute_sql_write`, else `read_billing`. Say that. Do not say multi-agent reasoning.

## Script

1. **0:00–0:45** — Identity is checked at the JWT and again as a Postgres GUC. Tools cannot run outside the checkpoint scopes.
2. **0:45–2:30** — Sign in developer and admin (panel 01). Decode the access token (`tenant`, `scope`, `jti`, `family_id`). Panel 02 replay. Expect 401 `REFRESH_TOKEN_REUSE_DETECTED`. Audit must be 200, not 500.
3. **2:30–5:00** — Start the ticket job as developer → `awaiting_human_approval`. Approve as admin → `file_ticket` once.
4. **5:00–7:00** — Load the Demo runbook, search `AF9001`, then `NOMATCH99999` → 422 `INSUFFICIENT_EVIDENCE`.
5. **7:00–8:30** — Panel 07: sign in Other, load the same title, search `AF9001` as Demo. `TENANT-B-ONLY` must not appear.
6. **8:30–10:00** — Make developer a viewer, sign in again, injection task. Tool stays `read_billing`. Deactivate developer → next `/me` is 401.

Close with: next build is an OIDC `id_token` and an eval row that used to fail.

A recorded take belongs on the README when you have one. Do not invent a link.
