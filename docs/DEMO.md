# 10-minute demo

Walk the numbered panels at `http://localhost:8000/`. Do not open `/docs` unless asked. Skip Grafana if it is empty.

Compose demo passwords are in the form fields. Traefik is in front of a single service with no TLS; Prometheus scrapes `api:8000` directly. Do not spend time on the proxy.

One sentence at 0:00: identity is checked at the JWT and again as a Postgres GUC. Tools cannot run outside the checkpoint scopes. The graph is the control plane; tool selection is deterministic so authz can be tested.

1. **0:00–0:45** — Sign in developer and admin. Decode the access token (tenant, scopes, `jti`, `family_id`).
2. **0:45–2:30** — Replay button. Expect 401 + `REFRESH_TOKEN_REUSE_DETECTED`. Audit JSON must load (not 500).
3. **2:30–5:00** — Start ticket job as developer → `awaiting_human_approval`. Approve as admin → `file_ticket` once. Mention version mismatch and signature nonce if time is tight.
4. **5:00–7:00** — Load runbook, search `AF9001`, then `NOMATCH99999` → 422 `INSUFFICIENT_EVIDENCE`.
5. **7:00–8:30** — Make developer a viewer (family revoked). Sign in again. Injection task. Tool stays `read_billing`. First line is the command; the body cannot promote a write tool.
6. **8:30–9:15** — Deactivate developer → next `/me` is 401.
7. **9:15–10:00** — Panel 07: sign in Acme, load the same title with `RESET-ACME`, search as Demo. Demo must not show Acme’s reset.

Close with: what I would build next is an OIDC `id_token` and a real-model faithfulness eval. Do not claim multi-agent reasoning.
