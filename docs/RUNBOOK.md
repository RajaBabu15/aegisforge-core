# Runbook

## Boot

1. Copy `docker/local.env.example` to `docker/local.env`.
2. Set `AEGIS_JWT_SECRET` and `AEGIS_APPROVAL_SECRET` (≥32 bytes).
3. Role passwords are the passwords inside `DATABASE_URL`, `MIGRATOR_DATABASE_URL`, `AEGIS_TOOL_SQL_DATABASE_URL`, and `AEGIS_CHECKPOINT_DATABASE_URL`. Change them before any shared Postgres.
4. `docker compose -f docker/docker-compose.yml up --build -d`
5. `curl -fsS http://localhost:8000/ready` must show postgres, redis, qdrant, and hydrate `ok`.

API: `http://localhost:8000/docs`

## Auth

Authorization code + PKCE S256 only. Password grant is rejected.

```
POST /oauth/authorize  (form login)
POST /oauth/token      grant_type=authorization_code | refresh_token
```

Reuse of a refresh token returns 401 `REFRESH_TOKEN_REUSE_DETECTED` and kills the family.

## Jobs

```
POST /api/v1/agents/jobs
POST /api/v1/agents/jobs/{id}/approve
```

Approve with `x-aegis-timestamp` and `x-aegis-signature`. 429 `RATE_LIMITED` if the sliding 60s window is exceeded (token per peer IP, approve per user).

## Search

```
POST /api/v1/retrieval/documents
POST /api/v1/retrieval/query
```

Index write is retried three times. Failure rolls back the request transaction. Empty or low-score query is 422 `INSUFFICIENT_EVIDENCE`.
