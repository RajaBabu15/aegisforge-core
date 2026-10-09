# AegisForge

Multi-tenant agent API.

Login binds a tenant. Postgres RLS checks it again. Refresh reuse kills the token family. High-risk tools wait for a signed admin approval. Search cites a runbook chunk or returns `INSUFFICIENT_EVIDENCE`.

Tool pick is the first line of the task (`ticket` / `sql` / else billing).

## Run

```bash
export AEGIS_JWT_SECRET="$(openssl rand -hex 32)"
export AEGIS_APPROVAL_SECRET="$(openssl rand -hex 32)"
cp docker/local.env.example docker/local.env
# paste the two secrets into docker/local.env
docker compose -f docker/docker-compose.yml up --build -d
curl -fsS http://localhost:8000/health
```

API: `http://localhost:8000/docs`. Metrics: `http://localhost:8000/metrics`.

Role passwords come from the database URLs in `docker/local.env`, not from `schema.sql`. Threats: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Ops: [docs/RUNBOOK.md](docs/RUNBOOK.md).
