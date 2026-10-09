# AegisForge

Multi-tenant agent API. The build contract is [docs/PRD.md](docs/PRD.md). Console walkthrough: [docs/DEMO.md](docs/DEMO.md). Threats: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Identity is checked at the edge and again in PostgreSQL. Refresh-token reuse revokes the whole family. Agent tools run only when the checkpoint scopes allow them, and high-risk tools stay suspended until a signed approval. Hybrid search cites chunks or returns `INSUFFICIENT_EVIDENCE` before any generator call.

The LangGraph is the control plane. Tool selection is the first line of the task, so authorization can be tested without a model. Do not describe this as multi-agent reasoning.

## Run the cluster

```bash
export AEGIS_JWT_SECRET="$(openssl rand -hex 32)"
export AEGIS_APPROVAL_SECRET="$(openssl rand -hex 32)"
cp docker/local.env.example docker/local.env
# paste the two secrets into docker/local.env
docker compose -f docker/docker-compose.yml up --build -d
curl -fsS http://localhost:8000/health
```

Open `http://localhost:8000/`. Sign in and use the numbered panels. Copy `AEGIS_BOOTSTRAP_B_*` from `docker/local.env.example` into `docker/local.env` so panel 07 has the Other tenant. API docs stay at `http://localhost:8000/docs`. Grafana is at `http://localhost:3000`. Skip Grafana if the dashboard is empty. Traces: Grafana Explore → Tempo → `trace_id` from any API body.

```bash
python scripts/simulate_replay_attack.py
k6 run -e BASE_URL=http://localhost:8000 -e ACCESS_TOKEN="$TOKEN" scripts/load_test_k6.js
```

Last `/api/v1/me` k6 table: [docs/evidence/k6.txt](docs/evidence/k6.txt). Unit + security tests: `pytest tests/unit -q -m "not slow"`. Retrieval eval (near-misses, synonyms, tenant B): `pytest tests/evaluation -q`. `AF0100` used to rank `AF0100-BETA` (`RESET-0150`) first; `lexical_score` now down-weights hyphenated cousins so `near_miss_ok` is P@1 against the gold reset. CI is `.github/workflows/ci-eval-pipeline.yml`.

## Model switches

Default retrieval is a hashing embedder plus a lexical reranker. Set `AEGIS_EMBEDDER=fastembed` and `AEGIS_RERANKER=cross-encoder` (`AEGIS_RERANKER_MODEL`, default `BAAI/bge-reranker-base`) after `pip install -r requirements-eval.txt`.

`AEGIS_LLM=stub` quotes retrieved chunks and records token use once per step. `AEGIS_LLM=openai` calls `AEGIS_LLM_BASE_URL` with `AEGIS_LLM_API_KEY`.

Langfuse receives spans only when `LANGFUSE_HOST`, `LANGFUSE_PUBLIC_KEY`, and `LANGFUSE_SECRET_KEY` are all set. Grafana is always provisioned.
