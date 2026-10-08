# AegisForge

Multi-tenant agent API. The build contract is [docs/PRD.md](docs/PRD.md).

Identity is checked at the edge and again in PostgreSQL. Refresh-token reuse revokes the whole family. Agent tools run only when the checkpoint scopes allow them, and high-risk tools stay suspended until a signed approval. Hybrid search cites chunks or returns `INSUFFICIENT_EVIDENCE` before any generator call.

## Run the cluster

```bash
export AEGIS_JWT_SECRET="$(openssl rand -hex 32)"
export AEGIS_APPROVAL_SECRET="$(openssl rand -hex 32)"
cp docker/local.env.example docker/local.env
# paste the two secrets into docker/local.env
docker compose -f docker/docker-compose.yml up --build -d
curl -fsS http://localhost:8000/health
```

Open `http://localhost:8000/`. Sign in and use the buttons on that page. API docs stay at `http://localhost:8000/docs`. Grafana is at `http://localhost:3000`. Traces are not a dashboard panel: open Grafana Explore, pick the Tempo datasource, and search by the `trace_id` returned in any API response or error body.

```bash
python scripts/simulate_replay_attack.py
```

## Model switches

Default retrieval is a hashing embedder plus a lexical reranker. Set `AEGIS_EMBEDDER=fastembed` and `AEGIS_RERANKER=cross-encoder` (`AEGIS_RERANKER_MODEL`, default `BAAI/bge-reranker-base`) after `pip install -r requirements-eval.txt`.

`AEGIS_LLM=stub` quotes retrieved chunks and records token use once per step. `AEGIS_LLM=openai` calls `AEGIS_LLM_BASE_URL` with `AEGIS_LLM_API_KEY`.

Langfuse receives spans only when `LANGFUSE_HOST`, `LANGFUSE_PUBLIC_KEY`, and `LANGFUSE_SECRET_KEY` are all set. Grafana is always provisioned.
