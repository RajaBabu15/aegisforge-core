# Evidence

Check in artifacts from a real compose run. Do not invent a p95.

```bash
# after docker compose is up and you have signed in:
export ACCESS_TOKEN=...
export BASE_URL=http://localhost:8000
k6 run scripts/load_test_k6.js | tee docs/evidence/k6.txt
```

If p95 misses the threshold in `scripts/load_test_k6.js`, raise that threshold to a number this machine actually hit.

For Tempo: start a ticket job that reaches the stub generator, copy `trace_id` from the response, open Grafana Explore → Tempo, save `docs/evidence/tempo-iam-workflow-llm.png` showing `iam.token_verify` → `workflow.execute` → `llm.infer`.
