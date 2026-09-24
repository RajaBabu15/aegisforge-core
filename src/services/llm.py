import httpx
from opentelemetry.propagate import inject

from src.services.telemetry import tracer


class StubLLM:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, task: str, chunks: list[dict], model: str) -> tuple[str, int]:
        del task, model
        self.calls += 1
        text = "\n".join(chunk["content"] for chunk in chunks)
        return text, max(1, len(text.split()))


class OpenAICompatibleLLM:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.calls = 0

    async def complete(self, task: str, chunks: list[dict], model: str) -> tuple[str, int]:
        self.calls += 1
        context = "\n".join(chunk["content"] for chunk in chunks)
        headers = {"Authorization": f"Bearer {self.api_key}"}
        inject(headers)
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "Answer only from the supplied chunks and echo citation ids."},
                        {"role": "user", "content": f"{task}\n\n{context}"},
                    ],
                },
            )
            response.raise_for_status()
            payload = response.json()
        message = payload["choices"][0]["message"]["content"]
        usage = payload.get("usage", {}).get("total_tokens", 0)
        return message, int(usage)


def build_llm(settings):
    if settings.llm == "openai":
        if not settings.llm_base_url or not settings.llm_api_key:
            raise RuntimeError("AEGIS_LLM_BASE_URL and AEGIS_LLM_API_KEY are required")
        return OpenAICompatibleLLM(settings.llm_base_url, settings.llm_api_key)
    return StubLLM()


async def infer(llm, task: str, chunks: list[dict], model: str) -> tuple[str, int]:
    with tracer().start_as_current_span("llm.infer"):
        return await llm.complete(task, chunks, model)
