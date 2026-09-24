from opentelemetry import trace
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, set_span_in_context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Gauge, Histogram

TOKEN_CONSUMPTION = Counter(
    "aegisforge_token_consumption_total",
    "LLM tokens recorded for a tenant and model.",
    ["tenant_id", "model"],
)
TOOL_DURATION = Histogram(
    "aegisforge_tool_execution_duration_seconds",
    "Sandboxed tool execution time.",
    ["tool", "outcome"],
)
EVAL_SCORE = Gauge(
    "aegisforge_agent_evaluation_score",
    "Offline evaluation scores.",
    ["metric"],
)

_PROVIDER_READY = False


def configure_tracing(otlp_endpoint: str | None, langfuse: tuple[str, str, str] | None) -> None:
    global _PROVIDER_READY
    if _PROVIDER_READY:
        return
    provider = TracerProvider(resource=Resource.create({"service.name": "aegisforge"}))
    if otlp_endpoint or langfuse:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        headers = {}
        endpoint = otlp_endpoint
        if langfuse:
            host, public, secret = langfuse
            endpoint = endpoint or f"{host.rstrip('/')}/api/public/otel/v1/traces"
            import base64

            basic = base64.b64encode(f"{public}:{secret}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, headers=headers)))
    trace.set_tracer_provider(provider)
    _PROVIDER_READY = True


def tracer():
    return trace.get_tracer("aegisforge")


def parent_context(trace_id: str):
    if not trace_id or len(trace_id) != 32:
        return None
    try:
        parsed = int(trace_id, 16)
    except ValueError:
        return None
    if parsed == 0:
        return None
    span_id = int(trace_id[:16], 16) or 1
    context = SpanContext(
        trace_id=parsed,
        span_id=span_id,
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    return set_span_in_context(NonRecordingSpan(context))
