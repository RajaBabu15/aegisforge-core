from opentelemetry import trace
from opentelemetry.propagate import extract


def install_telemetry(app) -> None:
    @app.middleware("http")
    async def spans(request, call_next):
        context = extract(request.headers)
        with tracer_start(context) as span:
            span.set_attribute("http.route", request.url.path)
            span.update_name("gateway.parse")
            current = trace.get_current_span().get_span_context()
            request.state.trace_id = format(current.trace_id, "032x") if current.trace_id else ""
            return await call_next(request)


def tracer_start(context):
    return trace.get_tracer("aegisforge").start_as_current_span("gateway.parse", context=context)
