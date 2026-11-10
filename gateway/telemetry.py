"""OpenTelemetry: traces, metrics and logs.
- Default: JSONL files under GATEWAY_TELEMETRY_DIR (default ./telemetry), rotated daily, 7 days kept.
- OTEL_EXPORTER_OTLP_ENDPOINT set (e.g. https://otel.example.com:4318): OTLP/HTTP is used INSTEAD of the files.
  Standard OTEL_* env vars apply (OTEL_EXPORTER_OTLP_HEADERS etc.). A warning is logged for http:// to a
  non-localhost host, because that sends telemetry in plaintext.
Telemetry carries IDs, method, status and timing only, never message or reply text."""
import json
import logging
import logging.handlers
import os
import time
from urllib.parse import urlparse

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult

TELEMETRY_DIR = os.environ.get("GATEWAY_TELEMETRY_DIR", "telemetry")
OTLP_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
RETENTION_DAYS = 7  # daily rotation, 7 backups kept

tracer = trace.get_tracer("kimiclaw")
meter = metrics.get_meter("kimiclaw")
requests_total = meter.create_counter("gateway.requests", description="HTTP requests")
request_ms = meter.create_histogram("gateway.request.duration", unit="ms")
agent_ms = meter.create_histogram("gateway.agent.duration", unit="ms")
notify_failures = meter.create_counter("gateway.notify.failures")
breaker_opens = meter.create_counter("gateway.notify.breaker_opens")

EVENTS = logging.getLogger("kimiclaw.telemetry")  # structured events only; not propagated to stdout
EVENTS.propagate = False
EVENTS.setLevel(logging.INFO)


def _daily_handler(name: str) -> logging.Handler:
    return logging.handlers.TimedRotatingFileHandler(os.path.join(TELEMETRY_DIR, f"{name}.jsonl"),
                                                     when="midnight", backupCount=RETENTION_DAYS, utc=True)


def _rotating(name: str) -> logging.Logger:
    lg = logging.getLogger(f"kimiclaw.telemetry.file.{name}")
    lg.propagate = False
    lg.setLevel(logging.INFO)
    if not lg.handlers:
        h = _daily_handler(name)
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
    return lg


class _FileSpanExporter(SpanExporter):
    def __init__(self):
        self.out = _rotating("traces")

    def export(self, spans):
        for s in spans:
            self.out.info(s.to_json(indent=None))
        return SpanExportResult.SUCCESS


class _FileMetricExporter(MetricExporter):
    def __init__(self):
        super().__init__()
        self.out = _rotating("metrics")

    def export(self, metrics_data, timeout_millis=10_000, **kw):
        self.out.info(metrics_data.to_json(indent=None))
        return MetricExportResult.SUCCESS

    def force_flush(self, timeout_millis=10_000):
        return True

    def shutdown(self, timeout_millis=30_000, **kw):
        pass


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        ctx = trace.get_current_span().get_span_context()
        doc = {"ts": self.formatTime(record), "level": record.levelname, "event": record.getMessage()}
        if ctx.is_valid:
            doc["trace_id"] = format(ctx.trace_id, "032x")
            doc["span_id"] = format(ctx.span_id, "016x")
        doc.update(getattr(record, "fields", {}))
        return json.dumps(doc)


_SETUP_DONE = False


def _warn_if_plaintext(endpoint: str):
    u = urlparse(endpoint)
    if u.scheme == "http" and (u.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
        logging.getLogger("kimiclaw").warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT uses http:// to non-local host %s; telemetry is sent unencrypted", u.hostname)


def setup():
    """Idempotent: only the first call installs providers and handlers."""
    global _SETUP_DONE
    if _SETUP_DONE:
        return
    _SETUP_DONE = True
    resource = Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "kimiclaw-a2a-gateway")})
    tp = TracerProvider(resource=resource)
    if OTLP_ENDPOINT:
        _warn_if_plaintext(OTLP_ENDPOINT)
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        readers = [PeriodicExportingMetricReader(OTLPMetricExporter())]
        lp = LoggerProvider(resource=resource)
        lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
        EVENTS.addHandler(LoggingHandler(logger_provider=lp))
    else:
        os.makedirs(TELEMETRY_DIR, exist_ok=True)
        tp.add_span_processor(BatchSpanProcessor(_FileSpanExporter()))
        readers = [PeriodicExportingMetricReader(_FileMetricExporter(), export_interval_millis=60_000)]
        logs_handler = _daily_handler("logs")
        logs_handler.setFormatter(_JsonFormatter())
        EVENTS.addHandler(logs_handler)
    trace.set_tracer_provider(tp)
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=readers))


def event(name: str, **fields):
    EVENTS.info(name, extra={"fields": fields})


async def telemetry_middleware(request, call_next):
    """One "rpc" span per request. For SSE (message/stream) the span and duration close at stream end."""
    started = time.perf_counter()
    span = tracer.start_span("rpc", attributes={
        "http.request.method": request.method, "url.path": request.url.path})
    state = {"status": 500}

    def finish():
        ms = (time.perf_counter() - started) * 1000
        status = state["status"]
        span.set_attribute("http.response.status_code", status)
        attrs = {"http.request.method": request.method, "http.response.status_code": status}
        requests_total.add(1, attrs)
        request_ms.record(ms, attrs)
        with trace.use_span(span):
            event("http_request", method=request.method, path=request.url.path, status=status,
                  duration_ms=round(ms, 1), **getattr(request.state, "ids", {}))
        span.end()

    try:
        with trace.use_span(span, end_on_exit=False):
            response = await call_next(request)
    except BaseException:
        finish()
        raise
    state["status"] = response.status_code
    if not response.headers.get("content-type", "").startswith("text/event-stream"):
        finish()
        return response

    inner = response.body_iterator

    async def wrapped():
        try:
            async for chunk in inner:
                yield chunk
        finally:
            finish()

    response.body_iterator = wrapped()
    return response


def shutdown():
    for provider in (trace.get_tracer_provider(), metrics.get_meter_provider()):
        if hasattr(provider, "shutdown"):
            provider.shutdown()
