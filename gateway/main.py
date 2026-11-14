"""App factory. The process is started only by `python -m gateway`."""
import asyncio
import os
import re
import time

from gateway.launcher_guard import FACTORY_REFUSAL, launched, refuse_launcher
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from gateway import auth, telemetry
from gateway.config import LOG, SIGNATURE_FUTURE_S
from gateway.models import SCHEMAS, SECURITY_SCHEMES
from gateway.routes import a2a, health
from gateway.routes.health import set_main_serving

LIMIT_CONCURRENCY_MIN = 64
LIMIT_CONCURRENCY_MAX = 4096
HEADER_TIMEOUT_MIN = 1
HEADER_TIMEOUT_MAX = 30
HEADER_TIMEOUT_DEFAULT = 5
PROBE_PORT_DEFAULT = 8001
_DIGITS = re.compile(r"^[1-9][0-9]*$")


def _env_int(name: str, raw, lo: int, hi: int, *, required: bool, default: int | None = None) -> int:
    if raw is None or raw == "":
        if required:
            raise RuntimeError(f"{name} is not set (want an integer from {lo} to {hi})")
        return default
    text = raw if isinstance(raw, str) else str(raw)
    if not _DIGITS.fullmatch(text):
        raise RuntimeError(f"{name} must be an integer from {lo} to {hi}")
    n = int(text, 10)
    if not lo <= n <= hi:
        raise RuntimeError(f"{name} must be an integer from {lo} to {hi}")
    return n


def limit_concurrency() -> int:
    """KIMICLAW_LIMIT_CONCURRENCY is required: an integer from 64 to 4096, passed to uvicorn."""
    return _env_int("KIMICLAW_LIMIT_CONCURRENCY", os.environ.get("KIMICLAW_LIMIT_CONCURRENCY"),
                    LIMIT_CONCURRENCY_MIN, LIMIT_CONCURRENCY_MAX, required=True)


def header_timeout_s() -> int:
    """GATEWAY_HEADER_TIMEOUT_S: seconds to wait for complete request headers (default 5, range 1–30)."""
    return _env_int("GATEWAY_HEADER_TIMEOUT_S", os.environ.get("GATEWAY_HEADER_TIMEOUT_S"),
                    HEADER_TIMEOUT_MIN, HEADER_TIMEOUT_MAX, required=False, default=HEADER_TIMEOUT_DEFAULT)


def probe_port() -> int:
    """GATEWAY_PROBE_PORT: uncapped /healthz and /readyz listener (default 8001)."""
    return _env_int("GATEWAY_PROBE_PORT", os.environ.get("GATEWAY_PROBE_PORT"),
                    1, 65535, required=False, default=PROBE_PORT_DEFAULT)


@asynccontextmanager
async def lifespan(app):
    LOG.warning("rate limits and task caps are per process; run exactly one replica and one worker")
    await asyncio.sleep(max(0.0, auth.STARTED_S + SIGNATURE_FUTURE_S + 1 - time.time()))  # serve only after STARTED_S + FUTURE_S
    yield
    set_main_serving(False)
    telemetry.shutdown()  # flush spans/metrics on graceful stop


def create_app() -> FastAPI:
    if not launched():
        refuse_launcher(FACTORY_REFUSAL)
    app = FastAPI(title="Kimiclaw A2A Gateway", version="0.1.0", lifespan=lifespan,
                 telemetry={"tracing": False, "operation_spans": False, "metrics": False, "logs": False})
    telemetry.setup()
    app.middleware("http")(auth.signed_auth)
    app.middleware("http")(telemetry.telemetry_middleware)  # added last = outermost; quiet refusals are counted, not traced
    app.include_router(a2a.router)
    app.include_router(health.router)  # also on the main port, inside the concurrency cap; probes must use GATEWAY_PROBE_PORT

    def openapi():
        if app.openapi_schema is None:
            spec = get_openapi(title=app.title, version=app.version, routes=app.routes)
            comps = spec.setdefault("components", {}).setdefault("schemas", {})
            for model in SCHEMAS:
                schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
                comps.update(schema.pop("$defs", {}))
                comps[model.__name__] = schema
            spec["components"]["securitySchemes"] = SECURITY_SCHEMES
            spec["security"] = [{"kcEd25519": []}]
            app.openapi_schema = spec
        return app.openapi_schema

    app.openapi = openapi
    return app
