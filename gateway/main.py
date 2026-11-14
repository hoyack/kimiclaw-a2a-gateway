"""App factory."""
import asyncio
import inspect
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from gateway import auth, telemetry
from gateway.config import LOG, SIGNATURE_FUTURE_S
from gateway.models import SCHEMAS, SECURITY_SCHEMES
from gateway.routes import a2a, health

LIMIT_CONCURRENCY_MIN = 64
LIMIT_CONCURRENCY_MAX = 4096


def limit_concurrency() -> int:
    """KIMICLAW_LIMIT_CONCURRENCY is required: an integer from 64 to 4096, passed to uvicorn."""
    raw = os.environ.get("KIMICLAW_LIMIT_CONCURRENCY")
    if raw is None or not str(raw).strip():
        raise RuntimeError("KIMICLAW_LIMIT_CONCURRENCY is not set (want an integer from 64 to 4096)")
    try:
        n = int(raw, 10)
    except ValueError:
        raise RuntimeError("KIMICLAW_LIMIT_CONCURRENCY must be an integer from 64 to 4096") from None
    if not LIMIT_CONCURRENCY_MIN <= n <= LIMIT_CONCURRENCY_MAX:
        raise RuntimeError("KIMICLAW_LIMIT_CONCURRENCY must be an integer from 64 to 4096")
    return n


def bind_uvicorn_limit_concurrency(cap: int) -> None:
    """When this module is loaded by `uvicorn app:app`, Config already exists; set limit_concurrency on it."""
    for fr in inspect.stack():
        self_obj = fr.frame.f_locals.get("self")
        if (self_obj is not None and type(self_obj).__module__.startswith("uvicorn.")
                and type(self_obj).__name__ == "Config" and hasattr(self_obj, "limit_concurrency")):
            self_obj.limit_concurrency = cap
            return

@asynccontextmanager
async def lifespan(app):
    LOG.warning("rate limits and task caps are per process; run exactly one replica and one worker")
    await asyncio.sleep(max(0.0, auth.STARTED_S + SIGNATURE_FUTURE_S + 1 - time.time()))  # serve only after STARTED_S + FUTURE_S
    yield
    telemetry.shutdown()  # flush spans/metrics on graceful stop


def create_app() -> FastAPI:
    cap = limit_concurrency()
    bind_uvicorn_limit_concurrency(cap)
    LOG.warning("uvicorn limit_concurrency=%d", cap)
    app = FastAPI(title="Kimiclaw A2A Gateway", version="0.1.0", lifespan=lifespan)
    telemetry.setup()
    auth.install_access_log_filter()
    app.middleware("http")(auth.signed_auth)
    app.middleware("http")(telemetry.telemetry_middleware)  # added last = outermost, so 401s are recorded
    app.include_router(a2a.router)
    app.include_router(health.router)

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


app = create_app()
