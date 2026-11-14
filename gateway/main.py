"""App factory."""
import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from gateway import auth, telemetry
from gateway.config import LOG, SIGNATURE_FUTURE_S
from gateway.models import SCHEMAS, SECURITY_SCHEMES
from gateway.routes import a2a, health


@asynccontextmanager
async def lifespan(app):
    LOG.warning("rate limits and task caps are per process; run exactly one replica and one worker")
    await asyncio.sleep(max(0.0, auth.STARTED_S + SIGNATURE_FUTURE_S + 1 - time.time()))  # serve only after STARTED_S + FUTURE_S
    yield
    telemetry.shutdown()  # flush spans/metrics on graceful stop


def create_app() -> FastAPI:
    app = FastAPI(title="Kimiclaw A2A Gateway", version="0.1.0", lifespan=lifespan)
    telemetry.setup()
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
