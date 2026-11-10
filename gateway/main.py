"""App factory."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from gateway import telemetry
from gateway.auth import bearer_auth
from gateway.models import SCHEMAS
from gateway.routes import a2a, health


@asynccontextmanager
async def lifespan(app):
    yield
    telemetry.shutdown()  # flush spans/metrics on graceful stop


def create_app() -> FastAPI:
    app = FastAPI(title="Kimiclaw A2A Gateway", version="0.1.0", lifespan=lifespan)
    telemetry.setup()
    app.middleware("http")(bearer_auth)
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
            spec["components"]["securitySchemes"] = {"bearerAuth": {"type": "http", "scheme": "bearer"}}
            spec["security"] = [{"bearerAuth": []}]
            app.openapi_schema = spec
        return app.openapi_schema

    app.openapi = openapi
    return app


app = create_app()
