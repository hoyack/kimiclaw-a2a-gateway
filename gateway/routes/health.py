"""Liveness and readiness on the main port (inside the concurrency cap).

Kubernetes probes must use the uncapped probe listener (gateway.probe:probe_app on
GATEWAY_PROBE_PORT, default 8001), not these routes.
"""
import os
import shutil

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

# Set by python -m gateway when the main Server has bound and is accepting.
MAIN_SERVING = False


def set_main_serving(value: bool) -> None:
    global MAIN_SERVING
    MAIN_SERVING = value


def require_openclaw() -> bool:
    """True unless GATEWAY_REQUIRE_OPENCLAW is the exact string '0'. Unset, 'false', 'no', ' 0', '00' all stay on."""
    return os.environ.get("GATEWAY_REQUIRE_OPENCLAW") != "0"


@router.get("/healthz", openapi_extra={"security": []})
async def healthz():
    return {"status": "ok"}


@router.get("/readyz", openapi_extra={"security": []})
async def readyz():
    if require_openclaw() and shutil.which("openclaw") is None:
        return JSONResponse({"status": "not ready", "reason": "openclaw binary not found on PATH"}, status_code=503)
    return {"status": "ready"}
