"""Liveness and readiness probes. Both are public and are handled before auth or read-pool logic."""
import shutil

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/healthz", openapi_extra={"security": []})
async def healthz():
    return {"status": "ok"}


@router.get("/readyz", openapi_extra={"security": []})
async def readyz():
    if shutil.which("openclaw") is None:
        return JSONResponse({"status": "not ready", "reason": "openclaw binary not found on PATH"}, status_code=503)
    return {"status": "ready"}
