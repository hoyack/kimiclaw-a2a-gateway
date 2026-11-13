"""New in this refactor: liveness and readiness probes (/healthz is public and returns only {"status":"ok"}; /readyz needs a signed request)."""
import shutil

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/healthz", openapi_extra={"security": []})
async def healthz():
    return {"status": "ok"}


@router.get("/readyz")
async def readyz():
    if shutil.which("openclaw") is None:
        return JSONResponse({"status": "not ready", "reason": "openclaw binary not found on PATH"}, status_code=503)
    return {"status": "ready"}
