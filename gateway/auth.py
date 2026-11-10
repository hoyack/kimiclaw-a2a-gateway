"""Bearer auth middleware: constant-time exact match, same exemptions as the original plus public /healthz."""
import hmac

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.config import TOKEN

PUBLIC_PATHS = {"/.well-known/agent.json", "/healthz"}


async def bearer_auth(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    authz = request.headers.get("authorization", "")
    if not hmac.compare_digest(authz.encode(), f"Bearer {TOKEN}".encode()):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)
