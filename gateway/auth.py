"""Per-caller bearer auth and a per-caller fixed-window rate limit on JSON-RPC task calls (POST /)."""
import hmac
import math
import time

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.config import API_KEYS, RATE_LIMIT, RATE_WINDOW_S

PUBLIC_PATHS = {"/.well-known/agent.json", "/healthz"}

_windows: dict[str, tuple[float, int]] = {}


def caller_for(authz: str) -> str | None:
    """Checks every key so timing does not reveal which one matched."""
    found = None
    for name, key in API_KEYS.items():
        if hmac.compare_digest(authz.encode(), f"Bearer {key}".encode()):
            found = name
    return found


def retry_after(caller: str) -> int:
    """0 if the call is allowed (and counted), else seconds until the caller's window resets."""
    now = time.monotonic()
    start, count = _windows.get(caller, (now, 0))
    if now - start >= RATE_WINDOW_S:
        start, count = now, 0
    if count >= RATE_LIMIT:
        return max(1, math.ceil(start + RATE_WINDOW_S - now))
    _windows[caller] = (start, count + 1)
    return 0


async def bearer_auth(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    caller = caller_for(request.headers.get("authorization", ""))
    if caller is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if request.method == "POST" and request.url.path == "/":
        wait = retry_after(caller)
        if wait:
            return JSONResponse({"error": "rate limited"}, status_code=429, headers={"Retry-After": str(wait)})
    return await call_next(request)
