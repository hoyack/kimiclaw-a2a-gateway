"""Per-caller API keys (`kc_<key_id>_<secret>`, checked against hashes from GATEWAY_KEYS_FILE) and per-key token buckets."""
import hashlib
import hmac
import math
import time

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.config import API_KEYS, CANCEL_PER_S, CREATE_BURST, CREATE_PER_MIN, GET_PER_S, KEY_ID_RE, LOG, log_safe

PUBLIC_PATHS = {"/.well-known/agent.json", "/healthz"}

# rpc method -> (tokens per second, bucket size)
LIMITS = {
    "message/send": (CREATE_PER_MIN / 60, CREATE_BURST),
    "message/stream": (CREATE_PER_MIN / 60, CREATE_BURST),
    "tasks/get": (GET_PER_S, max(1, math.ceil(GET_PER_S))),
    "tasks/cancel": (CANCEL_PER_S, max(1, math.ceil(CANCEL_PER_S))),
}
BUCKET_OF = {"message/stream": "message/send"}
_buckets: dict[tuple[str, str], tuple[float, float]] = {}


def bearer_token(authz: str) -> str:
    scheme, _, token = authz.partition(" ")
    return token if scheme.lower() == "bearer" else ""


def key_id_of(token: str) -> str | None:
    """The key_id part of `kc_<key_id>_<secret>`, if it is shaped like one (not proof the key is valid)."""
    if not token.startswith("kc_"):
        return None
    key_id, sep, _ = token[len("kc_"):].partition("_")
    return key_id if sep and KEY_ID_RE.fullmatch(key_id) else None


def verify(token: str) -> str | None:
    key_id = key_id_of(token)
    entry = API_KEYS.get(key_id) if key_id else None
    if entry is None:
        return None
    presented = hashlib.sha256(token.encode()).hexdigest()
    return key_id if hmac.compare_digest(presented.encode(), entry[0].encode()) else None


def retry_after(key_id: str, method: str) -> int:
    """0 if allowed (a token is spent), else whole seconds until the next token. Methods without a limit are free."""
    if not isinstance(method, str) or method not in LIMITS:
        return 0
    rate, size = LIMITS[method]
    slot = (key_id, BUCKET_OF.get(method, method))
    now = time.monotonic()
    tokens, last = _buckets.get(slot, (size, now))
    tokens = min(size, tokens + (now - last) * rate)
    if tokens < 1:
        _buckets[slot] = (tokens, now)
        return max(1, math.ceil((1 - tokens) / rate))
    _buckets[slot] = (tokens - 1, now)
    return 0


def rate_limited(wait: int) -> JSONResponse:
    return JSONResponse({"error": "rate limited"}, status_code=429, headers={"Retry-After": str(wait)})


async def bearer_auth(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    token = bearer_token(request.headers.get("authorization", ""))
    key_id = verify(token)
    if key_id is None:
        hint = key_id_of(token)
        LOG.warning("unauthorized key_id_hint=%s path=%s", log_safe(hint or "-"), log_safe(request.url.path))
        request.state.key_id = f"invalid:{hint}" if hint else "none"
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    request.state.key_id = key_id
    LOG.info("request key_id=%s caller=%s %s %s", key_id, log_safe(API_KEYS[key_id][1]), request.method,
             log_safe(request.url.path))
    return await call_next(request)
