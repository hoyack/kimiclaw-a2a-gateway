"""HMAC-signed requests (X-KC-* headers, per-caller secrets from GATEWAY_SIGNING_KEYS_FILE) and per-key token buckets."""
import hashlib
import heapq
import hmac
import math
import re
import time

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.config import (CANCEL_PER_S, CREATE_BURST, CREATE_PER_MIN, GET_PER_S, KEY_ID_RE, LOG, MAX_BODY, MAX_NONCES,
                            SIGNATURE_SKEW_S, SIGNING_KEYS, log_safe)

PUBLIC_PATHS = {"/.well-known/agent.json", "/healthz"}
HEADERS = ("x-kc-key-id", "x-kc-timestamp", "x-kc-nonce", "x-kc-signature")
TIMESTAMP_RE = re.compile(r"[0-9]{1,12}")
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")
SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")

# rpc method -> (tokens per second, bucket size)
LIMITS = {
    "message/send": (CREATE_PER_MIN / 60, CREATE_BURST),
    "message/stream": (CREATE_PER_MIN / 60, CREATE_BURST),
    "tasks/get": (GET_PER_S, max(1, math.ceil(GET_PER_S))),
    "tasks/cancel": (CANCEL_PER_S, max(1, math.ceil(CANCEL_PER_S))),
}
BUCKET_OF = {"message/stream": "message/send"}
_buckets: dict[tuple[str, str], tuple[float, float]] = {}
_nonces: set[tuple[str, str]] = set()
_nonce_expiry: list[tuple[int, str, str]] = []


def canonical(method: str, raw_path: bytes, query: bytes, timestamp: str, nonce: str, body: bytes) -> bytes:
    sorted_query = b"&".join(sorted(p for p in query.split(b"&") if p))
    target = raw_path + (b"?" + sorted_query if sorted_query else b"")
    return b"\n".join([method.encode(), target, timestamp.encode(), nonce.encode(), hashlib.sha256(body).hexdigest().encode()])


def spend_nonce(key_id: str, nonce: str, timestamp: int) -> str | None:
    """None if this nonce is new for key_id (it is then remembered until its timestamp leaves the window), else why not."""
    now = time.time()
    while _nonce_expiry and _nonce_expiry[0][0] < now:
        _, k, n = heapq.heappop(_nonce_expiry)
        _nonces.discard((k, n))
    if (key_id, nonce) in _nonces:
        return "replayed_nonce"
    if len(_nonces) >= MAX_NONCES:
        return "nonce_cache_full"
    _nonces.add((key_id, nonce))
    heapq.heappush(_nonce_expiry, (timestamp + SIGNATURE_SKEW_S, key_id, nonce))
    return None


async def read_body(request: Request) -> bytes | None:
    """The request body, or None if Content-Length or the bytes read pass MAX_BODY."""
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_BODY:
        return None
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            return None
    return body


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


def unauthorized(request: Request, key_id: str, reason: str) -> JSONResponse:
    LOG.warning("unauthorized reason=%s key_id=%s path=%s", reason, log_safe(key_id or "-"), log_safe(request.url.path))
    request.state.key_id = f"invalid:{log_safe(key_id)}" if key_id else "none"
    return JSONResponse({"error": "unauthorized"}, status_code=401)


async def signed_auth(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    key_id, timestamp, nonce, signature = (request.headers.get(h, "") for h in HEADERS)
    if not (key_id and timestamp and nonce and signature):
        return unauthorized(request, key_id, "missing_header")
    if not (KEY_ID_RE.fullmatch(key_id) and TIMESTAMP_RE.fullmatch(timestamp) and NONCE_RE.fullmatch(nonce)
            and SIGNATURE_RE.fullmatch(signature)):
        return unauthorized(request, key_id, "malformed_header")
    if key_id not in SIGNING_KEYS:
        return unauthorized(request, key_id, "unknown_key")
    if abs(time.time() - int(timestamp)) > SIGNATURE_SKEW_S:
        return unauthorized(request, key_id, "stale_timestamp")
    body = await read_body(request)
    if body is None:
        request.state.key_id = f"unverified:{key_id}"
        return JSONResponse({"error": "request body too large"}, status_code=413)
    caller, secret = SIGNING_KEYS[key_id]
    message = canonical(request.method, request.scope["raw_path"], request.scope["query_string"], timestamp, nonce, body)
    if not hmac.compare_digest(hmac.new(secret, message, hashlib.sha256).hexdigest(), signature):
        return unauthorized(request, key_id, "bad_signature")
    reason = spend_nonce(key_id, nonce, int(timestamp))
    if reason:
        return unauthorized(request, key_id, reason)
    request.state.key_id = key_id
    request.state.body = body
    LOG.info("request key_id=%s caller=%s %s %s", key_id, log_safe(caller), request.method, log_safe(request.url.path))
    return await call_next(request)
