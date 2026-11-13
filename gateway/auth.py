"""HMAC-signed requests (X-KC-* headers, per-caller secrets from GATEWAY_SIGNING_KEYS_FILE) and per-key token buckets."""
import hashlib
import heapq
import hmac
import math
import re
import secrets
import time

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.config import (CANCEL_PER_S, CREATE_BURST, CREATE_PER_MIN, GET_PER_S, KEY_ID_RE, LOG, MAX_BODY,
                            MAX_NONCES_PER_CALLER, REQUESTS_BURST, REQUESTS_PER_S, SIGNATURE_SKEW_S, SIGNING_KEYS,
                            log_safe)

PUBLIC_PATHS = {"/.well-known/agent.json", "/healthz"}
HEADERS = ("x-kc-key-id", "x-kc-timestamp", "x-kc-nonce", "x-kc-signature")
TIMESTAMP_RE = re.compile(r"[0-9]{1,12}")
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")
SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")
DUMMY_SECRET = secrets.token_bytes(32)  # unknown key_ids pay for the same HMAC + compare as a wrong signature

# rpc method -> (tokens per second, bucket size)
LIMITS = {
    "message/send": (CREATE_PER_MIN / 60, CREATE_BURST),
    "message/stream": (CREATE_PER_MIN / 60, CREATE_BURST),
    "tasks/get": (GET_PER_S, max(1, math.ceil(GET_PER_S))),
    "tasks/cancel": (CANCEL_PER_S, max(1, math.ceil(CANCEL_PER_S))),
}
BUCKET_OF = {"message/stream": "message/send"}
_buckets: dict[tuple[str, str], tuple[float, float]] = {}
_nonces: dict[str, tuple[set[str], list[tuple[int, str]]]] = {}  # caller -> (nonces, heap of (expiry, nonce))


def canonical(method: str, raw_path: bytes, query: bytes, timestamp: str, nonce: str, body: bytes, key_id: str) -> bytes:
    target = raw_path + (b"?" + query if query else b"")
    return b"\n".join([method.encode(), target, timestamp.encode(), nonce.encode(),
                       hashlib.sha256(body).hexdigest().encode(), key_id.encode()])


def live_nonces(caller: str) -> tuple[set[str], list[tuple[int, str]]]:
    """caller's nonces whose timestamps are still inside the window (older ones are dropped here)."""
    seen, expiry = _nonces.setdefault(caller, (set(), []))
    now = time.time()
    while expiry and expiry[0][0] < now:
        seen.discard(heapq.heappop(expiry)[1])
    return seen, expiry


def nonce_quota_wait(seen: set[str], expiry: list[tuple[int, str]]) -> int:
    """0 if caller may store another nonce, else seconds until its oldest one expires."""
    if len(seen) < MAX_NONCES_PER_CALLER:
        return 0
    return max(1, math.ceil(expiry[0][0] - time.time()))


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


def retry_after(caller: str, method: str) -> int:
    """Per rpc method: 0 if allowed (a token is spent), else whole seconds until the next token. Methods without a
    limit are free here (every signed request already paid the caller's general bucket)."""
    if not isinstance(method, str) or method not in LIMITS:
        return 0
    rate, size = LIMITS[method]
    return take((caller, BUCKET_OF.get(method, method)), rate, size)


def take(slot: tuple[str, str], rate: float, size: float) -> int:
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
    """A header value that isn't shaped like a key_id is never logged (it could be a misplaced secret)."""
    shown = key_id if KEY_ID_RE.fullmatch(key_id) else ("malformed" if key_id else "-")
    LOG.warning("unauthorized reason=%s key_id=%s path=%s", reason, shown, log_safe(request.url.path))
    request.state.key_id = f"invalid:{shown}" if key_id else "none"
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
    if abs(time.time() - int(timestamp)) > SIGNATURE_SKEW_S:
        return unauthorized(request, key_id, "stale_timestamp")
    body = await read_body(request)
    if body is None:
        request.state.key_id = f"unverified:{key_id}"
        return JSONResponse({"error": "request body too large"}, status_code=413)
    caller, secret = SIGNING_KEYS.get(key_id, (None, DUMMY_SECRET))
    message = canonical(request.method, request.scope["raw_path"], request.scope["query_string"], timestamp, nonce, body,
                        key_id)
    matches = hmac.compare_digest(hmac.new(secret, message, hashlib.sha256).hexdigest(), signature)
    if caller is None:
        return unauthorized(request, key_id, "unknown_key")
    if not matches:
        return unauthorized(request, key_id, "bad_signature")
    seen, expiry = live_nonces(caller)
    if nonce in seen:
        return unauthorized(request, key_id, "replayed_nonce")
    wait = take((caller, ""), REQUESTS_PER_S, REQUESTS_BURST) or nonce_quota_wait(seen, expiry)
    if wait:
        LOG.warning("rate limited key_id=%s caller=%s live_nonces=%d retry_after=%d", key_id, caller, len(seen), wait)
        request.state.key_id = key_id
        return rate_limited(wait)
    seen.add(nonce)
    heapq.heappush(expiry, (int(timestamp) + SIGNATURE_SKEW_S, nonce))
    request.state.key_id = key_id
    request.state.caller = caller
    request.state.body = body
    LOG.info("request key_id=%s caller=%s %s %s", key_id, log_safe(caller), request.method, log_safe(request.url.path))
    return await call_next(request)
