"""Ed25519-signed requests (X-KC-* headers, callers' public keys from GATEWAY_PUBLIC_KEYS_FILE) and per-key token buckets."""
import asyncio
import contextvars
import hashlib
import heapq
import logging
import math
import os
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from gateway.config import (BODY_IDLE_TIMEOUT_S, BODY_READ_TIMEOUT_S, CANCEL_PER_S, CREATE_BURST, CREATE_PER_MIN,
                            GET_PER_S, KEY_ID_RE, LOG, MAX_BODY, MAX_NONCES_PER_CALLER, READS_PER_CALLER,
                            REQUESTS_BURST, REQUESTS_PER_S, SIGNATURE_FUTURE_S, SIGNATURE_PAST_S, PUBLIC_KEYS,
                            log_safe)

PUBLIC_PATHS = {"/.well-known/agent.json", "/healthz", "/readyz"}
HEADERS = ("x-kc-key-id", "x-kc-timestamp", "x-kc-nonce", "x-kc-signature", "x-kc-content-sha256")
TIMESTAMP_RE = re.compile(r"[0-9]{1,12}")
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")
SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
CONTENT_SHA256_RE = re.compile(r"[0-9a-f]{64}")
STARTED_S = int(time.time())  # nonces don't survive a restart; reject timestamps at or before STARTED_S + FUTURE_S
_reads: dict[str, int] = {}  # in-progress body reads per caller (only after a valid signature)
READ_FAILURES = {"too_large": (413, "request body too large"), "read_deadline": (408, "request timeout"),
                 "read_idle": (408, "request timeout"), "client_disconnected": (400, "client disconnected")}
QUIET_READS = {"pool_full", "read_deadline", "read_idle"}  # 429/408: aggregate, no per-request log or trace
_refusals: dict[str, dict] = {}  # pool_name -> {reasons, task}
REFUSAL_LOG_S = float(os.environ.get("GATEWAY_REFUSAL_LOG_S", "1"))
_quiet_log = contextvars.ContextVar("kc_quiet_log", default=False)


class _SkipQuietAccess(logging.Filter):
    """Drop uvicorn access-log lines for quiet refusals (precheck 401s and pool 429/408)."""

    def filter(self, record):
        return not _quiet_log.get()


def install_access_log_filter():
    log = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _SkipQuietAccess) for f in log.filters):
        log.addFilter(_SkipQuietAccess())


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


def canonical(method: str, raw_path: bytes, query: bytes, timestamp: str, nonce: str, body_sha256: str, key_id: str) -> bytes:
    target = raw_path + (b"?" + query if query else b"")
    return b"\n".join([method.encode(), target, timestamp.encode(), nonce.encode(), body_sha256.encode(), key_id.encode()])


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


async def hash_body(request: Request) -> tuple[str, bytearray] | str:
    """(sha256 hex, body) hashed chunk by chunk. Else a READ_FAILURES reason: over MAX_BODY, past the total
    deadline, idle too long between chunks, or the client went away."""
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_BODY:
        return "too_large"
    digest, body, size = hashlib.sha256(), bytearray(), 0
    chunks = request.stream().__aiter__()
    try:
        async with asyncio.timeout(BODY_READ_TIMEOUT_S):
            while True:
                try:
                    chunk = await asyncio.wait_for(anext(chunks), BODY_IDLE_TIMEOUT_S)
                except StopAsyncIteration:
                    return digest.hexdigest(), body
                except TimeoutError:
                    return "read_idle"
                size += len(chunk)
                if size > MAX_BODY:
                    return "too_large"
                digest.update(chunk)
                body += chunk
    except TimeoutError:
        return "read_deadline"
    except ClientDisconnect:
        return "client_disconnected"


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


def verified(key: Ed25519PublicKey, signature: str, message: bytes) -> bool:
    try:
        key.verify(bytes.fromhex(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def rate_limited(wait: int) -> JSONResponse:
    return JSONResponse({"error": "rate limited"}, status_code=429, headers={"Retry-After": str(wait)})


def unauthorized() -> JSONResponse:
    """Byte-identical generic 401 for every pre-body and body-hash refusal."""
    return JSONResponse({"error": "unauthorized"}, status_code=401)


def emit_refusals(pool_name: str, reasons: dict[str, int]):
    count = sum(reasons.values())
    parts = ",".join(f"{k}:{v}" for k, v in sorted(reasons.items()))
    if pool_name == "precheck":
        LOG.warning("auth refused count=%d reasons=%s", count, parts)
    else:
        LOG.warning("read refused pool=%s count=%d reasons=%s", pool_name, count, parts)


async def _flush_refusals(pool_name: str):
    await asyncio.sleep(max(0.0, REFUSAL_LOG_S))
    rec = _refusals.get(pool_name)
    if rec is None:
        return
    reasons, rec["reasons"] = rec["reasons"], {}
    rec["task"] = None
    if reasons:
        emit_refusals(pool_name, reasons)
    if rec["reasons"] and rec["task"] is None:
        rec["task"] = asyncio.get_running_loop().create_task(_flush_refusals(pool_name))


def note_refusal(request: Request, pool_name: str, reason: str):
    """Quiet refusal: one aggregated log line per pool per interval, no per-request log, trace, or access log."""
    request.state.quiet_read = True
    _quiet_log.set(True)
    rec = _refusals.setdefault(pool_name, {"reasons": {}, "task": None})
    rec["reasons"][reason] = rec["reasons"].get(reason, 0) + 1
    if REFUSAL_LOG_S <= 0:
        reasons, rec["reasons"] = rec["reasons"], {}
        if reasons:
            emit_refusals(pool_name, reasons)
        return
    if rec["task"] is None:
        rec["task"] = asyncio.get_running_loop().create_task(_flush_refusals(pool_name))


def quiet_unauthorized(request: Request, reason: str) -> JSONResponse:
    note_refusal(request, "precheck", reason)
    return unauthorized()


# rpc method -> (tokens per second, bucket size) already defined above


async def signed_auth(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    values = [request.headers.getlist(h) for h in HEADERS]
    key_id, timestamp, nonce, signature, body_sha256 = (v[0] if v else "" for v in values)
    # 1. header shape
    if any(len(v) > 1 for v in values):
        return quiet_unauthorized(request, "duplicate_header")
    if not (key_id and timestamp and nonce and signature and body_sha256):
        return quiet_unauthorized(request, "missing_header")
    if not (KEY_ID_RE.fullmatch(key_id) and TIMESTAMP_RE.fullmatch(timestamp) and NONCE_RE.fullmatch(nonce)
            and SIGNATURE_RE.fullmatch(signature) and CONTENT_SHA256_RE.fullmatch(body_sha256)):
        return quiet_unauthorized(request, "malformed_header")
    # 2. timestamp window and restart rule (before any key lookup)
    if not -SIGNATURE_FUTURE_S <= time.time() - int(timestamp) <= SIGNATURE_PAST_S:
        return quiet_unauthorized(request, "stale_timestamp")
    if int(timestamp) <= STARTED_S + SIGNATURE_FUTURE_S:
        return quiet_unauthorized(request, "stale_after_restart")
    # 3. key lookup. Unknown key_ids are refused here; there is no dummy verify.
    found = PUBLIC_KEYS.get(key_id)
    if found is None:
        return quiet_unauthorized(request, "unknown_key")
    caller, key = found
    request.state.key_id = f"unverified:{key_id}"
    message = canonical(request.method, request.scope["raw_path"], request.scope["query_string"], timestamp, nonce,
                        body_sha256, key_id)
    if not verified(key, signature, message):
        return quiet_unauthorized(request, "bad_signature")
    # nonce is consumed at verification; quota and the general bucket follow a valid verify
    seen, expiry = live_nonces(caller)
    if nonce in seen:
        return quiet_unauthorized(request, "replayed_nonce")
    wait = nonce_quota_wait(seen, expiry) or take((caller, ""), REQUESTS_PER_S, REQUESTS_BURST)
    if wait:
        LOG.warning("rate limited key_id=%s caller=%s live_nonces=%d retry_after=%d", key_id, caller, len(seen), wait)
        request.state.key_id = key_id
        return rate_limited(wait)
    seen.add(nonce)
    heapq.heappush(expiry, (int(timestamp) + SIGNATURE_PAST_S, nonce))
    request.state.key_id = key_id
    request.state.caller = caller
    # 4. only a verified request may take this caller's reserved read slot
    if _reads.get(caller, 0) >= READS_PER_CALLER:
        note_refusal(request, "caller", "pool_full")
        return rate_limited(1)
    _reads[caller] = _reads.get(caller, 0) + 1
    try:
        hashed = await hash_body(request)
    finally:
        _reads[caller] -= 1
    if isinstance(hashed, str):
        if hashed in QUIET_READS:
            note_refusal(request, "caller", hashed)
        else:
            LOG.warning("read failed pool=caller reason=%s key_id=%s", hashed, key_id)
        status, error = READ_FAILURES[hashed]
        return JSONResponse({"error": error}, status_code=status)
    got_sha, body = hashed
    if got_sha != body_sha256:
        return quiet_unauthorized(request, "body_hash_mismatch")
    request.state.body = body
    LOG.info("request key_id=%s caller=%s %s %s", key_id, log_safe(caller), request.method, log_safe(request.url.path))
    return await call_next(request)
