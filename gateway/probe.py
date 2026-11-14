"""Uncapped probe listener: GET /healthz and GET /readyz only. Not the main app."""
import contextvars
import json
import shutil

import h11

# Per-task counter: a probe swallow must not hide a main-port incomplete-response line.
_drop_incomplete: contextvars.ContextVar[int] = contextvars.ContextVar("drop_incomplete", default=0)

from gateway.routes import health as health_state

_JSON = [(b"content-type", b"application/json")]


def _already_sent(exc: BaseException) -> bool:
    """True when uvicorn already sent a 400 or closed, and this send cannot go out."""
    msg = str(exc)
    if isinstance(exc, h11.LocalProtocolError) and "can't handle event type Response" in msg:
        return True
    if isinstance(exc, RuntimeError) and "after response already completed" in msg:
        return True
    return False


async def _send(send, status: int, body: dict):
    raw = json.dumps(body).encode()
    try:
        await send({"type": "http.response.start", "status": status,
                    "headers": _JSON + [(b"content-length", str(len(raw)).encode())]})
        await send({"type": "http.response.body", "body": raw})
    except (h11.LocalProtocolError, RuntimeError) as exc:
        if not _already_sent(exc):
            raise
        from gateway.auth import note_quiet
        note_incomplete_drop()
        note_quiet("http", "malformed")


def note_incomplete_drop() -> None:
    _drop_incomplete.set(_drop_incomplete.get() + 1)


def take_incomplete_drop() -> bool:
    """True once after probe._send swallowed an already-sent failure on this task."""
    n = _drop_incomplete.get()
    if n <= 0:
        return False
    _drop_incomplete.set(n - 1)
    return True


async def probe_app(scope, receive, send):
    """Plain ASGI callable. No auth, no pools, no cap, no telemetry. Never reads the HTTP body."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
        return
    if scope["type"] != "http":
        return
    path, method = scope.get("path", ""), scope.get("method", "")
    if method == "GET" and path == "/healthz":
        await _send(send, 200, {"status": "up"})
        return
    if method == "GET" and path == "/readyz":
        if not health_state.MAIN_SERVING:
            await _send(send, 503, {"status": "starting"})
        elif health_state.require_openclaw() and shutil.which("openclaw") is None:
            await _send(send, 503, {"status": "not ready"})
        else:
            await _send(send, 200, {"status": "ready"})
        return
    await _send(send, 404, {"status": "not found"})
