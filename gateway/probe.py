"""Uncapped probe listener: GET /healthz and GET /readyz only. Not the main app."""
import json
import shutil

from gateway.routes import health as health_state

_JSON = [(b"content-type", b"application/json")]


async def _send(send, status: int, body: dict):
    raw = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": _JSON + [(b"content-length", str(len(raw)).encode())]})
    await send({"type": "http.response.body", "body": raw})


async def probe_app(scope, receive, send):
    """Plain ASGI callable. No auth, no pools, no cap, no telemetry."""
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
        elif shutil.which("openclaw") is None:
            await _send(send, 503, {"status": "not ready"})
        else:
            await _send(send, 200, {"status": "ready"})
        return
    await _send(send, 404, {"status": "not found"})
