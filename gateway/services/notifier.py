"""Outbound task-event webhook (n8n AI firewall). Wire format must stay byte-identical."""
import asyncio
import json
import time
import urllib.parse
import urllib.request

from gateway.config import LOG, log_safe, TOKEN, NOTIFY_AUTH_MODE, NOTIFY_AUTH_USER, NOTIFY_TIMEOUT, NOTIFY_URL, NOTIFY_EVENTS, NOTIFY_FAIL_LIMIT, NOTIFY_COOLDOWN_S
from gateway.models import now
from gateway.telemetry import breaker_opens, notify_failures, tracer

_notify_fails = 0
_notify_disabled_until = 0.0


async def _post_json(url: str, payload: dict):
    """Fire-and-forget POST. Authorization shape per NOTIFY_AUTH_MODE:
    basic -> Basic base64(user:KIMICLAW_TOKEN); bearer -> Bearer token; raw -> token."""
    if NOTIFY_AUTH_MODE == "basic":
        import base64
        cred = base64.b64encode(f"{NOTIFY_AUTH_USER}:{TOKEN}".encode()).decode()
        auth = f"Basic {cred}"
    elif NOTIFY_AUTH_MODE == "bearer":
        auth = f"Bearer {TOKEN}"
    else:
        auth = TOKEN
    def _do():
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": auth},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=NOTIFY_TIMEOUT) as resp:
            return resp.status
    return await asyncio.to_thread(_do)


async def notify(event: str, task_id: str, ctx_id: str, extra: dict | None = None):
    global _notify_fails, _notify_disabled_until
    if not NOTIFY_URL or event not in NOTIFY_EVENTS:
        return
    if time.time() < _notify_disabled_until:
        return
    payload = {
        "event": event,
        "source": "kimiclaw-a2a-gateway",
        "taskId": task_id,
        "contextId": ctx_id,
        "timestamp": now(),
    }
    if extra:
        payload.update(extra)
    span = tracer.start_span("notify", attributes={"notify.event": event, "task.id": task_id})
    try:
        status = await _post_json(NOTIFY_URL, payload)
        span.set_attribute("http.response.status_code", status)
        _notify_fails = 0
        LOG.info("notify %s task=%s -> %s", event, log_safe(task_id), status)
    except Exception as e:
        _notify_fails += 1
        notify_failures.add(1, {"notify.event": event})
        span.set_attribute("error", True)
        LOG.warning("notify %s task=%s failed (%d/%d) host=%s error_type=%s",
                    event, log_safe(task_id), _notify_fails, NOTIFY_FAIL_LIMIT,
                    urllib.parse.urlsplit(NOTIFY_URL).hostname, type(e).__name__)
        if _notify_fails >= NOTIFY_FAIL_LIMIT:
            _notify_disabled_until = time.time() + NOTIFY_COOLDOWN_S
            _notify_fails = 0
            breaker_opens.add(1)
            LOG.error("notify circuit breaker OPEN: outbound webhooks paused %ds",
                      NOTIFY_COOLDOWN_S)
    finally:
        span.end()
