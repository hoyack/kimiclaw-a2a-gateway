"""Runs one OpenClaw turn as a subprocess and extracts the reply."""
import asyncio
import json
import time

from gateway.config import AGENT_TIMEOUT, LOG
from opentelemetry.trace import Status, StatusCode

from gateway.telemetry import agent_ms, tracer


def _last_json_block(raw: str):
    """Find the last parseable top-level JSON object in a noisy stream."""
    idx = raw.rfind("\n{")
    while idx != -1:
        try:
            return json.loads(raw[idx + 1:])
        except json.JSONDecodeError:
            idx = raw.rfind("\n{", 0, idx)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def parse_agent_reply(raw: str) -> str:
    """Best-effort extraction of reply text from openclaw --json output."""
    raw = raw.strip()
    obj = _last_json_block(raw)
    if obj is None:
        return raw
    if isinstance(obj, dict):
        texts = [p["text"] for p in (obj.get("payloads") or [])
                 if isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"]]
        if texts:
            return "\n".join(texts)
        for key in ("reply", "text", "result", "message", "output", "response"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                return v
    return raw


async def run_agent(session_id: str, text: str) -> str:
    started = time.perf_counter()
    # No record_exception: agent stderr can echo message text, and telemetry must never carry it.
    with tracer.start_as_current_span("agent.run", attributes={"session.id": session_id},
                                      record_exception=False, set_status_on_exception=False) as span:
        try:
            return await _run_agent(session_id, text)
        except BaseException as e:
            span.set_status(Status(StatusCode.ERROR, type(e).__name__))
            span.set_attribute("error.type", type(e).__name__)
            raise
        finally:
            agent_ms.record((time.perf_counter() - started) * 1000)


async def _run_agent(session_id: str, text: str) -> str:
    cmd = [
        "openclaw", "agent",
        "--local",
        "--session-id", session_id,
        "--message", text,
        "--json",
        "--timeout", str(AGENT_TIMEOUT),
    ]
    LOG.info("agent run start session=%s len=%d", session_id, len(text))
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=AGENT_TIMEOUT + 30)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError("agent timeout")
    if proc.returncode != 0:
        raise RuntimeError(f"agent exited {proc.returncode}: {err.decode(errors='replace')[-500:]}")
    # openclaw --json emits the result envelope on stderr after log noise
    raw_out = out.decode(errors="replace").strip()
    raw_err = err.decode(errors="replace").strip()
    reply = parse_agent_reply(raw_out) if raw_out else None
    if not reply or reply == raw_out and raw_err:
        parsed = parse_agent_reply(raw_err)
        if parsed != raw_err or not reply:
            reply = parsed
    reply = reply or ""
    LOG.info("agent run done session=%s reply_len=%d", session_id, len(reply))
    return reply
