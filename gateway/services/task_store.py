"""In-memory task store and task execution."""
import asyncio
import re
import time
import uuid

from gateway.config import AGENT_CONCURRENCY, LOG, MAX_INFLIGHT_PER_KEY, MAX_PENDING, MAX_TASKS_PER_KEY, MAX_TEXT, TASK_TTL, log_safe
from gateway.models import extract_text, make_agent_message, now, rpc_error
from gateway.services.agent_runner import run_agent
from gateway.services.notifier import notify
from gateway.telemetry import event

tasks: dict[str, dict] = {}
store_lock = asyncio.Lock()
agent_sem = asyncio.Semaphore(AGENT_CONCURRENCY)


BUSY = {"busy": True}


def owned_task(task_id, key_id: str) -> dict | None:
    """The task entry if key_id created it; anyone else gets the same None as a missing id."""
    entry = tasks.get(task_id) if isinstance(task_id, str) else None
    return entry if entry and entry["owner"] == key_id else None


def prune_tasks():
    t = time.time()
    dead = [k for k, v in tasks.items() if v["expires"] < t]
    for k in dead:
        tasks.pop(k, None)


async def execute_task(task_id: str, ctx_id: str, text: str, queue: asyncio.Queue | None):
    entry = tasks[task_id]
    try:
        await _execute_task(entry, task_id, ctx_id, text, queue)
    finally:
        entry["running"] = False


async def _execute_task(entry: dict, task_id: str, ctx_id: str, text: str, queue: asyncio.Queue | None):
    session = f"a2a-{entry['owner']}-" + re.sub(r"[^A-Za-z0-9-]", "-", ctx_id)[:64]

    async def emit(ev):
        if queue is not None:
            await queue.put(ev)

    task = entry["task"]
    started = time.time()

    await notify("task_started", task_id, ctx_id)

    await emit({
        "kind": "status-update", "taskId": task_id, "contextId": ctx_id,
        "final": False, "status": {"state": "working", "timestamp": now()},
    })

    async with agent_sem:
        try:
            reply = await run_agent(session, text)
            state = "completed"
        except Exception as e:
            LOG.error("agent run failed task=%s error_type=%s", log_safe(task_id), type(e).__name__)
            reply = f"agent error (task {task_id})"
            state = "failed"

    status = {"state": state, "message": make_agent_message(reply), "timestamp": now()}
    task["status"] = status
    task["final"] = True
    task.setdefault("history", []).append(status["message"])
    if state == "completed":
        artifact = {
            "artifactId": str(uuid.uuid4()),
            "name": "reply",
            "index": 0,
            "parts": [{"kind": "text", "text": reply}],
        }
        task["artifacts"] = [artifact]
        await emit({
            "kind": "artifact-update", "taskId": task_id, "contextId": ctx_id,
            "final": False, "artifact": artifact,
        })
    await emit({
        "kind": "status-update", "taskId": task_id, "contextId": ctx_id,
        "final": True, "status": status,
    })
    if queue is not None:
        await queue.put(None)
    entry["done"].set()
    event("task_finished", task_id=task_id, context_id=ctx_id, state=state,
          duration_ms=int((time.time() - started) * 1000))
    await notify(f"task_{state}", task_id, ctx_id, {
        "state": state,
        "reply": reply[:4000],
        "durationMs": int((time.time() - started) * 1000),
    })


async def start_task(req_id, params, queue: asyncio.Queue | None, key_id: str):
    """Task ids are always minted here (a client taskId is ignored), and the task belongs to key_id.
    Returns BUSY when the key or the gateway has too many tasks running or queued. Past MAX_TASKS_PER_KEY stored
    tasks, the key's oldest finished ones are dropped."""
    msg = params.get("message") or {}
    if msg.get("role") not in (None, "user"):
        return rpc_error(req_id, -32602, "only user-role messages accepted")
    text = extract_text(msg)
    if not text:
        return rpc_error(req_id, -32602, "empty message")
    if len(text) > MAX_TEXT:
        return rpc_error(req_id, -32602, "message too large")

    task_id = str(uuid.uuid4())
    ctx_id = msg.get("contextId") or str(uuid.uuid4())

    # F26: never log message bodies; ids and length only.
    if msg.get("messageId"):
        LOG.info("inbound task_id=%s message_id=%s len=%d", log_safe(task_id), log_safe(msg.get("messageId")), len(text))
    else:
        LOG.info("inbound task_id=%s len=%d", log_safe(task_id), len(text))

    async with store_lock:
        prune_tasks()
        running = [e["owner"] for e in tasks.values() if e["running"]]
        if len(running) >= MAX_PENDING or running.count(key_id) >= MAX_INFLIGHT_PER_KEY:
            LOG.warning("busy key_id=%s running_for_key=%d running=%d", key_id, running.count(key_id), len(running))
            return BUSY
        mine = [k for k, e in tasks.items() if e["owner"] == key_id and not e["running"]]
        for k in mine[:max(0, len(mine) + 1 - MAX_TASKS_PER_KEY)]:
            tasks.pop(k)
        tasks[task_id] = {
            "owner": key_id,
            "running": True,
            "task": {
                "id": task_id, "contextId": ctx_id, "kind": "task",
                "status": {"state": "submitted", "timestamp": now()},
                "artifacts": [], "history": [],
                "final": False,
            },
            "created": time.time(),
            "expires": time.time() + TASK_TTL,
            "done": asyncio.Event(),
        }

    asyncio.create_task(execute_task(task_id, ctx_id, text, queue))
    return {"taskId": task_id, "contextId": ctx_id}
