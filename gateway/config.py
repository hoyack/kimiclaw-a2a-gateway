"""Env-based settings. Names, defaults and the .env fallback match the original app.py."""
import logging
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOG = logging.getLogger("kimiclaw")

MAX_LOG_ID = 128


def log_safe(value) -> str:
    """Client-supplied values (taskId, messageId, JSON-RPC id) go in log lines: escape control chars,
    line/paragraph separators and NEL (no log forging) and cap the length."""
    s = str(value)[:MAX_LOG_ID]
    return "".join(
        c if c.isprintable() else (f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}")
        for c in s
    )


def _load_token() -> str:
    """Env var first, then .env. Missing or empty fails at startup with a clear message (never the value)."""
    tok = (os.environ.get("KIMICLAW_TOKEN") or "").strip()
    if not tok:
        env_path = os.path.join(BASE_DIR, ".env")
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.startswith("KIMICLAW_TOKEN="):
                        tok = line.split("=", 1)[1].strip()
                        break
    if not tok:
        raise RuntimeError("KIMICLAW_TOKEN not set (set the env var or add KIMICLAW_TOKEN=... to .env; empty is refused)")
    return tok


TOKEN = _load_token()
NOTIFY_URL = os.environ.get("GATEWAY_NOTIFY_URL", "").strip()
NOTIFY_AUTH_MODE = os.environ.get("GATEWAY_NOTIFY_AUTH_MODE", "raw").lower()
NOTIFY_AUTH_USER = os.environ.get("GATEWAY_NOTIFY_AUTH_USER", "agent")
NOTIFY_EVENTS = {e.strip() for e in os.environ.get(
    "GATEWAY_NOTIFY_EVENTS", "task_completed,task_failed").split(",") if e.strip()}
NOTIFY_TIMEOUT = 10
NOTIFY_FAIL_LIMIT = int(os.environ.get("GATEWAY_NOTIFY_FAIL_LIMIT", "5"))
NOTIFY_COOLDOWN_S = int(os.environ.get("GATEWAY_NOTIFY_COOLDOWN_S", "900"))
MAX_TEXT = 200_000
AGENT_TIMEOUT = 560           # seconds, passed to openclaw
AGENT_CONCURRENCY = 3         # concurrent agent turns
TASK_TTL = 24 * 3600          # task retention
