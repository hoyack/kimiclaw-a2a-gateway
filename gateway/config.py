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
MIN_API_KEY_LEN = 32


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


def _load_api_keys(default_token: str) -> dict:
    """GATEWAY_API_KEYS="caller:key,caller:key" gives each caller its own key; unset keeps KIMICLAW_TOKEN as the
    only key (caller "default"). Errors name the entry position, never the key."""
    raw = os.environ.get("GATEWAY_API_KEYS", "").strip()
    if not raw:
        return {"default": default_token}
    keys = {}
    for i, entry in enumerate(raw.split(","), 1):
        name, sep, key = entry.strip().partition(":")
        name, key = name.strip(), key.strip()
        if not sep or not name or len(key) < MIN_API_KEY_LEN:
            raise RuntimeError(f"GATEWAY_API_KEYS entry {i}: want caller:key with a key of at least {MIN_API_KEY_LEN} chars")
        if name in keys or key in keys.values():
            raise RuntimeError(f"GATEWAY_API_KEYS entry {i}: duplicate caller name or key")
        keys[name] = key
    return keys


TOKEN = _load_token()
API_KEYS = _load_api_keys(TOKEN)
RATE_LIMIT = int(os.environ.get("GATEWAY_RATE_LIMIT", "60"))
RATE_WINDOW_S = int(os.environ.get("GATEWAY_RATE_WINDOW_S", "60"))
PUBLIC_URL = os.environ.get("GATEWAY_PUBLIC_URL", "").strip() or "https://kimiclaw.hoyack.ai/"
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
