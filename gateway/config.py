"""Env-based settings. Names, defaults and the .env fallback match the original app.py."""
import logging
import os
import re
import stat

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOG = logging.getLogger("kimiclaw")

MAX_LOG_ID = 128
KEY_ID_RE = re.compile(r"[a-z0-9]{8,12}")
SECRET_RE = re.compile(r"[A-Za-z0-9_-]{43,128}")


def log_safe(value) -> str:
    """Client-supplied values (taskId, messageId, JSON-RPC id) go in log lines: escape control chars,
    line/paragraph separators and NEL (no log forging) and cap the length."""
    s = str(value)[:MAX_LOG_ID]
    return "".join(
        c if c.isprintable() else (f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}")
        for c in s
    )


def _load_token() -> str:
    """Env var first, then .env. Needed only when GATEWAY_NOTIFY_URL is set; then missing or empty fails at startup
    with a clear message (never the value)."""
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
        raise RuntimeError("KIMICLAW_TOKEN not set but GATEWAY_NOTIFY_URL is (set the env var or add KIMICLAW_TOKEN=... to .env; empty is refused)")
    return tok


def load_signing_keys(path: str) -> dict[str, tuple[str, bytes]]:
    """Signing keys file: one `<key_id> <caller> <secret>` per line; blank lines and # comments skipped.
    Missing, empty, malformed, or readable/writable by others (or group-writable) refuses startup.
    Errors name the line number, never its content."""
    if not path:
        raise RuntimeError("GATEWAY_SIGNING_KEYS_FILE not set (path to the per-caller signing secrets file)")
    try:
        with open(path) as f:
            mode = os.fstat(f.fileno()).st_mode
            lines = f.read().splitlines()
    except OSError as e:
        raise RuntimeError(f"GATEWAY_SIGNING_KEYS_FILE unreadable: {type(e).__name__}") from None
    if mode & (stat.S_IWGRP | stat.S_IRWXO):
        raise RuntimeError(f"GATEWAY_SIGNING_KEYS_FILE mode {stat.S_IMODE(mode):o} is too open (want 0400, 0440, 0600 or 0640)")
    keys = {}
    for n, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3 or not KEY_ID_RE.fullmatch(parts[0]) or not SECRET_RE.fullmatch(parts[2]) or parts[0] in keys:
            raise RuntimeError(f"GATEWAY_SIGNING_KEYS_FILE line {n}: want unique `<key_id> <caller> <secret>`")
        keys[parts[0]] = (parts[1], parts[2].encode())
    if not keys:
        raise RuntimeError("GATEWAY_SIGNING_KEYS_FILE has no keys")
    return keys


NOTIFY_URL = os.environ.get("GATEWAY_NOTIFY_URL", "").strip()
TOKEN = _load_token() if NOTIFY_URL else ""  # outbound notify credential only; never accepted inbound
SIGNING_KEYS = load_signing_keys(os.environ.get("GATEWAY_SIGNING_KEYS_FILE", "").strip())
SIGNATURE_SKEW_S = 300
MAX_NONCES = 100_000
CREATE_PER_MIN = float(os.environ.get("GATEWAY_CREATE_PER_MIN", "10"))
CREATE_BURST = int(os.environ.get("GATEWAY_CREATE_BURST", "5"))
GET_PER_S = float(os.environ.get("GATEWAY_GET_PER_S", "2"))
CANCEL_PER_S = float(os.environ.get("GATEWAY_CANCEL_PER_S", "1"))
MAX_BODY = 1_000_000
MAX_INFLIGHT_PER_KEY = int(os.environ.get("GATEWAY_MAX_INFLIGHT_PER_KEY", "2"))
MAX_PENDING = int(os.environ.get("GATEWAY_MAX_PENDING", "50"))
MAX_TASKS_PER_KEY = int(os.environ.get("GATEWAY_MAX_TASKS_PER_KEY", "100"))
PUBLIC_URL = os.environ.get("GATEWAY_PUBLIC_URL", "").strip() or "https://kimiclaw.hoyack.ai/"
NOTIFY_AUTH_MODE = os.environ.get("GATEWAY_NOTIFY_AUTH_MODE", "raw").lower()
NOTIFY_AUTH_USER = os.environ.get("GATEWAY_NOTIFY_AUTH_USER", "agent")
NOTIFY_EVENTS = {e.strip() for e in os.environ.get(
    "GATEWAY_NOTIFY_EVENTS", "task_completed,task_failed").split(",") if e.strip()}
NOTIFY_TIMEOUT = 10
NOTIFY_FAIL_LIMIT = int(os.environ.get("GATEWAY_NOTIFY_FAIL_LIMIT", "5"))
NOTIFY_COOLDOWN_S = int(os.environ.get("GATEWAY_NOTIFY_COOLDOWN_S", "900"))
MAX_TEXT = 100_000
AGENT_TIMEOUT = 560           # seconds, passed to openclaw
AGENT_CONCURRENCY = 3         # concurrent agent turns
TASK_TTL = 24 * 3600          # task retention

if os.environ.get("WEB_CONCURRENCY", "1").strip() not in ("", "1"):
    raise RuntimeError("WEB_CONCURRENCY must be 1: rate limits and task caps are per process")
if AGENT_CONCURRENCY > 1 and MAX_INFLIGHT_PER_KEY >= AGENT_CONCURRENCY:
    raise RuntimeError(f"GATEWAY_MAX_INFLIGHT_PER_KEY must be below {AGENT_CONCURRENCY} so one key can't hold every agent slot")
