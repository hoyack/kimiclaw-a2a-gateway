"""Env-based settings. Names, defaults and the .env fallback match the original app.py."""
import logging
import os
import re
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gateway.pubkey import public_key

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOG = logging.getLogger("kimiclaw")

MAX_LOG_ID = 128
KEY_ID_RE = re.compile(r"[0-9a-f]{10}")  # exactly what tools/new_api_key.py mints (token_hex(5))
CALLER_RE = re.compile(r"[A-Za-z0-9_]{1,32}")
PUBLIC_KEYS_HEADER = "# kimiclaw-public-keys v1"


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


def load_public_keys(path: str) -> dict[str, tuple[str, Ed25519PublicKey]]:
    """Public keys file: first line must be `# kimiclaw-public-keys v1`, then one `<key_id> <caller> <public_key>`
    per line; blank lines and # comments skipped. A caller may have several key_ids (rotation). Missing, empty,
    malformed, missing the header, or writable by group or others refuses startup. Errors name the line number,
    never its content. Setting GATEWAY_SIGNING_KEYS_FILE (the old HMAC secrets path) refuses startup, even if
    GATEWAY_PUBLIC_KEYS_FILE is also set."""
    if "GATEWAY_SIGNING_KEYS_FILE" in os.environ:
        raise RuntimeError("GATEWAY_SIGNING_KEYS_FILE is set; it held HMAC secrets and is no longer read. "
                           "Unset it and set GATEWAY_PUBLIC_KEYS_FILE to the callers' Ed25519 public keys "
                           "(mint with tools/new_api_key.py). The file must start with `# kimiclaw-public-keys v1`")
    if not path:
        raise RuntimeError("GATEWAY_PUBLIC_KEYS_FILE not set (path to the callers' Ed25519 public keys; "
                           "first line must be `# kimiclaw-public-keys v1`)")
    try:
        with open(path) as f:
            mode = os.fstat(f.fileno()).st_mode
            lines = f.read().splitlines()
    except OSError as e:
        raise RuntimeError(f"GATEWAY_PUBLIC_KEYS_FILE unreadable: {type(e).__name__}") from None
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(f"GATEWAY_PUBLIC_KEYS_FILE mode {stat.S_IMODE(mode):o} is writable by group or others")
    if not lines or lines[0] != PUBLIC_KEYS_HEADER:
        raise RuntimeError("GATEWAY_PUBLIC_KEYS_FILE: first line must be `# kimiclaw-public-keys v1`")
    keys = {}
    for n, line in enumerate(lines, 1):
        if n == 1 or not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split()
        key = public_key(parts[2]) if len(parts) == 3 else None
        if key is None or not KEY_ID_RE.fullmatch(parts[0]) or not CALLER_RE.fullmatch(parts[1]) or parts[0] in keys:
            raise RuntimeError(f"GATEWAY_PUBLIC_KEYS_FILE line {n}: want unique `<key_id> <caller> <public_key>` "
                               "(key_id: 10 lowercase hex; caller: up to 32 of A-Z a-z 0-9 _; "
                               "public_key: 32-byte canonical on-curve Ed25519 key of order > 8, unpadded base64url)")
        keys[parts[0]] = (parts[1], key)
    if not keys:
        raise RuntimeError("GATEWAY_PUBLIC_KEYS_FILE has no keys")
    return keys


NOTIFY_URL = os.environ.get("GATEWAY_NOTIFY_URL", "").strip()
TOKEN = _load_token() if NOTIFY_URL else ""  # outbound notify credential only; never accepted inbound
PUBLIC_KEYS = load_public_keys(os.environ.get("GATEWAY_PUBLIC_KEYS_FILE", "").strip())
SIGNATURE_PAST_S = int(os.environ.get("GATEWAY_SIGNATURE_PAST_S", "300"))
SIGNATURE_FUTURE_S = int(os.environ.get("GATEWAY_SIGNATURE_FUTURE_S", "30"))
if not 0 <= SIGNATURE_FUTURE_S <= SIGNATURE_PAST_S:
    raise RuntimeError("want 0 <= GATEWAY_SIGNATURE_FUTURE_S <= GATEWAY_SIGNATURE_PAST_S")
MAX_NONCES_PER_CALLER = int(os.environ.get("GATEWAY_MAX_NONCES_PER_CALLER", "20000"))
REQUESTS_PER_S = float(os.environ.get("GATEWAY_REQUESTS_PER_S", "5"))
REQUESTS_BURST = int(os.environ.get("GATEWAY_REQUESTS_BURST", "10"))
READS_PER_CALLER = int(os.environ.get("GATEWAY_READS_PER_CALLER", "3"))
BODY_READ_TIMEOUT_S = float(os.environ.get("GATEWAY_BODY_READ_TIMEOUT_S", "10"))
BODY_IDLE_TIMEOUT_S = float(os.environ.get("GATEWAY_BODY_IDLE_TIMEOUT_S", "5"))
if not 2 <= READS_PER_CALLER <= 4:
    raise RuntimeError("GATEWAY_READS_PER_CALLER must be 2, 3 or 4")
if not 0 < BODY_IDLE_TIMEOUT_S <= BODY_READ_TIMEOUT_S:
    raise RuntimeError("want 0 < GATEWAY_BODY_IDLE_TIMEOUT_S <= GATEWAY_BODY_READ_TIMEOUT_S")
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
