"""Pre-auth body reads: unknown key_ids share one 32-slot pool, each known caller has its own small pool, and every
read has a total deadline and a per-chunk idle timeout (408). Slow or junk reads must never 503 a real caller."""
import os
import secrets
import socket
import threading
import time

import httpx
import pytest

from conftest import KEY, OTHER_KEY, start_gateway
from sign_request import signed_headers

GET = b'{"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}'
SHORT = {"GATEWAY_BODY_READ_TIMEOUT_S": "3", "GATEWAY_BODY_IDLE_TIMEOUT_S": "1.5"}


@pytest.fixture
def gw(tmp_path):
    procs = []
    def make(**env):
        p, base, _ = start_gateway(tmp_path, env); procs.append(p)
        return p, base, int(base.rsplit(":", 1)[1]), tmp_path / "gateway.log"
    yield make
    for p in procs:
        if p.poll() is None:
            p.terminate(); p.wait(10)


def stall(port, key_id, private_key=None, sent=b"", length=1000):
    """A POST whose headers are well formed and signed (with a throwaway private key unless given) but whose body stops
    after `sent` bytes of the `length` promised."""
    body = sent + b"x" * (length - len(sent))
    h = signed_headers(key_id, private_key or secrets.token_urlsafe(32), "POST", b"/", b"", body)
    head = "POST / HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall((head + f"Content-Type: application/json\r\nContent-Length: {length}\r\n\r\n").encode() + sent)
    return s


def status(s, timeout=30):
    s.settimeout(timeout)
    try:
        data = s.recv(200)
        return int(data.split(b" ")[1]) if data else None
    except socket.timeout:
        return None


def get(base, key):
    return httpx.post(base + "/", content=GET, auth=key, headers={"Content-Type": "application/json"}, timeout=10)


def test_with_32_unknown_key_reads_held_valid_callers_get_200_at_once(gw):
    _, base, port, log = gw(**SHORT)
    held = [stall(port, "eeeeeeeeee") for _ in range(32)]
    time.sleep(0.3)
    extra = stall(port, "eeeeeeeeee")
    assert status(extra, 1) == 503
    for key in (KEY, OTHER_KEY):
        started = time.monotonic()
        assert get(base, key).status_code == 200 and time.monotonic() - started < 1
    assert [status(s) for s in held] == [408] * 32
    time.sleep(1.1)
    text = log.read_text()
    assert "read refused pool=unknown count=" in text and "pool_full:" in text


def test_a_slow_upload_on_caller_a_does_not_affect_caller_b(gw):
    _, base, port, log = gw(**SHORT)
    held = [stall(port, KEY.key_id, KEY.private_key, sent=b"x" * 10) for _ in range(3)]
    time.sleep(0.3)
    r = get(base, KEY)
    assert (r.status_code, r.headers["retry-after"]) == (429, "1")
    assert [get(base, OTHER_KEY).status_code for _ in range(3)] == [200] * 3
    assert [status(s) for s in held] == [408] * 3
    assert get(base, KEY).status_code == 200
    time.sleep(1.1)
    text = log.read_text()
    assert "read refused pool=caller count=" in text and "pool_full:" in text


def test_a_flood_with_a_real_key_id_but_not_its_private_key_only_fills_that_callers_pool(gw):
    _, base, port, _ = gw(**SHORT)
    flood = [stall(port, KEY.key_id) for _ in range(20)]
    time.sleep(0.5)
    assert sorted(status(s, 0.5) or 0 for s in flood[3:]) == [429] * 17
    assert [get(base, OTHER_KEY).status_code for _ in range(5)] == [200] * 5
    unknown = httpx.post(base + "/", content=GET, auth=type(KEY)("eeeeeeeeee", KEY.private_key))
    assert unknown.status_code == 401
    assert [status(s) for s in flood[:3]] == [408] * 3


def test_100_aborted_reads_in_each_pool_leak_no_slots(gw):
    _, base, port, log = gw()
    for key_id, private_key in (("eeeeeeeeee", None), (KEY.key_id, KEY.private_key)):
        for _ in range(100):
            s = stall(port, key_id, private_key, sent=b"x" * 10)
            s.close()
    time.sleep(1)
    unknown = [stall(port, "eeeeeeeeee") for _ in range(32)]
    mine = [stall(port, KEY.key_id, KEY.private_key) for _ in range(3)]
    time.sleep(0.3)
    assert [status(s, 0.05) for s in unknown + mine] == [None] * 35
    assert status(stall(port, "eeeeeeeeee"), 1) == 503
    assert status(stall(port, KEY.key_id, KEY.private_key), 1) == 429
    assert get(base, OTHER_KEY).status_code == 200
    time.sleep(1.1)
    text = log.read_text()
    for pool in ("unknown", "caller"):
        n = text.count(f"read failed pool={pool} reason=client_disconnected")
        for ln in text.splitlines():
            if f"read refused pool={pool} count=" in ln:
                n += int(ln.split("count=", 1)[1].split()[0])
        assert n >= 100, (pool, n)
    assert "Traceback" not in text


def test_a_stalled_read_gets_408_at_the_idle_timeout_and_a_trickle_at_the_deadline(gw):
    _, base, port, log = gw(**SHORT)
    started = time.monotonic()
    assert status(stall(port, "eeeeeeeeee")) == 408
    assert 1.3 < time.monotonic() - started < 2.5
    s = stall(port, KEY.key_id, KEY.private_key, sent=b"x")
    started = time.monotonic()
    for _ in range(4):
        time.sleep(1)
        try:
            s.sendall(b"x")
        except OSError:
            break
    assert status(s) == 408
    assert 2.5 < time.monotonic() - started < 4.5
    time.sleep(1.1)
    text = log.read_text()
    assert "read refused pool=unknown count=" in text and "read_idle:" in text
    assert "read refused pool=caller count=" in text and "read_deadline:" in text
    assert get(base, KEY).status_code == 200


def test_shutdown_is_not_blocked_by_held_reads(gw):
    p, _, port, _ = gw(**SHORT)
    held = [stall(port, "eeeeeeeeee") for _ in range(32)] + [stall(port, KEY.key_id) for _ in range(3)]
    time.sleep(0.3)
    started = time.monotonic()
    p.terminate(); p.wait(15)
    assert time.monotonic() - started < 4
    [s.close() for s in held]


def test_a_flood_of_read_refusals_is_aggregated_to_one_log_line_per_pool_per_second_and_leaves_no_traces(gw, tmp_path):
    tdir = tmp_path / "tel"
    p, base, port, log = gw(GATEWAY_TELEMETRY_DIR=str(tdir), **SHORT)
    held = [stall(port, "eeeeeeeeee") for _ in range(32)] + [stall(port, KEY.key_id, KEY.private_key) for _ in range(3)]
    time.sleep(0.2)
    started = time.monotonic()
    codes = []
    for _ in range(120):
        codes.append(status(stall(port, "eeeeeeeeee"), 1))
        codes.append(status(stall(port, KEY.key_id, KEY.private_key), 1))
    # held reads hit the idle timeout and become 408
    assert [status(s) for s in held] == [408] * 35
    elapsed = time.monotonic() - started
    time.sleep(1.1)
    p.terminate(); p.wait(5)
    text = log.read_text()
    unknown = [ln for ln in text.splitlines() if "read refused pool=unknown count=" in ln]
    caller = [ln for ln in text.splitlines() if "read refused pool=caller count=" in ln]
    assert unknown and caller
    assert all("key_id=" not in ln for ln in unknown + caller)
    assert "reason=pool_full key_id=" not in text and "reason=read_idle key_id=" not in text
    slack = 2
    assert len(unknown) <= elapsed + slack and len(caller) <= elapsed + slack, (len(unknown), len(caller), elapsed)
    assert codes.count(503) + codes.count(429) >= 200
    traces = tdir / "traces.jsonl"
    raw = traces.read_text() if traces.exists() else ""
    import json
    statuses = []
    for ln in raw.splitlines():
        if not ln.strip():
            continue
        doc = json.loads(ln)
        attrs = {a["key"]: a.get("value", a) for a in doc.get("attributes", [])} if isinstance(doc.get("attributes"), list) else doc.get("attributes") or {}
        # otel to_json uses a list of {key, value}
        val = None
        if isinstance(doc.get("attributes"), list):
            for a in doc["attributes"]:
                if a.get("key") == "http.response.status_code":
                    val = a.get("value")
                    if isinstance(val, dict):
                        val = val.get("intValue") or val.get("value")
        if val is not None:
            statuses.append(int(val))
    assert not any(s in (408, 429, 503) for s in statuses), statuses


@pytest.mark.skipif(not os.environ.get("KC_SUSTAINED_S"), reason="set KC_SUSTAINED_S=30 to run the sustained flood")
def test_sustained_unknown_key_flood_never_503s_a_valid_caller(gw):
    seconds = float(os.environ["KC_SUSTAINED_S"])
    _, base, port, _ = gw()
    stop = time.monotonic() + seconds
    attacker, lock = {}, threading.Lock()
    def keep_one_slot():
        while time.monotonic() < stop:
            code = status(stall(port, "eeeeeeeeee"), 30)
            with lock:
                attacker[code] = attacker.get(code, 0) + 1
    threads = [threading.Thread(target=keep_one_slot, daemon=True) for _ in range(32)]
    [t.start() for t in threads]
    time.sleep(0.5)
    valid = {}
    while time.monotonic() < stop:
        code = get(base, OTHER_KEY).status_code
        valid[code] = valid.get(code, 0) + 1
        time.sleep(0.5)
    [t.join(15) for t in threads]
    print(f"\nsustained {seconds:.0f}s: valid caller {valid}; attacker {attacker}")
    assert set(valid) == {200} and attacker.get(408, 0) >= 32
