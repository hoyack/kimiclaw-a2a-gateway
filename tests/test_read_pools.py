"""Verified body reads: each caller has a reserved pool of GATEWAY_READS_PER_CALLER slots. Unauthenticated
requests never take a slot. Every read has a total deadline and a per-chunk idle timeout (408)."""
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


def stall(port, key_id, private_key, sent=b"", length=1000):
    """A POST signed with the caller's private key whose body stops after `sent` bytes of `length` promised."""
    body = sent + b"x" * (length - len(sent))
    h = signed_headers(key_id, private_key, "POST", b"/", b"", body)
    head = "POST / HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall((head + f"Content-Type: application/json\r\nContent-Length: {length}\r\n\r\n").encode() + sent)
    return s


def unsigned_stall(port, sent=b"", length=1000):
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall((f"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
               f"Content-Length: {length}\r\n\r\n").encode() + sent)
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


def test_healthz_and_readyz_never_compete_for_read_slots(gw):
    _, base, port, _ = gw(**SHORT)
    held = [stall(port, KEY.key_id, KEY.private_key, sent=b"x" * 10) for _ in range(3)]
    time.sleep(0.3)
    assert get(base, KEY).status_code == 429
    for path in ("/healthz", "/readyz"):
        r = httpx.get(base + path, timeout=2)
        assert r.status_code == 200, (path, r.status_code, r.text)
    assert [status(s) for s in held] == [408] * 3
    assert get(base, KEY).status_code == 200


def test_a_slow_upload_on_caller_a_does_not_affect_caller_b(gw):
    _, base, port, log = gw(**SHORT)
    held = [stall(port, KEY.key_id, KEY.private_key, sent=b"x" * 10) for _ in range(3)]
    time.sleep(0.3)
    r = get(base, KEY)
    assert (r.status_code, r.headers["retry-after"]) == (429, "1")
    assert [get(base, OTHER_KEY).status_code for _ in range(3)] == [200] * 3
    assert [status(s) for s in held] == [408] * 3
    assert get(base, KEY).status_code == 200
    time.sleep(0.3)
    text = log.read_text()
    assert "read refused pool=caller count=" in text and "pool_full:" in text


def test_a_flood_of_unsigned_or_unknown_or_forged_requests_uses_zero_slots(gw):
    """Alice's reserved floor stays intact: junk requests 401 with no slot, her in-flight verified reads still 429 her."""
    _, base, port, _ = gw(**SHORT)
    held = [stall(port, KEY.key_id, KEY.private_key, sent=b"x" * 10) for _ in range(3)]
    time.sleep(0.3)
    codes, retry = [], []
    def one(h):
        r = httpx.post(base + "/", content=GET, headers=h, timeout=5)
        codes.append(r.status_code)
        if "retry-after" in r.headers:
            retry.append(r.headers["retry-after"])
    # unsigned
    one({"Content-Type": "application/json"})
    # unknown key_id
    one({**signed_headers("eeeeeeeeee", KEY.private_key, "POST", b"/", b"", GET), "Content-Type": "application/json"})
    # alice's real key_id without her private key
    for _ in range(20):
        one({**signed_headers(KEY.key_id, secrets.token_urlsafe(32), "POST", b"/", b"", GET),
             "Content-Type": "application/json"})
    assert set(codes) == {401} and retry == []
    # alice's reserve is still held by the three slow uploads
    r = get(base, KEY)
    assert (r.status_code, r.headers["retry-after"]) == (429, "1")
    assert [get(base, OTHER_KEY).status_code for _ in range(5)] == [200] * 5
    assert [status(s) for s in held] == [408] * 3
    assert get(base, KEY).status_code == 200


def test_100_aborted_verified_reads_leak_no_slots(gw):
    _, base, port, log = gw()
    for _ in range(100):
        s = stall(port, KEY.key_id, KEY.private_key, sent=b"x" * 10)
        s.close()
    time.sleep(1)
    mine = [stall(port, KEY.key_id, KEY.private_key) for _ in range(3)]
    time.sleep(0.3)
    assert [status(s, 0.05) for s in mine] == [None] * 3
    assert status(stall(port, KEY.key_id, KEY.private_key), 1) == 429
    assert get(base, OTHER_KEY).status_code == 200
    time.sleep(0.3)
    text = log.read_text()
    n = text.count("read failed pool=caller reason=client_disconnected")
    for ln in text.splitlines():
        if "read refused pool=caller count=" in ln:
            n += int(ln.split("count=", 1)[1].split()[0])
    assert n >= 100, n
    assert "Traceback" not in text


def test_a_stalled_verified_read_gets_408_at_the_idle_timeout_and_a_trickle_at_the_deadline(gw):
    _, base, port, log = gw(**SHORT)
    started = time.monotonic()
    assert status(stall(port, KEY.key_id, KEY.private_key)) == 408
    assert 1.3 < time.monotonic() - started < 2.5
    s = stall(port, OTHER_KEY.key_id, OTHER_KEY.private_key, sent=b"x")
    started = time.monotonic()
    for _ in range(4):
        time.sleep(1)
        try:
            s.sendall(b"x")
        except OSError:
            break
    assert status(s) == 408
    assert 2.5 < time.monotonic() - started < 4.5
    time.sleep(0.3)
    text = log.read_text()
    assert "read refused pool=caller count=" in text
    assert "read_idle:" in text and "read_deadline:" in text
    assert get(base, KEY).status_code == 200


def test_shutdown_is_not_blocked_by_held_reads(gw):
    p, _, port, _ = gw(**SHORT)
    held = [stall(port, KEY.key_id, KEY.private_key) for _ in range(3)]
    time.sleep(0.3)
    started = time.monotonic()
    p.terminate(); p.wait(15)
    assert time.monotonic() - started < 4
    [s.close() for s in held]


def test_a_flood_of_read_refusals_is_aggregated_to_one_log_line_per_pool_per_second_and_leaves_no_traces(gw, tmp_path):
    tdir = tmp_path / "tel"
    p, base, port, log = gw(GATEWAY_TELEMETRY_DIR=str(tdir), **SHORT)
    held = [stall(port, KEY.key_id, KEY.private_key) for _ in range(3)]
    time.sleep(0.2)
    started = time.monotonic()
    codes = []
    for _ in range(120):
        codes.append(status(stall(port, KEY.key_id, KEY.private_key), 1))
        codes.append(httpx.post(base + "/", content=GET, timeout=2).status_code)  # unsigned 401
    assert [status(s) for s in held] == [408] * 3
    elapsed = time.monotonic() - started
    time.sleep(0.3)
    p.terminate(); p.wait(5)
    text = log.read_text()
    caller = [ln for ln in text.splitlines() if "read refused pool=caller count=" in ln]
    pre = [ln for ln in text.splitlines() if "auth refused count=" in ln]
    assert caller and pre
    assert all("key_id=" not in ln for ln in caller + pre)
    assert "unauthorized reason=" not in text
    slack = 2
    # 0.05 s flush in tests, plus held-read 408s; bound the number of aggregate lines loosely
    assert len(caller) <= elapsed / 0.05 + slack + 5, (len(caller), elapsed)
    assert codes.count(429) >= 100 and codes.count(401) >= 100
    traces = tdir / "traces.jsonl"
    raw = traces.read_text() if traces.exists() else ""
    import json
    statuses = []
    for ln in raw.splitlines():
        if not ln.strip():
            continue
        doc = json.loads(ln)
        if isinstance(doc.get("attributes"), list):
            for a in doc["attributes"]:
                if a.get("key") == "http.response.status_code":
                    val = a.get("value")
                    if isinstance(val, dict):
                        val = val.get("intValue") or val.get("value")
                    if val is not None:
                        statuses.append(int(val))
    assert not any(s in (401, 408, 429, 503) for s in statuses), statuses


@pytest.mark.skipif(not os.environ.get("KC_SUSTAINED_S"), reason="set KC_SUSTAINED_S=30 to run the sustained flood")
def test_sustained_unknown_key_flood_never_503s_a_valid_caller(gw):
    seconds = float(os.environ["KC_SUSTAINED_S"])
    _, base, port, _ = gw()
    stop = time.monotonic() + seconds
    attacker, lock = {}, threading.Lock()
    def keep_flooding():
        while time.monotonic() < stop:
            try:
                h = {**signed_headers("eeeeeeeeee", KEY.private_key, "POST", b"/", b"", GET),
                     "Content-Type": "application/json"}
                code = httpx.post(base + "/", content=GET, headers=h, timeout=5).status_code
            except httpx.HTTPError as e:
                code = type(e).__name__
            with lock:
                attacker[code] = attacker.get(code, 0) + 1
    threads = [threading.Thread(target=keep_flooding, daemon=True) for _ in range(32)]
    [t.start() for t in threads]
    time.sleep(0.5)
    valid = {}
    while time.monotonic() < stop:
        code = get(base, OTHER_KEY).status_code
        valid[code] = valid.get(code, 0) + 1
        time.sleep(0.5)
    [t.join(15) for t in threads]
    print(f"\nsustained {seconds:.0f}s: valid caller {valid}; attacker {attacker}")
    assert set(valid) == {200} and set(attacker) <= {401} and attacker.get(401, 0) >= 32
