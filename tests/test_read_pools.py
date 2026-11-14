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
    held = [stall(port, "zzzzzzzzzz") for _ in range(32)]
    time.sleep(0.3)
    extra = stall(port, "zzzzzzzzzz")
    assert status(extra, 1) == 503
    for key in (KEY, OTHER_KEY):
        started = time.monotonic()
        assert get(base, key).status_code == 200 and time.monotonic() - started < 1
    assert [status(s) for s in held] == [408] * 32
    assert "read refused pool=unknown reason=pool_full key_id=zzzzzzzzzz" in log.read_text()


def test_a_slow_upload_on_caller_a_does_not_affect_caller_b(gw):
    _, base, port, log = gw(**SHORT)
    held = [stall(port, KEY.key_id, KEY.private_key, sent=b"x" * 10) for _ in range(3)]
    time.sleep(0.3)
    r = get(base, KEY)
    assert (r.status_code, r.headers["retry-after"]) == (429, "1")
    assert [get(base, OTHER_KEY).status_code for _ in range(3)] == [200] * 3
    assert [status(s) for s in held] == [408] * 3
    assert get(base, KEY).status_code == 200
    assert "read refused pool=caller reason=pool_full key_id=testkey01" in log.read_text()


def test_a_flood_with_a_real_key_id_but_not_its_private_key_only_fills_that_callers_pool(gw):
    _, base, port, _ = gw(**SHORT)
    flood = [stall(port, KEY.key_id) for _ in range(20)]
    time.sleep(0.5)
    assert sorted(status(s, 0.5) or 0 for s in flood[3:]) == [429] * 17
    assert [get(base, OTHER_KEY).status_code for _ in range(5)] == [200] * 5
    unknown = httpx.post(base + "/", content=GET, auth=type(KEY)("zzzzzzzzzz", KEY.private_key))
    assert unknown.status_code == 401
    assert [status(s) for s in flood[:3]] == [408] * 3


def test_100_aborted_reads_in_each_pool_leak_no_slots(gw):
    _, base, port, log = gw()
    for key_id, private_key in (("zzzzzzzzzz", None), (KEY.key_id, KEY.private_key)):
        for _ in range(100):
            s = stall(port, key_id, private_key, sent=b"x" * 10)
            s.close()
    time.sleep(1)
    unknown = [stall(port, "zzzzzzzzzz") for _ in range(32)]
    mine = [stall(port, KEY.key_id, KEY.private_key) for _ in range(3)]
    time.sleep(0.3)
    assert [status(s, 0.05) for s in unknown + mine] == [None] * 35
    assert status(stall(port, "zzzzzzzzzz"), 1) == 503
    assert status(stall(port, KEY.key_id, KEY.private_key), 1) == 429
    assert get(base, OTHER_KEY).status_code == 200
    text = log.read_text()
    for pool in ("unknown", "caller"):
        assert text.count(f"read failed pool={pool} reason=client_disconnected") + text.count(
            f"read refused pool={pool} reason=pool_full") >= 100
    assert "Traceback" not in text


def test_a_stalled_read_gets_408_at_the_idle_timeout_and_a_trickle_at_the_deadline(gw):
    _, base, port, log = gw(**SHORT)
    started = time.monotonic()
    assert status(stall(port, "zzzzzzzzzz")) == 408
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
    text = log.read_text()
    assert "read failed pool=unknown reason=read_idle key_id=zzzzzzzzzz" in text
    assert "read failed pool=caller reason=read_deadline key_id=testkey01" in text
    assert get(base, KEY).status_code == 200


def test_shutdown_is_not_blocked_by_held_reads(gw):
    p, _, port, _ = gw(**SHORT)
    held = [stall(port, "zzzzzzzzzz") for _ in range(32)] + [stall(port, KEY.key_id) for _ in range(3)]
    time.sleep(0.3)
    started = time.monotonic()
    p.terminate(); p.wait(15)
    assert time.monotonic() - started < 4
    [s.close() for s in held]


@pytest.mark.skipif(not os.environ.get("KC_SUSTAINED_S"), reason="set KC_SUSTAINED_S=30 to run the sustained flood")
def test_sustained_unknown_key_flood_never_503s_a_valid_caller(gw):
    seconds = float(os.environ["KC_SUSTAINED_S"])
    _, base, port, _ = gw()
    stop = time.monotonic() + seconds
    attacker, lock = {}, threading.Lock()
    def keep_one_slot():
        while time.monotonic() < stop:
            code = status(stall(port, "zzzzzzzzzz"), 30)
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
