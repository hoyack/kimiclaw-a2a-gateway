"""HMAC request signing: what the gateway accepts, what it rejects with a generic 401, and the reason it logs."""
import hashlib
import hmac
import json
import os
import threading
import secrets
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, KEYS_FILE, OTHER_KEY, ROOT, SECRETS, Signer, start_gateway
from sign_request import canonical, signed_headers

GET = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}).encode()
UNAUTHORIZED = (401, {"error": "unauthorized"})


@pytest.fixture(scope="module")
def gw(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("hmac")
    p, base, _ = start_gateway(tmp, {})
    yield base, tmp / "gateway.log"
    p.terminate(); p.wait(5)


def send(base, path="/", body=GET, method="POST", key=KEY, sign_path=None, sign_body=None, drop=None, skew=None,
         **override):
    if skew is not None:
        override["timestamp"] = str(int(time.time()) + skew)
    raw_path, _, query = (path if sign_path is None else sign_path).encode().partition(b"?")
    h = signed_headers(key.key_id, key.secret, method, raw_path, query, body if sign_body is None else sign_body,
                       **{k: v for k, v in override.items() if k in ("timestamp", "nonce")})
    h.update({k: v for k, v in override.items() if k.startswith("X-")})
    h.pop(drop, None)
    r = httpx.request(method, base + path, content=body, headers={**h, "Content-Type": "application/json"})
    return r.status_code, r.json()


def test_valid_signature_on_get_and_post(gw):
    base, _ = gw
    assert send(base, method="GET", body=b"")[1]["service"] == "kimiclaw-a2a-gateway"
    status, body = send(base)
    assert status == 200 and body["error"]["code"] == -32001
    assert httpx.post(base + "/?wait=false", content=GET, auth=OTHER_KEY).status_code == 200


def test_query_is_signed_exactly_as_sent_so_reordering_breaks_it(gw):
    base, _ = gw
    assert send(base, path="/?wait=false&b=2")[0] == 200
    assert send(base, path="/?wait=false&b=2", sign_path="/?b=2&wait=false") == UNAUTHORIZED
    assert send(base, path="/?wait=false&wait=true", sign_path="/?wait=true&wait=false") == UNAUTHORIZED


@pytest.mark.parametrize("case,kw,reason", [
    ("wrong secret", {"key": Signer("testkey01", secrets.token_urlsafe(32))}, "bad_signature"),
    ("altered body", {"sign_body": GET.replace(b"nope", b"nopf")}, "bad_signature"),
    ("altered path", {"sign_path": "/readyz"}, "bad_signature"),
    ("altered query", {"path": "/?wait=true", "sign_path": "/?wait=false"}, "bad_signature"),
    ("query dropped", {"path": "/", "sign_path": "/?wait=false"}, "bad_signature"),
    ("stale timestamp", {"skew": -301}, "stale_timestamp"),
    ("future timestamp", {"skew": 301}, "stale_timestamp"),
    ("unknown key", {"key": Signer("testkey09", KEY.secret)}, "unknown_key"),
    ("uppercase signature", {"X-KC-Signature": "A" * 64}, "malformed_header"),
    ("short signature", {"X-KC-Signature": "0" * 63}, "malformed_header"),
    ("non-hex signature", {"X-KC-Signature": "z" * 64}, "malformed_header"),
    ("nonce too long", {"nonce": "n" * 65}, "malformed_header"),
    ("nonce too short", {"nonce": "n" * 15}, "malformed_header"),
    ("timestamp not a number", {"timestamp": "1.5e9"}, "malformed_header"),
    ("key id not a key id", {"X-KC-Key-Id": "kc_" + "a" * 60}, "malformed_header"),
])
def test_rejections_are_a_generic_401_with_the_reason_logged(gw, case, kw, reason):
    base, log = gw
    assert send(base, **kw) == UNAUTHORIZED
    time.sleep(0.1)
    assert f"unauthorized reason={reason} " in log.read_text()


def test_signature_for_another_method_is_401(gw):
    h = signed_headers(KEY.key_id, KEY.secret, "POST", b"/", b"", b"")
    r = httpx.get(gw[0] + "/", headers=h)
    assert (r.status_code, r.json()) == UNAUTHORIZED


@pytest.mark.parametrize("header", ["X-KC-Key-Id", "X-KC-Timestamp", "X-KC-Nonce", "X-KC-Signature"])
def test_missing_any_header_is_401(gw, header):
    assert send(gw[0], drop=header) == UNAUTHORIZED
    assert "unauthorized reason=missing_header" in gw[1].read_text()


def test_timestamp_inside_the_window_is_accepted(gw):
    for skew in (0, 290):
        assert send(gw[0], skew=skew)[0] == 200


def test_replayed_nonce_is_rejected_even_with_a_fresh_signature(gw):
    base, log = gw
    nonce = secrets.token_urlsafe(24)
    assert send(base, nonce=nonce)[0] == 200
    assert send(base, nonce=nonce) == UNAUTHORIZED
    assert send(base, nonce=nonce, skew=1) == UNAUTHORIZED
    assert send(base, key=OTHER_KEY, nonce=nonce)[0] == 200
    time.sleep(0.1)
    assert "unauthorized reason=replayed_nonce key_id=testkey01" in log.read_text()


def test_exact_replay_of_a_captured_request_is_rejected(gw):
    base, _ = gw
    h = {**signed_headers(KEY.key_id, KEY.secret, "POST", b"/", b"", GET), "Content-Type": "application/json"}
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 200
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 401


def test_bearer_keys_are_no_longer_accepted(gw):
    r = httpx.post(gw[0] + "/", content=GET, headers={"Authorization": "Bearer kc_testkey01_" + "k" * 43})
    assert (r.status_code, r.json()) == UNAUTHORIZED


def test_signed_task_is_invisible_and_uncancelable_to_another_caller(gw):
    base, _ = gw
    send_ = {"jsonrpc": "2.0", "id": 1, "method": "message/send",
             "params": {"message": {"role": "user", "parts": [{"kind": "text", "text": "SLOW mine"}]}}}
    tid = httpx.post(base + "/?wait=false", json=send_, auth=KEY, timeout=10).json()["result"]["id"]
    for method in ("tasks/get", "tasks/cancel"):
        body = {"jsonrpc": "2.0", "id": 2, "method": method, "params": {"id": tid}}
        assert httpx.post(base + "/", json=body, auth=OTHER_KEY).json()["error"]["code"] == -32001
    body = {"jsonrpc": "2.0", "id": 3, "method": "tasks/get", "params": {"id": tid}}
    assert httpx.post(base + "/", json=body, auth=KEY).json()["result"]["id"] == tid


def test_key_id_is_bound_into_the_signature(gw):
    base, log = gw
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(24)
    headers = {"X-KC-Key-Id": "testkey01", "X-KC-Timestamp": ts, "X-KC-Nonce": nonce, "Content-Type": "application/json"}
    for message in (canonical("POST", b"/", b"", ts, nonce, GET, "testkey02"),
                    canonical("POST", b"/", b"", ts, nonce, GET, "testkey01").rsplit(b"\n", 1)[0]):
        sig = hmac.new(KEY.secret.encode(), message, hashlib.sha256).hexdigest()
        r = httpx.post(base + "/", content=GET, headers={**headers, "X-KC-Signature": sig})
        assert (r.status_code, r.json()) == UNAUTHORIZED
    sig = hmac.new(KEY.secret.encode(), canonical("POST", b"/", b"", ts, nonce, GET, "testkey01"), hashlib.sha256)
    assert httpx.post(base + "/", content=GET, headers={**headers, "X-KC-Signature": sig.hexdigest()}).status_code == 200


def test_unknown_key_id_gets_the_same_401_as_a_bad_signature(gw):
    base, log = gw
    def raw(key):
        h = signed_headers(key.key_id, key.secret, "POST", b"/", b"", GET)
        r = httpx.post(base + "/", content=GET, headers={**h, "Content-Type": "application/json"})
        return r.status_code, r.content, sorted((k, v) for k, v in r.headers.items() if k != "date")
    assert raw(Signer("testkey09", KEY.secret)) == raw(Signer("testkey01", secrets.token_urlsafe(32)))
    time.sleep(0.1)
    assert "reason=unknown_key key_id=testkey09" in log.read_text()


def test_body_is_hashed_as_received_not_reserialized(gw):
    base, _ = gw
    odd = b'{ "params":{"id":"nope"},  "method":"tasks/get", "id":"1",\n "jsonrpc":"2.0" }'
    status, body = send(base, body=odd)
    assert status == 200 and body["error"]["code"] == -32001
    assert send(base, body=odd, sign_body=json.dumps(json.loads(odd)).encode()) == UNAUTHORIZED


def test_a_header_value_that_is_not_a_key_id_is_never_logged(gw, tmp_path):
    base, log = gw
    misplaced = secrets.token_urlsafe(32)
    assert send(base, **{"X-KC-Key-Id": misplaced}) == UNAUTHORIZED
    time.sleep(0.1)
    text = log.read_text()
    assert misplaced not in text and "reason=malformed_header key_id=malformed" in text


@pytest.fixture
def capped(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_MAX_NONCES_PER_CALLER": "3"})
    yield base
    p.terminate(); p.wait(5)


def test_nonce_cap_per_caller_is_429_with_retry_after_and_spares_other_callers(capped):
    assert [send(capped)[0] for _ in range(3)] == [200, 200, 200]
    r = httpx.post(capped + "/", content=GET, auth=KEY)
    assert (r.status_code, r.json()) == (429, {"error": "rate limited"})
    assert 1 <= int(r.headers["retry-after"]) <= 301
    assert send(capped, key=OTHER_KEY)[0] == 200


def test_rejected_signatures_do_not_spend_nonces_or_fill_the_cache(capped):
    nonce = secrets.token_urlsafe(24)
    for i in range(20):
        assert send(capped, key=Signer("testkey01", secrets.token_urlsafe(32)), nonce=nonce if i == 0 else None) == UNAUTHORIZED
        assert send(capped, key=Signer("testkey09", KEY.secret)) == UNAUTHORIZED
    assert send(capped, nonce=nonce)[0] == 200
    assert [send(capped)[0] for _ in range(2)] == [200, 200]


def test_no_secret_in_probe_card_or_spec_output(gw):
    base, _ = gw
    texts = [httpx.get(base + p, auth=KEY).text for p in ("/readyz", "/healthz", "/.well-known/agent.json", "/openapi.json")]
    assert not any(secret in t for secret in SECRETS.values() for t in texts)


def test_bastion_d3_repro_one_caller_filling_its_nonce_quota_gets_429_and_others_still_get_200(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_MAX_NONCES_PER_CALLER": "50"})
    try:
        codes = [httpx.get(base + "/", auth=KEY).status_code for _ in range(60)]
        assert codes == [200] * 50 + [429] * 10
        assert [httpx.get(base + "/", auth=OTHER_KEY).status_code for _ in range(5)] == [200] * 5
    finally:
        p.terminate(); p.wait(5)


def test_every_signed_request_pays_the_callers_general_bucket_before_its_nonce_is_kept(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_REQUESTS_PER_S": "0.01", "GATEWAY_REQUESTS_BURST": "3"})
    try:
        unknown = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "foo/bar"}).encode()
        h = {**signed_headers(KEY.key_id, KEY.secret, "GET", b"/", b"", b""), "Content-Type": "application/json"}
        assert httpx.get(base + "/", headers=h).status_code == 200
        assert httpx.post(base + "/", content=unknown, auth=KEY).status_code == 200
        assert httpx.get(base + "/docs", auth=KEY).status_code == 200
        limited = signed_headers(KEY.key_id, KEY.secret, "GET", b"/", b"", b"")
        r = httpx.get(base + "/", headers=limited)
        assert (r.status_code, r.json()) == (429, {"error": "rate limited"}) and int(r.headers["retry-after"]) >= 1
        assert httpx.post(base + "/", content=unknown, auth=KEY).status_code == 429
        assert httpx.get(base + "/", headers=h).status_code == 401
        assert httpx.get(base + "/", auth=OTHER_KEY).status_code == 200
    finally:
        p.terminate(); p.wait(5)


def test_a_request_and_nonce_captured_before_a_restart_are_rejected_after_it(tmp_path):
    p, base, _ = start_gateway(tmp_path, {})
    h = {**signed_headers(KEY.key_id, KEY.secret, "POST", b"/", b"", GET), "Content-Type": "application/json"}
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 200
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 401
    p.terminate(); p.wait(5)
    p, base, _ = start_gateway(tmp_path, {})
    try:
        r = httpx.post(base + "/", content=GET, headers=h)
        assert (r.status_code, r.json()) == UNAUTHORIZED
        assert httpx.post(base + "/", content=GET, auth=KEY).status_code == 200
        time.sleep(0.1)
        assert "unauthorized reason=stale-after-restart key_id=testkey01" in (tmp_path / "gateway.log").read_text()
    finally:
        p.terminate(); p.wait(5)


@pytest.mark.parametrize("header", ["X-KC-Key-Id", "X-KC-Timestamp", "X-KC-Nonce", "X-KC-Signature"])
def test_a_repeated_signing_header_is_401(gw, header):
    base, log = gw
    h = signed_headers(KEY.key_id, KEY.secret, "POST", b"/", b"", GET)
    pairs = list(h.items()) + [(header, h[header]), ("Content-Type", "application/json")]
    r = httpx.post(base + "/", content=GET, headers=pairs)
    assert (r.status_code, r.json()) == UNAUTHORIZED
    time.sleep(0.1)
    assert "unauthorized reason=duplicate_header key_id=testkey01" in log.read_text()


def test_a_429_from_the_nonce_quota_does_not_spend_a_bucket_token():
    prog = f"""
import sys
sys.path.insert(0, "tools")
from fastapi.testclient import TestClient
from sign_request import Signer
from gateway import auth
from gateway.main import app
key = Signer("testkey01", {KEY.secret!r})
with TestClient(app, base_url="http://127.0.0.1") as c:
    codes = [c.get("/", auth=key).status_code for _ in range(2)]
    auth._nonces.clear()
    codes.append(c.get("/", auth=key).status_code)
print(codes)
"""
    env = {**{k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_", "WEB_"))},
           "GATEWAY_SIGNING_KEYS_FILE": KEYS_FILE, "GATEWAY_MAX_NONCES_PER_CALLER": "1",
           "GATEWAY_REQUESTS_PER_S": "0.0001", "GATEWAY_REQUESTS_BURST": "2"}
    r = subprocess.run([sys.executable, "-c", prog], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-2000:]
    assert r.stdout.split("\n")[-2] == "[200, 429, 200]"


def vm(pid, field):
    return int(next(l for l in open(f"/proc/{pid}/status") if l.startswith(field)).split()[1]) // 1024


def flood(base, n, body, trickle=False):
    h = {**signed_headers("zzzzzzzzzz", KEY.secret, "POST", b"/", b"", body), "Content-Type": "application/json"}
    def content():
        for i in range(0, len(body), 100_000):
            yield body[i:i + 100_000]; time.sleep(0.2)
    codes, lock = [], threading.Lock()
    def one():
        try:
            s = httpx.post(base + "/", content=content() if trickle else body, headers=h, timeout=60).status_code
        except httpx.HTTPError as e:
            s = type(e).__name__
        with lock:
            codes.append(s)
    threads = [threading.Thread(target=one) for _ in range(n)]
    [t.start() for t in threads]
    return threads, codes


def test_concurrent_1mb_bodies_with_unknown_keys_keep_memory_bounded(tmp_path):
    p, base, _ = start_gateway(tmp_path, {})
    try:
        body = b'{"pad":"' + b"p" * 999_000 + b'"}'
        before = vm(p.pid, "VmRSS")
        threads, codes = flood(base, 300, body, trickle=True)
        time.sleep(1)
        assert httpx.post(base + "/", content=GET, auth=OTHER_KEY).status_code in (200, 503)
        [t.join() for t in threads]
        peak = vm(p.pid, "VmHWM")
        assert set(codes) <= {401, 503} and 401 in codes and 503 in codes, set(codes)
        assert peak - before < 60, f"RSS {before} -> peak {peak} MB"
        assert httpx.post(base + "/", content=GET, auth=OTHER_KEY).status_code == 200
    finally:
        p.terminate(); p.wait(5)


def test_preauth_read_cap_is_503_with_retry_after(tmp_path):
    p, base, _ = start_gateway(tmp_path, {})
    try:
        threads, codes = flood(base, 40, b"x" * 500_000, trickle=True)
        time.sleep(0.5)
        r = httpx.post(base + "/", content=GET, auth=OTHER_KEY)
        assert (r.status_code, r.json(), r.headers["retry-after"]) == (503, {"error": "busy"}, "1")
        [t.join() for t in threads]
        assert codes.count(401) == 32 and codes.count(503) == 8, codes
        assert httpx.post(base + "/", content=GET, auth=OTHER_KEY).status_code == 200
        assert "busy pre-auth body reads=32 key_id=testkey02" in (tmp_path / "gateway.log").read_text()
    finally:
        p.terminate(); p.wait(5)
