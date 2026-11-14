"""Ed25519 request signing: what the gateway accepts, what it rejects with a generic 401, and the reason it logs."""
import base64
import json
import os
import threading
import secrets
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, KEYS_FILE, OTHER_KEY, ROOT, PRIVATE_KEYS, Signer, start_gateway
from sign_request import canonical, load_private_key, signed_headers

GET = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}).encode()
UNAUTHORIZED = (401, {"error": "unauthorized"})


def wait_auth_reason(log, reason, timeout=0.5):
    """Aggregated `auth refused ... reasons=...` line contains the reason (no per-request key_id)."""
    path = log if hasattr(log, "read_text") else None
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        text = log.read_text() if path is not None else log
        if "auth refused" in text and f"{reason}:" in text:
            return text
        time.sleep(0.05)
    raise AssertionError(f"missing auth reason {reason} in: {text[-2000:]}")


def raw_401(base, **kw):
    status, body = send(base, **kw) if "status_already" not in kw else (None, None)
    # used via httpx in the oracle tests
    return status, body


def response_fingerprint(r):
    headers = sorted((k.lower(), v) for k, v in r.headers.items() if k.lower() != "date")
    return r.status_code, r.content, r.headers.get("content-length"), tuple(headers)



@pytest.fixture(scope="module")
def gw(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("signing")
    p, base, _ = start_gateway(tmp, {})
    yield base, tmp / "gateway.log"
    p.terminate(); p.wait(5)


def send(base, path="/", body=GET, method="POST", key=KEY, sign_path=None, sign_body=None, drop=None, skew=None,
         **override):
    if skew is not None:
        override["timestamp"] = str(int(time.time()) + skew)
    raw_path, _, query = (path if sign_path is None else sign_path).encode().partition(b"?")
    h = signed_headers(key.key_id, key.private_key, method, raw_path, query, body if sign_body is None else sign_body,
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
    ("another caller's private key", {"key": Signer("a1a1a1a1a1", PRIVATE_KEYS["b2b2b2b2b2"])}, "bad_signature"),
    ("random private key", {"key": Signer("a1a1a1a1a1", secrets.token_urlsafe(32))}, "bad_signature"),
    ("well-formed but invalid signature", {"X-KC-Signature": "0" * 128}, "bad_signature"),
    ("signature with S out of range", {"X-KC-Signature": "0" * 64 + "f" * 64}, "bad_signature"),
    ("altered body", {"sign_body": GET.replace(b"nope", b"nopf")}, "body_hash_mismatch"),
    ("altered path", {"sign_path": "/readyz"}, "bad_signature"),
    ("altered query", {"path": "/?wait=true", "sign_path": "/?wait=false"}, "bad_signature"),
    ("query dropped", {"path": "/", "sign_path": "/?wait=false"}, "bad_signature"),
    ("stale timestamp", {"skew": -301}, "stale_timestamp"),
    ("future timestamp", {"skew": 3}, "stale_timestamp"),
    ("unknown key", {"key": Signer("eeeeeeeeee", KEY.private_key)}, "unknown_key"),
    ("uppercase content sha256", {"X-KC-Content-SHA256": "A" * 64}, "malformed_header"),
    ("short content sha256", {"X-KC-Content-SHA256": "a" * 63}, "malformed_header"),
    ("uppercase signature", {"X-KC-Signature": "A" * 128}, "malformed_header"),
    ("short signature", {"X-KC-Signature": "0" * 127}, "malformed_header"),
    ("63-byte signature", {"X-KC-Signature": "0" * 126}, "malformed_header"),
    ("long signature", {"X-KC-Signature": "0" * 130}, "malformed_header"),
    ("non-hex signature", {"X-KC-Signature": "z" * 128}, "malformed_header"),
    ("base64url signature", {"X-KC-Signature": base64.urlsafe_b64encode(b"\0" * 64).rstrip(b"=").decode()},
     "malformed_header"),
    ("old HMAC-length signature", {"X-KC-Signature": "0" * 64}, "malformed_header"),
    ("nonce too long", {"nonce": "n" * 65}, "malformed_header"),
    ("nonce too short", {"nonce": "n" * 15}, "malformed_header"),
    ("timestamp not a number", {"timestamp": "1.5e9"}, "malformed_header"),
    ("key id not a key id", {"X-KC-Key-Id": "kc_" + "a" * 60}, "malformed_header"),
])
def test_rejections_are_a_generic_401_with_the_reason_logged(gw, case, kw, reason):
    base, log = gw
    assert send(base, **kw) == UNAUTHORIZED
    wait_auth_reason(log, reason)


def test_signature_for_another_method_is_401(gw):
    h = signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", b"")
    r = httpx.get(gw[0] + "/", headers=h)
    assert (r.status_code, r.json()) == UNAUTHORIZED


@pytest.mark.parametrize("header", ["X-KC-Key-Id", "X-KC-Timestamp", "X-KC-Nonce", "X-KC-Signature",
                                    "X-KC-Content-SHA256"])
def test_missing_any_header_is_401(gw, header):
    assert send(gw[0], drop=header) == UNAUTHORIZED
    wait_auth_reason(gw[1], "missing_header")


def test_timestamp_inside_the_window_is_accepted(gw):
    for skew in (0, 2):
        assert send(gw[0], skew=skew)[0] == 200


def test_replayed_nonce_is_rejected_even_with_a_fresh_signature(gw):
    base, log = gw
    nonce = secrets.token_urlsafe(24)
    assert send(base, nonce=nonce)[0] == 200
    assert send(base, nonce=nonce) == UNAUTHORIZED
    assert send(base, nonce=nonce, skew=1) == UNAUTHORIZED
    assert send(base, key=OTHER_KEY, nonce=nonce)[0] == 200
    wait_auth_reason(log, "replayed_nonce")


def test_exact_replay_of_a_captured_request_is_rejected(gw):
    base, _ = gw
    h = {**signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", GET), "Content-Type": "application/json"}
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 200
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 401


def test_bearer_keys_are_no_longer_accepted(gw):
    r = httpx.post(gw[0] + "/", content=GET, headers={"Authorization": "Bearer kc_a1a1a1a1a1_" + "k" * 43})
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
    import hashlib as _hashlib
    headers = {"X-KC-Key-Id": "a1a1a1a1a1", "X-KC-Timestamp": ts, "X-KC-Nonce": nonce,
               "X-KC-Content-SHA256": _hashlib.sha256(GET).hexdigest(), "Content-Type": "application/json"}
    for message in (canonical("POST", b"/", b"", ts, nonce, GET, "b2b2b2b2b2"),
                    canonical("POST", b"/", b"", ts, nonce, GET, "a1a1a1a1a1").rsplit(b"\n", 1)[0]):
        sig = load_private_key(KEY.private_key).sign(message).hex()
        r = httpx.post(base + "/", content=GET, headers={**headers, "X-KC-Signature": sig})
        assert (r.status_code, r.json()) == UNAUTHORIZED
    sig = load_private_key(KEY.private_key).sign(canonical("POST", b"/", b"", ts, nonce, GET, "a1a1a1a1a1")).hex()
    assert httpx.post(base + "/", content=GET, headers={**headers, "X-KC-Signature": sig}).status_code == 200


def test_early_and_late_401s_are_byte_identical(gw):
    """Bastion (2): precheck 401s and a bad-signature 401 are the same status, body, headers and Content-Length."""
    base, log = gw
    def post(**kw):
        if "headers" in kw:
            return httpx.post(base + "/", **kw)
        # send() path
        if "drop" in kw or "key" in kw or "skew" in kw or "sign_body" in kw or any(k.startswith("X-") for k in kw):
            raw_path, _, query = b"/", b"", b""
            key = kw.get("key", KEY)
            body = kw.get("body", GET)
            h = signed_headers(key.key_id, key.private_key, "POST", b"/", b"",
                               body if kw.get("sign_body") is None else kw["sign_body"],
                               **{k: kw[k] for k in ("timestamp", "nonce") if k in kw})
            if "skew" in kw:
                h = signed_headers(key.key_id, key.private_key, "POST", b"/", b"", body,
                                   timestamp=str(int(time.time()) + kw["skew"]))
            h.update({k: v for k, v in kw.items() if k.startswith("X-")})
            h.pop(kw.get("drop"), None)
            return httpx.post(base + "/", content=body, headers={**h, "Content-Type": "application/json"})
        raise AssertionError(kw)
    cases = [
        post(drop="X-KC-Signature"),
        post(key=Signer("eeeeeeeeee", KEY.private_key)),
        post(key=Signer("a1a1a1a1a1", secrets.token_urlsafe(32))),
        post(skew=-301),
        post(sign_body=GET.replace(b"nope", b"nopf")),
        post(**{"X-KC-Key-Id": "not-a-key"}),
    ]
    fps = [response_fingerprint(r) for r in cases]
    assert all(fp[0] == 401 and fp[1] == b'{"error":"unauthorized"}' for fp in fps), fps
    assert len(set(fps)) == 1, fps
    wait_auth_reason(log, "unknown_key")
    wait_auth_reason(log, "bad_signature")


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
    text = wait_auth_reason(log, "malformed_header")
    assert misplaced not in text
    assert all("key_id=" not in ln for ln in text.splitlines() if "auth refused" in ln)


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
        assert send(capped, key=Signer("a1a1a1a1a1", secrets.token_urlsafe(32)), nonce=nonce if i == 0 else None) == UNAUTHORIZED
        assert send(capped, key=Signer("eeeeeeeeee", KEY.private_key)) == UNAUTHORIZED
    assert send(capped, nonce=nonce)[0] == 200
    assert [send(capped)[0] for _ in range(2)] == [200, 200]


def test_no_private_key_in_probe_card_or_spec_output(gw):
    base, _ = gw
    texts = [httpx.get(base + p, auth=KEY).text for p in ("/readyz", "/healthz", "/.well-known/agent.json", "/openapi.json")]
    assert not any(private in t for private in PRIVATE_KEYS.values() for t in texts)


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
        h = {**signed_headers(KEY.key_id, KEY.private_key, "GET", b"/", b"", b""), "Content-Type": "application/json"}
        assert httpx.get(base + "/", headers=h).status_code == 200
        assert httpx.post(base + "/", content=unknown, auth=KEY).status_code == 200
        assert httpx.get(base + "/docs", auth=KEY).status_code == 200
        limited = signed_headers(KEY.key_id, KEY.private_key, "GET", b"/", b"", b"")
        r = httpx.get(base + "/", headers=limited)
        assert (r.status_code, r.json()) == (429, {"error": "rate limited"}) and int(r.headers["retry-after"]) >= 1
        assert httpx.post(base + "/", content=unknown, auth=KEY).status_code == 429
        assert httpx.get(base + "/", headers=h).status_code == 401
        assert httpx.get(base + "/", auth=OTHER_KEY).status_code == 200
    finally:
        p.terminate(); p.wait(5)


def test_a_request_and_nonce_captured_before_a_restart_are_rejected_after_it(tmp_path):
    p, base, _ = start_gateway(tmp_path, {})
    h = {**signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", GET), "Content-Type": "application/json"}
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 200
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 401
    p.terminate(); p.wait(5)
    p, base, _ = start_gateway(tmp_path, {})
    try:
        r = httpx.post(base + "/", content=GET, headers=h)
        assert (r.status_code, r.json()) == UNAUTHORIZED
        assert httpx.post(base + "/", content=GET, auth=KEY).status_code == 200
        time.sleep(0.1)
        wait_auth_reason(tmp_path / "gateway.log", "stale_after_restart")
    finally:
        p.terminate(); p.wait(5)


def test_a_request_240s_ahead_is_401_now_and_after_a_restart(tmp_path):
    p, base, _ = start_gateway(tmp_path, {})
    ahead = str(int(time.time()) + 240)
    h = {**signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", GET, timestamp=ahead),
         "Content-Type": "application/json"}
    assert httpx.post(base + "/", content=GET, headers=h).status_code == 401
    wait_auth_reason(tmp_path / "gateway.log", "stale_timestamp")
    p.terminate(); p.wait(5)
    p, base, _ = start_gateway(tmp_path, {})
    try:
        assert httpx.post(base + "/", content=GET, headers=h).status_code == 401
        wait_auth_reason(tmp_path / "gateway.log", "stale_timestamp")
    finally:
        p.terminate(); p.wait(5)


def _signing_subprocess(prog, extra_env=None):
    env = {**{k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_", "WEB_"))},
           "GATEWAY_PUBLIC_KEYS_FILE": KEYS_FILE, "GATEWAY_SIGNATURE_FUTURE_S": "0",
           "GATEWAY_REQUESTS_PER_S": "100000", "GATEWAY_REQUESTS_BURST": "100000",
           "GATEWAY_CREATE_PER_MIN": "100000", "GATEWAY_CREATE_BURST": "1000",
           "GATEWAY_GET_PER_S": "1000", "GATEWAY_CANCEL_PER_S": "1000",
           "GATEWAY_REFUSAL_LOG_S": "0", "KIMICLAW_LIMIT_CONCURRENCY": "1024"}
    env.update(extra_env or {})
    boot = "from gateway.launcher_guard import mark_launched; mark_launched()\n" + prog
    r = subprocess.run([sys.executable, "-c", boot], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-2000:]
    return r.stdout


def test_a_plus_25s_request_captured_before_a_simulated_restart_is_rejected_after_it():
    """A +25 s timestamp is accepted now, then 401 stale_after_restart after STARTED_S is moved to 'now'."""
    prog = """
import io, logging, os, sys, time
sys.path[0:0] = ["tools", "tests"]
from conftest import KEY, KEYS_FILE
os.environ["GATEWAY_PUBLIC_KEYS_FILE"] = KEYS_FILE
from fastapi.testclient import TestClient
from sign_request import Signer, signed_headers
from gateway import auth
from gateway.main import create_app
app = create_app()
body = b'{"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}'
auth.STARTED_S = int(time.time()) - 40
log = io.StringIO()
logging.getLogger("kimiclaw").addHandler(logging.StreamHandler(log))
ahead = str(int(time.time()) + 25)
h = signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", body, timestamp=ahead)
h["Content-Type"] = "application/json"
with TestClient(app, base_url="http://127.0.0.1") as c:
    print("before", c.post("/", content=body, headers=h).status_code)
    auth.STARTED_S = int(time.time())
    r = c.post("/", content=body, headers=h)
    print("after", r.status_code, r.json())
    print("reason", "stale_after_restart" in log.getvalue())
    auth.STARTED_S = int(time.time()) - 40
    print("fresh", c.post("/", content=body, auth=Signer(KEY.key_id, KEY.private_key)).status_code)
"""
    out = _signing_subprocess(prog, {"GATEWAY_SIGNATURE_FUTURE_S": "30", "GATEWAY_SIGNATURE_PAST_S": "300"})
    assert "before 200" in out and "after 401 {'error': 'unauthorized'}" in out
    assert "reason True" in out and "fresh 200" in out


def test_a_timestamp_299s_in_the_past_is_accepted_once_the_restart_window_has_passed():
    """STARTED_S is far enough back that stale_after_restart cannot hide the -299 s / PAST_S=300 edge."""
    prog = """
import os, sys, time
sys.path[0:0] = ["tools", "tests"]
from conftest import KEY, KEYS_FILE
os.environ["GATEWAY_PUBLIC_KEYS_FILE"] = KEYS_FILE
from fastapi.testclient import TestClient
from sign_request import signed_headers
from gateway import auth
from gateway.main import create_app
app = create_app()
body = b'{"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}'
auth.STARTED_S = int(time.time()) - 400
def send(skew):
    h = signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", body, timestamp=str(int(time.time()) + skew))
    h["Content-Type"] = "application/json"
    r = c.post("/", content=body, headers=h)
    return r.status_code
with TestClient(app, base_url="http://127.0.0.1") as c:
    print([send(-299), send(-301)])
"""
    out = _signing_subprocess(prog, {"GATEWAY_SIGNATURE_FUTURE_S": "0", "GATEWAY_SIGNATURE_PAST_S": "300"})
    assert out.splitlines()[-1] == "[200, 401]"


@pytest.mark.parametrize("header", ["X-KC-Key-Id", "X-KC-Timestamp", "X-KC-Nonce", "X-KC-Signature",
                                    "X-KC-Content-SHA256"])
def test_a_repeated_signing_header_is_401(gw, header):
    base, log = gw
    h = signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", GET)
    pairs = list(h.items()) + [(header, h[header]), ("Content-Type", "application/json")]
    r = httpx.post(base + "/", content=GET, headers=pairs)
    assert (r.status_code, r.json()) == UNAUTHORIZED
    wait_auth_reason(log, "duplicate_header")


def test_verification_never_raises_on_a_bad_signature_length_or_encoding():
    prog = """
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from gateway.auth import verified
key = Ed25519PrivateKey.generate()
other = Ed25519PrivateKey.generate().public_key()
good = key.sign(b"m").hex()
print([verified(key.public_key(), good, b"m"), verified(other, good, b"m")]
      + [verified(key.public_key(), s, b"m") for s in ("", "ab", "zz" * 64, good[:-2], good + "00", "0" * 128)])
"""
    env = {**os.environ, "GATEWAY_PUBLIC_KEYS_FILE": KEYS_FILE, "GATEWAY_SIGNATURE_FUTURE_S": "0",
           "KIMICLAW_LIMIT_CONCURRENCY": "1024"}
    boot = "from gateway.launcher_guard import mark_launched; mark_launched()\n" + prog
    r = subprocess.run([sys.executable, "-c", boot], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-2000:]
    assert r.stdout.split("\n")[-2] == str([True] + [False] * 7)


def test_a_429_from_the_nonce_quota_does_not_spend_a_bucket_token():
    prog = """
import os, sys
sys.path[0:0] = ["tools", "tests"]
from conftest import KEY, KEYS_FILE
os.environ["GATEWAY_PUBLIC_KEYS_FILE"] = KEYS_FILE
from fastapi.testclient import TestClient
from gateway import auth
from gateway.main import create_app
app = create_app()
with TestClient(app, base_url="http://127.0.0.1") as c:
    codes = [c.get("/", auth=KEY).status_code for _ in range(2)]
    auth._nonces.clear()
    codes.append(c.get("/", auth=KEY).status_code)
print(codes)
"""
    env = {**{k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_", "WEB_"))},
           "GATEWAY_PUBLIC_KEYS_FILE": KEYS_FILE, "GATEWAY_SIGNATURE_FUTURE_S": "0",
           "GATEWAY_MAX_NONCES_PER_CALLER": "1",
           "GATEWAY_REQUESTS_PER_S": "0.0001", "GATEWAY_REQUESTS_BURST": "2",
           "KIMICLAW_LIMIT_CONCURRENCY": "1024"}
    boot = "from gateway.launcher_guard import mark_launched; mark_launched()\n" + prog
    r = subprocess.run([sys.executable, "-c", boot], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-2000:]
    assert r.stdout.split("\n")[-2] == "[200, 429, 200]"


def vm(pid, field):
    return int(next(l for l in open(f"/proc/{pid}/status") if l.startswith(field)).split()[1]) // 1024


def flood(base, n, body, trickle=False):
    h = {**signed_headers("eeeeeeeeee", KEY.private_key, "POST", b"/", b"", body), "Content-Type": "application/json"}
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
        assert httpx.post(base + "/", content=GET, auth=OTHER_KEY).status_code == 200
        [t.join() for t in threads]
        peak = vm(p.pid, "VmHWM")
        assert set(codes) == {401}, set(codes)
        assert peak - before < 60, f"RSS {before} -> peak {peak} MB"
        assert httpx.post(base + "/", content=GET, auth=OTHER_KEY).status_code == 200
    finally:
        p.terminate(); p.wait(5)


def test_a_bad_timestamp_is_401_before_key_lookup_for_known_and_unknown_key_ids(gw):
    """Bastion (4): header shape, then timestamp, then key lookup. A stale timestamp never reaches the key table."""
    base, _ = gw
    def stale(key_id, private_key):
        h = signed_headers(key_id, private_key, "POST", b"/", b"", GET, timestamp=str(int(time.time()) - 301))
        return httpx.post(base + "/", content=GET, headers={**h, "Content-Type": "application/json"})
    known = stale(KEY.key_id, KEY.private_key)
    unknown = stale("eeeeeeeeee", KEY.private_key)
    assert response_fingerprint(known) == response_fingerprint(unknown)
    assert known.status_code == 401 and known.content == b'{"error":"unauthorized"}'


def test_unknown_key_ids_are_not_counted_per_key_and_never_get_429(gw):
    """Bastion (3): an unknown key_id cannot be observed via 429 or Retry-After keyed on that id."""
    base, _ = gw
    codes, retry = [], []
    for i in range(40):
        kid = f"{i:010x}" if i else "eeeeeeeeee"
        h = signed_headers(kid, secrets.token_urlsafe(32), "POST", b"/", b"", GET)
        r = httpx.post(base + "/", content=GET, headers={**h, "Content-Type": "application/json"})
        codes.append(r.status_code)
        if "retry-after" in r.headers:
            retry.append(r.headers["retry-after"])
    assert set(codes) == {401} and retry == []
    assert send(base, key=OTHER_KEY)[0] == 200

