"""HMAC request signing: what the gateway accepts, what it rejects with a generic 401, and the reason it logs."""
import json
import secrets
import time

import httpx
import pytest

from conftest import KEY, OTHER_KEY, Signer, start_gateway
from sign_request import signed_headers

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


def test_query_is_signed_in_sorted_order(gw):
    base, _ = gw
    assert send(base, path="/?wait=false&b=2", sign_path="/?b=2&wait=false")[0] == 200


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
    for skew in (-290, 290):
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
