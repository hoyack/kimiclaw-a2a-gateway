"""Per-caller signing keys file, per-key rate limits, body cap, key_id audit logs, agent-card URL."""
import base64
import json
import os
import secrets
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, OTHER_KEY, ROOT, SECRETS, TOKEN, Signer, start_gateway, write_keys_file

GET = {"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}
SEND = {"jsonrpc": "2.0", "id": "1", "method": "message/send",
        "params": {"message": {"parts": [{"kind": "text", "text": "hi"}]}, "configuration": {"blocking": False}}}
WRONG_SECRET = Signer("testkey01", secrets.token_urlsafe(32))


@pytest.fixture
def start(tmp_path):
    procs = []
    def make(**env):
        p, base, _ = start_gateway(tmp_path, env); procs.append(p)
        return base
    yield make
    for p in procs:
        p.terminate(); p.wait(5)


def post(base, body, key=KEY):
    return httpx.post(base + "/", json=body, auth=key)


def boot(tmp_path, keys_text=None, keys_file=None):
    path = keys_file
    if keys_text is not None:
        path = tmp_path / "keys.txt"; path.write_text(keys_text); path.chmod(0o600)
    env = {**os.environ, "KIMICLAW_TOKEN": TOKEN, "GATEWAY_SIGNING_KEYS_FILE": str(path or "")}
    return subprocess.run([sys.executable, "-c", "import gateway.config"], cwd=ROOT, env=env, capture_output=True, text=True)


def test_agent_card_and_healthz_stay_open_while_a_key_is_limited(start):
    base = start(GATEWAY_GET_PER_S="0.01")
    post(base, GET)
    assert post(base, GET).status_code == 429
    for h in ({}, {"Authorization": "Bearer wrong"}):
        assert httpx.get(base + "/healthz", headers=h).json() == {"status": "ok"}
        assert httpx.get(base + "/.well-known/agent.json", headers=h).status_code == 200


def test_task_create_limit_is_per_key_with_retry_after(start):
    base = start(GATEWAY_CREATE_PER_MIN="1", GATEWAY_CREATE_BURST="2")
    assert [post(base, SEND).status_code for _ in range(2)] == [200, 200]
    r = httpx.post(base + "/", json={**SEND, "method": "message/stream"}, auth=KEY)
    assert (r.status_code, r.json()) == (429, {"error": "rate limited"})
    assert 1 <= int(r.headers["retry-after"]) <= 60
    assert post(base, SEND, OTHER_KEY).status_code == 200
    assert post(base, GET).status_code == 200


def test_get_and_cancel_buckets_refill(start):
    base = start(GATEWAY_GET_PER_S="5", GATEWAY_CANCEL_PER_S="5")
    for body in (GET, {**GET, "method": "tasks/cancel"}):
        codes = [post(base, body).status_code for _ in range(6)]
        assert codes[:5] == [200] * 5 and codes[5] == 429
        time.sleep(0.3)
        assert post(base, body).status_code == 200


def test_failed_auth_does_not_spend_a_keys_quota(start):
    base = start(GATEWAY_GET_PER_S="0.01")
    for _ in range(5):
        assert post(base, GET, WRONG_SECRET).status_code == 401
    assert post(base, GET).status_code == 200


def test_body_over_1mb_is_413(start):
    base = start()
    big = json.dumps({**GET, "pad": "x" * 1_000_001}).encode()
    r = httpx.post(base + "/", content=big, auth=KEY, headers={"Content-Type": "application/json"})
    assert (r.status_code, r.json()) == (413, {"error": "request body too large"})
    ok = json.dumps({**GET, "pad": "x" * 900_000}).encode()
    assert httpx.post(base + "/", content=ok, auth=KEY, headers={"Content-Type": "application/json"}).status_code == 200


def test_agent_card_url_is_configurable_and_card_does_not_advertise_backend(start):
    card = httpx.get(start(GATEWAY_PUBLIC_URL="https://a2a.hoyack.ai/") + "/.well-known/agent.json")
    assert card.json()["url"] == "https://a2a.hoyack.ai/"
    assert "openclaw" not in card.text.lower() and "shell" not in card.text.lower()


S1 = SECRETS["testkey01"]


@pytest.mark.parametrize("keys_text", [
    "", "# only a comment\n\n",
    f"testkey01 {S1}\n",
    f"TESTKEY01 alice {S1}\n",
    f"testkey01 alice {S1[:42]}\n",
    f"testkey01 alice {S1}!\n",
    f"testkey01 alice {S1}\ntestkey01 bob {S1}\n",
])
def test_bad_keys_file_refuses_to_start_without_echoing_it(tmp_path, keys_text):
    r = boot(tmp_path, keys_text)
    assert r.returncode != 0 and "GATEWAY_SIGNING_KEYS_FILE" in r.stderr
    assert S1[:16] not in r.stderr and "alice" not in r.stderr


@pytest.mark.parametrize("mode,ok", [(0o600, True), (0o400, True), (0o440, True), (0o640, True),
                                     (0o644, False), (0o604, False), (0o660, False), (0o666, False)])
def test_keys_file_open_to_others_refuses_to_start(tmp_path, mode, ok):
    r = boot(tmp_path, keys_file=write_keys_file(tmp_path / "keys.txt", mode=mode))
    assert (r.returncode == 0) == ok, r.stderr
    assert ok or "too open" in r.stderr and S1[:16] not in r.stderr


def test_missing_keys_file_refuses_to_start(tmp_path):
    for path in (None, tmp_path / "nope.txt"):
        r = boot(tmp_path, keys_file=path)
        assert r.returncode != 0 and "GATEWAY_SIGNING_KEYS_FILE" in r.stderr


def test_removing_a_keys_line_revokes_it(start, tmp_path):
    base = start(GATEWAY_SIGNING_KEYS_FILE=write_keys_file(tmp_path / "revoked.txt", ("testkey02",)))
    assert post(base, GET).status_code == 401
    assert post(base, GET, OTHER_KEY).status_code == 200


def test_new_api_key_tool_mints_a_working_key(start, tmp_path):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"), "acme"],
                       capture_output=True, text=True, check=True)
    line = r.stdout.strip()
    key_id, caller, secret = line.split()
    assert len(key_id) == 10 and int(key_id, 16) >= 0 and caller == "acme"
    assert len(base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))) >= 32
    assert key_id in r.stderr and secret not in r.stderr
    minted = tmp_path / "minted.txt"
    minted.write_text(line + "\n"); minted.chmod(0o600)
    base = start(GATEWAY_SIGNING_KEYS_FILE=str(minted))
    assert post(base, GET, Signer(key_id, secret)).status_code == 200
    assert post(base, GET).status_code == 401


def test_key_id_and_reason_are_logged_never_the_secret_or_signature(start, tmp_path):
    tdir = tmp_path / "tel"
    base = start(GATEWAY_TELEMETRY_DIR=str(tdir))
    ok = post(base, GET)
    post(base, GET, Signer("testkey09", S1))
    bad = post(base, GET, WRONG_SECRET)
    time.sleep(0.5)
    out = (tmp_path / "gateway.log").read_text()
    logs = (tdir / "logs.jsonl").read_text()
    assert "key_id=testkey01 caller=alice POST /" in out
    assert "unauthorized reason=unknown_key key_id=testkey09" in out
    assert "unauthorized reason=bad_signature key_id=testkey01" in out
    assert '"key_id": "testkey01"' in logs and '"key_id": "invalid:testkey09"' in logs
    for text in (out, logs):
        assert all(sec not in text for sec in SECRETS.values())
        assert ok.request.headers["x-kc-signature"] not in text and bad.request.headers["x-kc-signature"] not in text


def test_rotation_two_key_ids_for_one_caller_share_its_tasks(start, tmp_path):
    base = start(GATEWAY_SIGNING_KEYS_FILE=write_keys_file(tmp_path / "k.txt", ("testkey01", "testkey02", "testkey03")))
    new_key = Signer("testkey03", SECRETS["testkey03"])
    tid = post(base, SEND, KEY).json()["result"]["id"]
    for method in ("tasks/get", "tasks/cancel"):
        body = {"jsonrpc": "2.0", "id": "1", "method": method, "params": {"id": tid}}
        assert post(base, body, OTHER_KEY).json()["error"]["code"] == -32001
        assert post(base, body, new_key).json()["result"]["id"] == tid
    retired = start(GATEWAY_SIGNING_KEYS_FILE=write_keys_file(tmp_path / "k2.txt", ("testkey02", "testkey03")))
    assert post(retired, GET, KEY).status_code == 401
    assert post(retired, GET, new_key).status_code == 200


@pytest.mark.parametrize("line", [
    "testkey01 alice {s} extra", "bad!id alice {s}", "testkey01 al-ice {s}", "testkey01 alice {s}=",
])
def test_startup_error_names_the_line_never_the_secret(tmp_path, line):
    secret = secrets.token_urlsafe(32)
    r = boot(tmp_path, f"# header\n{line.format(s=secret)}\n")
    assert r.returncode != 0 and "GATEWAY_SIGNING_KEYS_FILE line 2:" in r.stderr
    assert secret not in r.stderr and secret[:8] not in r.stderr


@pytest.mark.parametrize("nbytes,ok", [(16, False), (31, False), (32, True), (64, True)])
def test_secrets_under_32_bytes_refuse_to_start(tmp_path, nbytes, ok):
    secret = secrets.token_urlsafe(nbytes)
    r = boot(tmp_path, f"testkey01 alice {secret}\n")
    assert (r.returncode == 0) == ok, r.stderr
    assert secret not in r.stderr
