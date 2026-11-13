"""Per-caller API keys from a hashed keys file, per-key rate limits, body cap, key_id audit logs, agent-card URL."""
import hashlib
import json
import os
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, KEYS_FILE, OTHER_KEY, ROOT, TOKEN, start_gateway

GET = {"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}
SEND = {"jsonrpc": "2.0", "id": "1", "method": "message/send",
        "params": {"message": {"parts": [{"kind": "text", "text": "hi"}]}, "configuration": {"blocking": False}}}
KEY_HASH = hashlib.sha256(KEY.encode()).hexdigest()


@pytest.fixture
def start(tmp_path):
    procs = []
    def make(**env):
        p, base, _ = start_gateway(tmp_path, env); procs.append(p)
        return base
    yield make
    for p in procs:
        p.terminate(); p.wait(5)


def bearer(key):
    return {"Authorization": f"Bearer {key}"}


def post(base, body, key=KEY):
    return httpx.post(base + "/", json=body, headers=bearer(key) if key else {})


def boot(tmp_path, keys_text=None, keys_file=None):
    path = keys_file
    if keys_text is not None:
        path = tmp_path / "keys.txt"; path.write_text(keys_text)
    env = {**os.environ, "KIMICLAW_TOKEN": TOKEN, "GATEWAY_KEYS_FILE": str(path or "")}
    return subprocess.run([sys.executable, "-c", "import gateway.config"], cwd=ROOT, env=env, capture_output=True, text=True)


def test_only_listed_keys_pass(start):
    base = start()
    bad = [None, "wrong", TOKEN, KEY + "x", KEY[:-1], "kc_testkey09_" + "k" * 43, "kc_testkey01_" + "z" * 43]
    for key in bad:
        assert (post(base, GET, key).status_code, post(base, GET, key).json()) == (401, {"error": "unauthorized"})
    assert httpx.post(base + "/", json=GET, headers={"Authorization": KEY}).status_code == 401
    for key in (KEY, OTHER_KEY):
        r = post(base, GET, key)
        assert r.status_code == 200 and r.json()["error"]["code"] == -32001


def test_agent_card_and_healthz_stay_open_while_a_key_is_limited(start):
    base = start(GATEWAY_GET_PER_S="0.01")
    post(base, GET)
    assert post(base, GET).status_code == 429
    for h in ({}, bearer("wrong")):
        assert httpx.get(base + "/healthz", headers=h).json() == {"status": "ok"}
        assert httpx.get(base + "/.well-known/agent.json", headers=h).status_code == 200


def test_task_create_limit_is_per_key_with_retry_after(start):
    base = start(GATEWAY_CREATE_PER_MIN="1", GATEWAY_CREATE_BURST="2")
    assert [post(base, SEND).status_code for _ in range(2)] == [200, 200]
    r = httpx.post(base + "/", json={**SEND, "method": "message/stream"}, headers=bearer(KEY))
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
        assert post(base, GET, "wrong").status_code == 401
    assert post(base, GET).status_code == 200


def test_body_over_1mb_is_413(start):
    base = start()
    big = json.dumps({**GET, "pad": "x" * 1_000_001}).encode()
    r = httpx.post(base + "/", content=big, headers={**bearer(KEY), "Content-Type": "application/json"})
    assert (r.status_code, r.json()) == (413, {"error": "request body too large"})
    ok = json.dumps({**GET, "pad": "x" * 900_000}).encode()
    assert httpx.post(base + "/", content=ok, headers={**bearer(KEY), "Content-Type": "application/json"}).status_code == 200


def test_agent_card_url_is_configurable_and_card_does_not_advertise_backend(start):
    card = httpx.get(start(GATEWAY_PUBLIC_URL="https://a2a.hoyack.ai/") + "/.well-known/agent.json")
    assert card.json()["url"] == "https://a2a.hoyack.ai/"
    assert "openclaw" not in card.text.lower() and "shell" not in card.text.lower()


@pytest.mark.parametrize("keys_text", [
    "", "# only a comment\n\n",
    f"testkey01 {KEY_HASH}\n",
    f"TESTKEY01 {KEY_HASH} alice\n",
    f"testkey01 {KEY_HASH[:-1]} alice\n",
    f"testkey01 {KEY_HASH} alice\ntestkey01 {KEY_HASH} bob\n",
])
def test_bad_keys_file_refuses_to_start_without_echoing_it(tmp_path, keys_text):
    r = boot(tmp_path, keys_text)
    assert r.returncode != 0 and "GATEWAY_KEYS_FILE" in r.stderr
    assert KEY_HASH[:16] not in r.stderr and "alice" not in r.stderr


def test_missing_keys_file_refuses_to_start(tmp_path):
    for path in (None, tmp_path / "nope.txt"):
        r = boot(tmp_path, keys_file=path)
        assert r.returncode != 0 and "GATEWAY_KEYS_FILE" in r.stderr


def test_removing_a_keys_line_revokes_it(start, tmp_path):
    keys = tmp_path / "revoked.txt"
    keys.write_text("".join(l + "\n" for l in open(KEYS_FILE).read().splitlines() if not l.startswith("testkey01")))
    base = start(GATEWAY_KEYS_FILE=str(keys))
    assert post(base, GET).status_code == 401
    assert post(base, GET, OTHER_KEY).status_code == 200


def test_new_api_key_tool_mints_a_working_key(start, tmp_path):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"), "acme"],
                       capture_output=True, text=True, check=True)
    line = r.stdout.strip()
    key = r.stderr.strip().rsplit(" ", 1)[1]
    key_id, digest, caller = line.split()
    assert key.startswith(f"kc_{key_id}_") and len(key) >= len(f"kc_{key_id}_") + 43
    assert digest == hashlib.sha256(key.encode()).hexdigest() and caller == "acme" and key not in r.stdout
    (tmp_path / "minted.txt").write_text(line + "\n")
    assert post(start(GATEWAY_KEYS_FILE=str(tmp_path / "minted.txt")), GET, key).status_code == 200


def test_key_id_is_logged_never_the_key_or_hash(start, tmp_path):
    tdir = tmp_path / "tel"
    base = start(GATEWAY_TELEMETRY_DIR=str(tdir))
    post(base, GET)
    post(base, GET, "kc_testkey09_" + "q" * 43)
    time.sleep(0.5)
    out = (tmp_path / "gateway.log").read_text()
    logs = (tdir / "logs.jsonl").read_text()
    assert "key_id=testkey01 caller=caller-testkey01 POST /" in out
    assert "unauthorized key_id_hint=testkey09" in out
    assert '"key_id": "testkey01"' in logs and '"key_id": "invalid:testkey09"' in logs
    for text in (out, logs):
        assert KEY not in text and KEY_HASH not in text and "q" * 43 not in text
