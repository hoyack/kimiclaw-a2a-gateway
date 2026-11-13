"""Per-caller API keys, per-caller rate limit on POST /, and the configurable agent-card URL."""
import os
import subprocess
import sys

import httpx
import pytest

from conftest import ROOT, start_gateway

ALICE = "a" * 32
BOB = "b" * 40
KEYS = f"alice:{ALICE}, bob:{BOB}"
GET_TASK = {"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}


@pytest.fixture
def start(tmp_path):
    procs = []
    def make(**env):
        p, base, _ = start_gateway(tmp_path, env); procs.append(p)
        return p, base
    yield make
    for p in procs:
        p.terminate(); p.wait(5)


def bearer(key):
    return {"Authorization": f"Bearer {key}"}


def test_task_endpoint_needs_a_valid_caller_key(start):
    _, base = start(GATEWAY_API_KEYS=KEYS)
    for h in ({}, bearer("wrong"), bearer("dummy-test-token"), {"Authorization": ALICE}, bearer(ALICE + "x")):
        r = httpx.post(base + "/", json=GET_TASK, headers=h)
        assert (r.status_code, r.json()) == (401, {"error": "unauthorized"})
    for key in (ALICE, BOB):
        r = httpx.post(base + "/", json=GET_TASK, headers=bearer(key))
        assert r.status_code == 200 and r.json()["error"]["code"] == -32001


def test_agent_card_and_healthz_stay_open(start):
    _, base = start(GATEWAY_API_KEYS=KEYS, GATEWAY_RATE_LIMIT="1")
    httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE))
    assert httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE)).status_code == 429
    for h in ({}, bearer("wrong")):
        assert httpx.get(base + "/healthz", headers=h).json() == {"status": "ok"}
        assert httpx.get(base + "/.well-known/agent.json", headers=h).status_code == 200


def test_rate_limit_is_per_caller_with_retry_after(start):
    _, base = start(GATEWAY_API_KEYS=KEYS, GATEWAY_RATE_LIMIT="3", GATEWAY_RATE_WINDOW_S="30")
    codes = [httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE)).status_code for _ in range(3)]
    assert codes == [200, 200, 200]
    r = httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE))
    assert (r.status_code, r.json()) == (429, {"error": "rate limited"})
    assert 1 <= int(r.headers["retry-after"]) <= 30
    assert httpx.post(base + "/", json=GET_TASK, headers=bearer(BOB)).status_code == 200
    assert httpx.get(base + "/", headers=bearer(ALICE)).status_code == 200


def test_unauthenticated_calls_do_not_spend_a_callers_quota(start):
    _, base = start(GATEWAY_API_KEYS=KEYS, GATEWAY_RATE_LIMIT="1")
    for _ in range(5):
        assert httpx.post(base + "/", json=GET_TASK, headers=bearer("wrong")).status_code == 401
    assert httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE)).status_code == 200


def test_rate_limit_window_resets(start):
    import time
    _, base = start(GATEWAY_API_KEYS=KEYS, GATEWAY_RATE_LIMIT="1", GATEWAY_RATE_WINDOW_S="1")
    assert httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE)).status_code == 200
    assert httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE)).status_code == 429
    time.sleep(1.1)
    assert httpx.post(base + "/", json=GET_TASK, headers=bearer(ALICE)).status_code == 200


def test_agent_card_url_is_configurable(start):
    _, base = start(GATEWAY_PUBLIC_URL="https://a2a.hoyack.ai/")
    assert httpx.get(base + "/.well-known/agent.json").json()["url"] == "https://a2a.hoyack.ai/"


@pytest.mark.parametrize("keys", ["alice", f"alice:{'s' * 31}", f":{ALICE}", f"alice:{ALICE},alice:{BOB}",
                                  f"alice:{ALICE},bob:{ALICE}"])
def test_bad_key_config_refuses_to_start_without_echoing_keys(keys):
    env = {**os.environ, "KIMICLAW_TOKEN": "t", "GATEWAY_API_KEYS": keys}
    r = subprocess.run([sys.executable, "-c", "import gateway.config"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "GATEWAY_API_KEYS entry" in r.stderr
    assert ALICE not in r.stderr and BOB not in r.stderr and "s" * 31 not in r.stderr
