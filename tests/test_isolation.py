"""R1 caller isolation (replays Bastion's repro.py), R5 task caps, R4 agent subprocess env/stdin, R8 telemetry cap."""
import json
import os
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, KEYS_FILE, OTHER_KEY, ROOT, TOKEN, start_gateway


@pytest.fixture
def gw(tmp_path):
    procs = []
    def make(**env):
        p, base, rec = start_gateway(tmp_path, env); procs.append(p)
        def rpc(key, method, params, query=""):
            body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            return httpx.post(base + "/" + query, json=body, auth=key, timeout=20)
        rpc.calls = lambda: [json.loads(l) for l in rec.read_text().splitlines()] if rec.exists() else []
        return rpc
    yield make
    for p in procs:
        p.terminate(); p.wait(5)


def msg(text, **kw):
    return {"message": {"role": "user", "parts": [{"kind": "text", "text": text}], **kw}}


def test_r1_other_key_cannot_read_overwrite_join_or_cancel(gw):
    rpc = gw()
    a = rpc(KEY, "message/send", msg("A-SECRET-DATA", taskId="t-A", contextId="ctx-A")).json()["result"]
    a_id = a["id"]
    assert a_id != "t-A" and a["artifacts"][0]["parts"][0]["text"] == "echo: A-SECRET-DATA"

    for tid in ("t-A", a_id):  # repro R2: read by client id or by real id
        for key in (OTHER_KEY,):
            r = rpc(key, "tasks/get", {"id": tid}).json()
            assert r["error"] == {"code": -32001, "message": "task not found"} and "A-SECRET" not in json.dumps(r)

    b = rpc(OTHER_KEY, "message/send", msg("B-OVERWRITE", taskId=a_id, contextId="ctx-B")).json()["result"]  # repro R3
    assert b["id"] != a_id
    still = rpc(KEY, "tasks/get", {"id": a_id}).json()["result"]
    assert still["contextId"] == "ctx-A" and still["artifacts"][0]["parts"][0]["text"] == "echo: A-SECRET-DATA"

    rpc(OTHER_KEY, "message/send", msg("B-joins-A-session", contextId="ctx-A"))  # repro R4
    sessions = {c["message"]: c["argv"][c["argv"].index("--session-id") + 1] for c in rpc.calls()}
    assert sessions["A-SECRET-DATA"] == "a2a-testkey01-ctx-A"
    assert sessions["B-joins-A-session"] == "a2a-testkey02-ctx-A"

    slow = rpc(KEY, "message/send", msg("SLOW job", taskId="t-A2"), "?wait=false").json()["result"]  # repro R6
    r = rpc(OTHER_KEY, "tasks/cancel", {"id": slow["id"]}).json()
    assert r["error"]["code"] == -32001
    assert rpc(KEY, "tasks/get", {"id": slow["id"]}).json()["result"]["status"]["state"] == "submitted"
    assert rpc(KEY, "tasks/cancel", {"id": slow["id"]}).json()["result"]["status"]["state"] == "canceled"


def test_r1_failure_reply_is_generic(gw):
    t = gw()(KEY, "message/send", msg("FAIL please")).json()["result"]  # repro R5
    assert t["status"]["state"] == "failed"
    assert t["status"]["message"]["parts"][0]["text"] == f"agent error (task {t['id']})"


def test_r5_inflight_per_key_and_global_caps(gw):
    rpc = gw(GATEWAY_MAX_INFLIGHT_PER_KEY="2", GATEWAY_MAX_PENDING="3")
    assert [rpc(KEY, "message/send", msg("SLOW"), "?wait=false").status_code for _ in range(2)] == [200, 200]
    r = rpc(KEY, "message/send", msg("SLOW"), "?wait=false")
    assert (r.status_code, r.json(), r.headers["retry-after"]) == (429, {"error": "rate limited"}, "5")
    assert rpc(KEY, "message/stream", msg("SLOW")).status_code == 429
    assert rpc(OTHER_KEY, "message/send", msg("SLOW"), "?wait=false").status_code == 200
    assert rpc(OTHER_KEY, "message/send", msg("SLOW"), "?wait=false").status_code == 429  # global cap 3
    time.sleep(3)
    assert rpc(KEY, "message/send", msg("hi")).status_code == 200


def test_r5_stored_tasks_per_key_are_capped(gw):
    rpc = gw(GATEWAY_MAX_TASKS_PER_KEY="2")
    ids = [rpc(KEY, "message/send", msg(f"m{i}")).json()["result"]["id"] for i in range(3)]
    other = rpc(OTHER_KEY, "message/send", msg("o")).json()["result"]["id"]
    assert rpc(KEY, "tasks/get", {"id": ids[0]}).json()["error"]["code"] == -32001
    for tid in ids[1:]:
        assert rpc(KEY, "tasks/get", {"id": tid}).json()["result"]["status"]["state"] == "completed"
    assert rpc(OTHER_KEY, "tasks/get", {"id": other}).json()["result"]["status"]["state"] == "completed"


def test_r4_agent_env_has_no_gateway_settings_or_key_material(gw):
    rpc = gw(GATEWAY_NOTIFY_URL="http://127.0.0.1:9/hook", GATEWAY_PUBLIC_URL="https://a2a.hoyack.ai/")
    rpc(KEY, "message/send", msg("run env"))
    call = rpc.calls()[0]
    assert set(call["env"]) <= {"PATH", "HOME", "LANG", "LC_ALL", "TZ"}
    assert "--message" not in call["argv"] and "run env" not in call["argv"]


def test_r4_message_over_128kb_goes_over_stdin(tmp_path):
    """argv caps one argument at 128 KB (MAX_ARG_STRLEN); stdin has no such limit. MAX_TEXT (100 KB) is bypassed
    here on purpose to prove the transport."""
    text = "y" * 140_000
    prog = ("import asyncio, sys\nfrom gateway.services.agent_runner import run_agent\n"
            "print(len(asyncio.run(run_agent('s1', sys.stdin.read()))))")
    env = {**os.environ, "GATEWAY_SIGNING_KEYS_FILE": KEYS_FILE, "KIMICLAW_TOKEN": TOKEN, "HOME": str(tmp_path),
           "GATEWAY_TELEMETRY_DIR": str(tmp_path / "tel"),
           "PATH": os.path.join(ROOT, "tests", "fakebin") + os.pathsep + os.environ["PATH"]}
    r = subprocess.run([sys.executable, "-c", prog], input=text, cwd=ROOT, env=env, capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    assert int(r.stdout.strip()) == len("echo: ") + len(text)
    assert json.loads((tmp_path / "argv.jsonl").read_text())["message"] == text


def test_r4_message_at_max_text_works_end_to_end(gw):
    t = gw()(KEY, "message/send", msg("z" * 100_000)).json()["result"]
    assert t["status"]["state"] == "completed"
    assert gw()(KEY, "message/send", msg("z" * 100_001)).json()["error"]["message"] == "message too large"


def test_r8_telemetry_files_are_size_capped(gw, tmp_path):
    tdir = tmp_path / "tel"
    rpc = gw(GATEWAY_TELEMETRY_DIR=str(tdir), GATEWAY_TELEMETRY_FILE_MB="0.002")
    for _ in range(60):
        rpc(KEY, "tasks/get", {"id": "nope"})
    time.sleep(0.5)
    files = sorted(p.name for p in tdir.iterdir() if p.name.startswith("logs.jsonl"))
    assert files == ["logs.jsonl"] + [f"logs.jsonl.{i}" for i in range(1, 5)]
    assert all((tdir / f).stat().st_size < 4000 for f in files)


def test_startup_warns_limits_are_single_replica(caplog):
    import asyncio
    import logging

    from gateway.main import lifespan

    async def run():
        async with lifespan(None):
            pass

    with caplog.at_level(logging.WARNING, logger="kimiclaw"):
        asyncio.run(run())
    assert "one replica" in caplog.text
