"""Critic FIX FIRST on #5: no hung tasks, single-worker and per-key-slot guards, sanitized log fields, early 413."""
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, KEYS_FILE, ROOT, start_gateway
from sign_request import signed_headers

ENV = {**{k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_", "WEB_"))},
       "GATEWAY_SIGNING_KEYS_FILE": KEYS_FILE}


def py(prog, **env):
    return subprocess.run([sys.executable, "-c", prog], cwd=ROOT, env={**ENV, **env}, capture_output=True, text=True,
                          timeout=30)


@pytest.fixture
def base(tmp_path):
    p, url, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tmp_path / "tel")})
    yield url
    p.terminate(); p.wait(5)


def rpc(url, body, **kw):
    return httpx.post(url + "/", json=body, auth=KEY, timeout=5, **kw)


def test_send_with_contextid_5_and_stream_with_contextid_object_return_promptly(base):
    started = time.monotonic()
    for method, ctx in (("message/send", 5), ("message/stream", {})):
        r = rpc(base, {"jsonrpc": "2.0", "id": "1", "method": method,
                       "params": {"message": {"parts": [{"kind": "text", "text": "x"}], "contextId": ctx}}})
        assert r.json()["error"]["code"] == -32602
    assert time.monotonic() - started < 3


def test_a_crash_inside_a_task_still_finishes_it_and_closes_the_stream(tmp_path):
    prog = """
import asyncio, json
from gateway.services import task_store

async def boom(*a, **k):
    raise RuntimeError("injected")
task_store.notify = boom

async def main():
    q = asyncio.Queue()
    started = await task_store.start_task("1", {"message": {"parts": [{"kind": "text", "text": "x"}]}}, q, "testkey01")
    entry = task_store.tasks[started["taskId"]]
    await asyncio.wait_for(entry["done"].wait(), 2)
    events = [await asyncio.wait_for(q.get(), 1) for _ in range(2)]
    print(json.dumps([entry["running"], entry["task"]["final"], entry["task"]["status"]["state"],
                      events[0]["final"], events[0]["status"]["state"], events[1]]))
asyncio.run(main())
"""
    r = py(prog, GATEWAY_TELEMETRY_DIR=str(tmp_path / "tel"))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == '[false, true, "failed", true, "failed", null]'
    assert "task crashed" in r.stderr and "error_type=RuntimeError" in r.stderr and "injected" not in r.stderr


@pytest.mark.parametrize("env,needle", [
    ({"WEB_CONCURRENCY": "2"}, "WEB_CONCURRENCY must be 1"),
    ({"GATEWAY_MAX_INFLIGHT_PER_KEY": "3"}, "GATEWAY_MAX_INFLIGHT_PER_KEY must be below 3"),
])
def test_refuses_to_start_when_limits_could_be_bypassed(env, needle):
    r = py("import gateway.config", **env)
    assert r.returncode != 0 and needle in r.stderr


def test_default_inflight_per_key_leaves_an_agent_slot_free():
    r = py("from gateway.config import AGENT_CONCURRENCY, MAX_INFLIGHT_PER_KEY; print(MAX_INFLIGHT_PER_KEY, AGENT_CONCURRENCY)",
           WEB_CONCURRENCY="1")
    assert r.stdout.split() == ["2", "3"]


def test_huge_id_and_junk_method_do_not_land_raw_in_logs(base, tmp_path):
    big = "I" * 900_000
    assert rpc(base, {"jsonrpc": "2.0", "id": big, "method": "J\r\nUNK" * 1000}).json()["error"]["code"] == -32601
    rpc(base, {"jsonrpc": "2.0", "id": "2", "method": "message/send",
               "params": {"message": {"parts": [{"kind": "text", "text": "x"}], "contextId": "c\r\nFORGED" + "C" * 100}}})
    time.sleep(0.5)
    logs = (tmp_path / "tel" / "logs.jsonl").read_text()
    out = (tmp_path / "gateway.log").read_text()
    for text in (logs, out):
        assert "I" * 200 not in text and "JUNK" not in text and "J\r\n" not in text and "\nFORGED" not in text
    assert '"rpc_method": "unknown"' in logs and '"rpc_id": "' + "I" * 128 + '"' in logs
    assert '"context_id": "c\\\\x0d\\\\x0aFORGED' in logs


def test_oversized_content_length_is_refused_before_the_body_is_read(base):
    host, port = base.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=3) as s:
        signed = "".join(f"{k}: {v}\r\n" for k, v in signed_headers(KEY.key_id, KEY.secret, "POST", b"/", b"", b"").items())
        s.sendall((f"POST / HTTP/1.1\r\nHost: x\r\n{signed}"
                   "Content-Type: application/json\r\nContent-Length: 2000000\r\n\r\n").encode())
        assert s.recv(200).startswith(b"HTTP/1.1 413")
