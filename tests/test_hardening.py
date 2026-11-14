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
       "GATEWAY_PUBLIC_KEYS_FILE": KEYS_FILE, "KIMICLAW_LIMIT_CONCURRENCY": "1024"}


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
    started = await task_store.start_task("1", {"message": {"parts": [{"kind": "text", "text": "x"}]}}, q, "alice")
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
        signed = "".join(f"{k}: {v}\r\n" for k, v in signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", b"").items())
        s.sendall((f"POST / HTTP/1.1\r\nHost: x\r\n{signed}"
                   "Content-Type: application/json\r\nContent-Length: 2000000\r\n\r\n").encode())
        assert s.recv(200).startswith(b"HTTP/1.1 413")


@pytest.mark.parametrize("value,needle", [
    (None, "KIMICLAW_LIMIT_CONCURRENCY is not set"),
    ("", "KIMICLAW_LIMIT_CONCURRENCY is not set"),
    ("nope", "must be an integer"),
    ("128.0", "must be an integer"),
    ("1_024", "must be an integer"),
    ("+128", "must be an integer"),
    ("63", "from 64 to 4096"),
    ("4097", "from 64 to 4096"),
])
def test_refuses_to_start_without_a_valid_concurrency_cap(value, needle):
    env = {k: v for k, v in ENV.items() if k != "KIMICLAW_LIMIT_CONCURRENCY"}
    if value is not None:
        env["KIMICLAW_LIMIT_CONCURRENCY"] = value
    r = subprocess.run([sys.executable, "-c", "from gateway.main import limit_concurrency; limit_concurrency()"],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and needle in r.stderr


def _probe(p):
    return p.probe_base


def test_uvicorn_app_app_is_refused():
    r = subprocess.run([sys.executable, "-c", "import app"], cwd=ROOT, env=ENV,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and "python -m gateway" in r.stderr and "uvicorn app:app" in r.stderr


@pytest.mark.parametrize("value,needle", [
    ("0", "from 1 to 30"),
    ("31", "from 1 to 30"),
    ("5.5", "must be an integer"),
    ("+5", "must be an integer"),
])
def test_refuses_to_start_with_a_bad_header_timeout(value, needle):
    r = subprocess.run([sys.executable, "-c", "from gateway.main import header_timeout_s; header_timeout_s()"],
                       cwd=ROOT, env={**ENV, "GATEWAY_HEADER_TIMEOUT_S": value},
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and needle in r.stderr


def test_a_valid_concurrency_cap_is_passed_to_uvicorn_and_logged(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"KIMICLAW_LIMIT_CONCURRENCY": "64"})
    try:
        log = (tmp_path / "gateway.log").read_text()
        assert "uvicorn limit_concurrency=64" in log
        assert "probe_port=" in log and "workers=1" in log and "header_timeout_s=" in log
        port = int(base.rsplit(":", 1)[1])
        held = []
        for _ in range(64):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")  # incomplete, stays open
            held.append(s)
        r = httpx.get(base + "/healthz", timeout=5)
        assert r.status_code == 503, r.status_code
        probe = httpx.get(_probe(p) + "/healthz", timeout=5)
        assert probe.status_code == 200, probe.status_code
        assert httpx.get(_probe(p) + "/readyz", timeout=5).status_code == 200
        [s.close() for s in held]
        assert httpx.get(base + "/healthz", timeout=5).status_code == 200
    finally:
        p.terminate(); p.wait(5)


def test_probe_healthz_is_up_and_readyz_is_503_during_the_startup_hold(tmp_path):
    """Probe listener starts at once; /healthz is 200 during the hold, /readyz is 503 until the main port serves."""
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_SIGNATURE_FUTURE_S": "8"}, wait="probe")
    try:
        hz = httpx.get(_probe(p) + "/healthz", timeout=2)
        assert hz.status_code == 200 and hz.json() == {"status": "up"}
        ready = httpx.get(_probe(p) + "/readyz", timeout=2)
        assert ready.status_code == 503 and ready.json() == {"status": "starting"}
        # main port is not serving yet
        with pytest.raises(httpx.ConnectError):
            httpx.get(base + "/healthz", timeout=0.4)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                if httpx.get(_probe(p) + "/readyz", timeout=0.5).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        assert httpx.get(_probe(p) + "/healthz", timeout=2).json() == {"status": "up"}
        assert httpx.get(_probe(p) + "/readyz", timeout=2).json() == {"status": "ready"}
        assert httpx.get(base + "/healthz", timeout=2).status_code == 200
    finally:
        p.terminate(); p.wait(5)


@pytest.mark.parametrize("value,required", [
    (None, True),
    ("false", True),
    ("no", True),
    (" 0", True),
    ("00", True),
    ("1", True),
    ("", True),
    ("0", False),
])
def test_require_openclaw_is_on_unless_the_value_is_exactly_0(value, required, monkeypatch):
    if value is None:
        monkeypatch.delenv("GATEWAY_REQUIRE_OPENCLAW", raising=False)
    else:
        monkeypatch.setenv("GATEWAY_REQUIRE_OPENCLAW", value)
    from gateway.routes.health import require_openclaw
    assert require_openclaw() is required


def test_probe_readyz_is_starting_during_the_hold_even_when_openclaw_is_not_required(tmp_path):
    p, base, _ = start_gateway(tmp_path, {
        "GATEWAY_SIGNATURE_FUTURE_S": "8",
        "GATEWAY_REQUIRE_OPENCLAW": "0",
        "PATH": "/usr/bin:/bin",
    }, wait="probe")
    try:
        ready = httpx.get(_probe(p) + "/readyz", timeout=2)
        assert ready.status_code == 503 and ready.json() == {"status": "starting"}
        with pytest.raises(httpx.ConnectError):
            httpx.get(base + "/healthz", timeout=0.4)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                if httpx.get(_probe(p) + "/readyz", timeout=0.5).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        r = httpx.get(_probe(p) + "/readyz", timeout=2)
        assert r.status_code == 200 and r.json() == {"status": "ready"}
        log = (tmp_path / "gateway.log").read_text()
        assert "GATEWAY_REQUIRE_OPENCLAW=0: readiness ignores openclaw; message/send will fail until openclaw is installed" in log
    finally:
        p.terminate(); p.wait(5)


def test_probe_readyz_is_200_when_openclaw_is_not_required_and_is_missing(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_REQUIRE_OPENCLAW": "0", "PATH": "/usr/bin:/bin"})
    try:
        r = httpx.get(_probe(p) + "/readyz", timeout=5)
        assert r.status_code == 200 and r.json() == {"status": "ready"}
        log = (tmp_path / "gateway.log").read_text()
        assert "GATEWAY_REQUIRE_OPENCLAW=0: readiness ignores openclaw; message/send will fail until openclaw is installed" in log
    finally:
        p.terminate(); p.wait(5)


def test_probe_readyz_is_not_ready_when_openclaw_is_required_and_is_missing(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"PATH": "/usr/bin:/bin"})
    try:
        r = httpx.get(_probe(p) + "/readyz", timeout=5)
        assert r.status_code == 503 and r.json() == {"status": "not ready"}
        log = (tmp_path / "gateway.log").read_text()
        assert "GATEWAY_REQUIRE_OPENCLAW=0:" not in log
    finally:
        p.terminate(); p.wait(5)


def test_zero_byte_and_partial_header_connections_are_closed_by_the_header_timeout(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_HEADER_TIMEOUT_S": "5", "KIMICLAW_LIMIT_CONCURRENCY": "64"})
    port = int(base.rsplit(":", 1)[1])
    try:
        idle = socket.create_connection(("127.0.0.1", port), timeout=5)
        partial = socket.create_connection(("127.0.0.1", port), timeout=5)
        partial.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
        idle.settimeout(8)
        partial.settimeout(8)
        t0 = time.monotonic()
        assert idle.recv(64) == b""  # peer closed
        assert partial.recv(64) == b""
        elapsed = time.monotonic() - t0
        assert 4 <= elapsed <= 8, elapsed
    finally:
        p.terminate(); p.wait(5)


def test_after_cap_many_idle_connections_time_out_a_signed_request_gets_200(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_HEADER_TIMEOUT_S": "5", "KIMICLAW_LIMIT_CONCURRENCY": "64"})
    port = int(base.rsplit(":", 1)[1])
    try:
        held = []
        for _ in range(64):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            held.append(s)
        assert httpx.get(base + "/healthz", timeout=2).status_code == 503
        assert httpx.get(_probe(p) + "/healthz", timeout=2).status_code == 200
        deadline = time.monotonic() + 10
        status = None
        while time.monotonic() < deadline:
            try:
                status = httpx.get(base + "/", auth=KEY, timeout=2).status_code
                if status == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        assert status == 200, status
    finally:
        [s.close() for s in held]
        p.terminate(); p.wait(5)


def test_a_thousand_quiet_refusals_do_not_write_uvicorn_access_lines_or_client_addresses(tmp_path):
    """A-1: 1000 quiet 401s produce aggregated lines, no uvicorn access line, no client ip:port."""
    import re
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_REFUSAL_LOG_S": "1"})
    try:
        for _ in range(1000):
            assert httpx.get(base + "/", timeout=5).status_code == 401
        time.sleep(1.2)
        text = (tmp_path / "gateway.log").read_text()
        refused = [ln for ln in text.splitlines() if "auth refused count=" in ln]
        assert refused, text
        total = sum(int(ln.split("count=", 1)[1].split()[0]) for ln in refused)
        assert total >= 1000, (total, refused)
        # fewer log lines than refusals (aggregated, not per-request)
        assert len(text.splitlines()) < 1000
        assert not any("uvicorn.access" in ln for ln in text.splitlines())
        access = [ln for ln in text.splitlines() if "kimiclaw.access" in ln or "uvicorn.access" in ln]
        assert not any(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b", ln) for ln in access), access
        assert not any(" GET / 401" in ln or ln.endswith("GET / 401") for ln in access)
    finally:
        p.terminate(); p.wait(5)


def test_quiet_refusals_are_counted_in_requests_total_and_not_exported_as_spans(tmp_path):
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir)})
    try:
        assert httpx.get(base + "/", timeout=5).status_code == 401
        assert httpx.get(base + "/", auth=KEY, timeout=5).status_code == 200
    finally:
        p.terminate(); p.wait(10)
    import json
    traces = (tdir / "traces.jsonl").read_text() if (tdir / "traces.jsonl").exists() else ""
    assert "kimiclaw.quiet" not in traces
    spans = [json.loads(l) for l in traces.splitlines() if l.strip()]
    # no exported span may be the quiet 401 on /
    for s in spans:
        attrs = s.get("attributes") or {}
        path = attrs.get("url.path") or attrs.get("http.target") or attrs.get("http.route")
        status = attrs.get("http.response.status_code") or attrs.get("http.status_code")
        assert not (path in ("/", "") and status == 401), s
    slash_rpc = [s for s in spans if s.get("name") == "rpc" and (s.get("attributes") or {}).get("url.path") == "/"]
    assert len(slash_rpc) == 1 and slash_rpc[0]["attributes"].get("http.response.status_code") == 200
    metrics = (tdir / "metrics.jsonl").read_text() if (tdir / "metrics.jsonl").exists() else ""
    assert "gateway.requests" in metrics
    assert "401" in metrics and "200" in metrics

def test_plain_uvicorn_including_workers_2_is_refused():
    """W-1: python -m gateway is the only launcher; a second worker must not be startable."""
    from conftest import free_port
    port = free_port()
    r = subprocess.run(
        [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=15)
    assert r.returncode != 0 and "python -m gateway" in (r.stderr + r.stdout)
    # --workers 2 runs a supervisor that may not exit when the workers fail to import
    port = free_port()
    p = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(port), "--workers", "2"],
        cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        try:
            out, _ = p.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
        assert "python -m gateway" in (out or ""), out
        try:
            status = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1).status_code
        except httpx.HTTPError:
            status = None
        assert status not in (200, 503), status
    finally:
        p.kill(); p.wait(5)

def test_concurrency_cap_is_taken_from_the_env_only_and_logged_after_it_is_applied(tmp_path):
    """C-1: no --limit-concurrency flag; the env value is logged only after Config has it."""
    r = subprocess.run(
        [sys.executable, "-m", "gateway", "--limit-concurrency", "128"],
        cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=15)
    assert r.returncode != 0
    err = r.stderr + r.stdout
    assert "unrecognized arguments" in err or "limit-concurrency" in err
    assert "uvicorn limit_concurrency=" not in err
    p, base, _ = start_gateway(tmp_path, {"KIMICLAW_LIMIT_CONCURRENCY": "64"})
    try:
        log = (tmp_path / "gateway.log").read_text()
        assert "uvicorn limit_concurrency=64" in log
        # logged after the cap was bound onto the main Config, not before serve is configured
        assert log.index("uvicorn limit_concurrency=64") < log.index("probe listening")
        assert httpx.get(base + "/healthz", timeout=5).status_code == 200
    finally:
        p.terminate(); p.wait(5)

def test_probe_port_404s_every_main_app_route_and_wrong_methods(tmp_path):
    p, base, _ = start_gateway(tmp_path, {})
    probe = _probe(p)
    try:
        assert httpx.get(probe + "/healthz", timeout=5).json() == {"status": "up"}
        assert httpx.get(probe + "/readyz", timeout=5).json() == {"status": "ready"}
        for path in ("/", "/.well-known/agent.json", "/docs", "/openapi.json", "/redoc",
                     "/healthz/x", "/readyz/x", "/message/send"):
            unsigned = httpx.get(probe + path, timeout=5)
            assert unsigned.status_code == 404 and unsigned.json() == {"status": "not found"}, (path, unsigned.status_code)
            signed = httpx.get(probe + path, auth=KEY, timeout=5)
            assert signed.status_code == 404, (path, signed.status_code)
            posted = httpx.post(probe + path, content=b"{}", auth=KEY, timeout=5)
            assert posted.status_code == 404, (path, posted.status_code)
        for method, path in (("POST", "/healthz"), ("PUT", "/healthz"), ("POST", "/readyz"),
                             ("PUT", "/readyz"), ("DELETE", "/healthz")):
            r = httpx.request(method, probe + path, timeout=5)
            assert r.status_code == 404 and r.json() == {"status": "not found"}, (method, path, r.status_code)
    finally:
        p.terminate(); p.wait(5)

def _read_http_response(sock, timeout=5):
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    while len(rest) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk
    status = int(head.split()[1]) if head.split()[1:2] else 0
    return status, rest


def test_header_timer_is_rearmed_on_a_kept_alive_connection(tmp_path):
    """After a 200 on a kept-alive connection, slow/partial headers are closed in about 5s."""
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_HEADER_TIMEOUT_S": "5"})
    port = int(base.rsplit(":", 1)[1])
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        hdr = signed_headers(KEY.key_id, KEY.private_key, "GET", b"/", b"", b"")
        lines = "".join(f"{k}: {v}\r\n" for k, v in hdr.items())
        s.sendall(f"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n{lines}\r\n".encode())
        status, _ = _read_http_response(s)
        assert status == 200, status
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")  # incomplete headers on the same connection
        s.settimeout(8)
        t0 = time.monotonic()
        assert s.recv(64) == b""
        elapsed = time.monotonic() - t0
        assert 4 <= elapsed <= 8, elapsed
    finally:
        p.terminate(); p.wait(5)


def test_eleven_hundred_idle_connections_time_out_and_a_signed_request_gets_200(tmp_path):
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 8192), hard if hard > 0 else 8192))
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_HEADER_TIMEOUT_S": "5", "KIMICLAW_LIMIT_CONCURRENCY": "1024"})
    port = int(base.rsplit(":", 1)[1])
    held = []
    try:
        for _ in range(1100):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            held.append(s)
        # cap is held by idle connections; the probe stays up
        assert httpx.get(_probe(p) + "/healthz", timeout=5).json() == {"status": "up"}
        deadline = time.monotonic() + 12
        status = None
        while time.monotonic() < deadline:
            try:
                status = httpx.get(base + "/", auth=KEY, timeout=2).status_code
                if status == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        assert status == 200, status
    finally:
        [s.close() for s in held]
        p.terminate(); p.wait(5)


def test_idle_connections_on_the_probe_port_are_closed_while_healthz_stays_200(tmp_path):
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_HEADER_TIMEOUT_S": "5"})
    probe = _probe(p)
    port = int(probe.rsplit(":", 1)[1])
    held = []
    try:
        for _ in range(32):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            held.append(s)
        assert httpx.get(probe + "/healthz", timeout=2).json() == {"status": "up"}
        for s in held:
            s.settimeout(8)
        t0 = time.monotonic()
        for s in held:
            assert s.recv(64) == b""
        elapsed = time.monotonic() - t0
        assert 4 <= elapsed <= 8, elapsed
        assert httpx.get(probe + "/healthz", timeout=2).json() == {"status": "up"}
    finally:
        [s.close() for s in held]
        p.terminate(); p.wait(5)
