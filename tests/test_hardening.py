"""Critic FIX FIRST on #5: no hung tasks, single-worker and per-key-slot guards, sanitized log fields, early 413."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, KEYS_FILE, ROOT, start_gateway
from sign_request import signed_headers

ENV = {**{k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_", "WEB_", "UVICORN_"))},
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
    ({"GATEWAY_MAX_INFLIGHT_PER_KEY": "abc"}, "GATEWAY_MAX_INFLIGHT_PER_KEY must be an integer"),
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
    (" 128", "must be an integer"),
    ("128\n", "must be an integer"),
    ("0128", "must be an integer"),
    ("63", "from 64 to 4096"),
    ("4097", "from 64 to 4096"),
])
def test_refuses_to_start_without_a_valid_concurrency_cap(value, needle):
    env = {k: v for k, v in ENV.items() if k != "KIMICLAW_LIMIT_CONCURRENCY"}
    if value is not None:
        env["KIMICLAW_LIMIT_CONCURRENCY"] = value
    r = _run_official(env)
    out = r.stderr + r.stdout
    assert r.returncode != 0 and needle in out and "Traceback" not in out, out


def _probe(p):
    return p.probe_base


def _run_official(env, timeout=10):
    """Run `python -m gateway` on a free port. Used for clean config-error checks."""
    from conftest import free_port
    port, probe = free_port(), free_port()
    env = {**env, "GATEWAY_PROBE_PORT": str(probe)}
    return subprocess.run(
        [sys.executable, "-m", "gateway", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)


def test_uvicorn_app_app_is_refused():
    r = subprocess.run([sys.executable, "-c", "import app"], cwd=ROOT, env=ENV,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and "python -m gateway" in r.stderr and "uvicorn app:app" in r.stderr


@pytest.mark.parametrize("value,needle", [
    ("0", "must be an integer"),
    ("31", "from 1 to 30"),
    ("5.5", "must be an integer"),
    ("+5", "must be an integer"),
    (" 5", "must be an integer"),
    ("05", "must be an integer"),
])
def test_refuses_to_start_with_a_bad_header_timeout(value, needle):
    r = _run_official({**ENV, "GATEWAY_HEADER_TIMEOUT_S": value})
    out = r.stderr + r.stdout
    assert r.returncode != 0 and needle in out and "Traceback" not in out, out


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

def _venv_script(name):
    return os.path.join(os.path.dirname(sys.executable), name)


def _assert_launch_refused(kind, argv, extra_env=None):
    """Unsupported server starts exit non-zero in a few seconds, never serve a signed 200, and do not flood."""
    from conftest import free_port
    port = free_port()
    if kind == "uvicorn":
        cmd = [sys.executable, "-m", "uvicorn", *argv, "--host", "127.0.0.1", "--port", str(port)]
    elif kind == "console":
        cmd = [_venv_script("uvicorn"), *argv, "--host", "127.0.0.1", "--port", str(port)]
    elif kind == "gunicorn":
        cmd = [_venv_script("gunicorn"), *argv, "-b", f"127.0.0.1:{port}"]
    elif kind == "hypercorn":
        cmd = [_venv_script("hypercorn"), *argv, "-b", f"127.0.0.1:{port}"]
    elif kind == "py-uvicorn":
        cmd = [sys.executable, *argv, "--host", "127.0.0.1", "--port", str(port)]
    elif kind == "py-hypercorn":
        cmd = [sys.executable, *argv, "-b", f"127.0.0.1:{port}"]
    else:
        raise ValueError(kind)
    env = {**ENV, **(extra_env or {})}
    t0 = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    served = False
    try:
        deadline = t0 + 8
        while proc.poll() is None and time.monotonic() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{port}/", auth=KEY, timeout=0.2).status_code == 200:
                    served = True
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        if proc.poll() is None:
            proc.kill()
        stdout, stderr = proc.communicate(timeout=3)
    except Exception:
        proc.kill()
        raise
    elapsed = time.monotonic() - t0
    out = (stderr or "") + (stdout or "")
    assert not served, out
    assert proc.returncode not in (0, None), (proc.returncode, out)
    assert elapsed < 6, elapsed
    n = out.count("start with `python -m gateway`")
    assert 1 <= n <= 8, out  # one line, or a handful of workers; never a flood
    assert "Traceback" not in out, out
    return out


@pytest.mark.parametrize("kind,argv,extra_env", [
    ("uvicorn", ["app:app"], None),
    ("uvicorn", ["app:app", "--workers", "2"], None),
    ("uvicorn", ["app:app", "--workers=3"], None),
    ("uvicorn", ["app:app"], {"WEB_CONCURRENCY": "2"}),
    ("uvicorn", ["app:app"], {"UVICORN_WORKERS": "2"}),
    ("uvicorn", ["app:app"], {"UVICORN_RELOAD": "true"}),
    ("uvicorn", ["app:app", "--reload"], None),
    ("uvicorn", ["--factory", "gateway.main:create_app"], None),
    ("uvicorn", ["--factory", "gateway.main:create_app", "--workers", "2"], None),
    ("uvicorn", ["gateway.main:create_app"], {"UVICORN_FACTORY": "true", "WEB_CONCURRENCY": "2"}),
    ("console", ["app:app", "--workers", "2"], None),
    ("uvicorn", ["app:app", "--workers", "1"], {"WEB_CONCURRENCY": "2"}),
    ("uvicorn", ["app:app", "--reload-delay", "1"], None),
    ("uvicorn", ["app:app", "--reload-dir", "."], None),
    ("uvicorn", ["--factory", "gateway.__main__:create_app"], None),
    ("uvicorn", ["--factory", "gateway.__main__:create_app", "--workers", "2"], None),
    ("gunicorn", ["-k", "uvicorn.workers.UvicornWorker", "gateway.__main__:create_app()"], None),
    ("hypercorn", ["gateway.__main__:create_app()"], None),
    ("uvicorn", ["tools.freeze_openapi:app"], None),
    ("py-uvicorn", ["-u", _venv_script("uvicorn"), "app:app", "--workers", "2"], None),
    ("py-uvicorn", ["-X", "dev", "-m", "uvicorn", "app:app", "--workers", "2"], None),
    ("py-uvicorn", ["-I", "-m", "uvicorn", "--app-dir", ROOT, "app:app", "--workers", "2"], None),
    ("py-hypercorn", ["-u", "-m", "hypercorn", "-w", "2", "gateway.__main__:create_app()"], None),
], ids=[
    "app:app",
    "app:app --workers 2",
    "app:app --workers=3",
    "WEB_CONCURRENCY=2 app:app",
    "UVICORN_WORKERS=2",
    "UVICORN_RELOAD=true",
    "--reload",
    "factory",
    "factory --workers 2",
    "UVICORN_FACTORY=true WEB_CONCURRENCY=2",
    "console-script uvicorn --workers 2",
    "WEB_CONCURRENCY=2 --workers 1",
    "--reload-delay 1 without --reload",
    "--reload-dir without --reload",
    "gateway.__main__:create_app --factory",
    "gateway.__main__:create_app --factory --workers 2",
    "gunicorn UvicornWorker gateway.__main__:create_app()",
    "hypercorn gateway.__main__:create_app()",
    "uvicorn tools.freeze_openapi:app",
    "python -u $(which uvicorn) --workers 2",
    "python -X dev -m uvicorn --workers 2",
    "python -I -m uvicorn --workers 2",
    "python -u -m hypercorn -w 2",
])
def test_unsupported_uvicorn_launches_are_refused(kind, argv, extra_env):
    """Every non-launcher start is refused: one sentinel, no argv/env case list in the guard."""
    if kind in ("gunicorn", "hypercorn", "py-hypercorn"):
        pytest.importorskip("gunicorn" if kind == "gunicorn" else "hypercorn")
        exe = _venv_script("gunicorn" if kind == "gunicorn" else "hypercorn")
        if not os.path.exists(exe):
            pytest.skip(f"{exe} is not installed")
    if kind in ("console", "py-uvicorn") and not os.path.exists(_venv_script("uvicorn")):
        pytest.skip("uvicorn console script is not installed")
    _assert_launch_refused(kind, argv, extra_env)


def test_import_app_under_bash_does_not_signal_the_shell():
    """WEB_CONCURRENCY=2 python -c import app must refuse without aborting bash."""
    r = subprocess.run(
        ["bash", "-c", f'{sys.executable} -c "import app"; echo X'],
        cwd=ROOT, env={**ENV, "WEB_CONCURRENCY": "2"},
        capture_output=True, text=True, timeout=8)
    out = r.stderr + r.stdout
    assert "X" in r.stdout.splitlines(), (r.returncode, out)
    assert r.returncode == 0, (r.returncode, out)  # echo X ran; bash was not killed
    assert "start with `python -m gateway`" in out
    assert r.stdout.count("X") == 1


def _assert_wrapper_survives(wrapper_argv, extra_env=None):
    """The wrapper process must print X and exit 0; only the inner uvicorn is refused."""
    r = subprocess.run(wrapper_argv, cwd=ROOT, env={**ENV, **(extra_env or {})},
                       capture_output=True, text=True, timeout=8)
    out = r.stderr + r.stdout
    assert "X" in r.stdout.splitlines(), (r.returncode, out)
    assert r.returncode == 0, (r.returncode, out)
    assert "start with `python -m gateway`" in out
    return out


def test_uvicorn_under_a_shell_wrapper_does_not_kill_the_shell():
    from conftest import free_port
    port = free_port()
    inner = f'{sys.executable} -m uvicorn app:app --host 127.0.0.1 --port {port} --workers 1'
    _assert_wrapper_survives(["bash", "-c", f"{inner}; echo X"], {"WEB_CONCURRENCY": "2"})


def test_uvicorn_under_a_python_wrapper_does_not_kill_the_wrapper():
    from conftest import free_port
    port = free_port()
    script = (
        "import subprocess, sys\n"
        f"subprocess.run({[sys.executable, '-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', str(port), '--reload-delay', '1']!r})\n"
        "print('X')\n"
    )
    _assert_wrapper_survives([sys.executable, "-c", script])


def test_wrap_py_spawn_uvicorn_parent_survives(tmp_path):
    """python wrap.py spawn uvicorn must not get SIGALRM just because argv contains 'uvicorn'."""
    wrap = tmp_path / "wrap.py"
    wrap.write_text(
        "import multiprocessing, os, sys\n"
        "sys.path.insert(0, os.getcwd())\n"
        "def child():\n"
        "    import app\n"
        "if __name__ == '__main__':\n"
        "    p = multiprocessing.get_context('spawn').Process(target=child)\n"
        "    p.start()\n"
        "    p.join()\n"
        "    print('X')\n"
    )
    _assert_wrapper_survives([sys.executable, str(wrap), "spawn", "uvicorn"])


def test_official_launcher_rejects_web_concurrency_without_traceback():
    r = _run_official({**ENV, "WEB_CONCURRENCY": "2"})
    out = r.stderr + r.stdout
    assert r.returncode != 0 and "WEB_CONCURRENCY must be 1" in out and "Traceback" not in out, out


def test_official_launcher_rejects_bad_inflight_without_traceback():
    r = _run_official({**ENV, "GATEWAY_MAX_INFLIGHT_PER_KEY": "abc"})
    out = r.stderr + r.stdout
    assert r.returncode != 0 and "GATEWAY_MAX_INFLIGHT_PER_KEY must be an integer" in out and "Traceback" not in out, out


def test_official_launcher_rejects_bad_create_burst_without_traceback():
    r = _run_official({**ENV, "GATEWAY_CREATE_BURST": "abc"})
    out = r.stderr + r.stdout
    assert r.returncode != 0 and "GATEWAY_CREATE_BURST must be an integer" in out and "Traceback" not in out, out


def test_importing_freeze_openapi_does_not_write_openapi_yaml():
    path = os.path.join(ROOT, "openapi.yaml")
    before = Path(path).read_bytes() if os.path.exists(path) else None
    mtime = os.path.getmtime(path) if os.path.exists(path) else None
    r = subprocess.run(
        [sys.executable, "-c", "import tools.freeze_openapi"],
        cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=15)
    assert r.returncode == 0, r.stderr + r.stdout
    if before is None:
        assert not os.path.exists(path)
    else:
        assert os.path.getmtime(path) == mtime
        assert Path(path).read_bytes() == before


def test_probe_incomplete_drop_does_not_hide_a_main_port_line():
    """A probe swallow is task-local and cannot hide a main-port incomplete-response line."""
    import contextvars
    from gateway.probe import note_incomplete_drop, take_incomplete_drop

    assert take_incomplete_drop() is False
    probe_ctx = contextvars.copy_context()

    def in_probe():
        note_incomplete_drop()
        assert take_incomplete_drop() is True
        assert take_incomplete_drop() is False

    probe_ctx.run(in_probe)
    assert take_incomplete_drop() is False


def test_official_launcher_still_serves(tmp_path):
    p, base, _ = start_gateway(tmp_path, {})
    try:
        assert httpx.get(base + "/.well-known/agent.json", timeout=5).status_code == 200
        assert httpx.get(base + "/", auth=KEY, timeout=5).status_code == 200
    finally:
        p.terminate()
        p.wait(5)

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




def test_a_pipelined_request_with_a_slow_body_is_not_closed_by_the_header_timer(tmp_path):
    """Complete headers of request 2 are already buffered when request 1 finishes; a body trickled past 5s must still get a response."""
    p, base, _ = start_gateway(tmp_path, {
        "GATEWAY_HEADER_TIMEOUT_S": "5",
        "GATEWAY_BODY_READ_TIMEOUT_S": "15",
        "GATEWAY_BODY_IDLE_TIMEOUT_S": "8",
    })
    port = int(base.rsplit(":", 1)[1])
    try:
        body = b'{"jsonrpc":"2.0","id":"1","method":"tasks/get","params":{"id":"x"}}'
        h1 = signed_headers(KEY.key_id, KEY.private_key, "GET", b"/", b"", b"")
        h2 = signed_headers(KEY.key_id, KEY.private_key, "POST", b"/", b"", body)
        req1 = "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in h1.items()) + "\r\n"
        req2_head = (
            f"POST / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            + "".join(f"{k}: {v}\r\n" for k, v in h2.items()) + "\r\n"
        )
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(req1.encode() + req2_head.encode())
        status1, _ = _read_http_response(s, timeout=5)
        assert status1 == 200, status1
        t0 = time.monotonic()
        for i, byte in enumerate(body):
            s.sendall(bytes([byte]))
            if i + 1 < len(body):
                time.sleep(0.15)
        # stretch past the 5s header deadline while staying inside body deadlines
        leftover = 5.5 - (time.monotonic() - t0)
        if leftover > 0:
            time.sleep(leftover)
            s.sendall(b"")  # nothing; body already complete. If we already sent all bytes early, wait then read.
        elapsed = time.monotonic() - t0
        assert elapsed >= 5.2, elapsed
        status2, raw = _read_http_response(s, timeout=8)
        assert status2 in (200, 400), (status2, raw)
        assert not (status2 == 0 and raw == b""), "connection closed instead of a response"
    finally:
        p.terminate(); p.wait(5)


def test_unverified_options_public_paths_and_404_405_are_aggregated_quietly(tmp_path):
    """A-2: 1,000 unauthenticated OPTIONS, public-path, 404 and 405 requests produce only a few aggregated lines."""
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_REFUSAL_LOG_S": "1", "GATEWAY_TELEMETRY_DIR": str(tdir)})
    try:
        for _ in range(1000):
            assert httpx.options(base + "/", timeout=5).status_code == 405
        for _ in range(1000):
            assert httpx.get(base + "/healthz", timeout=5).status_code == 200
        for _ in range(1000):
            assert httpx.get(base + "/no-such-route", auth=KEY, timeout=5).status_code == 404
        for _ in range(1000):
            assert httpx.post(base + "/healthz", timeout=5).status_code == 405
        time.sleep(1.2)
    finally:
        p.terminate(); p.wait(10)
    text = (tmp_path / "gateway.log").read_text()
    public = [ln for ln in text.splitlines() if "public count=" in ln]
    http_refused = [ln for ln in text.splitlines() if "http refused count=" in ln]
    assert public and http_refused, text
    # a handful of aggregated lines, not one per request
    assert len(public) + len(http_refused) < 40, (len(public), len(http_refused))
    # public 200s and a verified caller's 404/405 are not labelled "auth refused"
    auth = [ln for ln in text.splitlines() if "auth refused" in ln]
    assert not any("reasons=public:" in ln or "reasons=not_found:" in ln or "reasons=method_not_allowed:" in ln
                   or "reasons=ok:" in ln for ln in auth), auth
    pub_n = sum(int(ln.split("count=", 1)[1].split()[0]) for ln in public)
    http_n = sum(int(ln.split("count=", 1)[1].split()[0]) for ln in http_refused)
    assert pub_n >= 1000 and http_n >= 2000, (pub_n, http_n, public, http_refused)
    access = [ln for ln in text.splitlines() if "kimiclaw.access" in ln or "uvicorn.access" in ln]
    assert not any(" OPTIONS " in ln or " /healthz " in ln or " /no-such-route " in ln for ln in access), access
    import json
    traces = (tdir / "traces.jsonl").read_text() if (tdir / "traces.jsonl").exists() else ""
    for s in [json.loads(l) for l in traces.splitlines() if l.strip()]:
        attrs = s.get("attributes") or {}
        method = attrs.get("http.request.method") or s.get("name")
        path = attrs.get("url.path") or ""
        status = attrs.get("http.response.status_code")
        assert method != "OPTIONS", s
        assert path not in ("/healthz", "/no-such-route"), s
        assert status not in (404, 405), s


def test_a_60kb_path_produces_a_log_line_under_300_bytes(tmp_path):
    """A-2: a logged path is capped at 128 characters after log_safe, so a 60 kB path cannot bloat the log."""
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_REFUSAL_LOG_S": "0"})
    path = "/p" + "a" * 60_000
    try:
        r = httpx.get(base + path, timeout=10)
        assert r.status_code in (401, 404)
        time.sleep(0.2)
    finally:
        p.terminate(); p.wait(5)
    text = (tmp_path / "gateway.log").read_text()
    # the new refusal line must exist and every log line stays small
    assert "auth refused count=" in text
    long = [ln for ln in text.splitlines() if len(ln.encode()) >= 300]
    assert not long, [(len(ln.encode()), ln[:80]) for ln in long]
    assert path not in text
    assert ("a" * 200) not in text


def test_a_thousand_rate_limit_429s_are_aggregated(tmp_path):
    """A-3: 1,000 429s from a valid key produce aggregated lines, not two lines each."""
    p, base, _ = start_gateway(tmp_path, {
        "GATEWAY_REFUSAL_LOG_S": "1",
        "GATEWAY_REQUESTS_PER_S": "0.0001",
        "GATEWAY_REQUESTS_BURST": "1",
    })
    try:
        codes = []
        for _ in range(1001):
            codes.append(httpx.get(base + "/", auth=KEY, timeout=5).status_code)
        time.sleep(1.2)
    finally:
        p.terminate(); p.wait(5)
    assert codes[0] == 200
    n429 = sum(1 for c in codes if c == 429)
    assert n429 >= 1000, (n429, set(codes))
    text = (tmp_path / "gateway.log").read_text()
    limited = [ln for ln in text.splitlines() if "rate limited count=" in ln]
    assert limited, text
    total = sum(int(ln.split("count=", 1)[1].split()[0]) for ln in limited)
    assert total >= 1000, (total, limited)
    assert len(limited) < 40, limited
    # no per-request rate-limit warning or access line for the 429s
    assert not any("rate limited key_id=" in ln for ln in text.splitlines())
    access = [ln for ln in text.splitlines() if "kimiclaw.access" in ln]
    assert not any(ln.endswith(" 429") or " 429" in ln.split("kimiclaw.access")[-1] for ln in access), access


def test_message_send_without_openclaw_is_a_generic_503(tmp_path):
    """Even with GATEWAY_REQUIRE_OPENCLAW=0, a signed message/send fails closed with a generic 503."""
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_REQUIRE_OPENCLAW": "0", "PATH": "/usr/bin:/bin"})
    try:
        assert httpx.get(_probe(p) + "/readyz", timeout=5).json() == {"status": "ready"}
        body = {"jsonrpc": "2.0", "id": "1", "method": "message/send",
                "params": {"message": {"role": "user", "parts": [{"kind": "text", "text": "hi"}]}}}
        r = httpx.post(base + "/", json=body, auth=KEY, timeout=10)
        text = r.text
        assert r.status_code == 503, (r.status_code, text)
        for needle in ("openclaw", "/", "No such file", "Errno"):
            assert needle not in text, (needle, text)
        log = (tmp_path / "gateway.log").read_text()
        # only generic wording; no binary name, path, or OS error text on the failure line
        fail_lines = [ln for ln in log.splitlines() if "agent unavailable" in ln or "message/send" in ln
                      or "openclaw" in ln.lower() or "No such file" in ln or "Errno" in ln
                      or "FileNotFound" in ln]
        assert any("agent unavailable" in ln for ln in fail_lines), log
        for ln in fail_lines:
            if "GATEWAY_REQUIRE_OPENCLAW=0:" in ln:
                continue  # the documented startup warning is allowed to name openclaw
            assert "No such file" not in ln and "Errno" not in ln and "FileNotFound" not in ln
            # the access/error line for the failed send itself is generic
            if "agent unavailable" in ln:
                assert "openclaw" not in ln.lower() and "No such file" not in ln
    finally:
        p.terminate(); p.wait(5)


def _raw_requests(port, payload, n=1000, workers=32):
    from concurrent.futures import ThreadPoolExecutor

    def one(_):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(payload)
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            data = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            first = data.split(b"\r\n", 1)[0]
            try:
                return int(first.split()[1])
            except (IndexError, ValueError):
                return 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, range(n)))


def _assert_few_protocol_lines(chunk, reason, expected):
    """A-4: raw uvicorn.error templates are gone; at most 5 new lines; counts land in the summary."""
    raw = (
        "Invalid HTTP request received.",
        "Unsupported upgrade request.",
        "No supported WebSocket library detected.",
        "Exceeded concurrency limit.",
    )
    assert not any(s in chunk for s in raw), chunk
    lines = [ln for ln in chunk.splitlines() if ln.strip()]
    assert len(lines) <= 5, (len(lines), lines)
    refused = [ln for ln in lines if "http refused count=" in ln]
    assert refused, chunk
    import re
    total = 0
    for ln in refused:
        m = re.search(rf"\b{reason}:(\d+)", ln)
        if m:
            total += int(m.group(1))
    assert total >= expected, (total, reason, chunk)
    return lines


def test_uvicorn_protocol_warnings_are_aggregated_on_both_ports(tmp_path):
    """A-4: 1,000 malformed, Upgrade, and cap-full 503s on both listeners produce <=5 log lines per kind.

    The probe has no concurrency cap, so cap-full 503s are generated on the main port only;
    malformed and Upgrade are sent to both ports. Startup uvicorn.error lines must remain.
    """
    p, base, _ = start_gateway(tmp_path, {
        "GATEWAY_REFUSAL_LOG_S": "3",
        "KIMICLAW_LIMIT_CONCURRENCY": "64",
        "GATEWAY_HEADER_TIMEOUT_S": "30",
    })
    log = tmp_path / "gateway.log"
    main_port = int(base.rsplit(":", 1)[1])
    probe_port = int(p.probe_base.rsplit(":", 1)[1])
    malformed = b"FOO * BAR\r\n\r\n"
    upgrade = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Connection: upgrade\r\n"
        b"Upgrade: websocket\r\n"
        b"\r\n"
    )
    try:
        text = log.read_text()
        assert "Started server process" in text or "Uvicorn running" in text, text
        # 1. malformed on both ports
        mark = len(text)
        _raw_requests(main_port, malformed, 1000)
        _raw_requests(probe_port, malformed, 1000)
        time.sleep(3.3)
        _assert_few_protocol_lines(log.read_text()[mark:], "malformed", 2000)
        # 2. Upgrade: header on both ports (uvicorn would otherwise write two lines each)
        mark = len(log.read_text())
        _raw_requests(main_port, upgrade, 1000)
        _raw_requests(probe_port, upgrade, 1000)
        time.sleep(3.3)
        _assert_few_protocol_lines(log.read_text()[mark:], "upgrade", 2000)
        # 3. cap-full 503s on the main port (probe is uncapped by design)
        held = []
        try:
            for _ in range(64):
                s = socket.create_connection(("127.0.0.1", main_port), timeout=5)
                s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
                held.append(s)
            mark = len(log.read_text())
            complete = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            codes = _raw_requests(main_port, complete, 1000)
            assert codes.count(503) >= 1000, (codes.count(503), set(codes))
            time.sleep(3.3)
            _assert_few_protocol_lines(log.read_text()[mark:], "concurrency", 1000)
        finally:
            for s in held:
                try:
                    s.close()
                except OSError:
                    pass
    finally:
        p.terminate()
        p.wait(10)


def test_probe_app_never_reads_the_http_body():
    """A-5: the probe callable must not call receive() on HTTP (so a bad body cannot be read)."""
    import asyncio
    from gateway.probe import probe_app

    received = []

    async def receive():
        received.append(True)
        return {"type": "http.request", "body": b"secret", "more_body": False}

    sent = []

    async def send(msg):
        sent.append(msg)

    async def run():
        for path, method in (("/healthz", "GET"), ("/readyz", "GET"), ("/nope", "POST"), ("/", "PUT")):
            await probe_app({"type": "http", "path": path, "method": method}, receive, send)

    asyncio.run(run())
    assert received == []
    assert sent and all(m.get("type", "").startswith("http.response") for m in sent)


def test_a_thousand_bad_chunked_requests_on_each_port_are_quiet(tmp_path):
    """A-5: 1,000 Transfer-Encoding: chunked + ZZZ requests per port produce <=5 new log lines and no traceback."""
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_REFUSAL_LOG_S": "3", "GATEWAY_HEADER_TIMEOUT_S": "30"})
    log = tmp_path / "gateway.log"
    main_port = int(base.rsplit(":", 1)[1])
    probe_port = int(p.probe_base.rsplit(":", 1)[1])
    # any path or method; invalid chunk body after a complete header block
    payloads = [
        b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\n",
        b"POST /readyz HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\n",
        b"GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\n",
        b"PUT / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\n",
    ]
    try:
        mark = len(log.read_text())
        for port in (main_port, probe_port):
            for payload in payloads:
                _raw_requests(port, payload, 250)
        time.sleep(3.3)
        chunk = log.read_text()[mark:]
        assert "Exception in ASGI application" not in chunk, chunk
        assert "Traceback" not in chunk, chunk
        lines = [ln for ln in chunk.splitlines() if ln.strip()]
        assert len(lines) <= 5, (len(lines), lines)
    finally:
        p.terminate()
        p.wait(10)
