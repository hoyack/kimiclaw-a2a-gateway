"""Contract: the spec served at /openapi.json equals the frozen openapi.yaml; new probes behave."""
import os
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_served_spec_matches_frozen_yaml(gw_factory):
    served = gw_factory().get("/openapi.json").json()
    with open(os.path.join(ROOT, "openapi.yaml")) as f:
        assert served == yaml.safe_load(f)


def test_docs_still_served(gw_factory):
    assert "swagger" in gw_factory().get("/docs").text.lower()


def test_healthz_readyz(gw_factory):
    c = gw_factory()
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/readyz").json() == {"status": "ready"}  # fake openclaw is on PATH


def test_healthz_public_minimal_readyz_protected(gw_factory):
    import httpx
    base = str(gw_factory().base_url)
    for h in ({}, {"Authorization": "Bearer wrong"}):
        r = httpx.get(base + "/healthz", headers=h)
        assert (r.status_code, r.json()) == (200, {"status": "ok"})
        r = httpx.get(base + "/readyz", headers=h)
        assert (r.status_code, r.json()) == (401, {"error": "unauthorized"})
    for m in ("POST", "PUT", "DELETE"):  # only GET /healthz exists; other methods are not a back door
        assert httpx.request(m, base + "/healthz").status_code == 405
    for p in ("/healthz/", "/healthz/x", "/openapi.json", "/redoc"):
        r = httpx.get(base + p)
        assert (r.status_code, r.json()) == (401, {"error": "unauthorized"})


def test_readyz_without_openclaw(gw_factory):
    c = gw_factory(PATH="/usr/bin:/bin")
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json()["status"] == "not ready"


def test_telemetry_files_written_without_message_text(gw_factory, tmp_path):
    tdir = tmp_path / "telemetry"
    c = gw_factory(GATEWAY_TELEMETRY_DIR=str(tdir))
    c.post("/", json={"jsonrpc": "2.0", "id": "1", "method": "message/send",
                      "params": {"message": {"parts": [{"kind": "text", "text": "SECRET-TEXT-42"}], "taskId": "tt"}}})
    logs = (tdir / "logs.jsonl").read_text()
    assert '"task_id": "tt"' in logs and '"status": 200' in logs and '"rpc_method": "message/send"' in logs
    assert "SECRET-TEXT-42" not in logs and "echo:" not in logs


def test_traces_and_metrics_files(tmp_path):
    import httpx
    from conftest import start_gateway, TOKEN
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir)})
    httpx.get(base + "/", headers={"Authorization": f"Bearer {TOKEN}"})
    p.terminate(); p.wait(10)
    traces = (tdir / "traces.jsonl").read_text()
    assert '"name": "rpc"' in traces
    assert "gateway.requests" in (tdir / "metrics.jsonl").read_text()


def _read_spans(tdir):
    import json
    return [json.loads(l) for l in (tdir / "traces.jsonl").read_text().splitlines() if l.strip()]


def _rpc(text, task_id, method="message/send"):
    return {"jsonrpc": "2.0", "id": "1", "method": method,
            "params": {"message": {"parts": [{"kind": "text", "text": text}], "taskId": task_id}}}


def test_rpc_agent_notify_spans_share_one_trace(tmp_path, mock):
    import httpx
    from conftest import start_gateway, TOKEN
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir),
                                          "GATEWAY_NOTIFY_URL": f"http://127.0.0.1:{mock.port}/hook"})
    httpx.post(base + "/", json=_rpc("hi", "tr1"), headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30)
    mock.wait(1)
    p.terminate(); p.wait(10)
    spans = _read_spans(tdir)
    by_name = {}
    for s in spans:
        by_name.setdefault(s["name"], []).append(s["context"]["trace_id"])
    notify_trace = by_name["notify"][0]
    agent_trace = by_name["agent.run"][0]
    assert notify_trace == agent_trace and notify_trace in by_name["rpc"]


def test_no_message_text_in_logs_or_traces_including_agent_error(tmp_path):
    import httpx
    from conftest import start_gateway, TOKEN
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir)})
    h = {"Authorization": f"Bearer {TOKEN}"}
    ok = httpx.post(base + "/", json=_rpc("SECRET-OK-77", "ok1"), headers=h, timeout=30).json()
    bad = httpx.post(base + "/", json=_rpc("SECRET-FAIL-88 FAIL", "bad1"), headers=h, timeout=30).json()
    assert ok["result"]["status"]["state"] == "completed" and bad["result"]["status"]["state"] == "failed"
    p.terminate(); p.wait(10)
    for name in ("logs.jsonl", "traces.jsonl"):
        text = (tdir / name).read_text()
        assert ("bad1" in text) if name == "logs.jsonl" else (text.count('"name": "agent.run"') == 2), name
        for needle in ("SECRET-OK-77", "SECRET-FAIL-88", "echo:", "boom"):
            assert needle not in text, (name, needle)


def test_stream_span_and_duration_close_at_stream_end(tmp_path):
    import httpx, json
    from conftest import start_gateway, TOKEN
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir)})
    with httpx.stream("POST", base + "/", json=_rpc("SLOW", "st1", "message/stream"),
                      headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30) as r:
        body = "".join(r.iter_text())
    assert '"completed"' in body
    p.terminate(); p.wait(10)
    rpc = [s for s in _read_spans(tdir) if s["name"] == "rpc" and s["attributes"].get("http.request.method") == "POST"]
    assert len(rpc) == 1
    from datetime import datetime
    dur = (datetime.fromisoformat(rpc[0]["end_time"].replace("Z", "+00:00"))
           - datetime.fromisoformat(rpc[0]["start_time"].replace("Z", "+00:00"))).total_seconds()
    assert dur >= 1.9  # fake agent sleeps 2 s for SLOW; span must cover the whole stream
    logs = [json.loads(l) for l in (tdir / "logs.jsonl").read_text().splitlines()]
    req = [l for l in logs if l["event"] == "http_request" and l["method"] == "POST"]
    assert req and req[0]["duration_ms"] >= 1900


def test_setup_is_idempotent(tmp_path, monkeypatch):
    import importlib, logging
    monkeypatch.setenv("GATEWAY_TELEMETRY_DIR", str(tmp_path / "t"))
    from gateway import telemetry
    telemetry = importlib.reload(telemetry)
    telemetry.setup()
    n_handlers = len(telemetry.EVENTS.handlers)
    from opentelemetry import trace
    tp = trace.get_tracer_provider()
    telemetry.setup(); telemetry.setup()
    assert len(telemetry.EVENTS.handlers) == n_handlers == 1
    assert trace.get_tracer_provider() is tp
    h = telemetry.EVENTS.handlers[0]
    assert isinstance(h, logging.handlers.TimedRotatingFileHandler) and h.backupCount == 7 and h.when == "MIDNIGHT"


def _boot_fails(tmp_path, token_env):
    import os, subprocess, sys, shutil
    app = tmp_path / "app"
    shutil.copytree(ROOT, app, ignore=shutil.ignore_patterns(".venv", ".git", ".env", "telemetry", "__pycache__"))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_"))}
    env.update(token_env)
    r = subprocess.run([sys.executable, "-c", "import app"], cwd=app, env=env, capture_output=True, text=True, timeout=60)
    return r


def test_missing_token_and_no_dotenv_fails_clearly(tmp_path):
    r = _boot_fails(tmp_path, {})
    assert r.returncode != 0 and "KIMICLAW_TOKEN not set" in r.stderr and "FileNotFoundError" not in r.stderr


def test_empty_token_refused(tmp_path):
    r = _boot_fails(tmp_path, {"KIMICLAW_TOKEN": "   "})
    assert r.returncode != 0 and "KIMICLAW_TOKEN not set" in r.stderr


def test_otlp_endpoint_replaces_files_and_warns_on_plaintext(tmp_path):
    from conftest import start_gateway
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir),
                                          "OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel.invalid:4318"})
    import httpx
    assert httpx.get(base + "/healthz").status_code == 200
    p.kill(); p.wait(10)
    assert not tdir.exists() or not any(tdir.iterdir())
    assert "telemetry is sent unencrypted" in (tmp_path / "gateway.log").read_text()


def test_agent_error_stderr_and_traceback_not_in_stdout_or_logs(tmp_path):
    import httpx
    from conftest import start_gateway, TOKEN
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir)})
    h = {"Authorization": f"Bearer {TOKEN}"}
    bad = httpx.post(base + "/", json=_rpc("PROMPT-ECHO-99 FAIL", "bad2"), headers=h, timeout=30).json()
    assert bad["result"]["status"]["state"] == "failed"
    p.terminate(); p.wait(10)
    out = (tmp_path / "gateway.log").read_text()
    assert "agent run failed task=" in out and "error_type=" in out
    for text in (out, (tdir / "logs.jsonl").read_text()):
        for needle in ("boom", "PROMPT-ECHO-99", "Traceback"):
            assert needle not in text, needle


def _run_success(tmp_path, env):
    import httpx
    from conftest import start_gateway, TOKEN
    tdir = tmp_path / "tel"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir), **env})
    h = {"Authorization": f"Bearer {TOKEN}"}
    r = httpx.post(base + "/", json=_rpc("PROMPT-OK-77 hello", "ok77"), headers=h, timeout=30).json()
    assert r["result"]["status"]["state"] != "failed"
    p.terminate(); p.wait(10)
    return (tmp_path / "gateway.log").read_text(), (tdir / "logs.jsonl").read_text()


def test_success_prompt_not_in_stdout_or_logs_by_default(tmp_path):
    out, logs = _run_success(tmp_path, {})
    assert "inbound task_id=" in out and "len=18" in out
    for text in (out, logs):
        assert "PROMPT-OK-77" not in text


def test_success_prompt_never_logged_even_with_legacy_payload_flag(tmp_path):
    # F26: GATEWAY_LOG_PAYLOADS was removed; setting it must not log bodies.
    out, logs = _run_success(tmp_path, {"GATEWAY_LOG_PAYLOADS": "1"})
    assert "inbound task_id=" in out and "len=18" in out
    for text in (out, logs):
        assert "PROMPT-OK-77" not in text


def test_notify_failure_logs_type_and_host_only(tmp_path):
    import httpx
    from conftest import start_gateway, TOKEN
    tdir = tmp_path / "tel"
    url = "http://127.0.0.1:9/SECRET-HOOK-PATH/abc123?k=SECRETQ"
    p, base, _ = start_gateway(tmp_path, {"GATEWAY_TELEMETRY_DIR": str(tdir), "GATEWAY_NOTIFY_URL": url})
    h = {"Authorization": f"Bearer {TOKEN}"}
    r = httpx.post(base + "/", json=_rpc("hello notify", "n1"), headers=h, timeout=30).json()
    assert r["result"]["status"]["state"] == "completed"
    import time
    for _ in range(50):
        if "failed (" in (tmp_path / "gateway.log").read_text():
            break
        time.sleep(0.1)
    p.terminate(); p.wait(10)
    out = (tmp_path / "gateway.log").read_text()
    assert "host=127.0.0.1" in out and "error_type=" in out
    for text in (out, (tdir / "logs.jsonl").read_text()):
        for needle in ("SECRET-HOOK-PATH", "abc123", "SECRETQ", "Traceback"):
            assert needle not in text, needle


def test_sse_error_logs_type_only_no_traceback(caplog, monkeypatch, tmp_path):
    import asyncio, logging
    from conftest import TOKEN
    monkeypatch.setenv("KIMICLAW_TOKEN", TOKEN)
    monkeypatch.setenv("GATEWAY_TELEMETRY_DIR", str(tmp_path / "tel"))
    from gateway.controllers.rpc import sse_events

    class BadQueue:
        async def get(self):
            raise RuntimeError("SECRET-SSE-DETAIL http://x/SECRET-PATH")

    async def collect():
        return [c async for c in sse_events("s1", BadQueue())]

    with caplog.at_level(logging.DEBUG, logger="kimiclaw"):
        chunks = asyncio.run(collect())
    assert len(chunks) == 1 and "stream error: SECRET-SSE-DETAIL" in chunks[0]  # wire unchanged
    recs = [r for r in caplog.records if r.name == "kimiclaw"]
    assert any("error_type=RuntimeError" in r.getMessage() for r in recs)
    for r in recs:
        assert r.exc_info is None
        assert "SECRET" not in r.getMessage()
