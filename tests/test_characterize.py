"""Characterization tests: pin CURRENT behavior of app.py (bugs included)."""
import base64, json, time
import httpx, pytest
from conftest import TOKEN


def rpc(method, params=None, id_="1"):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


def user_msg(text, **kw):
    m = {"role": "user", "messageId": "m1", "parts": [{"kind": "text", "text": text}]}
    m.update(kw); return {"message": m}


# ---------- auth / public routes ----------

def test_agent_card_public(gw_factory):
    c = gw_factory()
    r = httpx.get(str(c.base_url) + "/.well-known/agent.json")
    assert r.status_code == 200
    card = r.json()
    assert card["name"] == "Kimiclaw" and card["url"] == "https://kimiclaw.hoyack.ai/"
    assert card["capabilities"] == {"streaming": True, "pushNotifications": False, "stateTransitionHistory": False}
    assert card["securitySchemes"] == {"bearerAuth": {"type": "http", "scheme": "bearer"}}


@pytest.mark.parametrize("hdr", [None, "Bearer wrong", TOKEN, f"bearer {TOKEN}"])
def test_unauthorized(gw_factory, hdr):
    c = gw_factory()
    h = {"Authorization": hdr} if hdr else {}
    for m, p in (("GET", "/"), ("POST", "/"), ("GET", "/docs"), ("GET", "/nope"),
                 ("GET", "/readyz"), ("GET", "/openapi.json")):
        r = httpx.request(m, str(c.base_url) + p, headers=h)
        assert (r.status_code, r.json()) == (401, {"error": "unauthorized"})


def test_root_get(gw_factory):
    r = gw_factory().get("/")
    assert r.json() == {"service": "kimiclaw-a2a-gateway", "protocol": "A2A 1.0",
                        "agent_card": "/.well-known/agent.json", "rpc": "POST / (JSON-RPC 2.0)"}


def test_fastapi_docs_exist_behind_auth(gw_factory):
    c = gw_factory()
    assert c.get("/docs").status_code == 200
    assert c.get("/openapi.json").status_code == 200


# ---------- JSON-RPC errors ----------

def test_parse_error(gw_factory):
    r = gw_factory().post("/", content=b"{bad", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert r.json() == {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}


def test_unknown_method(gw_factory):
    r = gw_factory().post("/", json=rpc("foo/bar", id_=7))
    assert r.status_code == 200
    assert r.json() == {"jsonrpc": "2.0", "id": 7, "error": {"code": -32601, "message": "method not found: foo/bar"}}


def test_non_object_body_is_500(gw_factory):
    # body.get on a list -> unhandled AttributeError -> 500 plain text
    r = gw_factory().post("/", json=[1, 2])
    assert r.status_code == 500


@pytest.mark.parametrize("params,msg", [
    ({"message": {"role": "agent", "parts": [{"kind": "text", "text": "x"}]}}, "only user-role messages accepted"),
    ({"message": {"role": "user", "parts": []}}, "empty message"),
    ({}, "empty message"),
    ({"message": {"parts": [{"kind": "text", "text": "x" * 200_001}]}}, "message too large"),
])
def test_validation_errors(gw_factory, params, msg):
    r = gw_factory().post("/", json=rpc("message/send", params))
    assert r.status_code == 200
    assert r.json() == {"jsonrpc": "2.0", "id": "1", "error": {"code": -32602, "message": msg}}


# ---------- message/send ----------

def test_send_blocking_roundtrip_and_openclaw_argv(gw_factory):
    c = gw_factory()
    r = c.post("/", json=rpc("message/send", user_msg("hello", contextId="ctx/1 x", taskId="t1")))
    body = r.json()
    assert body["jsonrpc"] == "2.0" and body["id"] == "1"
    t = body["result"]
    assert t["id"] == "t1" and t["contextId"] == "ctx/1 x" and t["kind"] == "task" and t["final"] is True
    assert t["status"]["state"] == "completed"
    assert t["status"]["message"]["role"] == "agent"
    assert t["status"]["message"]["parts"] == [{"kind": "text", "text": "echo: hello"}]
    assert t["history"] == [t["status"]["message"]]
    assert len(t["artifacts"]) == 1
    a = t["artifacts"][0]
    assert a["name"] == "reply" and a["index"] == 0 and a["parts"] == [{"kind": "text", "text": "echo: hello"}]
    argv = json.loads(c.argv_file.read_text().splitlines()[0])
    assert argv == ["agent", "--local", "--session-id", "a2a-ctx-1-x", "--message", "hello", "--json", "--timeout", "560"]


def test_extract_text_part_kinds(gw_factory):
    c = gw_factory()
    parts = [{"kind": "text", "text": "a"}, {"kind": "data", "data": {"k": 1}},
             {"kind": "file", "file": {"name": "f.txt"}}, {"kind": "file"}, {"kind": "weird"}]
    c.post("/", json=rpc("message/send", {"message": {"parts": parts}}))
    argv = json.loads(c.argv_file.read_text().splitlines()[0])
    assert argv[5] == 'a\n{"k": 1}\n[file: f.txt]\n[file: ?]'


def test_send_failure(gw_factory):
    t = gw_factory().post("/", json=rpc("message/send", user_msg("FAIL"))).json()["result"]
    assert t["status"]["state"] == "failed"
    assert t["status"]["message"]["parts"][0]["text"] == "agent error: agent exited 3: boom\n"
    assert t["artifacts"] == []


@pytest.mark.parametrize("how", ["query", "config"])
def test_send_nonblocking_then_get(gw_factory, how):
    c = gw_factory()
    params = user_msg("SLOW")
    url = "/"
    if how == "query":
        url = "/?wait=false"
    else:
        params["configuration"] = {"blocking": False}
    t = c.post(url, json=rpc("message/send", params)).json()["result"]
    assert t["status"]["state"] == "submitted" and t["final"] is False
    for _ in range(100):
        g = c.post("/", json=rpc("tasks/get", {"id": t["id"]})).json()["result"]
        if g["final"]: break
        time.sleep(0.1)
    assert g["status"]["state"] == "completed"
    # taskId alias also works
    assert c.post("/", json=rpc("tasks/get", {"taskId": t["id"]})).json()["result"]["id"] == t["id"]


def test_tasks_get_cancel_not_found(gw_factory):
    c = gw_factory()
    for m in ("tasks/get", "tasks/cancel"):
        assert c.post("/", json=rpc(m, {"id": "nope"})).json() == \
            {"jsonrpc": "2.0", "id": "1", "error": {"code": -32001, "message": "task not found"}}


def test_cancel_is_overwritten_by_completion(gw_factory):
    """Current behavior: cancel marks canceled but does not kill openclaw; completion later overwrites it."""
    c = gw_factory()
    t = c.post("/?wait=false", json=rpc("message/send", user_msg("SLOW"))).json()["result"]
    x = c.post("/", json=rpc("tasks/cancel", {"id": t["id"]})).json()["result"]
    assert x["status"]["state"] == "canceled" and x["final"] is True
    time.sleep(3)
    g = c.post("/", json=rpc("tasks/get", {"id": t["id"]})).json()["result"]
    assert g["status"]["state"] == "completed"


# ---------- message/stream ----------

def test_stream_events(gw_factory):
    c = gw_factory()
    with c.stream("POST", "/", json=rpc("message/stream", user_msg("hi", taskId="s1", contextId="c1"), id_=9)) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        assert r.headers["cache-control"] == "no-cache"
        raw = r.read().decode()
    evs = [json.loads(l[6:]) for l in raw.split("\n\n") if l.startswith("data: ")]
    assert all(e["jsonrpc"] == "2.0" and e["id"] == 9 for e in evs)
    kinds = [(e["result"]["kind"], e["result"]["final"]) for e in evs]
    assert kinds == [("status-update", False), ("artifact-update", False), ("status-update", True)]
    assert evs[0]["result"]["status"]["state"] == "working"
    assert evs[1]["result"]["artifact"]["parts"] == [{"kind": "text", "text": "echo: hi"}]
    assert evs[2]["result"]["status"]["state"] == "completed"


def test_stream_validation_error_is_json(gw_factory):
    r = gw_factory().post("/", json=rpc("message/stream", {}))
    assert r.headers["content-type"] == "application/json"
    assert r.json()["error"]["code"] == -32602


# ---------- outbound notify (n8n firewall webhook) ----------

def _notify_env(mock, **kw):
    env = {"GATEWAY_NOTIFY_URL": f"http://127.0.0.1:{mock.port}/webhook/firewall"}
    env.update(kw); return env


def test_no_outbound_when_unset(gw_factory, mock):
    gw_factory().post("/", json=rpc("message/send", user_msg("hello")))
    time.sleep(0.5)
    assert mock.requests == []


def test_notify_completed_exact_request(gw_factory, mock):
    c = gw_factory(**_notify_env(mock))
    c.post("/", json=rpc("message/send", user_msg("hello", taskId="t9", contextId="c9")))
    reqs = mock.wait(1); time.sleep(0.3)
    assert len(mock.requests) == 1  # task_started excluded by default
    q = reqs[0]
    assert q["path"] == "/webhook/firewall"
    h = {k.lower(): v for k, v in q["headers"].items()}
    assert h["content-type"] == "application/json"
    assert h["authorization"] == TOKEN  # raw mode: no scheme prefix
    assert h["user-agent"].startswith("Python-urllib/")
    assert h["content-length"] == str(len(q["body"]))
    body = json.loads(q["body"])
    assert list(body) == ["event", "source", "taskId", "contextId", "timestamp", "state", "reply", "durationMs"]
    assert body["event"] == "task_completed" and body["source"] == "kimiclaw-a2a-gateway"
    assert body["taskId"] == "t9" and body["contextId"] == "c9"
    assert body["state"] == "completed" and body["reply"] == "echo: hello"
    assert isinstance(body["durationMs"], int) and body["timestamp"].endswith("+00:00")
    # serialization: json.dumps default separators (", " and ": ")
    assert q["body"].startswith(b'{"event": "task_completed", "source": ')


def test_notify_failed_and_reply_truncated(gw_factory, mock):
    c = gw_factory(**_notify_env(mock))
    c.post("/", json=rpc("message/send", user_msg("FAIL " + "z" * 5000)))
    body = json.loads(mock.wait(1)[0]["body"])
    assert body["event"] == "task_failed" and body["state"] == "failed"
    assert body["reply"].startswith("agent error: agent exited 3")


@pytest.mark.parametrize("mode,expect", [
    ("bearer", f"Bearer {TOKEN}"),
    ("basic", "Basic " + base64.b64encode(f"agent:{TOKEN}".encode()).decode()),
    ("BASIC", "Basic " + base64.b64encode(f"agent:{TOKEN}".encode()).decode()),
    ("whatever", TOKEN),
])
def test_notify_auth_modes(gw_factory, mock, mode, expect):
    c = gw_factory(**_notify_env(mock, GATEWAY_NOTIFY_AUTH_MODE=mode))
    c.post("/", json=rpc("message/send", user_msg("hi")))
    h = {k.lower(): v for k, v in mock.wait(1)[0]["headers"].items()}
    assert h["authorization"] == expect


def test_notify_basic_custom_user(gw_factory, mock):
    c = gw_factory(**_notify_env(mock, GATEWAY_NOTIFY_AUTH_MODE="basic", GATEWAY_NOTIFY_AUTH_USER="n8n"))
    c.post("/", json=rpc("message/send", user_msg("hi")))
    h = {k.lower(): v for k, v in mock.wait(1)[0]["headers"].items()}
    assert h["authorization"] == "Basic " + base64.b64encode(f"n8n:{TOKEN}".encode()).decode()


def test_notify_started_event_when_enabled(gw_factory, mock):
    c = gw_factory(**_notify_env(mock, GATEWAY_NOTIFY_EVENTS="task_started, task_completed"))
    c.post("/", json=rpc("message/send", user_msg("hi", taskId="a", contextId="b")))
    reqs = mock.wait(2)
    b0, b1 = json.loads(reqs[0]["body"]), json.loads(reqs[1]["body"])
    assert b0 == {"event": "task_started", "source": "kimiclaw-a2a-gateway", "taskId": "a",
                  "contextId": "b", "timestamp": b0["timestamp"]}
    assert b1["event"] == "task_completed"


def test_notify_circuit_breaker(gw_factory):
    # unreachable port -> failures; limit 2 -> breaker opens and logs
    c = gw_factory(GATEWAY_NOTIFY_URL="http://127.0.0.1:9/x", GATEWAY_NOTIFY_FAIL_LIMIT="2")
    for _ in range(3):
        assert c.post("/", json=rpc("message/send", user_msg("hi"))).json()["result"]["status"]["state"] == "completed"
    time.sleep(0.5)
    log = c.log_file.read_text()
    assert "failed (1/2)" in log and "failed (2/2)" in log
    assert "notify circuit breaker OPEN: outbound webhooks paused 900s" in log
    assert log.count("notify task_completed") == 2  # third call suppressed by breaker
