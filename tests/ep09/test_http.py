"""HTTP adapters against local fake servers (fake Jira REST and fake A2A gateway)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from routing.gateway import Gateway
from routing.jira import Jira, adf_text
from routing.router import HandoffError, poll_once


def serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def fake_gateway(final_state="completed", rpc_error=False):
    seen = []
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append({"auth": self.headers.get("Authorization"), "body": body})
            if rpc_error:
                res = {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "boom"}}
            elif body["method"] == "message/send":
                m = body["params"]["message"]
                res = {"jsonrpc": "2.0", "id": body["id"], "result": {"id": m["taskId"], "contextId": m["contextId"], "final": False, "status": {"state": "submitted"}}}
            else:
                done = sum(s["body"]["method"] == "tasks/get" for s in seen) >= 2
                task = {"id": body["params"]["id"], "final": done, "status": {"state": final_state if done else "working"},
                        "artifacts": [{"parts": [{"kind": "text", "text": "the answer"}]}] if done and final_state == "completed" else []}
                res = {"jsonrpc": "2.0", "id": body["id"], "result": task}
            out = json.dumps(res).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    srv, url = serve(H)
    return srv, url, seen


def test_gateway_sends_issue_key_as_task_and_context_id():
    srv, url, seen = fake_gateway()
    assert Gateway(url, "tok", poll_every=0).run("A2A-7", "hello") == "the answer"
    send = seen[0]["body"]
    assert seen[0]["auth"] == "Bearer tok"
    assert send["method"] == "message/send"
    assert send["params"]["configuration"] == {"blocking": False}
    m = send["params"]["message"]
    assert (m["taskId"], m["contextId"], m["messageId"]) == ("A2A-7", "A2A-7", "A2A-7")
    assert m["parts"] == [{"kind": "text", "text": "hello"}]
    assert [s["body"]["method"] for s in seen[1:]] == ["tasks/get", "tasks/get"]
    srv.shutdown()


def test_gateway_failed_state_and_rpc_error():
    srv, url, _ = fake_gateway(final_state="failed")
    with pytest.raises(HandoffError) as e:
        Gateway(url, "tok", poll_every=0).run("A2A-7", "x")
    assert e.value.kind == "agent_failed" and not e.value.retryable
    srv.shutdown()
    srv, url, _ = fake_gateway(rpc_error=True)
    with pytest.raises(HandoffError) as e:
        Gateway(url, "tok", poll_every=0).run("A2A-7", "x")
    assert e.value.kind == "rpc_error_-32000"
    srv.shutdown()


def test_gateway_timeout():
    srv, url, _ = fake_gateway()
    with pytest.raises(HandoffError) as e:
        Gateway(url, "tok", poll_every=0, max_polls=1).run("A2A-7", "x")
    assert e.value.kind == "gateway_timeout"
    srv.shutdown()


class JiraState:
    def __init__(self):
        self.status, self.comments, self.reqs = "To Do", [], []


def fake_jira(st):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, obj, code=200):
            out = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
        def do_GET(self):
            st.reqs.append(("GET", self.path, self.headers.get("Authorization")))
            if self.path.startswith("/rest/api/3/search/jql"):
                issues = [] if st.status != "To Do" else [{"key": "A2A-9", "fields": {
                    "summary": "Fix it", "labels": ["owner_rivet"], "status": {"name": st.status},
                    "description": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "body"}]}]}}}]
                return self._send({"issues": issues, "isLast": True})
            if self.path.endswith("/transitions"):
                return self._send({"transitions": [{"id": "11", "to": {"name": "To Do"}}, {"id": "21", "to": {"name": "In Progress"}}]})
            if "/comment" in self.path:
                return self._send({"comments": [{"body": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": c}]}]}} for c in st.comments], "total": len(st.comments)})
            return self._send({"fields": {"status": {"name": st.status}}})
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            st.reqs.append(("POST", self.path, body))
            if self.path.endswith("/transitions"):
                st.status = {"11": "To Do", "21": "In Progress"}[body["transition"]["id"]]
                self.send_response(204); self.end_headers(); return
            st.comments.append(adf_text(body["body"]))
            return self._send({"id": "1"}, 201)
    return serve(H)


def test_jira_adapter_end_to_end_with_fake_gateway_double_poll():
    st = JiraState()
    jsrv, jurl = fake_jira(st)
    gsrv, gurl, seen = fake_gateway()
    jira, gw = Jira(jurl, "bot@example.com", "jtok"), Gateway(gurl, "gtok", poll_every=0)
    poll_once("rivet", jira, gw, sleep=lambda s: None)
    poll_once("rivet", jira, gw, sleep=lambda s: None)
    assert sum(s["body"]["method"] == "message/send" for s in seen) == 1
    assert st.comments == ["[rivet] picked up", "[rivet] result\n\nthe answer"]
    assert st.status == "In Progress"
    assert all(r[2].startswith("Basic ") for r in st.reqs if r[0] == "GET")
    jsrv.shutdown(); gsrv.shutdown()


def test_adf_round_trip_keeps_lines():
    from routing.jira import adf_doc
    assert adf_text(adf_doc("[rivet] result\n\na\nb")) == "[rivet] result\n\na\nb"
