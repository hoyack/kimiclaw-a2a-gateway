#!/usr/bin/env python3
"""Golden fixtures for the Kimiclaw A2A gateway.

record:  python golden.py record --app-dir DIR      (starts DIR's app.py with stubs, writes cases/*.json)
replay:  python golden.py replay --base-url URL --n8n-port PORT [--profile default|n8n_basic]
   n8n_basic profile: target also needs GATEWAY_NOTIFY_AUTH_MODE=basic GATEWAY_NOTIFY_AUTH_USER=n8n-dummy-user.
   Target must run with: KIMICLAW_TOKEN=dummy-test-token, fakebin/ first on PATH,
   FAKE_OPENCLAW_RECORD=<any file>, GATEWAY_NOTIFY_URL=http://127.0.0.1:PORT/webhook/firewall.
replay-local: python golden.py replay-local --app-dir DIR   (starts DIR's app with stubs, then replays)
Normalized: timestamps, UUIDs, durationMs, Content-Length/Date/server headers.
"""
import argparse, json, os, re, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
TOKEN = "dummy-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?\+00:00")
KEEP_HDR = {"content-type", "cache-control", "authorization", "user-agent"}


def norm(o):
    if isinstance(o, dict):
        return {k: ("<int>" if k == "durationMs" and isinstance(v, int) else norm(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [norm(x) for x in o]
    if isinstance(o, str):
        return TS.sub("<ts>", UUID.sub("<uuid>", o))
    return o


def body_of(raw, ctype):
    if ctype.startswith("text/event-stream"):
        return {"sse_frames": [norm(json.loads(f[6:])) if f.startswith("data: ") else f
                               for f in raw.split("\n\n") if f]}
    try:
        return {"json": norm(json.loads(raw)), "raw_key_order": list(json.loads(raw)) if raw.startswith("{") else None}
    except Exception:
        return {"text": raw}


class N8n:
    def __init__(self, port=0):
        self.reqs = []; me = self
        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                b = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                me.reqs.append({"method": "POST", "path": self.path,
                                "headers": {k.lower(): norm(v) for k, v in self.headers.items() if k.lower() in KEEP_HDR},
                                "header_names": sorted(k.lower() for k in self.headers),
                                "json": norm(json.loads(b)), "key_order": list(json.loads(b)),
                                "default_separators": b.startswith(b'{"event": ')})
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            def log_message(self, *a): pass
        self.srv = HTTPServer(("127.0.0.1", port), H); self.port = self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


def rpc(method, params, id_="1"):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params}


def msg(text, **kw):
    m = {"role": "user", "messageId": "m1", "parts": [{"kind": "text", "text": text}]}; m.update(kw); return {"message": m}


# Each case: list of steps. A step = request; "n8n": expected outbound count after the steps.
CASE_DEFS = {
    "get_root": [{"m": "GET", "p": "/"}],
    "get_root_unauth": [{"m": "GET", "p": "/", "auth": None}],
    "get_root_wrong_scheme": [{"m": "GET", "p": "/", "auth": {"Authorization": TOKEN}}],
    "get_agent_card": [{"m": "GET", "p": "/.well-known/agent.json", "auth": None}],
    "post_parse_error": [{"m": "POST", "p": "/", "raw": "{bad"}],
    "post_unknown_method": [{"m": "POST", "p": "/", "json": rpc("foo/bar", {}, 7)}],
    "post_unauth": [{"m": "POST", "p": "/", "auth": None, "json": rpc("tasks/get", {"id": "x"})}],
    "send_agent_role": [{"m": "POST", "p": "/", "json": rpc("message/send", {"message": {"role": "agent", "parts": [{"kind": "text", "text": "x"}]}})}],
    "send_empty": [{"m": "POST", "p": "/", "json": rpc("message/send", {})}],
    "send_too_large": [{"m": "POST", "p": "/", "json": rpc("message/send", msg("x" * 200_001))}],
    "send_blocking_completed": [{"m": "POST", "p": "/", "json": rpc("message/send", msg("hello", taskId="t-ok", contextId="ctx/1 x"))}],
    "send_mixed_parts": [{"m": "POST", "p": "/", "json": rpc("message/send", {"message": {"parts": [
        {"kind": "text", "text": "a"}, {"kind": "data", "data": {"k": 1}}, {"kind": "file", "file": {"name": "f.txt"}}, {"kind": "file"}]}})}],
    "send_blocking_failed": [{"m": "POST", "p": "/", "json": rpc("message/send", msg("FAIL", taskId="t-fail", contextId="c-fail"))}],
    "send_nonblocking_query_then_get": [
        {"m": "POST", "p": "/?wait=false", "json": rpc("message/send", msg("SLOW", taskId="t-nb", contextId="c-nb"))},
        {"sleep": 3.5},
        {"m": "POST", "p": "/", "json": rpc("tasks/get", {"id": "t-nb"})}],
    "send_nonblocking_config": [{"m": "POST", "p": "/", "json": rpc("message/send", {**msg("SLOW", taskId="t-nb2"), "configuration": {"blocking": False}})}, {"sleep": 3.5}],
    "stream_completed": [{"m": "POST", "p": "/", "json": rpc("message/stream", msg("hi", taskId="t-s", contextId="c-s"), 9)}],
    "stream_failed": [{"m": "POST", "p": "/", "json": rpc("message/stream", msg("FAIL", taskId="t-sf", contextId="c-sf"), 10)}],
    "stream_validation_error": [{"m": "POST", "p": "/", "json": rpc("message/stream", {})}],
    "tasks_get_taskid_alias": [
        {"m": "POST", "p": "/", "json": rpc("message/send", msg("hello", taskId="t-g"))},
        {"m": "POST", "p": "/", "json": rpc("tasks/get", {"taskId": "t-g"})}],
    "tasks_get_not_found": [{"m": "POST", "p": "/", "json": rpc("tasks/get", {"id": "nope"})}],
    "tasks_cancel_not_found": [{"m": "POST", "p": "/", "json": rpc("tasks/cancel", {"id": "nope"})}],
    "tasks_cancel_then_overwritten_by_completion": [
        {"m": "POST", "p": "/?wait=false", "json": rpc("message/send", msg("SLOW", taskId="t-c", contextId="c-c"))},
        {"m": "POST", "p": "/", "json": rpc("tasks/cancel", {"id": "t-c"})},
        {"sleep": 3.5},
        {"m": "POST", "p": "/", "json": rpc("tasks/get", {"id": "t-c"})}],
    "tasks_cancel_completed_task": [
        {"m": "POST", "p": "/", "json": rpc("message/send", msg("hello", taskId="t-cc"))},
        {"m": "POST", "p": "/", "json": rpc("tasks/cancel", {"id": "t-cc"})}],
    # A2A_Firewall n8n workflow inputs
    "n8n_inbound_nonblocking_submitted": [
        {"m": "POST", "p": "/?wait=false", "json": {"jsonrpc": "2.0", "id": "req-123", "method": "message/send", "params": {"message": {
            "role": "user", "messageId": "msg-123", "contextId": "ctx-n8n-default", "parts": [{"kind": "text", "text": "hello from n8n"}]}}}},
        {"sleep": 1}],
    "n8n_basic_notify_completed": [{"m": "POST", "p": "/", "json": rpc("message/send", msg("hello", taskId="t-bc", contextId="c-bc"))}],
    "n8n_basic_notify_failed": [{"m": "POST", "p": "/", "json": rpc("message/send", msg("FAIL", taskId="t-bf", contextId="c-bf"))}],
}
# Cases whose name starts with a profile prefix need the target started with that env.
PROFILES = {"default": {}, "n8n_basic": {"GATEWAY_NOTIFY_AUTH_MODE": "basic", "GATEWAY_NOTIFY_AUTH_USER": "n8n-dummy-user"}}


def profile_of(name):
    return "n8n_basic" if name.startswith("n8n_basic_") else "default"


def run_case(base, n8n, steps):
    n8n.reqs.clear(); out = []
    with httpx.Client(base_url=base, timeout=30) as c:
        for s in steps:
            if "sleep" in s:
                time.sleep(s["sleep"]); continue
            h = dict(AUTH if s.get("auth", AUTH) is AUTH else (s["auth"] or {}))
            kw = {"headers": h}
            if "json" in s: kw["json"] = s["json"]
            if "raw" in s: kw["content"] = s["raw"].encode(); h["Content-Type"] = "application/json"
            r = c.request(s["m"], s["p"], **kw)
            ct = r.headers.get("content-type", "")
            out.append({"request": {"method": s["m"], "path": s["p"], "auth": "bearer" if h.get("Authorization", "").startswith("Bearer ") else ("raw-token" if h.get("Authorization") else None),
                                    **({"json": s["json"]} if "json" in s and len(json.dumps(s["json"])) < 5000 else {}),
                                    **({"raw": s["raw"]} if "raw" in s else {})},
                        "response": {"status": r.status_code,
                                     "headers": {k: v for k, v in r.headers.items() if k in ("content-type", "cache-control")},
                                     **body_of(r.text, ct)}})
    time.sleep(0.7)
    return {"steps": out, "n8n_outbound": sorted(n8n.reqs, key=lambda q: q["json"]["event"])}


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def start_app(app_dir, n8n_port, extra=None):
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_"))}
    env.update(KIMICLAW_TOKEN=TOKEN, PATH=os.path.join(HERE, "fakebin") + os.pathsep + env["PATH"],
               FAKE_OPENCLAW_RECORD=os.path.join(tempfile.mkdtemp(prefix="golden-"), "openclaw-argv.jsonl"),
               GATEWAY_NOTIFY_URL=f"http://127.0.0.1:{n8n_port}/webhook/firewall", NO_PROXY="*")
    env.update(extra or {})
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--port", str(port), "--log-level", "warning"], cwd=app_dir, env=env)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try: httpx.get(base + "/.well-known/agent.json", timeout=0.5); break
        except Exception: time.sleep(0.1)
    return p, base


def replay(base, n8n, profile):
    fails = 0; names = [f[:-5] for f in sorted(os.listdir(CASES)) if profile_of(f[:-5]) == profile]
    for name in names:
        f = name + ".json"; want = json.load(open(os.path.join(CASES, f)))
        got = run_case(base, n8n, CASE_DEFS[name])
        ok = got == want; fails += not ok
        print(("PASS " if ok else "FAIL ") + name)
        if not ok:
            print("  want:", json.dumps(want)[:800]); print("  got: ", json.dumps(got)[:800])
    print(f"[{profile}] {len(names) - fails} passed, {fails} failed"); return fails


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("mode", choices=["record", "replay", "replay-local"])
    ap.add_argument("--app-dir"); ap.add_argument("--base-url"); ap.add_argument("--n8n-port", type=int, default=0)
    ap.add_argument("--profile", default="default", choices=list(PROFILES)); ap.add_argument("--only")
    a = ap.parse_args()
    if a.mode == "replay":
        sys.exit(1 if replay(a.base_url, N8n(a.n8n_port), a.profile) else 0)
    fails = 0
    for prof, extra in PROFILES.items():
        n8n = N8n(); p, base = start_app(a.app_dir, n8n.port, extra)
        try:
            if a.mode == "record":
                os.makedirs(CASES, exist_ok=True)
                for name, steps in CASE_DEFS.items():
                    if profile_of(name) != prof or (a.only and not name.startswith(a.only)):
                        continue
                    json.dump(run_case(base, n8n, steps), open(os.path.join(CASES, name + ".json"), "w"), indent=2)
                    print("recorded", name)
                if prof == "default" and not a.only:
                    json.dump(httpx.get(base + "/.well-known/agent.json").text, open(os.path.join(HERE, "agent_card.raw.json"), "w"))
            else:
                fails += replay(base, n8n, prof)
        finally:
            p.terminate(); n8n.srv.shutdown()
    sys.exit(1 if fails else 0)
