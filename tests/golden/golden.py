#!/usr/bin/env python3
"""Golden fixtures for the Kimiclaw A2A gateway.

record:  python golden.py record --app-dir DIR      (starts DIR's app.py with stubs, writes cases/*.json)
replay:  python golden.py replay --base-url URL --n8n-port PORT [--profile default|n8n_basic]
   n8n_basic profile: target also needs GATEWAY_NOTIFY_AUTH_MODE=basic GATEWAY_NOTIFY_AUTH_USER=n8n-dummy-user.
   Target must run with: KIMICLAW_TOKEN=dummy-test-token, GATEWAY_PUBLIC_KEYS_FILE=<file with a a1a1a1a1a1 public line; pass
   the matching private key as --private-key-file>, rate limits raised
   (see start_app), fakebin/ first on PATH,
   HOME=<writable dir>, GATEWAY_NOTIFY_URL=http://127.0.0.1:PORT/webhook/firewall.
replay-local: python golden.py replay-local --app-dir DIR   (starts DIR's app with stubs, then replays)
Normalized: timestamps, UUIDs, durationMs, Content-Length/Date/server headers.
"""
import argparse, base64, json, os, re, secrets, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools"))
from sign_request import Signer, load_private_key  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

CASES = os.path.join(HERE, "cases")
TOKEN = "dummy-test-token"  # KIMICLAW_TOKEN, notify credential
SIGNER = Signer("a1a1a1a1a1", secrets.token_urlsafe(32))  # replay-local: fresh Ed25519 key per run; replay: --private-key-file
AUTH = {}
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
    "get_root_wrong_scheme": [{"m": "GET", "p": "/", "auth": {"Authorization": "Bearer kc_a1a1a1a1a1_" + "k" * 43}}],
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


def with_server_ids(body, ids):
    """Task ids are minted by the server; later steps refer to a task by the taskId the case sent, mapped here."""
    p = body.get("params") or {}
    key = "id" if "id" in p else "taskId" if "taskId" in p else None
    return {**body, "params": {**p, key: ids[p[key]]}} if key and p[key] in ids else body


def run_case(base, n8n, steps):
    n8n.reqs.clear(); out = []; ids = {}
    with httpx.Client(base_url=base, timeout=30) as c:
        for s in steps:
            if "sleep" in s:
                time.sleep(s["sleep"]); continue
            signed = s.get("auth", AUTH) is AUTH
            h = dict(s.get("auth") or {})
            kw = {"headers": h, "auth": SIGNER if signed else None}
            if "json" in s: kw["json"] = with_server_ids(s["json"], ids)
            if "raw" in s: kw["content"] = s["raw"].encode(); h["Content-Type"] = "application/json"
            r = c.request(s["m"], s["p"], **kw)
            ct = r.headers.get("content-type", "")
            sent = ((s.get("json") or {}).get("params") or {}).get("message", {}).get("taskId")
            if sent and ct.startswith("application/json") and isinstance(r.json().get("result"), dict):
                ids[sent] = r.json()["result"]["id"]
            out.append({"request": {"method": s["m"], "path": s["p"], "auth": "signed" if signed else ("raw-token" if h.get("Authorization") else None),
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
    keys = os.path.join(tempfile.mkdtemp(prefix="golden-keys-"), "keys.txt")
    with os.fdopen(os.open(keys, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
        raw = load_private_key(SIGNER.private_key).public_key().public_bytes(serialization.Encoding.Raw,
                                                                             serialization.PublicFormat.Raw)
        f.write("# kimiclaw-public-keys v1\n")
        f.write(f"{SIGNER.key_id} golden {base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}\n")
    env.update(KIMICLAW_TOKEN=TOKEN, GATEWAY_PUBLIC_KEYS_FILE=keys,
               GATEWAY_CREATE_PER_MIN="100000", GATEWAY_CREATE_BURST="1000", GATEWAY_GET_PER_S="1000",
               GATEWAY_CANCEL_PER_S="1000", GATEWAY_REQUESTS_PER_S="100000", GATEWAY_REQUESTS_BURST="100000", PATH=os.path.join(HERE, "fakebin") + os.pathsep + env["PATH"],
               HOME=tempfile.mkdtemp(prefix="golden-"),
               GATEWAY_NOTIFY_URL=f"http://127.0.0.1:{n8n_port}/webhook/firewall", NO_PROXY="*")
    env.update(extra or {})
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--port", str(port), "--log-level", "warning"], cwd=app_dir, env=env)
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + int(env.get("GATEWAY_SIGNATURE_FUTURE_S", "30")) + 10
    while time.time() < deadline:
        if p.poll() is not None:
            break
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
    ap.add_argument("--private-key-file", help="replay: private key for the target's a1a1a1a1a1 public line")
    a = ap.parse_args()
    if a.mode == "replay":
        SIGNER.private_key = open(a.private_key_file).read().strip()
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
