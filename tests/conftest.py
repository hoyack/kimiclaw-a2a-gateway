import atexit, os, secrets, shutil, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
import httpx, pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from sign_request import Signer  # noqa: E402

TOKEN = "dummy-test-token"  # KIMICLAW_TOKEN: outbound notify credential only
SECRETS = {key_id: secrets.token_urlsafe(32) for key_id in ("testkey01", "testkey02")}  # fresh every run, never committed
KEY = Signer("testkey01", SECRETS["testkey01"])
OTHER_KEY = Signer("testkey02", SECRETS["testkey02"])
LIMITS_OFF = {"GATEWAY_CREATE_PER_MIN": "100000", "GATEWAY_CREATE_BURST": "1000",
              "GATEWAY_GET_PER_S": "1000", "GATEWAY_CANCEL_PER_S": "1000"}



def write_keys_file(path, key_ids=tuple(SECRETS), mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.writelines(f"{k} caller-{k} {SECRETS[k]}\n" for k in key_ids)
    os.chmod(path, mode)
    return str(path)


_keys_dir = tempfile.mkdtemp(prefix="kc-test-keys-")
atexit.register(shutil.rmtree, _keys_dir, True)
KEYS_FILE = write_keys_file(os.path.join(_keys_dir, "keys.txt"))


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Mock:
    def __init__(self):
        self.requests = []
        mock = self
        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                mock.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            def log_message(self, *a): pass
        self.port = free_port()
        self.srv = HTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def wait(self, n, timeout=10):
        t = time.time()
        while len(self.requests) < n and time.time() - t < timeout:
            time.sleep(0.05)
        return self.requests


def start_gateway(tmp_path, extra_env):
    port = free_port()
    rec = tmp_path / "argv.jsonl"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_", "KIMICLAW_"))}
    env.update({
        "KIMICLAW_TOKEN": TOKEN,
        "GATEWAY_SIGNING_KEYS_FILE": KEYS_FILE,
        **LIMITS_OFF,
        "PATH": os.path.join(ROOT, "tests", "fakebin") + os.pathsep + env["PATH"],
        "HOME": str(tmp_path),
        "NO_PROXY": "*",
    })
    env.update(extra_env)
    log = open(tmp_path / "gateway.log", "w")
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--port", str(port)],
                         cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(base + "/.well-known/agent.json", timeout=0.5); break
        except Exception:
            time.sleep(0.1)
    return p, base, rec


@pytest.fixture
def mock():
    m = Mock(); yield m; m.srv.shutdown()


@pytest.fixture
def gw_factory(tmp_path):
    procs = []
    def make(**env):
        p, base, rec = start_gateway(tmp_path, env); procs.append(p)
        c = httpx.Client(base_url=base, auth=KEY, timeout=30)
        c.argv_file = rec; c.log_file = tmp_path / "gateway.log"
        return c
    yield make
    for p in procs:
        p.terminate(); p.wait(5)
