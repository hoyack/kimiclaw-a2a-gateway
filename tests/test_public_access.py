"""Per-caller public keys file, per-key rate limits, body cap, key_id audit logs, agent-card URL."""
import base64
import json
import os
import secrets
import subprocess
import sys
import time

import httpx
import pytest

from conftest import KEY, OTHER_KEY, ROOT, PRIVATE_KEYS, TOKEN, Signer, public_key, start_gateway, write_keys_file

GET = {"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {"id": "nope"}}
SEND = {"jsonrpc": "2.0", "id": "1", "method": "message/send",
        "params": {"message": {"parts": [{"kind": "text", "text": "hi"}]}, "configuration": {"blocking": False}}}
WRONG_KEY = Signer("a1a1a1a1a1", secrets.token_urlsafe(32))  # a different Ed25519 private key


@pytest.fixture
def start(tmp_path):
    procs = []
    def make(**env):
        p, base, _ = start_gateway(tmp_path, env); procs.append(p)
        return base
    yield make
    for p in procs:
        p.terminate(); p.wait(5)


def post(base, body, key=KEY):
    return httpx.post(base + "/", json=body, auth=key)


def boot(tmp_path, keys_text=None, keys_file=None):
    path = keys_file
    if keys_text is not None:
        path = tmp_path / "keys.txt"; path.write_text(keys_text); path.chmod(0o600)
    env = {**os.environ, "KIMICLAW_TOKEN": TOKEN, "GATEWAY_PUBLIC_KEYS_FILE": str(path or "")}
    return subprocess.run([sys.executable, "-c", "import gateway.config"], cwd=ROOT, env=env, capture_output=True, text=True)


def test_agent_card_and_healthz_stay_open_while_a_key_is_limited(start):
    base = start(GATEWAY_GET_PER_S="0.01")
    post(base, GET)
    assert post(base, GET).status_code == 429
    for h in ({}, {"Authorization": "Bearer wrong"}):
        assert httpx.get(base + "/healthz", headers=h).json() == {"status": "ok"}
        assert httpx.get(base + "/.well-known/agent.json", headers=h).status_code == 200


def test_task_create_limit_is_per_key_with_retry_after(start):
    base = start(GATEWAY_CREATE_PER_MIN="1", GATEWAY_CREATE_BURST="2")
    assert [post(base, SEND).status_code for _ in range(2)] == [200, 200]
    r = httpx.post(base + "/", json={**SEND, "method": "message/stream"}, auth=KEY)
    assert (r.status_code, r.json()) == (429, {"error": "rate limited"})
    assert 1 <= int(r.headers["retry-after"]) <= 60
    assert post(base, SEND, OTHER_KEY).status_code == 200
    assert post(base, GET).status_code == 200


def test_get_and_cancel_buckets_refill(start):
    base = start(GATEWAY_GET_PER_S="5", GATEWAY_CANCEL_PER_S="5")
    for body in (GET, {**GET, "method": "tasks/cancel"}):
        codes = [post(base, body).status_code for _ in range(6)]
        assert codes[:5] == [200] * 5 and codes[5] == 429
        time.sleep(0.3)
        assert post(base, body).status_code == 200


def test_failed_auth_does_not_spend_a_keys_quota(start):
    base = start(GATEWAY_GET_PER_S="0.01")
    for _ in range(5):
        assert post(base, GET, WRONG_KEY).status_code == 401
    assert post(base, GET).status_code == 200


def test_body_over_1mb_is_413(start):
    base = start()
    big = json.dumps({**GET, "pad": "x" * 1_000_001}).encode()
    r = httpx.post(base + "/", content=big, auth=KEY, headers={"Content-Type": "application/json"})
    assert (r.status_code, r.json()) == (413, {"error": "request body too large"})
    ok = json.dumps({**GET, "pad": "x" * 900_000}).encode()
    assert httpx.post(base + "/", content=ok, auth=KEY, headers={"Content-Type": "application/json"}).status_code == 200


def test_agent_card_url_is_configurable_and_card_does_not_advertise_backend(start):
    card = httpx.get(start(GATEWAY_PUBLIC_URL="https://a2a.hoyack.ai/") + "/.well-known/agent.json")
    assert card.json()["url"] == "https://a2a.hoyack.ai/"
    assert "openclaw" not in card.text.lower() and "shell" not in card.text.lower()


S1 = public_key(PRIVATE_KEYS["a1a1a1a1a1"])
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


HEADER = "# kimiclaw-public-keys v1\n"


@pytest.mark.parametrize("keys_text", [
    "", "# only a comment\n\n",
    HEADER,
    HEADER + f"a1a1a1a1a1 {S1}\n",
    HEADER + f"TESTKEY01 alice {S1}\n",
    HEADER + f"a1a1a1a1a1 alice {S1[:42]}\n",
    HEADER + f"a1a1a1a1a1 alice {S1}!\n",
    HEADER + f"a1a1a1a1a1 alice {S1}\na1a1a1a1a1 bob {S1}\n",
    HEADER + f"a1a1a1a1a1 alice {S1[:42]}{B64[B64.index(S1[42]) ^ 1]}\n",  # same bytes, non-canonical last char
])
def test_bad_keys_file_refuses_to_start_without_echoing_it(tmp_path, keys_text):
    r = boot(tmp_path, keys_text)
    assert r.returncode != 0 and "GATEWAY_PUBLIC_KEYS_FILE" in r.stderr
    assert S1[:16] not in r.stderr and "alice" not in r.stderr


@pytest.mark.parametrize("mode,ok", [(0o600, True), (0o400, True), (0o440, True), (0o640, True), (0o644, True),
                                     (0o604, True), (0o620, False), (0o602, False), (0o660, False), (0o666, False)])
def test_keys_file_writable_by_others_refuses_to_start(tmp_path, mode, ok):
    r = boot(tmp_path, keys_file=write_keys_file(tmp_path / "keys.txt", mode=mode))
    assert (r.returncode == 0) == ok, r.stderr
    assert ok or "writable by group or others" in r.stderr and S1[:16] not in r.stderr


def test_the_old_secrets_env_var_alone_refuses_to_start_and_says_why(tmp_path):
    env = {**os.environ, "KIMICLAW_TOKEN": TOKEN, "GATEWAY_SIGNING_KEYS_FILE": str(tmp_path / "old.txt")}
    env.pop("GATEWAY_PUBLIC_KEYS_FILE", None)
    r = subprocess.run([sys.executable, "-c", "import gateway.config"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "GATEWAY_SIGNING_KEYS_FILE" in r.stderr and "new_api_key.py" in r.stderr


def test_the_old_secrets_env_var_refuses_to_start_even_when_the_public_file_is_set(tmp_path):
    env = {**os.environ, "KIMICLAW_TOKEN": TOKEN,
           "GATEWAY_PUBLIC_KEYS_FILE": write_keys_file(tmp_path / "keys.txt"),
           "GATEWAY_SIGNING_KEYS_FILE": str(tmp_path / "old.txt")}
    r = subprocess.run([sys.executable, "-c", "import gateway.config"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "GATEWAY_SIGNING_KEYS_FILE" in r.stderr
    assert "no longer read" in r.stderr


def test_missing_keys_file_refuses_to_start(tmp_path):
    for path in (None, tmp_path / "nope.txt"):
        r = boot(tmp_path, keys_file=path)
        assert r.returncode != 0 and "GATEWAY_PUBLIC_KEYS_FILE" in r.stderr


def test_removing_a_keys_line_revokes_it(start, tmp_path):
    base = start(GATEWAY_PUBLIC_KEYS_FILE=write_keys_file(tmp_path / "revoked.txt", ("b2b2b2b2b2",)))
    assert post(base, GET).status_code == 401
    assert post(base, GET, OTHER_KEY).status_code == 200


def test_new_api_key_tool_mints_a_working_keypair_and_shows_the_private_key_once(start, tmp_path):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"), "acme"],
                       capture_output=True, text=True, check=True)
    lines = r.stdout.splitlines()
    assert lines[0].startswith("# WARNING: the next line is the PRIVATE key for acme")
    private, line = lines[-3], lines[-1]
    key_id, caller, public = line.split()
    assert len(key_id) == 10 and int(key_id, 16) >= 0 and caller == "acme" and public == public_key(private)
    assert r.stdout.count(private) == 1 and private not in line
    assert len(base64.urlsafe_b64decode(public + "=")) == 32
    minted = tmp_path / "minted.txt"
    minted.write_text("# kimiclaw-public-keys v1\n" + line + "\n"); minted.chmod(0o644)
    base = start(GATEWAY_PUBLIC_KEYS_FILE=str(minted))
    assert post(base, GET, Signer(key_id, private)).status_code == 200
    assert post(base, GET).status_code == 401
    pasted_all = boot(tmp_path, r.stdout)
    assert pasted_all.returncode != 0 and private not in pasted_all.stderr


def test_key_id_and_reason_are_logged_never_a_private_key_or_signature(start, tmp_path):
    tdir = tmp_path / "tel"
    base = start(GATEWAY_TELEMETRY_DIR=str(tdir))
    ok = post(base, GET)
    post(base, GET, Signer("eeeeeeeeee", S1))
    bad = post(base, GET, WRONG_KEY)
    time.sleep(0.5)
    out = (tmp_path / "gateway.log").read_text()
    logs = (tdir / "logs.jsonl").read_text()
    assert "key_id=a1a1a1a1a1 caller=alice POST /" in out
    assert "unauthorized reason=unknown_key key_id=eeeeeeeeee" in out
    assert "unauthorized reason=bad_signature key_id=a1a1a1a1a1" in out
    assert '"key_id": "a1a1a1a1a1"' in logs and '"key_id": "invalid:eeeeeeeeee"' in logs
    for text in (out, logs):
        assert all(sec not in text for sec in PRIVATE_KEYS.values())
        assert ok.request.headers["x-kc-signature"] not in text and bad.request.headers["x-kc-signature"] not in text


def test_rotation_two_key_ids_for_one_caller_share_its_tasks(start, tmp_path):
    base = start(GATEWAY_PUBLIC_KEYS_FILE=write_keys_file(tmp_path / "k.txt", ("a1a1a1a1a1", "b2b2b2b2b2", "a1a1a1a1a3")))
    new_key = Signer("a1a1a1a1a3", PRIVATE_KEYS["a1a1a1a1a3"])
    tid = post(base, SEND, KEY).json()["result"]["id"]
    for method in ("tasks/get", "tasks/cancel"):
        body = {"jsonrpc": "2.0", "id": "1", "method": method, "params": {"id": tid}}
        assert post(base, body, OTHER_KEY).json()["error"]["code"] == -32001
        assert post(base, body, new_key).json()["result"]["id"] == tid
    retired = start(GATEWAY_PUBLIC_KEYS_FILE=write_keys_file(tmp_path / "k2.txt", ("b2b2b2b2b2", "a1a1a1a1a3")))
    assert post(retired, GET, KEY).status_code == 401
    assert post(retired, GET, new_key).status_code == 200


@pytest.mark.parametrize("line", [
    "a1a1a1a1a1 alice {s} extra", "bad!id alice {s}", "a1a1a1a1a1 al-ice {s}", "a1a1a1a1a1 alice {s}=",
])
def test_startup_error_names_the_line_never_its_content(tmp_path, line):
    r = boot(tmp_path, f"# kimiclaw-public-keys v1\n{line.format(s=S1)}\n")
    assert r.returncode != 0 and "GATEWAY_PUBLIC_KEYS_FILE line 2:" in r.stderr
    assert S1[:8] not in r.stderr


@pytest.mark.parametrize("nbytes,ok", [(16, False), (31, False), (32, True), (33, False), (64, False)])
def test_public_keys_must_be_32_bytes(tmp_path, nbytes, ok):
    key = public_key(secrets.token_urlsafe(32)) if nbytes == 32 else secrets.token_urlsafe(nbytes)
    r = boot(tmp_path, f"# kimiclaw-public-keys v1\na1a1a1a1a1 alice {key}\n")
    assert (r.returncode == 0) == ok, r.stderr


def test_a_keys_file_without_the_format_header_refuses_to_start(tmp_path):
    r = boot(tmp_path, f"a1a1a1a1a1 alice {S1}\n")
    assert r.returncode != 0 and "first line must be `# kimiclaw-public-keys v1`" in r.stderr
    assert S1[:16] not in r.stderr


def test_caller_generated_keypair_is_registered_without_the_operator_seeing_the_private_key(start, tmp_path):
    key_file, pub_file = tmp_path / "a2a.key", tmp_path / "pub.b64"
    minted = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_keypair.py"),
                             "--private-key-file", str(key_file)], capture_output=True, text=True, check=True)
    public = minted.stdout.strip()
    assert minted.stdout.count("\n") == 1 and public == public_key(key_file.read_text().strip())
    assert key_file.read_text().strip() not in minted.stdout
    assert oct(key_file.stat().st_mode & 0o777) == "0o600"
    pub_file.write_text(public + "\n")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"),
                        "--caller", "acme", "--public-key-file", str(pub_file)],
                       capture_output=True, text=True, check=True)
    line = r.stdout.strip()
    key_id, caller, recorded = line.split()
    assert r.stdout.count("\n") == 1 and caller == "acme" and recorded == public
    assert key_file.read_text().strip() not in r.stdout + r.stderr
    same = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"),
                           "--caller", "acme", "--public-key=" + public],
                          capture_output=True, text=True, check=True)
    assert same.stdout.strip().split()[1:] == ["acme", public]
    keys = tmp_path / "keys.txt"
    keys.write_text("# kimiclaw-public-keys v1\n" + line + "\n"); keys.chmod(0o600)
    base = start(GATEWAY_PUBLIC_KEYS_FILE=str(keys))
    assert post(base, GET, Signer(key_id, key_file.read_text().strip())).status_code == 200
    assert post(base, GET).status_code == 401


def test_new_keypair_refuses_to_overwrite_an_existing_private_key_file(tmp_path):
    key_file = tmp_path / "a2a.key"
    key_file.write_text("keep\n"); key_file.chmod(0o600)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_keypair.py"),
                        "--private-key-file", str(key_file)], capture_output=True, text=True)
    assert r.returncode != 0 and "already exists" in r.stderr and key_file.read_text() == "keep\n"


def test_new_api_key_rejects_a_malformed_public_key_without_echoing_it(tmp_path):
    bad = "leakme-not-a-key"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"),
                        "--caller", "acme", "--public-key=" + bad], capture_output=True, text=True)
    assert r.returncode != 0 and "public key" in r.stderr and bad not in r.stderr and bad not in r.stdout


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _weak_cases():
    from gateway.pubkey import P, SMALL_ORDER
    cases = []
    labels = {
        (0).to_bytes(32, "little"): "all-zero",
        (1).to_bytes(32, "little"): "identity",
        (P - 1).to_bytes(32, "little"): "y-equals-p-minus-1",
        P.to_bytes(32, "little"): "noncanonical-y-equals-p",
        (P + 1).to_bytes(32, "little"): "noncanonical-y-equals-p-plus-1",
    }
    for raw in sorted(SMALL_ORDER, key=bytes.hex):
        cases.append((labels.get(raw, f"small-order-{raw[:4].hex()}"), raw))
        signed = raw[:31] + bytes([raw[31] | 0x80])
        if signed != raw:
            cases.append((labels.get(raw, f"small-order-{raw[:4].hex()}") + "-sign-bit", signed))
    cases.append(("noncanonical-y-equals-p-plus-2", (P + 2).to_bytes(32, "little")))
    cases.append(("off-curve-y-equals-2", (2).to_bytes(32, "little")))
    return cases


@pytest.mark.parametrize("label,raw", _weak_cases(), ids=[c[0] for c in _weak_cases()])
def test_a_weak_ed25519_public_key_is_refused_at_load(tmp_path, label, raw):
    encoded = _b64(raw)
    r = boot(tmp_path, HEADER + f"aaaaaaaaaa mallory {encoded}\n")
    assert r.returncode != 0 and "GATEWAY_PUBLIC_KEYS_FILE line 2:" in r.stderr, label
    assert encoded[:16] not in r.stderr and "mallory" not in r.stderr


def test_a_forged_request_under_a_weak_key_is_refused_because_the_key_never_loads(start, tmp_path):
    encoded = _b64(bytes(32))
    weak = tmp_path / "weak.txt"
    weak.write_text(HEADER + f"aaaaaaaaaa mallory {encoded}\n"); weak.chmod(0o600)
    assert boot(tmp_path, keys_file=weak).returncode != 0
    # identity / S=0 would verify any message if this key had loaded; it must not be served
    base = start()
    h = {"X-KC-Key-Id": "aaaaaaaaaa", "X-KC-Timestamp": str(int(time.time())),
         "X-KC-Nonce": "n" * 24, "X-KC-Signature": "0" * 128, "Content-Type": "application/json"}
    r = httpx.post(base + "/", content=b"{}", headers=h)
    assert r.status_code == 401 and r.json() == {"error": "unauthorized"}
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"),
                        "--caller", "mallory", "--public-key=" + encoded],
                       capture_output=True, text=True)
    assert r.returncode != 0 and encoded not in r.stderr and encoded not in r.stdout


@pytest.mark.parametrize("key_id", [
    "aaaaaaaa", "a1a1a1a1a", "a1a1a1a1a1a", "A1A1A1A1A1", "testkey01", "012345678g",
])
def test_the_loader_accepts_only_the_10_lowercase_hex_key_id_the_tool_mints(tmp_path, key_id):
    r = boot(tmp_path, HEADER + f"{key_id} alice {S1}\n")
    assert r.returncode != 0 and "GATEWAY_PUBLIC_KEYS_FILE line 2:" in r.stderr
    assert key_id not in r.stderr and S1[:8] not in r.stderr and "alice" not in r.stderr


def test_new_api_key_issues_only_a_10_lowercase_hex_key_id():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "new_api_key.py"),
                        "--caller", "acme", "--public-key=" + S1],
                       capture_output=True, text=True, check=True)
    key_id, caller, pub = r.stdout.strip().split()
    assert len(key_id) == 10 and key_id == key_id.lower() and int(key_id, 16) >= 0 and caller == "acme" and pub == S1
