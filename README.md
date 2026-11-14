# Kimiclaw A2A Gateway

A2A protocol (v1.0 subset) gateway fronting the local OpenClaw agent.

- Public URL: `https://kimiclaw.hoyack.ai/`
- Agent card: `GET /.well-known/agent.json` (public)
- JSON-RPC: `POST /` (Ed25519-signed requests only, per-key rate limits; see "Request signing")
- Origin: uvicorn on `127.0.0.1:8000`, tunnel via cloudflared systemd service

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt            # requirements-dev.txt for tests
export KIMICLAW_TOKEN=...                  # only with GATEWAY_NOTIFY_URL; or KIMICLAW_TOKEN=... in .env (chmod 600)
export GATEWAY_PUBLIC_KEYS_FILE=/path/to/keys.txt # callers' Ed25519 public keys, see "Caller keys"
export KIMICLAW_LIMIT_CONCURRENCY=1024     # required; integer 64–4096
python -m gateway --host 127.0.0.1 --port 8000
```
`openclaw` must be on PATH. The app refuses to start without a valid `GATEWAY_PUBLIC_KEYS_FILE`, without `KIMICLAW_LIMIT_CONCURRENCY`, or without `KIMICLAW_TOKEN` when `GATEWAY_NOTIFY_URL` is set. The only supported launcher is `python -m gateway`, which pins one worker, applies the concurrency cap, starts the probe listener, and arms the request-header timeout. `uvicorn app:app` is refused at import.

Docker: the image CMD is still `uvicorn app:app` and must be overridden to `["python","-m","gateway"]`, with `KIMICLAW_LIMIT_CONCURRENCY` set and both 8000 and 8001 published. The stock HEALTHCHECK still hits `:8000/healthz` and should be moved to `:8001/healthz`. The image does not contain openclaw; add it in a derived image or mount it.

A reverse proxy with client header and body timeouts (for example ingress nginx) is required in front of the gateway for any public deploy. uvicorn 0.54 counts idle connections toward `limit_concurrency` and will not time them out on its own.

## Layout

```
app.py                     refused shim (`uvicorn app:app` is not supported)
gateway/__main__.py        only supported entrypoint (`python -m gateway`)
gateway/probe.py           tiny ASGI app for the uncapped probe port (GET /healthz, GET /readyz only)
gateway/config.py          env settings + .env fallback
gateway/models.py          agent card, wire builders, pydantic schemas (docs only)
gateway/auth.py            signature middleware (per-caller Ed25519 public keys, nonces, POST / rate limit)
gateway/telemetry.py       OpenTelemetry setup + request middleware
gateway/routes/            a2a.py (GET /, agent card, POST /), health.py
gateway/controllers/rpc.py JSON-RPC dispatch + SSE
gateway/services/          task_store.py, agent_runner.py, notifier.py
openapi.yaml               frozen API contract (served spec must match; see tests/test_contract.py)
```

## Endpoints

| Method | Path | Auth | |
|---|---|---|---|
| GET | `/.well-known/agent.json` | public | agent card |
| GET | `/` | signed | service info |
| POST | `/` | signed | JSON-RPC: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`. 429 + `Retry-After` over the caller's rate limit |
| GET | `/healthz` | public | **new**: liveness, returns only `{"status":"ok"}` (no version/config) |
| GET | `/readyz` | public | **new**: 200 if `openclaw` is on PATH, else 503; handled before auth or read pools |

| GET | `/docs`, `/openapi.json` | signed | Swagger UI and spec |

> **`/readyz` returning 503 is by design, not an outage**, when OpenClaw isn't installed (e.g. the stock Docker
> image, CI). Use `/healthz` for liveness; `/readyz` only means "can run agent turns". The Docker HEALTHCHECK uses `/healthz`.

`message/send` is blocking by default. Through Cloudflare it is capped at ~120 s; for longer turns use
`?wait=false` (or `params.configuration.blocking=false`) and poll `tasks/get`, or use `message/stream` (SSE, 15 s keepalives).
A2A `contextId` maps to OpenClaw session `a2a-<caller>-<ctx>`; reuse it to continue a conversation.

### Example
```bash
# the private key file from tools/new_keypair.py, kept by the CALLER (chmod 600, or env KC_PRIVATE_KEY)
python tools/sign_request.py --key-id "$A2A_KEY_ID" --private-key-file a2a.key https://kimiclaw.hoyack.ai/ \
  '{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"Summarize the systemd journal for yesterday"}]}}}'
```
From Python: `httpx.Client(base_url="https://kimiclaw.hoyack.ai", auth=Signer(key_id, private_key))` with `Signer` from
`tools/sign_request.py` signs every request the client sends.

## Request signing

Every request except `GET /.well-known/agent.json`, `GET /healthz` and `GET /readyz` carries five headers:

| Header | Value |
|---|---|
| `X-KC-Key-Id` | the caller's key_id (exactly 10 lowercase hex characters, as `tools/new_api_key.py` mints; not `kc_<hex>`) |
| `X-KC-Timestamp` | unix time in whole seconds, decimal |
| `X-KC-Nonce` | 16 to 64 chars of `A-Z a-z 0-9 - _`, new for every request (e.g. 24 random bytes, base64url) |
| `X-KC-Content-SHA256` | lowercase hex sha256 of the body bytes exactly as sent (sha256 of empty for GET); this is also line 5 of the canonical string |
| `X-KC-Signature` | the Ed25519 signature of the canonical string, made with the caller's private key: 64 bytes as 128 lowercase hex chars |

The gateway holds only public keys, so nothing it stores can be used to sign. Hex was picked over base64url because it
has exactly one spelling per signature, so there are no padding or alphabet variants to normalize.

The canonical string is six lines joined by `\n` (no trailing newline), in this order:

```
METHOD                  upper case, e.g. POST
PATH[?QUERY]            see below
TIMESTAMP               the X-KC-Timestamp value
NONCE                   the X-KC-Nonce value
BODY_SHA256             lowercase hex sha256 of the body bytes exactly as sent (sha256 of empty for GET)
KEY_ID                  the X-KC-Key-Id value
```

`PATH` is the request path exactly as sent on the wire, still percent-encoded, without scheme, host or fragment.
`QUERY` is the raw query string exactly as sent (the part after `?`, before any `#`): not sorted, decoded or
re-encoded. With no query, or an empty one, the line is the path alone with no `?`. Example: `POST /?wait=false&b=2`
signs the line `/?wait=false&b=2`, and sending `/?b=2&wait=false` with that signature fails. Signing the query as sent
(not sorted) means the order of repeated keys such as `?wait=true&wait=false` is signed too, with no
duplicate-key rule to get wrong. This is the reviewed design from the HMAC rounds and is kept for Ed25519. A proxy in front of the gateway must not rewrite the path, the query or the body.

The gateway verifies the signature from headers alone, before it reads the body. Checks run in this order: each of the five headers present exactly once (a repeated `X-KC-*` header is rejected) and well formed (`X-KC-Content-SHA256` is exactly 64 lowercase hex characters); the timestamp at most 300 s behind its clock and at most 30 s ahead (`GATEWAY_SIGNATURE_PAST_S`, `GATEWAY_SIGNATURE_FUTURE_S`) and later than the start second plus `GATEWAY_SIGNATURE_FUTURE_S`; then the key lookup; then the Ed25519 verify over the canonical string that uses the hash from the header (line 5). An unknown `key_id` is refused at lookup with no dummy verify and no body read. A signature that isn't 128 lowercase hex chars is rejected as malformed, and a verify failure of any kind is a plain 401, never an exception. Only a request whose signature verifies has its nonce checked and recorded. A nonce already used by the same caller within the window is rejected (401). Next, the caller's nonce quota must have room (else 429, with no bucket token spent). Then every signed request, including `GET /`, `/docs` and unknown JSON-RPC methods, pays the caller's general token bucket (`GATEWAY_REQUESTS_PER_S`, default 5/s, burst `GATEWAY_REQUESTS_BURST` 10); when it is empty the caller gets 429 and no nonce is kept. Only then is the nonce stored. The per-method limits below apply on top.

Only a request that has already verified enters that caller's reserved read pool. There is no unauthenticated pre-auth pool and no shared unknown-key pool: missing, duplicate or malformed headers, an unknown `key_id`, a timestamp outside the window or caught by the restart rule, a replayed nonce, and a bad signature are all refused with a byte-identical generic 401, without taking a slot, reading the body, writing a per-request log or trace, or emitting an access-log line (and no access line contains a client ip:port). Those refusals go into one aggregated log line per second (`auth refused count=N reasons=missing_header:N,...`).

- Each known caller has its own reserved pool of `GATEWAY_READS_PER_CALLER` reads (default 3, allowed 2 to 4, checked at startup). Only that caller's verified requests can use those slots. Over the floor, that caller gets `429 {"error": "rate limited"}` with `Retry-After: 1`. One caller cannot take another caller's reserved slots.
- The body is then streamed under `MAX_BODY` (1 MB, else 413) with a total deadline (`GATEWAY_BODY_READ_TIMEOUT_S`, default 10 s) and a limit on the gap between chunks (`GATEWAY_BODY_IDLE_TIMEOUT_S`, default 5 s); past either the request gets `408 {"error": "request timeout"}`. As it streams, the body is hashed; if that hash does not match `X-KC-Content-SHA256`, the response is the same generic 401 (`body_hash_mismatch`). A client that disconnects mid-body gets nothing back and no traceback is logged. The slot is always freed in `finally`.
- 429 and 408 from the read pools (pool_full, read_deadline, read_idle) are not logged or traced per request, and they do not write an access-log line (uvicorn access logging is off; our own access logger also skips quiet refusals and never writes a client ip:port). One aggregated line per pool per second records the count and reasons (`read refused pool=caller count=N reasons=pool_full:N,...`). Per-request logs remain for 413 (`too_large`) and a client disconnect (`client_disconnected`).
- `GET /healthz` and `GET /readyz` exist on the main port, inside the concurrency cap, so they are the wrong targets for Kubernetes probes. Use the uncapped probe listener (`GATEWAY_PROBE_PORT`, default 8001), which is a separate tiny ASGI app (not the main app) that serves only `GET /healthz` and `GET /readyz`. `/healthz` (liveness and startup) returns 200 `{"status":"up"}` as soon as the process is up, including during the ~31 s startup hold. `/readyz` (readiness) returns 503 `{"status":"starting"}` during the hold and 200 `{"status":"ready"}` once the main port is serving (or 503 `{"status":"not ready"}` if `openclaw` is not on PATH). Any other path or method on the probe port is 404 `{"status":"not found"}`, with no auth, no pools and no telemetry. `GET /.well-known/agent.json` stays on the main port only, public, and never competes for reserved read slots.

Unauthenticated floods therefore cannot fill a caller's pool or force a 503 on a signed request. key_ids are not secret (they travel in every request) and an immediate 401 for an unknown `key_id` is a timing oracle for whether that id is loaded; the id format is only 10 lowercase hex characters (40 bits from `secrets`, issued only by `tools/new_api_key.py`; callers never choose a key_id; the loader does not accept `kc_<hex>`). A per-IP connection cap belongs at the edge, not in the gateway.

Any of the header, timestamp, key, signature, nonce-replay or body-hash refusals is `401 {"error": "unauthorized"}`, with the same status, body, headers and Content-Length. The reason (`duplicate_header`, `missing_header`, `malformed_header`, `stale_timestamp`, `stale_after_restart`, `unknown_key`, `bad_signature`, `replayed_nonce`, `body_hash_mismatch`) goes only to the aggregated log, without a key_id. A header value that isn't shaped like a key_id is never logged verbatim (it could be a misplaced private key), and signatures are never logged.

Nonces are kept in process memory per caller, each until its timestamp leaves the window, and at most
`GATEWAY_MAX_NONCES_PER_CALLER` (default 20,000) per caller. The general bucket keeps a caller far below that
(5/s × 330 s + 10 ≈ 1,660), so the cap is a backstop. A caller at its cap gets `429 {"error": "rate limited"}` with
`Retry-After` set to when its oldest nonce expires. Only that caller is affected: other callers keep getting 200 and
never 401. Memory is bounded by callers × cap. Per-process state is sound because the
gateway runs one worker. A restart forgets the nonces, so the gateway also rejects (401, reason `stale_after_restart`)
any timestamp at or before the start second plus `GATEWAY_SIGNATURE_FUTURE_S`, and holds startup for
`GATEWAY_SIGNATURE_FUTURE_S + 1` seconds (about 31 s by default) before it serves. That covers every previously
acceptable timestamp, including one stamped up to 30 s ahead and captured before the restart: it cannot be replayed
after it. There is no remaining capture-across-restart window. The cost: right after a restart, requests signed just
before it get 401, a caller whose clock lags by N seconds gets 401 for N seconds after each restart, and startup is
delayed by about 31 s. Callers should re-sign and retry. `Authorization: Bearer` keys are no longer accepted.

### Caller keys

`GATEWAY_PUBLIC_KEYS_FILE` must start with the line `# kimiclaw-public-keys v1`, then one
`<key_id> <caller> <public_key>` line per key (`#` comments allowed), where `public_key` is the 32-byte Ed25519 public
key as unpadded base64url (43 chars). It holds no secrets: a public key can verify a signature but not make one. It can
be a ConfigMap or a read-only mount; the gateway only insists that nobody but its owner can write it, because whoever
can add a line can add a caller.

Startup is refused, with an error that names only the line number, if the file is missing, empty or malformed, if the
first line isn't the format header, if a key_id isn't exactly 10 lowercase hex characters (the format
`tools/new_api_key.py` mints; callers never choose a key_id), if a key_id repeats, if a caller name isn't 1 to 32 of
`A-Z a-z 0-9 _`, if a public key isn't a canonical 32-byte on-curve Ed25519 key in the prime-order subgroup (all-zero,
the identity, other torsion points, non-canonical y, off-curve encodings, and honest-plus-torsion mixed points are refused), or if the file is writable by its group or others. The old
`GATEWAY_SIGNING_KEYS_FILE` (HMAC secrets) is no longer read; setting it at all, even together with
`GATEWAY_PUBLIC_KEYS_FILE`, refuses startup. A 32-byte HMAC secret would otherwise parse as an Ed25519 public key, so
the format header is required to stop an old secrets file being loaded. The caller generates the keypair; the operator
only ever receives the public key:

```bash
# on the caller: writes the private key to a2a.key (chmod 600) and prints only the public key
python tools/new_keypair.py --private-key-file a2a.key > pub.b64
# on the operator: prints the public line to append to GATEWAY_PUBLIC_KEYS_FILE
python tools/new_api_key.py --caller <caller> --public-key-file pub.b64
```

(`--public-key` also accepts the public key directly.) Create the keys file with `# kimiclaw-public-keys v1` as its
first line, then append the public line. The private key stays on the caller (the 0600 file, or `KC_PRIVATE_KEY`).

If the caller cannot mint a keypair, `python tools/new_api_key.py --caller <caller> --mint` (or `new_api_key.py <caller>`)
prints, once, a warning, the **private key**, and the public line. Hand the private key to the caller over a secure
channel and don't keep a copy. Prefer caller-generated keys: the operator then never sees the private key. Pasting
`--mint` output into the keys file by mistake fails startup, because the private key line doesn't parse.

key_ids are not secret but must be unguessable (see the read pools above). **`tools/new_api_key.py` is the only
supported way to issue a key_id, and callers never choose one:** the tool draws 10 lowercase hex characters (40 bits)
from Python's `secrets` module (the OS CSPRNG), and the loader accepts only that shape. The keypair comes
from `cryptography`'s Ed25519 generator, on the caller via `tools/new_keypair.py` unless `--mint` is used. A submitted
public key that is small-order, off-curve or non-canonical is refused, so a caller cannot register a key that would
let anyone forge requests as them.

**Rotation.** A caller can have several key_ids at once:
1. The caller runs `new_keypair.py` again. Run `new_api_key.py --caller <same name> --public-key-file` and add the new public line.
2. Restart the gateway, then give the caller the new key_id. Both keys work during the overlap.
3. Once the caller has switched, delete the old line and restart.

To revoke a key immediately, delete its line and restart.

**Everything is scoped per caller, not per key_id:** task ownership, the `a2a-<caller>-<contextId>` agent session,
rate limits, the in-flight and stored-task caps, and nonces. A rotation therefore doesn't orphan tasks or split a
conversation, and holding two keys doesn't double a caller's limits. The key_id still appears in every log line, so you
can tell which key was used. Task ids are minted by the gateway (a client `taskId` is ignored). Other callers get "task
not found" on `tasks/get`/`tasks/cancel` and can't join another caller's session. A caller name has no `-`, so a
session id can't be ambiguous. The agent runs with only `PATH`, `HOME`, `LANG`, `LC_ALL` and `TZ` from the gateway env,
gets the message on stdin (`--message-file -`, no temp file), and callers see `agent error (task <id>)` instead of agent
stderr.

Over a limit: 429 with `Retry-After`. `POST /` bodies over 1 MB: 413. Limits are in-process, per replica, so run
exactly one replica with one worker (the gateway logs this at startup). More replicas or workers multiply every limit.

## Environment variables (names only)

See `.env.example` for a placeholder template. For the n8n A2A_Firewall webhook set `GATEWAY_NOTIFY_AUTH_MODE=basic`
(the default `raw` will be rejected by that webhook's Basic auth).


| Name | Default | Purpose |
|---|---|---|
| `KIMICLAW_TOKEN` | required only when `GATEWAY_NOTIFY_URL` is set (env or `.env`) | outbound notify credential; never accepted inbound |
| `GATEWAY_PUBLIC_KEYS_FILE` | required | path to the callers' Ed25519 public keys (see "Caller keys"; no secrets). First line must be `# kimiclaw-public-keys v1`. Missing, empty, malformed, headerless or writable by group or others refuses startup. Setting `GATEWAY_SIGNING_KEYS_FILE` at all refuses startup |
| `GATEWAY_CREATE_PER_MIN` / `GATEWAY_CREATE_BURST` | `10` / `5` | per caller: `message/send` + `message/stream` token bucket |
| `GATEWAY_GET_PER_S` | `2` | per caller: `tasks/get` |
| `GATEWAY_CANCEL_PER_S` | `1` | per caller: `tasks/cancel` |
| `GATEWAY_MAX_INFLIGHT_PER_KEY` | `2` | per caller (all its key_ids): running or queued tasks; more gets 429 (`Retry-After: 5`). Must stay below the 3 agent slots, or startup fails, so one caller can't hold them all |
| `WEB_CONCURRENCY` | `1` | anything but 1 refuses startup (limits are per process) |
| `GATEWAY_MAX_PENDING` | `50` | all callers: running or queued tasks; more gets 429 |
| `GATEWAY_REQUESTS_PER_S` / `GATEWAY_REQUESTS_BURST` | `5` / `10` | per caller: every signed request (any path or method), checked before its nonce is stored; empty gets 429 |
| `GATEWAY_MAX_NONCES_PER_CALLER` | `20000` | per caller: live nonces kept for replay checks; more gets 429 until the oldest expires |
| `GATEWAY_SIGNATURE_PAST_S` / `GATEWAY_SIGNATURE_FUTURE_S` | `300` / `30` | how far behind / ahead of the gateway clock a signed timestamp may be; ahead must not exceed behind. Startup waits `FUTURE_S + 1` s (~31 s by default) so a future-stamped request captured before a restart cannot be replayed after it |
| `KIMICLAW_LIMIT_CONCURRENCY` | required (no default) | uvicorn concurrency cap on the main port; an integer from 64 to 4096 (`^[0-9]+$` only), fail closed if missing or out of range. Recommended 1024. Applied only by `python -m gateway` (CMD `["python","-m","gateway"]`), which also pins `workers=1`. `uvicorn app:app` is refused; do not pass `--limit-concurrency` or `--workers` on a command line — the launcher does not take those flags, so an env or CLI override cannot fight it |
| `GATEWAY_PROBE_PORT` | `8001` | uncapped probe listener in the same process: `GET /healthz` and `GET /readyz`. Must differ from the main port. Range 1–65535, digits only |
| `GATEWAY_READS_PER_CALLER` | `3` | per caller: reserved body-read slots for already-verified requests (2 to 4); more gets 429 |
| `GATEWAY_BODY_READ_TIMEOUT_S` / `GATEWAY_BODY_IDLE_TIMEOUT_S` | `10` / `5` | total time to read a body / longest gap between chunks; past either gets 408 |
| `GATEWAY_MAX_TASKS_PER_KEY` | `100` | per caller: stored tasks; the oldest finished ones are dropped past this |
| `GATEWAY_TELEMETRY_FILE_MB` | `10` | size of each telemetry file; 5 files each for traces, metrics and logs (150 MB total) |
| `GATEWAY_PUBLIC_URL` | `https://kimiclaw.hoyack.ai/` | `url` published in `/.well-known/agent.json` (e.g. `https://a2a.hoyack.ai/`) |
| `GATEWAY_NOTIFY_URL` | empty (disabled) | task-event webhook (n8n AI firewall) |
| `GATEWAY_NOTIFY_AUTH_MODE` | `raw` | `raw` (token), `bearer`, or `basic` (user:token). **Must be `basic` for the n8n A2A_Firewall webhook** |
| `GATEWAY_NOTIFY_AUTH_USER` | `agent` | user for `basic` |
| `GATEWAY_NOTIFY_EVENTS` | `task_completed,task_failed` | `task_started` also allowed |
| `GATEWAY_NOTIFY_FAIL_LIMIT` | `5` | consecutive failures before circuit breaker opens |
| `GATEWAY_NOTIFY_COOLDOWN_S` | `900` | breaker pause |
| `GATEWAY_TELEMETRY_DIR` | `telemetry` | new: where trace/metric/log files go |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | new: when set (e.g. `https://otel.example.com:4318`), traces, metrics and logs go via OTLP/HTTP **instead of** the files. Standard `OTEL_*` vars apply. `http://` to a non-localhost host logs a plaintext warning |
| `OTEL_SERVICE_NAME` | `kimiclaw-a2a-gateway` | new |

## Telemetry

Size-capped files (5 × `GATEWAY_TELEMETRY_FILE_MB` each, default 10 MB, so 150 MB total; replaced by OTLP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set) in `GATEWAY_TELEMETRY_DIR`: `traces.jsonl` (spans `rpc`, `agent.run`, `notify`),
`metrics.jsonl` (`gateway.requests`, `gateway.request.duration`, `gateway.agent.duration`, `gateway.notify.failures`,
`gateway.notify.breaker_opens`; flushed every 60 s and on shutdown), `logs.jsonl` (one JSON line per request and per
finished task: IDs, method, status, timing; never message or reply text). The existing stdout/journal log lines are unchanged.

## Notify webhook

Disabled unless `GATEWAY_NOTIFY_URL` is set. On the configured events the gateway POSTs
`{event, source:"kimiclaw-a2a-gateway", taskId, contextId, timestamp, state?, reply? (first 4000 chars), durationMs?}`
with `Content-Type: application/json` and an `Authorization` header per `GATEWAY_NOTIFY_AUTH_MODE` (10 s timeout).
Circuit breaker: after `GATEWAY_NOTIFY_FAIL_LIMIT` consecutive failures, webhooks pause for `GATEWAY_NOTIFY_COOLDOWN_S`.

Hard rule for the receiving flow: never call back into the gateway for `task_*` events. A single unfiltered round trip
fans out exponentially. The n8n side MUST filter on `event`.

## Known issues (kept on purpose; changing them changes the wire behavior)

- **HTTP 200 on JSON-RPC errors.** -32602 (bad role, empty, >100k chars, non-object params or message, malformed parts, contextId not a string of at most 128 chars), -32601, -32001 and -32000 return HTTP 200; only parse errors (-32700) and a non-object body (-32600) return 400.
- **Inline n8n call.** The notify POST is awaited inside the task (not fire-and-forget). The blocking `message/send` response is released first, but a slow webhook holds the task coroutine for up to 10 s.
- **Cancel then completed.** `tasks/cancel` marks the task canceled but does not stop openclaw; when the run finishes it overwrites the state with `completed` or `failed`.

## Ops

- `systemctl status kimiclaw-gateway cloudflared`
- Logs: `journalctl -u kimiclaw-gateway -f`
- Restart: `systemctl restart kimiclaw-gateway`

## Tests

See TUGBOAT.md. `python -m pytest tests -q`.
