# Kimiclaw A2A Gateway

A2A protocol (v1.0 subset) gateway fronting the local OpenClaw agent.

- Public URL: `https://kimiclaw.hoyack.ai/`
- Agent card: `GET /.well-known/agent.json` (public)
- JSON-RPC: `POST /` (HMAC-signed requests only, per-key rate limits; see "Request signing")
- Origin: uvicorn on `127.0.0.1:8000`, tunnel via cloudflared systemd service

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt            # requirements-dev.txt for tests
export KIMICLAW_TOKEN=...                  # only with GATEWAY_NOTIFY_URL; or KIMICLAW_TOKEN=... in .env (chmod 600)
export GATEWAY_SIGNING_KEYS_FILE=/path/to/keys.txt # caller signing secrets (chmod 600), see "Request signing"
uvicorn app:app --host 127.0.0.1 --port 8000
```
`openclaw` must be on PATH. The app refuses to start without a valid `GATEWAY_SIGNING_KEYS_FILE`, or without `KIMICLAW_TOKEN` when `GATEWAY_NOTIFY_URL` is set.

Docker: `docker build -t kimiclaw-gw . && docker run -e GATEWAY_SIGNING_KEYS_FILE=/keys/keys.txt -v $PWD/keys.txt:/keys/keys.txt:ro -p 8000:8000 kimiclaw-gw`
(the image does not contain openclaw; add it in a derived image or mount it).

## Layout

```
app.py                     entrypoint shim (uvicorn app:app)
gateway/config.py          env settings + .env fallback
gateway/models.py          agent card, wire builders, pydantic schemas (docs only)
gateway/auth.py            signature middleware (per-caller HMAC secrets, nonces, POST / rate limit)
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
| GET | `/readyz` | signed | **new**: 200 if `openclaw` is on PATH, else 503 |

| GET | `/docs`, `/openapi.json` | signed | Swagger UI and spec |

> **`/readyz` returning 503 is by design, not an outage**, when OpenClaw isn't installed (e.g. the stock Docker
> image, CI). Use `/healthz` for liveness; `/readyz` only means "can run agent turns". The Docker HEALTHCHECK uses `/healthz`.

`message/send` is blocking by default. Through Cloudflare it is capped at ~120 s; for longer turns use
`?wait=false` (or `params.configuration.blocking=false`) and poll `tasks/get`, or use `message/stream` (SSE, 15 s keepalives).
A2A `contextId` maps to OpenClaw session `a2a-<caller>-<ctx>`; reuse it to continue a conversation.

### Example
```bash
printf '%s' "$A2A_SECRET" > secret.txt && chmod 600 secret.txt   # or write it there from your secret store
python tools/sign_request.py --key-id "$A2A_KEY_ID" --secret-file secret.txt https://kimiclaw.hoyack.ai/ \
  '{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"Summarize the systemd journal for yesterday"}]}}}'
```
From Python: `httpx.Client(base_url="https://kimiclaw.hoyack.ai", auth=Signer(key_id, secret))` with `Signer` from
`tools/sign_request.py` signs every request the client sends.

## Request signing

Every request except `GET /.well-known/agent.json` and `GET /healthz` carries four headers:

| Header | Value |
|---|---|
| `X-KC-Key-Id` | the caller's key_id (10 lowercase hex chars) |
| `X-KC-Timestamp` | unix time in whole seconds, decimal |
| `X-KC-Nonce` | 16 to 64 chars of `A-Z a-z 0-9 - _`, new for every request (e.g. 24 random bytes, base64url) |
| `X-KC-Signature` | lowercase hex HMAC-SHA256 of the canonical string, keyed with the caller's secret string as ASCII bytes (see below) |

> **Do not base64-decode the secret.** It looks like base64url, but the HMAC key is the secret string itself, as
> ASCII bytes: `hmac.new(secret.encode(), canonical, sha256)`. Decoding it first gives a different key and every request
> fails with 401.

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
duplicate-key rule to get wrong. A proxy in front of the gateway must not rewrite the path, the query or the body.

The gateway checks, in order: each of the four headers present exactly once (a repeated `X-KC-*` header is rejected)
and well formed, the timestamp at most 300 s behind its clock and at most 30 s ahead (`GATEWAY_SIGNATURE_PAST_S`,
`GATEWAY_SIGNATURE_FUTURE_S`) and later than the second the process started in, then a slot for reading the body (see
below), the body is at most 1 MB (else 413), read within the deadlines below (else 408) and hashed chunk by chunk (its
bytes are kept only when the key_id is known, so an unknown key_id costs one chunk of memory), then the signature, compared in constant time over the bytes
it received, before any JSON parsing. An unknown key_id is checked against a random dummy secret, so it costs the same
as a wrong signature and gets the same response. Only a request whose signature verifies has its nonce checked and
recorded. A nonce already used by the same caller within the window is rejected (401). Next, the caller's nonce quota
must have room (else 429, with no bucket token spent). Then every signed request, including `GET /`, `/docs` and
unknown JSON-RPC methods, pays the caller's general token bucket (`GATEWAY_REQUESTS_PER_S`, default 5/s, burst
`GATEWAY_REQUESTS_BURST` 10); when it is empty the caller gets 429 and no nonce is kept. Only then is the nonce
stored. The per-method limits below apply on top.

Bodies are read before the signature can be checked, so reads are pooled by the key_id they claim:

- key_ids not in the keys file share one pool of 32 reads; over that, `503 {"error": "busy"}` with `Retry-After: 1`.
- Each known caller has its own pool of `GATEWAY_READS_PER_CALLER` reads (default 3, allowed 2 to 4, checked at
  startup); over that, that caller gets `429 {"error": "rate limited"}` with `Retry-After: 1`. Its slow or forged
  uploads never touch another caller's pool or the unknown pool.
- Every read has a total deadline (`GATEWAY_BODY_READ_TIMEOUT_S`, default 10 s) and a limit on the gap between chunks
  (`GATEWAY_BODY_IDLE_TIMEOUT_S`, default 5 s); past either the request gets `408 {"error": "request timeout"}`. A
  client that disconnects mid-body gets nothing back and no traceback is logged. The slot is freed whatever happens.
- Refused and failed reads are logged as `read refused pool=<unknown|caller> reason=pool_full key_id=...` or
  `read failed pool=... reason=<too_large|read_deadline|read_idle|client_disconnected> key_id=...`.

Peak RSS stays within tens of MB however many 1 MB unauthenticated bodies arrive, slow uploads with junk key_ids can
no longer 503 a real caller, and since every read ends within 10 s, held reads can't block shutdown for longer than
that. key_ids are not secret (they travel in every request), but they must be unguessable: someone who has a caller's
key_id can fill that caller's small pool and get it 429s. They are 40 random bits from `secrets` and must only be
issued by `tools/new_api_key.py`. A per-IP connection cap belongs at the edge, not in the gateway.

Any rejection is `401 {"error": "unauthorized"}`. The reason (`duplicate_header`, `missing_header`, `malformed_header`, `stale_timestamp`, `stale_after_restart`,
`unknown_key`, `bad_signature`, `replayed_nonce`) goes to the log with the key_id. A header value that isn't shaped like
a key_id is logged as `malformed`, never verbatim, and the secret and the signature are never logged.

Nonces are kept in process memory per caller, each until its timestamp leaves the window, and at most
`GATEWAY_MAX_NONCES_PER_CALLER` (default 20,000) per caller. The general bucket keeps a caller far below that
(5/s × 330 s + 10 ≈ 1,660), so the cap is a backstop. A caller at its cap gets `429 {"error": "rate limited"}` with
`Retry-After` set to when its oldest nonce expires. Only that caller is affected: other callers keep getting 200 and
never 401. Memory is bounded by callers × cap. Per-process state is sound because the
gateway runs one worker. A restart forgets the nonces, so the gateway also rejects (401, reason `stale_after_restart`)
any timestamp from the second it started in or earlier, and holds startup until the next second begins before it
serves (startup takes up to 1 s longer). That covers every request timestamped before the restart. What remains: a
request timestamped up to 30 s in the future (`GATEWAY_SIGNATURE_FUTURE_S`), captured before a restart, can be
replayed once after it until its timestamp falls behind the restart second, so at most 30 s after it was signed. The
cost: right after a restart, requests signed just before it get 401, and a caller whose clock lags by N seconds gets
401 for N seconds after each restart. Callers should re-sign and retry. `Authorization: Bearer` keys are no longer accepted.

### Caller keys

`GATEWAY_SIGNING_KEYS_FILE` holds one `<key_id> <caller> <secret>` line per key (`#` comments allowed). It is the only
place a secret lives: the gateway never reads secrets from env vars or arguments, and never writes them to logs,
telemetry, error messages or probe output. The secret has to be readable by the gateway to check signatures, so this
file is the credential store. Mount it from the secret store, read-only, mode `0400`/`0440` (or `0600`/`0640`).

Startup is refused, with an error that names only the line number, if the file is missing, empty or malformed, if a
key_id repeats, if a caller name isn't 1 to 32 of `A-Z a-z 0-9 _`, if a secret isn't base64url of at least 32 bytes, or
if the file is writable by its group or has any permission for others. Mint a key with

```bash
(umask 077; python tools/new_api_key.py <caller> >> keys.txt)   # stdout: the file line (holds the secret); stderr: the key_id
```

It draws 32 bytes from Python's `secrets` module (the OS CSPRNG). **`tools/new_api_key.py` is the only supported way to
make a secret.** The startup check can only confirm the secret is base64url of at least 32 bytes; it can't tell random
bytes from a hand-typed or derived value. Hand the caller its key_id and secret over a secure channel.

**Rotation.** A caller can have several key_ids at once:
1. Run `new_api_key.py` with the same caller name and add the new line.
2. Restart the gateway, then give the caller the new key_id and secret. Both keys work during the overlap.
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
| `GATEWAY_SIGNING_KEYS_FILE` | required | path to the per-caller signing secrets file (mount it from the secret store, mode 0400/0440; see "Caller keys"). Missing, empty, malformed or open to others refuses startup |
| `GATEWAY_CREATE_PER_MIN` / `GATEWAY_CREATE_BURST` | `10` / `5` | per caller: `message/send` + `message/stream` token bucket |
| `GATEWAY_GET_PER_S` | `2` | per caller: `tasks/get` |
| `GATEWAY_CANCEL_PER_S` | `1` | per caller: `tasks/cancel` |
| `GATEWAY_MAX_INFLIGHT_PER_KEY` | `2` | per caller (all its key_ids): running or queued tasks; more gets 429 (`Retry-After: 5`). Must stay below the 3 agent slots, or startup fails, so one caller can't hold them all |
| `WEB_CONCURRENCY` | `1` | anything but 1 refuses startup (limits are per process) |
| `GATEWAY_MAX_PENDING` | `50` | all callers: running or queued tasks; more gets 429 |
| `GATEWAY_REQUESTS_PER_S` / `GATEWAY_REQUESTS_BURST` | `5` / `10` | per caller: every signed request (any path or method), checked before its nonce is stored; empty gets 429 |
| `GATEWAY_MAX_NONCES_PER_CALLER` | `20000` | per caller: live nonces kept for replay checks; more gets 429 until the oldest expires |
| `GATEWAY_SIGNATURE_PAST_S` / `GATEWAY_SIGNATURE_FUTURE_S` | `300` / `30` | how far behind / ahead of the gateway clock a signed timestamp may be; ahead must not exceed behind |
| `GATEWAY_READS_PER_CALLER` | `3` | per caller: bodies read at once before the signature is checked (2 to 4); more gets 429 |
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
