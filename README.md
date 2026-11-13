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
A2A `contextId` maps to OpenClaw session `a2a-<ctx>`; reuse it to continue a conversation.

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
| `X-KC-Signature` | lowercase hex HMAC-SHA256 of the canonical string, keyed with the caller's secret (its ASCII bytes) |

The canonical string is five lines joined by `\n` (no trailing newline):

```
METHOD                  upper case, e.g. POST
PATH[?SORTED_QUERY]     see below
TIMESTAMP               the X-KC-Timestamp value
NONCE                   the X-KC-Nonce value
BODY_SHA256             lowercase hex sha256 of the raw body bytes (sha256 of empty for GET)
```

`PATH` is the request path exactly as sent on the wire, still percent-encoded, without scheme, host or fragment.
`SORTED_QUERY` is the raw query string as sent (the part after `?`), split on `&`, empty pieces dropped, the pieces
sorted by byte value and joined with `&`. Nothing is decoded or re-encoded. With no query, or an empty one, the line is
the path alone with no `?`. Example: `POST /?wait=false&b=2` signs the line `/?b=2&wait=false`. A proxy in front of the
gateway must not rewrite the path or query.

The gateway checks, in order: all four headers present and well formed, the key_id is in the keys file, the timestamp is
within 300 s of its clock (either direction), the body is at most 1 MB (else 413), the signature matches (constant-time
compare over the raw body, before any JSON parsing), and the nonce has not been used by that key_id within the window.
Any failure is `401 {"error": "unauthorized"}`; the reason (`missing_header`, `malformed_header`, `unknown_key`,
`stale_timestamp`, `bad_signature`, `replayed_nonce`, `nonce_cache_full`) goes to the log with the key_id, never the
secret or the signature. Nonces are remembered in process memory (up to 100,000, each until its timestamp leaves the
window), which is sound because the gateway runs one worker. A restart forgets them, but a request captured before a
restart is still bound to its timestamp, so it can only be replayed inside the same 300 s. `Authorization: Bearer`
keys are no longer accepted.

### Caller keys

The gateway keeps one `<key_id> <caller> <secret>` line per caller in `GATEWAY_SIGNING_KEYS_FILE` (`#` comments
allowed). The secret has to be readable by the gateway to check signatures, so this file is the credential store: mount
it from the secret store, read-only, mode `0400`/`0440` (or `0600`/`0640`). Startup is refused if it is missing, empty,
malformed, writable by its group, or has any permission for others. Mint a caller with

```bash
python tools/new_api_key.py <caller> >> keys.txt   # stdout: the file line (holds the secret); stderr: the key_id
```

and hand the caller its key_id and secret over a secure channel. Revoke a caller by deleting its line and restarting. A
caller can hold two key_ids during rotation.

Tasks belong to the key_id that created them: task ids are minted by the gateway (a client `taskId` is ignored), other
key_ids get "task not found" on `tasks/get`/`tasks/cancel`, and the agent session is `a2a-<key_id>-<contextId>`, so a
caller can't join another caller's session. The agent runs with only `PATH`, `HOME`, `LANG`, `LC_ALL` and `TZ` from the
gateway env, gets the message on stdin (`--message-file -`, no temp file), and callers see `agent error (task <id>)`
instead of agent stderr.

Logs carry the `key_id`, never the secret. Over a limit: 429 with `Retry-After`; `POST /` bodies over 1 MB: 413.
Limits are in-process, per replica, so run exactly one replica with one worker (the gateway logs this at startup). More
replicas or workers multiply every limit.

## Environment variables (names only)

See `.env.example` for a placeholder template. For the n8n A2A_Firewall webhook set `GATEWAY_NOTIFY_AUTH_MODE=basic`
(the default `raw` will be rejected by that webhook's Basic auth).


| Name | Default | Purpose |
|---|---|---|
| `KIMICLAW_TOKEN` | required only when `GATEWAY_NOTIFY_URL` is set (env or `.env`) | outbound notify credential; never accepted inbound |
| `GATEWAY_SIGNING_KEYS_FILE` | required | path to the per-caller signing secrets file (mount it from the secret store, mode 0400/0440; see "Caller keys"). Missing, empty, malformed or open to others refuses startup |
| `GATEWAY_CREATE_PER_MIN` / `GATEWAY_CREATE_BURST` | `10` / `5` | per key: `message/send` + `message/stream` token bucket |
| `GATEWAY_GET_PER_S` | `2` | per key: `tasks/get` |
| `GATEWAY_CANCEL_PER_S` | `1` | per key: `tasks/cancel` |
| `GATEWAY_MAX_INFLIGHT_PER_KEY` | `2` | per key: running or queued tasks; more gets 429 (`Retry-After: 5`). Must stay below the 3 agent slots, or startup fails, so one key can't hold them all |
| `WEB_CONCURRENCY` | `1` | anything but 1 refuses startup (limits are per process) |
| `GATEWAY_MAX_PENDING` | `50` | all keys: running or queued tasks; more gets 429 |
| `GATEWAY_MAX_TASKS_PER_KEY` | `100` | per key: stored tasks; the oldest finished ones are dropped past this |
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
