# Kimiclaw A2A Gateway

A2A protocol (v1.0 subset) gateway fronting the local OpenClaw agent.

- Public URL: `https://kimiclaw.hoyack.ai/`
- Agent card: `GET /.well-known/agent.json` (public)
- JSON-RPC: `POST /` (per-caller key required, per-key rate limits; see "Caller keys")
- Origin: uvicorn on `127.0.0.1:8000`, tunnel via cloudflared systemd service

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt            # requirements-dev.txt for tests
export KIMICLAW_TOKEN=...                  # only with GATEWAY_NOTIFY_URL; or KIMICLAW_TOKEN=... in .env (chmod 600)
export GATEWAY_KEYS_FILE=/path/to/keys.txt # hashed caller keys, see "Caller keys"
uvicorn app:app --host 127.0.0.1 --port 8000
```
`openclaw` must be on PATH. The app refuses to start without a valid `GATEWAY_KEYS_FILE`, or without `KIMICLAW_TOKEN` when `GATEWAY_NOTIFY_URL` is set.

Docker: `docker build -t kimiclaw-gw . && docker run -e GATEWAY_KEYS_FILE=/keys/keys.txt -v $PWD/keys.txt:/keys/keys.txt:ro -p 8000:8000 kimiclaw-gw`
(the image does not contain openclaw; add it in a derived image or mount it).

## Layout

```
app.py                     entrypoint shim (uvicorn app:app)
gateway/config.py          env settings + .env fallback
gateway/models.py          agent card, wire builders, pydantic schemas (docs only)
gateway/auth.py            bearer middleware (per-caller keys, POST / rate limit)
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
| GET | `/` | bearer | service info |
| POST | `/` | bearer | JSON-RPC: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`. 429 + `Retry-After` over the caller's rate limit |
| GET | `/healthz` | public | **new**: liveness, returns only `{"status":"ok"}` (no version/config) |
| GET | `/readyz` | bearer | **new**: 200 if `openclaw` is on PATH, else 503 |

| GET | `/docs`, `/openapi.json` | bearer | Swagger UI and spec |

> **`/readyz` returning 503 is by design, not an outage**, when OpenClaw isn't installed (e.g. the stock Docker
> image, CI). Use `/healthz` for liveness; `/readyz` only means "can run agent turns". The Docker HEALTHCHECK uses `/healthz`.

`message/send` is blocking by default. Through Cloudflare it is capped at ~120 s; for longer turns use
`?wait=false` (or `params.configuration.blocking=false`) and poll `tasks/get`, or use `message/stream` (SSE, 15 s keepalives).
A2A `contextId` maps to OpenClaw session `a2a-<ctx>`; reuse it to continue a conversation.

### Example
```bash
curl -s https://kimiclaw.hoyack.ai/ -H "Authorization: Bearer $A2A_KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"Summarize the systemd journal for yesterday"}]}}}'
```

## Caller keys

Each caller gets its own key, `kc_<key_id>_<secret>` (10-char hex id, 32 random bytes), sent as
`Authorization: Bearer <key>` on everything except `/.well-known/agent.json` and `/healthz`. The gateway stores only
`<key_id> <sha256 of the key> <caller>` lines in `GATEWAY_KEYS_FILE` (`#` comments allowed). Mint one with

```bash
python tools/new_api_key.py <caller> >> keys.txt   # stdout: the file line; stderr: the key, shown once
```

Tasks belong to the key that created them: task ids are minted by the gateway (a client `taskId` is ignored), other
keys get "task not found" on `tasks/get`/`tasks/cancel`, and the agent session is `a2a-<key_id>-<contextId>`, so a
caller can't join another key's session. The agent runs with only `PATH`, `HOME`, `LANG`, `LC_ALL` and `TZ` from the
gateway env, gets the message on stdin (`--message-file -`, no temp file), and callers see `agent error (task <id>)`
instead of agent stderr.

Give the key to the caller once; it is not stored anywhere. Revoke a key by deleting its line and restarting. A caller
can hold two keys during rotation. Logs carry the `key_id`, never the key or its hash. Over a limit: 429 with
`Retry-After`; `POST /` bodies over 1 MB: 413. Limits are in-process, per replica, so run exactly one replica with one worker (the gateway logs this at
startup). More replicas or workers multiply every limit.

## Environment variables (names only)

See `.env.example` for a placeholder template. For the n8n A2A_Firewall webhook set `GATEWAY_NOTIFY_AUTH_MODE=basic`
(the default `raw` will be rejected by that webhook's Basic auth).


| Name | Default | Purpose |
|---|---|---|
| `KIMICLAW_TOKEN` | required only when `GATEWAY_NOTIFY_URL` is set (env or `.env`) | outbound notify credential; never accepted inbound |
| `GATEWAY_KEYS_FILE` | required | path to the hashed API keys file (mount it from a Secret; see "Caller keys"). Missing, empty or malformed refuses startup |
| `GATEWAY_CREATE_PER_MIN` / `GATEWAY_CREATE_BURST` | `10` / `5` | per key: `message/send` + `message/stream` token bucket |
| `GATEWAY_GET_PER_S` | `2` | per key: `tasks/get` |
| `GATEWAY_CANCEL_PER_S` | `1` | per key: `tasks/cancel` |
| `GATEWAY_MAX_INFLIGHT_PER_KEY` | `3` | per key: running or queued tasks; more gets 429 (`Retry-After: 5`) |
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

- **HTTP 200 on JSON-RPC errors.** -32602 (bad role, empty, >100k chars), -32601, -32001 and -32000 return HTTP 200; only parse errors return 400. A non-object JSON body returns a plain 500.
- **Inline n8n call.** The notify POST is awaited inside the task (not fire-and-forget). The blocking `message/send` response is released first, but a slow webhook holds the task coroutine for up to 10 s.
- **Cancel then completed.** `tasks/cancel` marks the task canceled but does not stop openclaw; when the run finishes it overwrites the state with `completed` or `failed`.

## Ops

- `systemctl status kimiclaw-gateway cloudflared`
- Logs: `journalctl -u kimiclaw-gateway -f`
- Restart: `systemctl restart kimiclaw-gateway`

## Tests

See TUGBOAT.md. `python -m pytest tests -q`.
