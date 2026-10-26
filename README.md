# Kimiclaw A2A Gateway

A2A protocol (v1.0 subset) gateway fronting the local OpenClaw agent.

- Public URL: `https://kimiclaw.hoyack.ai/`
- Agent card: `GET /.well-known/agent.json` (public)
- JSON-RPC: `POST /` (bearer token required)
- Origin: uvicorn on `127.0.0.1:8000`, tunnel via cloudflared systemd service

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt            # requirements-dev.txt for tests
export KIMICLAW_TOKEN=...                  # or put KIMICLAW_TOKEN=... in .env (chmod 600, gitignored)
uvicorn app:app --host 127.0.0.1 --port 8000
```
`openclaw` must be on PATH. The app refuses to start without `KIMICLAW_TOKEN`.

Docker: `docker build -t kimiclaw-gw . && docker run -e KIMICLAW_TOKEN -p 8000:8000 kimiclaw-gw`
(the image does not contain openclaw; add it in a derived image or mount it).

## Layout

```
app.py                     entrypoint shim (uvicorn app:app)
gateway/config.py          env settings + .env fallback
gateway/models.py          agent card, wire builders, pydantic schemas (docs only)
gateway/auth.py            bearer middleware
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
| POST | `/` | bearer | JSON-RPC: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel` |
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
curl -s https://kimiclaw.hoyack.ai/ -H "Authorization: Bearer $KIMICLAW_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"Summarize the systemd journal for yesterday"}]}}}'
```

## Environment variables (names only)

See `.env.example` for a placeholder template. For the n8n A2A_Firewall webhook set `GATEWAY_NOTIFY_AUTH_MODE=basic`
(the default `raw` will be rejected by that webhook's Basic auth).


| Name | Default | Purpose |
|---|---|---|
| `KIMICLAW_TOKEN` | required (env or `.env`) | inbound bearer token; also the outbound notify credential |
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

Daily-rotated files (7 days kept; replaced by OTLP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set) in `GATEWAY_TELEMETRY_DIR`: `traces.jsonl` (spans `rpc`, `agent.run`, `notify`),
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

- **HTTP 200 on JSON-RPC errors.** -32602 (bad role, empty, >200k chars), -32601, -32001 and -32000 return HTTP 200; only parse errors return 400. A non-object JSON body returns a plain 500.
- **Inline n8n call.** The notify POST is awaited inside the task (not fire-and-forget). The blocking `message/send` response is released first, but a slow webhook holds the task coroutine for up to 10 s.
- **Cancel then completed.** `tasks/cancel` marks the task canceled but does not stop openclaw; when the run finishes it overwrites the state with `completed` or `failed`.
- **Shared token.** `KIMICLAW_TOKEN` is both the inbound bearer token and the outbound webhook credential. Rotating it means updating the n8n side too.

## Ops

- `systemctl status kimiclaw-gateway cloudflared`
- Logs: `journalctl -u kimiclaw-gateway -f`
- Restart: `systemctl restart kimiclaw-gateway`

## Tests

See TUGBOAT.md. `python -m pytest tests -q`.
