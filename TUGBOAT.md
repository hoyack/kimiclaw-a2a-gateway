# For Tugboat: test commands (CI workflow is yours; none is committed here)

Python 3.13. No secrets or network access needed; tests use a fake `openclaw` (tests/fakebin) and a local mock n8n receiver.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests -q          # characterization + contract tests, ~35 s
```

Contract check only: `python -m pytest tests/test_contract.py -q`
If routes or schemas change on purpose: run `tools/freeze_openapi.py` (its docstring shows how to make a throwaway keys file) and commit openapi.yaml. Tests mint fresh signing secrets in a temp dir each run; none are committed.

Golden replay (parity against fixtures recorded from original main, vendored in tests/golden/):
```bash
python tests/golden/golden.py replay-local --app-dir .   # expect "[default] 24 passed" and "[n8n_basic] 2 passed"
```
Everything at once (pytest + golden replay, non-zero exit on failure): `./check.sh` (uses `.venv/bin/python` if
present, else `python`).
Docker: the committed Dockerfile CMD is still `["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]` and must be overridden. `uvicorn app:app` now refuses to start.

## Deploy contract

CMD must be `["python", "-m", "gateway"]` (optionally `--host 0.0.0.0 --port 8000`). That is the only supported launcher: it pins `workers=1` and `ws=none` (so a websocket upgrade cannot bypass the header timer), applies `KIMICLAW_LIMIT_CONCURRENCY`, starts the probe listener immediately, and arms the request-header timeout. Do not pass `--limit-concurrency` or `--workers`. `uvicorn app:app` and `uvicorn --factory gateway.main:create_app` are refused.

Do not run uvicorn directly as PID 1 (for example as a container entrypoint without a supervisor). The kernel drops default-action signals sent to PID 1, so a refused `uvicorn --workers` process would not exit (it still never serves). CMD is `python -m gateway`.

Publish two ports:

| Listener | Default | Routes | Cap |
| --- | --- | --- | --- |
| Main | 8000 (`--port`) | `/`, `/docs`, `/.well-known/agent.json`, and also `/healthz` + `/readyz` **inside the cap** | `KIMICLAW_LIMIT_CONCURRENCY` (required, 64–4096, recommended 1024) |
| Probe | `GATEWAY_PROBE_PORT` (default **8001**) | a separate tiny ASGI app (not the main app): only `GET /healthz` and `GET /readyz`. Everything else, including signed `/` or `/.well-known/agent.json` and `POST /healthz`, is 404. No auth, no middleware, no cap, no telemetry | none |

Kubernetes probes must use the probe port, not 8000:

- **Startup and liveness:** `GET :8001/healthz`. Returns 200 `{"status":"up"}` as soon as the process is up, **including during the startup hold** of `GATEWAY_SIGNATURE_FUTURE_S + 1` seconds (~31 s by default). The probe listener is bound before that hold begins. Bodies carry no version, config or caller data.
- **Readiness:** `GET :8001/readyz`. Returns 503 `{"status":"starting"}` during the hold and 200 `{"status":"ready"}` once the main port is serving. If `GATEWAY_REQUIRE_OPENCLAW` is on (the default: only the exact string `0` turns it off) and `openclaw` is not on PATH, it stays 503 `{"status":"not ready"}`. The v1 manifest sets `GATEWAY_REQUIRE_OPENCLAW=0` so the stock image becomes ready without OpenClaw (`message/send` will still fail until it is installed); the openclaw release turns the flag back on. Even with the flag at `0`, a signed `message/send` or `message/stream` fails closed with a generic HTTP 503 (`{"jsonrpc":"2.0",... "message":"agent unavailable"}`) if `openclaw` is missing; the body and logs do not name the binary or a path.

Move the image HEALTHCHECK from `:8000/healthz` to `:8001/healthz`. Publish 8001 as well as 8000.

A buffering reverse proxy (ingress nginx or equivalent) with request buffering on and no idle upstream connections is required in front of the gateway for any public deploy; client header and body timeouts on it are recommended. The app timer (`GATEWAY_HEADER_TIMEOUT_S`, default 5 s, range 1–30) is defense in depth and applies to both the main port and the probe port (re-armed at connect and after each keep-alive response). The probe port has no connection cap, so a pile of idle probe connections cannot turn into a liveness failure; they are just closed after the header timeout. uvicorn 0.54 counts idle and partial-header connections toward `limit_concurrency` and will not time them out on its own; without a proxy (and without the app timer) cap-many idle TCP connections 503 the main port, including its own `/healthz`; probes belong on the uncapped probe port.

Required / relevant env:

| Name | Default | Notes |
| --- | --- | --- |
| `KIMICLAW_LIMIT_CONCURRENCY` | required | integer 64–4096, `^[1-9][0-9]*$` only (no whitespace, no leading zeros) |
| `GATEWAY_PROBE_PORT` | `8001` | 1–65535, `^[1-9][0-9]*$` only, must differ from the main port |
| `GATEWAY_HEADER_TIMEOUT_S` | `5` | 1–30, `^[1-9][0-9]*$` only (no whitespace, no leading zeros) |
| `GATEWAY_REQUIRE_OPENCLAW` | on (unset) | only the exact string `0` turns it off. v1 manifest sets `0`; the openclaw release turns it back on |
| `GATEWAY_PUBLIC_KEYS_FILE` | required | see README |
| `GATEWAY_SIGNATURE_FUTURE_S` | `30` | hold is this plus 1 second |
| `WEB_CONCURRENCY` | `1` | anything but 1 refuses startup |

- Telemetry file rotation assumes a single uvicorn worker; `python -m gateway` pins that.
