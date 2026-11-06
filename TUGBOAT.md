# For Tugboat: test commands (CI workflow is yours; none is committed here)

Python 3.13. No secrets or network access needed; tests use a fake `openclaw` (tests/fakebin) and a local mock n8n receiver.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests -q          # characterization + contract tests, ~35 s
```

Contract check only: `python -m pytest tests/test_contract.py -q`
If routes or schemas change on purpose: `KIMICLAW_TOKEN=x python tools/freeze_openapi.py` and commit openapi.yaml.

Golden replay (parity against fixtures recorded from original main, vendored in tests/golden/):
```bash
python tests/golden/golden.py replay-local --app-dir .   # expect "[default] 24 passed" and "[n8n_basic] 2 passed"
```
Everything at once (pytest + golden replay, non-zero exit on failure): `./check.sh` (uses `.venv/bin/python` if
present, else `python`).
Docker smoke: `docker build -t kimiclaw-gw .`; the HEALTHCHECK hits public `/healthz`.

**`/readyz` returns 503 without OpenClaw installed. That is by design, not an outage.** CI and the stock image
have no `openclaw`, so expect 503 there (tests cover it). Probe `/healthz` (public, `{"status":"ok"}`) for liveness.

- Daily telemetry log rotation assumes a single uvicorn worker; multiple workers would race on rotation.
