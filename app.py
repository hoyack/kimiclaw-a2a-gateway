"""Kimiclaw A2A Gateway entrypoint (kept so `uvicorn app:app` is unchanged).

Exposes the local OpenClaw agent over the A2A protocol (v1.0 subset).
Public: agent card at /.well-known/agent.json
Bearer-protected: JSON-RPC at / (message/send, message/stream, tasks/get, tasks/cancel)
"""

from gateway.main import app  # noqa: F401
