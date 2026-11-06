"""Wire shapes. AGENT_CARD and the builders return plain dicts so serialization stays byte-identical."""
import json
import uuid
from datetime import datetime, timezone

AGENT_CARD = {
    "protocolVersion": "1.0",
    "name": "Kimiclaw",
    "description": "A2A gateway into the OpenClaw agent (kimi-claw). Research, code, ops, writing, automation.",
    "url": "https://kimiclaw.hoyack.ai/",
    "provider": {"organization": "hoyack"},
    "version": "0.1.0",
    "capabilities": {
        "streaming": True,
        "pushNotifications": False,
        "stateTransitionHistory": False,
    },
    "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
    "security": [{"bearerAuth": []}],
    "defaultInputModes": ["text"],
    "defaultOutputModes": ["text"],
    "skills": [
        {
            "id": "general-agent",
            "name": "General agent",
            "description": "General-purpose agent: research, coding, shell ops, writing, planning, automation.",
            "tags": ["general-purpose", "agent", "openclaw"],
        }
    ],
    "supportsAuthenticatedExtendedCard": False,
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def rpc_error(req_id, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def make_agent_message(text: str) -> dict:
    return {
        "role": "agent",
        "parts": [{"kind": "text", "text": text}],
        "messageId": str(uuid.uuid4()),
    }


def extract_text(msg: dict) -> str:
    out = []
    for p in msg.get("parts") or []:
        kind = p.get("kind")
        if kind == "text":
            out.append(p.get("text", ""))
        elif kind == "data":
            out.append(json.dumps(p.get("data")))
        elif kind == "file":
            name = (p.get("file") or {}).get("name", "?")
            out.append(f"[file: {name}]")
    return "\n".join(out).strip()


# ---- Pydantic schemas: documentation only (OpenAPI). POST / still parses raw JSON so error
# codes and HTTP statuses stay exactly as before; these are never used to validate requests.
from typing import Any, Literal, Optional, Union  # noqa: E402

from pydantic import BaseModel, Field  # noqa: E402


class Part(BaseModel):
    kind: Literal["text", "data", "file"]
    text: Optional[str] = None
    data: Optional[Any] = None
    file: Optional[dict] = None


class Message(BaseModel):
    role: Optional[Literal["user"]] = Field(None, description="Only 'user' (or omitted) is accepted")
    messageId: Optional[str] = None
    parts: list[Part]
    taskId: Optional[str] = Field(None, description="Reuse or set the task id; generated if absent")
    contextId: Optional[str] = Field(None, description="Maps to OpenClaw session a2a-<contextId>")


class SendConfiguration(BaseModel):
    blocking: Optional[bool] = Field(None, description="false returns the task immediately (submitted)")


class RpcParams(BaseModel):
    message: Optional[Message] = Field(None, description="message/send, message/stream")
    configuration: Optional[SendConfiguration] = None
    id: Optional[str] = Field(None, description="tasks/get, tasks/cancel")
    taskId: Optional[str] = Field(None, description="alias of id for tasks/get, tasks/cancel")


class JsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: Union[str, int, None] = None
    method: Literal["message/send", "message/stream", "tasks/get", "tasks/cancel"]
    params: RpcParams = RpcParams()


class RpcError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class JsonRpcResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: Union[str, int, None] = None
    result: Optional[dict] = Field(None, description="Task, or SSE event when streaming")
    error: Optional[RpcError] = None


SCHEMAS = [JsonRpcRequest, JsonRpcResponse]
