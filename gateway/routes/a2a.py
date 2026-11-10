"""HTTP routes. Handlers stay thin; logic lives in controllers/services."""
from fastapi import APIRouter, Request

from gateway.controllers.rpc import handle_rpc
from gateway.models import AGENT_CARD

router = APIRouter()


@router.get("/")
async def root():
    return {
        "service": "kimiclaw-a2a-gateway",
        "protocol": "A2A 1.0",
        "agent_card": "/.well-known/agent.json",
        "rpc": "POST / (JSON-RPC 2.0)",
    }


@router.get("/.well-known/agent.json")
async def agent_card():
    return AGENT_CARD


RPC_DOC = {
    "summary": "A2A JSON-RPC 2.0",
    "description": "Validation errors (-32602), unknown method (-32601), not found (-32001) and gateway "
                   "timeout (-32000) return HTTP 200 with a JSON-RPC error. Parse error returns 400.",
    "parameters": [{"name": "wait", "in": "query", "required": False, "schema": {"type": "string", "default": "true"},
                    "description": "message/send only: 'false' returns the task immediately"}],
    "requestBody": {"required": True, "content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/JsonRpcRequest"}}}},
    "responses": {"200": {"description": "JSON-RPC response, or text/event-stream for message/stream",
                          "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonRpcResponse"}},
                                      "text/event-stream": {"schema": {"type": "string"}}}},
                  "400": {"description": "parse error (-32700)"}, "401": {"description": "unauthorized"}},
}


@router.post("/", openapi_extra=RPC_DOC)
async def rpc(request: Request):
    return await handle_rpc(request)
