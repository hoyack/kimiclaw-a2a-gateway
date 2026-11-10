"""A2A JSON-RPC client for kimiclaw-a2a-gateway: message/send (non-blocking) then tasks/get until final.

Non-blocking because the gateway sits behind Cloudflare's ~120s proxy timeout. The issue key is the
taskId, contextId and messageId, so the bot's session (a2a-<key>) and gateway logs tie back to the ticket.
"""
import time

from routing.http import call
from routing.router import HandoffError


class Gateway:
    def __init__(self, url, token, poll_every=10, max_polls=90, sleep=time.sleep):
        self.url, self.auth = url.rstrip("/") + "/", {"Authorization": f"Bearer {token}"}
        self.poll_every, self.max_polls, self.sleep = poll_every, max_polls, sleep

    def _rpc(self, rid, method, params):
        res = call("POST", self.url, self.auth, {"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        if res.get("error"):
            raise HandoffError(f"rpc_error_{res['error'].get('code')}")
        return res["result"]

    def run(self, key, text):
        msg = {"role": "user", "messageId": key, "taskId": key, "contextId": key,
               "parts": [{"kind": "text", "text": text}]}
        task = self._rpc(f"{key}-send", "message/send", {"message": msg, "configuration": {"blocking": False}})
        for n in range(self.max_polls):
            if task.get("final"):
                break
            self.sleep(self.poll_every)
            task = self._rpc(f"{key}-get-{n}", "tasks/get", {"id": key})
        else:
            if not task.get("final"):
                raise HandoffError("gateway_timeout", retryable=False)
        state = task["status"]["state"]
        if state != "completed":
            raise HandoffError(f"agent_{state}", retryable=False)
        return "\n".join(p.get("text", "") for a in task.get("artifacts", []) for p in a.get("parts", [])
                         if p.get("kind") == "text").strip()
