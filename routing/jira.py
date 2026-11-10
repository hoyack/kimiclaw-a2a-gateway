"""Jira Cloud REST v3 adapter for the router's Jira port. Basic auth: service account email + API token."""
import base64
import urllib.parse

from routing.http import call
from routing.router import HandoffError

FIELDS = "summary,description,labels,status"


def adf_text(node):
    """Plain text from an Atlassian Document Format node (paragraphs become lines)."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    if node.get("type") == "text":
        return node.get("text", "")
    if node.get("type") == "hardBreak":
        return "\n"
    sep = "\n" if node.get("type") in ("doc", "bulletList", "orderedList") else ""
    return sep.join(adf_text(c) for c in node.get("content", []))


def adf_doc(text):
    return {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": line}] if line else []}
        for line in text.split("\n")]}


class Jira:
    def __init__(self, base_url, email, token):
        self.base = base_url.rstrip("/") + "/rest/api/3"
        cred = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.auth = {"Authorization": f"Basic {cred}"}

    def _get(self, path):
        return call("GET", self.base + path, self.auth)

    def search(self, jql):
        out, token = [], None
        while True:
            q = {"jql": jql, "fields": FIELDS, "maxResults": 50, **({"nextPageToken": token} if token else {})}
            page = self._get("/search/jql?" + urllib.parse.urlencode(q))
            for i in page.get("issues", []):
                f = i["fields"]
                out.append({"key": i["key"], "summary": f.get("summary") or "", "labels": f.get("labels") or [],
                            "status": f["status"]["name"], "description": adf_text(f.get("description"))})
            token = page.get("nextPageToken")
            if page.get("isLast", True) or not token:
                return out

    def status(self, key):
        return self._get(f"/issue/{key}?fields=status")["fields"]["status"]["name"]

    def comments(self, key):
        page = self._get(f"/issue/{key}/comment?maxResults=100&orderBy=created")
        return [adf_text(c["body"]) for c in page.get("comments", [])]

    def transition(self, key, status):
        ts = self._get(f"/issue/{key}/transitions")["transitions"]
        tid = next((t["id"] for t in ts if t["to"]["name"] == status), None)
        if tid is None:
            raise HandoffError("no_transition", retryable=False)
        call("POST", f"{self.base}/issue/{key}/transitions", self.auth, {"transition": {"id": tid}})

    def comment(self, key, body):
        call("POST", f"{self.base}/issue/{key}/comment", self.auth, {"body": adf_doc(body)})
