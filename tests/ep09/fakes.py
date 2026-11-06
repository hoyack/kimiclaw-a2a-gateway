"""In-memory fakes for Jira and the A2A gateway. No network."""
from routing.router import HandoffError


class FakeJira:
    def __init__(self, issues):
        # issues: {key: {"summary", "description", "labels", "status"}}
        self.issues = {k: dict(v, comments=[]) for k, v in issues.items()}
        self.transitions = []

    def search(self, jql):
        # Supports only the queue JQL shape: labels=owner_X AND status="To Do".
        label = jql.split("labels=")[1].split(" ")[0]
        return [dict(key=k, **{f: v[f] for f in ("summary", "description", "labels", "status")})
                for k, v in self.issues.items() if label in v["labels"] and v["status"] == "To Do"]

    def status(self, key):
        return self.issues[key]["status"]

    def comments(self, key):
        return list(self.issues[key]["comments"])

    def transition(self, key, status):
        self.transitions.append((key, status))
        self.issues[key]["status"] = status

    def comment(self, key, body):
        self.issues[key]["comments"].append(body)


class FakeGateway:
    def __init__(self, reply="done", fail=None, on_run=None):
        self.calls = []
        self.reply, self.fail, self.on_run = reply, fail, on_run

    def run(self, key, text):
        self.calls.append((key, text))
        if self.on_run:
            self.on_run()
        if self.fail:
            raise HandoffError(self.fail)
        return self.reply
