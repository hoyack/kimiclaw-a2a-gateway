"""Routing logic. Jira and the gateway are ports so tests can fake them.

Jira is the only dedupe store: the queue JQL only matches To Do, the claim moves the task to
In Progress, and signed comments mark pickup and result. Logs carry issue keys and error types only.
"""
import logging
import time

LOG = logging.getLogger("routing")
BOTS = ("rivet", "tugboat", "critic", "bastion", "cpo", "cto", "brandon")
TODO, IN_PROGRESS = "To Do", "In Progress"
ATTEMPTS, BACKOFF = 3, (1, 4)


class HandoffError(Exception):
    """Gateway handoff failed. kind is a short type name, safe to put in a comment."""
    def __init__(self, kind, retryable=None):
        super().__init__(kind)
        self.kind = kind
        self.retryable = kind != "agent_failed" if retryable is None else retryable


def queue_jql(bot):
    if bot not in BOTS:
        raise ValueError(f"unknown bot: {bot}")
    return f'project=A2A AND labels=owner_{bot} AND status="To Do"'


def owner_of(labels):
    owners = [l[len("owner_"):] for l in labels if l.startswith("owner_")]
    return owners[0] if len(owners) == 1 and owners[0] in BOTS else None


def lint(issues):
    """A2A-64 check: tasks with missing or multiple owner_ labels."""
    bad = []
    for i in issues:
        n = sum(l.startswith("owner_") for l in i["labels"])
        if n != 1:
            bad.append((i["key"], "missing owner_ label" if n == 0 else "multiple owner_ labels"))
    return bad


def sig(bot):
    return f"[{bot}]"


def with_retry(fn, sleep, attempts=ATTEMPTS):
    for n in range(attempts):
        try:
            return fn()
        except HandoffError as e:
            if not e.retryable or n == attempts - 1:
                raise
        except OSError as e:  # urllib/socket errors from Jira or the gateway
            if n == attempts - 1:
                raise HandoffError(type(e).__name__) from e
        sleep(BACKOFF[min(n, len(BACKOFF) - 1)])


def post_result(bot, jira, key, text, sleep):
    head = f"{sig(bot)} result"
    if any(c.startswith(head) for c in with_retry(lambda: jira.comments(key), sleep)):
        return
    with_retry(lambda: jira.comment(key, f"{head}\n\n{text}"), sleep)


def _fail(bot, jira, key, kind, sleep):
    LOG.warning("handoff failed key=%s error_type=%s", key, kind)
    with_retry(lambda: jira.comment(key, f"{sig(bot)} failed: {kind}"), sleep)
    with_retry(lambda: jira.transition(key, TODO), sleep)


def process(bot, jira, gw, issue, sleep):
    """Returns 'completed', 'failed' or 'skipped'."""
    key = issue["key"]
    if owner_of(issue["labels"]) != bot or not (issue.get("summary") or "").strip():
        LOG.info("skip malformed key=%s", key)
        return "skipped"
    # Re-read right before claiming: the search result may be stale if another poll ran.
    if jira.status(key) != TODO or any(c.startswith(f"{sig(bot)} picked up") for c in jira.comments(key)):
        return "skipped"
    with_retry(lambda: jira.transition(key, IN_PROGRESS), sleep)
    with_retry(lambda: jira.comment(key, f"{sig(bot)} picked up"), sleep)
    text = f"{key}: {issue['summary'].strip()}\n\n{(issue.get('description') or '').strip()}".strip()
    try:
        reply = with_retry(lambda: gw.run(key, text), sleep)
    except HandoffError as e:
        _fail(bot, jira, key, e.kind, sleep)
        return "failed"
    post_result(bot, jira, key, reply, sleep)
    return "completed"


def poll_once(bot, jira, gw, sleep=time.sleep):
    out = {"completed": [], "failed": [], "skipped": []}
    for issue in jira.search(queue_jql(bot)):
        try:
            result = process(bot, jira, gw, issue, sleep)
        except HandoffError as e:  # Jira itself failed after retries; next poll picks it up again
            LOG.error("jira error key=%s error_type=%s", issue["key"], e.kind)
            result = "failed"
        out[result].append(issue["key"])
    return out
