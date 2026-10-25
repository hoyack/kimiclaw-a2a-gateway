import pytest

from routing.router import BOTS, OWNERS, lint, owner_of, poll_once, queue_jql
from tests.ep09.fakes import FakeGateway, FakeJira

NOSLEEP = lambda s: None


def task(labels=("owner_rivet",), status="To Do", summary="Do X", description="details"):
    return {"summary": summary, "description": description, "labels": list(labels), "status": status}


def test_queue_jql():
    assert queue_jql("rivet") == 'project=A2A AND labels=owner_rivet AND status="To Do"'
    with pytest.raises(ValueError):
        queue_jql("nobody")


def test_owner_of():
    assert owner_of(["owner_rivet", "sp_3"]) == "rivet"
    assert owner_of(["sp_3"]) is None
    assert owner_of(["owner_rivet", "owner_cto"]) is None
    assert owner_of(["owner_ghost"]) is None
    assert owner_of(["owner_brandon"]) == "brandon"
    assert set(OWNERS) == {"rivet", "tugboat", "critic", "bastion", "cpo", "cto", "brandon"}


def test_brandon_is_a_human_queue_with_no_poller():
    assert "brandon" not in BOTS
    with pytest.raises(ValueError):
        queue_jql("brandon")
    assert lint([dict(key="A2A-5", **task(labels=["owner_brandon"]))]) == []


def test_lint_flags_missing_and_multiple():
    issues = [dict(key="A2A-1", **task()), dict(key="A2A-2", **task(labels=["sp_1"])),
              dict(key="A2A-3", **task(labels=["owner_rivet", "owner_cto"]))]
    assert lint(issues) == [("A2A-2", "missing owner_ label"), ("A2A-3", "multiple owner_ labels")]


def test_happy_path():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway(reply="all good")
    out = poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert jira.transitions == [("A2A-1", "In Progress")]
    assert gw.calls == [("A2A-1", "A2A-1: Do X\n\ndetails")]
    c = jira.issues["A2A-1"]["comments"]
    assert c == ["[rivet] picked up", "[rivet] result\n\nall good"]
    assert out == {"completed": ["A2A-1"], "failed": [], "skipped": []}


def test_double_poll_sequential():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway()
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert len(gw.calls) == 1
    assert sum(c.startswith("[rivet] result") for c in jira.issues["A2A-1"]["comments"]) == 1


def test_double_poll_in_flight():
    jira = FakeJira({"A2A-1": task()})
    inner = FakeGateway()
    gw = FakeGateway(on_run=lambda: poll_once("rivet", jira, inner, sleep=NOSLEEP))
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert len(gw.calls) == 1 and inner.calls == []
    assert jira.issues["A2A-1"]["comments"].count("[rivet] picked up") == 1


def test_stale_search_result_rechecked_before_claim():
    # Search saw To Do, but another poll claimed it before we did.
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway()
    hits = jira.search(queue_jql("rivet"))
    jira.issues["A2A-1"]["status"] = "In Progress"
    jira.search = lambda jql: hits
    out = poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert gw.calls == [] and out["skipped"] == ["A2A-1"]


def test_existing_pickup_comment_skips():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway()
    jira.issues["A2A-1"]["comments"].append("[rivet] picked up")
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert gw.calls == [] and jira.transitions == []


def test_existing_result_not_duplicated():
    from routing.router import post_result
    jira = FakeJira({"A2A-1": task(status="In Progress")})
    jira.issues["A2A-1"]["comments"] += ["[rivet] picked up", "[rivet] result\n\nold"]
    post_result("rivet", jira, "A2A-1", "new", sleep=NOSLEEP)
    assert jira.issues["A2A-1"]["comments"][-1] == "[rivet] result\n\nold"


def test_gateway_failure_bounded_retry_then_one_failure_comment():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway(fail="ConnectionError")
    slept = []
    out = poll_once("rivet", jira, gw, sleep=slept.append)
    assert len(gw.calls) == 3 and slept == [1, 4]
    c = jira.issues["A2A-1"]["comments"]
    assert c == ["[rivet] picked up", "[rivet] failed: ConnectionError"]
    assert jira.issues["A2A-1"]["status"] == "Blocked"
    assert out["failed"] == ["A2A-1"]


def test_gateway_failure_not_relooped_on_next_poll():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway(fail="ConnectionError")
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert len(gw.calls) == 3


def test_agent_failed_state_is_not_retried():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway(fail="agent_failed")
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert len(gw.calls) == 1
    assert jira.issues["A2A-1"]["comments"][-1] == "[rivet] failed: agent_failed"


def test_failure_comment_has_no_payload():
    jira = FakeJira({"A2A-1": task(description="secret-ish body")})
    poll_once("rivet", jira, FakeGateway(fail="RPCError"), sleep=NOSLEEP)
    assert all("secret-ish" not in c for c in jira.issues["A2A-1"]["comments"])


@pytest.mark.parametrize("labels,summary", [(["owner_rivet", "owner_cto"], "x"), (["owner_rivet"], "  ")])
def test_malformed_issue_no_handoff_no_comment(labels, summary):
    jira, gw = FakeJira({"A2A-1": task(labels=labels, summary=summary)}), FakeGateway()
    out = poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert gw.calls == [] and jira.issues["A2A-1"]["comments"] == [] and jira.transitions == []
    assert out["skipped"] == ["A2A-1"]


def test_jira_comment_error_retried():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway()
    real, n = jira.comment, {"i": 0}
    def flaky(key, body):
        n["i"] += 1
        if n["i"] == 2:
            raise OSError("503")
        real(key, body)
    jira.comment = flaky
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert jira.issues["A2A-1"]["comments"][-1] == "[rivet] result\n\ndone"


def test_jira_outage_on_one_issue_does_not_stop_the_poll():
    jira, gw = FakeJira({"A2A-1": task(), "A2A-2": task()}), FakeGateway()
    real = jira.transition
    def t(key, status):
        if key == "A2A-1":
            raise OSError("503")
        real(key, status)
    jira.transition = t
    out = poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert out["failed"] == ["A2A-1"] and out["completed"] == ["A2A-2"]


def test_failure_goes_to_blocked_status_from_env(monkeypatch):
    import routing.router as r
    monkeypatch.setattr(r, "BLOCKED", "On Hold")
    jira = FakeJira({"A2A-1": task()})
    poll_once("rivet", jira, FakeGateway(fail="ConnectionError"), sleep=NOSLEEP)
    assert jira.transitions == [("A2A-1", "In Progress"), ("A2A-1", "On Hold")]


def test_manual_move_back_to_todo_requeues_exactly_once():
    jira, bad = FakeJira({"A2A-1": task()}), FakeGateway(fail="ConnectionError")
    poll_once("rivet", jira, bad, sleep=NOSLEEP)
    assert jira.issues["A2A-1"]["status"] == "Blocked"
    poll_once("rivet", jira, bad, sleep=NOSLEEP)  # Blocked is not in the queue
    assert len(bad.calls) == 3
    jira.issues["A2A-1"]["status"] = "To Do"  # human re-queues
    good = FakeGateway(reply="second try")
    poll_once("rivet", jira, good, sleep=NOSLEEP)
    poll_once("rivet", jira, good, sleep=NOSLEEP)
    assert len(good.calls) == 1
    c = jira.issues["A2A-1"]["comments"]
    assert c == ["[rivet] picked up", "[rivet] failed: ConnectionError",
                 "[rivet] picked up", "[rivet] result\n\nsecond try"]


def test_result_check_only_counts_results_after_latest_pickup():
    from routing.router import post_result
    jira = FakeJira({"A2A-1": task(status="In Progress")})
    jira.issues["A2A-1"]["comments"] += ["[rivet] picked up", "[rivet] result\n\nold",
                                         "[rivet] picked up"]
    post_result("rivet", jira, "A2A-1", "new", sleep=NOSLEEP)
    assert jira.issues["A2A-1"]["comments"][-1] == "[rivet] result\n\nnew"


def test_done_task_moved_back_to_todo_is_not_rerun():
    jira, gw = FakeJira({"A2A-1": task()}), FakeGateway()
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    jira.issues["A2A-1"]["status"] = "To Do"
    poll_once("rivet", jira, gw, sleep=NOSLEEP)
    assert len(gw.calls) == 1
