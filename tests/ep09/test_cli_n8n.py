import glob
import json
import os
import re

from routing.cli import main
from routing.n8n.build import workflow
from routing.router import BOTS

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_cli_refuses_without_env(capsys):
    assert main(["poll", "--bot", "rivet"], env={}) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["vars"] == ["JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "A2A_GATEWAY_TOKEN"]


def test_n8n_files_match_builder_one_per_bot_inactive_no_secrets():
    files = sorted(glob.glob(os.path.join(ROOT, "routing/n8n/poller-*.json")))
    assert [os.path.basename(f) for f in files] == sorted(f"poller-{b}.json" for b in BOTS)
    for bot in BOTS:
        raw = open(os.path.join(ROOT, f"routing/n8n/poller-{bot}.json")).read()
        wf = json.loads(raw)
        assert wf == workflow(bot)
        assert wf["active"] is False
        assert f"--bot {bot}" in raw and "flock -n" in raw
        assert not re.search(r"(?i)(token|password|secret)\s*[:=]\s*['\"]?\w", raw)
        assert "credentials" not in raw
