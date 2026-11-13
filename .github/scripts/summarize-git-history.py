#!/usr/bin/env python3
"""Write redacted git-history scan results (rule/detector, path, commit, line)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size == 0:
        return None
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        items = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


def trufflehog_rows(data: Any) -> list[dict[str, str]]:
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if "DetectorName" not in item and "DetectorType" not in item:
            continue
        git = ((item.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {}
        rows.append(
            {
                "detector": str(item.get("DetectorName") or item.get("DetectorType") or "unknown"),
                "path": str(git.get("file") or git.get("File") or "(unknown path)"),
                "commit": str(git.get("commit") or git.get("Commit") or ""),
                "line": str(git.get("line") or git.get("Line") or ""),
            }
        )
    return rows


def gitleaks_rows(data: Any) -> list[dict[str, str]]:
    if not data:
        return []
    if isinstance(data, dict):
        data = data.get("findings", [data])
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "rule": str(item.get("RuleID") or item.get("Description") or "unknown"),
                "path": str(item.get("File") or item.get("FilePath") or "(unknown path)"),
                "commit": str(item.get("Commit") or ""),
                "line": str(item.get("StartLine") or item.get("Line") or ""),
            }
        )
    return rows


def fmt(kind: str, name: str, path: str, commit: str, line: str) -> str:
    loc = path
    if line:
        loc = f"{path}:{line}"
    suffix = f" @ `{commit}`" if commit else ""
    return f"- {kind} `{name}` in `{loc}`{suffix}"


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: summarize-git-history.py <trufflehog-json> <trufflehog-rc> <gitleaks-json> <gitleaks-rc>",
            file=sys.stderr,
        )
        return 2
    th_path = Path(sys.argv[1])
    th_rc = int(sys.argv[2])
    gl_path = Path(sys.argv[3])
    gl_rc = int(sys.argv[4])
    th_rows = trufflehog_rows(load_json(th_path))
    gl_rows = gitleaks_rows(load_json(gl_path))
    th_tool_error = th_rc not in (0, 183)
    gl_tool_error = gl_rc not in (0, 1)

    lines = [
        "## Git history secret scan",
        "",
        f"- trufflehog git --no-update (exit {th_rc}): {len(th_rows)} finding(s)",
        f"- gitleaks detect --redact --log-opts=--all (exit {gl_rc}): {len(gl_rows)} finding(s)",
        "",
        "Values are omitted. Only rule or detector, path, commit, and line are listed.",
        "",
    ]
    if th_tool_error:
        lines.append(f"**ERROR:** trufflehog exited {th_rc} without a findings status.")
        lines.append("")
    if gl_tool_error:
        lines.append(f"**ERROR:** gitleaks exited {gl_rc} without a findings status.")
        lines.append("")
    if th_rows:
        lines.append("trufflehog findings (detector, path, commit, line only):")
        for row in th_rows:
            lines.append(fmt("detector", row["detector"], row["path"], row["commit"], row["line"]))
        lines.append("")
    if gl_rows:
        lines.append("gitleaks findings (rule, path, commit, line only):")
        for row in gl_rows:
            lines.append(fmt("rule", row["rule"], row["path"], row["commit"], row["line"]))
        lines.append("")
    if not th_rows and not gl_rows and not th_tool_error and not gl_tool_error:
        lines.append("**PASS:** no secrets found in the repository git history.")
        lines.append("")

    text = "\n".join(lines) + "\n"
    print(text, end="")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    if th_tool_error or gl_tool_error:
        return 2
    if th_rows or gl_rows or th_rc == 183 or gl_rc == 1:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
