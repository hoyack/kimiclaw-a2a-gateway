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


def classify_trufflehog(item: dict[str, Any]) -> str:
    if item.get("Verified") is True:
        return "verified"
    status = str(item.get("Status") or item.get("verification_status") or "").lower()
    if item.get("VerificationError") or item.get("verification_error") or status == "unknown":
        return "unknown"
    return "unverified"


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
                "class": classify_trufflehog(item),
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
    th_verified = [r for r in th_rows if r.get("class") == "verified"]
    th_unknown = [r for r in th_rows if r.get("class") == "unknown"]
    th_unverified = [r for r in th_rows if r.get("class") not in {"verified", "unknown"}]

    lines = [
        "## Git history secret scan",
        "",
        f"- trufflehog git --no-update (exit {th_rc}): {len(th_verified)} verified, {len(th_unknown)} unknown, {len(th_unverified)} unverified",
        f"- gitleaks detect --redact --log-opts=--all (exit {gl_rc}): {len(gl_rows)} finding(s)",
        "",
        "Values are omitted. Only rule or detector, path, commit, and line are listed.",
        "The job fails on verified or unknown trufflehog results, or any gitleaks finding.",
        "Unverified results are listed for review and do not fail the job.",
        "",
    ]
    if th_tool_error:
        lines.append(f"**ERROR:** trufflehog exited {th_rc} without a findings status.")
        lines.append("")
    if gl_tool_error:
        lines.append(f"**ERROR:** gitleaks exited {gl_rc} without a findings status.")
        lines.append("")

    def emit(title: str, kind: str, key: str, rows: list[dict[str, str]]) -> None:
        if not rows:
            return
        lines.append(title)
        for row in rows:
            lines.append(fmt(kind, row[key], row["path"], row["commit"], row["line"]))
        lines.append("")

    emit("trufflehog verified findings (detector, path, commit, line only):", "detector", "detector", th_verified)
    emit("trufflehog unknown findings (detector, path, commit, line only):", "detector", "detector", th_unknown)
    emit("trufflehog unverified findings (informational, detector, path, commit, line only):", "detector", "detector", th_unverified)
    emit("gitleaks findings (rule, path, commit, line only):", "rule", "rule", gl_rows)

    blocking = bool(th_verified or th_unknown or gl_rows or gl_rc == 1)
    if not blocking and not th_tool_error and not gl_tool_error:
        if th_unverified:
            lines.append("**PASS:** no verified or unknown secrets in the repository git history.")
        else:
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
    if blocking:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
