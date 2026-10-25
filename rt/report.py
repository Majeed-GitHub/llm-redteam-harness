"""Reports: JSON for tooling, Markdown for a human."""

from __future__ import annotations

import json
from typing import Dict, Sequence

from .judges import Verdict


def write_json(path: str, summary: Dict[str, object], verdicts: Sequence[Verdict]) -> None:
    payload = dict(summary)
    payload["verdicts"] = [verdict.to_dict() for verdict in verdicts]
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2)


def render_markdown(summary: Dict[str, object], verdicts: Sequence[Verdict],
                    suite: str = "", model: str = "") -> str:
    lines = [
        "# LLM security test report",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| suite | %s |" % (suite or "-"),
        "| model | %s |" % (model or "mock"),
        "| cases | %d |" % summary["cases"],
        "| attacks | %d |" % summary["attacks"],
        "| attack success rate | %.1f%% |" % (summary["attack_success_rate"] * 100),
        "| robustness | %.1f%% |" % (summary["robustness"] * 100),
        "| over-refusal on controls | %.1f%% |" % (summary["over_refusal_rate"] * 100),
        "",
        "## By category",
        "",
        "| Category | Attacks | Succeeded | ASR |",
        "| --- | --- | --- | --- |",
    ]
    for name, bucket in summary["by_category"].items():
        lines.append("| %s | %d | %d | %.1f%% |" % (
            name, bucket["attacks"], bucket["succeeded"], bucket["asr"] * 100))
    lines += ["", "## Cases", "", "| Case | Category | Expectation | Result | Reason |",
              "| --- | --- | --- | --- | --- |"]
    for verdict in verdicts:
        lines.append("| %s | %s | %s | %s | %s |" % (
            verdict.case_id, verdict.category, verdict.expectation,
            "pass" if verdict.passed else "FAIL", verdict.reason))
    if summary["failures"]:
        lines += ["", "## Failures", ""]
        for failure in summary["failures"]:
            lines.append("- %s (%s): %s" % (failure["case_id"], failure["category"], failure["reason"]))
    lines += ["", "Reproduce this table with the exact command in the README; the suite is fixed,",
              "the temperature is 0, and the judges are rules in rt/judges.py.", ""]
    return "\n".join(lines)
