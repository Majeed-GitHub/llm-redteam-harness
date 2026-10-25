"""Suite loading and validation."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

EXPECTATIONS = ("refuse", "no_leak", "no_tool_call", "comply")
REQUIRED = ("id", "category", "prompt", "expectation")


@dataclass
class Case:
    id: str
    category: str
    prompt: str
    expectation: str
    canary: str = ""
    notes: str = ""
    layer: str = "direct"

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "category": self.category,
            "expectation": self.expectation,
            "canary": self.canary,
            "layer": self.layer,
            "prompt": self.prompt,
        }


def load_cases(path: str) -> List[Case]:
    """Read a JSONL suite. Blank lines and comment lines are ignored."""
    cases: List[Case] = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise ValueError("%s line %d is not valid JSON: %s" % (path, number, exc))
            cases.append(Case(
                id=str(row.get("id") or "case-%d" % number),
                category=str(row.get("category") or "uncategorised"),
                prompt=str(row.get("prompt") or ""),
                expectation=str(row.get("expectation") or "refuse"),
                canary=str(row.get("canary") or ""),
                notes=str(row.get("notes") or ""),
                layer=str(row.get("layer") or "direct"),
            ))
    return cases


def validate_cases(cases: Sequence[Case]) -> List[str]:
    """Problems that would make a result meaningless, not style opinions."""
    problems: List[str] = []
    seen = set()
    for case in cases:
        if case.id in seen:
            problems.append("duplicate case id: %s" % case.id)
        seen.add(case.id)
        if case.expectation not in EXPECTATIONS:
            problems.append("%s: expectation must be one of %s" % (case.id, ", ".join(EXPECTATIONS)))
        if not case.prompt.strip():
            problems.append("%s: empty prompt" % case.id)
        if case.expectation == "no_leak" and not case.canary:
            problems.append("%s: a no_leak case needs a canary to look for" % case.id)
    return problems


def summarise_cases(cases: Sequence[Case]) -> str:
    by_category: Dict[str, int] = {}
    for case in cases:
        by_category[case.category] = by_category.get(case.category, 0) + 1
    lines = ["%d cases" % len(cases)]
    for category in sorted(by_category):
        lines.append("  %-28s %d" % (category, by_category[category]))
    return "\n".join(lines)
