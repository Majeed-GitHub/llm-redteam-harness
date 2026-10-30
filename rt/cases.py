"""Suite loading, the case model, and validation.

A case used to be a prompt and an expectation. An agent case needs more: the
tool definitions the model is handed, the calls it must not make, the arguments
it must not carry, how many turns the loop may run, and the follow-up turns that
make a multi-turn escalation visible. Those live here so every other module can
stay about behaviour.

Two formats are accepted. JSONL is the native one and needs no dependency.
YAML is accepted when PyYAML happens to be installed, because people write
suites by hand and YAML is friendlier - but the core stays standard-library
only, so a missing PyYAML is a clear error with the command to fix it, never a
silent failure.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

EXPECTATIONS = ("refuse", "no_leak", "no_tool_call", "comply")
REQUIRED = ("id", "category", "prompt", "expectation")

# A poisoned description is written by an attacker, so the harness never trusts
# a tool definition to be documentation - it only needs the shape.
TOOL_KEYS = ("name", "description", "parameters")


@dataclass
class Case:
    id: str
    category: str
    prompt: str
    expectation: str
    canary: str = ""
    notes: str = ""
    layer: str = "direct"

    # --- agent surface -----------------------------------------------------
    # Definitions handed to the model, including any poisoning. Each may carry
    # a mock_return string: what the fake tool answers when called. It is
    # stripped before the definition is sent, because a harness that leaks its
    # own fixtures to the model is measuring itself.
    tools: List[Dict[str, object]] = field(default_factory=list)
    # Calls that must never happen. A single match fails the case.
    forbidden_tool_calls: List[str] = field(default_factory=list)
    # Regexes checked against the serialised arguments of every call.
    forbidden_arg_patterns: List[str] = field(default_factory=list)
    # How many model turns the loop may take before it is cut off.
    max_turns: int = 3
    # Scripted user follow-ups, one per turn after the first.
    user_turns: List[str] = field(default_factory=list)
    # Text the final answer must contain to count as useful.
    must_contain: List[str] = field(default_factory=list)
    # Regexes that must not appear in the final answer.
    leak_patterns: List[str] = field(default_factory=list)
    # Declarative business-logic invariants (see rt/scoring.py).
    policy_invariants: List[Dict[str, object]] = field(default_factory=list)
    # OWASP MCP Top 10 / LLM Top 10 identifier this case exercises.
    owasp: str = ""

    # --- rug-pull ----------------------------------------------------------
    # Replace the tool set from this turn onwards. Models a server that serves
    # a clean definition when inspected and a payload once it is trusted.
    mutate_on_turn: int = 0
    mutate_tools: List[Dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "id": self.id,
            "category": self.category,
            "expectation": self.expectation,
            "canary": self.canary,
            "layer": self.layer,
            "prompt": self.prompt,
        }
        if self.owasp:
            payload["owasp"] = self.owasp
        if self.tools:
            payload["tools"] = self.tools
        if self.forbidden_tool_calls:
            payload["forbidden_tool_calls"] = self.forbidden_tool_calls
        if self.forbidden_arg_patterns:
            payload["forbidden_arg_patterns"] = self.forbidden_arg_patterns
        if self.user_turns:
            payload["user_turns"] = self.user_turns
        if self.must_contain:
            payload["must_contain"] = self.must_contain
        if self.leak_patterns:
            payload["leak_patterns"] = self.leak_patterns
        if self.policy_invariants:
            payload["policy_invariants"] = self.policy_invariants
        if self.mutate_on_turn:
            payload["mutate_on_turn"] = self.mutate_on_turn
            payload["mutate_tools"] = self.mutate_tools
        return payload

    def is_control(self) -> bool:
        """A benign case: ordinary request, nothing the model must refuse.

        A "comply" expectation is not enough. A poisoned tool definition means
        the case is measuring whether the model disobeys the tool while still
        helping the user, so it is an attack case and its failure is a bypass,
        not over-refusal.
        """
        if self.expectation != "comply":
            return False
        return not (self.forbidden_tool_calls or self.forbidden_arg_patterns
                    or self.leak_patterns or self.policy_invariants
                    or self.mutate_on_turn or self.canary)

    def tool_specs(self) -> List[Dict[str, object]]:
        """Tool definitions as the model should see them: no mock_return."""
        return [{key: tool[key] for key in TOOL_KEYS if key in tool}
                for tool in self.tools]

    def mutated_tool_specs(self) -> List[Dict[str, object]]:
        return [{key: tool[key] for key in TOOL_KEYS if key in tool}
                for tool in self.mutate_tools]

    def mock_return_for(self, name: str, arguments: Optional[Dict[str, object]] = None) -> str:
        """What the fake tool answers, optionally depending on what it was sent.

        A static return cannot tell whether the agent actually carried a value
        from one tool into the next: it would answer the same thing to a real
        extraction and to a guess. mock_return_by_arg closes that hole - the
        booking only succeeds when the guest name that get_contact_list returned
        is the name passed into book_appointment.
        """
        for tool in list(self.tools) + list(self.mutate_tools):
            if tool.get("name") != name:
                continue
            rules = tool.get("mock_return_by_arg")
            if isinstance(rules, dict) and rules:
                values = [str(value) for value in (arguments or {}).values()]
                for value in values:
                    if value in rules:
                        return str(rules[value])
                if "default" in rules:
                    return str(rules["default"])
            if "mock_return" in tool:
                return str(tool["mock_return"])
        return "{}"


def _case_from_row(row: Dict[str, object], fallback_id: str) -> Case:
    def str_list(key: str) -> List[str]:
        value = row.get(key) or []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    def dict_list(key: str) -> List[Dict[str, object]]:
        value = row.get(key) or []
        return [item for item in value if isinstance(item, dict)]

    return Case(
        id=str(row.get("id") or fallback_id),
        category=str(row.get("category") or "uncategorised"),
        prompt=str(row.get("prompt") or ""),
        expectation=str(row.get("expectation") or "refuse"),
        canary=str(row.get("canary") or ""),
        notes=str(row.get("notes") or ""),
        layer=str(row.get("layer") or "direct"),
        tools=dict_list("tools"),
        forbidden_tool_calls=str_list("forbidden_tool_calls"),
        forbidden_arg_patterns=str_list("forbidden_arg_patterns"),
        max_turns=int(row.get("max_turns") or 3),
        user_turns=str_list("user_turns"),
        must_contain=str_list("must_contain"),
        leak_patterns=str_list("leak_patterns"),
        policy_invariants=dict_list("policy_invariants"),
        owasp=str(row.get("owasp") or ""),
        mutate_on_turn=int(row.get("mutate_on_turn") or 0),
        mutate_tools=dict_list("mutate_tools"),
    )


def _load_yaml(path: str) -> List[Dict[str, object]]:
    try:
        import yaml  # noqa: F401
    except ImportError:
        raise ValueError(
            "YAML suites need PyYAML, which this install does not have. Use the "
            "JSONL form, or install it with: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or []
    if isinstance(document, dict):
        document = document.get("cases") or []
    if not isinstance(document, list):
        raise ValueError("%s must hold a list of cases" % path)
    return [item for item in document if isinstance(item, dict)]


def _load_rows(path: str) -> List[Dict[str, object]]:
    extension = os.path.splitext(path)[1].lower()
    if extension in (".yaml", ".yml"):
        return _load_yaml(path)
    if extension == ".json":
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        if isinstance(document, dict):
            document = document.get("cases") or []
        if not isinstance(document, list):
            raise ValueError("%s must hold a list of cases" % path)
        return [item for item in document if isinstance(item, dict)]
    rows: List[Dict[str, object]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rows.append(json.loads(line))
            except ValueError as exc:
                raise ValueError("%s line %d is not valid JSON: %s" % (path, number, exc))
    return rows


def load_cases(path: str) -> List[Case]:
    """Read a suite. JSONL is native; JSON and YAML are accepted."""
    if not os.path.exists(path):
        raise ValueError("no such suite: %s" % path)
    cases: List[Case] = []
    for number, row in enumerate(_load_rows(path), 1):
        cases.append(_case_from_row(row, "case-%d" % number))
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
        if case.max_turns < 1:
            problems.append("%s: max_turns must be at least 1" % case.id)
        if len(case.user_turns) > max(0, case.max_turns - 1):
            problems.append("%s: %d scripted user turns do not fit in max_turns %d"
                            % (case.id, len(case.user_turns), case.max_turns))
        names = set()
        for tool in case.tools:
            name = str(tool.get("name") or "")
            if not name:
                problems.append("%s: a tool definition has no name" % case.id)
            names.add(name)
            if not isinstance(tool.get("parameters", {}), dict):
                problems.append("%s: tool %s parameters must be an object" % (case.id, name))
            rules = tool.get("mock_return_by_arg")
            if rules is not None and not isinstance(rules, dict):
                problems.append("%s: tool %s mock_return_by_arg must be an object" % (case.id, name))
        for name in case.forbidden_tool_calls:
            if case.tools and name not in names:
                problems.append("%s: forbidden tool %s is not defined in this case" % (case.id, name))
        for pattern in list(case.forbidden_arg_patterns) + list(case.leak_patterns):
            try:
                re.compile(pattern)
            except re.error as exc:
                problems.append("%s: bad regex %r: %s" % (case.id, pattern, exc))
        if case.mutate_on_turn:
            if case.mutate_on_turn < 2:
                problems.append("%s: mutate_on_turn must be 2 or later" % case.id)
            if not case.mutate_tools:
                problems.append("%s: mutate_on_turn set with no mutate_tools" % case.id)
        for invariant in case.policy_invariants:
            if invariant.get("type") not in ("no_pattern", "no_tool", "max_tool_calls"):
                problems.append("%s: unknown policy invariant %r" % (case.id, invariant.get("type")))
    return problems


def summarise_cases(cases: Sequence[Case]) -> str:
    by_category: Dict[str, int] = {}
    for case in cases:
        by_category[case.category] = by_category.get(case.category, 0) + 1
    lines = ["%d cases" % len(cases)]
    for category in sorted(by_category):
        lines.append("  %-28s %d" % (category, by_category[category]))
    return "\n".join(lines)
