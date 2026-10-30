"""Run a suite against one or more endpoints, and compare them.

Latency is measured per request, so a gateway that is safer but five times slower
shows up as exactly that instead of a footnote.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from .agent import run_trajectory
from .cases import Case
from .client import ChatClient, ClientError
from .judges import Verdict, judge, summarize
from .scoring import score_trajectory


@dataclass
class Run:
    name: str
    endpoint: str
    model: str
    verdicts: List[Verdict] = field(default_factory=list)
    latencies_ms: List[float] = field(default_factory=list)
    error: str = ""

    @property
    def summary(self) -> Dict[str, object]:
        return summarize(self.verdicts) if self.verdicts else {}

    def latency(self, fraction: float = 0.5) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        index = int(round(fraction * (len(ordered) - 1)))
        return ordered[max(0, min(len(ordered) - 1, index))]


def run_suite(cases: Sequence[Case], client: ChatClient, name: str = "target") -> Run:
    """One endpoint, one suite. A failing case is recorded, not raised."""
    run = Run(name=name, endpoint=client.endpoint, model=client.model)
    for case in cases:
        started = time.perf_counter()
        try:
            response = client.complete(case.prompt)
        except ClientError as error:
            run.error = str(error)
            break
        run.latencies_ms.append((time.perf_counter() - started) * 1000)
        run.verdicts.append(judge(case, response))
    return run


def run_agent_suite(cases: Sequence[Case], client: ChatClient,
                    name: str = "target") -> Run:
    """Run a tool-using suite: each case becomes a conversation, not a prompt.

    Latency is recorded per model turn rather than per case, because a case with
    a four-turn budget makes four requests and hiding that inside one number
    would make a slow agent look fast.
    """
    run = Run(name=name, endpoint=client.endpoint, model=client.model)
    for case in cases:
        started = time.perf_counter()
        trajectory = run_trajectory(case, client)
        run.latencies_ms.append((time.perf_counter() - started) * 1000)
        if trajectory.error:
            run.error = trajectory.error
        score = score_trajectory(case, trajectory)
        run.verdicts.append(Verdict(
            case_id=case.id,
            category=case.category,
            expectation=case.expectation,
            passed=score.passed,
            reason=score.reason,
            response=trajectory.final_text,
            canary_leaked=score.canary_leaked,
            failure_reason=score.failure_reason,
            tool_calls=score.tool_calls,
            turns=score.turns,
            owasp=case.owasp,
            control=case.is_control(),
        ))
    return run


def compare(targets: Sequence[Tuple[str, str]], cases: Sequence[Case], model: str,
            api_key_env: str = "", timeout: float = 120.0) -> List[Run]:
    """Run the same suite against every target, in order."""
    runs: List[Run] = []
    for name, endpoint in targets:
        client = ChatClient(endpoint=endpoint, model=model, api_key_env=api_key_env, timeout=timeout)
        runs.append(run_suite(cases, client, name=name))
    return runs


def render_comparison(runs: Sequence[Run], suite: str = "") -> str:
    lines = [
        "# Endpoint comparison",
        "",
        "| Target | Endpoint | Cases | Attacks | ASR | Robustness | Over-refusal | p50 ms | p95 ms |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for run in runs:
        if run.error:
            lines.append("| %s | %s | - | - | - | - | - | - | - |" % (run.name, run.endpoint))
            continue
        summary = run.summary
        lines.append("| %s | %s | %d | %d | %.1f%% | %.1f%% | %.1f%% | %.1f | %.1f |" % (
            run.name, run.endpoint, summary["cases"], summary["attacks"],
            summary["attack_success_rate"] * 100, summary["robustness"] * 100,
            summary["over_refusal_rate"] * 100, run.latency(0.5), run.latency(0.95)))
    for run in runs:
        if run.error:
            lines += ["", "**%s** could not be reached: %s" % (run.name, run.error)]
    lines += ["", "Suite: %s. Lower attack success rate is better; over-refusal is reported" % suite,
              "alongside it because a model that refuses everything scores a perfect ASR.", ""]
    return "\n".join(lines)
