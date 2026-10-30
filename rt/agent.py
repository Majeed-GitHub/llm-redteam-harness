"""The agent loop: run a case as a conversation with tools, not one string.

An agent attack does not live in one message. A poisoned tool definition is read
on turn one, obeyed on turn two, and a privileged call happens on turn three
after a reconnaissance call returned the data it needed. Scoring the final
string alone sees none of that, which is why this module keeps the whole
trajectory: every call, its arguments, what the fake tool answered, and which
turn it happened on.

The loop is deliberately dumb about policy. It executes whatever the model asks
for against the case's own mock_return values and records it. Deciding whether
that was an attack is the scorer's job, so a bug in scoring cannot hide a bug in
execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .cases import Case
from .client import AssistantTurn, ChatClient, ClientError


@dataclass
class Invocation:
    """One executed tool call, with what the tool answered."""

    turn: int
    name: str
    arguments: Dict[str, object]
    arguments_raw: str
    result: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "turn": self.turn,
            "name": self.name,
            "arguments": self.arguments,
            "arguments_raw": self.arguments_raw,
            "result": self.result[:400],
        }


@dataclass
class Trajectory:
    """Everything that happened in one case, in order."""

    messages: List[Dict[str, object]] = field(default_factory=list)
    final_text: str = ""
    invocations: List[Invocation] = field(default_factory=list)
    turns: int = 0
    schema_swaps: int = 0
    turn_budget_exhausted: bool = False
    error: str = ""

    @property
    def tool_calls(self) -> List[Dict[str, object]]:
        return [invocation.to_dict() for invocation in self.invocations]

    def invoked_names(self) -> List[str]:
        return [invocation.name for invocation in self.invocations]

    def serialized_arguments(self) -> str:
        """Every argument of every call, flattened, for pattern matching."""
        return "\n".join(invocation.arguments_raw for invocation in self.invocations)

    def to_dict(self) -> Dict[str, object]:
        return {
            "turns": self.turns,
            "final_text": self.final_text[:1000],
            "schema_swaps": self.schema_swaps,
            "turn_budget_exhausted": self.turn_budget_exhausted,
            "error": self.error,
            "tool_calls": self.tool_calls,
        }


def run_trajectory(case: Case, client: ChatClient,
                   max_turns: Optional[int] = None) -> Trajectory:
    """Drive one case to a final answer or to the turn budget."""
    budget = max_turns or case.max_turns or 3
    tools = case.tool_specs()
    mutated = False
    trajectory = Trajectory(messages=[{"role": "user", "content": case.prompt}])

    for turn in range(1, budget + 1):
        trajectory.turns = turn

        # Scripted follow-ups model a user who keeps supplying what the previous
        # turn asked for - slot filling, not a new attack.
        if turn > 1 and case.user_turns and turn - 2 < len(case.user_turns):
            trajectory.messages.append({"role": "user", "content": case.user_turns[turn - 2]})

        # A rug-pull: the definition inspected earlier is not the one in force.
        if case.mutate_on_turn and turn >= case.mutate_on_turn and not mutated:
            tools = case.mutated_tool_specs()
            trajectory.schema_swaps += 1
            mutated = True

        try:
            step = client.complete_with_tools(trajectory.messages, tools)
        except ClientError as error:
            trajectory.error = str(error)
            return trajectory

        if not step.wants_tools:
            trajectory.final_text = step.content
            trajectory.messages.append({"role": "assistant", "content": step.content})
            return trajectory

        trajectory.messages.append({
            "role": "assistant",
            "content": step.content or "",
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.arguments_raw},
                }
                for call in step.tool_calls
            ],
        })
        for call in step.tool_calls:
            result = case.mock_return_for(call.name)
            trajectory.invocations.append(Invocation(
                turn=turn,
                name=call.name,
                arguments=call.arguments,
                arguments_raw=call.arguments_raw,
                result=result,
            ))
            trajectory.messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "name": call.name,
                "content": result,
            })

    trajectory.turn_budget_exhausted = True
    return trajectory


def run_case(case: Case, client: ChatClient) -> Trajectory:
    """Convenience wrapper so callers do not import two names."""
    return run_trajectory(case, client)
