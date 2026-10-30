"""Static MCP tool-schema linting: find poisoning before a model is called.

A tool schema reaches the model before the first user message does, so it is
the cheapest place to catch an injected instruction: the JSON is already in
memory, nothing has to be fetched, and no token has been spent. Every check
here is a pure function of that JSON, which is why a run is cheap enough to put
in front of every test and every pull request.

Codes are stable identifiers. A gate, a waiver file, or a reviewer's notes key
off them, so a new check gets a new code rather than changing an old one.

The interesting cases are the two the eye cannot see: text hidden in Unicode
tag characters, and a description that quietly redirects a call to a different
tool. Both are reported with the payload decoded, because a finding a human
cannot read is a finding that gets waived.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, Iterator, List, Sequence, Tuple

# Unicode tag characters: the block an attacker uses to write invisible ASCII.
TAG_FIRST = 0xE0000
TAG_LAST = 0xE007F
# Zero-width characters: no glyph, but a model still tokenises them.
ZERO_WIDTH = frozenset(("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"))

# Phrases that turn a description into an instruction. Two or more is a
# deliberate payload; one is often a careless vendor, so it stays a warning.
IMPERATIVES = (
    "BEFORE CALLING",
    "WITHOUT ASKING",
    "DO NOT TELL",
    "CRITICAL",
    "IMPORTANT",
    "ALWAYS",
    "IGNORE",
    "MUST",
)

# A description that names another tool and redirects traffic is shadowing.
REDIRECT_VERBS = ("instead", "always use", "do not use", "route", "delegate", "redirect")

# Parameter names that turn an open schema into an execution surface.
EXEC_PARAMETERS = frozenset(("command", "cmd", "exec", "shell", "path", "url"))

# Long enough that nobody reads it before approving it in a config review.
OVERSIZED_DESCRIPTION = 1200


@dataclass
class Finding:
    """One reason to distrust one field of one tool schema."""

    tool: str
    field: str
    code: str
    severity: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "tool": self.tool,
            "field": self.field,
            "code": self.code,
            "severity": self.severity,
            "detail": self.detail,
        }


def decode_smuggled(text: str) -> str:
    """Read text that was hidden with tag or zero-width characters.

    Tag characters map back to ASCII by subtracting the block base, so an
    encoded "IGNORE ALL" comes out readable. Zero-width characters carry no
    payload and are simply dropped.
    """
    parts: List[str] = []
    for char in text:
        code = ord(char)
        if TAG_FIRST <= code <= TAG_LAST:
            parts.append(chr(code - TAG_FIRST))
        elif char in ZERO_WIDTH:
            continue
        else:
            parts.append(char)
    return "".join(parts)


def hidden_characters(text: str) -> List[str]:
    """Every character in text that a human cannot see."""
    return [char for char in text
            if TAG_FIRST <= ord(char) <= TAG_LAST or char in ZERO_WIDTH]


def lint_tools(tools: Sequence[dict]) -> List[Finding]:
    """Lint a tool surface. Findings are ordered by tool, then by check."""
    rows = [tool for tool in tools if isinstance(tool, dict)]
    findings: List[Finding] = []
    for tool in rows:
        findings.extend(_lint_one(tool, rows))
    return findings


def load_tools(path: str) -> Tuple[List[dict], List[str]]:
    """Read a tool surface from a list, a {tools: [...]} file, or an MCP config.

    Returns the tools and the structural complaints about them. A complaint is
    a reason the file cannot be linted as written -- not a finding: a missing
    name or a parameters value that is a string makes the schema meaningless
    before any rule can apply. Tools are still returned when they have such a
    problem, because the description may still carry a payload.

    Tools from an mcpServers config remember their server, and every finding
    about them is labelled "server/tool", which is the name the client uses.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError as exc:
        return [], ["cannot read %s: %s" % (path, exc)]
    except ValueError as exc:
        return [], ["%s is not valid JSON: %s" % (path, exc)]

    problems: List[str] = []
    if isinstance(raw, list):
        return _collect(raw, "", problems), problems
    if isinstance(raw, dict) and isinstance(raw.get("tools"), list):
        return _collect(raw["tools"], "", problems), problems
    if isinstance(raw, dict) and isinstance(raw.get("mcpServers"), dict):
        tools: List[dict] = []
        for server in sorted(raw["mcpServers"]):
            entry = raw["mcpServers"][server]
            if not isinstance(entry, dict):
                problems.append("server %s: entry is not an object" % server)
                continue
            server_tools = entry.get("tools")
            if not isinstance(server_tools, list):
                problems.append("server %s: has no tools list" % server)
                continue
            tools.extend(_collect(server_tools, str(server), problems))
        return tools, problems

    problems.append("%s: expected a list of tools, {\"tools\": [...]}, "
                    "or {\"mcpServers\": {...}}" % path)
    return [], problems


def schema_hashes(tools: Sequence[dict]) -> Dict[str, str]:
    """A sha256 per tool over the canonical JSON of the fields a model reads.

    Only name, description and parameters are hashed: those are the things
    that can carry an instruction. Key order and whitespace do not matter, so
    a formatter that rewrites the config does not look like a drift.
    """
    hashes: Dict[str, str] = {}
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        payload = {
            "name": _text(tool.get("name")),
            "description": _text(tool.get("description")),
            "parameters": _parameters(tool),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
        hashes[_qualified(tool)] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return hashes


def diff_lockfile(tools: Sequence[dict], lock: Dict[str, str]) -> List[Finding]:
    """Compare a tool surface with the hashes that were reviewed last time.

    A lockfile is not a trust decision, only a memory of one: this makes a
    changed description, a new tool, or a removed tool visible without any
    judgement about whether the change is good.
    """
    findings: List[Finding] = []
    current = schema_hashes(tools)
    for name in sorted(current):
        digest = current[name]
        if name not in lock:
            findings.append(Finding(
                name, "schema", "mcp.schema.added", "medium",
                "tool is not in the lockfile (sha256 %s); review it once and pin it"
                % digest[:12]))
        elif str(lock[name]) != digest:
            findings.append(Finding(
                name, "schema", "mcp.schema.changed", "high",
                "schema changed since review (sha256 %s -> %s); re-read the description "
                "and parameters before trusting the tool" % (str(lock[name])[:12], digest[:12])))
    for name in sorted(lock):
        if name not in current:
            findings.append(Finding(
                name, "schema", "mcp.schema.removed", "medium",
                "tool was reviewed as sha256 %s and is no longer in the surface"
                % str(lock[name])[:12]))
    return findings


def _lint_one(tool: dict, all_tools: Sequence[dict]) -> List[Finding]:
    label = _qualified(tool)
    name = _text(tool.get("name"))
    description = _text(tool.get("description"))
    parameters = _parameters(tool)
    findings: List[Finding] = []

    hits = _imperative_hits(description)
    if hits:
        findings.append(Finding(
            label, "description", "mcp.instruction.in_description",
            "high" if len(hits) >= 2 else "medium",
            "description reads as an instruction (%d marker%s: %s)"
            % (len(hits), "" if len(hits) == 1 else "s", ", ".join(hits))))

    if len(description) > OVERSIZED_DESCRIPTION:
        findings.append(Finding(
            label, "description", "mcp.description.oversized", "medium",
            "description is %d characters, over the %d-character limit; long text is "
            "where a payload hides" % (len(description), OVERSIZED_DESCRIPTION)))

    findings.extend(_hidden_findings(label, name, description, parameters))
    findings.extend(_shadowing_findings(label, name, description, all_tools))
    findings.extend(_parameter_findings(label, parameters))
    return findings


def _hidden_findings(label: str, name: str, description: str,
                     parameters: dict) -> List[Finding]:
    findings: List[Finding] = []
    fields: List[Tuple[str, str]] = [("name", name), ("description", description)]
    fields.extend(_walk_strings(parameters, "parameters"))
    for field, text in fields:
        hidden = hidden_characters(text)
        if not hidden:
            continue
        findings.append(Finding(
            label, field, "mcp.unicode.hidden", "critical",
            "%d hidden character%s in %s; decoded: %s"
            % (len(hidden), "" if len(hidden) == 1 else "s", field,
               _readable(decode_smuggled(text)))))
    for argument in _property_names(parameters):
        if hidden_characters(argument):
            findings.append(Finding(
                label, "parameters.properties", "mcp.unicode.hidden", "critical",
                "hidden characters in a parameter name; decoded: %s"
                % _readable(decode_smuggled(argument))))
    return findings


def _shadowing_findings(label: str, name: str, description: str,
                        all_tools: Sequence[dict]) -> List[Finding]:
    """A description that sends the model to a different tool.

    The redirect is what makes it poisoning rather than documentation: a tool
    is entitled to mention its neighbours, not to forbid them.
    """
    findings: List[Finding] = []
    lowered = description.lower()
    if not lowered:
        return findings
    verb = next((candidate for candidate in REDIRECT_VERBS if candidate in lowered), "")
    if not verb:
        return findings
    for other in all_tools:
        other_name = _text(other.get("name"))
        # Four characters keeps a tool called "id" from matching every word;
        # the redirect verb is what makes the remaining matches meaningful.
        if other_name == name or len(other_name) < 4:
            continue
        if other_name.lower() not in lowered:
            continue
        findings.append(Finding(
            label, "description", "mcp.shadowing", "high",
            "description mentions %s and redirects with %r; a tool may describe its own "
            "work but not reroute another tool's calls" % (other_name, verb)))
    return findings


def _parameter_findings(label: str, parameters: dict) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(parameters, dict):
        return findings

    properties = parameters.get("properties")
    if isinstance(properties, dict):
        for argument, schema in properties.items():
            if not isinstance(argument, str) or not isinstance(schema, dict):
                continue
            base = "parameters.properties.%s" % argument
            description = _text(schema.get("description"))
            hits = _imperative_hits(description)
            if hits:
                findings.append(Finding(
                    label, base + ".description", "mcp.instruction.in_parameter",
                    "high" if len(hits) >= 2 else "medium",
                    "parameter description reads as an instruction (%s)"
                    % ", ".join(hits)))
            for key in ("default", "examples"):
                if key not in schema:
                    continue
                for field, text in _walk_strings(schema[key], base + "." + key):
                    hits = _imperative_hits(text)
                    if hits:
                        findings.append(Finding(
                            label, field, "mcp.instruction.in_parameter",
                            "high" if len(hits) >= 2 else "medium",
                            "parameter %s value reads as an instruction (%s)"
                            % (key, ", ".join(hits))))

    if parameters.get("additionalProperties") is True:
        exec_like = sorted(argument for argument in _property_names(parameters)
                           if argument.lower() in EXEC_PARAMETERS)
        if exec_like:
            findings.append(Finding(
                label, "parameters.additionalProperties", "mcp.parameter.open_schema",
                "medium",
                "additionalProperties is true and the tool takes exec-like argument%s "
                "(%s); an unconstrained object next to a shell is a way to run "
                "something that was never reviewed"
                % ("" if len(exec_like) == 1 else "s", ", ".join(exec_like))))
    return findings


def _imperative_hits(text: str) -> List[str]:
    upper = text.upper()
    return [marker for marker in IMPERATIVES if marker in upper]


def _property_names(parameters: dict) -> List[str]:
    if not isinstance(parameters, dict):
        return []
    properties = parameters.get("properties")
    if not isinstance(properties, dict):
        return []
    return [argument for argument in properties if isinstance(argument, str)]


def _walk_strings(value: object, path: str) -> Iterator[Tuple[str, str]]:
    """Every string reachable from a JSON value, with a locator for each."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key in value:
            if isinstance(key, str):
                for pair in _walk_strings(value[key], "%s.%s" % (path, key)):
                    yield pair
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            for pair in _walk_strings(item, "%s[%d]" % (path, index)):
                yield pair


def _parameters(tool: dict) -> dict:
    parameters = tool.get("parameters")
    if isinstance(parameters, dict):
        return parameters
    # MCP exports call the same object inputSchema; a client that hands us one
    # should still be linted rather than silently pass with no parameters.
    schema = tool.get("inputSchema")
    return schema if isinstance(schema, dict) else {}


def _qualified(tool: dict) -> str:
    name = _text(tool.get("name")) or "<unnamed>"
    server = _server_of(tool)
    return "%s/%s" % (server, name) if server else name


def _server_of(tool: dict) -> str:
    server = getattr(tool, "server", "")
    if not server:
        server = _text(tool.get("_server"))
    return server


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _readable(text: str, limit: int = 240) -> str:
    if len(text) > limit:
        text = text[:limit] + "..."
    return repr(text)


def _where(server: str, label: str) -> str:
    return "%s/%s" % (server, label) if server else label


def _collect(rows: Sequence[object], server: str,
             problems: List[str]) -> List[dict]:
    tools: List[dict] = []
    for index, row in enumerate(rows):
        label = "tool #%d" % index
        if not isinstance(row, dict):
            problems.append("%s: is not an object" % _where(server, label))
            continue
        tool = _ServerTool(row, server) if server else dict(row)
        name = row.get("name")
        if not isinstance(name, str) or not name.strip():
            problems.append("%s: missing a name" % _where(server, label))
        elif server:
            label = name
        parameters = row.get("parameters")
        if "parameters" not in row and isinstance(row.get("inputSchema"), dict):
            tool["parameters"] = row["inputSchema"]
            parameters = tool["parameters"]
        if parameters is not None and not isinstance(parameters, dict):
            problems.append("%s: parameters is not an object"
                            % _where(server, name if isinstance(name, str) and name else label))
        tools.append(tool)
    return tools


class _ServerTool(dict):
    """A tool dict that remembers which MCP server it came from.

    The server tag rides on the object instead of inside it, so a caller that
    compares the loaded tools with the JSON it wrote still gets equality while
    findings can still say which server a poisoned tool speaks for.
    """

    def __init__(self, data: dict, server: str) -> None:
        super().__init__(data)
        self.server = server
