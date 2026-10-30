"""Read a live MCP server's tool surface instead of a file on disk.

A schema in a config file is what someone meant to run. The schema a model
actually sees is whatever the server returns from tools/list, after its own
environment, feature flags and startup fetches have had their say. That gap is
where a poisoned tool hides: the reviewed file describes "get_weather" and the
running server answers with a second tool nobody read, or with the same tool
whose description arrived from a remote template.

The handshake below is the one every MCP client performs -- initialize,
notifications/initialized, tools/list -- over either transport a deployment
uses: a subprocess spoken to over newline-delimited JSON on stdio, or an HTTP
endpoint that answers with JSON or with an event stream. Both end in plain tool
dicts, so grading stays in rt.mcp_lint: this module discovers, it does not
judge. Re-implementing a static check here would give a scan two opinions about
one schema.

Shutdown is the part that bites. A stdio server is a child process, and a child
left running holds a pipe open and hangs whatever waits on it, which is why
every exit path terminates, reaps and closes the pipes, and why every read is
bounded by one deadline for the whole exchange.

Deliberately not negotiated here: MCP session ids, protocol-version headers and
tools/list pagination. A server that needs them is a server whose own client
already knows how to talk to it; this module only has to be honest about what
it managed to read.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Sequence, Tuple, Union

# Discovery only: the grading lives in mcp_lint, and the drift line here is a
# formatting of its findings rather than a second opinion about them.
from .mcp_lint import diff_lockfile

# The revision every client shipped since late 2024 speaks.
PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "llm-redteam-harness"

# Fixed request ids: one exchange, three messages, so a reply can never be
# mistaken for the answer to a different call.
INITIALIZE_ID = 1
TOOLS_LIST_ID = 2

# Worst first, the same order the scan-mcp report uses.
SEVERITY_ORDER = {"medium": 1, "high": 2, "critical": 3}

# What a pump thread posts when the child closes stdout.
_EOF = object()

__all__ = ["compare_hashes", "list_tools_http", "list_tools_stdio", "load_config"]


def list_tools_stdio(command: Union[str, Sequence[str]],
                     timeout: float = 30.0) -> List[dict]:
    """Spawn an MCP server and return the tools from its tools/list result.

    command is either an argv sequence (what load_config hands back) or a
    single command line, which is split without a shell: no shell means no
    quoting rules to get wrong and no child shell left to leak on Windows.

    timeout bounds the whole exchange, not each message, because three slow
    phases that each fit their own budget can still add up to a scan that hangs
    CI. The child is terminated, reaped and disconnected on every path out of
    this function, including a timeout and a JSON-RPC error.
    """
    argv = _command_argv(command)
    limit = _positive(timeout)
    label = _shorten(" ".join(argv))
    deadline = time.monotonic() + limit
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        raise RuntimeError("cannot spawn MCP server %s: %s" % (label, exc))

    session = _StdioSession(process, label, limit)
    try:
        session.request("initialize", _initialize_params(), INITIALIZE_ID, deadline)
        # The notification has no id and no reply: the server only has to see it.
        session.notify("notifications/initialized")
        result = session.request("tools/list", {}, TOOLS_LIST_ID, deadline)
        return _tools_of(result, label)
    finally:
        session.close()


def list_tools_http(url: str, timeout: float = 30.0) -> List[dict]:
    """POST the handshake to an MCP endpoint and return its tools/list tools.

    Streamable HTTP servers answer in two shapes: one JSON object, or a
    text/event-stream whose data lines carry the same JSON. Both are accepted
    because a proxy in front of a server can switch between them, and the
    schema read should not depend on which one it got today.
    """
    label = url.strip() if isinstance(url, str) else ""
    if not label:
        raise RuntimeError("cannot POST to an empty MCP url")
    limit = _positive(timeout)
    deadline = time.monotonic() + limit

    messages = _http_post(label, _message("initialize", _initialize_params(),
                                          INITIALIZE_ID), deadline)
    _result_of(_pick(messages, INITIALIZE_ID, label, "initialize"),
               "initialize", label)

    # A notification is answered with an empty body, or with nothing at all.
    _http_post(label, _message("notifications/initialized", None), deadline)

    messages = _http_post(label, _message("tools/list", {}, TOOLS_LIST_ID), deadline)
    result = _result_of(_pick(messages, TOOLS_LIST_ID, label, "tools/list"),
                        "tools/list", label)
    return _tools_of(result, label)


def load_config(path: str) -> List[Tuple[str, object]]:
    """Read the mcpServers block of a desktop-style MCP client config.

    A claude_desktop_config.json or .cursor/mcp.json says how each server is
    reached: a command plus args to spawn, or a url to POST. Returning that as
    data instead of spawning here keeps this function usable for a listing, a
    diff, or a scan of everything at once.

    A file without an mcpServers object is an error rather than an empty list:
    "no servers" and "not an MCP config" look identical downstream, and silently
    returning nothing would report a clean surface for a file that was never
    read. Servers are sorted by name so two runs print the same order.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError as exc:
        raise RuntimeError("cannot read MCP config %s: %s" % (path, exc))
    except ValueError as exc:
        raise RuntimeError("MCP config %s is not valid JSON: %s" % (path, exc))

    if not isinstance(raw, dict):
        raise RuntimeError("MCP config %s must be a JSON object with an mcpServers object"
                           % path)
    servers = raw.get("mcpServers")
    if not isinstance(servers, dict):
        raise RuntimeError('MCP config %s has no mcpServers object; expected '
                           '{"mcpServers": {"name": {"command": ...}}}' % path)

    entries: List[Tuple[str, object]] = []
    for name in sorted(servers):
        label = "MCP config %s, server %r" % (path, name)
        spec = servers[name]
        if not isinstance(spec, dict):
            raise RuntimeError("%s: entry is not an object" % label)

        url = spec.get("url")
        if isinstance(url, str) and url.strip():
            entries.append((name, url.strip()))
            continue

        command = spec.get("command")
        if isinstance(command, str) and command.strip():
            args = spec.get("args")
            if args is None:
                args = []
            if not isinstance(args, (list, tuple)) or not all(
                    isinstance(argument, str) for argument in args):
                raise RuntimeError("%s: args must be a list of strings" % label)
            entries.append((name, [command.strip()] + list(args)))
            continue

        # env, cwd and headers are a launcher's business; this module only
        # records what it can actually run or POST to.
        raise RuntimeError("%s: has neither a command nor a url" % label)
    return entries


def compare_hashes(tools: Sequence[dict],
                   lock: Dict[str, str]) -> List[str]:
    """Diff a tool surface against reviewed hashes, as report-ready lines.

    The pinned hashes come from mcp_lint.schema_hashes, so the comparison is a
    pure delegation: a second implementation would drift from the linter's idea
    of what a tool's identity is. Worst severity first, because the top line is
    the one a reader stops at.
    """
    findings = diff_lockfile(tools, lock)
    findings.sort(key=lambda finding: (-SEVERITY_ORDER.get(finding.severity, 0),
                                       finding.tool, finding.code))
    return ["%-8s %-22s %-28s %s" % (finding.severity, finding.code,
                                      finding.tool, finding.detail)
            for finding in findings]


class _StdioSession:
    """One spawned server, read through a queue because pipes do not time out.

    select() cannot watch a pipe on Windows, so a daemon thread drains stdout
    into a queue and the caller waits on the queue with a deadline instead. Both
    pump threads are daemons: a server that leaks a grandchild of its own must
    never be able to keep the interpreter alive after the scan.
    """

    def __init__(self, process: subprocess.Popen, label: str,
                 timeout: float) -> None:
        self._process = process
        self._label = label
        self._timeout = timeout
        self._lines: queue.Queue = queue.Queue()
        self._errors: List[str] = []
        self._out = threading.Thread(target=self._pump_stdout,
                                     name="mcp-stdio-stdout", daemon=True)
        self._err = threading.Thread(target=self._pump_stderr,
                                     name="mcp-stdio-stderr", daemon=True)
        self._out.start()
        self._err.start()

    def request(self, method: str, params: Dict[str, object], request_id: int,
                deadline: float) -> dict:
        """Send one request and return the result object of its reply."""
        self._send(_message(method, params, request_id))
        return self._await(request_id, method, deadline)

    def notify(self, method: str) -> None:
        """Send a notification: no id, and the server must not answer it."""
        self._send(_message(method, None))

    def _send(self, message: Dict[str, object]) -> None:
        stream = self._process.stdin
        if stream is None or stream.closed:
            raise RuntimeError(self._gone("while sending %s" % message.get("method")))
        try:
            stream.write(json.dumps(message) + "\n")
            stream.flush()
        except (OSError, ValueError):
            raise RuntimeError(self._gone("while sending %s" % message.get("method")))

    def _await(self, request_id: int, method: str, deadline: float) -> dict:
        while True:
            message = self._read(deadline, method)
            if message.get("id") != request_id:
                # A server may emit its own notifications; only the reply counts.
                continue
            return _result_of(message, method, self._label)

    def _read(self, deadline: float, method: str) -> dict:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(self._timed_out(method))
            try:
                item = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise RuntimeError(self._timed_out(method))
            if item is _EOF:
                raise RuntimeError(self._gone("before answering %s" % method))
            try:
                message = json.loads(item)
            except ValueError:
                # A server is allowed to log to stdout. A line that is not JSON
                # is not a reply, and failing on one would be this module's bug.
                continue
            if isinstance(message, dict):
                return message

    def close(self) -> None:
        """Stop the child, then close every pipe it was given.

        terminate() first and kill() only if it did not take: a server that
        ignores SIGTERM must not be able to hold the caller here. A pipe whose
        pump thread is still blocked is left to that thread, because closing a
        buffered reader from another thread can block on the read it is waiting
        for -- the one failure mode that would turn a failed scan into a hang.
        """
        self._stop_process()
        for thread in (self._out, self._err):
            if thread.is_alive():
                thread.join(timeout=1.0)
        self._close(self._process.stdout, self._out)
        self._close(self._process.stderr, self._err)
        self._close(self._process.stdin, None)

    def _stop_process(self) -> None:
        process = self._process
        try:
            if process.poll() is None:
                process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=5.0)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            pass  # an unkillable child is still not allowed to hang the scan

    def _close(self, stream, owner: Optional[threading.Thread]) -> None:
        if stream is None or stream.closed:
            return
        if owner is not None and owner.is_alive():
            return  # its pump thread closes that end at EOF
        _close_quietly(stream)

    def _pump_stdout(self) -> None:
        stream = self._process.stdout
        try:
            if stream is not None:
                for line in stream:
                    self._lines.put(line)
        except (OSError, ValueError):
            pass
        finally:
            _close_quietly(stream)
            self._lines.put(_EOF)

    def _pump_stderr(self) -> None:
        stream = self._process.stderr
        try:
            if stream is not None:
                for line in stream:
                    self._errors.append(line)
                    if len(self._errors) > 200:
                        del self._errors[:100]
        except (OSError, ValueError):
            pass
        finally:
            _close_quietly(stream)

    def _stderr_tail(self, limit: int = 3) -> str:
        lines = [line.strip() for line in self._errors if line.strip()]
        return _shorten(" | ".join(lines[-limit:]))

    def _note(self, text: str) -> str:
        tail = self._stderr_tail()
        return text + ("; stderr: " + tail if tail else "")

    def _timed_out(self, method: str) -> str:
        return self._note("timed out after %.1fs waiting for %s from MCP server %s"
                          % (self._timeout, method, self._label))

    def _gone(self, stage: str) -> str:
        code = self._process.poll()
        text = "MCP server %s stopped %s" % (self._label, stage)
        if code is not None:
            text += " (exit code %s)" % code
        return self._note(text)


def _message(method: str, params: Optional[Dict[str, object]],
             request_id: Optional[int] = None) -> Dict[str, object]:
    """One JSON-RPC 2.0 message; a request has an id, a notification does not."""
    message: Dict[str, object] = {"jsonrpc": "2.0"}
    if request_id is not None:
        message["id"] = request_id
    message["method"] = method
    if params is not None:
        message["params"] = params
    return message


def _initialize_params() -> Dict[str, object]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": _client_version()},
    }


def _client_version() -> str:
    """The harness version, read from the package instead of copied here."""
    from . import __version__

    return __version__


def _result_of(message: Dict[str, object], method: str, label: str) -> dict:
    """The result object, or a RuntimeError that quotes the server's error."""
    error = message.get("error")
    if error:
        if isinstance(error, dict):
            detail = "%s (code %s)" % (error.get("message", "unknown error"),
                                       error.get("code", "?"))
        else:
            detail = str(error)
        raise RuntimeError("MCP server %s returned a JSON-RPC error for %s: %s"
                           % (label, method, detail))
    result = message.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("MCP server %s returned no result object for %s"
                           % (label, method))
    return result


def _tools_of(result: dict, label: str) -> List[dict]:
    tools = result.get("tools")
    if not isinstance(tools, list):
        raise RuntimeError("MCP server %s returned no tools array in the tools/list result"
                           % label)
    return [tool for tool in tools if isinstance(tool, dict)]


def _http_post(url: str, message: Dict[str, object], deadline: float) -> List[dict]:
    """POST one message and return every JSON-RPC message the reply carried."""
    method = message.get("method")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("timed out before sending %s to MCP server %s"
                           % (method, url))
    request = urllib.request.Request(
        url,
        data=json.dumps(message).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=remaining) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError("MCP server %s answered HTTP %d for %s%s"
                           % (url, exc.code, method, _http_error_body(exc)))
    except urllib.error.URLError as exc:
        raise RuntimeError("cannot reach MCP server %s: %s" % (url, exc.reason))
    except OSError as exc:  # socket timeouts and resets arrive as OSError
        raise RuntimeError("MCP server %s failed during %s: %s" % (url, method, exc))
    return _parse_messages(body.decode("utf-8", "replace"), url, method)


def _http_error_body(error: urllib.error.HTTPError) -> str:
    try:
        text = error.read().decode("utf-8", "replace").strip()
    except OSError:
        return ""
    return ": " + _shorten(text) if text else ""


def _parse_messages(body: str, label: str, method: object) -> List[dict]:
    """Read a JSON body or an event stream into JSON-RPC messages."""
    text = body.strip()
    if not text:
        return []
    if text.startswith("data:") or "\ndata:" in text:
        messages = _parse_event_stream(text)
        if messages:
            return messages
        raise RuntimeError("MCP server %s sent an event stream with no JSON data for %s"
                           % (label, method))
    try:
        parsed = json.loads(text)
    except ValueError:
        raise RuntimeError("MCP server %s did not answer %s with JSON: %s"
                           % (label, method, _shorten(text)))
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):  # a JSON-RPC batch reply
        return [item for item in parsed if isinstance(item, dict)]
    raise RuntimeError("MCP server %s did not answer %s with a JSON-RPC message"
                       % (label, method))


def _parse_event_stream(body: str) -> List[dict]:
    """Pull the JSON payloads out of a text/event-stream body.

    The transport frames each message with data: lines, and a data field split
    over several lines is one JSON value, so the lines are joined per event
    before parsing. A blank line ends an event; a line starting with ':' is a
    comment and carries no payload.
    """
    messages: List[dict] = []
    data: List[str] = []
    for line in body.splitlines():
        if not line:
            _flush_event(data, messages)
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            value = line[5:]
            # Exactly one leading space is framing, the rest is payload.
            data.append(value[1:] if value.startswith(" ") else value)
    _flush_event(data, messages)
    return messages


def _flush_event(data: List[str], messages: List[dict]) -> None:
    if not data:
        return
    payload = "\n".join(data)
    del data[:]
    try:
        parsed = json.loads(payload)
    except ValueError:
        return
    if isinstance(parsed, dict):
        messages.append(parsed)


def _pick(messages: List[dict], request_id: int, label: str,
          method: str) -> dict:
    """The reply to this request, if the server sent several messages."""
    for message in reversed(messages):
        if message.get("id") == request_id:
            return message
    raise RuntimeError("MCP server %s answered %s with no JSON-RPC reply for request %d"
                       % (label, method, request_id))


def _command_argv(command: Union[str, Sequence[str]]) -> List[str]:
    if isinstance(command, str):
        argv = _split_command(command)
    elif isinstance(command, (list, tuple)):
        argv = [str(part) for part in command]
    else:
        raise RuntimeError("command must be a string or a sequence of strings, got %r"
                           % (command,))
    if not argv or not argv[0].strip():
        raise RuntimeError("cannot spawn an MCP server from an empty command")
    return argv


def _split_command(line: str) -> List[str]:
    """Split a config command line without a shell.

    posix=False on Windows is what keeps backslashes in a path intact; the
    quotes that mode leaves in the tokens are stripped here. No shell is
    involved on either platform, so a quote in an argument is data, not syntax
    someone else gets to interpret.
    """
    try:
        parts = shlex.split(line, posix=(os.name != "nt"))
    except ValueError as exc:
        raise RuntimeError("cannot parse MCP command %r: %s" % (line, exc))
    cleaned: List[str] = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in ("'", '"'):
            part = part[1:-1]
        cleaned.append(part)
    return cleaned


def _positive(value: float) -> float:
    size = float(value)
    if size <= 0:
        raise RuntimeError("timeout must be greater than zero, got %r" % (value,))
    return size


def _close_quietly(stream) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except (OSError, ValueError):
        pass


def _shorten(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit] + "..."
