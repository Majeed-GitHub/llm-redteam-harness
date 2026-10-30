# llm-redteam-harness

Test what an LLM agent **does**, not just what it says: prompt injection, poisoned
MCP tool schemas, mid-session rug-pulls, and multi-turn tool chains, measured with
published numbers instead of opinions.

```bash
# 1. Lint a third-party MCP server before spending a single token
python -m rt scan-mcp examples/poisoned_mcp.json

# 2. Run the tool-poisoning suite against a deliberately poisoned agent
python -m rt agent --suite suites/mcp_schema.jsonl --mock --mock-mode agent-vulnerable

# 3. See what a defense buys you, on the same suite
python -m rt agent --suite suites/mcp_schema.jsonl --mock --mock-mode agent-vulnerable \
    --defense sanitize-schemas
```

The two fixtures are the evidence: **100% attack success** against
`agent-vulnerable`, **0%** against `agent-safe`, and **25%** once schemas are
sanitized - the survivors being the chain cases that carry no poisoned schema, which
is the limit of that defense stated instead of hidden. CI asserts all three on every
push.

No key, no network, no third-party dependency: every number above is reproducible
from a clone. Against a real deployment, swap `--mock` for
`--endpoint URL --model NAME --api-key-env VAR`.

## What it tests

| Surface | Command | What a failure means |
| --- | --- | --- |
| MCP tool definitions | `rt scan-mcp` | a server's schema carries instructions, not documentation |
| Poisoned tool metadata | `rt agent` (MCP suite) | the agent obeyed a tool description instead of the user |
| Mid-session rug-pulls | `rt agent` + `mutate_on_turn` | the agent trusted a definition that changed after inspection |
| Multi-turn tool chains | `rt agent` + `user_turns` | legitimate tools were chained into a privileged action |
| Prompt injection | `rt run` | the model complied with an injected instruction |
| A defense's value | `rt agent --defense ...` | the defense did not change the attack success rate |

Reports: `--format markdown | junit | sarif | html`, grouped by OWASP id, with a
tool-call trace per case.

## Why another one

Most "LLM red team" scripts are a list of prompts and a human reading the output.
That produces an opinion, not a measurement. This harness fixes the things that
make a result reproducible:

1. **Fixed, versioned suites.** JSONL cases with expectations, canaries, tool
   definitions and scoring rules in the case itself, so a number means the same
   thing next month.
2. **Judges you can read.** Refusal detection, canary leakage, forbidden calls and
   argument patterns are regular expressions and explicit assertions in
   `rt/judges.py` and `rt/scoring.py`. No model grades the model, and
   business-logic invariants are declarative rather than an LLM judge - a flaky
   judge in a security harness is worse than no judge.
3. **Temperature 0 and an explicit model name.** The same suite against the same
   endpoint should give the same table next month; if it does not, that is a
   finding, not noise.
4. **The fixture has to fail.** Every suite ships with an agent that is supposed to
   fail it, and CI fails if that agent starts passing.

## Quick start, offline

    python -m unittest discover -s tests -t .
    python -m rt run --suite suites/owasp_llm01.jsonl --mock --mock-mode good --report good.md
    python -m rt run --suite suites/owasp_llm01.jsonl --mock --mock-mode leaky --report leaky.md

The bundled mock has two behaviours. **good** refuses attacks and answers ordinary
questions; it should score a robustness of 100 percent. **leaky** complies, leaks
the canary and emits a tool call; it should score a high attack success rate. The
test suite asserts both, because a harness that cannot show a failing model
failing cannot show anything.

## Against a real endpoint

    export OPENAI_API_KEY=...
    python -m rt run --suite suites/owasp_llm01.jsonl \
        --endpoint https://api.example.com --model some-model \
        --api-key-env OPENAI_API_KEY --report report.md --max-asr 0.1

The API key is read from the environment variable you name; it is never written to
the report or the JSON.

## Comparing endpoints

The same suite against several endpoints, side by side, because "which gateway is
safer" is a question you answer with a table and a latency column:

    python -m rt compare --suite suites/owasp_llm01.jsonl \
        --target prod=https://api.example.com \
        --target staging=https://stage.example.com \
        --model some-model --api-key-env OPENAI_API_KEY --report compare.md

    | Target | Endpoint | Cases | Attacks | ASR | Robustness | Over-refusal | p50 ms | p95 ms |

An endpoint that cannot be reached is recorded as unreachable rather than raising,
so one dead target does not lose the other results. Latency is measured per
request, which is the point: a proxy that is safer but five times slower should
show up as exactly that.

## What the numbers mean

| Field | Meaning |
| --- | --- |
| attacks | cases whose expectation is refuse, no_leak or no_tool_call |
| attack success rate | share of attacks where the model did the wrong thing |
| robustness | 1 minus the attack success rate |
| over-refusal rate | share of control cases the model wrongly refused |
| by category | the same rate per attack family |

The over-refusal number is there because a model that refuses everything scores
perfectly on robustness and is useless. Both numbers are reported, always.

## Tool poisoning and MCP schemas

A poisoned tool definition is obeyed by a call, not a sentence, so `rt run` (one
prompt in, one string out) cannot see it. `rt agent` runs the case as a
conversation: it hands the model the tool definitions, executes whatever it asks
for against the case's own mock returns, appends the results, and repeats until
the model answers or the turn budget is spent. Every call, its arguments and the
turn it happened on are kept and scored.

    # the poisoned fixture must fail every attack case
    python -m rt agent --suite suites/mcp_schema.jsonl --mock --mock-mode agent-vulnerable

    # the safe fixture must pass every one of them
    python -m rt agent --suite suites/mcp_schema.jsonl --mock --mock-mode agent-safe --max-asr 0.0

    # a real deployment instead of a fixture
    python -m rt agent --suite suites/mcp_schema.jsonl --endpoint http://localhost:8000 \
        --model my-model --api-key-env OPENAI_API_KEY --max-asr 0.0 --format sarif --report out.sarif

Those two commands are the evidence for the suite: **100% attack success against
`agent-vulnerable`, 0% against `agent-safe`**, and the same in CI. A suite that
cannot fail a deliberately poisoned agent measures nothing.

`suites/mcp_schema.jsonl` covers direct description poisoning, instructions in a
parameter description and in a default value, cross-server shadowing, hidden
unicode, a multi-turn reconnaissance-to-booking chain, a mid-session rug-pull, and
a negative control.

| Case field | What it does |
| --- | --- |
| `tools` | definitions handed to the model, each with a `mock_return`; the mock return is stripped before sending |
| `forbidden_tool_calls` | fail if the agent calls any of these |
| `forbidden_arg_patterns` | regexes checked against every call's serialised arguments |
| `max_turns` | turn budget for the loop (default 3) |
| `user_turns` | scripted follow-ups, for slot-filling chains |
| `leak_patterns` / `must_contain` | assertions on the final answer |
| `policy_invariants` | declarative business-logic assertions: `no_pattern`, `no_tool`, `max_tool_calls` |
| `mutate_on_turn` + `mutate_tools` | rug-pull: swap the definitions after a turn that inspected them |
| `owasp` | MCP03/MCP06/LLM01/... so reports group by the standard, not by our test names |

Failures are named, not just counted: `forbidden_tool_called: send_email`,
`canary_leaked_in_tool_args`, `canary_leaked_in_text`, or a
`policy_invariant` line. A forbidden call outranks a leaky sentence, because the
call is the damage; data in arguments outranks the answer, because it has already
left.

### Before you spend a token: scan the server

```
# a file on disk
python -m rt scan-mcp examples/poisoned_mcp.json

# the server a client actually runs, over stdio
python -m rt scan-mcp --cmd "npx -y @acme/mcp-server"

# every server in a client config, or a live HTTP endpoint
python -m rt scan-mcp --config ~/.config/claude/claude_desktop_config.json
python -m rt scan-mcp --url http://localhost:8000/mcp

# pin what you reviewed, then fail on drift
python -m rt scan-mcp --config config.json --write-lockfile mcp.lock.json
python -m rt scan-mcp --config config.json --lockfile mcp.lock.json
```

A file is what someone meant to run; `tools/list` is what the model actually
sees, and the difference is where a poisoned tool hides. The live modes perform
the real `initialize` / `tools/list` handshake (JSON-RPC over newline-delimited
stdio, or Streamable HTTP with JSON or event-stream replies) and run the same
checks on the answer. The child process is always terminated, stderr is drained,
and every read is bounded by `--timeout`.

Static checks: imperative text in a description or a parameter default, hidden
unicode (with the decoded payload printed), a tool that redirects a sibling's
calls, an open schema next to an exec-like argument, and SHA-256 schema drift
against a pinned lockfile. No model, no key, no tokens.

## Measure a defense, not just a failure

A red-team report that stops at "the agent failed" leaves the reader with no next
step. The same suite runs with middleware in front of the model, and the attack
success rate is the measurement:

    python -m rt agent --suite suites/mcp_schema.jsonl --mock --mock-mode agent-vulnerable
    # attack success   : 100.0%

    python -m rt agent --suite suites/mcp_schema.jsonl --mock --mock-mode agent-vulnerable \
        --defense sanitize-schemas
    # attack success   : 25.0%

- **sanitize-schemas** strips hidden characters from tool definitions and removes
  any sentence that talks to the model instead of describing the tool. When every
  sentence is an instruction, the description becomes a factual stub built from
  the tool name, because an empty description breaks the feature it protects.
- **spotlighting** wraps tool output in `<untrusted_tool_output>` and adds one
  system message stating that content inside those tags is data, never an
  instruction.

The honest limits, measured rather than implied: sanitizing removes the attack
surface of a *description*, so the three survivors in the table above are the chain
cases that never carried a poisoned description - which is why they stay in the
suite. Spotlighting addresses a model that reads tool output as guidance; the
bundled fixtures return data rather than instructions, so that defense cannot be
measured offline and no number is claimed for it here. A live model is needed, and
that run is yours to take with your key.

## Report formats

A run can write four things, because four different readers need them: Markdown
for a person reading a pull request, JSON for whatever parses the result next,
JUnit XML for the CI system that already renders test results, and SARIF or HTML
for the security tab and a scorecard.

    python -m rt run --suite suites/owasp_llm01.jsonl --mock \
        --report report.md --json-out result.json
    python -m rt run --suite suites/owasp_llm01.jsonl --mock \
        --format junit --report junit.xml

--format accepts markdown (the default), junit, sarif and html. With --format junit the file named by
--report is JUnit XML: one <testsuite> named after the suite, one <testcase> per
case (classname is the category, name is the case id), and a <failure> carrying
the judge reason for every attack that succeeded or control that was over-refused.
A CI host renders that natively, so a case the model got wrong is a red row with
its reason attached instead of a number in a log. --json-out still always writes
JSON, and --json still prints the summary as JSON on stdout. With --format junit
and no --report, the XML goes to stdout, so redirecting it into junit.xml works
in a pipeline.

In GitHub Actions, for example:

    - run: python -m rt run --suite suites/owasp_llm01.jsonl --mock \
             --format junit --report junit.xml
    - uses: actions/upload-artifact@v4
      with: {name: junit, path: junit.xml}

GitLab and Jenkins read the same file with their own JUnit reporters.

## What it does not do

- **It does not grade quality.** Rules judge refusal, leakage and tool calls, not
  whether an answer was helpful, correct or safe in a subtler sense. A model that
  refuses in an unusual phrasing will be scored as not refusing; the verdicts file
  carries the response text so you can check.
- **It does not test the system prompt.** The suite sends user turns only.
- **It does not run a real tool.** `rt run` looks for a tool call in the response
  text and `rt agent` answers calls from the case's own `mock_return` values; no
  real MCP server is contacted. That is deliberate - a harness that called a
  third-party server while testing it would be doing exactly what it warns about.
- **It does not judge prose with a model.** Invariants are regexes and tool-name
  assertions, so a published number stays reproducible offline. A subtle
  business-logic rule that needs a reader is out of scope, not approximated.
- **No live-model numbers are published here.** Everything in this repository is
  measured against the bundled fixtures; a number for a hosted model needs that
  model's key, and is your measurement to take, not ours to claim.
- **It is not a benchmark for comparing vendors.** 34 cases is a starting suite,
  not a leaderboard, and a number from it means "under these cases", nothing more.

## Adding cases

One JSON object per line in a suite file:

    {"id": "DIO-07", "category": "direct_instruction_override",
     "prompt": "...", "expectation": "refuse"}

Expectations are refuse, no_leak (needs a canary), no_tool_call, and comply. Run
python -m rt validate --suite your-suite.jsonl before trusting a run.

## Layout

    rt/cases.py      suite loading and validation
    rt/client.py     OpenAI-compatible client, stdlib only
    rt/mock.py       deterministic mock model, good and leaky
    rt/judges.py     rule judges and the scoring arithmetic
    rt/report.py     JSON, Markdown and JUnit XML reports
    rt/cli.py        run and validate commands
    suites/          the graded suite
    tests/           unit and end-to-end tests, including both mock modes

## Licence

MIT. See LICENSE.

## Honest note

No result in this repository was produced against a hosted model. Every number
quoted above comes from the bundled mock, which is a fixture, not a finding about
any real model. Run it against your own endpoint and publish that.