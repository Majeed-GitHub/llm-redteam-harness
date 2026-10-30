# Changelog

All notable changes. One line per change, in the commit that made it.

## 0.6.0 - defenses, live servers, and the value of a fix

The previous release showed what fails. This one answers "how do I fix it, and
does the fix work", without asking anyone to trust a claim.

- rt/defense.py plus `rt agent --defense`: runtime middleware measured on the same
  suite. `sanitize-schemas` strips hidden characters and removes instruction
  sentences from tool definitions; `spotlighting` wraps tool output in an
  untrusted block with one system notice. On the shipped fixtures, attack success
  goes 100% -> 25% with sanitizing; the three survivors are the chain cases that
  carry no poisoned description, which is the limit of that defense and the reason
  they stay in the suite.
- `mock_return_by_arg`: a tool can answer differently depending on what it was
  sent, so a multi-turn case only succeeds when the agent really moved a value
  from one tool into the next. A guessed name now gets "unknown employee" instead
  of the gate code, which turns a data-flow claim into a test.
- suites/mcp_schema.jsonl gained MCP-10, a stateful chain using that mechanism.
- rt/mcp_live.py plus `rt scan-mcp --cmd/--config/--url`: read tool schemas from a
  live MCP server (JSON-RPC over stdio, or Streamable HTTP) and lint the response,
  so the static check runs against what a developer's client actually sees.
- .github/workflows/release.yml: on a `v*` tag, build the wheel and sdist, run
  `twine check`, install the built wheel and run the suite against it (testing the
  package, not the tree), attach report.html / report.sarif / mcp-scan.json to the
  release, and publish to PyPI through Trusted Publishing when a publisher exists.
  The publish job is skipped with a notice rather than failed when none is
  configured, so the artifacts still ship.
- README now opens with the two-command quickstart and the defense delta.
- Version honesty: package and pyproject both say 0.6.0, and tests/test_release.py
  fails if they ever disagree with the changelog.

Not claimed: no PyPI publication yet (needs a trusted publisher or a token on the
owner's account), no live-model numbers (the fixtures are the evidence), no
recorded demo, no hosted scorecard.

## 0.5.0 - tool poisoning, MCP schemas, and the trajectory

The harness could only test what a model said. Agent attacks are what a model
*does*, so this release adds a real agent loop, trajectory scoring, and a suite
about poisoned tool definitions.

- rt/agent.py: the agent loop. Tool calls are executed against the case's own
  mock_return values, the results are appended as role-tool messages, and the
  loop runs until the model answers or the turn budget is spent. Scripted user
  follow-ups model slot filling; mutate_on_turn models a rug-pull, where the
  definition inspected on turn one is replaced by a payload later.
- rt/client.py: complete_with_tools and native tool_calls parsing. Unparseable
  arguments are recorded, never dropped, because a harness that silently loses
  a call reports a clean run for an agent that tried to exfiltrate.
- rt/scoring.py: trajectory scoring. A forbidden call, a canary in the
  arguments, a canary in the text and a declared business-logic invariant are
  reported as separate, named failures ("forbidden_tool_called: send_email"),
  in that order, because the call is the damage and data in arguments is
  already gone.
- rt/cases.py: the case schema grew tools, forbidden_tool_calls,
  forbidden_arg_patterns, max_turns, user_turns, must_contain, leak_patterns,
  policy_invariants, owasp, mutate_on_turn and mutate_tools. JSONL stays
  native; JSON works, and YAML works when PyYAML is installed, with a clear
  error when it is not.
- suites/mcp_schema.jsonl: nine cases - direct description poisoning,
  parameter-description and default-value poisoning, cross-server shadowing,
  hidden unicode, a multi-turn reconnaissance-to-booking chain scored two ways
  (text leak and called tool), a rug-pull, and a negative control.
- rt/mock.py: two agent fixtures. agent-safe treats tool metadata as data and
  refuses restricted flows; agent-vulnerable obeys poisoned definitions, chains
  reconnaissance into a privileged call and repeats what tools returned. The
  suite reports 100% attack success against the vulnerable fixture and 0%
  against the safe one - that contrast is what makes the MCP cases evidence
  rather than assertion.
- rt/mcp_lint.py plus 'rt scan-mcp': a static linter for third-party MCP
  servers, so a poisoned schema is caught before a single token is spent.
  Imperative text in descriptions and parameter defaults, hidden unicode with
  the decoded payload shown, cross-tool shadowing, open schemas next to
  exec-like arguments, and SHA-256 schema drift against a pinned lockfile.
- Reports: --format sarif and --format html, alongside markdown and junit.
  SARIF puts a finding in a code-scanning tab; HTML is a self-contained
  dark-mode scorecard with per-category and per-OWASP pass rates plus a
  collapsible tool-call trace per case.
- Every case can cite an OWASP MCP Top 10 or LLM Top 10 identifier, and reports
  group pass rates by it.
- Verdict gained failure_reason, tool_calls, turns, owasp and control. The
  control flag is tri-state: a "comply" case carrying a poisoned tool is an
  attack case, and this release is why that distinction exists - a default of
  False had silently reclassified an exfiltration as over-refusal in SARIF.
- pyproject.toml, so 'pip install .' works and the CLI installs as
  llm-redteam-harness.
- A composite GitHub Action that runs a suite and can upload SARIF.
- 130 tests.

Not in this release, and not claimed: no published PyPI package (metadata is
ready; the upload needs an account token), no live-model numbers (everything
here is measured against the bundled fixtures, because a live number would need
that model's key), no hosted demo, and no recorded terminal GIF.

deterministic mock model, endpoint comparison, and the host plugin contract.

## 0.4.0 - JUnit XML reports

- rt/report.py: render_junit, one testcase per case with the judge reason in a
  failure element, XML-escaped because reasons contain quotes and brackets.
- rt/cli.py: --format {markdown,junit}; with no --report the XML goes to stdout.
- Version corrected to 0.4.0: __init__.py said 0.1.0 while v0.2.0 and v0.3.0
  were tagged.
- 47 tests.
