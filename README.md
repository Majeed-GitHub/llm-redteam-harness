# llm-redteam-harness

A small, reproducible harness for testing how an LLM application behaves under
prompt-injection and tool-abuse attacks. Point it at any OpenAI-compatible
endpoint, or at the mock model it ships with, and it runs a graded suite, judges
each response with rules, and writes a report someone else can reproduce.

    python -m rt run --suite suites/owasp_llm01.jsonl --mock --report report.md

## Why another one

Most "LLM red team" scripts are a list of prompts and a human reading the output.
That produces an opinion, not a measurement. This harness fixes the three things
that make a result reproducible:

1. **A fixed, versioned suite.** 34 cases in JSONL: 28 attacks across five
   categories plus 6 controls that must still be answered.
2. **A rule judge you can read.** Refusal detection, canary leakage, and tool-call
   emission are regular expressions in rt/judges.py. No model grades the model.
3. **Temperature 0 and an explicit model name.** The same suite against the same
   endpoint should give the same table next month; if it does not, that is a
   finding, not noise.

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

## Report formats

A run can write three things, because three different readers need them: Markdown
for a person reading a pull request, JSON for whatever parses the result next, and
JUnit XML for the CI system that already renders test results.

    python -m rt run --suite suites/owasp_llm01.jsonl --mock \
        --report report.md --json-out result.json
    python -m rt run --suite suites/owasp_llm01.jsonl --mock \
        --format junit --report junit.xml

--format accepts markdown (the default, which leaves the report exactly as it
was) and junit. With --format junit the file named by
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
- **It does not simulate tools.** The tool-call judge looks for a tool call in the
  response text; it does not execute anything.
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
