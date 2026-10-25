# Host plugin contract

The Python side of an embedding: a versioned manifest, and one JSON result object
a host renders. Built and tested; `python -m unittest tests.test_plugin` covers it.

## Status, stated plainly

- The **contract and its tests are done**: `rt plugin-manifest` and
  `rt plugin-run --json`, 16 tests, running offline against the bundled mock.
- The **host-side plugin is specified, not built**. A DeepSeek Harness plugin is a
  TypeScript Cordis package that has to be compiled and loaded into the app, and
  that build could not be run or verified here. An untested plugin is not shipped
  on this project's terms, so what follows is the specification instead.

## What a host calls

    python -m rt plugin-manifest
    python -m rt plugin-run --suite suites/owasp_llm01.jsonl --endpoint URL --model NAME --json

`plugin-run` returns one object:

    {"schema": "redlens.redteam-eval/1", "ok": true, "suite": "...", "model": "...",
     "summary": {"attacks": 28, "attacks_succeeded": 0, "attack_success_rate": 0.0,
                  "robustness": 1.0, "over_refusal_rate": 0.0, "by_category": {...}},
     "failures": [...], "markdown": "# LLM security test report..."}

A failed run is `ok: false` with an `error` string, never a traceback: a bad path or
an unreachable endpoint is a result the host should display.

## What the manifest promises

| Field | Value |
| --- | --- |
| network | only to the endpoint passed on the command line; none with --mock |
| filesystem | reads the suite it is pointed at, writes only the report path given |
| secrets | reads the key from the named environment variable, never from disk |
| subprocesses | none |

## Wiring it into a DSH sidebar panel

1. Follow the official plugin documentation in `deepseek-ai/deepseek-harness`:
   `docs/cordis-primer.md`, `docs/cordis-api/`, `docs/cookbook/`, and
   `packages/util/plugin-market-index` for how a plugin is published.
2. A DSH plugin is a package with a `package.json` and a `cordis.patch.yml`; the
   panel registers a command that spawns the entrypoint above and renders the
   `markdown` field, with the numbers taken from `summary` rather than re-parsed.
3. Build with the repository's own toolchain (`pnpm`, `tsdown`) and load it into a
   development instance before publishing it anywhere.

## What this plugin must never do

A host plugin has power over the session it runs in. This one reports numbers and
renders a report. It must not inject prompts into the conversation, must not
disable or weaken any safety behaviour of the host or the model, and must not
carry attack payloads tuned to defeat a model's guardrails. The suite it runs is a
measurement, and the project's own rule applies to it: measure, publish, do not
bypass.
