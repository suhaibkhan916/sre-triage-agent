# sre-triage-agent

An SRE incident-triage agent that reads auth and application logs, detects failure and attack patterns, and produces a severity-ranked incident report with runbook recommendations. Built as a demonstration of the "AI agent" pattern applied to on-call work: **the agent decides, the LLM (optionally) narrates.**

## Why this design

Triage output must be **reproducible** — the same logs must always produce the same severity ranking, or the report cannot be trusted in a paging channel. So the classification engine is deterministic rules over tool outputs, and the LLM layer is strictly a narrator: it summarises the finished report and never changes a severity. With no LLM endpoint configured, the agent is fully functional.

Zero runtime dependencies — standard library only.

## What it detects

| Rule | Severity | Trigger |
|---|---|---|
| `ssh-brute-force` | HIGH | ≥ N failed SSH logins from one source IP (default 10) |
| `credential-stuffing` | HIGH | Failures across ≥ N distinct usernames from one IP (default 5) |
| `successful-login-after-brute-force` | CRITICAL | Failed logins from an IP followed by a successful login — possible compromise |
| `http-5xx-spike` | HIGH | 5xx ratio over a window (default 20%) |
| `latency-regression` | MEDIUM | p95 latency above SLO (default 2000ms) |

## Architecture

```
logs ──▶ tools (parse, group, count, stats)   # pure functions, stdlib only
            │
            ▼
      rule engine (TriageAgent) ──▶ IncidentReport (severity-ranked, runbook-linked)
            │
            ▼
      optional LLM narration (OpenAI-compatible endpoint)  # never classifies
```

## Usage

```bash
pip install -e .[dev]
pytest -v                                    # 12 tests

# Triage sample logs
python -m sre_agent sample-logs/auth.log
python -m sre_agent sample-logs/app.log
python -m sre_agent sample-logs/auth.log sample-logs/app.log

# Custom thresholds
python -m sre_agent sample-logs/auth.log --rules config/thresholds.json

# Optional LLM on-call summary (any OpenAI-compatible endpoint)
export SRE_AGENT_LLM_URL="https://api.openai.com/v1/chat/completions"
export SRE_AGENT_API_KEY="sk-..."
python -m sre_agent sample-logs/auth.log --llm
```

## Sample output

```markdown
# Incident triage report — sre-triage-agent

Worst severity: **CRITICAL** — 3 detection(s).

## 1. [CRITICAL] successful-login-after-brute-force
- **Summary:** 12 failed logins from 192.0.2.99 followed by a successful login as 'deploy' — possible compromise.
- **Evidence:** 12 failures, 1 distinct usernames, then acceptance at 11:13:05
- **Runbook:** `rb-compromise.md — isolate host, rotate credentials, preserve logs for forensics`
- **Recommended action:** Isolate the host and rotate credentials before anything else.

## 2. [HIGH] ssh-brute-force
...
```

## Design decisions

- **Determinism over cleverness.** A probabilistic classifier is the wrong tool for paging decisions; rules are auditable and testable.
- **LLM at the edge.** The model adds a human-readable summary for a Slack channel, nothing more. Remove it and the agent still works.
- **Thresholds are config, not code.** `config/thresholds.json` or `--rules` lets an on-call team tune sensitivity without touching logic.
- **Stdlib only.** Runs anywhere, including air-gapped CI (which is exactly where it is tested).
