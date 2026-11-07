"""Command-line interface: triage one or more log files."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import TriageAgent
from .llm import llm_available, narrate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sre-agent", description="AI triage agent for auth and app logs")
    parser.add_argument("logs", nargs="+", help="log file(s): auth.log and/or app.log style")
    parser.add_argument("--rules", help="path to a JSON rules file overriding thresholds")
    parser.add_argument("--llm", action="store_true", help="add an LLM on-call summary when an endpoint is configured")
    args = parser.parse_args(argv)

    agent = TriageAgent()
    if args.rules:
        agent.load_rules(args.rules)

    auth_text = app_text = ""
    for log in args.logs:
        content = Path(log).read_text()
        if "sshd" in content:
            auth_text = content
        else:
            app_text = content

    report = agent.triage(auth_log=auth_text, app_log=app_text)
    print(report.to_markdown())

    if args.llm:
        if llm_available():
            summary = narrate(report.to_markdown())
            if summary:
                print("## On-call summary (LLM)\n")
                print(summary)
        else:
            print("LLM narration requested but SRE_AGENT_LLM_URL / SRE_AGENT_API_KEY are not set; "
                  "the deterministic report above is complete on its own.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
