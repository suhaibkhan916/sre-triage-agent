"""The triage agent: calls tools, applies rules, ranks detections.

The rule engine is deterministic on purpose — triage output must be the same
on every run so it can be trusted in an incident channel. The optional LLM
layer only narrates the report; it never decides severity.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from . import tools
from .models import Detection, IncidentReport, Severity

DEFAULT_RULES = {
    "failed_login_threshold": 10,      # per source IP
    "credential_stuffing_users": 5,    # distinct usernames from one IP
    "server_error_ratio": 0.20,        # 5xx fraction over the window
    "p95_latency_ms": 2000,
}

RUNBOOKS = {
    "ssh-brute-force": "rb-ssh-bruteforce.md — block source IP at the edge, review SSH exposure, check for created accounts",
    "possible-compromise": "rb-compromise.md — isolate host, rotate credentials, preserve logs for forensics",
    "http-5xx-spike": "rb-5xx-spike.md — check upstream health, recent deploys, connection pool saturation",
    "latency-regression": "rb-latency.md — check p95 per endpoint, DB slow queries, GC pauses",
}


class TriageAgent:
    """An SRE triage agent over auth and application logs."""

    name = "sre-triage-agent"

    def __init__(self, rules: Optional[dict] = None):
        self.rules = {**DEFAULT_RULES, **(rules or {})}

    def load_rules(self, path: str | Path) -> None:
        self.rules.update(json.loads(Path(path).read_text()))

    def triage(self, auth_log: str = "", app_log: str = "") -> IncidentReport:
        report = IncidentReport(agent=self.name)
        if auth_log:
            self._triage_auth(tools.parse_auth_log(auth_log), report)
        if app_log:
            self._triage_app(tools.parse_app_log(app_log), report)
        return report

    # --- auth rules -------------------------------------------------------

    def _triage_auth(self, events: list, report: IncidentReport) -> None:
        failures = tools.failed_logins_by_ip(events)
        for ip, count in failures.most_common():
            if count < self.rules["failed_login_threshold"]:
                continue
            users = tools.distinct_users_attacked(events, ip)
            successes = tools.successful_logins_from(events, ip)
            if successes:
                report.add(Detection(
                    rule="successful-login-after-brute-force",
                    severity=Severity.CRITICAL,
                    summary=(f"{count} failed logins from {ip} followed by a successful "
                             f"login as '{successes[0].detail['user']}' — possible compromise."),
                    evidence=f"{count} failures, {len(users)} distinct usernames, "
                             f"then acceptance at {successes[0].timestamp}",
                    runbook=RUNBOOKS["possible-compromise"],
                    recommended_action="Isolate the host and rotate credentials before anything else.",
                ))
            elif len(users) >= self.rules["credential_stuffing_users"]:
                report.add(Detection(
                    rule="credential-stuffing",
                    severity=Severity.HIGH,
                    summary=f"{count} failed logins across {len(users)} usernames from {ip}.",
                    evidence=f"top targeted users: {', '.join(sorted(users)[:5])}",
                    runbook=RUNBOOKS["ssh-brute-force"],
                    recommended_action="Block the IP at the edge and enforce key-only auth.",
                ))
            else:
                report.add(Detection(
                    rule="ssh-brute-force",
                    severity=Severity.HIGH,
                    summary=f"{count} failed SSH logins from {ip}.",
                    evidence=f"target user(s): {', '.join(sorted(users)[:5])}",
                    runbook=RUNBOOKS["ssh-brute-force"],
                    recommended_action="Block the IP and confirm no account was created.",
                ))

    # --- application rules ------------------------------------------------

    def _triage_app(self, events: list, report: IncidentReport) -> None:
        stats = tools.error_stats(events)
        if stats["requests"] == 0:
            return
        if stats["server_error_ratio"] >= self.rules["server_error_ratio"]:
            report.add(Detection(
                rule="http-5xx-spike",
                severity=Severity.HIGH,
                summary=(f"{stats['server_error_ratio']:.0%} of {stats['requests']} requests "
                         f"returned 5xx over the window."),
                evidence=f"p95 latency {stats['p95_latency_ms']}ms, threshold ratio "
                         f"{self.rules['server_error_ratio']:.0%}",
                runbook=RUNBOOKS["http-5xx-spike"],
                recommended_action="Check upstream health and the most recent deploy.",
            ))
        elif stats["p95_latency_ms"] >= self.rules["p95_latency_ms"]:
            report.add(Detection(
                rule="latency-regression",
                severity=Severity.MEDIUM,
                summary=f"p95 latency {stats['p95_latency_ms']}ms exceeds the "
                        f"{self.rules['p95_latency_ms']}ms SLO.",
                evidence=f"{stats['requests']} requests in window",
                runbook=RUNBOOKS["latency-regression"],
                recommended_action="Break p95 down per endpoint and check slow queries.",
            ))
