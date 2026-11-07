"""Tools the agent can call — pure functions over parsed log events.

Deliberately dependency-free: everything runs on the standard library so the
agent works in any environment, including air-gapped CI.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from .models import LogEvent

AUTH_FAILED = re.compile(
    r"(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
AUTH_ACCEPTED = re.compile(
    r"(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
APP_LINE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+"
    r"(?P<method>GET|POST|PUT|DELETE)\s+(?P<path>\S+)\s+"
    r"(?P<status>\d{3})\s+(?P<latency>\d+)ms"
)


def parse_auth_log(text: str) -> list[LogEvent]:
    """Parse an sshd-style auth.log into events."""
    events: list[LogEvent] = []
    for line in text.splitlines():
        if m := AUTH_FAILED.search(line):
            events.append(LogEvent(m["ts"], "auth", "failed_login",
                                   {"user": m["user"], "ip": m["ip"]}))
        elif m := AUTH_ACCEPTED.search(line):
            events.append(LogEvent(m["ts"], "auth", "accepted_login",
                                   {"user": m["user"], "ip": m["ip"]}))
    return events


def parse_app_log(text: str) -> list[LogEvent]:
    """Parse a 'ts METHOD path status latencyms' application log into events."""
    events: list[LogEvent] = []
    for line in text.splitlines():
        if m := APP_LINE.match(line.strip()):
            events.append(LogEvent(
                m["ts"], "app", "http_request",
                {"method": m["method"], "path": m["path"],
                 "status": int(m["status"]), "latency_ms": int(m["latency"])},
            ))
    return events


def failed_logins_by_ip(events: Iterable[LogEvent]) -> Counter:
    """Count failed SSH logins grouped by source IP."""
    return Counter(e.detail["ip"] for e in events
                   if e.source == "auth" and e.kind == "failed_login")


def distinct_users_attacked(events: Iterable[LogEvent], ip: str) -> set[str]:
    """Which usernames a single source IP has tried."""
    return {e.detail["user"] for e in events
            if e.source == "auth" and e.kind == "failed_login" and e.detail["ip"] == ip}


def successful_logins_from(events: Iterable[LogEvent], ip: str) -> list[LogEvent]:
    return [e for e in events
            if e.source == "auth" and e.kind == "accepted_login" and e.detail["ip"] == ip]


def error_stats(events: Iterable[LogEvent]) -> dict:
    """HTTP 5xx ratio and p95 latency over app events."""
    reqs = [e for e in events if e.source == "app" and e.kind == "http_request"]
    if not reqs:
        return {"requests": 0, "server_error_ratio": 0.0, "p95_latency_ms": 0}
    errors = [e for e in reqs if e.detail["status"] >= 500]
    latencies = sorted(e.detail["latency_ms"] for e in reqs)
    p95 = latencies[max(0, int(len(latencies) * 0.95) - 1)]
    return {
        "requests": len(reqs),
        "server_error_ratio": len(errors) / len(reqs),
        "p95_latency_ms": p95,
    }
