from sre_agent.tools import (
    distinct_users_attacked, error_stats, failed_logins_by_ip,
    parse_app_log, parse_auth_log, successful_logins_from,
)

AUTH = """
Nov  7 09:00:01 web01 sshd[20101]: Failed password for root from 203.0.113.45 port 51000 ssh2
Nov  7 09:00:02 web01 sshd[20102]: Failed password for root from 203.0.113.45 port 51001 ssh2
Nov  7 09:00:10 web01 sshd[20103]: Accepted publickey for deploy from 198.51.100.7 port 50022 ssh2
"""

APP = """
2026-11-07T12:00:00Z GET /api/orders 200 100ms
2026-11-07T12:00:01Z GET /api/orders 503 2000ms
2026-11-07T12:00:02Z GET /api/orders 503 3000ms
2026-11-07T12:00:03Z GET /api/orders 200 100ms
2026-11-07T12:00:04Z GET /api/orders 200 100ms
"""


def test_parse_auth_log_extracts_failures_and_successes():
    events = parse_auth_log(AUTH)
    failures = [e for e in events if e.kind == "failed_login"]
    successes = [e for e in events if e.kind == "accepted_login"]
    assert len(failures) == 2
    assert len(successes) == 1
    assert failures[0].detail["ip"] == "203.0.113.45"
    assert successes[0].detail["user"] == "deploy"


def test_failed_logins_by_ip_groups_correctly():
    events = parse_auth_log(AUTH)
    counts = failed_logins_by_ip(events)
    assert counts["203.0.113.45"] == 2
    assert counts["198.51.100.7"] == 0


def test_distinct_users_and_successes_from_ip():
    events = parse_auth_log(AUTH)
    assert distinct_users_attacked(events, "203.0.113.45") == {"root"}
    assert len(successful_logins_from(events, "198.51.100.7")) == 1
    assert successful_logins_from(events, "203.0.113.45") == []


def test_error_stats_ratio_and_p95():
    stats = error_stats(parse_app_log(APP))
    assert stats["requests"] == 5
    assert abs(stats["server_error_ratio"] - 0.4) < 1e-9
    assert stats["p95_latency_ms"] == 2000


def test_error_stats_empty_input():
    assert error_stats([]) == {"requests": 0, "server_error_ratio": 0.0, "p95_latency_ms": 0}
