from sre_agent.agent import TriageAgent
from sre_agent.models import Severity

BRUTE_FORCE = "\n".join(
    f"Nov  7 09:00:{i:02d} web01 sshd[201{i}]: Failed password for root from 203.0.113.45 port 51{i}00 ssh2"
    for i in range(15)
)

COMPROMISE = BRUTE_FORCE + "\n" + \
    "Nov  7 09:01:00 web01 sshd[20999]: Accepted password for root from 203.0.113.45 port 51999 ssh2"

STUFFING = "\n".join(
    f"Nov  7 10:0{i}:0{j} web01 sshd[202{i}]: Failed password for {u} from 198.51.100.77 port 60{i}1{j} ssh2"
    for i, u in enumerate(["deploy", "jenkins", "git", "ubuntu", "postgres", "oracle"])
    for j in (0, 1)
)

APP_HEALTHY = "\n".join(
    f"2026-11-07T12:00:0{i}Z GET /api/orders 200 {100 + i}ms" for i in range(10)
)

APP_5XX = APP_HEALTHY + "\n" + "\n".join(
    f"2026-11-07T12:01:0{i}Z GET /api/orders 503 2500ms" for i in range(5)
)


def test_brute_force_detected_as_high():
    report = TriageAgent().triage(auth_log=BRUTE_FORCE)
    assert any(d.rule == "ssh-brute-force" and d.severity == Severity.HIGH for d in report.detections)


def test_success_after_failures_escalates_to_critical():
    report = TriageAgent().triage(auth_log=COMPROMISE)
    assert any(d.rule == "successful-login-after-brute-force"
               and d.severity == Severity.CRITICAL for d in report.detections)


def test_credential_stuffing_across_users():
    report = TriageAgent().triage(auth_log=STUFFING)
    assert any(d.rule == "credential-stuffing" for d in report.detections)


def test_5xx_spike_beats_latency_rule():
    report = TriageAgent().triage(app_log=APP_5XX)
    rules = {d.rule for d in report.detections}
    assert "http-5xx-spike" in rules
    assert "latency-regression" not in rules  # 5xx spike is the louder signal


def test_healthy_baseline_reports_nothing():
    report = TriageAgent().triage(auth_log="", app_log=APP_HEALTHY)
    assert report.detections == []
    assert report.worst_severity == Severity.INFO


def test_custom_rules_change_thresholds():
    agent = TriageAgent(rules={"failed_login_threshold": 20})
    report = agent.triage(auth_log=BRUTE_FORCE)  # 15 failures < 20
    assert not any(d.rule == "ssh-brute-force" for d in report.detections)


def test_report_markdown_includes_runbook_and_action():
    report = TriageAgent().triage(auth_log=BRUTE_FORCE)
    md = report.to_markdown()
    assert "rb-ssh-bruteforce.md" in md
    assert "Recommended action" in md
    assert "CRITICAL" in md or "HIGH" in md
